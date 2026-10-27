import Foundation
import Security
import UIKit
import UserNotifications

/// App-side owner of engine.json, modules, local scripts and the MitM CA.
@MainActor
final class EngineStore: ObservableObject {
    static let shared = EngineStore()

    @Published var config = EngineConfig.load()
    @Published var caInfo = CAInfoModel(exists: false)
    @Published var caTrusted: Bool?
    @Published var message: String?
    @Published var busy: Set<String> = []
    /// Parsed module summaries by module id.
    @Published var moduleInfo: [String: ParsedEngineText] = [:]

    private var reloadTask: Task<Void, Never>?
    /// fix/nav-jank: bumped by every module parse / CA refresh, so a background result never overwrites a newer one.
    private var parseGeneration = 0
    private var caGeneration = 0

    /// fix/nav-jank (「动画有卡顿」): the store is usually created by the first page that needs it (高级设置,
    /// 模块, MitM …), i.e. during a push. init used to parse every module in the old core, build a test leaf and run
    /// SecTrustEvaluateWithError on the main thread right then. Now engine.json loads synchronously and the
    /// parse + CA check run off main; views update when they land.
    init() {
        Task { [weak self] in
            await self?.refreshCAInBackground()
            await self?.reparseModulesInBackground()
        }
    }

    var home: String { AppShared.homeURL.path }

    // MARK: config

    /// Persist and (debounced) reload the running tunnel.
    func save(reload: Bool = true) {
        config.save()
        guard reload else { return }
        reloadTask?.cancel()
        reloadTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 400_000_000)
            guard !Task.isCancelled, let self else { return }
            // v0.19.22: rewrite / module / plugin / script / MitM switches are applied in place when the core can.
            if VPNManager.shared.isConnected, let err = await VPNManager.shared.reload(hot: true) {
                self.message = String(localized: "重载失败：\(err)")
            }
        }
    }

    /// Splits pasted text into items; hostname lines go to the MitM list. Returns count added.
    @discardableResult
    func addLines(_ text: String, toScripts: Bool) -> Int {
        var n = 0
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("[") { continue }
            let lower = line.lowercased()
            if lower.hasPrefix("hostname") , let eq = line.firstIndex(of: "=") {
                let hosts = line[line.index(after: eq)...].split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "%APPEND%", with: "").replacingOccurrences(of: "%INSERT%", with: "").trimmingCharacters(in: .whitespaces)
                }.filter { !$0.isEmpty }
                for h in hosts where !config.hostnames.contains(h) { config.hostnames.append(h) }
                continue
            }
            let p = NCEngineParser.parseLine(line, section: toScripts ? "script" : "")
            let isScript = p.rules.first?.kind == "script"
            if isScript { config.scripts.append(EngineItem(line: line)) } else { config.rules.append(EngineItem(line: line)) }
            n += 1
        }
        save()
        return n
    }

    static func describe(_ line: String, section: String = "") -> (desc: String, kind: String, error: String?) {
        let p = NCEngineParser.parseLine(line, section: section)
        if let r = p.rules.first { return (r.desc, r.kind, nil) }
        if let t = p.tasks?.first { return (t.desc, t.kind, nil) }
        if let e = p.errors.first { return ("无效", "", e) }
        if !p.coreRules.isEmpty { return ("内核规则：" + p.coreRules[0], "core", nil) }
        if !p.hostnames.isEmpty { return ("MitM 主机名", "hostname", nil) }
        return ("不支持的语法", "", "暂不支持此语法")
    }

    // MARK: modules

    func reparseModules() {
        parseGeneration += 1
        var out: [String: ParsedEngineText] = [:]
        for m in config.modules {
            if let text = try? String(contentsOf: EnginePaths.moduleURL(m.id), encoding: .utf8) {
                let args = (try? JSONEncoder().encode(m.args ?? [:])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
                out[m.id] = NCEngineParser.parseText(text, argsJSON: args)
            }
        }
        moduleInfo = out
    }

    /// v0.19.8: the same parse off the main thread (模块与资源 opened: the synchronous parse of every module ran
    /// during the push animation and made it stutter). A change made meanwhile wins: the result is dropped when
    /// the module list changed while parsing.
    func reparseModulesInBackground() async {
        let mods = config.modules
        parseGeneration += 1
        let gen = parseGeneration
        let out = await Task.detached(priority: .userInitiated) { () -> [String: ParsedEngineText] in
            var out: [String: ParsedEngineText] = [:]
            for m in mods {
                if let text = try? String(contentsOf: EnginePaths.moduleURL(m.id), encoding: .utf8) {
                    let args = (try? JSONEncoder().encode(m.args ?? [:])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
                    out[m.id] = NCEngineParser.parseText(text, argsJSON: args)
                }
            }
            return out
        }.value
        if config.modules == mods && gen == parseGeneration { moduleInfo = out }
    }

    /// fix/nc-0.20.2: the module's own client User-Agent (some hosts answer 403 to anything else): Loon for plugins,
    /// Quantumult X for QX snippets / rewrite_remote, Surge otherwise.
    nonisolated static func moduleUserAgent(_ url: String, client: String? = nil) -> String {
        switch client?.lowercased() {
        case "qx", "quantumult x": return "Quantumult%20X/1.5.2"
        case "loon": return "Loon/3.2.4"
        case "surge": return "Surge iOS/3000"
        default: break
        }
        let path = (URL(string: url)?.path ?? url).lowercased()
        if path.hasSuffix(".plugin") || path.hasSuffix(".lpx") || path.contains("/loon/") { return "Loon/3.2.4" }
        if path.hasSuffix(".snippet") || path.hasSuffix(".qxrewrite") || path.contains("/quantumultx/")
            || path.contains("/quantumult-x/") || path.contains("/qx/") { return "Quantumult%20X/1.5.2" }
        return "Surge iOS/3000"
    }

    static func download(_ url: String, client: String? = nil) async throws -> String {
        guard let u = URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines)), u.scheme?.hasPrefix("http") == true else {
            throw ProfileStore.StoreError.badURL
        }
        var req = URLRequest(url: u, timeoutInterval: 30)
        req.setValue(moduleUserAgent(url, client: client), forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        // v0.11: readable reasons (was a generic system error).
        if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) { throw ProfileStore.StoreError.http(h.statusCode) }
        if data.isEmpty { throw ProfileStore.StoreError.empty }
        guard let s = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { throw ProfileStore.StoreError.empty }
        // fix/nc-e2e-real: a moved / removed module host can answer 200 with a web page (a site's new home page after a
        // redirect, a bot-challenge page); that used to be saved as the module and parse to nothing, silently.
        let head = s.prefix(512).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let ctype = ((resp as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type") ?? "").lowercased()
        if head.hasPrefix("<!doctype html") || head.hasPrefix("<html") || (ctype.contains("text/html") && head.hasPrefix("<")) {
            throw ProfileStore.StoreError.invalid(String(localized: "链接返回的是网页而不是模块（可能已失效、已迁移或被拦截）"))
        }
        return s
    }

    /// fix/nc-0.20.2: 添加订阅 form — a user-typed name is kept (customName), interval / enabled as chosen.
    func addModule(fields f: SubscriptionFormFields) async {
        await addModule(url: f.url, name: f.trimmedName, interval: f.interval, enabled: f.enabled)
    }

    /// fix/nc-0.20.2: 编辑订阅 — rename (empty = back to the module's own #!name), change URL / interval / 启用.
    /// A changed URL is downloaded again.
    func editModuleSubscription(_ id: String, fields f: SubscriptionFormFields) async {
        guard let i = config.modules.firstIndex(where: { $0.id == id }) else { return }
        var m = config.modules[i]
        let urlChanged = !f.url.isEmpty && f.url != m.url
        if urlChanged, config.modules.contains(where: { $0.id != id && $0.url == f.url }) {
            message = String(localized: "模块已存在：「\(m.name)」")
            return
        }
        m.url = f.url.isEmpty ? m.url : f.url
        if f.trimmedName.isEmpty {
            m.customName = nil
            let own = moduleInfo[m.id]?.name ?? ""
            m.name = own.isEmpty ? (URL(string: m.url)?.deletingPathExtension().lastPathComponent ?? m.name) : own
        } else {
            m.name = f.trimmedName
            m.customName = true
        }
        m.interval = f.interval
        m.enabled = f.enabled
        config.modules[i] = m
        if f.enabled { enableForModules() }
        save()
        if urlChanged { await updateModule(m) }
    }

    func addModule(url: String, name customName: String = "", interval: Int? = nil, enabled: Bool = true) async {
        // v0.19.2: opening the same install link twice (tern:// / surge:/// / a pasted URL) added a second copy,
        // so every rewrite and script of that module ran twice. The other add paths already refused duplicates.
        let wanted = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if let existing = config.modules.first(where: { $0.url == wanted || $0.url == url }) {
            message = String(localized: "模块已存在：「\(existing.name)」")
            return
        }
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        busy.insert("add")
        defer { busy.remove("add") }
        do {
            let text = try await Self.download(wanted)
            let p = NCEngineParser.parseText(text, argsJSON: "{}")
            guard !(p.rules.isEmpty && p.hostnames.isEmpty && p.coreRules.isEmpty && (p.tasks ?? []).isEmpty && (p.panels ?? []).isEmpty) else {
                message = String(localized: "未识别到可用的重写、脚本或 MitM 内容")
                return
            }
            var name = customName.isEmpty ? p.name : customName
            if name.isEmpty { name = URL(string: url)?.deletingPathExtension().lastPathComponent ?? "模块" }
            var m = EngineModule(name: name, url: wanted, enabled: enabled, args: nil, updatedAt: Date().timeIntervalSince1970,
                                 interval: interval)
            if !customName.isEmpty { m.customName = true }
            try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
            config.modules.append(m)
            if enabled { enableForModules() }
            reparseModules()
            save()
            var msg = String(localized: "已添加「\(name)」：\(p.rules.count) 条规则/脚本，\(p.hostnames.count) 个 MitM 主机")
            // v0.19.9: task-only modules (QX task gallery JSON such as Sub-Store's QX-Task.json) showed "0 条规则/脚本".
            if let n = p.tasks?.count, n > 0 { msg += String(localized: "，\(n) 个定时任务") }
            if !p.unsupported.isEmpty { msg += String(localized: "，\(p.unsupported.count) 行暂不支持") }
            if !p.hostnames.isEmpty && !caTrustedOrUnknownTrue { msg += String(localized: "。HTTPS 规则需要先在「HTTPS 解密」页安装并信任证书") }
            message = msg
        } catch {
            message = String(localized: "下载失败：\(error.localizedDescription)")
        }
    }

    /// v0.15 模块库: add a module whose text was already downloaded for the preview (no second download).
    /// Returns false when the URL is already a module.
    /// feat/module-browser: `enabled`, `interval` (seconds, nil = 1 day) and `args` chosen in the preview.
    @discardableResult
    func addPreviewedModule(url: String, text: String, name: String, enabled: Bool = true, interval: Int? = nil, args: [String: String]? = nil) -> Bool {
        if config.modules.contains(where: { $0.url == url }) { return false }
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        let m = EngineModule(name: name.isEmpty ? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? "模块") : name,
                             url: url, enabled: enabled, args: args?.isEmpty == false ? args : nil, updatedAt: Date().timeIntervalSince1970,
                             interval: interval)
        guard (try? text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)) != nil else { return false }
        config.modules.append(m)
        if enabled { enableForModules() }
        reparseModules()
        save()
        return true
    }

    /// A module just added or turned on carries rewrites and / or scripts: switch on whichever of the two
    /// master switches is off (the same as the single switch did before they were split).
    func enableForModules() {
        if !config.enabled { config.enabled = true }
        if !config.scriptsEnabled { config.scriptsEnabled = true }
    }

    /// Turns one script file (local name or remote URL) on / off wherever it is used: engine.json
    /// scriptResources, the same setting ResourceStore.setEnabled writes for script resources.
    func setScriptPathEnabled(_ path: String, _ on: Bool) {
        guard !path.isEmpty else { return }
        var m = config.scriptResources ?? [:]
        var s = m[path] ?? ScriptResourceSetting()
        if (s.disabled ?? false) == !on { return }
        s.disabled = on ? nil : true
        m[path] = (s.disabled == nil && s.interval == nil) ? nil : s
        config.scriptResources = m.isEmpty ? nil : m
        save()
    }

    func setModuleEnabled(_ id: String, _ on: Bool) {
        guard let i = config.modules.firstIndex(where: { $0.id == id }) else { return }
        config.modules[i].enabled = on
        if on { enableForModules() }
        save()
    }

    /// QX [rewrite_remote] (v0.8.1): one module per line, named from tag= or the file name, enabled= kept.
    /// Downloaded by the app right away (works while disconnected); a failed download keeps the module so
    /// 更新 can fetch it later. Returns the error text, nil on success. A URL that is already a module is skipped.
    func addRemoteModule(url: String, name: String, enabled: Bool, interval: Int, client: String? = nil) async -> String? {
        if config.modules.contains(where: { $0.url == url }) { return nil }
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        var m = EngineModule(name: name.isEmpty ? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? "模块") : name,
                             url: url, enabled: enabled, args: nil, updatedAt: nil, interval: interval > 0 ? interval : nil)
        var err: String?
        do {
            if !name.isEmpty { m.customName = true }
            let text = try await Self.download(url, client: client)
            try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
            m.updatedAt = Date().timeIntervalSince1970
        } catch {
            err = error.localizedDescription
            try? "".write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
        }
        config.modules.append(m)
        if enabled { enableForModules() }
        reparseModules()
        save()
        return err
    }

    /// Rewrites / scripts / MitM hosts of the enabled modules (更多 shows the same numbers as 模块与资源).
    var enabledModuleCounts: (rewrites: Int, scripts: Int, hosts: Int) {
        var r = 0, s = 0
        // fix/nc-tls-scripts: distinct host patterns across the enabled modules (the runtime dedupes them) — the
        // ximalaya QX module lists 246 entries / 145 distinct, so 自检 showed 「MitM 主机：模块 250 → 运行时 149」
        // and read as a loss.
        var h = Set<String>()
        for m in config.modules where m.enabled {
            guard let p = moduleInfo[m.id] else { continue }
            s += p.rules.filter { $0.kind == "script" }.count
            r += p.rules.filter { $0.kind != "script" }.count
            for x in p.hostnames where !x.hasPrefix("-") { h.insert(x.lowercased()) }
        }
        return (r, s, h.count)
    }

    private var caTrustedOrUnknownTrue: Bool { caTrusted == true }

    func addModule(text: String, name: String) {
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        let p = NCEngineParser.parseText(text, argsJSON: "{}")
        let m = EngineModule(name: (!p.name.isEmpty ? p.name : name), url: "", enabled: true, args: nil, updatedAt: Date().timeIntervalSince1970)
        try? text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
        config.modules.append(m)
        enableForModules()
        reparseModules()
        save()
    }

    func updateModule(_ m: EngineModule) async {
        guard !m.url.isEmpty else { return }
        busy.insert(m.id)
        defer { busy.remove(m.id) }
        do {
            let text = try await Self.download(m.url)
            try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
            if let i = config.modules.firstIndex(where: { $0.id == m.id }) { config.modules[i].updatedAt = Date().timeIntervalSince1970 }
            reparseModules()
            save()
        } catch {
            message = String(localized: "更新「\(m.name)」失败：\(error.localizedDescription)")
        }
    }

    func deleteModule(_ m: EngineModule) {
        SnapshotStore.shared.capture(String(localized: "删除模块「\(m.name)」前"))
        config.modules.removeAll { $0.id == m.id }
        try? FileManager.default.removeItem(at: EnginePaths.moduleURL(m.id))
        reparseModules()
        save()
    }

    func moduleText(_ m: EngineModule) -> String {
        (try? String(contentsOf: EnginePaths.moduleURL(m.id), encoding: .utf8)) ?? ""
    }

    // MARK: scripts

    func localScripts() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: EnginePaths.scriptsDir.path)) ?? []).filter { $0.hasSuffix(".js") }.sorted()
    }

    func readScript(_ name: String) -> String { (try? String(contentsOf: EnginePaths.scriptURL(name), encoding: .utf8)) ?? "" }

    func writeScript(_ name: String, _ text: String) {
        try? text.write(to: EnginePaths.scriptURL(name), atomically: true, encoding: .utf8)
        save()
    }

    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    // MARK: persistent store ($persistentStore / $prefs)

    func storeItems() -> [(String, String)] {
        guard let d = try? Data(contentsOf: EnginePaths.storeURL),
              let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [] }
        return m.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    func storeSet(_ key: String, _ value: String?) {
        var m: [String: String] = [:]
        if let d = try? Data(contentsOf: EnginePaths.storeURL), let x = try? JSONDecoder().decode([String: String].self, from: d) { m = x }
        if let value { m[key] = value } else { m.removeValue(forKey: key) }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(m) { try? d.write(to: EnginePaths.storeURL, options: .atomic) }
    }

    // MARK: 持久化存储 导出 / 导入 / 清空 (Loon gap). File work runs off the main thread (a store can be MBs).

    /// The temp file 导出 shares (holds scripts' cookies / tokens; the share sheet deletes it).
    nonisolated static var storeExportURL: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("Tern-persistentStore.json")
    }

    /// Writes the whole store as pretty JSON to storeExportURL. nil when the store is empty or unreadable.
    nonisolated static func storeExportFile() -> URL? {
        guard let d = try? Data(contentsOf: EnginePaths.storeURL),
              let m = try? JSONDecoder().decode([String: String].self, from: d), !m.isEmpty else { return nil }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let out = try? enc.encode(m) else { return nil }
        let url = storeExportURL
        do { try out.write(to: url, options: [.atomic, .completeFileProtection]) } catch { return nil }
        return url
    }

    /// Merges a JSON object into the store (same keys are replaced). String values are kept as they are; other
    /// values (numbers, booleans, objects, arrays) are stored as their JSON text, which is how scripts read them.
    /// Returns the number of imported keys, nil when the data is not a JSON object.
    nonisolated static func storeImport(_ data: Data) -> Int? {
        guard let obj = (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) as? [String: Any] else { return nil }
        var m: [String: String] = [:]
        if let d = try? Data(contentsOf: EnginePaths.storeURL), let x = try? JSONDecoder().decode([String: String].self, from: d) { m = x }
        var n = 0
        for (k, v) in obj where !k.isEmpty {
            if v is NSNull { continue }
            if let str = v as? String {
                m[k] = str
            } else if JSONSerialization.isValidJSONObject(v), let d = try? JSONSerialization.data(withJSONObject: v), let t = String(data: d, encoding: .utf8) {
                m[k] = t
            } else if let num = v as? NSNumber {
                // A bare number / boolean is not a valid top-level object for JSONSerialization.
                m[k] = CFGetTypeID(num) == CFBooleanGetTypeID() ? (num.boolValue ? "true" : "false") : num.stringValue
            } else {
                continue
            }
            n += 1
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let out = try? enc.encode(m) else { return nil }
        do { try out.write(to: EnginePaths.storeURL, options: .atomic) } catch { return nil }
        return n
    }

    /// 清空全部: an empty object (the engine notices the new file and drops its copy).
    nonisolated static func storeClear() -> Bool {
        (try? Data("{}".utf8).write(to: EnginePaths.storeURL, options: .atomic)) != nil
    }

    // MARK: CA

    func refreshCA() {
        caGeneration += 1
        caInfo = NCCAManager.caInfo(home: home)
        caTrusted = caInfo.exists ? checkTrust() : nil
    }

    /// fix/nav-jank: refreshCA off the main thread (Swift CA load + test leaf + SecTrust evaluation).
    func refreshCAInBackground() async {
        caGeneration += 1
        let gen = caGeneration
        let home = self.home
        let (info, trusted) = await Task.detached(priority: .userInitiated) { () -> (CAInfoModel?, Bool?) in
            let i = NCCAManager.caInfo(home: home)
            guard i.exists else { return (i, nil) }
            return (i, EngineStore.checkTrust(home: home))
        }.value
        guard gen == caGeneration else { return }
        if let info { caInfo = info }
        caTrusted = trusted
    }

    func generateCA() {
        do {
            _ = try NCCAManager.generateCA(home: home)
        } catch {
            message = String(localized: "生成失败：\(error.localizedDescription)")
        }
        refreshCA()
        save()
    }

    /// Evaluates a leaf signed by our CA with the system trust store: true only when the profile is
    /// installed AND full trust is enabled in 证书信任设置.
    func checkTrust() -> Bool { Self.checkTrust(home: home) }

    nonisolated static func checkTrust(home: String) -> Bool {
        NCCAManager.checkTrust(home: home)
    }

    func mobileConfigFile() -> URL? {
        guard let data = NCCAManager.mobileConfig(home: home) else {
            message = "请先生成证书"
            return nil
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Tern-CA.mobileconfig")
        try? data.write(to: url, options: .atomic)
        return url
    }

    func certFile() -> URL? {
        guard let data = NCCAManager.caCertDER(home: home) else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Tern-CA.cer")
        try? data.write(to: url, options: .atomic)
        return url
    }

    func p12File(password: String) -> URL? {
        do {
            let data = try NCCAManager.exportP12(home: home, password: password)
            let url = Self.p12TempURL
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            return url
        } catch {
            message = String(localized: "导出失败：\(error.localizedDescription)")
            return nil
        }
    }

    nonisolated static var p12TempURL: URL { FileManager.default.temporaryDirectory.appendingPathComponent("Tern-CA.p12") }

    /// Review 5 P2-9: the exported .p12 (private key) does not stay in tmp after the share sheet closes.
    nonisolated static func purgeP12() { try? FileManager.default.removeItem(at: p12TempURL) }

    func importP12(_ url: URL, password: String) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { message = String(localized: "无法读取文件"); return }
        do {
            try NCCAManager.importP12(home: home, data: data, password: password)
            message = String(localized: "已导入证书，请重新安装并信任描述文件")
        } catch {
            message = error.localizedDescription
        }
        refreshCA()
        save()
    }

    private var bgTask: UIBackgroundTaskIdentifier = .invalid

    func endBackgroundTask() {
        if bgTask != .invalid {
            UIApplication.shared.endBackgroundTask(bgTask)
            bgTask = .invalid
        }
    }

    /// Serves the profile on 127.0.0.1 and opens it in Safari (system profile install needs Safari / Files).
    func installViaSafari() {
        do {
            let port = try NCCAManager.serveProfile(home: home)
            // Keep the app (and its tiny server) alive for a bit while Safari downloads the profile.
            if bgTask != .invalid { UIApplication.shared.endBackgroundTask(bgTask) }
            // Review 5 P2-5: end the task synchronously inside the expiration handler (the handler runs on the main
            // thread); a Task hop could run after the handler returned, and iOS kills apps that overrun.
            bgTask = UIApplication.shared.beginBackgroundTask(withName: "ca-profile") {
                MainActor.assumeIsolated { EngineStore.shared.endBackgroundTask() }
            }
            if let u = URL(string: "http://127.0.0.1:\(port)/ca.mobileconfig") { UIApplication.shared.open(u) }
        } catch {
            message = error.localizedDescription
        }
    }
}
