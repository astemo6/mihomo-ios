import Foundation
import Security
import UIKit
import UserNotifications
import Libmihomo

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

    init() {
        refreshCA()
        reparseModules()
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
            if VPNManager.shared.isConnected, let err = await VPNManager.shared.reload() {
                self.message = "重载失败：\(err)"
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
            let p = ParsedEngineText.parse(LibmihomoEngineParseLine(line, toScripts ? "script" : ""))
            let isScript = p?.rules.first?.kind == "script"
            if isScript { config.scripts.append(EngineItem(line: line)) } else { config.rules.append(EngineItem(line: line)) }
            n += 1
        }
        save()
        return n
    }

    static func describe(_ line: String, section: String = "") -> (desc: String, kind: String, error: String?) {
        guard let p = ParsedEngineText.parse(LibmihomoEngineParseLine(line, section)) else { return ("无法解析", "", "无法解析") }
        if let r = p.rules.first { return (r.desc, r.kind, nil) }
        if let t = p.tasks?.first { return (t.desc, t.kind, nil) }
        if let e = p.errors.first { return ("无效", "", e) }
        if !p.coreRules.isEmpty { return ("内核规则：" + p.coreRules[0], "core", nil) }
        if !p.hostnames.isEmpty { return ("MitM 主机名", "hostname", nil) }
        return ("不支持的语法", "", "暂不支持此语法")
    }

    // MARK: modules

    func reparseModules() {
        var out: [String: ParsedEngineText] = [:]
        for m in config.modules {
            if let text = try? String(contentsOf: EnginePaths.moduleURL(m.id), encoding: .utf8) {
                let args = (try? JSONEncoder().encode(m.args ?? [:])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
                if let p = ParsedEngineText.parse(LibmihomoEngineParseText(text, args)) { out[m.id] = p }
            }
        }
        moduleInfo = out
    }

    static func download(_ url: String) async throws -> String {
        guard let u = URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines)), u.scheme?.hasPrefix("http") == true else {
            throw ProfileStore.StoreError.badURL
        }
        var req = URLRequest(url: u, timeoutInterval: 30)
        req.setValue("Surge iOS/3000", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        // v0.11: readable reasons (was a generic system error).
        if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) { throw ProfileStore.StoreError.http(h.statusCode) }
        if data.isEmpty { throw ProfileStore.StoreError.empty }
        guard let s = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { throw ProfileStore.StoreError.empty }
        return s
    }

    func addModule(url: String) async {
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        busy.insert("add")
        defer { busy.remove("add") }
        do {
            let text = try await Self.download(url)
            let p = ParsedEngineText.parse(LibmihomoEngineParseText(text, "{}"))
            guard let p, !(p.rules.isEmpty && p.hostnames.isEmpty && p.coreRules.isEmpty && (p.tasks ?? []).isEmpty && (p.panels ?? []).isEmpty) else {
                message = "未识别到可用的重写、脚本或 MitM 内容"
                return
            }
            var name = p.name
            if name.isEmpty { name = URL(string: url)?.deletingPathExtension().lastPathComponent ?? "模块" }
            let m = EngineModule(name: name, url: url, enabled: true, args: nil, updatedAt: Date().timeIntervalSince1970)
            try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
            config.modules.append(m)
            if !config.enabled { config.enabled = true }
            reparseModules()
            save()
            var msg = String(localized: "已添加「\(name)」：\(p.rules.count) 条规则/脚本，\(p.hostnames.count) 个 MitM 主机")
            if !p.unsupported.isEmpty { msg += String(localized: "，\(p.unsupported.count) 行暂不支持") }
            if !p.hostnames.isEmpty && !caTrustedOrUnknownTrue { msg += String(localized: "。HTTPS 规则需要先在 MitM 页安装并信任证书") }
            message = msg
        } catch {
            message = "下载失败：\(error.localizedDescription)"
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
        if enabled && !config.enabled { config.enabled = true }
        reparseModules()
        save()
        return true
    }

    func setModuleEnabled(_ id: String, _ on: Bool) {
        guard let i = config.modules.firstIndex(where: { $0.id == id }) else { return }
        config.modules[i].enabled = on
        if on && !config.enabled { config.enabled = true }
        save()
    }

    /// QX [rewrite_remote] (v0.8.1): one module per line, named from tag= or the file name, enabled= kept.
    /// Downloaded by the app right away (works while disconnected); a failed download keeps the module so
    /// 更新 can fetch it later. Returns the error text, nil on success. A URL that is already a module is skipped.
    func addRemoteModule(url: String, name: String, enabled: Bool, interval: Int) async -> String? {
        if config.modules.contains(where: { $0.url == url }) { return nil }
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        var m = EngineModule(name: name.isEmpty ? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? "模块") : name,
                             url: url, enabled: enabled, args: nil, updatedAt: nil, interval: interval > 0 ? interval : nil)
        var err: String?
        do {
            let text = try await Self.download(url)
            try text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
            m.updatedAt = Date().timeIntervalSince1970
        } catch {
            err = error.localizedDescription
            try? "".write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
        }
        config.modules.append(m)
        if enabled && !config.enabled { config.enabled = true }
        reparseModules()
        save()
        return err
    }

    /// Rewrites / scripts / MitM hosts of the enabled modules (更多 shows the same numbers as 模块与资源).
    var enabledModuleCounts: (rewrites: Int, scripts: Int, hosts: Int) {
        var r = 0, s = 0, h = 0
        for m in config.modules where m.enabled {
            guard let p = moduleInfo[m.id] else { continue }
            s += p.rules.filter { $0.kind == "script" }.count
            r += p.rules.filter { $0.kind != "script" }.count
            h += p.hostnames.filter { !$0.hasPrefix("-") }.count
        }
        return (r, s, h)
    }

    private var caTrustedOrUnknownTrue: Bool { caTrusted == true }

    func addModule(text: String, name: String) {
        SnapshotStore.shared.capture(String(localized: "添加模块前"))
        let p = ParsedEngineText.parse(LibmihomoEngineParseText(text, "{}"))
        let m = EngineModule(name: (p?.name.isEmpty == false ? p!.name : name), url: "", enabled: true, args: nil, updatedAt: Date().timeIntervalSince1970)
        try? text.write(to: EnginePaths.moduleURL(m.id), atomically: true, encoding: .utf8)
        config.modules.append(m)
        if !config.enabled { config.enabled = true }
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
            message = "更新「\(m.name)」失败：\(error.localizedDescription)"
        }
    }

    func updateAllModules() async {
        for m in config.modules where !m.url.isEmpty { await updateModule(m) }
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

    /// Hostnames contributed by enabled modules (read-only in the MitM page).
    var moduleHostnames: [String] {
        var out: [String] = []
        for m in config.modules where m.enabled {
            for h in moduleInfo[m.id]?.hostnames ?? [] where !out.contains(h) { out.append(h) }
        }
        return out
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

    // MARK: CA

    func refreshCA() {
        if let d = LibmihomoCAInfo(home).data(using: .utf8), let i = try? JSONDecoder().decode(CAInfoModel.self, from: d) {
            caInfo = i
        }
        caTrusted = caInfo.exists ? checkTrust() : nil
    }

    func generateCA() {
        var err: NSError?
        _ = LibmihomoCAGenerate(home, &err)
        if let err { message = "生成失败：\(err.localizedDescription)" }
        refreshCA()
        save()
    }

    /// Evaluates a leaf signed by our CA with the system trust store: true only when the profile is
    /// installed AND full trust is enabled in 证书信任设置.
    func checkTrust() -> Bool {
        var err: NSError?
        let s = LibmihomoCATrustChain(home, &err)
        let parts = s.split(separator: ",").map(String.init)
        guard err == nil, parts.count == 3,
              let leafData = Data(base64Encoded: parts[0]), let caData = Data(base64Encoded: parts[1]),
              let leaf = SecCertificateCreateWithData(nil, leafData as CFData),
              let ca = SecCertificateCreateWithData(nil, caData as CFData) else { return false }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, parts[2] as CFString)
        guard SecTrustCreateWithCertificates([leaf, ca] as CFArray, policy, &trust) == errSecSuccess, let trust else { return false }
        var cfErr: CFError?
        return SecTrustEvaluateWithError(trust, &cfErr)
    }

    func mobileConfigFile() -> URL? {
        var err: NSError?
        guard let data = LibmihomoCAMobileConfig(home, &err), err == nil else {
            message = err?.localizedDescription ?? "请先生成证书"
            return nil
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Mihomo-CA.mobileconfig")
        try? data.write(to: url, options: .atomic)
        return url
    }

    func certFile() -> URL? {
        var err: NSError?
        guard let data = LibmihomoCACertDER(home, &err), err == nil else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Mihomo-CA.cer")
        try? data.write(to: url, options: .atomic)
        return url
    }

    func p12File(password: String) -> URL? {
        var err: NSError?
        guard let data = LibmihomoCAExportP12(home, password, &err), err == nil else {
            message = "导出失败：\(err?.localizedDescription ?? "")"
            return nil
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Mihomo-CA.p12")
        try? data.write(to: url, options: .atomic)
        return url
    }

    func importP12(_ url: URL, password: String) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { message = "无法读取文件"; return }
        var err: NSError?
        _ = LibmihomoCAImportP12(home, data, password, &err)
        if let err { message = err.localizedDescription } else { message = "已导入证书，请重新安装并信任描述文件" }
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
        var err: NSError?
        var port: Int = 0
        _ = LibmihomoCAServeProfile(home, &port, &err)
        if let err { message = err.localizedDescription; return }
        // Keep the app (and its tiny server) alive for a bit while Safari downloads the profile.
        if bgTask != .invalid { UIApplication.shared.endBackgroundTask(bgTask) }
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "ca-profile") {
            Task { @MainActor in EngineStore.shared.endBackgroundTask() }
        }
        if let u = URL(string: "http://127.0.0.1:\(port)/ca.mobileconfig") { UIApplication.shared.open(u) }
    }
}
