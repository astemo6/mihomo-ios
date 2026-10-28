import Foundation

struct SubscriptionUserInfo: Codable, Hashable {
    var upload: Int64 = 0
    var download: Int64 = 0
    var total: Int64 = 0
    var expire: Int64 = 0

    /// Saturating: two huge header values must not trap (v0.19.2).
    var used: Int64 { let (s, o) = upload.addingReportingOverflow(download); return o ? .max : s }
    var fraction: Double { total > 0 ? min(Double(used) / Double(total), 1) : 0 }
    var expireDate: Date? { expire > 0 ? Date(timeIntervalSince1970: TimeInterval(expire)) : nil }

    /// Parses "upload=123; download=456; total=789; expire=1700000000".
    static func parse(_ header: String?) -> SubscriptionUserInfo? {
        guard let header, !header.isEmpty else { return nil }
        var info = SubscriptionUserInfo()
        var found = false
        for part in header.split(whereSeparator: { $0 == ";" || $0 == "," }) {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            guard kv.count == 2 else { continue }
            // v0.19.2: Int64(Double) traps on inf / nan / values beyond Int64 ("total=1e30" from a broken
            // panel) — that crashed the app on every update of that subscription, also in background refresh.
            let v = Self.clampedInt64(kv[1])
            switch kv[0] {
            case "upload": info.upload = v; found = true
            case "download": info.download = v; found = true
            case "total": info.total = v; found = true
            case "expire": info.expire = v; found = true
            default: break
            }
        }
        return found ? info : nil
    }

    /// Whole bytes / seconds from a header value: plain integers exactly, decimals / exponents rounded down,
    /// anything non-finite or negative → 0, larger than Int64 → Int64.max.
    static func clampedInt64(_ s: String) -> Int64 {
        if let i = Int64(s) { return max(i, 0) }
        guard let d = Double(s), d.isFinite, d > 0 else { return 0 }
        return d >= 9.2e18 ? Int64.max : Int64(d)
    }
}

struct Profile: Codable, Identifiable, Hashable {
    enum Kind: String, Codable { case remote, local }
    var id: String = UUID().uuidString
    var name: String
    var kind: Kind
    var url: String?
    var userAgent: String = "clash.meta"
    var updateIntervalHours: Int = 24
    var lastUpdated: Date?
    var userInfo: SubscriptionUserInfo?
    /// feat/group-order: set on an 自定义 copy made by the first 策略组 reorder — the profile it was copied from
    /// (its id, and its name at the time, shown when the source is gone). The source file is never rewritten by a
    /// reorder; a subscription source regenerates its copies when it updates.
    var sourceID: String? = nil
    var sourceName: String? = nil
    /// feat/group-order review: the copy was edited by the user since it was last generated, so subscription
    /// updates leave it alone until 「从订阅重新生成」.
    var copyModified: Bool? = nil
    /// fb-subs-global (device feedback 「订阅停用没做」): 停用 keeps the link and settings, but the profile is skipped
    /// by automatic updates / 全部更新 and cannot become the active profile. Stored as an optional `disabled` key so
    /// profiles.json written by earlier builds (no key) decodes as enabled.
    var disabled: Bool? = nil
    var enabled: Bool {
        get { disabled != true }
        set { disabled = newValue ? nil : true }
    }

    var fileURL: URL { AppShared.profileURL(id: id) }

    /// selftest: the built-in 「手动节点」 profile is stored with its Chinese name; show it in the UI language.
    var displayName: String { id == "manual-nodes" && name == "手动节点" ? String(localized: "手动节点") : name }
}

@MainActor
final class ProfileStore: ObservableObject {
    static let shared = ProfileStore()

    @Published private(set) var profiles: [Profile] = []
    @Published var activeID: String? = AppShared.activeProfileID
    @Published var updating: Set<String> = []

    init() { load() }

    var active: Profile? { profiles.first { $0.id == activeID } }

    func load() {
        if let data = try? Data(contentsOf: AppShared.profilesIndexURL),
           let list = try? JSONDecoder().decode([Profile].self, from: data) {
            profiles = list
        }
        if activeID == nil || !profiles.contains(where: { $0.id == activeID }) {
            activeID = fallbackActiveID()
            AppShared.activeProfileID = activeID
        }
        // v0.8.1: profiles converted by v0.8.0 and earlier get source URLs and readable provider names.
        let paths = profiles.filter { $0.kind == .local }.map { $0.fileURL.path }
        let allPaths = profiles.map { $0.fileURL.path }
        Task.detached(priority: .utility) {
            // fix/nc-e2e-real: first re-convert imports the old YAML emitter cut short (from their .source.conf);
            // migrateProfileProviders re-emits the profile from what it parses, which would make the loss permanent.
            for path in paths { NCProfileYAMLRepair.repair(profilePath: path) }
            // fix/nc-0.20.2: absolute provider paths into an old container become home-relative (idempotent).
            let home = AppShared.homeURL.path
            for path in allPaths { NCProviderPathRebase.migrateFile(path, home: home) }
            for path in paths { _ = NCProviderPorts.migrateProfileProviders(path) }
            // feat/nc-conf-native: every profile gets its .conf (first launch: generated once, the YAML kept as
            // <id>.yaml.pre-conf); later launches only compare the YAML hash.
            for path in allPaths { TernConfStore.sync(yamlPath: path) }
        }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(profiles) {
            try? data.write(to: AppShared.profilesIndexURL, options: .atomic)
        }
    }

    /// The profile to make active when the current one is gone: the first enabled one. When every profile is
    /// disabled the first one is re-enabled (the active profile can never be disabled).
    private func fallbackActiveID() -> String? {
        if let p = profiles.first(where: { $0.enabled }) { return p.id }
        guard !profiles.isEmpty else { return nil }
        profiles[0].enabled = true
        persist()
        return profiles[0].id
    }

    /// Why `p` cannot become the active profile, or nil. Callers check this before `setActive` so its message
    /// is not shown as a reload failure.
    func activationBlock(_ p: Profile) -> String? {
        let cur = profiles.first { $0.id == p.id } ?? p
        return cur.enabled ? nil : String(localized: "该配置已停用，启用后才能设为当前配置")
    }

    /// 停用 / 启用 a profile (订阅管理). The active profile cannot be disabled.
    func setEnabled(_ p: Profile, _ on: Bool) -> String? {
        guard let i = profiles.firstIndex(where: { $0.id == p.id }) else { return nil }
        if !on && p.id == activeID { return String(localized: "当前配置不能停用") }
        profiles[i].enabled = on
        persist()
        return nil
    }

    func setActive(_ p: Profile) async -> String? {
        if let block = activationBlock(p) { return block }
        activeID = p.id
        AppShared.activeProfileID = p.id
        return await VPNManager.shared.reload()
    }

    func delete(_ p: Profile) {
        SnapshotStore.shared.capture(String(localized: "删除配置「\(p.name)」前"))
        try? FileManager.default.removeItem(at: p.fileURL)
        SubRulesStore.set(p.id, nil)
        UsageAlerts.remove(p.id)
        HomeGroupsStore.forget(profile: p.id) // feat/home-groups
        OverrideScriptStore.shared.forget(profile: p) // v0.19 覆写脚本
        // Per-profile settings (策略组编辑 / order, 前置代理, 订阅规则, 网络策略) and side files (.bak, .gen,
        // .selected.json) of the deleted profile.
        let err = ImportTools.forgetProfile(home: AppShared.homeURL.path, profileID: p.id, profilePath: p.fileURL.path)
        if !err.isEmpty { StartupLog.write("forget profile: \(err)", tag: "app") }
        // 自定义 copies of a deleted source become plain local profiles (they no longer follow a subscription).
        for i in profiles.indices where profiles[i].sourceID == p.id {
            profiles[i].sourceID = nil
            profiles[i].copyModified = nil
        }
        profiles.removeAll { $0.id == p.id }
        let wasActive = activeID == p.id
        if wasActive {
            activeID = fallbackActiveID()
            AppShared.activeProfileID = activeID
        }
        persist()
        // v0.19.2: deleting the running profile left the core on the deleted file while the list showed another
        // one as active. Switch the tunnel to the new active profile, or disconnect when none is left.
        if wasActive, VPNManager.shared.isConnected {
            if activeID != nil {
                // rv2: a failed reload (e.g. the fallback profile's file is gone → NativeRuntimePrep error) is shown
                // instead of being dropped — the tunnel would otherwise keep running the deleted profile silently.
                Task { if let e = await VPNManager.shared.reload() { VPNManager.shared.lastError = e } }
            } else {
                VPNManager.shared.stop()
            }
        }
    }

    func rename(_ p: Profile, to name: String) {
        guard let i = profiles.firstIndex(where: { $0.id == p.id }) else { return }
        profiles[i].name = name
        persist()
    }

    func update(_ p: Profile) {
        guard let i = profiles.firstIndex(where: { $0.id == p.id }) else { return }
        profiles[i] = p
        persist()
    }

    func content(of p: Profile) -> String {
        (try? String(contentsOf: p.fileURL, encoding: .utf8)) ?? ""
    }

    /// feat/more-dedup (user 2026-10-21 「配置里长按没有导出」): a temp copy of the profile's YAML named after the
    /// profile, for the share sheet (配置 long-press → 导出, YAML editor toolbar). `text` = the editor's current text.
    /// It holds node secrets, so the share sheet deletes it when it ends (ShareItem.temporary) and leftovers are purged.
    func exportFile(of p: Profile, text: String? = nil) -> URL? {
        let body = text ?? content(of: p)
        guard !body.isEmpty else { return nil }
        Self.purgeExports()
        let dir = Self.exportDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var base = p.name.components(separatedBy: CharacterSet(charactersIn: "/\\:?*\"<>|\n\r")).joined(separator: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if base.isEmpty || base.hasPrefix(".") { base = "profile" + base }
        let url = dir.appendingPathComponent(String(base.prefix(80)) + ".yaml")
        do { try body.write(to: url, atomically: true, encoding: .utf8) } catch { return nil }
        return url
    }

    /// 「导出最终配置（含覆写）」: the YAML the core runs for this profile (覆写脚本, 节点处理, 节点订阅, node-set
    /// edits, core overrides; credentials as in the profile; controller / probe plumbing removed), built in Swift (NCFinalConfigReadable)
    /// off the main thread, as `<name> · 最终配置.yaml`. feat/export-readable: written for people (block YAML in
    /// Clash.Meta's usual order, a header naming the profile / Tern version / export time, one comment per section);
    /// the tunnel's own runtime.yaml is unchanged.
    func exportFinalFile(of p: Profile) async -> Result<URL, Error> {
        let home = AppShared.homeURL.path
        let path = p.fileURL.path
        let name = p.name
        let version = DiagnosticsExporter.version(of: .main)
        let r: Result<String, Error> = await Task.detached(priority: .userInitiated) {
            do {
                return .success(try NCFinalConfigReadable.render(home: home, path: path, profileName: name, appVersion: version))
            } catch {
                return .failure(error)
            }
        }.value
        switch r {
        case .failure(let e): return .failure(e)
        case .success(let text):
            var q = p
            q.name = p.name + " · " + String(localized: "最终配置")
            guard let u = exportFile(of: q, text: text) else {
                return .failure(NSError(domain: "Tern", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "配置文件为空或无法读取")]))
            }
            return .success(u)
        }
    }

    nonisolated static var exportDir: URL { FileManager.default.temporaryDirectory.appendingPathComponent("ProfileExport", isDirectory: true) }
    nonisolated static func purgeExports() { try? FileManager.default.removeItem(at: exportDir) }

    // MARK: Validation / conversion

    /// Validates YAML text with the full config parse (NCConfigValidator, the Swift port of Clash.Meta's). Returns nil if OK, else the error.
    nonisolated static func validate(text: String) async -> String? {
        await Task.detached(priority: .userInitiated) {
            let tmp = AppShared.homeURL.appendingPathComponent("validate-\(UUID().uuidString).yaml")
            defer { try? FileManager.default.removeItem(at: tmp) }
            do { try text.write(to: tmp, atomically: true, encoding: .utf8) } catch { return error.localizedDescription }
            let r = NCConfigValidator.validateConfigIn(home: AppShared.homeURL.path, path: tmp.path)
            return r.isEmpty ? nil : r
        }.value
    }

    /// If text is not a Clash.Meta YAML (no proxies / proxy-providers), try converting share links / base64.
    nonisolated static func normalize(_ text: String) -> String {
        let looksYAML = text.contains("proxies:") || text.contains("proxy-providers:") || text.contains("proxy-groups:")
        if looksYAML { return text }
        let converted = NCShareLink.convertShareLinks(text)
        return converted.isEmpty ? text : converted
    }

    // MARK: Add / import

    func addLocal(name: String, text: String) async throws -> Profile {
        let yaml = Self.normalize(text)
        if let err = await Self.validate(text: yaml) { throw StoreError.invalid(err) }
        SnapshotStore.shared.capture(String(localized: "导入配置前"))
        let p = Profile(name: name.isEmpty ? "本地配置" : name, kind: .local)
        try await Self.writeProfile(yaml, to: p.fileURL)
        profiles.append(p)
        persist()
        if activeID == nil { _ = await setActive(p) }
        return p
    }

    func saveLocalEdit(_ p: Profile, text: String) async throws {
        if let err = await Self.validate(text: text) { throw StoreError.invalid(err) }
        SnapshotStore.shared.capture(String(localized: "编辑配置「\(p.name)」前"))
        try await Self.writeProfile(text, to: p.fileURL)
        if OverrideScriptStore.shared.enabledCount(p.id) > 0 { await OverrideScriptStore.shared.apply(p, force: false) } // v0.19
        // rv2: the save itself succeeded; a reload that could not apply it is reported, not dropped.
        if p.id == activeID, let e = await VPNManager.shared.reload() { VPNManager.shared.lastError = e }
    }

    func addRemote(url: String, name: String, userAgent: String, intervalHours: Int) async throws -> Profile {
        var p = Profile(name: name, kind: .remote, url: url.trimmingCharacters(in: .whitespacesAndNewlines),
                        userAgent: userAgent.isEmpty ? "clash.meta" : userAgent, updateIntervalHours: intervalHours)
        SnapshotStore.shared.capture(String(localized: "添加订阅前"))
        p = try await download(p)
        profiles.append(p)
        persist()
        if activeID == nil { _ = await setActive(p) }
        return p
    }

    enum StoreError: LocalizedError {
        case invalid(String), badURL, http(Int), empty
        var errorDescription: String? {
            switch self {
            case .invalid(let s): return String(localized: "配置校验失败：\(CoreText.localize(s))")
            case .badURL: return String(localized: "订阅链接无效")
            case .http(let c): return String(localized: "下载失败：HTTP \(c)")
            case .empty: return String(localized: "订阅内容为空")
            }
        }
    }

    /// rv2: profile writes go through the same per-file NCPathLock as the node editor (NCProfileNodes), manual
    /// nodes, selection / override-output writers, and use NCRuntimeFiles.writeAtomic (unique temp + rename).
    /// A direct `String.write(atomically:)` could interleave with a locked read-modify-write of the same profile
    /// and have its content overwritten by the other writer's stale copy. Runs off the main actor: the lock can be
    /// held for a whole node-edit validation.
    nonisolated static func writeProfile(_ text: String, to url: URL, syncConf: Bool = true) async throws {
        let path = url.path
        try await Task.detached(priority: .userInitiated) {
            try NCPathLock.shared.withLock(for: path) {
                try NCRuntimeFiles.writeAtomic(Data(text.utf8), to: path)
            }
            // feat/nc-conf-native: an imported / downloaded YAML is converted to the profile's .conf right away.
            if syncConf { TernConfStore.sync(yamlPath: path) }
        }.value
    }

    // MARK: feat/nc-conf-native — the .conf editor

    /// The editor text for `p` (nil = a new local profile): its .conf plus the shared rewrite / script / MitM sections.
    nonisolated static func confEditorText(_ p: Profile?) async -> String {
        let path = p?.fileURL.path
        let home = AppShared.homeURL.path
        return await Task.detached(priority: .userInitiated) {
            TernConfStore.editorText(yamlPath: path, home: home, engine: EngineConfig.load())
        }.value
    }

    /// The internal YAML of `p` (advanced, read-only view).
    func internalText(of p: Profile) -> String { content(of: p) }

    /// 保存并重载 in the .conf editor: the .conf is parsed and validated, the YAML regenerated from it, then the shared
    /// sections (rewrite / scripts / MitM, CA) are applied and the tunnel reloads.
    func saveConfEdit(_ p: Profile, text: String) async throws {
        let prep = try await Self.prepareConf(text)
        if let err = await Self.validate(text: prep.yaml) { throw StoreError.invalid(err) }
        SnapshotStore.shared.capture(String(localized: "编辑配置「\(p.name)」前"))
        try await Self.writeProfile(prep.yaml, to: p.fileURL, syncConf: false)
        let path = p.fileURL.path
        try await Task.detached(priority: .userInitiated) {
            try TernConfStore.commit(yamlPath: path, yaml: prep.yaml, conf: prep.profileConf)
        }.value
        let engineChanged = applyShared(prep)
        if OverrideScriptStore.shared.enabledCount(p.id) > 0 { await OverrideScriptStore.shared.apply(p, force: false) }
        if p.id == activeID, let e = await VPNManager.shared.reload() { VPNManager.shared.lastError = e }
        else if engineChanged, VPNManager.shared.isConnected, let e = await VPNManager.shared.reload(hot: true) { VPNManager.shared.lastError = e }
    }

    /// 校验并保存 for a new local profile written as .conf.
    func addLocalConf(name: String, text: String) async throws -> Profile {
        let prep = try await Self.prepareConf(text)
        if let err = await Self.validate(text: prep.yaml) { throw StoreError.invalid(err) }
        SnapshotStore.shared.capture(String(localized: "导入配置前"))
        let p = Profile(name: name.isEmpty ? "本地配置" : name, kind: .local)
        try await Self.writeProfile(prep.yaml, to: p.fileURL, syncConf: false)
        let path = p.fileURL.path
        try await Task.detached(priority: .userInitiated) {
            try TernConfStore.commit(yamlPath: path, yaml: prep.yaml, conf: prep.profileConf)
        }.value
        profiles.append(p)
        persist()
        _ = applyShared(prep)
        if activeID == nil { _ = await setActive(p) }
        return p
    }

    nonisolated static func prepareConf(_ text: String) async throws -> TernConfStore.Prepared {
        try await Task.detached(priority: .userInitiated) { try TernConfStore.prepare(text: text) }.value
    }

    /// Applies the shared sections of a saved .conf to engine.json (and a changed MitM CA). True when anything changed.
    @discardableResult
    func applyShared(_ prep: TernConfStore.Prepared) -> Bool {
        guard let e = prep.engine else { return false }
        let es = EngineStore.shared
        let next = e.applied(to: es.config)
        var changed = false
        if next != es.config {
            let newModules = next.modules.filter { m in !m.url.isEmpty && !es.config.modules.contains(where: { $0.id == m.id }) }
            es.config = next
            es.save(reload: false)
            changed = true
            if !newModules.isEmpty { Task { for m in newModules where m.enabled { await es.updateModule(m) } } }
        }
        if let ca = prep.caPEM {
            let home = AppShared.homeURL.path
            if !TernConfStore.sameCA(home: home, pemCert: ca.cert) {
                let dir = AppShared.homeURL.appendingPathComponent("engine/ca", isDirectory: true)
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let pem = dir.appendingPathComponent("ca.pem"), key = dir.appendingPathComponent("ca.key")
                if (try? ca.cert.write(to: pem, options: .atomic)) != nil, (try? ca.key.write(to: key, options: .atomic)) != nil {
                    try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: pem.path)
                    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key.path)
                    NCCAManager.shared.reloadCA(home: home)
                    es.refreshCA()
                    changed = true
                }
            }
        }
        return changed
    }

    /// Share sheet copy of the editor text as `<name>.conf` (temporary; it can hold node secrets and the MitM key).
    func exportConfFile(of p: Profile?, name: String, text: String) -> URL? {
        guard !text.isEmpty else { return nil }
        Self.purgeExports()
        let dir = Self.exportDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var base = (p?.name ?? name).components(separatedBy: CharacterSet(charactersIn: "/\\:?*\"<>|\n\r")).joined(separator: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if base.isEmpty || base.hasPrefix(".") { base = "profile" + base }
        let url = dir.appendingPathComponent(String(base.prefix(80)) + ".conf")
        do { try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtection]) } catch { return nil }
        return url
    }

    /// Downloads a remote profile, parses subscription-userinfo, validates, and writes it.
    private func download(_ input: Profile) async throws -> Profile {
        var p = input
        guard let s = p.url, let url = URL(string: s), url.scheme?.hasPrefix("http") == true else { throw StoreError.badURL }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue(SubscriptionUA.migrated(p.userAgent), forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        let http = resp as? HTTPURLResponse
        if let code = http?.statusCode, !(200..<300).contains(code) { throw StoreError.http(code) }
        // v0.19.2: same decoder as opened files (UTF-8 with the BOM stripped, UTF-16, GB18030). A BOM used to stay in
        // the text and a GBK-encoded subscription was reported as 「订阅内容为空」.
        guard var text = ImportRouter.decodeText(data), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw StoreError.empty }
        text = Self.normalize(text)
        if let err = await Self.validate(text: text) { throw StoreError.invalid(err) }
        try await Self.writeProfile(text, to: p.fileURL)
        p.userInfo = SubscriptionUserInfo.parse(http?.value(forHTTPHeaderField: "subscription-userinfo")) ?? p.userInfo
        if p.name.trimmingCharacters(in: .whitespaces).isEmpty {
            p.name = Self.nameFromHeaders(http) ?? url.host ?? "订阅"
        }
        p.lastUpdated = Date()
        return p
    }

    static func nameFromHeaders(_ http: HTTPURLResponse?) -> String? {
        if let t = http?.value(forHTTPHeaderField: "profile-title"), !t.isEmpty {
            if t.hasPrefix("base64:"), let d = Data(base64Encoded: String(t.dropFirst(7))), let s = String(data: d, encoding: .utf8) { return s }
            return t
        }
        if let cd = http?.value(forHTTPHeaderField: "Content-Disposition") {
            // v0.19.5: RFC 5987 parameters are case-insensitive (`filename*=utf-8''…` from many panels fell back to
            // the host name), `filename="a.yaml"; size=1` kept the rest after the quote, .yml was not stripped.
            if let r = cd.range(of: "filename*=utf-8''", options: .caseInsensitive) {
                let raw = String(cd[r.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
                if let dec = raw.trimmingCharacters(in: .whitespaces).removingPercentEncoding, !dec.isEmpty { return Self.stripYAMLExtension(dec) }
            }
            if let r = cd.range(of: "filename=", options: .caseInsensitive) {
                var rest = String(cd[r.upperBound...]).trimmingCharacters(in: .whitespaces)
                if rest.hasPrefix("\"") {
                    rest.removeFirst()
                    rest = String(rest.prefix { $0 != "\"" })
                } else {
                    rest = rest.split(separator: ";").first.map(String.init) ?? ""
                }
                let raw = rest.trimmingCharacters(in: .whitespaces)
                if !raw.isEmpty { return Self.stripYAMLExtension(raw) }
            }
        }
        return nil
    }

    nonisolated static func stripYAMLExtension(_ s: String) -> String {
        for ext in [".yaml", ".yml"] where s.lowercased().hasSuffix(ext) && s.count > ext.count {
            return String(s.dropLast(ext.count))
        }
        return s
    }

    /// v0.19.2 merge of a finished download into the entry as it is now (rename / interval / User-Agent edits
    /// made during the download stay; only the download's results are taken).
    nonisolated static func mergeRefreshed(current: Profile, downloaded: Profile) -> Profile {
        var np = current
        np.userInfo = downloaded.userInfo
        np.lastUpdated = downloaded.lastUpdated
        if np.name.trimmingCharacters(in: .whitespaces).isEmpty { np.name = downloaded.name }
        return np
    }

    func refresh(_ p: Profile) async -> String? {
        // feat/group-order: updating an 自定义 copy of a subscription updates its source (which regenerates the copy).
        if p.kind == .local, let src = source(of: p), src.kind == .remote { return await refresh(src) }
        guard p.kind == .remote else { return nil }
        // v0.19.2: one download per profile at a time (manual 更新 + the foreground auto-update pass could run
        // two, each reloading the tunnel).
        guard !updating.contains(p.id) else { return nil }
        updating.insert(p.id)
        defer { updating.remove(p.id) }
        do {
            SnapshotStore.shared.capture(String(localized: "更新订阅「\(p.name)」前"))
            let downloaded = try await download(p)
            // v0.19.2: merge into the entry as it is now. Writing back the copy taken before the download undid a
            // rename / interval / User-Agent change made meanwhile; a profile deleted meanwhile stays deleted.
            guard let cur = profiles.first(where: { $0.id == p.id }) else {
                try? FileManager.default.removeItem(at: p.fileURL)
                return nil
            }
            let np = Self.mergeRefreshed(current: cur, downloaded: downloaded)
            update(np)
            UsageAlerts.evaluate(id: np.id, name: np.name, info: np.userInfo)
            let (copies, notes) = await regenerateCopies(of: np)
            // v0.19: re-run the override scripts of the profile (and of its 自定义 copies) now, so an on-demand
            // connect later still finds a current output (the reload below skips them again when nothing else changed).
            for q in [np] + copies where OverrideScriptStore.shared.enabledCount(q.id) > 0 {
                await OverrideScriptStore.shared.apply(q, force: false)
            }
            if np.id == activeID || copies.contains(where: { $0.id == activeID }) { _ = await VPNManager.shared.reload() }
            // The subscription itself updated; a copy that could not follow it is reported.
            return notes.isEmpty ? nil : notes.joined(separator: "\n")
        } catch {
            return error.localizedDescription
        }
    }

    func refreshAll() async -> [String] {
        var errors: [String] = []
        for p in profiles where p.kind == .remote && p.enabled {
            if let e = await refresh(p) { errors.append("\(p.name)：\(e)") }
        }
        return errors
    }

    /// Updates remote profiles whose interval has elapsed (foreground + background refresh, v0.14 results
    /// for the update notification).
    @discardableResult
    func autoUpdateIfNeeded() async -> [SubUpdateResult] {
        var out: [SubUpdateResult] = []
        for p in profiles where p.kind == .remote && p.enabled && p.updateIntervalHours > 0 {
            let due = (p.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(p.updateIntervalHours) * 3600)
            if due < Date() { out.append(SubUpdateResult(name: p.name, error: await refresh(p))) }
        }
        return out
    }

    // MARK: feat/group-order — 自定义 copies

    /// The profile `p` was copied from (nil for an original, or when the source was deleted).
    func source(of p: Profile) -> Profile? {
        guard let id = p.sourceID else { return nil }
        return profiles.first { $0.id == id }
    }

    /// The 自定义 copy of `p` (the first reorder of `p` made it), if any.
    func orderCopy(of p: Profile) -> Profile? { profiles.first { $0.sourceID == p.id } }

    /// Adds a new 自定义 copy right after its source.
    func insertCopy(_ c: Profile, after src: Profile) {
        let i = profiles.firstIndex(where: { $0.id == src.id }).map { $0 + 1 } ?? profiles.endIndex
        profiles.insert(c, at: i)
        persist()
    }

    /// After a subscription update: rebuilds every 自定义 copy of `src` from the fresh content with the copy's saved
    /// order, and carries the subscription info over. A copy the user edited is left as it is (copyModified).
    /// Returns the copies and one message per copy that did not follow the update.
    @discardableResult
    func regenerateCopies(of src: Profile) async -> ([Profile], [String]) {
        let copies = profiles.filter { $0.sourceID == src.id }
        var notes: [String] = []
        for c in copies {
            let r = await GroupOrder.regenerate(c, from: src)
            guard var nc = profiles.first(where: { $0.id == c.id }) else { continue }
            nc.copyModified = r.modified ? true : nil
            if r.modified {
                notes.append(String(localized: "「\(c.displayName)」副本已手动修改，没有随订阅更新。可在配置列表中选择「从订阅重新生成」。"))
            } else {
                nc.userInfo = src.userInfo
                nc.lastUpdated = src.lastUpdated
                if let e = r.error { notes.append(String(localized: "「\(c.displayName)」无法保持策略组顺序，已恢复为订阅的顺序：\(e)")) }
            }
            nc.sourceName = src.displayName
            update(nc)
        }
        if !copies.isEmpty { objectWillChange.send() }
        return (copies, notes)
    }

    /// 「从订阅重新生成」 on an edited copy: replaces its content with the subscription's (saved order applied;
    /// the edited file is kept as .bak). Returns an error / note or nil.
    func regenerateCopy(_ c: Profile) async -> String? {
        guard let src = source(of: c) else { return nil }
        SnapshotStore.shared.capture(String(localized: "重新生成「\(c.name)」前"))
        let r = await GroupOrder.regenerate(c, from: src, force: true)
        if var nc = profiles.first(where: { $0.id == c.id }) {
            nc.copyModified = nil
            nc.userInfo = src.userInfo
            nc.lastUpdated = src.lastUpdated
            update(nc)
        }
        if OverrideScriptStore.shared.enabledCount(c.id) > 0 { await OverrideScriptStore.shared.apply(c, force: false) }
        if r.changed, c.id == activeID { _ = await VPNManager.shared.reload() }
        await ProfileInspector.shared.load()
        return r.error.map { String(localized: "「\(c.displayName)」无法保持策略组顺序，已恢复为订阅的顺序：\($0)") }
    }

    /// The 自定义 copies made from `p` (shown before deleting it).
    func copies(of p: Profile) -> [Profile] { profiles.filter { $0.sourceID == p.id } }

    // MARK: Manual nodes (Shadowrocket style) — a local profile "手动节点"

    static let manualID = "manual-nodes"

    var manualProfile: Profile? { profiles.first { $0.id == Self.manualID } }

    @discardableResult
    func ensureManualProfile() -> Profile {
        if let p = manualProfile { return p }
        let p = Profile(id: Self.manualID, name: "手动节点", kind: .local)
        if !FileManager.default.fileExists(atPath: p.fileURL.path) {
            _ = NCManualNodes.delete(path: p.fileURL.path, name: "") // writes an empty manual profile
        }
        profiles.insert(p, at: 0)
        persist()
        return p
    }

    func manualNodes() -> [[String: Any]] {
        Self.manualNodes(path: manualProfile?.fileURL.path)
    }

    /// v0.19.6: callable off the main actor (NodeManagerModel.reload).
    nonisolated static func manualNodes(path: String?) -> [[String: Any]] {
        guard let path else { return [] }
        return NCManualNodes.list(path: path)
    }

    /// Parses links / lines and adds them. Returns the number of nodes added.
    func addManualNodes(text: String) async throws -> Int {
        SnapshotStore.shared.capture(String(localized: "添加手动节点前"))
        let p = ensureManualProfile()
        // v0.19.6: parse + write off the main actor (pasting a few thousand links froze the UI).
        let path = p.fileURL.path
        let (n, err) = await Task.detached(priority: .userInitiated) { () -> (Int32, String) in
            NCManualNodes.addText(path: path, text: text)
        }.value
        if n < 0 { throw StoreError.invalid(err) }
        objectWillChange.send()
        if activeID == nil { _ = await setActive(p) } else if activeID == p.id { _ = await VPNManager.shared.reload() }
        return Int(n)
    }

    func upsertManualNode(_ node: [String: Any], oldName: String?) async throws {
        SnapshotStore.shared.capture(String(localized: "编辑手动节点前"))
        let p = ensureManualProfile()
        let err = NCManualNodes.upsert(path: p.fileURL.path, node: node, oldName: oldName)
        if !err.isEmpty { throw StoreError.invalid(err) }
        objectWillChange.send()
        if activeID == nil { _ = await setActive(p) } else if activeID == p.id { _ = await VPNManager.shared.reload() }
    }

    // MARK: v0.15.4 nodes defined in a profile file (节点管理 → 配置 · <profile>)

    struct NodeDeleteCheck: Decodable {
        var groups: [String]?
        var emptyGroups: [String]?
        var rules: Int?
        var dialers: [String]?
        var error: String?
    }

    /// The full proxy entry of `name` in the profile file, or nil (not defined there, e.g. a provider node).
    nonisolated static func profileNode(_ p: Profile, _ name: String) -> [String: Any]? {
        let json = NCProfileNodes.get(path: p.fileURL.path, name: name)
        guard !json.isEmpty, let o = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else { return nil }
        return o
    }

    /// Writes `node` into the profile (in place; a new entry when oldName is nil), renames every reference on a
    /// rename, keeps <file>.bak + a snapshot, and reloads the core when this profile is running.
    func upsertProfileNode(_ p: Profile, _ node: [String: Any], oldName: String?) async throws {
        SnapshotStore.shared.capture(String(localized: "编辑配置节点前"))
        let data = try JSONSerialization.data(withJSONObject: node)
        let json = String(decoding: data, as: UTF8.self)
        let path = p.fileURL.path, home = AppShared.homeURL.path
        let newName = (node["name"] as? String ?? "").trimmingCharacters(in: .whitespaces)
        let renamed = oldName != nil && oldName != newName
        var pinned: [String] = []
        if renamed, p.id == activeID, let oldName { pinned = await NameRefs.selectionsUsing(oldName) }
        let err = await Task.detached(priority: .userInitiated) { NCProfileNodes.upsert(homeDir: home, path: path, nodeJSON: json, oldName: oldName ?? "") }.value
        if !err.isEmpty { throw StoreError.invalid(err) }
        if renamed, let oldName { NameRefs.rename(oldName, to: newName, profileID: p.id, isGroup: false) }
        objectWillChange.send()
        if p.id == activeID {
            _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0)
            await NameRefs.reselect(pinned, newName)
        }
    }

    func duplicateProfileNode(_ p: Profile, _ name: String) async throws -> String {
        SnapshotStore.shared.capture(String(localized: "编辑配置节点前"))
        let path = p.fileURL.path, home = AppShared.homeURL.path, suffix = String(localized: "副本")
        let nn = await Task.detached(priority: .userInitiated) { NCProfileNodes.duplicate(homeDir: home, path: path, name: name, suffix: suffix) }.value
        if nn.isEmpty { throw StoreError.invalid(NCProfileNodes.lastError) }
        objectWillChange.send()
        if p.id == activeID { _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0) }
        return nn
    }

    nonisolated static func profileNodeDeleteCheck(_ p: Profile, _ name: String) -> NodeDeleteCheck {
        let json = NCProfileNodes.deleteCheck(path: p.fileURL.path, name: name)
        return (try? JSONDecoder().decode(NodeDeleteCheck.self, from: Data(json.utf8))) ?? NodeDeleteCheck(error: json)
    }

    func deleteProfileNode(_ p: Profile, _ name: String) async throws {
        SnapshotStore.shared.capture(String(localized: "编辑配置节点前"))
        let path = p.fileURL.path, home = AppShared.homeURL.path
        let err = await Task.detached(priority: .userInitiated) { NCProfileNodes.delete(homeDir: home, path: path, name: name) }.value
        if !err.isEmpty { throw StoreError.invalid(err) }
        NameRefs.rename(name, to: nil, profileID: p.id, isGroup: false)
        objectWillChange.send()
        if p.id == activeID { _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0) }
    }

    /// One-level undo of the last profile node edit (<file>.bak).
    func undoProfileNodeEdit(_ p: Profile) async throws {
        let err = NCProfileNodes.undo(path: p.fileURL.path)
        if !err.isEmpty { throw StoreError.invalid(err) }
        objectWillChange.send()
        if p.id == activeID { _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0) }
    }

    func deleteManualNode(_ name: String) async {
        guard let p = manualProfile else { return }
        _ = NCManualNodes.delete(path: p.fileURL.path, name: name)
        objectWillChange.send()
        if activeID == p.id { _ = await VPNManager.shared.reload() }
    }
}

