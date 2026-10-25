import Foundation
import Security

// 完整导出（.conf）— user decision 2026-10-25: ONE plain-text .conf modelled on Quantumult X's exported
// configuration, always carrying everything (no options, no password prompt):
//   the profile (its YAML exactly as stored, incl. 自定义 copy edits), remote rewrites / modules / plugins with their
//   argument values and policy mappings, local rewrite and script lines, local script files, the profile's override
//   scripts, node subscriptions (URL + settings), MitM settings, and the MitM root CA + private key as a
//   passphrase-encrypted PKCS#12 with the passphrase next to it in plain text (exactly like QX's `passphrase` / `p12`).
// Left out: logs, request records, traffic statistics, geo databases, downloaded rule-set / node-set caches.
// Optional (user 2026-10-25 18:20, off by default): the scripts' key-value store and controller + LAN secrets
// (engine/store.json, secrets.json — cookies, tokens, passwords) via build(includeSensitive: true).
//
// File layout (INI sections, '#' comments; every free-form payload is base64 so a YAML line such as "[general]" can
// never be read as a section):
//
//   # Tern 完整导出 · Full Export  (header comments: app version, export time, private-key warning)
//   [general]            tern-export = 1, app-version, app-build, exported, rewrite = <bool>, script = <bool>
//   [profile]            name / kind / url (readable), format = yaml, meta = b64(JSON Profile), content = b64(YAML)
//   [server_remote]      <url>, tag=<name>, update-interval=<s>, enabled=<bool>, tern-meta=b64(JSON node subscription)
//   [rewrite_remote]     <url | tern-local>, tag=, update-interval=, opt-parser=false, enabled=, type=, id=, updated=,
//                        argument=b64(JSON args), policy=b64(JSON policy mapping)
//   [module_cache]       <module id> = b64(module text)      (downloaded body; the only copy for local modules)
//   [rewrite_local]      rewrite lines verbatim; "#line" = disabled; "#!note = …" before a line; "#!item = b64(JSON)"
//                        for a line that cannot be written verbatim
//   [script_rewrite_local]  script lines, same encoding
//   [script_resource]    <path or url>, disabled=<bool>, interval=<s>
//   [script_local]       <file name> = b64(file)
//   [override_script]    <name>, id=, enabled=, url=, meta=b64(JSON), content=b64(js)
//   [mitm]               enable, hostname = a, b, -c, skip_validating_cert, h2, capture-bodies, quic, quic-allow,
//                        passphrase = <random>, p12 = b64(PKCS#12 of CA cert + private key)
//   [tern_data]          <container-relative path> = b64(file)   (DNS, custom rules, group edits, node settings …)
//   [tern_prefs]         <g:|s:key> = b64(binary plist [value])   (app settings, the same set as 备份与恢复)
//   [end]
//
// Import: parse() decodes and validates everything (header version, every base64 value, every name, the p12 with its
// passphrase) into a Payload in memory; apply() then plans every file, stages them in a scratch directory inside the
// container and moves them into place, rolling back the moved ones if a move fails — an error writes nothing.

enum TernFullExport {
    static let formatVersion = 1
    static let magicKey = "tern-export"
    static let localModuleURL = "tern-local"

    /// Container-relative settings files carried verbatim in [tern_data] (the restore whitelist).
    static let dataFiles = ["mihomo/overrides.json", "mihomo/dns.json", "mihomo/localdns.json", "mihomo/group-icons.json",
                            "mihomo/rules.json", "mihomo/subscriptions.json", "mihomo/groups.json", "mihomo/netpolicy.json",
                            "mihomo/group-edits.json", "mihomo/provider-overrides.json", "mihomo/node-settings.json"]
    /// Opt-in only (完整导出（含脚本数据与密码）): script cookies / tokens and controller + LAN passwords.
    static let sensitiveDataFiles = ["mihomo/engine/store.json", "mihomo/secrets.json"]
    /// Import whitelist: whatever of these the file carries is restored.
    static var allDataFiles: [String] { dataFiles + sensitiveDataFiles }

    // Container-relative locations (the same layout as AppShared / EnginePaths / OverrideScriptStore).
    static let profilesIndexRel = "profiles.json"
    static func profileRel(_ id: String) -> String { "profiles/\(id).yaml" }
    static let engineRel = "mihomo/engine/engine.json"
    static func moduleRel(_ id: String) -> String { "mihomo/engine/modules/\(EnginePaths.safe(id)).txt" }
    static let scriptsRel = "mihomo/engine/scripts"
    static let overrideIndexRel = "mihomo/override-scripts/index.json"
    static func overrideContentRel(_ id: String) -> String { "mihomo/override-scripts/\(id).js" }
    static let nodeSubsRel = "mihomo/node-subscriptions.json"
    static let caPemRel = "mihomo/engine/ca/ca.pem"
    static let caKeyRel = "mihomo/engine/ca/ca.key"

    enum ExportError: LocalizedError, Equatable {
        case notAnExport
        case unsupportedVersion(Int)
        case corrupt(String)
        case badCertificate(String)
        case missingProfile
        case readFailed(String)
        case writeFailed(String)

        var errorDescription: String? {
            switch self {
            case .notAnExport: return String(localized: "不是 Tern 完整导出文件")
            case .unsupportedVersion(let v): return String(localized: "导出文件版本 \(v) 不受支持，请更新 Tern")
            case .corrupt(let w): return String(localized: "导出文件已损坏：\(w)")
            case .badCertificate(let w): return String(localized: "MitM 证书无法解开（口令错误或 p12 已损坏）：\(w)")
            case .missingProfile: return String(localized: "导出文件里没有配置")
            case .readFailed(let w): return String(localized: "无法读取：\(w)")
            case .writeFailed(let w): return String(localized: "写入失败：\(w)")
            }
        }
    }

    struct ScriptFile: Equatable {
        var name: String
        var content: Data
    }

    struct OverrideScriptEntry: Equatable {
        var id: String
        /// One element of override-scripts/index.json (JSON object, kept byte-for-byte as exported).
        var meta: Data
        /// nil = the exported device had no .js for it; the import leaves the target's file alone.
        var content: Data?
    }

    struct MitMSettings: Equatable {
        var enabled = false
        var hostnames: [String] = []
        var skipCertVerify = false
        var h2: Bool? = true
        var captureBodies: Bool? = true
        var quic: String? = nil
        var quicAllow: [String]? = nil
    }

    /// Everything a full export carries, decoded and validated.
    struct Payload {
        var appVersion = ""
        var appBuild = ""
        var exported = ""
        var profile: Profile
        var profileYAML: Data
        var rewriteEnabled = false
        var scriptsEnabled = false
        var modules: [EngineModule] = []
        /// module id → downloaded module text.
        var moduleCache: [String: Data] = [:]
        var rules: [EngineItem] = []
        var scriptRules: [EngineItem] = []
        var scriptResources: [String: ScriptResourceSetting] = [:]
        var scripts: [ScriptFile] = []
        var overrideScripts: [OverrideScriptEntry] = []
        /// node-subscriptions.json elements (JSON objects). nil = the export had no [server_remote] section.
        var nodeSubscriptions: [Data]? = nil
        var mitm = MitMSettings()
        /// PEM ca.pem / ca.key decoded from the p12 (nil = no CA in the export).
        var caPEM: (cert: Data, key: Data)? = nil
        var dataFiles: [String: Data] = [:]
        var prefs: [String: String] = [:]

        /// One line per kind for the confirmation sheet.
        var summaryLines: [String] {
            var out: [String] = []
            out.append(String(localized: "配置：\(profile.name)"))
            out.append(String(localized: "远程重写 / 模块 / 插件：\(modules.count) 个"))
            out.append(String(localized: "本地重写：\(rules.count) 条 · 脚本规则：\(scriptRules.count) 条"))
            out.append(String(localized: "本地脚本：\(scripts.count) 个 · 覆写脚本：\(overrideScripts.count) 个"))
            if let n = nodeSubscriptions?.count, n > 0 { out.append(String(localized: "节点订阅：\(n) 个")) }
            out.append(String(localized: "MitM 主机名：\(mitm.hostnames.count) 个"))
            out.append(caPEM != nil ? String(localized: "MitM 根证书和私钥：包含") : String(localized: "MitM 根证书和私钥：不包含"))
            if !dataFiles.isEmpty || !prefs.isEmpty {
                out.append(String(localized: "DNS、自定义规则与其他设置：\(dataFiles.count + prefs.count) 项"))
            }
            if !exported.isEmpty { out.append(String(localized: "导出于 \(exported) · Tern \(appVersion)")) }
            return out
        }
    }

    // MARK: - Detection

    /// True when the text is a Tern full export: the first section is [general] and it carries `tern-export = <n>`.
    /// A plain Surge / QX .conf (no such key) keeps going through the existing import path.
    static func isFullExport(_ text: String) -> Bool {
        var inGeneral = false
        var scanned = 0
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            scanned += 1
            if scanned > 200 { return false }
            var line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("\u{FEFF}") { line.removeFirst() }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if let s = sectionName(line) {
                if s == "general" { inGeneral = true; continue }
                return false
            }
            guard inGeneral else { return false }
            if let kv = keyValue(line), kv.0 == magicKey { return true }
        }
        return false
    }

    // MARK: - Export

    /// Builds the export text for `profileID` (nil = the active profile) from the container at `root`.
    /// `prefs`: BackupManager.collectPrefs() in the app; nil in unit tests.
    static func build(profileID: String?, root: URL, defaults: UserDefaults, prefs: [String: String]? = nil,
                      appVersion: String, appBuild: String, now: Date = Date(),
                      passphrase: String = randomPassphrase(), includeSensitive: Bool = false) throws -> String {
        let fm = FileManager.default
        func url(_ rel: String) -> URL { root.appendingPathComponent(rel) }
        func readIfPresent(_ rel: String) throws -> Data? {
            let u = url(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir), !isDir.boolValue else { return nil }
            do { return try Data(contentsOf: u) } catch { throw ExportError.readFailed(rel) }
        }

        // Profile
        let profiles = (try readIfPresent(profilesIndexRel)).flatMap { try? JSONDecoder().decode([Profile].self, from: $0) } ?? []
        let wanted = profileID ?? defaults.string(forKey: "activeProfileID")
        guard let profile = profiles.first(where: { $0.id == wanted }) ?? (profileID == nil ? profiles.first : nil) else {
            throw ExportError.missingProfile
        }
        guard let yaml = try readIfPresent(profileRel(profile.id)) else { throw ExportError.readFailed(profile.name) }

        // Engine (rewrites, scripts, modules, MitM)
        var engine = EngineConfig()
        if let d = try readIfPresent(engineRel), let c = try? JSONDecoder().decode(EngineConfig.self, from: d) { engine = c }

        var out = ""
        func line(_ s: String = "") { out += s + "\n" }
        func kv(_ k: String, _ v: String) { line("\(k) = \(v)") }

        let iso = DateFormatter()
        iso.locale = Locale(identifier: "en_US_POSIX")
        iso.timeZone = TimeZone(identifier: "UTC")
        iso.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        let exportedAt = iso.string(from: now)
        let local = DateFormatter()
        local.locale = Locale(identifier: "en_US_POSIX")
        local.dateFormat = "yyyy-MM-dd HH:mm:ss ZZZZZ"

        line("# Tern 完整导出 · Full Export")
        line("# Tern \(appVersion) (\(appBuild)) · \(local.string(from: now))")
        line("# 包含：配置、远程重写 / 模块 / 插件、本地重写、脚本、覆写脚本、节点订阅、MitM 设置、MitM 根证书和私钥。")
        line("# Contains the profile, rewrites, modules, scripts, MitM settings and the MitM root CA WITH ITS PRIVATE KEY.")
        line("# 私钥能解密信任此证书的设备上的 HTTPS 流量，请只保存在自己的位置。Keep this file private.")
        line("# 用 Tern 打开此文件即可全部恢复。Open this file in Tern to restore everything.")
        line()

        line("[general]")
        kv(magicKey, String(formatVersion))
        kv("app-version", oneLine(appVersion))
        kv("app-build", oneLine(appBuild))
        kv("exported", exportedAt)
        kv("rewrite", String(engine.enabled))
        kv("script", String(engine.scriptsEnabled))
        line()

        line("[profile]")
        kv("name", oneLine(profile.name))
        kv("kind", profile.kind.rawValue)
        if let u = profile.url, !u.isEmpty { kv("url", oneLine(u)) }
        kv("format", "yaml")
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let meta = try? enc.encode(profile) else { throw ExportError.readFailed(profile.name) }
        kv("meta", meta.base64EncodedString())
        kv("content", yaml.base64EncodedString())
        line()

        if let d = try readIfPresent(nodeSubsRel), let arr = (try? JSONSerialization.jsonObject(with: d)) as? [[String: Any]] {
            line("[server_remote]")
            for s in arr {
                guard let m = try? JSONSerialization.data(withJSONObject: s, options: [.sortedKeys]) else { continue }
                var f = [urlField(s["url"] as? String ?? "")]
                f.append("tag=" + esc(s["name"] as? String ?? ""))
                if let h = s["updateIntervalHours"] as? Int { f.append("update-interval=\(h * 3600)") }
                f.append("enabled=\((s["enabled"] as? Bool) ?? true)")
                f.append("tern-meta=" + m.base64EncodedString())
                line(f.joined(separator: ", "))
            }
            line()
        }

        line("[rewrite_remote]")
        var cache: [(String, Data)] = []
        var usedIDs = Set<String>()
        for m in engine.modules {
            let text = try readIfPresent(moduleRel(m.id))
            // The import only takes ids that are their own cache file name; an older id is written as that file name
            // (EnginePaths.safe — the file it already uses), made unique.
            var xid = isModuleID(m.id) ? m.id : EnginePaths.safe(m.id)
            if !isModuleID(xid) { xid = UUID().uuidString }
            if usedIDs.contains(xid) { var n = 2; while usedIDs.contains("\(xid)-\(n)") { n += 1 }; xid = "\(xid)-\(n)" }
            usedIDs.insert(xid)
            if let text { cache.append((xid, text)) }
            var f = [m.url.isEmpty ? localModuleURL : urlField(m.url)]
            f.append("tag=" + esc(m.name))
            if let i = m.interval { f.append("update-interval=\(i)") }
            f.append("opt-parser=false")
            f.append("enabled=\(m.enabled)")
            f.append("type=" + moduleType(url: m.url, text: text))
            f.append("id=" + esc(xid))
            if let u = m.updatedAt { f.append("updated=\(u)") }
            if let a = m.args, let d = try? enc.encode(a) { f.append("argument=" + d.base64EncodedString()) }
            if let p = m.policies, let d = try? enc.encode(p) { f.append("policy=" + d.base64EncodedString()) }
            line(f.joined(separator: ", "))
        }
        line()

        line("[module_cache]")
        for (id, d) in cache { kv(esc(id), d.base64EncodedString()) }
        line()

        line("[rewrite_local]")
        for it in engine.rules { writeItem(it, into: &out) }
        line()

        line("[script_rewrite_local]")
        for it in engine.scripts { writeItem(it, into: &out) }
        line()

        line("[script_resource]")
        for (k, v) in (engine.scriptResources ?? [:]).sorted(by: { $0.key < $1.key }) {
            var f = [esc(k)]
            if let d = v.disabled { f.append("disabled=\(d)") }
            if let i = v.interval { f.append("interval=\(i)") }
            line(f.joined(separator: ", "))
        }
        line()

        line("[script_local]")
        let scriptsDir = url(scriptsRel)
        for name in ((try? fm.contentsOfDirectory(atPath: scriptsDir.path)) ?? []).sorted() where !name.hasPrefix(".") {
            let rel = scriptsRel + "/" + name
            if let d = try readIfPresent(rel) { kv(esc(name), d.base64EncodedString()) }
        }
        line()

        line("[override_script]")
        if let d = try readIfPresent(overrideIndexRel),
           let index = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           let list = index[profile.id] as? [[String: Any]] {
            for s in list {
                guard let id = s["id"] as? String, isSafeName(id),
                      let m = try? JSONSerialization.data(withJSONObject: s, options: [.sortedKeys]) else { continue }
                let content = try readIfPresent(overrideContentRel(id))
                var f = [esc(s["name"] as? String ?? id), "id=" + esc(id), "enabled=\((s["enabled"] as? Bool) ?? true)"]
                if let u = s["url"] as? String, !u.isEmpty { f.append("url=" + urlField(u)) }
                f.append("meta=" + m.base64EncodedString())
                if let content { f.append("content=" + content.base64EncodedString()) }
                line(f.joined(separator: ", "))
            }
        }
        line()

        line("[mitm]")
        kv("enable", String(engine.mitm))
        kv("hostname", engine.hostnames.map(oneLine).joined(separator: ", "))
        kv("skip_validating_cert", String(engine.skipCertVerify))
        if let h = engine.h2 { kv("h2", String(h)) }
        if let c = engine.captureBodies { kv("capture-bodies", String(c)) }
        if let q = engine.quic { kv("quic", oneLine(q)) }
        if let q = engine.quicAllow { kv("quic-allow", q.map(oneLine).joined(separator: ", ")) }
        let home = root.appendingPathComponent("mihomo").path
        if NCCAManager.loadCA(home: home) != nil {
            let p12: Data
            do { p12 = try NCCAManager.exportP12(home: home, password: passphrase) } catch {
                throw ExportError.readFailed("MitM CA: \(error.localizedDescription)")
            }
            kv("passphrase", passphrase)
            kv("p12", p12.base64EncodedString())
        }
        line()

        line("[tern_data]")
        for rel in dataFiles + (includeSensitive ? sensitiveDataFiles : []) {
            if let d = try readIfPresent(rel) { kv(esc(rel), d.base64EncodedString()) }
        }
        line()

        if let prefs, !prefs.isEmpty {
            line("[tern_prefs]")
            for (k, v) in prefs.sorted(by: { $0.key < $1.key }) { kv(esc(k), v) }
            line()
        }

        line("[end]")
        return out
    }

    static func randomPassphrase(length: Int = 24) -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
        var bytes = [UInt8](repeating: 0, count: length)
        if SecRandomCopyBytes(kSecRandomDefault, length, &bytes) != errSecSuccess {
            for i in 0..<length { bytes[i] = UInt8.random(in: 0...255) }
        }
        return String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }

    /// Item lines: verbatim when they survive the round trip as text, else the JSON form.
    private static func writeItem(_ it: EngineItem, into out: inout String) {
        let l = it.line
        let verbatim = !l.isEmpty && l == l.trimmingCharacters(in: .whitespacesAndNewlines)
            && !l.contains("\n") && !l.contains("\r")
            && !l.hasPrefix("#") && !l.hasPrefix(";") && !l.hasPrefix("[") && !l.hasPrefix("!")
        if verbatim {
            if let n = it.note { out += "#!note = " + esc(n) + "\n" }
            out += (it.enabled ? "" : "#") + l + "\n"
        } else {
            var obj: [String: Any] = ["line": l, "enabled": it.enabled]
            if let n = it.note { obj["note"] = n }
            let d = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
            out += "#!item = " + d.base64EncodedString() + "\n"
        }
    }

    /// Informational engine type of a module (ignored on import).
    static func moduleType(url: String, text: Data?) -> String {
        if let text, let s = String(data: text, encoding: .utf8), !s.isEmpty {
            let c = ImportTools.classifyText(s)
            switch c {
            case "module:egern": return "egern"
            case "module:stash": return "stash"
            case "module:loon": return "loon"
            case "module:qx": return "quanx"
            default: if c.hasPrefix("module:") { return "surge" }
            }
        }
        switch (URL(string: url)?.pathExtension.lowercased() ?? "") {
        case "plugin", "lpx": return "loon"
        case "snippet", "conf": return "quanx"
        case "stoverride": return "stash"
        case "yaml", "yml": return "egern"
        case "list": return "list"
        default: return "surge"
        }
    }

    // MARK: - Escaping

    /// Percent-escapes what would break a `a, k=v` line or a `key = value` line: % , = # ; [ ] newlines, tabs and
    /// leading / trailing spaces. CJK and emoji stay readable.
    static func esc(_ s: String) -> String {
        let scalars = Array(s.unicodeScalars)
        var out = ""
        for (i, c) in scalars.enumerated() {
            switch c {
            case "%": out += "%25"
            case ",": out += "%2C"
            case "=": out += "%3D"
            case "#": out += "%23"
            case ";": out += "%3B"
            case "[": out += "%5B"
            case "]": out += "%5D"
            case "\n": out += "%0A"
            case "\r": out += "%0D"
            case "\t": out += "%09"
            case " " where i == 0 || i == scalars.count - 1: out += "%20"
            default: out.unicodeScalars.append(c)
            }
        }
        return out
    }

    static func unesc(_ s: String) -> String { s.removingPercentEncoding ?? s }

    /// URL fields: '%' → %25 and ',' → %2C so urlUnesc gives the URL back byte for byte (review 10-25 #5).
    static func urlField(_ s: String) -> String {
        oneLine(s).replacingOccurrences(of: "%", with: "%25").replacingOccurrences(of: ",", with: "%2C")
    }
    static func urlUnesc(_ s: String) -> String {
        s.replacingOccurrences(of: "%2C", with: ",").replacingOccurrences(of: "%25", with: "%")
    }

    static func oneLine(_ s: String) -> String {
        s.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
    }

    /// A file name / id that stays inside its directory.
    static func isSafeName(_ s: String) -> Bool {
        !s.isEmpty && s != "." && s != ".." && !s.contains("/") && !s.contains("\\") && !s.contains("\u{0}") && s.utf8.count <= 255
    }

    /// A module id is its cache file name as is (EnginePaths.safe(id) == id), so no two ids share one file.
    static func isModuleID(_ s: String) -> Bool { isSafeName(s) && EnginePaths.safe(s) == s }

    // MARK: - Parse

    static func sectionName(_ trimmed: String) -> String? {
        guard trimmed.count >= 3, trimmed.hasPrefix("["), trimmed.hasSuffix("]") else { return nil }
        let name = trimmed.dropFirst().dropLast()
        guard !name.isEmpty, name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }) else { return nil }
        return name.lowercased()
    }

    static func keyValue(_ line: String) -> (String, String)? {
        guard let r = line.range(of: "=") else { return nil }
        let k = line[..<r.lowerBound].trimmingCharacters(in: .whitespaces)
        let v = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
        return k.isEmpty ? nil : (k, v)
    }

    /// `first, k=v, k=v` → (unescaped-later first field, [k: v]).
    static func fields(_ line: String) -> (String, [String: String]) {
        let parts = line.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        var opts: [String: String] = [:]
        for p in parts.dropFirst() {
            if let kv = keyValue(p) { opts[kv.0.lowercased()] = kv.1 }
        }
        return (parts.first ?? "", opts)
    }

    static func b64(_ s: String, _ what: String) throws -> Data {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return Data() }
        guard let d = Data(base64Encoded: t) else { throw ExportError.corrupt(what) }
        return d
    }

    static func bool(_ s: String?) -> Bool? {
        switch s?.lowercased() {
        case "true", "1", "yes", "on": return true
        case "false", "0", "no", "off": return false
        default: return nil
        }
    }

    /// Decodes and validates a full export into memory. Writes nothing.
    static func parse(_ text: String) throws -> Payload {
        guard isFullExport(text) else { throw ExportError.notAnExport }
        var sections: [String: [String]] = [:]
        var order: [String] = []
        var current: String?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("\u{FEFF}") { line.removeFirst() }
            if line.isEmpty { continue }
            if let s = sectionName(line) {
                current = s
                if sections[s] == nil { sections[s] = []; order.append(s) }
                continue
            }
            guard let c = current else { continue } // header comments
            sections[c, default: []].append(line)
        }
        guard order.contains("end") else { throw ExportError.corrupt(String(localized: "文件不完整（缺少 [end]）")) }

        func keyValues(_ s: String) -> [(String, String)] {
            (sections[s] ?? []).compactMap { (l: String) -> (String, String)? in
                if l.hasPrefix("#") || l.hasPrefix(";") { return nil }
                return keyValue(l)
            }
        }
        func dict(_ s: String) -> [String: String] {
            var m: [String: String] = [:]
            for (k, v) in keyValues(s) { m[k.lowercased()] = v }
            return m
        }

        let general = dict("general")
        guard let vs = general[magicKey], let v = Int(vs) else { throw ExportError.corrupt("[general] \(magicKey)") }
        guard v <= formatVersion else { throw ExportError.unsupportedVersion(v) }

        // [profile]
        guard sections["profile"] != nil else { throw ExportError.missingProfile }
        let pf = dict("profile")
        if let f = pf["format"], f.lowercased() != "yaml" { throw ExportError.corrupt("[profile] format=\(f)") }
        guard let metaS = pf["meta"], let contentS = pf["content"] else { throw ExportError.missingProfile }
        let meta = try b64(metaS, "[profile] meta")
        guard let profile = try? JSONDecoder().decode(Profile.self, from: meta) else { throw ExportError.corrupt("[profile] meta") }
        guard isSafeName(profile.id) else { throw ExportError.corrupt("[profile] id") }
        let yaml = try b64(contentS, "[profile] content")

        var p = Payload(profile: profile, profileYAML: yaml)
        p.appVersion = general["app-version"] ?? ""
        p.appBuild = general["app-build"] ?? ""
        p.exported = general["exported"] ?? ""
        p.rewriteEnabled = bool(general["rewrite"]) ?? false
        p.scriptsEnabled = bool(general["script"]) ?? p.rewriteEnabled

        // [server_remote]
        if let lines = sections["server_remote"] {
            var subs: [Data] = []
            for l in lines where !l.hasPrefix("#") && !l.hasPrefix(";") {
                let (u, o) = fields(l)
                if let m = o["tern-meta"] {
                    let d = try b64(m, "[server_remote] \(u)")
                    guard (try? JSONSerialization.jsonObject(with: d)) is [String: Any] else { throw ExportError.corrupt("[server_remote] \(u)") }
                    subs.append(d)
                } else {
                    // A hand-written QX line: URL + tag only.
                    guard !u.isEmpty else { continue }
                    let u = urlUnesc(u)
                    var obj: [String: Any] = ["id": UUID().uuidString, "url": u, "name": unesc(o["tag"] ?? ""), "enabled": bool(o["enabled"]) ?? true,
                                              "userAgent": "clash.meta", "updateIntervalHours": max(1, (Int(o["update-interval"] ?? "") ?? 86400) / 3600)]
                    if (obj["name"] as? String)?.isEmpty == true { obj["name"] = URL(string: u)?.host ?? u }
                    if let d = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) { subs.append(d) }
                }
            }
            p.nodeSubscriptions = subs
        }

        // [rewrite_remote]
        for l in sections["rewrite_remote"] ?? [] where !l.hasPrefix("#") && !l.hasPrefix(";") {
            let (u, o) = fields(l)
            let url = u == localModuleURL ? "" : urlUnesc(u)
            let id = o["id"].map(unesc) ?? UUID().uuidString
            // review 10-25 #4: same rule as profile / script ids, so two ids can't collapse onto one cache file.
            guard isModuleID(id), !p.modules.contains(where: { $0.id == id }) else { throw ExportError.corrupt("[rewrite_remote] id") }
            let name = unesc(o["tag"] ?? "")
            var m = EngineModule(name: name.isEmpty ? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? id) : name, url: url)
            m.id = id
            m.enabled = bool(o["enabled"]) ?? true
            if let s = o["update-interval"] {
                guard let i = Int(s) else { throw ExportError.corrupt("[rewrite_remote] update-interval") }
                m.interval = i
            }
            if let s = o["updated"] {
                guard let d = Double(s) else { throw ExportError.corrupt("[rewrite_remote] updated") }
                m.updatedAt = d
            }
            if let s = o["argument"] {
                guard let a = try? JSONDecoder().decode([String: String].self, from: try b64(s, "[rewrite_remote] argument")) else {
                    throw ExportError.corrupt("[rewrite_remote] argument")
                }
                m.args = a
            }
            if let s = o["policy"] {
                guard let a = try? JSONDecoder().decode([String: String].self, from: try b64(s, "[rewrite_remote] policy")) else {
                    throw ExportError.corrupt("[rewrite_remote] policy")
                }
                m.policies = a
            }
            if p.modules.contains(where: { $0.id == m.id }) { throw ExportError.corrupt("[rewrite_remote] id \(m.id)") }
            p.modules.append(m)
        }

        // [module_cache]
        for (k, v) in keyValues("module_cache") {
            let id = unesc(k)
            guard isModuleID(id) else { throw ExportError.corrupt("[module_cache] \(k)") }
            p.moduleCache[id] = try b64(v, "[module_cache] \(id)")
        }
        // review 10-25 #3: no cache in the file → no cache written, so let the runtime refresh it.
        for i in p.modules.indices where p.moduleCache[p.modules[i].id] == nil { p.modules[i].updatedAt = nil }

        // [rewrite_local] / [script_rewrite_local]
        p.rules = try items(sections["rewrite_local"] ?? [], "rewrite_local")
        p.scriptRules = try items(sections["script_rewrite_local"] ?? [], "script_rewrite_local")

        // [script_resource]
        for l in sections["script_resource"] ?? [] where !l.hasPrefix("#") && !l.hasPrefix(";") {
            let (k, o) = fields(l)
            let key = unesc(k)
            guard !key.isEmpty else { continue }
            var s = ScriptResourceSetting()
            s.disabled = bool(o["disabled"])
            if let i = o["interval"] { s.interval = Int(i) }
            p.scriptResources[key] = s
        }

        // [script_local]
        for (k, v) in keyValues("script_local") {
            let name = unesc(k)
            guard isSafeName(name) else { throw ExportError.corrupt("[script_local] \(k)") }
            p.scripts.append(ScriptFile(name: name, content: try b64(v, "[script_local] \(name)")))
        }

        // [override_script]
        for l in sections["override_script"] ?? [] where !l.hasPrefix("#") && !l.hasPrefix(";") {
            let (n, o) = fields(l)
            guard let ms = o["meta"] else { throw ExportError.corrupt("[override_script] \(unesc(n))") }
            let meta = try b64(ms, "[override_script] \(unesc(n))")
            guard let obj = (try? JSONSerialization.jsonObject(with: meta)) as? [String: Any], let id = obj["id"] as? String, isSafeName(id) else {
                throw ExportError.corrupt("[override_script] \(unesc(n))")
            }
            p.overrideScripts.append(OverrideScriptEntry(id: id, meta: meta, content: try o["content"].map { try b64($0, "[override_script] \(unesc(n))") }))
        }

        // [mitm]
        let mm = dict("mitm")
        p.mitm.enabled = bool(mm["enable"]) ?? false
        p.mitm.hostnames = list(mm["hostname"])
        p.mitm.skipCertVerify = bool(mm["skip_validating_cert"]) ?? false
        p.mitm.h2 = mm["h2"] == nil ? nil : (bool(mm["h2"]) ?? true)
        p.mitm.captureBodies = mm["capture-bodies"] == nil ? nil : (bool(mm["capture-bodies"]) ?? true)
        p.mitm.quic = mm["quic"].flatMap { $0.isEmpty ? nil : $0 }
        p.mitm.quicAllow = mm["quic-allow"].map { list($0) }
        if let p12s = mm["p12"], !p12s.isEmpty {
            guard let pass = mm["passphrase"], !pass.isEmpty else { throw ExportError.badCertificate("passphrase") }
            let p12 = try b64(p12s, "[mitm] p12")
            do {
                let pair = try NCCAManager.pemPair(fromP12: p12, password: pass)
                p.caPEM = (cert: pair.pemCert, key: pair.pemKey)
            } catch {
                throw ExportError.badCertificate(error.localizedDescription)
            }
        }

        // [tern_data]
        for (k, v) in keyValues("tern_data") {
            let rel = unesc(k)
            guard allDataFiles.contains(rel) else { continue } // unknown paths are never written
            p.dataFiles[rel] = try b64(v, "[tern_data] \(rel)")
        }

        // [tern_prefs]
        for (k, v) in keyValues("tern_prefs") {
            let key = unesc(k)
            _ = try b64(v, "[tern_prefs] \(key)")
            p.prefs[key] = v
        }
        return p
    }

    private static func list(_ s: String?) -> [String] {
        (s ?? "").components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private static func items(_ lines: [String], _ section: String) throws -> [EngineItem] {
        var out: [EngineItem] = []
        var note: String?
        for l in lines {
            if l.hasPrefix("#!") {
                guard let kv = keyValue(String(l.dropFirst(2))) else { continue }
                let v = kv.1
                switch kv.0.lowercased() {
                case "note": note = unesc(v)
                case "item":
                    let d = try b64(v, "[\(section)] item")
                    guard let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any], let line = obj["line"] as? String else {
                        throw ExportError.corrupt("[\(section)] item")
                    }
                    var it = EngineItem(line: line)
                    it.enabled = (obj["enabled"] as? Bool) ?? true
                    it.note = obj["note"] as? String
                    out.append(it)
                    note = nil
                default: break
                }
                continue
            }
            var it: EngineItem
            if l.hasPrefix("#") || l.hasPrefix(";") {
                let body = String(l.dropFirst()).trimmingCharacters(in: .whitespaces)
                guard !body.isEmpty else { continue }
                it = EngineItem(line: body)
                it.enabled = false
            } else {
                it = EngineItem(line: l)
            }
            it.note = note
            note = nil
            out.append(it)
        }
        return out
    }

    // MARK: - Apply

    struct Write {
        var rel: String
        var data: Data
        var permissions: Int? = nil
    }

    /// Every file the payload writes, computed (reading the current profiles.json / override index / engine.json to
    /// merge into) before anything is touched.
    static func plan(_ p: Payload, root: URL) throws -> [Write] {
        let fm = FileManager.default
        var w: [Write] = []

        // profiles.json: replace the profile with the same id, else append.
        var profiles: [Profile] = []
        let idx = root.appendingPathComponent(profilesIndexRel)
        if fm.fileExists(atPath: idx.path) {
            guard let d = try? Data(contentsOf: idx), let l = try? JSONDecoder().decode([Profile].self, from: d) else {
                throw ExportError.readFailed(profilesIndexRel)
            }
            profiles = l
        }
        if let i = profiles.firstIndex(where: { $0.id == p.profile.id }) { profiles[i] = p.profile } else { profiles.append(p.profile) }
        guard let pj = try? JSONEncoder().encode(profiles) else { throw ExportError.writeFailed(profilesIndexRel) }
        w.append(Write(rel: profilesIndexRel, data: pj))
        w.append(Write(rel: profileRel(p.profile.id), data: p.profileYAML))

        // engine.json: rewrites / scripts / modules / MitM from the export; the stamped UI language is kept.
        var c = EngineConfig()
        c.enabled = p.rewriteEnabled
        c.scriptsEnabled = p.scriptsEnabled
        c.mitm = p.mitm.enabled
        c.skipCertVerify = p.mitm.skipCertVerify
        c.h2 = p.mitm.h2
        c.captureBodies = p.mitm.captureBodies
        c.hostnames = p.mitm.hostnames
        c.quic = p.mitm.quic
        c.quicAllow = p.mitm.quicAllow
        c.rules = p.rules
        c.scripts = p.scriptRules
        c.modules = p.modules
        c.scriptResources = p.scriptResources.isEmpty ? nil : p.scriptResources
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard var ej = try? enc.encode(c) else { throw ExportError.writeFailed(engineRel) }
        if let old = try? Data(contentsOf: root.appendingPathComponent(engineRel)),
           let oldObj = (try? JSONSerialization.jsonObject(with: old)) as? [String: Any], let lang = oldObj["language"] as? String,
           var obj = (try? JSONSerialization.jsonObject(with: ej)) as? [String: Any] {
            obj["language"] = lang
            if let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) { ej = d }
        }
        w.append(Write(rel: engineRel, data: ej))
        // review 10-25 #3: a module the export has no cache for keeps the target's file (or downloads on next use);
        // an empty file would truncate a good cache. Its updatedAt was cleared in parse so it refreshes.
        for m in p.modules { if let d = p.moduleCache[m.id] { w.append(Write(rel: moduleRel(m.id), data: d)) } }

        for s in p.scripts { w.append(Write(rel: scriptsRel + "/" + s.name, data: s.content)) }

        // override-scripts/index.json: this profile's list replaced, other profiles kept.
        var index: [String: Any] = [:]
        let oi = root.appendingPathComponent(overrideIndexRel)
        if fm.fileExists(atPath: oi.path) {
            guard let d = try? Data(contentsOf: oi), let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else {
                throw ExportError.readFailed(overrideIndexRel)
            }
            index = o
        }
        let entries = p.overrideScripts.compactMap { (try? JSONSerialization.jsonObject(with: $0.meta)) as? [String: Any] }
        if entries.isEmpty { index.removeValue(forKey: p.profile.id) } else { index[p.profile.id] = entries }
        if !(entries.isEmpty && !fm.fileExists(atPath: oi.path)) {
            guard let d = try? JSONSerialization.data(withJSONObject: index, options: [.prettyPrinted, .sortedKeys]) else {
                throw ExportError.writeFailed(overrideIndexRel)
            }
            w.append(Write(rel: overrideIndexRel, data: d))
        }
        for s in p.overrideScripts { if let c = s.content { w.append(Write(rel: overrideContentRel(s.id), data: c)) } }

        if let subs = p.nodeSubscriptions {
            let arr = subs.compactMap { try? JSONSerialization.jsonObject(with: $0) }
            guard let d = try? JSONSerialization.data(withJSONObject: arr, options: [.prettyPrinted, .sortedKeys]) else {
                throw ExportError.writeFailed(nodeSubsRel)
            }
            w.append(Write(rel: nodeSubsRel, data: d))
        }

        for rel in dataFiles { if let d = p.dataFiles[rel] { w.append(Write(rel: rel, data: d)) } }
        // Passwords / cookies stay owner-only, like the originals.
        for rel in sensitiveDataFiles { if let d = p.dataFiles[rel] { w.append(Write(rel: rel, data: d, permissions: 0o600)) } }

        if let ca = p.caPEM {
            w.append(Write(rel: caPemRel, data: ca.cert, permissions: 0o644))
            w.append(Write(rel: caKeyRel, data: ca.key, permissions: 0o600))
        }
        return w
    }

    /// Writes the payload into the container at `root`: all files staged first, then moved into place; a failed move
    /// puts back every file already replaced. Nothing is written when planning or staging fails.
    @discardableResult
    static func apply(_ p: Payload, root: URL, defaults: UserDefaults, applyPrefs: Bool = false) throws -> Int {
        let writes = try plan(p, root: root)
        let fm = FileManager.default
        let staging = root.appendingPathComponent(".tern-import-\(UUID().uuidString)", isDirectory: true)
        defer { try? fm.removeItem(at: staging) }
        do {
            try fm.createDirectory(at: staging, withIntermediateDirectories: true)
            for (i, wr) in writes.enumerated() {
                let u = staging.appendingPathComponent("new-\(i)")
                try wr.data.write(to: u, options: .atomic)
                // review 10-25 #7: owner-only before the file ever reaches its place; a failure aborts the import.
                if let perm = wr.permissions { try fm.setAttributes([.posixPermissions: perm], ofItemAtPath: u.path) }
            }
        } catch {
            throw ExportError.writeFailed(error.localizedDescription)
        }

        // Commit. `done` = (destination, backup of the file it replaced or nil when it was new).
        var done: [(URL, URL?)] = []
        var createdDirs: [URL] = []
        func rollback() {
            for (dst, backup) in done.reversed() {
                try? fm.removeItem(at: dst)
                if let backup { try? fm.moveItem(at: backup, to: dst) }
            }
            for d in createdDirs.reversed() { try? fm.removeItem(at: d) }
        }
        do {
            for (i, wr) in writes.enumerated() {
                let dst = root.appendingPathComponent(wr.rel)
                let parent = dst.deletingLastPathComponent()
                if !fm.fileExists(atPath: parent.path) {
                    // Remember the top-most directory this import creates, so a rollback removes it again.
                    var top = parent
                    while !fm.fileExists(atPath: top.deletingLastPathComponent().path) { top = top.deletingLastPathComponent() }
                    let attrs: [FileAttributeKey: Any]? = wr.rel.hasPrefix("mihomo/engine/ca/") ? [.posixPermissions: 0o700] : nil
                    try fm.createDirectory(at: parent, withIntermediateDirectories: true, attributes: attrs)
                    createdDirs.append(top)
                }
                var backup: URL?
                if fm.fileExists(atPath: dst.path) {
                    let b = staging.appendingPathComponent("old-\(i)")
                    try fm.moveItem(at: dst, to: b)
                    backup = b
                }
                do {
                    try fm.moveItem(at: staging.appendingPathComponent("new-\(i)"), to: dst)
                } catch {
                    if let backup { try? fm.moveItem(at: backup, to: dst) }
                    throw error
                }
                done.append((dst, backup))
            }
        } catch {
            rollback()
            throw ExportError.writeFailed(error.localizedDescription)
        }

        defaults.set(p.profile.id, forKey: "activeProfileID")
        if applyPrefs, !p.prefs.isEmpty { BackupManager.applyPrefs(p.prefs) }
        return writes.count
    }

    /// parse + apply (unit tests and callers that hold the text).
    @discardableResult
    static func importText(_ text: String, root: URL, defaults: UserDefaults, applyPrefs: Bool = false) throws -> Payload {
        let p = try parse(text)
        try apply(p, root: root, defaults: defaults, applyPrefs: applyPrefs)
        return p
    }

    // MARK: - App glue

    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?" }
    static var appBuild: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?" }

    /// 配置 → 导出 → 完整导出（.conf）: builds the file off the main thread into the share-sheet export folder
    /// (ProfileStore.exportDir, purged when the share sheet closes — it holds the CA private key).
    static func exportFile(profile: Profile, includeSensitive: Bool = false) async -> Result<URL, Error> {
        let id = profile.id, name = profile.name
        return await Task.detached(priority: .userInitiated) { () -> Result<URL, Error> in
            do {
                let text = try TernFullExport.build(profileID: id, root: AppShared.containerURL, defaults: AppShared.defaults,
                                                    prefs: BackupManager.collectPrefs(), appVersion: TernFullExport.appVersion,
                                                    appBuild: TernFullExport.appBuild, includeSensitive: includeSensitive)
                ProfileStore.purgeExports()
                let dir = ProfileStore.exportDir
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                var base = name.components(separatedBy: CharacterSet(charactersIn: "/\\:?*\"<>|\n\r")).joined(separator: "_")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if base.isEmpty || base.hasPrefix(".") { base = "profile" + base }
                let f = DateFormatter()
                f.locale = Locale(identifier: "en_US_POSIX")
                f.dateFormat = "yyyyMMdd-HHmm"
                let url = dir.appendingPathComponent("Tern-\(String(base.prefix(60)))-\(f.string(from: Date())).conf")
                try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtection])
                return .success(url)
            } catch {
                return .failure(error)
            }
        }.value
    }

    /// Import sheet: validated payload → snapshot → staged write off the main thread → every store reloaded.
    @MainActor
    static func applyInApp(_ p: Payload) async throws -> String {
        _ = await SnapshotStore.shared.captureAsync(String(localized: "导入完整导出前"))
        let payload = p
        _ = try await Task.detached(priority: .userInitiated) {
            try TernFullExport.apply(payload, root: AppShared.containerURL, defaults: AppShared.defaults, applyPrefs: true)
        }.value
        let home = AppShared.homeURL.path
        if p.caPEM != nil { NCCAManager.shared.reloadCA(home: home) }
        SnapshotStore.reloadStores()
        EngineStore.shared.refreshCA()
        if p.nodeSubscriptions?.isEmpty == false {
            // Node-set caches are not part of the export: download them now.
            Task { _ = await NodeSubStore.shared.refreshAll() }
        }
        var msg = String(localized: "已导入完整配置「\(p.profile.name)」并设为当前配置。")
        if p.caPEM != nil {
            msg += "\n" + String(localized: "MitM 根证书和私钥已导入。在新设备上请到「HTTPS 解密」页安装证书描述文件，再到 设置 → 通用 → 关于本机 → 证书信任设置 中开启完全信任。")
        }
        return msg
    }
}
