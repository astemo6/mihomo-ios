import Foundation

/// B6 (nc-dego-rest): the core half of 覆写脚本 (override scripts) in Swift — bridge/overridescript.go
/// ScriptInputSnapshot / ScriptOutputApplyFor / ScriptOutputClear / ScriptOutputStatus / ScriptOutputYAML.
/// The scripts run in the app (JSOverrideEngine); this hands them the profile as JSON and stores their output as
/// <home>/scripted/<profile id>.yaml + .json meta (SHA-256 of the source profile), which
/// NCRuntimeFiles.readRuntimeProfile (#112) reads instead of the profile while the source is unchanged.
///
/// Differences from Go, by design or for now:
///   - dns.nameserver-policy: Go handed it to scripts in the profile's own key order and wrote the script's
///     order back. NCYAML / NCJSONValue have no ordered maps, so input keys are sorted and output is written
///     sorted — the tunnel's nativecore-runtime.json sorts that map anyway (see NCRuntimeDNS header).
///   - Validation of the output: NCRuntimeBuilder.build with the app's overrides + NCConfigValidator (the Swift
///     port of mihomo's config parse, B1 ValidateConfigIn).
enum NCOverrideOutput {

    /// bridge errScriptSourceChanged (OverrideScripts compares the message).
    static let errSourceChanged = "配置在脚本运行期间已改变，请重新运行"

    struct InputError: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func paths(home: String, profilePath: String) -> (yaml: String, meta: String) {
        let id = NCRuntimeFiles.profileID(fromPath: profilePath)
        let d = URL(fileURLWithPath: home).appendingPathComponent("scripted")
        return (d.appendingPathComponent(id + ".yaml").path, d.appendingPathComponent(id + ".json").path)
    }

    // MARK: input

    /// bridge ScriptInputSnapshot: the sha256 of the exact bytes read and the profile as a JSON object
    /// (share-link / base64 subscriptions converted, `rule:` → `rules:`, proxy-providers ensured).
    static func inputSnapshot(profilePath: String) throws -> (sha: String, json: String) {
        guard let b = FileManager.default.contents(atPath: profilePath) else {
            throw InputError(message: "读取配置失败: " + (profilePath as NSString).lastPathComponent)
        }
        let sha = NCRuntimeFiles.sha256Hex(b)
        var raw = try profileAsMap(b)
        if let r = raw["rule"] {
            if raw["rules"] == nil { raw["rules"] = r }
            raw.removeValue(forKey: "rule")
        }
        var needProviders = raw["proxy-providers"] == nil
        if case .null? = raw["proxy-providers"] { needProviders = true }
        if needProviders { raw["proxy-providers"] = .object([:]) }
        guard let d = try? JSONSerialization.data(withJSONObject: NCJSONValue.object(raw).anyTree, options: [.sortedKeys, .fragmentsAllowed]),
              let s = String(data: d, encoding: .utf8) else {
            throw InputError(message: "配置无法转换为 JSON")
        }
        return (sha, s)
    }

    /// bridge profileAsMap: the profile as buildRuntimeWith sees it before any override.
    static func profileAsMap(_ profile: Data) throws -> [String: NCJSONValue] {
        let text = String(decoding: profile, as: UTF8.self)
        var raw: [String: NCJSONValue] = [:]
        if let parsed = NCYAML.parse(text) {
            switch parsed {
            case .object(let m): raw = m
            case .null: raw = [:]
            default: throw InputError(message: "YAML 解析失败: 配置顶层不是映射")
            }
        } else if !text.split(separator: "\n").allSatisfy({
            let t = $0.trimmingCharacters(in: .whitespaces)
            return t.isEmpty || t.hasPrefix("#") || t == "---"
        }) {
            throw InputError(message: "YAML 解析失败: 无法解析")
        }
        if raw["proxies"] == nil && raw["proxy-providers"] == nil {
            let conv = NCShareLink.convertShareLinks(text)
            if !conv.isEmpty, case .object(let m)? = NCYAML.parse(conv) { raw = m }
        }
        return raw
    }

    // MARK: output

    /// bridge scriptOutputYAML: the chain's JSON output as profile YAML.
    static func outputYAML(_ outputJSON: String) throws -> String {
        let obj: Any
        do {
            obj = try JSONSerialization.jsonObject(with: Data(outputJSON.utf8), options: [.fragmentsAllowed])
        } catch {
            throw InputError(message: "脚本返回的不是配置对象: " + error.localizedDescription)
        }
        if obj is NSNull { throw InputError(message: "脚本返回了空配置") }
        guard obj is [String: Any], case .object(var raw) = NCJSONValue(obj) else {
            throw InputError(message: "脚本返回的不是配置对象")
        }
        if case .object(let p)? = raw["proxy-providers"], p.isEmpty {
            raw.removeValue(forKey: "proxy-providers")
        }
        // NCYAMLEmitter writes whole numbers as integers (Go's normalizeJSONNumbers).
        return NCYAMLEmitter.emit(NCJSONValue.object(raw))
    }

    /// bridge ScriptOutputApplyFor: validates the output for the profile with the app's overrides and stores it.
    /// sourceSHA (from inputSnapshot): refused when the file no longer has that content; "" = no check.
    /// Returns "" or the error; on error nothing is stored and the previous output is removed.
    static func applyFor(home: String, profilePath: String, outputJSON: String, scripts: [String], sourceSHA: String) -> String {
        guard let src = FileManager.default.contents(atPath: profilePath) else {
            return "读取配置失败: " + (profilePath as NSString).lastPathComponent
        }
        let (yp, mp) = paths(home: home, profilePath: profilePath)
        return NCPathLock.shared.withLock(for: yp) { () -> String in
            let fm = FileManager.default
            func fail(_ msg: String) -> String {
                try? fm.removeItem(atPath: yp)
                try? fm.removeItem(atPath: mp)
                return msg
            }
            let srcSHA = NCRuntimeFiles.sha256Hex(src)
            if !sourceSHA.isEmpty && sourceSHA != srcSHA { return fail(errSourceChanged) }
            let y: String
            do { y = try outputYAML(outputJSON) } catch { return fail(error.localizedDescription) }
            if let msg = NCProfileRefRename.buildError(home: home, path: profilePath, bytes: Data(y.utf8)) {
                return fail("脚本输出的配置校验失败: " + msg)
            }
            do {
                try fm.createDirectory(atPath: (yp as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                try NCRuntimeFiles.writeAtomic(Data(y.utf8), to: yp)
                let meta: [String: Any] = ["source": srcSHA, "at": Int64(Date().timeIntervalSince1970), "scripts": scripts]
                try NCRuntimeFiles.writeAtomic(try JSONSerialization.data(withJSONObject: meta), to: mp)
            } catch {
                return fail(error.localizedDescription)
            }
            return ""
        }
    }

    /// bridge ScriptOutputClear: removes the stored output.
    static func clear(home: String, profilePath: String) {
        let (yp, mp) = paths(home: home, profilePath: profilePath)
        NCPathLock.shared.withLock(for: yp) {
            try? FileManager.default.removeItem(atPath: yp)
            try? FileManager.default.removeItem(atPath: mp)
        }
    }

    struct Status {
        var exists = false
        var fresh = false
        var at: Date?
        var scripts: [String] = []
        var bytes: Int64 = 0
    }

    /// bridge ScriptOutputStatus.
    static func status(home: String, profilePath: String) -> Status {
        struct Meta: Decodable { var source: String?; var at: Int64?; var scripts: [String]? }
        var st = Status()
        let src = FileManager.default.contents(atPath: profilePath) ?? Data()
        let (yp, mp) = paths(home: home, profilePath: profilePath)
        guard let mb = FileManager.default.contents(atPath: mp),
              let m = try? JSONDecoder().decode(Meta.self, from: mb),
              let attrs = try? FileManager.default.attributesOfItem(atPath: yp) else { return st }
        st.exists = true
        st.fresh = (m.source ?? "") == NCRuntimeFiles.sha256Hex(src)
        st.at = m.at.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        st.scripts = m.scripts ?? []
        st.bytes = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        return st
    }

    /// bridge ScriptOutputYAML: the stored output ("" when none).
    static func storedYAML(home: String, profilePath: String) -> String {
        let (yp, _) = paths(home: home, profilePath: profilePath)
        return (try? String(contentsOfFile: yp, encoding: .utf8)) ?? ""
    }
}
