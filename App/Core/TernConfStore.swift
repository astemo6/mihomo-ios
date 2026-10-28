import Foundation
import CryptoKit

// feat/nc-conf-native: every profile keeps its user-facing .conf next to the internal YAML:
//
//   profiles/<id>.conf         the source of truth the editor shows and saves (profile sections only; the shared
//                              rewrite / script / MitM sections are added from engine.json when the editor opens)
//   profiles/<id>.yaml         derived cache the runtime, NativeCore and every other screen keep reading (phase 1)
//   profiles/<id>.conf.state   SHA-256 of the YAML the .conf was last synced with (+ of the .conf itself)
//   profiles/<id>.yaml.pre-conf  the YAML as it was before its first .conf was generated (migration backup, once)
//
// Saving the editor regenerates the YAML from the .conf. A YAML written by anything else (subscription update, node
// editor, group order, manual nodes, a restored snapshot) no longer matches the recorded hash: the next sync rewrites
// the .conf from it — lossless by TernConf's contract, so nothing the user can express is lost; only comments of a
// hand-edited .conf go.
enum TernConfStore {

    static func confPath(_ yamlPath: String) -> String { (yamlPath as NSString).deletingPathExtension + ".conf" }
    static func statePath(_ yamlPath: String) -> String { (yamlPath as NSString).deletingPathExtension + ".conf.state" }
    static func backupPath(_ yamlPath: String) -> String { yamlPath + ".pre-conf" }
    /// Side files to remove with a deleted profile.
    static func sideFiles(_ yamlPath: String) -> [String] { [confPath(yamlPath), statePath(yamlPath), backupPath(yamlPath)] }

    struct State: Codable, Equatable {
        var version = 1
        var yaml: String
        var conf: String
    }

    static func sha(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

    static func readState(_ yamlPath: String) -> State? {
        guard let d = FileManager.default.contents(atPath: statePath(yamlPath)) else { return nil }
        return try? JSONDecoder().decode(State.self, from: d)
    }

    static func writeState(_ s: State, _ yamlPath: String) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        try NCRuntimeFiles.writeAtomic(try enc.encode(s), to: statePath(yamlPath))
    }

    // MARK: Conversion

    /// YAML text → canonical profile .conf (nil when the YAML is not a mapping).
    static func confFromYAML(_ yaml: String) -> String? {
        guard case .object(let m)? = NCYAML.parse(yaml) else { return nil }
        return TernConf.serializeProfile(m)
    }

    static func yamlFromProfile(_ m: [String: NCJSONValue]) -> String {
        NCYAMLEmitter.emit(NCJSONValue.object(m))
    }

    enum SyncResult: Equatable { case unchanged, migrated, regenerated, failed }

    /// The profile's .conf: as stored when it is in sync with the YAML, else generated from the YAML (first launch
    /// with this build = migration, with a one-time backup of the YAML; later = the YAML was changed elsewhere).
    @discardableResult
    static func sync(yamlPath: String) -> (text: String?, result: SyncResult) {
        let fm = FileManager.default
        let cp = confPath(yamlPath)
        guard let yd = fm.contents(atPath: yamlPath) else {
            return (fm.contents(atPath: cp).flatMap { String(data: $0, encoding: .utf8) }, .failed)
        }
        let ysha = sha(yd)
        if let st = readState(yamlPath), st.yaml == ysha, let cd = fm.contents(atPath: cp), let text = String(data: cd, encoding: .utf8) {
            return (text, .unchanged)
        }
        let existed = fm.fileExists(atPath: cp)
        guard let yaml = String(data: yd, encoding: .utf8), let conf = confFromYAML(yaml) else {
            return (fm.contents(atPath: cp).flatMap { String(data: $0, encoding: .utf8) }, .failed)
        }
        if !existed, !fm.fileExists(atPath: backupPath(yamlPath)) {
            try? NCRuntimeFiles.writeAtomic(yd, to: backupPath(yamlPath))
        }
        let cd = Data(conf.utf8)
        do {
            try NCRuntimeFiles.writeAtomic(cd, to: cp)
            try writeState(State(yaml: ysha, conf: sha(cd)), yamlPath)
        } catch {
            return (conf, .failed)
        }
        return (conf, existed ? .regenerated : .migrated)
    }

    // MARK: Save

    struct Prepared {
        /// Internal YAML regenerated from the text.
        var yaml: String
        /// What is stored as the profile's .conf: the text without the shared sections.
        var profileConf: String
        /// The shared part, when the text has it.
        var engine: TernConf.EngineSection?
        /// MitM CA from [mitm] p12 + passphrase (validated), as the PEM files the engine reads.
        var caPEM: (cert: Data, key: Data)?
        var profile: [String: NCJSONValue]
    }

    /// Parses and validates the editor text (nothing is written).
    static func prepare(text: String) throws -> Prepared {
        let parsed = try TernConf.parse(text)
        var ca: (cert: Data, key: Data)? = nil
        if let c = parsed.engine?.ca {
            do {
                let pair = try NCCAManager.pemPair(fromP12: c.p12, password: c.passphrase)
                ca = (cert: pair.pemCert, key: pair.pemKey)
            } catch {
                throw TernFullExport.ExportError.badCertificate(error.localizedDescription)
            }
        }
        var prof = TernConf.splitText(text).profile
        if prof.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { prof = TernConf.serializeProfile(parsed.profile) }
        return Prepared(yaml: yamlFromProfile(parsed.profile), profileConf: prof, engine: parsed.engine, caPEM: ca, profile: parsed.profile)
    }

    /// Stores the .conf after its YAML was written (the YAML hash is recorded so the next sync keeps this text).
    static func commit(yamlPath: String, yaml: String, conf: String) throws {
        let cd = Data(conf.utf8)
        try NCRuntimeFiles.writeAtomic(cd, to: confPath(yamlPath))
        try writeState(State(yaml: sha(Data(yaml.utf8)), conf: sha(cd)), yamlPath)
    }

    /// A Quantumult X import keeps the user's own text when it reads as exactly the profile the importer produced.
    @discardableResult
    static func adoptOriginal(yamlPath: String, original: String) -> Bool {
        guard let yd = FileManager.default.contents(atPath: yamlPath), case .object(let imported)? = NCYAML.parse(String(decoding: yd, as: UTF8.self)),
              let parsed = try? TernConf.parse(original), parsed.profile == imported else { return false }
        let prof = TernConf.splitText(original).profile
        guard !prof.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        let cd = Data(prof.utf8)
        do {
            try NCRuntimeFiles.writeAtomic(cd, to: confPath(yamlPath))
            try writeState(State(yaml: sha(yd), conf: sha(cd)), yamlPath)
        } catch { return false }
        return true
    }

    // MARK: Editor

    static let template = """
    # Tern profile
    # 请替换为你自己的节点 · Replace with your own nodes

    [general]
    mode = rule

    [policy]
    static=节点选择, direct

    [server_local]

    [filter_local]
    final, 节点选择

    """

    /// The editor text: the profile's .conf (synced) + the shared sections from engine.json (+ the MitM CA as
    /// passphrase / p12, like Quantumult X). `yamlPath` nil = a new profile (template).
    static func editorText(yamlPath: String?, home: String, engine: EngineConfig, includeCA: Bool = true) -> String {
        var text = template
        if let yamlPath, let t = sync(yamlPath: yamlPath).text { text = t }
        if !text.hasSuffix("\n") { text += "\n" }
        var e = TernConf.EngineSection(engine)
        if includeCA { e.ca = caFile(home: home) }
        return text + TernConf.serializeEngine(e)
    }

    static func caFile(home: String) -> TernConf.CAFile? {
        guard NCCAManager.loadCA(home: home) != nil else { return nil }
        let pass = passphrase(home: home)
        guard let p12 = try? NCCAManager.exportP12(home: home, password: pass) else { return nil }
        return TernConf.CAFile(passphrase: pass, p12: p12)
    }

    /// A stable passphrase for the editor's p12 (owner-only file next to the CA), so reopening shows the same key line.
    static func passphrase(home: String) -> String {
        let u = URL(fileURLWithPath: home).appendingPathComponent("engine/ca/conf-passphrase")
        if let s = try? String(contentsOf: u, encoding: .utf8) {
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if !t.isEmpty { return t }
        }
        let p = TernFullExport.randomPassphrase()
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        if (try? Data(p.utf8).write(to: u, options: .atomic)) != nil {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path)
        }
        return p
    }

    /// True when the PEM certificate is the one already installed (formatting of the PEM ignored).
    static func sameCA(home: String, pemCert: Data) -> Bool {
        func body(_ d: Data) -> String {
            String(decoding: d, as: UTF8.self).split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
                .filter { !$0.isWhitespace }
        }
        let cur = URL(fileURLWithPath: home).appendingPathComponent("engine/ca/ca.pem")
        guard let d = try? Data(contentsOf: cur) else { return false }
        return body(d) == body(pemCert)
    }

    // MARK: Live check (editor status line)

    /// Parses the .conf, then checks the YAML it stands for exactly like a connect would. Errors point at .conf lines.
    static func check(home: String, profilePath: String, text: String) -> NCProfileCheck.Result {
        let parsed: TernConf.Parsed
        do {
            parsed = try TernConf.parse(text)
        } catch let e as TernConf.ParseError {
            var r = NCProfileCheck.Result(error: e.errorDescription)
            r.line = e.line
            return r
        } catch {
            return NCProfileCheck.Result(error: error.localizedDescription)
        }
        var r = NCProfileCheck.check(home: home, profilePath: profilePath, text: yamlFromProfile(parsed.profile))
        if !r.ok {
            var msg = r.error ?? ""
            if let rng = msg.range(of: #"^第 \d+ 行："#, options: .regularExpression) { msg.removeSubrange(rng) }
            r.line = nil
            r.column = nil
            if let l = locate(text: text, message: msg) {
                r.line = l
                msg = String(localized: "第 \(l) 行：\(msg)")
            }
            r.error = msg
        }
        return r
    }

    /// The first .conf line naming something the message quotes (「name」, “name”, "name", 'name').
    static func locate(text: String, message: String) -> Int? {
        guard let re = try? NSRegularExpression(pattern: #"「([^」]+)」|“([^”]+)”|"([^"]+)"|'([^']+)'"#) else { return nil }
        let ns = message as NSString
        var names: [String] = []
        for m in re.matches(in: message, range: NSRange(location: 0, length: ns.length)) {
            for g in 1..<m.numberOfRanges where m.range(at: g).location != NSNotFound {
                names.append(ns.substring(with: m.range(at: g)))
            }
        }
        guard !names.isEmpty else { return nil }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        for n in names where !n.isEmpty {
            for (i, l) in lines.enumerated() {
                let t = l.trimmingCharacters(in: .whitespaces)
                if t.isEmpty || TernConf.isComment(t) || t.hasPrefix("[") { continue }
                if t.contains(n) || t.contains(TernConf.escField(n, positional: true)) { return i + 1 }
            }
        }
        return nil
    }

    // MARK: Diagnostics

    /// The diagnostic bundle's config.conf: the (already redacted) profile as .conf, plus the shared sections without
    /// the MitM CA.
    static func diagnosticConf(profile: [String: NCJSONValue], engine: EngineConfig?) -> String {
        var out = TernConf.serializeProfile(profile)
        if let engine { out += TernConf.serializeEngine(TernConf.EngineSection(engine)) }
        return out
    }
}
