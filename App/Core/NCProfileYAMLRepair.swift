import Foundation

/// fix/nc-e2e-real: NCYAMLEmitter (the Swift port's YAML writer, in use since the native-core switch) wrote every key
/// after the first of a NESTED mapping at column 0. A Surge / Quantumult X import with one ws node
/// (`ws-opts: {headers: {Host}, path}`) or a nested `dns:` therefore saved a profile whose YAML ends — for every
/// reader — at the first misplaced key: E2E replay 40268229079 ran a 9-node / 29-group / 85-rule QX export as
/// 1 node / 0 groups / 0 rules. The emitter is fixed; this re-converts the profiles that bug already wrote, from the
/// original .conf ConfImport keeps next to them (`<profile>.yaml.source.conf`), once, keeping the broken file as
/// `<profile>.yaml.pre-yaml-fix`.
enum NCProfileYAMLRepair {

    /// Keys Clash.Meta only has inside a node / provider / dns block. One of them at column 0 is a key the old emitter
    /// moved out of its mapping (the last key of a nested block, which `hasDedentedScalarKey` cannot see).
    static let nestedOnlyKeys: Set<String> = [
        "path", "headers", "Host", "host", "grpc-service-name", "max-early-data", "early-data-header-name",
        "public-key", "short-id", "enable", "nameserver", "fallback", "default-nameserver", "enhanced-mode",
        "fake-ip-range", "fake-ip-filter", "nameserver-policy", "proxy-server-nameserver", "fallback-filter",
        "behavior", "format", "lazy", "tolerance", "interval", "url", "header", "override",
    ]

    /// True when `text` has the old emitter's signature: a column-0 `key: <scalar>` line followed by an indented line
    /// (invalid YAML — no block can follow a scalar), or a column-0 key Clash.Meta only uses nested.
    static func looksTruncated(_ text: String) -> Bool {
        let lines = text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" || $0 == "\r" })
            .map(String.init)
        var i = 0
        while i < lines.count {
            let l = lines[i]
            defer { i += 1 }
            guard let c = l.first, c != " ", c != "\t", c != "#", c != "-", c != "%" else { continue }
            guard let colon = l.range(of: ":") else { continue }
            let key = String(l[..<colon.lowerBound]).trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
            let value = l[colon.upperBound...].trimmingCharacters(in: .whitespaces)
            if nestedOnlyKeys.contains(key) { return true }
            if value.isEmpty || value.hasPrefix("|") || value.hasPrefix(">") || value.hasPrefix("#") { continue }
            // A multi-line flow collection is legal; the emitter never writes one.
            if (value.hasPrefix("[") && !value.hasSuffix("]")) || (value.hasPrefix("{") && !value.hasSuffix("}")) { continue }
            var j = i + 1
            while j < lines.count {
                let t = lines[j].trimmingCharacters(in: .whitespaces)
                if t.isEmpty || t.hasPrefix("#") { j += 1; continue }
                break
            }
            if j < lines.count, let f = lines[j].first, f == " " { return true }
        }
        return false
    }

    /// proxies + proxy-groups + rules the parser reads from `text` (what every reader of the profile sees).
    static func itemCount(_ text: String) -> Int {
        guard case .object(let m)? = NCYAML.parse(text) else { return 0 }
        func n(_ k: String) -> Int { if case .array(let a)? = m[k] { return a.count }; return 0 }
        return n("proxies") + n("proxy-groups") + n("rules")
    }

    /// Repairs one profile file. Returns true when it was rewritten. Runs once per profile (`.yaml-fix-checked`
    /// marker), off the main actor (ProfileStore.load's migration task).
    @discardableResult
    static func repair(profilePath: String) -> Bool {
        let fm = FileManager.default
        let source = profilePath + ".source.conf"
        let marker = profilePath + ".yaml-fix-checked"
        guard fm.fileExists(atPath: source), !fm.fileExists(atPath: marker) else { return false }
        return NCPathLock.shared.withLock(for: profilePath) { () -> Bool in
            defer { fm.createFile(atPath: marker, contents: Data()) }
            guard let cur = try? String(contentsOfFile: profilePath, encoding: .utf8), looksTruncated(cur),
                  let conf = try? String(contentsOfFile: source, encoding: .utf8) else { return false }
            let res = NCConfImportPort.importConfResult(conf)
            if let e = res.error, !e.isEmpty { return false }
            guard !res.yaml.isEmpty, !looksTruncated(res.yaml), itemCount(res.yaml) > itemCount(cur) else { return false }
            try? fm.removeItem(atPath: profilePath + ".pre-yaml-fix")
            try? fm.copyItem(atPath: profilePath, toPath: profilePath + ".pre-yaml-fix")
            do {
                try NCRuntimeFiles.writeAtomic(Data(res.yaml.utf8), to: profilePath)
            } catch {
                return false
            }
            NSLog("[Tern] profile YAML repaired from its .conf source (old emitter cut it): %@", (profilePath as NSString).lastPathComponent)
            return true
        }
    }
}
