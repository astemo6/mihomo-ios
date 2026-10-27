import Foundation

/// fix/nc-0.20.2: provider `path:` values that point into another (old) container.
enum NCProviderPathRebase {
    /// Rewrites absolute provider paths outside home to home-relative ones in a parsed config. Returns the count.
    @discardableResult
    static func rebase(_ raw: inout [String: NCJSONValue], home: String) -> Int {
        guard !home.isEmpty else { return 0 }
        var n = 0
        for (key, dir) in [("rule-providers", "rules"), ("proxy-providers", "proxies")] {
            guard case .object(var pp)? = raw[key] else { continue }
            var changed = false
            for (name, v) in pp {
                guard case .object(var m) = v, case .string(let p)? = m["path"],
                      let r = NCPathContainment.rebaseForeignAbsolute(home: home, p, fallbackDir: dir) else { continue }
                m["path"] = .string(r); pp[name] = .object(m); changed = true; n += 1
            }
            if changed { raw[key] = .object(pp) }
        }
        return n
    }

    /// One-time text migration of a stored profile: `path:` lines whose value is an absolute iOS container path
    /// (…/Containers/Shared/AppGroup/… or …/Containers/Data/Application/…) outside the current home become
    /// home-relative. Only those values are touched, so the rest of the file keeps its formatting. Returns the new
    /// text, or nil when nothing changed.
    static func migrateText(_ text: String, home: String) -> String? {
        guard !home.isEmpty, text.contains("/Containers/") else { return nil }
        var changed = false
        var lines = text.components(separatedBy: "\n")
        for i in lines.indices {
            let line = lines[i]
            guard let r = line.range(of: "path:"), line.contains("/Containers/") else { continue }
            let head = line[..<r.lowerBound]
            // `path:` as a mapping key (indented block or inline `{…, path: …}`), not inside another word
            if let last = head.last, !(last == " " || last == "\t" || last == "{" || last == ",") { continue }
            var rest = line[r.upperBound...].drop(while: { $0 == " " || $0 == "\t" })
            var quote: Character? = nil
            if let q = rest.first, q == "\"" || q == "'" { quote = q; rest = rest.dropFirst() }
            let end = rest.firstIndex(where: { c in quote.map { c == $0 } ?? (c == " " || c == "," || c == "}" || c == "#") }) ?? rest.endIndex
            let value = String(rest[..<end])
            guard value.hasPrefix("/"),
                  value.contains("/Containers/Shared/AppGroup/") || value.contains("/Containers/Data/Application/"),
                  let nv = NCPathContainment.rebaseForeignAbsolute(home: home, value, fallbackDir: "rules") else { continue }
            lines[i] = String(line[..<rest.startIndex]) + nv + String(rest[end...])
            changed = true
        }
        return changed ? lines.joined(separator: "\n") : nil
    }

    /// Applies `migrateText` to a profile file in place (atomic write). True when rewritten.
    @discardableResult
    static func migrateFile(_ path: String, home: String) -> Bool {
        guard let d = FileManager.default.contents(atPath: path),
              let s = String(data: d, encoding: .utf8), let out = migrateText(s, home: home) else { return false }
        return (try? Data(out.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)) != nil
    }
}
