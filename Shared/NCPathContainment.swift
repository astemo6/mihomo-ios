import Foundation

/// fix/nc-0.20.2: one lexical, file-system-independent containment check for "is this path inside home".
///
/// Why not `NSString.standardizingPath`: it strips a leading "/private" ONLY when the stripped path exists. On iOS the
/// app-group container is `/private/var/mobile/Containers/Shared/AppGroup/<UUID>`, so an existing home became
/// "/var/…" while a not-yet-downloaded rule-set cache under it stayed "/private/var/…" — the prefix test failed and
/// every first download / force update said 「路径不在内核目录内」. It also resolves ".." in absolute paths through
/// symlinks. Here both sides are cleaned the same way, with no file-system lookups:
///   - "//" and "." components are dropped, ".." pops a component (never above "/");
///   - the firmlinked "/private/var", "/private/tmp", "/private/etc" prefixes fold to "/var", "/tmp", "/etc".
/// A container has no symlinks a config can plant, so lexical containment is the whole check.
enum NCPathContainment {
    /// Lexically cleaned absolute path ("" for an empty input). A relative `path` is resolved against `base`
    /// (itself cleaned); without a base a relative path is cleaned relative ("." for empty after cleaning).
    static func clean(_ path: String, base: String? = nil) -> String {
        if path.isEmpty { return "" }
        var full = path
        if !full.hasPrefix("/") {
            if let base, !base.isEmpty { full = base + "/" + full } else { return cleanRelative(full) }
        }
        var out: [Substring] = []
        for c in full.split(separator: "/", omittingEmptySubsequences: true) {
            if c == "." { continue }
            if c == ".." { if !out.isEmpty { out.removeLast() }; continue }
            out.append(c)
        }
        if out.count >= 2, out[0] == "private", ["var", "tmp", "etc"].contains(out[1]) { out.removeFirst() }
        return "/" + out.joined(separator: "/")
    }

    /// A relative path cleaned without a base; leading ".." components are kept so callers can see an escape.
    static func cleanRelative(_ path: String) -> String {
        var out: [Substring] = []
        for c in path.split(separator: "/", omittingEmptySubsequences: true) {
            if c == "." { continue }
            if c == "..", let last = out.last, last != ".." { out.removeLast(); continue }
            out.append(c)
        }
        return out.isEmpty ? "." : out.joined(separator: "/")
    }

    /// True when `path` (absolute, or relative to home) is home itself or lies under it. Empty home → false.
    static func isInside(home: String, _ path: String, allowHomeItself: Bool = true) -> Bool {
        let h = clean(home)
        guard h.hasPrefix("/"), !path.isEmpty else { return false }
        let c = clean(path, base: h)
        if c == h { return allowHomeItself }
        return c.hasPrefix(h == "/" ? "/" : h + "/")
    }

    /// The home-relative form of an absolute path inside home ("" when outside); relative input is cleaned.
    static func relative(home: String, _ path: String) -> String {
        let h = clean(home)
        let c = clean(path, base: h)
        guard isInside(home: h, c, allowHomeItself: false) else { return "" }
        return String(c.dropFirst(h.count + 1))
    }

    /// fix/nc-0.20.2: an absolute path persisted by an older install points into a container that no longer exists
    /// after delete + reinstall (or a re-signed build with another app-group UUID). Rebase it under the current home:
    /// the part after the last "/tern/" component (the home directory's name) when present, else
    /// `<fallbackDir>/<basename>`. Returns a home-relative path ("./…"), or nil when the input is already inside home,
    /// is relative, or cannot be rebased safely (no basename, or the result would escape home).
    static func rebaseForeignAbsolute(home: String, _ path: String, fallbackDir: String) -> String? {
        guard path.hasPrefix("/"), !isInside(home: home, path) else { return nil }
        let comps = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        var rel: String
        if let i = comps.lastIndex(of: "tern"), i + 1 < comps.count {
            rel = comps[(i + 1)...].joined(separator: "/")
        } else {
            guard let b = comps.last, b != "..", b != "." else { return nil }
            rel = fallbackDir.isEmpty ? b : fallbackDir + "/" + b
        }
        rel = cleanRelative(rel)
        if rel == "." || rel == ".." || rel.hasPrefix("../") { return nil }
        guard isInside(home: home, rel, allowHomeItself: false) else { return nil }
        return "./" + rel
    }
}

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
