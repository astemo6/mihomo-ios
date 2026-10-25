import Foundation

/// Pure Swift ports of two bridge helpers used by the import / profile
/// flows (bridge/grouporder.go ForgetProfile, bridge/nativeformats.go
/// DetectNodeFormat are the specs). The remaining B3 bridge functions
/// (ClassifyText, ImportConf, InspectProfile) are intentionally not ported
/// here: they are built on the Go module parser and the Go runtime-config
/// builder, and land with those batches (B6 / B1) instead of as look-alike
/// reimplementations.
enum ImportTools {

    // MARK: - ForgetProfile

    /// Per-profile settings files whose top-level JSON object is keyed by
    /// profile id (bridge: profileSettingFiles).
    private static let profileSettingFiles = ["group-edits.json", "groups.json", "subscriptions.json", "netpolicy.json"]

    /// Removes a deleted profile's per-profile settings (the entries keyed
    /// by its id in profileSettingFiles) and its side files:
    /// `<file>.bak`, `<file>.gen`, `<profile>.selected.json`,
    /// `<file>.source.conf`. Returns "" or the first error, like the Go
    /// version. (Go additionally serialises writers with a file lock; the
    /// app is the only writer of these files, so a read-modify-write here
    /// is equivalent in practice.)
    static func forgetProfile(home: String, profileID: String, profilePath: String) -> String {
        var firstErr = ""
        if !home.isEmpty, !profileID.isEmpty {
            for f in profileSettingFiles {
                let p = (home as NSString).appendingPathComponent(f)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: p)),
                      var m = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                      m[profileID] != nil else { continue }
                m.removeValue(forKey: profileID)
                guard let nb = try? JSONSerialization.data(withJSONObject: m,
                                                           options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { continue }
                do {
                    try writeAtomic(nb, to: p)
                } catch {
                    if firstErr.isEmpty { firstErr = error.localizedDescription }
                }
            }
        }
        if !profilePath.isEmpty {
            let selected = (profilePath as NSString).deletingPathExtension + ".selected.json"
            for side in [profilePath + ".bak", profilePath + ".gen", selected, profilePath + ".source.conf"] {
                try? FileManager.default.removeItem(atPath: side)
            }
        }
        return firstErr
    }

    private static func writeAtomic(_ data: Data, to path: String) throws {
        let tmp = path + ".tmp"
        try data.write(to: URL(fileURLWithPath: tmp))
        if FileManager.default.fileExists(atPath: path) {
            try FileManager.default.removeItem(atPath: path)
        }
        try FileManager.default.moveItem(atPath: tmp, toPath: path)
    }

    // MARK: - DetectNodeFormat

    /// Reports what kind of node source a text is and how many nodes it
    /// holds, as JSON: {"count":N,"format":"…"} — formats and detection
    /// order mirror the Go version: SIP008 / sing-box JSON, Clash YAML,
    /// Base64 分享链接， 分享链接， Surge / QX / Loon 节点行， 未识别.
    static func detectNodeFormat(_ text: String) -> String {
        let (format, count) = detect(text)
        let obj: [String: Any] = ["format": format, "count": count]
        guard let b = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]),
              let s = String(data: b, encoding: .utf8) else {
            return "{\"count\":0,\"format\":\"未识别\"}"
        }
        return s
    }

    private static func detect(_ text: String) -> (String, Int) {
        var t = text
        if t.hasPrefix("\u{FEFF}") { t.removeFirst() }
        t = t.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return ("未识别", 0) }

        if let (format, count) = jsonNodeCount(t) { return (format, count) }

        if t.contains("proxies:") || t.contains("proxy-providers:") {
            if let root = NCYAML.parse(t), let proxies = root["proxies"]?.array {
                return ("Clash YAML", proxies.count)
            }
        }

        var b64 = false
        if !t.contains("://"), !t.contains("=") {
            if let d = tryB64(t) { b64 = true; t = d }
        }

        let nodes = NCSubscription.parse(t)
        if !nodes.isEmpty {
            if t.contains("://") {
                return (b64 ? "Base64 分享链接" : "分享链接", nodes.count)
            }
            return ("Surge / QX / Loon 节点行", nodes.count)
        }
        // NCSubscription.parse covers share links and Clash YAML; bare
        // Surge/QX/Loon node lines (`name = ss, …`, `shadowsocks=…`) are
        // recognised by shape for the count when nothing else matched.
        let lineCount = nodeLineCount(t)
        if lineCount > 0 { return ("Surge / QX / Loon 节点行", lineCount) }
        return ("未识别", 0)
    }

    /// JSON node sources, Go parseJSONNodes semantics (count only):
    /// an object with a `servers` array is SIP008 (entries need a server);
    /// an object with `outbounds`, or a bare array, is sing-box (entries
    /// need a server and a recognised proxy type).
    private static func jsonNodeCount(_ t: String) -> (String, Int)? {
        guard t.hasPrefix("{") || t.hasPrefix("["),
              let data = t.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) else { return nil }
        if let obj = root as? [String: Any] {
            if let servers = obj["servers"] as? [[String: Any]] {
                let n = servers.filter { (($0["server"] as? String) ?? "") != "" }.count
                return ("SIP008", n)
            }
            guard let outbounds = obj["outbounds"] as? [[String: Any]] else { return nil }
            return ("sing-box", singBoxCount(outbounds))
        }
        if let arr = root as? [[String: Any]] {
            return ("sing-box", singBoxCount(arr))
        }
        return nil
    }

    private static let singBoxTypes: Set<String> = ["shadowsocks", "vmess", "vless", "trojan",
                                                    "hysteria2", "tuic", "anytls", "socks",
                                                    "http", "ssh", "wireguard"]

    private static func singBoxCount(_ list: [[String: Any]]) -> Int {
        list.filter {
            (($0["server"] as? String) ?? "") != "" && singBoxTypes.contains(($0["type"] as? String) ?? "")
        }.count
    }

    /// Go tryB64: no spaces/tabs anywhere, CR/LF stripped, then any of the
    /// four base64 variants (std/url × padded/raw) may decode it.
    private static func tryB64(_ s: String) -> String? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.contains(" ") || trimmed.contains("\t") { return nil }
        let stripped = trimmed.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        guard let d = base64DecodeLenient(stripped) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    private static func base64DecodeLenient(_ s: String) -> Data? {
        var v = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = v.count % 4
        if rem == 1 { return nil }
        if rem > 0 { v += String(repeating: "=", count: 4 - rem) }
        return Data(base64Encoded: v)
    }

    /// Bare node-line shapes from Surge / QX / Loon configs:
    /// `Name = ss, host, port, …`, `Name = vmess, …`, QX keyed forms like
    /// `shadowsocks=host:port,…`, `vmess=…`, `trojan=…`. Count-only
    /// recogniser; full node-line parsing lives in the subscription /
    /// conf importers.
    private static func nodeLineCount(_ t: String) -> Int {
        let types = ["ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2",
                     "tuic", "socks5", "socks", "http", "https", "snell", "wireguard",
                     "shadowsocks", "anytls"]
        var n = 0
        for raw in t.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("//") { continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let lhs = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let rhs = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).lowercased()
            if types.contains(lhs) { n += 1; continue } // QX keyed form: vmess=…
            // Surge/Loon form: name = <type>, …
            let first = rhs.split(separator: ",", maxSplits: 1).first?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if types.contains(first) { n += 1 }
        }
        return n
    }
}
