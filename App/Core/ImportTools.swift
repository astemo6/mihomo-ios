import Foundation

/// Pure Swift ports of bridge helpers used by the import / profile flows
/// (bridge/classify.go ClassifyText, bridge/grouporder.go ForgetProfile,
/// bridge/nativeformats.go DetectNodeFormat are the specs). ImportConf and
/// InspectProfile land in NCConfImportPort.swift and ProfileInspector.swift.
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
        // Review R-2: unique temp + rename(2), never delete-then-move.
        try NCRuntimeFiles.writeAtomic(data, to: path)
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

        let nodes = NCSubscriptionParser.parse(t)
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
                                                    "http", "ssh", "wireguard", "naive"]

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

    // MARK: - ClassifyText

    // qxConfSectionRe: sections only a full Quantumult X config has (modules / snippets never do).
    private static let qxConfSectionRe = try? NSRegularExpression(
        pattern: "^[ \\t]*\\[(server_local|server_remote|policy|filter_local|filter_remote)\\][ \\t]*\\r?$",
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    /// isQXConf reports whether text is a full Quantumult X configuration.
    private static func isQXConf(_ t: String) -> Bool {
        guard let re = qxConfSectionRe else { return false }
        return re.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil
    }

    private static let classifyConfRe = try? NSRegularExpression(
        pattern: "^[ \\t]*\\[(Proxy|Proxy Group|General|server_local|server_remote|policy|filter_local|filter_remote)\\][ \\t]*\\r?$",
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    // v0.19.11 (review 6 P1-1): sections only full configs have; a module never carries nodes or groups.
    private static let confOnlySectionRe = try? NSRegularExpression(
        pattern: "^[ \\t]*\\[(Proxy|Proxy Group|server_local|server_remote)\\][ \\t]*\\r?$",
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    private static let moduleSectionRe = try? NSRegularExpression(
        pattern: "^\\[(Script|URL Rewrite|Header Rewrite|Body Rewrite|Map Local|MITM|Rule|Rewrite|rewrite_local|mitm|Panel|task_local|Plugin)\\]\\s*$",
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    // classifyHeadMax bounds what ClassifyText scans (B31).
    private static let classifyHeadMax = 256 << 10

    /// classifyHead is t cut to classifyHeadMax bytes at the last line end; a single huge line (a base64
    /// subscription) is cut at a multiple of 4 bytes so its decoded prefix still parses.
    private static func classifyHead(_ t: String) -> String {
        let utf8 = t.utf8
        if utf8.count <= classifyHeadMax {
            return t
        }
        let index = utf8.index(utf8.startIndex, offsetBy: classifyHeadMax)
        let prefixData = Data(utf8[..<index])
        if let lastNL = prefixData.lastIndex(of: UInt8(ascii: "\n")), lastNL > 0 {
            let slice = prefixData[..<lastNL]
            return String(decoding: slice, as: UTF8.self)
        }
        let cutLen = prefixData.count - (prefixData.count % 4)
        return String(decoding: prefixData[..<cutLen], as: UTF8.self)
    }

    /// isManagedConf: Surge's managed-profile header ("#!MANAGED-CONFIG <url> interval=… strict=…").
    private static func isManagedConf(_ t: String) -> Bool {
        guard t.utf8.count >= 16 else { return false }
        let prefix16 = String(t.prefix(16))
        return prefix16.caseInsensitiveCompare("#!MANAGED-CONFIG") == .orderedSame
    }

    /// ClassifyText tells the app what pasted / opened text is, so it can route it into the one internal
    /// model: "profile" (mihomo / Clash YAML), "conf" (a full Surge / QX config), "module:<format>"
    /// (Surge / QX / Loon / Stash / Egern module or rewrite snippet), "nodes" (share links / proxy
    /// lines) or "" (not recognised).
    static func classifyText(_ text: String) -> String {
        var full = text
        if full.hasPrefix("\u{FEFF}") { full.removeFirst() }
        full = full.trimmingCharacters(in: .whitespacesAndNewlines)
        if full.isEmpty {
            return ""
        }
        // B31 (review 7 checklist): the markers this decides on are all near the top; the regex scans, the module
        // parser and the node parser on a 50 MB single line took ~15 s. They now read at most classifyHeadMax
        // bytes (cut at a line end); only the cheap substring checks for a YAML profile see the whole text.
        let t = classifyHead(full)
        if isQXConf(t) {
            return "conf"
        }
        if NCEngineRuleset.isEgern(t) {
            return "module:egern"
        }
        if t.contains("\nhttp:") || t.hasPrefix("http:\n") || t.contains("script-providers:") {
            return "module:stash"
        }
        if full.contains("proxies:") || full.contains("proxy-providers:") || full.contains("proxy-groups:") {
            return "profile"
        }
        if NCEngineRuleset.isStash(t) {
            return "module:stash" // v0.13: rules-only / rule-providers overrides
        }
        // v0.19.9: a module header wins over [General] (BoxJS's Surge module has a [General] section with
        // force-http-engine-hosts and was taken for a full config).
        // v0.19.11 (review 6 P1-1): but #!MANAGED-CONFIG (the first line of nearly every Surge subscription) is a
        // config marker, and [Proxy] / [Proxy Group] only exist in full configs.
        let hasConf = (classifyConfRe?.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil)
        let hasConfOnly = (confOnlySectionRe?.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil)
        if hasConf && (!t.hasPrefix("#!") || isManagedConf(t) || hasConfOnly) {
            return "conf"
        }
        let hasModule = (moduleSectionRe?.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil)
        if hasModule || t.hasPrefix("#!") {
            let rs = NCEngineRuleset()
            rs.parseText(t, source: "", args: [:])
            if !rs.format.isEmpty && rs.format != "list" {
                return "module:" + rs.format
            }
            return "module:surge"
        }
        let (nodeFmt, nodeCnt) = detect(t)
        if nodeCnt > 0 && nodeFmt != "未识别" {
            return "nodes"
        }
        // v0.19.9: section-less rewrite snippets (QX `.snippet`, e.g. Sub-Store's QX.snippet:
        // `hostname=…` + `… url script-analyze-echo-response …`) and QX task gallery JSON (QX-Task.json).
        let rs = NCEngineRuleset()
        rs.parseText(t, source: "", args: [:])
        if !rs.tasks.isEmpty || (!rs.rules.isEmpty && !rs.hostnames.isEmpty) {
            var f = rs.format
            if f.isEmpty || f == "list" {
                f = "qx"
            }
            return "module:" + f
        }
        return ""
    }
}
