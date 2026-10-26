import Foundation

/// Sudoku protocol configuration, validation, and parsing helpers (S1).
///
/// Specification reference:
/// - Official repository: SUDOKU-ASCII/sudoku (GPL-3.0)
/// - Author: saba / saba-futai (active 2025-2026)
/// - Reference implementations:
///   - Go: SUDOKU-ASCII/sudoku (official tunnel core), MetaCubeX/mihomo (PR #2397 merged)
///   - Swift: NodePassProject/Anywhere (open source on GitHub, GPL-3.0)
/// - Design note: docs/nc-proto-sudoku.md
enum NCSudoku {

    /// Supported AEAD encryption methods.
    enum AEADMethod: String, CaseIterable, Equatable {
        case chacha20Poly1305 = "chacha20-poly1305"
        case aes128GCM = "aes-128-gcm"
        case none = "none"

        static func parse(_ raw: String?) -> AEADMethod? {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
                return .chacha20Poly1305 // default
            }
            switch raw {
            case "chacha20-poly1305", "chacha20": return .chacha20Poly1305
            case "aes-128-gcm", "aes128": return .aes128GCM
            case "none", "plain": return .none
            default: return nil
            }
        }
    }

    /// Supported Sudoku table types / ASCII steganography modes.
    enum TableType: String, CaseIterable, Equatable {
        case preferEntropy = "prefer_entropy"
        case preferASCII = "prefer_ascii"
        case upASCIIToDownEntropy = "up_ascii_down_entropy"
        case upEntropyToDownASCII = "up_entropy_down_ascii"

        static func parse(_ raw: String?) -> TableType? {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
                return .preferEntropy // default
            }
            switch raw {
            case "prefer_entropy", "entropy": return .preferEntropy
            case "prefer_ascii", "ascii": return .preferASCII
            case "up_ascii_down_entropy": return .upASCIIToDownEntropy
            case "up_entropy_down_ascii": return .upEntropyToDownASCII
            default: return nil
            }
        }
    }

    /// Supported multiplex modes.
    enum MultiplexMode: String, CaseIterable, Equatable {
        case off = "off"
        case auto = "auto"
        case on = "on"

        static func parse(_ raw: String?) -> MultiplexMode? {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
                return .off // default
            }
            switch raw {
            case "off", "0", "false": return .off
            case "auto": return .auto
            case "on", "1", "true": return .on
            default: return nil
            }
        }
    }

    /// HTTP masking configuration.
    struct HTTPMaskConfig: Equatable {
        var disable: Bool = false
        var mode: String = "legacy"
        var tls: Bool = false
        var host: String = ""
        var pathRoot: String = ""

        static let supportedModes: Set<String> = ["legacy", "stream", "poll", "auto", "ws"]

        static func parse(from json: [String: NCJSONValue]?) -> HTTPMaskConfig {
            guard let json else { return HTTPMaskConfig() }
            let disable = json["disable"]?.bool ?? false
            let mode = json["mode"]?.string?.lowercased() ?? "legacy"
            let tls = json["tls"]?.bool ?? false
            let host = json["host"]?.string ?? ""
            let pathRoot = json["path-root"]?.string ?? json["path_root"]?.string ?? ""
            return HTTPMaskConfig(disable: disable, mode: mode, tls: tls, host: host, pathRoot: pathRoot)
        }
    }

    /// Validates an 8-character custom table pattern.
    /// According to the official Sudoku spec, a valid custom table must consist of
    /// exactly 2 'x', 2 'p', and 4 'v' characters (all 420 permutations accepted).
    static func isValidCustomTable(_ s: String) -> Bool {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard trimmed.count == 8 else { return false }
        var countX = 0, countP = 0, countV = 0
        for ch in trimmed {
            switch ch {
            case "x": countX += 1
            case "p": countP += 1
            case "v": countV += 1
            default: return false
            }
        }
        return countX == 2 && countP == 2 && countV == 4
    }

    /// Checks if a Sudoku proxy configuration has any unsupported or invalid parameters.
    /// Returns nil if supported and valid; returns a descriptive Chinese reason string otherwise.
    static func unsupportedReason(_ p: NCProxy) -> String? {
        guard let server = p.server, !server.isEmpty else {
            return "Sudoku 缺少 server"
        }
        guard let port = p.port, (1...65535).contains(port) else {
            return "Sudoku 缺少有效 port"
        }

        let key = p.fields["key"]?.string ?? p.fields["password"]?.string ?? ""
        guard !key.isEmpty else {
            return "Sudoku 缺少 key"
        }

        // Validate AEAD method
        let rawAEAD = p.fields["aead-method"]?.string ?? p.fields["aead"]?.string
        if let rawAEAD, !rawAEAD.isEmpty, AEADMethod.parse(rawAEAD) == nil {
            return "Sudoku 不支持的 aead-method: \(rawAEAD)"
        }

        // Validate Table type / ASCII mode
        let rawTable = p.fields["table-type"]?.string ?? p.fields["ascii"]?.string
        if let rawTable, !rawTable.isEmpty, TableType.parse(rawTable) == nil {
            return "Sudoku 不支持的 table-type: \(rawTable)"
        }

        // Validate padding range
        let pmin = p.fields["padding-min"]?.int ?? p.fields["padding_min"]?.int ?? 5
        let pmax = p.fields["padding-max"]?.int ?? p.fields["padding_max"]?.int ?? 15
        guard pmin >= 0, pmax >= pmin, pmax <= 100 else {
            return "Sudoku padding 范围无效: \(pmin)-\(pmax) (须 0 <= min <= max <= 100)"
        }

        // Validate custom table
        if let ct = p.fields["custom-table"]?.string ?? p.fields["custom_table"]?.string, !ct.isEmpty {
            guard isValidCustomTable(ct) else {
                return "Sudoku custom-table 无效: 须由 2个x、2个p、4个v 组成的8字符 (如 xpxvvpvv)"
            }
        }
        if let cts = p.fields["custom-tables"]?.array ?? p.fields["custom_tables"]?.array {
            for item in cts {
                if let s = item.string, !s.isEmpty, !isValidCustomTable(s) {
                    return "Sudoku custom-tables 包含无效条目: \(s)"
                }
            }
        }

        // Validate multiplex
        if let mux = p.fields["multiplex"]?.string, !mux.isEmpty, MultiplexMode.parse(mux) == nil {
            return "Sudoku multiplex 无效: 须为 off、auto 或 on"
        }

        // Validate httpmask
        if let hmObj = p.fields["httpmask"]?.object {
            if let mode = hmObj["mode"]?.string?.lowercased(), !HTTPMaskConfig.supportedModes.contains(mode) {
                return "Sudoku httpmask mode 不支持: \(mode)"
            }
        }

        // Flag features that are explicitly unsupported in outbound client
        if p.fields["reverse"] != nil {
            return "Sudoku reverse (反向代理) 尚未接入"
        }
        if p.fields["users"] != nil {
            return "Sudoku users (服务端白名单) 仅用于服务端"
        }

        return nil
    }

    /// Parse a sudoku:// share URI or short link.
    /// Supports:
    /// 1. Official shortlink: `sudoku://<base64url(json)>`
    /// 2. Standard URI format: `sudoku://key@host:port?params#name`
    static func parseURI(_ rest: String) -> NCProxy? {
        var body = rest
        var fragment = ""
        if let hash = body.firstIndex(of: "#") {
            fragment = String(body[body.index(after: hash)...]).removingPercentEncoding ?? ""
            body = String(body[..<hash])
        }

        // Mode 1: Shortlink base64url(json)
        if !body.contains("@"), let decoded = base64URLDecode(body) {
            if let json = (try? JSONSerialization.jsonObject(with: decoded)) as? [String: Any] {
                return buildFromShortLinkJSON(json, fragment: fragment)
            }
        }

        // Mode 2: Standard URI key@host:port?...
        if body.contains("@") {
            return buildFromStandardURI(rest)
        }

        return nil
    }

    private static func buildFromShortLinkJSON(_ json: [String: Any], fragment: String) -> NCProxy? {
        guard let host = json["h"] as? String, !host.isEmpty,
              let key = json["k"] as? String, !key.isEmpty else {
            return nil
        }
        let portInt: Int
        if let num = json["p"] as? NSNumber { portInt = num.intValue }
        else if let pStr = json["p"] as? String, let p = Int(pStr) { portInt = p }
        else { return nil }
        guard (1...65535).contains(portInt) else { return nil }

        let nameFromJSON = (json["n"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let name: String
        if let n = nameFromJSON, !n.isEmpty { name = n }
        else if !fragment.isEmpty { name = fragment }
        else { name = host }

        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(portInt)),
            "key": .string(key),
            "password": .string(key),
        ]

        let aead = (json["e"] as? String) ?? "chacha20-poly1305"
        fields["aead-method"] = .string(aead)

        let asciiRaw = (json["a"] as? String) ?? "entropy"
        let tableType: String
        switch asciiRaw.lowercased() {
        case "ascii": tableType = "prefer_ascii"
        case "entropy": tableType = "prefer_entropy"
        default: tableType = asciiRaw
        }
        fields["table-type"] = .string(tableType)

        let packedDownlink = (json["x"] as? Bool) ?? false
        fields["enable-pure-downlink"] = .bool(!packedDownlink)

        fields["padding-min"] = .number(5)
        fields["padding-max"] = .number(15)

        if let ct = json["t"] as? String, !ct.isEmpty {
            fields["custom-table"] = .string(ct)
        }
        if let ts = json["ts"] as? [String], !ts.isEmpty {
            fields["custom-tables"] = .array(ts.map { .string($0) })
        }
        if let mux = json["hx"] as? String, !mux.isEmpty {
            fields["multiplex"] = .string(mux)
        }

        var hmFields: [String: NCJSONValue] = [:]
        if let hd = json["hd"] as? Bool { hmFields["disable"] = .bool(hd) }
        if let hm = json["hm"] as? String { hmFields["mode"] = .string(hm) }
        if let ht = json["ht"] as? Bool { hmFields["tls"] = .bool(ht) }
        if let hh = json["hh"] as? String { hmFields["host"] = .string(hh) }
        if let hy = json["hy"] as? String { hmFields["path-root"] = .string(hy) }
        if !hmFields.isEmpty {
            fields["httpmask"] = .object(hmFields)
        }

        return NCProxy(name: name, type: "sudoku", fields: fields)
    }

    private static func buildFromStandardURI(_ uri: String) -> NCProxy? {
        var s = uri
        var frag = ""
        if let hash = s.firstIndex(of: "#") {
            frag = String(s[s.index(after: hash)...]).removingPercentEncoding ?? ""
            s = String(s[..<hash])
        }
        var query: [String: String] = [:]
        if let q = s.firstIndex(of: "?") {
            let qs = s[s.index(after: q)...]
            s = String(s[..<q])
            for pair in qs.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 {
                    query[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
                }
            }
        }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        var key = ""
        if let at = s.lastIndex(of: "@") {
            key = String(s[..<at]).removingPercentEncoding ?? String(s[..<at])
            s = String(s[s.index(after: at)...])
        }
        var host = s
        var port = 0
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            host = String(s[s.index(after: s.startIndex)..<close])
            let tail = s[s.index(after: close)...]
            if tail.hasPrefix(":") { port = Int(tail.dropFirst()) ?? 0 }
        } else if let colon = s.lastIndex(of: ":") {
            host = String(s[..<colon])
            port = Int(s[s.index(after: colon)...]) ?? 0
        }
        guard !host.isEmpty, (1...65535).contains(port), !key.isEmpty else { return nil }

        let name = !frag.isEmpty ? frag : host
        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(port)),
            "key": .string(key),
            "password": .string(key),
        ]
        if let a = query["aead-method"] ?? query["aead"] { fields["aead-method"] = .string(a) }
        if let t = query["table-type"] ?? query["ascii"] { fields["table-type"] = .string(t) }
        if let ct = query["custom-table"] ?? query["custom_table"] { fields["custom-table"] = .string(ct) }
        if let pmin = query["padding-min"] ?? query["padding_min"], let n = Int(pmin) { fields["padding-min"] = .number(Double(n)) }
        if let pmax = query["padding-max"] ?? query["padding_max"], let n = Int(pmax) { fields["padding-max"] = .number(Double(n)) }
        if let pd = query["enable-pure-downlink"] ?? query["pure-downlink"], let b = boolVal(pd) { fields["enable-pure-downlink"] = .bool(b) }
        if let m = query["multiplex"] { fields["multiplex"] = .string(m) }

        return NCProxy(name: name, type: "sudoku", fields: fields)
    }

    private static func boolVal(_ s: String) -> Bool? {
        switch s.lowercased() {
        case "true", "1", "yes": return true
        case "false", "0", "no": return false
        default: return nil
        }
    }

    private static func base64URLDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }

    /// Build a short link from an NCProxy.
    static func buildShortLink(from proxy: NCProxy) -> String? {
        guard let server = proxy.server, !server.isEmpty,
              let port = proxy.port, (1...65535).contains(port) else { return nil }
        let key = proxy.fields["key"]?.string ?? proxy.fields["password"]?.string ?? ""
        guard !key.isEmpty else { return nil }

        var dict: [String: Any] = [
            "h": server,
            "p": port,
            "k": key,
        ]
        if !proxy.name.isEmpty && proxy.name != server {
            dict["n"] = proxy.name
        }
        if let aead = proxy.fields["aead-method"]?.string ?? proxy.fields["aead"]?.string {
            dict["e"] = aead
        }
        if let table = proxy.fields["table-type"]?.string ?? proxy.fields["ascii"]?.string {
            switch table.lowercased() {
            case "prefer_ascii", "ascii": dict["a"] = "ascii"
            case "prefer_entropy", "entropy": dict["a"] = "entropy"
            default: dict["a"] = table
            }
        }
        if let pure = proxy.fields["enable-pure-downlink"]?.bool, !pure {
            dict["x"] = true
        }
        if let ct = proxy.fields["custom-table"]?.string {
            dict["t"] = ct
        }
        if let mux = proxy.fields["multiplex"]?.string {
            dict["hx"] = mux
        }
        if let hm = proxy.fields["httpmask"]?.object {
            if let hd = hm["disable"]?.bool { dict["hd"] = hd }
            if let m = hm["mode"]?.string { dict["hm"] = m }
            if let tls = hm["tls"]?.bool { dict["ht"] = tls }
            if let host = hm["host"]?.string { dict["hh"] = host }
            if let pr = hm["path-root"]?.string { dict["hy"] = pr }
        }

        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              !data.isEmpty else { return nil }
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "sudoku://" + b64
    }
}
