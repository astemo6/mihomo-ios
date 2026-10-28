import Foundation

/// Sudoku protocol configuration, validation, and import helpers.
///
/// - Official repository: SUDOKU-ASCII/sudoku (GPL-3.0), server/client v0.5.2 — the interop peer.
/// - Clash.Meta (≥ 1.19.21) `type: sudoku` field names are the canonical node fields here; importers
///   (sudoku:// short links / URIs, Surge-style and Quantumult X lines) normalise into them, and the
///   official nested `httpmask:` block is still honoured (it overrides the flat keys, as in Clash.Meta).
/// - First draft (parsing, KIP / AEAD framing, interop analysis) by astemo6 (#162); data plane made
///   wire-compatible in fix/nc-sudoku-interop (NCSudokuWire / NCSudokuSession).
/// - Design note: docs/nc-proto-sudoku.md
enum NCSudoku {

    /// Supported AEAD encryption methods (raw values are the wire names mixed into the record keys).
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
            case "none", "plain": return AEADMethod.none // not `.none`: that would be Optional.none
            default: return nil
            }
        }
    }

    /// Supported multiplex modes.
    enum MultiplexMode: String, CaseIterable, Equatable {
        case off, auto, on

        static func parse(_ raw: String?) -> MultiplexMode? {
            guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
                return .off
            }
            switch raw {
            case "off", "0", "false": return .off
            case "auto": return .auto
            case "on", "1", "true": return .on
            default: return nil
            }
        }
    }

    static let httpMaskModes: Set<String> = ["legacy", "stream", "poll", "auto", "ws"]

    /// A node's settings as the data plane uses them (Clash semantics and defaults).
    struct Options: Equatable {
        var server: String
        var port: Int
        var key: String
        var aead: AEADMethod
        var aeadRaw: String?
        var mode: NCSudokuASCIIMode
        var modeRaw: String?
        var customTable: String?
        var customTables: [String]
        var paddingMin: Int
        var paddingMax: Int
        var pureDownlink: Bool
        /// HTTP mask on (Clash `http-mask`, default true) — legacy mode sends one fake HTTP request head.
        var httpMaskEnabled: Bool
        var httpMaskMode: String
        var httpMaskTLS: Bool
        var httpMaskHost: String
        var pathRoot: String
        var multiplexRaw: String?

        init(proxy p: NCProxy) {
            let f = p.fields
            func str(_ keys: String...) -> String? {
                for k in keys { if let s = f[k]?.string, !s.isEmpty { return s } }
                return nil
            }
            func int(_ keys: String...) -> Int? {
                for k in keys { if let v = f[k]?.int { return v } }
                return nil
            }
            func bool(_ keys: String...) -> Bool? {
                for k in keys {
                    if let b = f[k]?.bool { return b }
                    if let s = f[k]?.string, let b = NCSudoku.boolValue(s) { return b }
                }
                return nil
            }
            server = p.server ?? ""
            port = p.port ?? 0
            key = str("key", "password") ?? ""
            aeadRaw = str("aead-method", "aead")
            aead = AEADMethod.parse(aeadRaw) ?? .chacha20Poly1305
            modeRaw = str("table-type", "ascii")
            mode = NCSudokuASCIIMode.parse(modeRaw) ?? NCSudokuASCIIMode(uplinkASCII: false, downlinkASCII: false)
            customTable = str("custom-table", "custom_table")
            customTables = (f["custom-tables"]?.array ?? f["custom_tables"]?.array ?? [])
                .compactMap { $0.string?.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            // Clash padding resolution: defaults 10 / 30; a lone bound drags the other along.
            let pmin = int("padding-min", "padding_min")
            let pmax = int("padding-max", "padding_max")
            var lo = pmin ?? 10, hi = pmax ?? 30
            if pmin == nil, pmax != nil, hi < lo { lo = hi }
            if pmax == nil, pmin != nil, hi < lo { hi = lo }
            paddingMin = lo
            paddingMax = hi
            pureDownlink = bool("enable-pure-downlink", "enable_pure_downlink") ?? true
            var enabled = bool("http-mask") ?? true
            var hmMode = str("http-mask-mode") ?? "legacy"
            var tls = bool("http-mask-tls") ?? false
            var host = str("http-mask-host") ?? ""
            var root = str("path-root") ?? ""
            var mux = str("multiplex") ?? str("http-mask-multiplex")
            if let hm = f["httpmask"]?.object {
                enabled = !(hm["disable"]?.bool ?? false)
                if let m = hm["mode"]?.string, !m.isEmpty { hmMode = m }
                tls = hm["tls"]?.bool ?? false
                host = hm["host"]?.string ?? ""
                if let r = (hm["path-root"] ?? hm["path_root"])?.string?.trimmingCharacters(in: .whitespaces), !r.isEmpty {
                    root = r
                }
                if let m = hm["multiplex"]?.string?.trimmingCharacters(in: .whitespaces), !m.isEmpty { mux = m }
            }
            httpMaskEnabled = enabled
            httpMaskMode = hmMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            httpMaskTLS = tls
            httpMaskHost = host
            pathRoot = root
            multiplexRaw = mux
        }

        /// server:port as the legacy HTTP head's Host (IPv6 bracketed), like the official client.
        var serverHostPort: String {
            return server.contains(":") ? "[\(server)]:\(port)" : "\(server):\(port)"
        }

        /// Valid by the protocol but not implemented by this data plane: an explicit reason, never a timeout.
        var dataPlaneUnsupported: String? {
            if httpMaskEnabled && httpMaskMode != "legacy" {
                return "Sudoku HTTP 隧道模式 \(httpMaskMode)（stream / poll / auto / ws）尚未接入，请改用 legacy 或关闭 HTTP 伪装"
            }
            if MultiplexMode.parse(multiplexRaw) == .on {
                return "Sudoku multiplex: on（会话多路复用）尚未接入，请设为 off"
            }
            return nil
        }
    }

    /// Validates a 8-character custom table pattern: exactly 2 'x', 2 'p', 4 'v' (420 permutations).
    static func isValidCustomTable(_ s: String) -> Bool {
        NCSudokuLayout.custom(s) != nil
    }

    /// Nil when the node is valid and the data plane can dial it; otherwise a descriptive reason.
    static func unsupportedReason(_ p: NCProxy) -> String? {
        guard let server = p.server, !server.isEmpty else { return "Sudoku 缺少 server" }
        guard let port = p.port, (1...65535).contains(port) else { return "Sudoku 缺少有效 port" }
        let o = Options(proxy: p)
        guard !o.key.isEmpty else { return "Sudoku 缺少 key" }
        if let raw = o.aeadRaw, AEADMethod.parse(raw) == nil { return "Sudoku 不支持的 aead-method: \(raw)" }
        if let raw = o.modeRaw, NCSudokuASCIIMode.parse(raw) == nil { return "Sudoku 不支持的 table-type: \(raw)" }
        guard o.paddingMin >= 0, o.paddingMax >= o.paddingMin, o.paddingMax <= 100 else {
            return "Sudoku padding 范围无效: \(o.paddingMin)-\(o.paddingMax) (须 0 <= min <= max <= 100)"
        }
        if let ct = o.customTable, !isValidCustomTable(ct) {
            return "Sudoku custom-table 无效: 须由 2个x、2个p、4个v 组成的8字符 (如 xpxvvpvv)"
        }
        for s in o.customTables where !isValidCustomTable(s) {
            return "Sudoku custom-tables 包含无效条目: \(s)"
        }
        if let mux = o.multiplexRaw, MultiplexMode.parse(mux) == nil { return "Sudoku multiplex 无效: 须为 off、auto 或 on" }
        if !httpMaskModes.contains(o.httpMaskMode) { return "Sudoku httpmask mode 不支持: \(o.httpMaskMode)" }
        if p.fields["reverse"] != nil { return "Sudoku reverse (反向代理) 尚未接入" }
        if p.fields["users"] != nil { return "Sudoku users (服务端白名单) 仅用于服务端" }
        return o.dataPlaneUnsupported
    }

    static func boolValue(_ s: String) -> Bool? {
        switch s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "1", "yes", "on": return true
        case "false", "0", "no", "off": return false
        default: return nil
        }
    }

    // MARK: - Import normalisation

    /// Maps a Surge / Loon / Quantumult X style `key=value` line's Sudoku parameters (taken through `take`,
    /// which removes them) onto the canonical (Clash) fields.
    static func importParams(into fields: inout [String: NCJSONValue], take: (String) -> String?) {
        if let k = take("key") ?? take("password") { fields["key"] = .string(k) }
        if let a = take("aead-method") ?? take("aead") { fields["aead-method"] = .string(a) }
        if let t = take("table-type") ?? take("ascii") { fields["table-type"] = .string(t) }
        if let ct = take("custom-table") ?? take("custom_table") ?? take("table") { fields["custom-table"] = .string(ct) }
        if let cts = take("custom-tables") ?? take("custom_tables") {
            let list = cts.replacingOccurrences(of: "|", with: ",").split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if !list.isEmpty { fields["custom-tables"] = .array(list.map { .string($0) }) }
        }
        if let v = take("udp"), let b = boolValue(v) { fields["udp"] = .bool(b) }
        if let v = take("padding-min") ?? take("padding_min"), let n = Int(v) { fields["padding-min"] = .number(Double(n)) }
        if let v = take("padding-max") ?? take("padding_max"), let n = Int(v) { fields["padding-max"] = .number(Double(n)) }
        if let v = take("enable-pure-downlink") ?? take("pure-downlink"), let b = boolValue(v) {
            fields["enable-pure-downlink"] = .bool(b)
        }
        if let v = take("http-mask"), let b = boolValue(v) { fields["http-mask"] = .bool(b) }
        if let v = take("httpmask-disable") ?? take("http-mask-disable"), let b = boolValue(v) { fields["http-mask"] = .bool(!b) }
        if let v = take("http-mask-mode") ?? take("httpmask-mode") { fields["http-mask-mode"] = .string(v) }
        if let v = take("http-mask-tls") ?? take("httpmask-tls"), let b = boolValue(v) { fields["http-mask-tls"] = .bool(b) }
        if let v = take("http-mask-host") ?? take("httpmask-host") { fields["http-mask-host"] = .string(v) }
        if let v = take("path-root") ?? take("httpmask-path") ?? take("http-mask-path") { fields["path-root"] = .string(v) }
        if let v = take("multiplex") ?? take("http-mask-multiplex") { fields["multiplex"] = .string(v) }
    }

    // MARK: - Share links

    /// Parse a sudoku:// share link:
    /// 1. Official short link `sudoku://<base64url(json)>` (fields n/h/p/k/a/e/x/t/ts/hd/hm/ht/hh/hx/hy).
    /// 2. URI form `sudoku://key@host:port?params#name`.
    static func parseURI(_ rest: String) -> NCProxy? {
        var body = rest
        var fragment = ""
        if let hash = body.firstIndex(of: "#") {
            fragment = String(body[body.index(after: hash)...]).removingPercentEncoding ?? ""
            body = String(body[..<hash])
        }
        if !body.contains("@"), let decoded = base64URLDecode(body),
           let json = (try? JSONSerialization.jsonObject(with: decoded)) as? [String: Any] {
            return buildFromShortLinkJSON(json, fragment: fragment)
        }
        if body.contains("@") { return buildFromStandardURI(rest) }
        return nil
    }

    private static func buildFromShortLinkJSON(_ json: [String: Any], fragment: String) -> NCProxy? {
        guard let host = json["h"] as? String, !host.isEmpty,
              let key = json["k"] as? String, !key.isEmpty else { return nil }
        let portInt: Int
        if let num = json["p"] as? NSNumber { portInt = num.intValue }
        else if let s = json["p"] as? String, let p = Int(s) { portInt = p }
        else { return nil }
        guard (1...65535).contains(portInt) else { return nil }

        let nameFromJSON = (json["n"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let name = !nameFromJSON.isEmpty ? nameFromJSON : (!fragment.isEmpty ? fragment : host)
        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(portInt)),
            "key": .string(key),
            // The official link builder always writes "e"; a link without it means "none" to the official
            // client (BuildConfigFromShortLink), not the chacha default of a YAML node.
            "aead-method": .string((json["e"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "none"),
            // Official short-link client padding.
            "padding-min": .number(5),
            "padding-max": .number(15),
        ]
        let ascii = (json["a"] as? String) ?? ""
        fields["table-type"] = .string(NCSudokuASCIIMode.parse(ascii)?.canonical ?? "prefer_entropy")
        fields["enable-pure-downlink"] = .bool(!((json["x"] as? Bool) ?? false))
        if let ct = json["t"] as? String, !ct.isEmpty { fields["custom-table"] = .string(ct) }
        if let ts = json["ts"] as? [String], !ts.isEmpty { fields["custom-tables"] = .array(ts.map { .string($0) }) }
        if let hd = json["hd"] as? Bool { fields["http-mask"] = .bool(!hd) }
        if let hm = json["hm"] as? String, !hm.isEmpty { fields["http-mask-mode"] = .string(hm) }
        if let ht = json["ht"] as? Bool, ht { fields["http-mask-tls"] = .bool(true) }
        if let hh = json["hh"] as? String, !hh.isEmpty { fields["http-mask-host"] = .string(hh) }
        if let hy = json["hy"] as? String, !hy.isEmpty { fields["path-root"] = .string(hy) }
        if let hx = json["hx"] as? String, !hx.isEmpty { fields["multiplex"] = .string(hx) }
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
                    query[String(kv[0]).lowercased()] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
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

        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(port)),
            "key": .string(key),
        ]
        importParams(into: &fields) { query.removeValue(forKey: $0) }
        return NCProxy(name: !frag.isEmpty ? frag : host, type: "sudoku", fields: fields)
    }

    private static func base64URLDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        while b.count % 4 != 0 { b.append("=") }
        return Data(base64Encoded: b)
    }

    /// Official short link for a node (same JSON keys as `sudoku -export-link`).
    static func buildShortLink(from proxy: NCProxy) -> String? {
        guard let server = proxy.server, !server.isEmpty,
              let port = proxy.port, (1...65535).contains(port) else { return nil }
        let o = Options(proxy: proxy)
        guard !o.key.isEmpty else { return nil }
        var dict: [String: Any] = ["h": server, "p": port, "k": o.key, "e": o.aead.rawValue]
        if !proxy.name.isEmpty && proxy.name != server { dict["n"] = proxy.name }
        switch o.mode.canonical {
        case "prefer_ascii": dict["a"] = "ascii"
        case "prefer_entropy": dict["a"] = "entropy"
        case let other: dict["a"] = other
        }
        if !o.pureDownlink { dict["x"] = true }
        if let ct = o.customTable { dict["t"] = ct }
        if !o.customTables.isEmpty { dict["ts"] = o.customTables }
        if !o.httpMaskEnabled { dict["hd"] = true }
        if o.httpMaskMode != "legacy" { dict["hm"] = o.httpMaskMode }
        if o.httpMaskTLS { dict["ht"] = true }
        if !o.httpMaskHost.isEmpty { dict["hh"] = o.httpMaskHost }
        if !o.pathRoot.isEmpty { dict["hy"] = o.pathRoot }
        if let mux = MultiplexMode.parse(o.multiplexRaw), mux != .off { dict["hx"] = mux.rawValue }
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]) else { return nil }
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "sudoku://" + b64
    }
}
