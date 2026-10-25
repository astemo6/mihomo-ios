import Foundation

// XHTTP (Xray "splithttp") transport — configuration and request construction (feat/nc-xhttp).
//
// Ported from mihomo v1.19.33 transport/xhttp (config.go, xpadding.go, browser.go) and the VLESS adapter's
// xhttp-opts handling (adapter/outbound/vless.go). The wire side (one HTTP/2 connection per dial, the three
// modes) lives in NCXHTTPStream.swift. Everything here is pure: tests build requests without a socket.

/// mihomo xhttp.Range: "100-1000" or "30" (ParseRange / parseRange).
struct NCXHTTPRange: Equatable {
    var min: Int
    var max: Int

    init(_ min: Int, _ max: Int) {
        self.min = min
        self.max = max
    }

    func rand() -> Int { min >= max ? min : Int.random(in: min...max) }

    /// nil = invalid. An empty / blank `s` parses `fallback` instead (mihomo ParseRange).
    static func parse(_ s: String?, fallback: String) -> NCXHTTPRange? {
        let t = (s ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return parseRaw(t.isEmpty ? fallback : t)
    }

    private static func parseRaw(_ s: String) -> NCXHTTPRange? {
        let parts = s.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: "-", omittingEmptySubsequences: false).map(String.init)
        if parts.count == 1 {
            guard let v = Int(parts[0]) else { return nil }
            return NCXHTTPRange(v, v)
        }
        guard parts.count == 2,
              let a = Int(parts[0].trimmingCharacters(in: .whitespacesAndNewlines)),
              let b = Int(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)),
              a >= 0, b >= a else { return nil }
        return NCXHTTPRange(a, b)
    }
}

/// Ordered HTTP header list with Go http.Header Set / Get / Del semantics on case-insensitive names.
/// Names are stored lowercased (HTTP/2 requires it).
struct NCXHTTPHeaders: Equatable {
    private(set) var fields: [(name: String, value: String)] = []

    static func == (a: NCXHTTPHeaders, b: NCXHTTPHeaders) -> Bool {
        a.fields.count == b.fields.count && zip(a.fields, b.fields).allSatisfy { $0.name == $1.name && $0.value == $1.value }
    }

    func get(_ name: String) -> String? {
        let n = name.lowercased()
        return fields.first(where: { $0.name == n })?.value
    }

    func has(_ name: String) -> Bool { get(name) != nil }

    mutating func set(_ name: String, _ value: String) {
        let n = name.lowercased()
        if let i = fields.firstIndex(where: { $0.name == n }) {
            fields[i].value = value
            var j = fields.count - 1
            while j > i { if fields[j].name == n { fields.remove(at: j) }; j -= 1 } // one entry per name
        } else {
            fields.append((n, value))
        }
    }

    mutating func del(_ name: String) {
        let n = name.lowercased()
        fields.removeAll { $0.name == n }
    }

    /// Go http.Request.AddCookie: appended to the one Cookie header with "; ".
    mutating func addCookie(_ name: String, _ value: String) {
        let c = "\(name)=\(value)"
        if let existing = get("cookie"), !existing.isEmpty {
            set("cookie", existing + "; " + c)
        } else {
            set("cookie", c)
        }
    }
}

/// One built XHTTP request: what goes into the HTTP/2 HEADERS frame (+ the body for packet-up body placement).
struct NCXHTTPRequest {
    var method: String
    var authority: String
    /// Unescaped path (session / seq segments appended).
    var path: String
    /// Query parameters (url.Values; encoded sorted by key, like Go's Values.Encode).
    var query: [String: String] = [:]
    var headers = NCXHTTPHeaders()
    var body: Data?
    /// The request streams a body (stream-one / stream-up upload): no content-length.
    var streamingBody = false

    /// Go url.URL.RequestURI(): escaped path + "?" + encoded query.
    var requestURI: String {
        var s = NCXHTTPConfig.escapePath(path)
        if !query.isEmpty {
            s += "?" + query.keys.sorted().map {
                NCXHTTPConfig.queryEscape($0) + "=" + NCXHTTPConfig.queryEscape(query[$0] ?? "")
            }.joined(separator: "&")
        }
        return s
    }

    /// The HTTP/2 header block: pseudo-headers, then the request headers (connection-specific ones
    /// dropped, as Go's http2 transport does), then content-length per Go's shouldSendReqContentLength.
    func h2Headers() -> [(String, String)] {
        var out: [(String, String)] = [
            (":method", method), (":scheme", "https"), (":authority", authority), (":path", requestURI),
        ]
        let skip: Set<String> = ["host", "content-length", "connection", "proxy-connection", "transfer-encoding",
                                 "upgrade", "keep-alive", "te"]
        for f in headers.fields where !skip.contains(f.name) && !f.name.isEmpty {
            out.append((f.name, f.value))
        }
        if !streamingBody {
            let n = body?.count ?? 0
            if n > 0 || ["POST", "PUT", "PATCH"].contains(method.uppercased()) {
                out.append(("content-length", String(n)))
            }
        }
        if !headers.has("user-agent") { out.append(("user-agent", "Go-http-client/2.0")) }
        return out
    }
}

struct NCXHTTPError: Error, LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}

/// mihomo xhttp.Config for the client side, with every Normalized*() getter resolved at parse time.
struct NCXHTTPConfig {
    static let placementQueryInHeader = "queryInHeader"
    static let placementCookie = "cookie"
    static let placementHeader = "header"
    static let placementQuery = "query"
    static let placementPath = "path"
    static let placementBody = "body"
    static let placementAuto = "auto"

    var host: String
    var rawPath: String
    /// "" in the config is "auto" (NormalizedMode).
    var mode: String
    /// xhttp-opts.headers, sorted by name for a deterministic order (Go map order is random anyway).
    var headers: [(String, String)] = []
    var noGRPCHeader = false
    var xPaddingBytes = NCXHTTPRange(100, 1000)
    var xPaddingObfsMode = false
    var xPaddingKey = ""
    var xPaddingHeader = ""
    var xPaddingPlacement = ""
    var xPaddingMethod = ""
    var uplinkHTTPMethod = "POST"
    var sessionPlacement = placementPath
    var sessionKey = ""
    var seqPlacement = placementPath
    var seqKey = ""
    var uplinkDataPlacement = placementBody
    var uplinkDataKey = ""
    var uplinkChunkSize = NCXHTTPRange(1_000_000, 1_000_000)
    var scMaxEachPostBytes = NCXHTTPRange(1_000_000, 1_000_000)
    var scMinPostsIntervalMs = NCXHTTPRange(30, 30)
    var sessionTable = ""
    var sessionLength = NCXHTTPRange(16, 32)
    var hasDownloadSettings = false
    var alpn: [String] = []

    init(host: String, path: String = "/", mode: String = "auto") {
        self.host = host
        self.rawPath = path
        self.mode = mode.isEmpty ? "auto" : mode
    }

    // MARK: parse (adapter/outbound/vless.go xhttp-opts + xhttp.NewClient validation)

    /// Builds the config from a proxy's fields. Throws the error mihomo's NewVless / NewClient would
    /// return for the same options (invalid range, unknown mode, session-table too small, …).
    static func parse(_ proxy: NCProxy) throws -> NCXHTTPConfig {
        let f = proxy.fields
        let o = f["xhttp-opts"]?.object ?? [:]
        func s(_ k: String) -> String { scalar(o[k]) }

        var host = s("host")
        if host.isEmpty {
            let sni = proxy.type.lowercased() == "trojan"
                ? (f["sni"]?.string ?? f["servername"]?.string ?? "")
                : (f["servername"]?.string ?? f["sni"]?.string ?? "")
            host = sni.isEmpty ? (proxy.server ?? "") : sni
            // netip.ParseAddr(...).Is6(): a hostname never contains ":", so any colon means an IPv6 literal.
            if host.contains(":"), !host.hasPrefix("[") { host = "[\(host)]" }
        }
        var c = NCXHTTPConfig(host: host, path: s("path"), mode: s("mode"))
        if let h = o["headers"]?.object {
            c.headers = h.keys.sorted().compactMap { k -> (String, String)? in
                guard let v = h[k], v.object == nil, v.array == nil else { return nil }
                return (k, scalar(v))
            }
        }
        c.noGRPCHeader = o["no-grpc-header"]?.bool ?? (s("no-grpc-header") == "true")
        c.xPaddingObfsMode = o["x-padding-obfs-mode"]?.bool ?? (s("x-padding-obfs-mode") == "true")
        c.xPaddingKey = s("x-padding-key")
        c.xPaddingHeader = s("x-padding-header")
        c.xPaddingPlacement = s("x-padding-placement")
        c.xPaddingMethod = s("x-padding-method")
        let method = s("uplink-http-method")
        c.uplinkHTTPMethod = method.isEmpty ? "POST" : method
        let sp = s("session-placement"), qp = s("seq-placement"), dp = s("uplink-data-placement")
        c.sessionPlacement = sp.isEmpty ? placementPath : sp
        c.seqPlacement = qp.isEmpty ? placementPath : qp
        c.uplinkDataPlacement = dp.isEmpty ? placementBody : dp
        c.sessionKey = normalizedKey(s("session-key"), placement: c.sessionPlacement, header: "X-Session", other: "x_session")
        c.seqKey = normalizedKey(s("seq-key"), placement: c.seqPlacement, header: "X-Seq", other: "x_seq")
        c.uplinkDataKey = s("uplink-data-key")
        c.sessionTable = s("session-table")
        c.hasDownloadSettings = o["download-settings"]?.object != nil
        c.alpn = f["alpn"]?.array?.compactMap { $0.string } ?? []

        switch c.mode {
        case "stream-one", "stream-up", "packet-up", "auto": break
        default: throw NCXHTTPError("xhttp mode \(c.mode) is not implemented yet")
        }
        if c.mode == "stream-one" && c.hasDownloadSettings {
            throw NCXHTTPError("xhttp mode \"stream-one\" cannot be used with download-settings")
        }
        guard let xp = NCXHTTPRange.parse(s("x-padding-bytes"), fallback: "100-1000") else {
            throw NCXHTTPError("invalid x-padding-bytes")
        }
        c.xPaddingBytes = xp
        guard let maxPost = NCXHTTPRange.parse(s("sc-max-each-post-bytes"), fallback: "1000000") else {
            throw NCXHTTPError("invalid sc-max-each-post-bytes")
        }
        guard maxPost.max > 0 else { throw NCXHTTPError("invalid sc-max-each-post-bytes: must be greater than zero") }
        c.scMaxEachPostBytes = maxPost
        guard let interval = NCXHTTPRange.parse(s("sc-min-posts-interval-ms"), fallback: "30") else {
            throw NCXHTTPError("invalid sc-min-posts-interval-ms")
        }
        guard interval.max > 0 else { throw NCXHTTPError("invalid sc-min-posts-interval-ms: must be greater than zero") }
        c.scMinPostsIntervalMs = interval
        guard let chunk = NCXHTTPRange.parse(s("uplink-chunk-size"), fallback: "0") else {
            throw NCXHTTPError("invalid uplink-chunk-size")
        }
        c.uplinkChunkSize = c.normalizedChunkSize(chunk)
        if !c.sessionTable.isEmpty && c.sessionTable != "uuid" {
            guard let len = NCXHTTPRange.parse(s("session-length"), fallback: "16-32") else {
                throw NCXHTTPError("invalid session-length")
            }
            let table = predefinedTables[c.sessionTable] ?? c.sessionTable
            if roomSize(table.utf8.count, len.min, len.max) < Double(2 << 30) {
                throw NCXHTTPError("session-table or session-length is too small")
            }
            if len.min <= 0 { throw NCXHTTPError("session-length must be greater than 0") }
            if table.utf8.contains(where: { $0 >= 0x80 }) {
                throw NCXHTTPError("session-table must contain only ASCII characters")
            }
            c.sessionTable = table
            c.sessionLength = len
        }
        return c
    }

    /// Parts of xhttp-opts the native transport does not implement (nil = fully supported).
    static func unsupportedReason(_ proxy: NCProxy) -> String? {
        let t = proxy.type.lowercased()
        guard t == "vless" || t == "vmess" || t == "trojan" else { return "\(t) 不支持 xhttp 传输" }
        let cfg: NCXHTTPConfig
        do { cfg = try parse(proxy) } catch { return "xhttp 配置无效：\((error as? NCXHTTPError)?.message ?? "\(error)")" }
        if cfg.hasDownloadSettings { return "xhttp download-settings（上下行分离）尚未接入" }
        if cfg.alpn.count == 1 && cfg.alpn[0] == "h3" { return "xhttp HTTP/3（alpn: [h3]）尚未接入" }
        if cfg.alpn.count == 1 && cfg.alpn[0] == "http/1.1" { return "xhttp HTTP/1.1（alpn: [http/1.1]）尚未接入" }
        return nil
    }

    private static func scalar(_ v: NCJSONValue?) -> String {
        switch v {
        case .string(let s)?: return s
        case .number(let n)?:
            if n.isFinite, n == n.rounded(), abs(n) < 9e15 { return String(Int64(n)) }
            return String(n)
        case .bool(let b)?: return b ? "true" : "false"
        default: return ""
        }
    }

    private static func normalizedKey(_ key: String, placement: String, header: String, other: String) -> String {
        if !key.isEmpty { return key }
        switch placement {
        case placementHeader: return header
        case placementCookie, placementQuery: return other
        default: return ""
        }
    }

    /// GetNormalizedUplinkChunkSize.
    private func normalizedChunkSize(_ r: NCXHTTPRange) -> NCXHTTPRange {
        var r = r
        if r.max == 0 {
            switch uplinkDataPlacement {
            case Self.placementCookie: return NCXHTTPRange(2 * 1024, 3 * 1024)
            case Self.placementHeader: return NCXHTTPRange(3 * 1024, 4 * 1024)
            default: return scMaxEachPostBytes
            }
        } else if r.min < 64 {
            r.min = 64
            if r.max < 64 { r.max = 64 }
        }
        return r
    }

    static let predefinedTables: [String: String] = [
        "ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX": "0123456789ABCDEF",
        "alphabet": "abcdefghijklmnopqrstuvwxyz",
        "base36": "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex": "0123456789abcdef",
        "number": "0123456789",
    ]

    /// Σ tableSize^k for k in min...max (only compared against 2^31, so Double is exact enough).
    static func roomSize(_ tableSize: Int, _ min: Int, _ max: Int) -> Double {
        guard min <= max else { return 0 }
        var sum = 0.0
        for k in min...max { sum += pow(Double(tableSize), Double(k)); if sum > 1e18 { break } }
        return sum
    }

    // MARK: modes, paths, session ids

    /// EffectiveMode: auto → stream-one over REALITY (stream-up with download-settings), else packet-up.
    func effectiveMode(hasReality: Bool) -> String {
        if mode != "auto" { return mode }
        if hasReality { return hasDownloadSettings ? "stream-up" : "stream-one" }
        return "packet-up"
    }

    /// NormalizedPath: leading "/", and a trailing "/" when the session or seq rides in the path.
    var normalizedPath: String {
        var p = rawPath.isEmpty ? "/" : rawPath
        if !p.hasPrefix("/") { p = "/" + p }
        if (sessionPlacement == Self.placementPath || seqPlacement == Self.placementPath) && !p.hasSuffix("/") {
            p += "/"
        }
        return p
    }

    /// GetGenerateSessionID.
    func generateSessionID() -> String {
        switch sessionTable {
        case "":
            var b = [UInt8](repeating: 0, count: 16)
            for i in b.indices { b[i] = UInt8.random(in: 0...255) }
            return b.map { String(format: "%02x", $0) }.joined()
        case "uuid":
            return UUID().uuidString.lowercased()
        default:
            let table = Array(sessionTable.utf8)
            guard !table.isEmpty else { return "" }
            let n = sessionLength.rand()
            var id = [UInt8](repeating: 0, count: Swift.max(0, n))
            for i in id.indices { id[i] = table[Int.random(in: 0..<table.count)] }
            return String(decoding: id, as: UTF8.self)
        }
    }

    // MARK: request construction (config.go Fill*Request)

    /// GetRequestHeader: xhttp-opts.headers, then the browser masquerade for a fetch() request.
    func baseHeaders() -> NCXHTTPHeaders {
        var h = NCXHTTPHeaders()
        for (k, v) in headers { h.set(k, v) }
        NCXHTTPBrowser.tryDefaultHeaders(&h, variant: "fetch")
        return h
    }

    private func newRequest(method: String) -> NCXHTTPRequest {
        NCXHTTPRequest(method: method, authority: host, path: normalizedPath)
    }

    /// The URL string mihomo reads back for the padding Referer (req.URL.String() before session/seq).
    private func rawURL(_ r: NCXHTTPRequest) -> String { "https://\(host)\(r.requestURI)" }

    /// FillStreamRequest: the stream-one request, the stream-up upload, and every download GET.
    func streamRequest(method: String, sessionID: String, hasBody: Bool) -> NCXHTTPRequest {
        var r = newRequest(method: method)
        r.headers = baseHeaders()
        r.streamingBody = hasBody
        applyPadding(&r)
        applyMeta(&r, sessionID: sessionID, seq: "")
        if hasBody && !noGRPCHeader { r.headers.set("Content-Type", "application/grpc") }
        return r
    }

    /// The download GET of stream-up / packet-up (FillDownloadRequest).
    func downloadRequest(sessionID: String) -> NCXHTTPRequest {
        streamRequest(method: "GET", sessionID: sessionID, hasBody: false)
    }

    /// FillPacketRequest: one packet-up upload of `data` with sequence number `seq`.
    func packetRequest(sessionID: String, seq: UInt64, data: Data) -> NCXHTTPRequest {
        var r = newRequest(method: uplinkHTTPMethod)
        switch uplinkDataPlacement {
        case Self.placementHeader:
            r.headers = baseHeaders()
            for (i, chunk) in chunkedPayload(data).enumerated() { r.headers.set("\(uplinkDataKey)-\(i)", chunk) }
        case Self.placementCookie:
            r.headers = baseHeaders()
            for (i, chunk) in chunkedPayload(data).enumerated() { r.headers.addCookie("\(uplinkDataKey)_\(i)", chunk) }
        default: // body / auto
            r.headers = baseHeaders()
            r.body = data
        }
        applyPadding(&r)
        applyMeta(&r, sessionID: sessionID, seq: String(seq))
        return r
    }

    /// base64.RawURLEncoding of the payload, cut into uplink-chunk-size pieces.
    func chunkedPayload(_ data: Data) -> [String] {
        var encoded = Substring(data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: ""))
        var out: [String] = []
        while !encoded.isEmpty {
            let n = Swift.max(1, Swift.min(uplinkChunkSize.rand(), encoded.count))
            out.append(String(encoded.prefix(n)))
            encoded = encoded.dropFirst(n)
        }
        return out
    }

    /// ApplyXPaddingToRequest with the placement FillStreamRequest / FillPacketRequest choose: the
    /// Referer `?x_padding=` query by default, the x-padding-* settings in obfs mode.
    func applyPadding(_ r: inout NCXHTTPRequest) {
        let length = xPaddingBytes.rand()
        let placement: String, key: String, header: String, method: String
        if xPaddingObfsMode {
            placement = xPaddingPlacement; key = xPaddingKey; header = xPaddingHeader; method = xPaddingMethod
        } else {
            placement = Self.placementQueryInHeader; key = "x_padding"; header = "Referer"; method = ""
        }
        let value = NCXHTTPPadding.generate(method: method, length: length)
        switch placement {
        case Self.placementHeader:
            if !header.isEmpty { r.headers.set(header, value) }
        case Self.placementQueryInHeader:
            if !header.isEmpty { r.headers.set(header, rawURL(r) + "?" + key + "=" + value) }
        case Self.placementCookie:
            if !key.isEmpty, !value.isEmpty { r.headers.addCookie(key, value) }
        case Self.placementQuery:
            if !key.isEmpty, !value.isEmpty { r.query[key] = value }
        default:
            break
        }
    }

    /// ApplyMetaToRequest.
    func applyMeta(_ r: inout NCXHTTPRequest, sessionID: String, seq: String) {
        func put(_ v: String, placement: String, key: String) {
            switch placement {
            case Self.placementPath: r.path = r.path.hasSuffix("/") ? r.path + v : r.path + "/" + v
            case Self.placementQuery: r.query[key] = v
            case Self.placementHeader: r.headers.set(key, v)
            case Self.placementCookie: r.headers.addCookie(key, v)
            default: break
            }
        }
        if !sessionID.isEmpty { put(sessionID, placement: sessionPlacement, key: sessionKey) }
        if !seq.isEmpty { put(seq, placement: seqPlacement, key: seqKey) }
    }

    // MARK: escaping (Go net/url)

    /// url.URL.EscapedPath (encodePath): unreserved + "$&+,/:;=@" stay, everything else %XX.
    static func escapePath(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            let keep = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                || "-_.~$&+,/:;=@".utf8.contains(b)
            if keep { out.append(Character(UnicodeScalar(b))) } else { out += String(format: "%%%02X", b) }
        }
        return out
    }

    /// url.QueryEscape: unreserved stay, space → "+", everything else %XX.
    static func queryEscape(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            let keep = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
                || b == 0x2D || b == 0x5F || b == 0x2E || b == 0x7E
            if keep { out.append(Character(UnicodeScalar(b))) }
            else if b == 0x20 { out.append("+") }
            else { out += String(format: "%%%02X", b) }
        }
        return out
    }
}

// MARK: - padding (xpadding.go)

enum NCXHTTPPadding {
    static let base62 = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".utf8)
    static let tolerance = 2

    /// GeneratePadding: "repeat-x" (and the default) is length × "X" — 'X' has an 8-bit HPACK/QPACK Huffman
    /// code, so header compression keeps the wire length; "tokenish" is base62 sized by its Huffman length.
    static func generate(method: String, length: Int) -> String {
        guard length > 0 else { return "" }
        if method == "tokenish" {
            let v = tokenish(targetHuffmanBytes: length)
            return v.isEmpty ? String(repeating: "X", count: length) : v
        }
        return String(repeating: "X", count: length)
    }

    /// hpack.HuffmanEncodeLength.
    static func huffmanLength(_ s: String) -> Int {
        var bits = 0
        for b in s.utf8 { bits += Int(NCHPACK.huffmanCodeLens[Int(b)]) }
        return (bits + 7) / 8
    }

    /// GenerateTokenishPaddingBase62.
    static func tokenish(targetHuffmanBytes: Int) -> String {
        let n = Swift.max(1, Int((Double(targetHuffmanBytes) / 0.8).rounded(.up)))
        var bytes = (0..<n).map { _ in base62[Int.random(in: 0..<base62.count)] }
        var adjust: UInt8 = UInt8(ascii: "X")
        for _ in 0..<150 {
            let s = String(decoding: bytes, as: UTF8.self)
            let diff = huffmanLength(s) - targetHuffmanBytes
            if abs(diff) <= tolerance { return s }
            if diff < 0 {
                bytes.append(adjust)
                adjust = adjust == UInt8(ascii: "X") ? UInt8(ascii: "Z") : UInt8(ascii: "X")
            } else {
                if bytes.count <= 1 { return s }
                bytes.removeLast()
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

// MARK: - browser masquerade (browser.go)

enum NCXHTTPBrowser {
    private static func daysSinceEpoch(_ d: Date = Date()) -> Int { Int(d.timeIntervalSince1970) / 86400 }

    private static func day(_ y: Int, _ m: Int, _ d: Int) -> Int {
        var c = DateComponents()
        c.year = y; c.month = m; c.day = d
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return daysSinceEpoch(cal.date(from: c) ?? Date())
    }

    /// ChromeVersion: Chrome 144 on 2026-01-13, one major per 35 days, skewed back by up to 105 days.
    static let chromeVersion: Int = {
        let diff = (daysSinceEpoch() - day(2026, 1, 13) - 35) - Int((pow(Double.random(in: 0..<1), 2) * 105).rounded(.down))
        return 144 + diff / 35
    }()

    static let firefoxVersion: Int = {
        let diff = daysSinceEpoch() - day(2024, 7, 29) - 25 - Int((pow(Double.random(in: 0..<1), 2) * 50).rounded(.down))
        return diff / 30 + 128
    }()

    static let curlVersion: String = {
        let diff = (daysSinceEpoch() - day(2023, 3, 20) - 60) - Int((pow(Double.random(in: 0..<1), 2) * 165).rounded(.down))
        return "8.\(diff / 57).0"
    }()

    private static let safariMinor: [Int] = [0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6]

    static let safariVersion: String = {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let now = Date()
        var year = cal.component(.year, from: now)
        let delayed = Int((pow(Double.random(in: 0..<1), 3) * 75).rounded(.down))
        func split(_ y: Int) -> Date {
            var c = DateComponents(); c.year = y; c.month = 9; c.day = 23
            return cal.date(byAdding: .day, value: delayed, to: cal.date(from: c) ?? now) ?? now
        }
        var sp = split(year)
        if now < sp { year -= 1; sp = split(year) }
        let idx = Swift.min(safariMinor.count - 1, Swift.max(0, Int(now.timeIntervalSince(sp)) / 1_296_000))
        return "\(year - 1999).\(safariMinor[idx])"
    }()

    private static let greaseNA = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
    private static let versionNA = ["8", "99", "24"]
    private static let shuffle3: [[Int]] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]

    /// getGreasedChUa (2–3 brands: the GREASE brand, Chromium, and the fork's own).
    static func greasedChUa(_ major: Int, fork: String) -> String {
        var brands = ["\"Not" + greaseNA[major % greaseNA.count] + "A" + greaseNA[(major + 1) % greaseNA.count]
                        + "Brand\";v=\"" + versionNA[major % versionNA.count] + "\"",
                      "\"Chromium\";v=\"\(major)\""]
        if fork == "chrome" { brands.append("\"Google Chrome\";v=\"\(major)\"") }
        if fork == "edge" { brands.append("\"Microsoft Edge\";v=\"\(major)\"") }
        let order: [Int]
        switch brands.count {
        case 2: order = [major % 2, (major + 1) % 2]
        default: order = shuffle3[major % shuffle3.count]
        }
        var shuffled = [String](repeating: "", count: brands.count)
        for (i, e) in order.enumerated() { shuffled[e] = brands[i] }
        return shuffled.joined(separator: ", ")
    }

    static var chromeUA: String {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(chromeVersion).0.0.0 Safari/537.36"
    }

    /// TryDefaultHeadersWith: no User-Agent → Chrome; a browser keyword as the User-Agent → that browser;
    /// any other User-Agent is left alone (and gets no fetch headers either, like mihomo).
    static func tryDefaultHeaders(_ h: inout NCXHTTPHeaders, variant: String) {
        guard let ua = h.get("user-agent") else {
            apply(&h, browser: "chrome", variant: variant)
            return
        }
        switch ua {
        case "chrome", "firefox", "safari", "edge", "curl", "golang": apply(&h, browser: ua, variant: variant)
        default: break
        }
    }

    static func apply(_ h: inout NCXHTTPHeaders, browser: String, variant: String) {
        switch browser {
        case "chrome", "edge":
            h.set("Sec-CH-UA", greasedChUa(chromeVersion, fork: browser))
            h.set("Sec-CH-UA-Mobile", "?0")
            h.set("Sec-CH-UA-Platform", "\"Windows\"")
            h.set("DNT", "1")
            h.set("User-Agent", browser == "edge" ? chromeUA + "Edg/\(chromeVersion).0.0.0" : chromeUA)
            h.set("Accept-Language", "en-US,en;q=0.9")
        case "firefox":
            h.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:\(firefoxVersion).0) Gecko/20100101 Firefox/\(firefoxVersion).0")
            h.set("DNT", "1")
            h.set("Accept-Language", "en-US,en;q=0.5")
        case "safari":
            h.set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(safariVersion) Safari/605.1.15")
            h.set("Accept-Language", "en-US,en;q=0.9")
        case "golang":
            h.del("User-Agent") // Go's own default user agent is added when the request is sent
            return
        case "curl":
            h.set("User-Agent", "curl/" + curlVersion)
            return
        default:
            break
        }
        guard variant == "fetch" else { return }
        h.set("Sec-Fetch-Mode", "cors")
        h.set("Sec-Fetch-Dest", "empty")
        h.set("Sec-Fetch-Site", "same-origin")
        if !h.has("Priority") {
            switch browser {
            case "chrome", "edge": h.set("Priority", "u=1, i")
            case "firefox": h.set("Priority", "u=4")
            case "safari": h.set("Priority", "u=3, i")
            default: break
            }
        }
        if !h.has("Cache-Control") { h.set("Cache-Control", "no-cache") }
        if !h.has("Pragma") { h.set("Pragma", "no-cache") }
        if !h.has("Accept") { h.set("Accept", "*/*") }
    }
}
