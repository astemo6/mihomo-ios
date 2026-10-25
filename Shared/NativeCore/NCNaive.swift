import Foundation

// feat/nc-naive-h2h3 — HTTP CONNECT over HTTP/2 and HTTP/3 (Shadowrocket's "HTTP2" / "HTTP3" proxy types)
// and NaïveProxy (the same CONNECT tunnel plus naive's padding protocol). Pure, unit-testable pieces live
// here: option parsing (NCH2H3ProxyOptions), the CONNECT request header list, the QPACK encoder for the h3
// request, the padding-header generator / negotiation and the padding framing codec (NCNaivePadding).
// The sessions are NCH2ProxySession.swift (h2, multiplexed over one TLS connection) and
// NCH3ProxySession.swift (h3, one QUIC connection, a bidi stream per flow).
//
// Wire references: klzgrad/naiveproxy (src/net/tools/naive/naive_protocol.h, naive_proxy_delegate.cc,
// naive_connection.cc) and sing-box protocol/naive (inbound.go / inbound_conn.go: padding header,
// paddingCount = 8, [u16 len][u8 padSize][payload][padSize bytes]).

/// Which carrier and which tunnel flavour a node uses.
struct NCH2H3ProxyOptions: Equatable {
    enum Carrier: Equatable { case h2, h3 }

    var carrier: Carrier
    /// NaïveProxy: request the padding protocol (and apply it when the server agrees).
    var naive: Bool
    var server: String
    var port: Int
    var username: String?
    var password: String?
    /// TLS SNI / :authority-independent server name (sni / servername; default: server).
    var serverName: String
    var allowInsecure: Bool
    /// ClientHello shape for the h2 TLS (NCTLSClientStream profile); naive defaults to chrome.
    var fingerprint: String?
    /// Extra request headers (sing-box `extra_headers`, naive `extra-headers`, Shadowrocket `headers`).
    var extraHeaders: [(String, String)]
    /// Number of shared connections the streams are spread over (sing-box / naive `insecure_concurrency`).
    var concurrency: Int
    /// sing-box naive `udp_over_tcp`: UDP rides UoT v2 through the CONNECT tunnel.
    var udpOverTCP: Bool

    static func == (a: NCH2H3ProxyOptions, b: NCH2H3ProxyOptions) -> Bool {
        a.carrier == b.carrier && a.naive == b.naive && a.server == b.server && a.port == b.port
            && a.username == b.username && a.password == b.password && a.serverName == b.serverName
            && a.allowInsecure == b.allowInsecure && a.fingerprint == b.fingerprint
            && a.extraHeaders.map { $0.0 + "\u{0}" + $0.1 } == b.extraHeaders.map { $0.0 + "\u{0}" + $0.1 }
            && a.concurrency == b.concurrency && a.udpOverTCP == b.udpOverTCP
    }

    /// Normalized type names this file handles (config `type:` values, lowercased).
    static let naiveTypes: Set<String> = ["naive"]
    static let h2Types: Set<String> = ["http2", "h2"]
    static let h3Types: Set<String> = ["http3", "h3"]
    static let allTypes: Set<String> = naiveTypes.union(h2Types).union(h3Types)

    static func handles(_ type: String) -> Bool { allTypes.contains(type.lowercased()) }

    /// nil = not one of these types, or no server / port.
    init?(proxy: NCProxy) {
        let t = proxy.type.lowercased()
        guard Self.allTypes.contains(t), let server = proxy.server, !server.isEmpty, let port = proxy.port, port > 0 else {
            return nil
        }
        let f = proxy.fields
        let isNaive = Self.naiveTypes.contains(t)
        naive = isNaive
        if Self.h3Types.contains(t) {
            carrier = .h3
        } else if isNaive {
            // sing-box `quic: true` / naive `naive+quic://` (imported as quic: true) → HTTP/3.
            let quic = f["quic"]?.bool ?? false
            let proto = (f["protocol"]?.string ?? f["scheme"]?.string ?? "").lowercased()
            carrier = (quic || proto == "quic" || proto == "h3" || proto == "http3") ? .h3 : .h2
        } else {
            carrier = .h2
        }
        self.server = server
        self.port = port
        let user = f["username"]?.string ?? f["user"]?.string
        username = (user?.isEmpty ?? true) ? nil : user
        let pass = proxy.password
        password = (pass?.isEmpty ?? true) ? nil : pass
        let sni = f["sni"]?.string ?? f["servername"]?.string ?? f["server-name"]?.string ?? ""
        serverName = sni.isEmpty ? server : sni
        allowInsecure = f["skip-cert-verify"]?.bool ?? f["insecure"]?.bool ?? false
        fingerprint = f["client-fingerprint"]?.string ?? f["fingerprint"]?.string
        extraHeaders = Self.parseHeaders(f["extra-headers"] ?? f["headers"])
        concurrency = max(1, min(8, f["insecure-concurrency"]?.int ?? f["concurrency"]?.int ?? 1))
        udpOverTCP = f["udp-over-tcp"]?.bool ?? false
    }

    /// Headers given as a map ({Name: value}), a list of "Name: value" strings, or one string with
    /// CRLF-separated "Name: value" lines (the naive+https `extra-headers` query form).
    static func parseHeaders(_ v: NCJSONValue?) -> [(String, String)] {
        guard let v else { return [] }
        var out: [(String, String)] = []
        func line(_ s: String) {
            guard let colon = s.firstIndex(of: ":") else { return }
            let name = s[..<colon].trimmingCharacters(in: .whitespaces)
            let value = s[s.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if !name.isEmpty { out.append((name, value)) }
        }
        switch v {
        case .object(let o):
            for k in o.keys.sorted() {
                if let s = o[k]?.string { out.append((k, s)) }
                else if let a = o[k]?.array?.first?.string { out.append((k, a)) }
            }
        case .array(let a):
            for e in a { if let s = e.string { line(s) } }
        case .string(let s):
            for l in s.components(separatedBy: CharacterSet(charactersIn: "\r\n")) where !l.isEmpty { line(l) }
        default:
            break
        }
        // Pseudo-headers, hop-by-hop headers and the ones we own cannot be overridden.
        let reserved: Set<String> = ["host", "connection", "proxy-connection", "keep-alive", "transfer-encoding",
                                     "upgrade", "te", "proxy-authorization", "padding", "padding-type-request"]
        return out.filter { !$0.0.hasPrefix(":") && !reserved.contains($0.0.lowercased()) }
    }
}

/// The CONNECT request (RFC 9113 §8.5 / RFC 9114 §4.4): :method CONNECT + :authority only.
enum NCHTTPConnect {
    /// host:port with IPv6 literals bracketed.
    static func authority(_ target: NCTarget) -> String {
        if case .v6? = target.ip { return "[\(target.host)]:\(target.port)" }
        return "\(target.host):\(target.port)"
    }

    static func basicAuth(username: String?, password: String?) -> String? {
        guard username != nil || password != nil else { return nil }
        return "Basic " + Data("\(username ?? ""):\(password ?? "")".utf8).base64EncodedString()
    }

    /// Header list for one tunnel request. `paddingHeader` is non-nil for naive (the random `padding`
    /// value, see NCNaivePadding.headerValue); naive also offers padding type 1 (variant 1) then 0 (none)
    /// via `padding-type-request`, the newer negotiation (naiveproxy ≥ v114) — old servers (sing-box)
    /// only look at `padding`. Header names are lowercase (HTTP/2 and HTTP/3 require it).
    static func requestHeaders(target: NCTarget, options: NCH2H3ProxyOptions,
                               paddingHeader: String?) -> [(String, String)] {
        var h: [(String, String)] = [(":method", "CONNECT"), (":authority", authority(target))]
        if let auth = basicAuth(username: options.username, password: options.password) {
            h.append(("proxy-authorization", auth))
        }
        if let paddingHeader {
            h.append(("padding", paddingHeader))
            h.append(("padding-type-request", "1, 0"))
        }
        for (k, v) in options.extraHeaders { h.append((k.lowercased(), v)) }
        return h
    }

    /// :status as an Int (nil when absent or malformed).
    static func status(_ headers: [(String, String)]) -> Int? {
        headers.first(where: { $0.0 == ":status" }).flatMap { Int($0.1) }
    }

    /// QPACK field section for an HTTP/3 request (RFC 9204, static table only — we announce a zero dynamic
    /// table, so every line is indexed-static, literal-with-static-name or literal-with-literal-name;
    /// strings are raw, H = 0). Same primitives as the hysteria2 auth request (NCHy2).
    static func qpackEncode(_ headers: [(String, String)]) -> Data {
        var out = Data([0x00, 0x00]) // required insert count 0, base 0
        let table = NCHy2.qpackStaticTable
        for (name, value) in headers {
            if let idx = table.firstIndex(where: { $0.name == name && $0.value == value }) {
                out.append(NCHy2.qpackEncodeInteger(idx, prefixBits: 6, flags: 0xC0))          // 1 T=1 index
            } else if let idx = table.firstIndex(where: { $0.name == name }) {
                out.append(NCHy2.qpackEncodeInteger(idx, prefixBits: 4, flags: 0x50))          // 0 1 N=0 T=1 index
                out.append(NCHy2.qpackEncodeString(value))
            } else {
                out.append(NCHy2.qpackEncodeString(name, prefixBits: 3, flags: 0x20))          // 0 0 1 N=0 H=0 len
                out.append(NCHy2.qpackEncodeString(value))
            }
        }
        return out
    }
}

/// NaïveProxy padding protocol, variant 1 ("padding type 1"): the first `frames` reads and writes of each
/// direction carry [payload length u16 BE][padding length u8][payload][padding zeros]; afterwards the
/// stream is raw. Payloads above 65535 bytes are split, each piece using one padded frame
/// (sing-box writeChunked / naiveproxy NaivePaddingSocket). Not thread-safe: owned by one stream.
struct NCNaivePadding {
    static let frames = 8
    static let maxPayload = 65535

    private(set) var writesPadded = 0
    private(set) var readsPadded = 0
    // read-side state machine
    private var header = Data()
    private var payloadRemaining = 0
    private var paddingRemaining = 0

    /// True once both directions are past the padded prefix (the codec is a pass-through then).
    var finished: Bool { writesPadded >= Self.frames && readsPadded >= Self.frames && payloadRemaining == 0 && paddingRemaining == 0 }

    /// Encode one outbound chunk. `paddingLength` supplies each frame's padding size (0...255; random in
    /// production, fixed in tests).
    mutating func encode(_ data: Data, paddingLength: () -> Int = { Int.random(in: 0...255) }) -> Data {
        guard writesPadded < Self.frames, !data.isEmpty else { return data }
        var out = Data()
        var offset = data.startIndex
        while offset < data.endIndex {
            if writesPadded >= Self.frames {
                out.append(data[offset...])
                break
            }
            let n = min(Self.maxPayload, data.endIndex - offset)
            let pad = max(0, min(255, paddingLength()))
            out.append(UInt8(n >> 8))
            out.append(UInt8(n & 0xff))
            out.append(UInt8(pad))
            out.append(data[offset..<(offset + n)])
            if pad > 0 { out.append(Data(count: pad)) }
            writesPadded += 1
            offset += n
        }
        return out
    }

    /// Decode one inbound chunk (any split of the wire). Returns the payload bytes it carried (possibly
    /// empty while a header or padding is still being consumed).
    mutating func decode(_ chunk: Data) -> Data {
        if readsPadded >= Self.frames && payloadRemaining == 0 && paddingRemaining == 0 && header.isEmpty {
            return chunk
        }
        var out = Data()
        var i = chunk.startIndex
        while i < chunk.endIndex {
            if payloadRemaining > 0 {
                let n = min(payloadRemaining, chunk.endIndex - i)
                out.append(chunk[i..<(i + n)])
                payloadRemaining -= n
                i += n
                continue
            }
            if paddingRemaining > 0 {
                let n = min(paddingRemaining, chunk.endIndex - i)
                paddingRemaining -= n
                i += n
                continue
            }
            if readsPadded >= Self.frames {
                out.append(chunk[i...])
                break
            }
            let need = 3 - header.count
            let n = min(need, chunk.endIndex - i)
            header.append(chunk[i..<(i + n)])
            i += n
            if header.count == 3 {
                let h = [UInt8](header)
                payloadRemaining = Int(h[0]) << 8 | Int(h[1])
                paddingRemaining = Int(h[2])
                header = Data()
                readsPadded += 1
            }
        }
        return out
    }

    /// The `padding` request header value: naiveproxy's FillNonindexHeaderValue — 16 characters from a
    /// set HPACK's Huffman code makes long (so the header length is not compressible), then '~' up to a
    /// random total length of 16...32.
    static func headerValue(length: Int = Int.random(in: 16...32)) -> String {
        let alphabet = Array("!#$()+<>?@[]^`{}")
        var s = ""
        var bits = UInt64.random(in: 0...UInt64.max)
        let len = max(16, length)
        for _ in 0..<16 {
            s.append(alphabet[Int(bits & 15)])
            bits >>= 4
        }
        s += String(repeating: "~", count: len - 16)
        return s
    }

    /// Server's answer: `padding-type-reply` (newer naive servers) decides; otherwise the legacy
    /// `padding` response header means variant 1 (sing-box, older caddy forwardproxy); neither = none.
    static func negotiated(responseHeaders: [(String, String)]) -> Bool {
        if let reply = responseHeaders.first(where: { $0.0.lowercased() == "padding-type-reply" })?.1 {
            return reply.trimmingCharacters(in: .whitespaces) == "1"
        }
        return responseHeaders.contains(where: { $0.0.lowercased() == "padding" })
    }
}
