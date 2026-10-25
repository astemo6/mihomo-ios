import Foundation
import Network
import Security
import os

/// Hysteria2 client (protocol v2, apernet/hysteria), built on the Network
/// framework's QUIC support.
///
/// Layout:
///  - `NCHy2` — pure, unit-testable wire functions: QUIC varints, the QPACK
///    subset the auth exchange needs (literal/static only, no dynamic table,
///    no Huffman), HTTP/3 framing, and the hysteria TCP request/response
///    headers.
///  - `NCHysteria2Connection` — one QUIC connection + the HTTP/3 handshake
///    (a unidirectional control stream for SETTINGS, a bidirectional stream
///    for the auth exchange); vends TCP proxy streams.
///  - `NCHysteria2TCPStream` — one proxied TCP flow (NCRelayStream).
/// UDP lives in NCHysteria2UDP.swift.
///
/// UNVERIFIED APPLE API POINTS (no Apple SDK on the build host; the QUIC
/// wiring is isolated here so a correction touches one place):
///  1. `NWProtocolQUIC.Options(alpn:)` and `NWParameters(quic:)` — the
///     documented iOS 15 QUIC entry points.
///  2. `quicOptions.securityProtocolOptions` for SNI / cert-verify control —
///     mirrors how NWProtocolTLS.Options is used elsewhere in this target.
///  3. Stream multiplexing via `NWConnectionGroup(with: NWMultiplexGroup(to:), using:)`
///     + `group.extract(connectionTo:using:)` — verified against Apple docs
///     (NWMultiplexGroup is the NWGroupDescriptor for multiplexed QUIC).
///     + `NWConnection(from: group)` + `group.newConnectionHandler` — the
///     WWDC21 QUIC group model. If the descriptor case name differs, this is
///     the first place to fix.
///     Connections are extracted ONLY after the group reports `.ready` via
///     its stateUpdateHandler: extracting from a just-started group logs
///     `nw_connection_group_create_connection_for_endpoint_and_parameters …
///     failed to create connection` and returns nil (proto-loopback run
///     40171239186, iOS 18.5 simulator — both this and NCTUIC failed there
///     with "cannot open control/auth stream" before any packet was sent).
///  4. QUIC datagrams: there is no clearly documented Swift-overlay datagram
///     surface. Datagrams are attempted on a dedicated group connection with
///     send(content:)/receiveMessage (the same calls UDP connections use).
///     If a given iOS version does not treat that connection as a datagram
///     context, UDP sessions will simply never answer — TCP is unaffected.
///  5. HTTP/3 stream discipline (RFC 9114): the client SETTINGS frame goes
///     ONLY on a dedicated client-initiated unidirectional control stream,
///     prefixed with stream type 0x00; the auth HEADERS exchange rides its
///     own bidirectional stream. (Review rework: the first cut sent SETTINGS
///     and the auth HEADERS together on the first extracted bidi stream with
///     no stream-type byte — a conforming H3 peer errors the connection on a
///     SETTINGS frame arriving on a request stream, and the auth is never
///     answered.) The server's control stream arrives via
///     newConnectionHandler and is drained, not cancelled. A stream extracted
///     with per-stream QUIC options must carry the same ALPN/TLS settings as
///     the group parameters (see NCTUICConnection.quicStreamOptions for the
///     same rule): bare options negotiate without ALPN and the server
///     refuses the stream.
///  6. Experimental ECH via `sec_protocol_options_set_enable_encrypted_client_hello` (Security framework):
///     Network.framework QUIC supports system ECH when enabled on the transport's securityProtocolOptions.
///     Precondition and limitations:
///     - System QUIC discovers ECHConfig exclusively via system DNS resolution of HTTPS/SVCB records;
///     - External/static ECHConfig cannot be injected via Network.framework API;
///     - Designated as "系统 ECH（尽力而为）" (best-effort system ECH); if no ECHConfig is found in DNS,
///       it falls back to standard TLS 1.3 ClientHello. Static configs in `ech-opts` are warned in logs/report.

// MARK: - Pure wire functions

enum NCHy2 {
    // MARK: QUIC varint (RFC 9000 §16): top two bits encode the length.

    static func varintEncode(_ value: UInt64) -> Data {
        var out = Data()
        switch value {
        case 0..<64:
            out.append(UInt8(value))
        case 64..<16384:
            out.appendBE16(UInt16(value) | 0x4000)
        case 16384..<1073741824:
            out.appendBE32(UInt32(value) | 0x8000_0000)
        default:
            out.appendBE64(value | 0xc000_0000_0000_0000)
        }
        return out
    }

    /// Returns (value, bytesConsumed) or nil when the buffer is incomplete.
    static func varintDecode(_ data: Data, at offset: Int = 0) -> (value: UInt64, length: Int)? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        let length = 1 << (first >> 6)
        guard data.count - offset >= length else { return nil }
        var value = UInt64(first & 0x3f)
        for i in 1..<length {
            value = value << 8 | UInt64(data[offset + i])
        }
        return (value, length)
    }

    // MARK: QPACK (RFC 9204) subset: prefix integers + string literals

    /// Prefix integer encoding: `flags` holds the already-set high bits of the
    /// first byte; `prefixBits` is the integer field width (N in the RFC).
    static func qpackEncodeInteger(_ value: Int, prefixBits: Int, flags: UInt8) -> Data {
        var out = Data()
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            out.append(flags | UInt8(value))
            return out
        }
        out.append(flags | UInt8(maxPrefix))
        var rest = value - maxPrefix
        while rest >= 128 {
            out.append(UInt8(rest % 128) | 0x80)
            rest /= 128
        }
        out.append(UInt8(rest))
        return out
    }

    static func qpackDecodeInteger(_ data: Data, at offset: Int, prefixBits: Int) -> (value: Int, length: Int)? {
        guard offset < data.count else { return nil }
        let mask = (1 << prefixBits) - 1
        var value = Int(data[offset]) & mask
        if value < mask { return (value, 1) }
        var shift = 0
        var idx = offset + 1
        while idx < data.count {
            let byte = data[idx]
            value += Int(byte & 0x7f) << shift
            shift += 7
            idx += 1
            if byte & 0x80 == 0 { return (value, idx - offset) }
            if shift > 28 { return nil }
        }
        return nil
    }

    /// String literal, raw on the way out (H = 0): `prefixBits`-bit length
    /// prefix (the H bit sits right above it) + bytes. `flags` carries the
    /// field-line pattern bits that share the first byte.
    static func qpackEncodeString(_ string: String, prefixBits: Int = 7, flags: UInt8 = 0) -> Data {
        let bytes = Data(string.utf8)
        var out = qpackEncodeInteger(bytes.count, prefixBits: prefixBits, flags: flags)
        out.append(bytes)
        return out
    }

    /// Decodes a string literal at `offset`: H bit (the bit right above the
    /// `prefixBits`-bit length) + length + bytes. Huffman strings are decoded
    /// with the HPACK code (RFC 9204 §4.1.2 reuses RFC 7541 Appendix B) —
    /// quic-go's QPACK encoder (sing-box / hysteria servers) Huffman-encodes
    /// every literal name and value, so an H=1 string is the normal case.
    static func qpackDecodeString(_ data: Data, at offset: Int, prefixBits: Int = 7) -> (value: String, length: Int)? {
        guard offset < data.count else { return nil }
        let huffman = data[offset] & UInt8(1 << prefixBits) != 0
        guard let (len, intLen) = qpackDecodeInteger(data, at: offset, prefixBits: prefixBits) else { return nil }
        let start = offset + intLen
        guard data.count - start >= len else { return nil }
        var raw = Data(data[start..<(start + len)])
        if huffman {
            guard let decoded = NCHPACK.huffmanDecode(raw) else { return nil }
            raw = decoded
        }
        return (String(decoding: raw, as: UTF8.self), intLen + len)
    }

    /// QPACK static table, complete (RFC 9204 Appendix A, indices 0...98 —
    /// generated from quic-go/qpack static_table.go). The table used to be a
    /// partial list with entries 2-14 missing, so every index past 1 was off
    /// (":method POST" was sent as 7 = "etag", ":scheme https" as 10).
    static let qpackStaticTable: [(name: String, value: String)] = [
        (":authority", ""), (":path", "/"), ("age", "0"),
        ("content-disposition", ""), ("content-length", "0"), ("cookie", ""),
        ("date", ""), ("etag", ""), ("if-modified-since", ""),
        ("if-none-match", ""), ("last-modified", ""), ("link", ""),
        ("location", ""), ("referer", ""), ("set-cookie", ""),
        (":method", "CONNECT"), (":method", "DELETE"), (":method", "GET"),
        (":method", "HEAD"), (":method", "OPTIONS"), (":method", "POST"),
        (":method", "PUT"), (":scheme", "http"), (":scheme", "https"),
        (":status", "103"), (":status", "200"), (":status", "304"),
        (":status", "404"), (":status", "503"), ("accept", "*/*"),
        ("accept", "application/dns-message"), ("accept-encoding", "gzip, deflate, br"), ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"), ("access-control-allow-headers", "content-type"), ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"), ("cache-control", "max-age=2592000"), ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"), ("cache-control", "no-store"), ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"), ("content-encoding", "gzip"), ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"), ("content-type", "application/json"), ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"), ("content-type", "image/jpeg"), ("content-type", "image/png"),
        ("content-type", "text/css"), ("content-type", "text/html; charset=utf-8"), ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"), ("range", "bytes=0-"), ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"), ("strict-transport-security", "max-age=31536000; includesubdomains; preload"), ("vary", "accept-encoding"),
        ("vary", "origin"), ("x-content-type-options", "nosniff"), ("x-xss-protection", "1; mode=block"),
        (":status", "100"), (":status", "204"), (":status", "206"),
        (":status", "302"), (":status", "400"), (":status", "403"),
        (":status", "421"), (":status", "425"), (":status", "500"),
        ("accept-language", ""), ("access-control-allow-credentials", "FALSE"), ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"), ("access-control-allow-methods", "get"), ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"), ("access-control-expose-headers", "content-length"), ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"), ("access-control-request-method", "post"), ("alt-svc", "clear"),
        ("authorization", ""), ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"), ("early-data", "1"),
        ("expect-ct", ""), ("forwarded", ""), ("if-range", ""),
        ("origin", ""), ("purpose", "prefetch"), ("server", ""),
        ("timing-allow-origin", "*"), ("upgrade-insecure-requests", "1"), ("user-agent", ""),
        ("x-forwarded-for", ""), ("x-frame-options", "deny"), ("x-frame-options", "sameorigin"),
    ]

    static func qpackStaticName(_ index: Int) -> String? {
        guard index >= 0, index < qpackStaticTable.count else { return nil }
        return qpackStaticTable[index].name
    }

    /// HTTP/3 request target of the hysteria2 auth exchange (apernet/hysteria
    /// protocol URLHost / URLPath; sing-quic hysteria2 ServeHTTP requires
    /// `r.Method == POST && r.Host == "hysteria" && r.URL.Path == "/auth"` and
    /// hands anything else to the masquerade handler).
    static let authAuthority = "hysteria"
    static let authPath = "/auth"

    /// Encode the hysteria2 auth request as a QPACK field section (RFC 9204
    /// §4.5): :method POST, :scheme https, :path /auth, :authority hysteria,
    /// then the Hysteria-* headers as literal field lines. No dynamic table
    /// (section prefix 0x00 0x00: required insert count 0, base 0).
    ///  - Indexed field line, static:        1 T=1 index(6)
    ///  - Literal with static name ref:      0 1 N=0 T=1 index(4) + value
    ///  - Literal with literal name:         0 0 1 N=0 H=0 nameLen(3) + name + value
    /// (The previous encoder used 7/6/5-bit prefixes with the wrong pattern
    /// bits, so the server decoded dynamic-table references and garbage
    /// lengths and closed the stream — "hysteria2 auth stream closed".)
    static func qpackEncodeAuthRequest(authority: String = NCHy2.authAuthority, path: String = NCHy2.authPath,
                                       password: String, padding: String) -> Data {
        var out = Data([0x00, 0x00])
        out.append(qpackEncodeInteger(20, prefixBits: 6, flags: 0xC0)) // :method POST
        out.append(qpackEncodeInteger(23, prefixBits: 6, flags: 0xC0)) // :scheme https
        out.append(qpackEncodeInteger(1, prefixBits: 4, flags: 0x50))  // :path
        out.append(qpackEncodeString(path))
        out.append(qpackEncodeInteger(0, prefixBits: 4, flags: 0x50))  // :authority
        out.append(qpackEncodeString(authority))
        for (name, value) in [("hysteria-auth", password),
                              ("hysteria-cc-rx", "0"),
                              ("hysteria-padding", padding)] {
            out.append(qpackEncodeString(name, prefixBits: 3, flags: 0x20))
            out.append(qpackEncodeString(value))
        }
        return out
    }

    /// Decode a QPACK field section produced by a server that was told
    /// QPACK_MAX_TABLE_CAPACITY=0 (so the required insert count must be 0 and
    /// every line is indexed-static or literal). Returns name/value pairs in
    /// wire order, or nil on anything outside the subset.
    static func qpackDecodeFieldSection(_ data: Data) -> [(name: String, value: String)]? {
        guard let (ric, ricLen) = qpackDecodeInteger(data, at: 0, prefixBits: 8), ric == 0,
              let (_, baseLen) = qpackDecodeInteger(data, at: ricLen, prefixBits: 7) else { return nil }
        var idx = ricLen + baseLen
        var fields: [(String, String)] = []
        while idx < data.count {
            let byte = data[idx]
            if byte & 0x80 != 0 {
                // Indexed field line: 1 T iiiiii (6-bit prefix index).
                guard byte & 0x40 != 0 else { return nil } // dynamic table: unsupported
                guard let (index, len) = qpackDecodeInteger(data, at: idx, prefixBits: 6) else { return nil }
                idx += len
                guard index < qpackStaticTable.count else { return nil }
                fields.append(qpackStaticTable[index])
            } else if byte & 0xc0 == 0x40 {
                // Literal, name reference: 0 1 N T iiii (4-bit prefix).
                guard byte & 0x10 != 0 else { return nil } // dynamic name ref: unsupported
                guard let (index, len) = qpackDecodeInteger(data, at: idx, prefixBits: 4) else { return nil }
                idx += len
                guard let name = qpackStaticName(index),
                      let (value, vlen) = qpackDecodeString(data, at: idx, prefixBits: 7) else { return nil }
                idx += vlen
                fields.append((name, value))
            } else if byte & 0xe0 == 0x20 {
                // Literal, literal name: 0 0 1 N H lll (3-bit prefix name length).
                guard let (name, nlen) = qpackDecodeString(data, at: idx, prefixBits: 3) else { return nil }
                idx += nlen
                guard let (value, vlen) = qpackDecodeString(data, at: idx, prefixBits: 7) else { return nil }
                idx += vlen
                fields.append((name, value))
            } else {
                // Post-base forms require a dynamic table: not in this subset.
                return nil
            }
        }
        return fields
    }

    // MARK: HTTP/3 frames (RFC 9114): varint type, varint length, payload.

    static func http3Frame(type: UInt64, payload: Data) -> Data {
        var out = varintEncode(type)
        out.append(varintEncode(UInt64(payload.count)))
        out.append(payload)
        return out
    }

    /// The client SETTINGS frame: QPACK max table capacity 0 (keeps server
    /// responses inside the decodable subset), QPACK blocked streams 0, and
    /// H3_DATAGRAM enabled (needed for UDP).
    static func http3SettingsFrame() -> Data {
        var payload = Data()
        payload.append(varintEncode(0x01)) // QPACK_MAX_TABLE_CAPACITY
        payload.append(varintEncode(0))
        payload.append(varintEncode(0x07)) // QPACK_BLOCKED_STREAMS
        payload.append(varintEncode(0))
        payload.append(varintEncode(0x33)) // H3_DATAGRAM
        payload.append(varintEncode(1))
        return http3Frame(type: 0x04, payload: payload)
    }

    static func http3HeadersFrame(fieldSection: Data) -> Data {
        http3Frame(type: 0x01, payload: fieldSection)
    }

    // MARK: Hysteria TCP stream header

    static let tcpRequestFrameType: UInt64 = 0x401

    /// Request: varint(0x401) + varint(len) + "host:port" + varint(len) + padding bytes.
    /// Padding is a parameter (not generated inside) so tests are exact.
    static func tcpRequestHeader(target: NCTarget, padding: Data) -> Data {
        let address = "\(target.host):\(target.port)"
        // Every proxied TCP stream opens with the TCPRequest frame type 0x401
        // (hysteria2 protocol; sing-quic ReadTCPRequest runs after its stream
        // hijacker consumed it). Without it the server reads the address
        // length as an HTTP/3 frame type.
        var out = varintEncode(tcpRequestFrameType)
        out.append(varintEncode(UInt64(address.utf8.count)))
        out.append(Data(address.utf8))
        out.append(varintEncode(UInt64(padding.count)))
        out.append(padding)
        return out
    }

    /// Parse a response from the front of `buffer`: status byte, then
    /// varint(len) + message, then varint(len) + padding. Returns nil when
    /// more bytes are needed; `consumed` counts header bytes to drop.
    static func tcpResponseHeader(_ buffer: Data) -> (status: UInt8, message: String, consumed: Int)? {
        guard buffer.count >= 1 else { return nil }
        let status = buffer[0]
        guard let (msgLen, l1) = varintDecode(buffer, at: 1) else { return nil }
        let msgStart = 1 + l1
        guard buffer.count - msgStart >= Int(msgLen) else { return nil }
        let message = String(decoding: buffer[msgStart..<(msgStart + Int(msgLen))], as: UTF8.self)
        guard let (padLen, l2) = varintDecode(buffer, at: msgStart + Int(msgLen)) else { return nil }
        let total = msgStart + Int(msgLen) + l2 + Int(padLen)
        guard buffer.count >= total else { return nil }
        return (status, message, total)
    }
}

// MARK: - QUIC stream channel

/// Byte-stream adapter over one QUIC stream NWConnection, with the same
/// one-shot receive shape as NCStream so handshake code reads identically.
final class NCHy2StreamChannel {
    let conn: NWConnection
    private var cancelled = false

    init(conn: NWConnection) { self.conn = conn }

    func start(queue: DispatchQueue, ready: @escaping (Error?) -> Void) {
        var fired = false
        conn.stateUpdateHandler = { state in
            guard !fired else { return }
            switch state {
            case .ready:
                fired = true
                ready(nil)
            case .failed(let e):
                fired = true
                ready(e)
            case .cancelled:
                fired = true
                ready(NCConnector.Failure.handshake("quic stream cancelled"))
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    func send(_ data: Data) {
        guard !cancelled, !data.isEmpty else { return }
        conn.send(content: data, completion: .idempotent)
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !cancelled, !data.isEmpty else { completion(); return }
        conn.send(content: data, completion: .contentProcessed { _ in completion() })
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                handler(data, nil)
            } else if isComplete {
                handler(nil, nil)
            } else {
                handler(nil, error)
            }
        }
    }

    /// Datagram-style receive (message boundaries preserved), used by the
    /// attempted QUIC datagram binding only.
    func receiveMessage(_ handler: @escaping (Data?, Error?) -> Void) {
        conn.receiveMessage { data, _, _, error in handler(data, error) }
    }

    func cancel() {
        cancelled = true
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}

// MARK: - Connection

final class NCHysteria2Connection {
    enum State {
        case idle, connecting, authenticating, ready, failed, closed
    }

    private let server: String
    private let port: Int
    private let password: String
    private let sni: String?
    private let allowInsecure: Bool
    private let echEnabled: Bool
    /// nc-races: the connection's own session queue (the #116 pattern, as in NCMuxSession): every piece of
    /// connection and stream state — the NW group, the streams registry, the control-stream parser, the
    /// datagram channel — is touched only here, no matter which caller (connector, data plane, local proxy)
    /// drives the connection. The queue passed to init is kept as `callbackQueue`: the start completion is
    /// delivered on it, exactly where callers used to get it when the NW group ran on their queue.
    let queue: DispatchQueue
    private let callbackQueue: DispatchQueue

    /// Lock-protected snapshot for cross-thread readers (the connector registry, UDP sessions): the state,
    /// the auth verdict's UDP flag / TX cap, and the readiness waiters. State changes are made from the
    /// session queue (close() also writes the snapshot directly, so registry readers see .closed at once);
    /// waiters are drained under the lock and fired outside it, each on its own caller queue — no polling.
    private struct Snapshot {
        var state: State = .idle
        /// Set from the auth response's Hysteria-UDP header.
        var udpEnabled = false
        /// Server-declared TX cap from the auth response (bytes/s, 0 = none).
        var serverTX: Int? = nil
        var waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready } }
    var udpEnabled: Bool { snapshot.withLock { $0.udpEnabled } }
    var serverTX: Int? { snapshot.withLock { $0.serverTX } }

    private func setSnapshot(state: State? = nil, udpEnabled: Bool? = nil, serverTX: Int?? = nil) {
        snapshot.withLock {
            if let state { $0.state = state }
            if let udpEnabled { $0.udpEnabled = udpEnabled }
            if let serverTX { $0.serverTX = serverTX }
        }
    }

    /// Registers interest in readiness (the connector registry): ready → nil at once on `callerQueue`,
    /// failed/closed → the failure, connecting → queued until start resolves either way. Replaces the
    /// registry's old 0.25 s × 60 poll of `state` (nc-races, mirroring NCMuxSession.whenReady).
    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        enum Action { case now(Error?), wait }
        let action: Action = snapshot.withLock { snap in
            switch snap.state {
            case .ready:
                return .now(nil)
            case .failed, .closed:
                return .now(NCConnector.Failure.handshake("hysteria2 connection failed"))
            case .idle, .connecting, .authenticating:
                snap.waiters.append((callerQueue, completion))
                return .wait
            }
        }
        if case .now(let error) = action {
            callerQueue.async { completion(error) }
        }
    }

    /// Fires every queued readiness waiter exactly once, each on its own caller queue.
    private func notifyWaiters(_ error: Error?) {
        let waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = snapshot.withLock { snap in
            let drained = snap.waiters
            snap.waiters = []
            return drained
        }
        for waiter in waiters {
            waiter.queue.async { waiter.completion(error) }
        }
    }

    private var group: NWConnectionGroup?
    /// Session queue only: the handshake streams are extracted exactly once, when the
    /// group first reports .ready (see the file header, point 3).
    private var handshakeOpened = false
    /// The HTTP/3 control stream (client-initiated unidirectional): carries only the
    /// stream-type byte 0x00 and the client SETTINGS frame, sent once (RFC 9114 §6.2).
    private var control: NCHy2StreamChannel?
    /// The bidirectional auth stream: carries only the auth HEADERS request/response.
    private var auth: NCHy2StreamChannel?
    private var authBuffer = Data()
    /// The server's control stream (server-initiated unidirectional, adopted via
    /// newConnectionHandler): drained so its SETTINGS can be observed; never answered.
    private var serverControl: NCHy2StreamChannel?
    private var serverControlBuffer = Data()
    private var serverControlTypeSeen = false
    private var serverSettingsSeen = false
    private var startCompletion: ((Error?) -> Void)?
    private var streams: [ObjectIdentifier: NCHysteria2TCPStream] = [:]

    // Datagram binding (unverified point 4, see file header).
    private var datagramChannel: NCHy2StreamChannel?
    /// Datagram sinks by hysteria session ID (session queue only). Was a single `onDatagram` slot: on a
    /// shared connection every new UDP session overwrote the previous session's handler, so only the
    /// last-registered session ever received replies. Each session now registers its own sink and keeps
    /// filtering by session ID, exactly as it did with the slot.
    private var datagramSinks: [UInt64: (Data) -> Void] = [:]

    init(server: String, port: Int, password: String, sni: String? = nil,
         allowInsecure: Bool = false, echEnabled: Bool = true, queue: DispatchQueue) {
        self.server = server
        self.port = port
        self.password = password
        self.sni = sni
        self.allowInsecure = allowInsecure
        self.echEnabled = echEnabled
        self.callbackQueue = queue
        self.queue = NCSessionQueues.make("nc.hy2.\(server):\(port)")
    }

    convenience init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let server = proxy.server, let port = proxy.port,
              let password = proxy.password else { return nil }
        let echEnabled = proxy.fields["ech-opts"]?.object?["enable"]?.bool ?? true
        if NCSupport.hasStaticECHConfig(proxy) {
            StartupLog.write("hysteria2「\(proxy.name)」: 节点配置了静态 ech-opts.config，但系统 QUIC 无法注入静态 ECH 配置（系统 ECH 仅依赖系统 DNS 获取，静态配置不生效）")
        }
        self.init(server: server, port: port, password: password,
                  sni: proxy.fields["sni"]?.string,
                  allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                  echEnabled: echEnabled,
                  queue: queue)
    }


    // MARK: Lifecycle

    /// Connect QUIC and run the auth handshake; completion fires once on the init (callback) queue,
    /// with nil error on :status 233.
    func start(completion: @escaping (Error?) -> Void) {
        // Check-and-set under the snapshot lock: two concurrent starts must not both pass and
        // overwrite each other's completion.
        let first: Bool = snapshot.withLock { snap in
            guard snap.state == .idle else { return false }
            snap.state = .connecting
            return true
        }
        guard first else {
            callbackQueue.async { completion(NCConnector.Failure.handshake("hysteria2 already started")) }
            return
        }
        startCompletion = completion
        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    /// The QUIC options for this connection: the group parameters and every stream
    /// extracted with per-stream options must agree on ALPN and TLS settings — a
    /// stream extracted with bare options negotiates without ALPN and the server
    /// refuses it (the TUIC auth-stream defect, same shape). Fresh instance per
    /// call: NWProtocolQUIC.Options is a mutable class, and sharing one instance
    /// between the group parameters and extracted streams invites drift.
    private func makeQUICOptions() -> NWProtocolQUIC.Options {
        // Hysteria2 is HTTP/3: the QUIC ALPN must be "h3" (the sing-box / hysteria server
        // side negotiates h3 only). This used to read "h2", which no hysteria2 server accepts.
        let quicOptions = NWProtocolQUIC.Options(alpn: ["h3"])
        let tlsOptions = quicOptions.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tlsOptions, .tlsProtocol13)
        if let sni, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions, sni)
        }
        if allowInsecure {
            sec_protocol_options_set_verify_block(tlsOptions, { _, _, complete in complete(true) }, queue)
        }
        // ECH（lane E6）：打开系统 QUIC 的实验性 ECH 开关（Security 框架 C API）。
        // 生效前提与限制：
        // 1. 系统 QUIC 的 ECH 只能由系统在 DNS 解析时自动从 HTTPS/SVCB 记录中获取 ECHConfig；
        // 2. 应用层无法向系统 QUIC 注入外部或静态（E1/E2 / ech-opts.config）获取的 ECHConfig；
        // 3. 需系统 DNS 解析具备 DoH/HTTPS 记录支持；若无法从 DNS 获取则自动回退为普通 ClientHello。
        // 因此此处为「系统 ECH（尽力而为）」。
        if echEnabled {
            sec_protocol_options_set_enable_encrypted_client_hello(tlsOptions, true)
        }
        // RFC 9221 max_datagram_frame_size: our SETTINGS announce H3_DATAGRAM=1, and a
        // quic-go HTTP/3 peer with datagrams enabled closes the connection
        // (H3_SETTINGS_ERROR "missing QUIC Datagram support") when the transport did not
        // negotiate datagrams. hysteria2 UDP rides QUIC datagrams too.
        quicOptions.maxDatagramFrameSize = 1400
        return quicOptions
    }

    /// Session queue only: build the QUIC group; the handshake streams open when the
    /// group reports .ready (openHandshakeStreams), not before.
    private func startOnQueue() {
        let parameters = NWParameters(quic: makeQUICOptions())
        parameters.allowLocalEndpointReuse = true
        NCOutboundBinding.apply(parameters, host: server)

        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
        self.group = group
        group.stateUpdateHandler = { [weak self] (groupState: NWConnectionGroup.State) in
            guard let self else { return }
            switch groupState {
            case .ready:
                self.openHandshakeStreams()
            case .failed(let error):
                if self.state == .connecting || self.state == .authenticating {
                    self.finishStart(error)
                }
            default:
                break
            }
        }
        group.newConnectionHandler = { [weak self] (incoming: NWConnection) in
            // Server-initiated stream: for hysteria2 this is the server's HTTP/3
            // control stream (unidirectional, carries its SETTINGS). Adopt and
            // drain it — cancelling would reset the peer's control stream, and
            // receiving its SETTINGS is part of a conforming H3 handshake.
            guard let self else { incoming.cancel(); return }
            self.acceptServerControlStream(incoming)
        }
        group.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.state == .connecting || self.state == .authenticating else { return }
            self.finishStart(NCConnector.Failure.handshake("hysteria2 auth timeout"))
        }
    }

    /// Session queue only, one-shot: the HTTP/3 handshake streams, extracted once the
    /// group is .ready (extracting earlier returns nil). Two separate streams, per
    /// RFC 9114 and the hysteria2 spec:
    ///  - a client-initiated UNIDIRECTIONAL control stream carrying the stream-type
    ///    byte 0x00 followed by the client SETTINGS frame — the only stream SETTINGS
    ///    may ever appear on;
    ///  - a BIDIRECTIONAL auth stream carrying only the auth HEADERS exchange.
    /// (The first cut sent SETTINGS and the auth HEADERS together on the first
    /// extracted bidi stream, with no stream-type byte: a conforming H3 server
    /// treats a SETTINGS frame on a request stream as a connection error, so the
    /// auth was never answered.)
    private func openHandshakeStreams() {
        guard !handshakeOpened, state == .connecting else { return }
        handshakeOpened = true

        // Derived from the group's own QUIC options (NCQUICStreamOptions): freshly built
        // options fail to clone onto the established connection (ENETDOWN).
        guard let group,
              let controlConn = group.extract(connectionTo: nil,
                                              using: NCQUICStreamOptions.unidirectional(from: group, fallback: makeQUICOptions)) else {
            finishStart(NCConnector.Failure.handshake("hysteria2: cannot open control stream"))
            return
        }
        let controlChannel = NCHy2StreamChannel(conn: controlConn)
        control = controlChannel

        guard let authConn = newStreamConnection() else {
            finishStart(NCConnector.Failure.handshake("hysteria2: cannot open auth stream"))
            return
        }
        let authChannel = NCHy2StreamChannel(conn: authConn)
        auth = authChannel

        setSnapshot(state: .authenticating)
        controlChannel.start(queue: queue) { [weak self] error in
            guard let self else { return }
            guard error == nil else { self.finishStart(error); return }
            // RFC 9114 §6.2: a control stream opens with its stream type (0x00
            // = control stream), followed by SETTINGS. Sent exactly once, on
            // this stream only — never on the auth stream or a proxy stream.
            var flight = NCHy2.varintEncode(0x00)
            flight.append(NCHy2.http3SettingsFrame())
            self.control?.send(flight)
        }
        authChannel.start(queue: queue) { [weak self] error in
            guard let self else { return }
            guard error == nil else { self.finishStart(error); return }
            self.sendAuth()
            self.receiveAuthLoop()
        }
    }

    /// Session queue only (the group runs on it): adopt a server-initiated stream
    /// as the server's control stream and drain it. Only the first such stream is
    /// kept — a hysteria2 server opens exactly one control stream and no
    /// client-bound bidi streams.
    private func acceptServerControlStream(_ conn: NWConnection) {
        guard serverControl == nil else { conn.cancel(); return }
        let channel = NCHy2StreamChannel(conn: conn)
        serverControl = channel
        channel.start(queue: queue) { [weak self] error in
            guard let self, error == nil else { return }
            self.receiveServerControlLoop()
        }
    }

    private func receiveServerControlLoop() {
        serverControl?.receive { [weak self] data, _ in
            guard let self else { return }
            guard let data else { return } // EOF or error: nothing more to drain.
            self.serverControlBuffer.append(data)
            // Same cap as the auth stream: a peer varint declares the frame
            // length, so an unbounded buffer could grow for the connection's life.
            guard self.serverControlBuffer.count <= 64 * 1024 else {
                self.serverControl?.cancel()
                self.serverControl = nil
                return
            }
            self.parseServerControlFrames()
            if self.serverControl != nil {
                self.receiveServerControlLoop()
            }
        }
    }

    /// Frame walk over the server's control stream: the stream opens with a
    /// stream-type varint (0x00 = control stream), then HTTP/3 frames; only the
    /// SETTINGS frame is recorded, everything else is skipped.
    private func parseServerControlFrames() {
        if !serverControlTypeSeen {
            guard let (type, len) = NCHy2.varintDecode(serverControlBuffer, at: 0) else { return }
            guard type == 0x00 else {
                // Not a control stream — not something a hysteria2 server
                // should be opening; stop draining it.
                serverControl?.cancel()
                serverControl = nil
                return
            }
            serverControlTypeSeen = true
            serverControlBuffer = Data(serverControlBuffer.dropFirst(len))
        }
        while true {
            guard let (type, l1) = NCHy2.varintDecode(serverControlBuffer, at: 0),
                  let (length, l2) = NCHy2.varintDecode(serverControlBuffer, at: l1) else { return }
            let headerLen = l1 + l2
            guard serverControlBuffer.count - headerLen >= Int(length) else { return }
            serverControlBuffer = Data(serverControlBuffer.dropFirst(headerLen + Int(length)))
            if type == 0x04 { serverSettingsSeen = true } // SETTINGS
        }
        _ = serverSettingsSeen // handshake diagnostics state (was the peer's SETTINGS seen)
    }

    func close() {
        // The snapshot flips synchronously so registry readers stop vending this connection at once;
        // the NW teardown itself is confined to the session queue like all other state.
        setSnapshot(state: .closed)
        notifyWaiters(NCConnector.Failure.handshake("hysteria2 connection closed"))
        ncOnSessionQueue(queue) {
            for stream in self.streams.values { stream.cancelFromConnection() }
            self.streams.removeAll()
            self.teardownNW()
        }
    }

    /// Session queue only: cancel and drop every NW object this connection owns.
    private func teardownNW() {
        control?.cancel()
        control = nil
        auth?.cancel()
        auth = nil
        serverControl?.cancel()
        serverControl = nil
        datagramChannel?.cancel()
        datagramChannel = nil
        datagramSinks.removeAll()
        group?.cancel()
        group = nil
    }

    // MARK: Streams

    private func newStreamConnection() -> NWConnection? {
        guard let group else { return nil }
        return group.extract(connectionTo: nil, using: nil)
    }

    /// Open a proxied TCP flow. Returns nil unless the connection is
    /// authenticated; the returned stream performs the hysteria TCP
    /// request/response handshake internally and buffers sends until the
    /// server accepts. `callerQueue` is where the stream delivers receive
    /// handlers (the mux-session pattern: the caller's state stays on its
    /// own queue). Synchronous return via the session queue, like
    /// NCMuxSession.openStream.
    func openTCP(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        if NCSessionQueues.isCurrent(queue) { return openTCPOnQueue(target: target, callerQueue: callerQueue) }
        return queue.sync { openTCPOnQueue(target: target, callerQueue: callerQueue) }
    }

    private func openTCPOnQueue(target: NCTarget, callerQueue: DispatchQueue) -> NCRelayStream? {
        guard state == .ready, let conn = newStreamConnection() else { return nil }
        let stream = NCHysteria2TCPStream(channel: NCHy2StreamChannel(conn: conn),
                                          target: target, queue: queue, callerQueue: callerQueue)
        streams[ObjectIdentifier(stream)] = stream
        stream.onFinished = { [weak self] in
            guard let self else { return }
            ncOnSessionQueue(self.queue) { self.streams.removeValue(forKey: ObjectIdentifier(stream)) }
        }
        stream.begin()
        return stream
    }

    // MARK: Datagrams (unverified binding — see file header, point 4)

    /// Register (or, with nil, unregister) the datagram sink for one hysteria UDP session ID.
    /// The sink is invoked on the session queue with every raw datagram the connection receives;
    /// sessions filter by their session ID, as they did with the old single slot.
    func setDatagramSink(sessionID: UInt64, _ handler: ((Data) -> Void)?) {
        ncOnSessionQueue(queue) {
            if let handler {
                self.datagramSinks[sessionID] = handler
            } else {
                self.datagramSinks.removeValue(forKey: sessionID)
            }
        }
    }

    /// Send one raw QUIC datagram payload (already hy2-framed by the codec
    /// in NCHysteria2UDP.swift).
    func sendDatagram(_ payload: Data) {
        ncOnSessionQueue(queue) {
            guard self.state == .ready, self.udpEnabled else { return }
            self.ensureDatagramChannel()?.send(payload)
        }
    }

    private func ensureDatagramChannel() -> NCHy2StreamChannel? {
        if let datagramChannel { return datagramChannel }
        guard let conn = newStreamConnection() else { return nil }
        let channel = NCHy2StreamChannel(conn: conn)
        datagramChannel = channel
        channel.start(queue: queue) { [weak self] error in
            guard let self, error == nil else { return }
            self.datagramReceiveLoop()
        }
        return channel
    }

    private func datagramReceiveLoop() {
        datagramChannel?.receiveMessage { [weak self] data, error in
            guard let self, self.state != .closed else { return }
            if let data, !data.isEmpty {
                for sink in self.datagramSinks.values { sink(data) }
            }
            if error == nil { self.datagramReceiveLoop() }
        }
    }

    // MARK: Auth handshake

    /// The auth request HEADERS — the only frame ever sent on the auth stream.
    /// (SETTINGS lives on the control stream; see openHandshakeStreams.)
    private func sendAuth() {
        var padding = ""
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        let random = NCConnector.randomData(64)
        for byte in random { padding.append(alphabet[Int(byte) % alphabet.count]) }
        let flight = NCHy2.http3HeadersFrame(fieldSection:
            NCHy2.qpackEncodeAuthRequest(password: password, padding: padding))
        auth?.send(flight)
    }

    private func receiveAuthLoop() {
        auth?.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.state == .authenticating {
                    self.finishStart(error ?? NCConnector.Failure.handshake("hysteria2 auth stream closed"))
                }
                return
            }
            self.authBuffer.append(data)
            // nc-memory: the auth stream carries only small frames (one auth HEADERS
            // response); a declared frame length is a peer varint, so without a cap the buffer
            // grows for the connection's life waiting for a frame that never completes.
            guard self.authBuffer.count <= 64 * 1024 else {
                self.finishStart(NCConnector.Failure.handshake("hysteria2 auth frame too large"))
                self.close()
                return
            }
            self.parseAuthFrames()
            if self.state == .authenticating || self.state == .ready {
                self.receiveAuthLoop()
            }
        }
    }

    /// Incremental HTTP/3 frame walk over the auth stream: the first HEADERS
    /// frame carries the auth verdict; other frame types are skipped. (The
    /// server's SETTINGS arrives on its own control stream — see
    /// parseServerControlFrames — never here.)
    private func parseAuthFrames() {
        while state == .authenticating || state == .ready {
            guard let (type, l1) = NCHy2.varintDecode(authBuffer, at: 0),
                  let (length, l2) = NCHy2.varintDecode(authBuffer, at: l1) else { return }
            let headerLen = l1 + l2
            guard authBuffer.count - headerLen >= Int(length) else { return }
            let payload = Data(authBuffer[headerLen..<(headerLen + Int(length))])
            authBuffer = Data(authBuffer.dropFirst(headerLen + Int(length)))
            switch type {
            case 0x01: // HEADERS
                if state == .authenticating { handleAuthResponse(payload) }
            case 0x07, 0x03: // GOAWAY / CANCEL_PUSH after auth: ignore content
                break
            default:
                break
            }
        }
    }

    private func handleAuthResponse(_ fieldSection: Data) {
        guard let fields = NCHy2.qpackDecodeFieldSection(fieldSection) else {
            finishStart(NCConnector.Failure.handshake("hysteria2: undecodable auth response"))
            return
        }
        var status: String?
        var udp = false
        var tx: Int?
        for (name, value) in fields {
            switch name.lowercased() {
            case ":status": status = value
            case "hysteria-udp": udp = (value.lowercased() == "true")
            case "hysteria-cc-tx": tx = Int(value)
            default: break
            }
        }
        setSnapshot(udpEnabled: udp, serverTX: tx)
        guard status == "233" else {
            finishStart(NCConnector.Failure.handshake("hysteria2 auth rejected (status \(status ?? "?"))"))
            return
        }
        setSnapshot(state: .ready)
        finishStart(nil)
    }

    /// Session queue only (every caller — group/channel handlers, the watchdog, the auth
    /// parser — runs there). Exactly-once: the start completion is consumed before firing,
    /// and the waiter list is drained under the snapshot lock before firing, so a second
    /// finishStart (e.g. the group reporting .failed after the extract already failed)
    /// fires nothing.
    private func finishStart(_ error: Error?) {
        if let error {
            setSnapshot(state: .failed)
        }
        let completion = startCompletion
        startCompletion = nil
        if let completion {
            callbackQueue.async { completion(error) }
        }
        notifyWaiters(error)
        if error != nil {
            // Mirror NCTUICConnection.finish: a failed start tears the group down now
            // instead of leaving a started NWConnectionGroup (and its QUIC machinery)
            // alive until deallocation — one leak per failed dial otherwise.
            teardownNW()
        }
    }
}

// MARK: - TCP proxy stream

/// One hysteria2 TCP flow: writes the request header on begin, consumes the
/// response header, then passes bytes through. Sends issued before the
/// server accepts are buffered (the connector's relay pump may start
/// sending as soon as openTCP returns).
final class NCHysteria2TCPStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let target: NCTarget
    /// The owning connection's session queue: all stream state lives here (nc-races, the #116 pattern).
    private let queue: DispatchQueue
    /// Where the registered receive handler is delivered (recorded at openTCP, as in NCMuxStream).
    private let callerQueue: DispatchQueue
    var onFinished: () -> Void = {}

    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking
    private var responseBuffer = Data()
    private var outbox = Data()
    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?
    /// Completions of sends buffered in `outbox` until the server accepts; fired on flush/fail/cancel.
    private var outboxWaiters: [NCCallOnce] = []

    /// nc-memory: caps for the handshake-phase outbox and the reader-ahead inbox. The channel
    /// receive loop runs free of the reader, so both were unbounded; overflow fails the stream.
    /// 256 KB aligns with the mux stream inbound cap (a single channel chunk can reach 64 KB).
    static let maxQueuedBytes = 256 * 1024

    init(channel: NCHy2StreamChannel, target: NCTarget, queue: DispatchQueue, callerQueue: DispatchQueue) {
        self.channel = channel
        self.target = target
        self.queue = queue
        self.callerQueue = callerQueue
    }

    func begin() {
        channel.start(queue: queue) { [weak self] error in
            guard let self else { return }
            guard error == nil else { self.fail(error); return }
            let padding = NCConnector.randomData(Int(NCConnector.randomData(1)[0]) % 256)
            self.channel.send(NCHy2.tcpRequestHeader(target: self.target, padding: padding))
            self.receiveLoop()
        }
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            switch self.phase {
            case .handshaking:
                guard self.outbox.count + data.count <= Self.maxQueuedBytes else {
                    once.call()
                    self.fail(NCConnector.Failure.handshake("hysteria2 tcp send buffer overflow"))
                    return
                }
                self.outbox.append(data); self.outboxWaiters.append(once)
            case .open:
                self.channel.send(data, completion: once.call)
            case .failed, .closed:
                once.call()
            }
        }
    }

    private func drainOutboxWaiters() {
        let w = outboxWaiters; outboxWaiters = []
        w.forEach { $0.call() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.inbox.isEmpty {
                let data = self.inbox.removeFirst()
                self.inboxBytes -= data.count
                self.callerQueue.async { handler(data, nil) }
                return
            }
            if self.phase == .failed {
                let failure = self.failure
                self.callerQueue.async { handler(nil, failure) }
                return
            }
            if self.phase == .closed {
                self.callerQueue.async { handler(nil, nil) }
                return
            }
            self.pendingReceive = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            self.phase = .closed
            self.drainOutboxWaiters()
            self.channel.cancel()
            self.onFinished()
        }
    }

    /// Connection is going away: tear down without the onFinished callback
    /// (the connection clears its own registry).
    func cancelFromConnection() {
        ncOnSessionQueue(queue) {
            self.phase = .closed
            self.drainOutboxWaiters()
            self.channel.cancel()
            if let handler = self.pendingReceive {
                self.pendingReceive = nil
                self.callerQueue.async { handler(nil, nil) }
            }
        }
    }

    private func receiveLoop() {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.phase == .open || self.phase == .handshaking {
                    self.phase = .closed
                    // EOF mid-handshake must still release the sends buffered in the
                    // outbox: their completions fire on every path per the NCRelayStream
                    // contract (previously they hung forever — the pump stalled).
                    self.drainOutboxWaiters()
                    if let handler = self.pendingReceive {
                        self.pendingReceive = nil
                        self.callerQueue.async { handler(nil, error) }
                    }
                    self.onFinished()
                }
                return
            }
            switch self.phase {
            case .handshaking:
                self.responseBuffer.append(data)
                if let parsed = NCHy2.tcpResponseHeader(self.responseBuffer) {
                    let rest = Data(self.responseBuffer.dropFirst(parsed.consumed))
                    self.responseBuffer = Data()
                    guard parsed.status == 0x00 else {
                        self.fail(NCConnector.Failure.handshake(
                            "hysteria2 tcp rejected: \(parsed.message)"))
                        return
                    }
                    self.phase = .open
                    if !self.outbox.isEmpty {
                        let waiters = self.outboxWaiters; self.outboxWaiters = []
                        self.channel.send(self.outbox) { waiters.forEach { $0.call() } }
                        self.outbox = Data()
                    }
                    if !rest.isEmpty { self.deliver(rest) }
                } else if self.responseBuffer.count > 65536 {
                    self.fail(NCConnector.Failure.handshake("hysteria2 tcp response overflow"))
                    return
                }
            case .open:
                self.deliver(data)
            case .failed, .closed:
                return
            }
            if self.phase == .handshaking || self.phase == .open {
                self.receiveLoop()
            }
        }
    }

    private func deliver(_ data: Data) {
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(data, nil) }
        } else if inboxBytes + data.count <= Self.maxQueuedBytes {
            inboxBytes += data.count
            inbox.append(data)
        } else {
            fail(NCConnector.Failure.handshake("hysteria2 tcp receive buffer overflow"))
        }
    }

    private func fail(_ error: Error?) {
        let error = error ?? NCConnector.Failure.handshake("hysteria2 tcp failed")
        phase = .failed
        failure = error
        drainOutboxWaiters()
        channel.cancel()
        if let handler = pendingReceive {
            pendingReceive = nil
            callerQueue.async { handler(nil, error) }
        }
        onFinished()
    }
}
