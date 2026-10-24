import Foundation
import Network

/// Hysteria2 client (protocol v2, apernet/hysteria), built on the Network
/// framework's QUIC support.
///
/// Layout:
///  - `NCHy2` — pure, unit-testable wire functions: QUIC varints, the QPACK
///    subset the auth exchange needs (literal/static only, no dynamic table,
///    no Huffman), HTTP/3 framing, and the hysteria TCP request/response
///    headers.
///  - `NCHysteria2Connection` — one QUIC connection + the HTTP/3-style auth
///    handshake on the first stream; vends TCP proxy streams.
///  - `NCHysteria2TCPStream` — one proxied TCP flow (NCRelayStream).
/// UDP lives in NCHysteria2UDP.swift.
///
/// UNVERIFIED APPLE API POINTS (no Apple SDK on the build host; the QUIC
/// wiring is isolated here so a correction touches one place):
///  1. `NWProtocolQUIC.Options(alpn:)` and `NWParameters(quic:)` — the
///     documented iOS 15 QUIC entry points.
///  2. `quicOptions.securityProtocolOptions` for SNI / cert-verify control —
///     mirrors how NWProtocolTLS.Options is used elsewhere in this target.
///  3. Stream multiplexing via `NWConnectionGroup(with: .endpoint(_:), using:)`
///     + `NWConnection(from: group)` + `group.newConnectionHandler` — the
///     WWDC21 QUIC group model. If the descriptor case name differs, this is
///     the first place to fix.
///  4. QUIC datagrams: there is no clearly documented Swift-overlay datagram
///     surface. Datagrams are attempted on a dedicated group connection with
///     send(content:)/receiveMessage (the same calls UDP connections use).
///     If a given iOS version does not treat that connection as a datagram
///     context, UDP sessions will simply never answer — TCP is unaffected.

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

    /// String literal: H bit (0 = raw, Huffman never emitted) + 7-bit prefix
    /// length + bytes.
    static func qpackEncodeString(_ string: String) -> Data {
        let bytes = Data(string.utf8)
        var out = qpackEncodeInteger(bytes.count, prefixBits: 7, flags: 0)
        out.append(bytes)
        return out
    }

    /// Decodes a value string literal at `offset`: H bit (bit 7, Huffman —
    /// rejected) + 7-bit prefix length + raw bytes.
    static func qpackDecodeString(_ data: Data, at offset: Int, prefixBits: Int = 7) -> (value: String, length: Int)? {
        guard offset < data.count, data[offset] & 0x80 == 0 else { return nil }
        guard let (len, intLen) = qpackDecodeInteger(data, at: offset, prefixBits: prefixBits) else { return nil }
        let start = offset + intLen
        guard data.count - start >= len else { return nil }
        return (String(decoding: data[start..<(start + len)], as: UTF8.self), intLen + len)
    }

    // QPACK static table (RFC 9204 Appendix A) — entries the decoder is
    // likely to meet in an auth response. Unknown indices decode as a
    // synthetic name so a missing entry never loses the :status line (which
    // real servers send as a literal, since 233 is not in the table).
    static let qpackStaticTable: [(name: String, value: String)] = [
        (":authority", ""), (":path", "/"), (":method", "CONNECT"), (":method", "DELETE"),
        (":method", "GET"), (":method", "HEAD"), (":method", "OPTIONS"), (":method", "POST"),
        (":method", "PUT"), (":scheme", "http"), (":scheme", "https"), (":status", "103"),
        (":status", "200"), (":status", "304"), (":status", "404"), (":status", "503"),
        ("accept", "*/*"), ("accept", "application/dns-message"),
    ]

    static func qpackStaticName(_ index: Int) -> String? {
        guard index >= 0, index < qpackStaticTable.count else { return nil }
        return qpackStaticTable[index].name
    }

    /// Encode the hysteria2 auth request as a QPACK field section:
    /// :method POST, :scheme https, :path /_hysteria/, :authority, then the
    /// Hysteria-* headers as literal field lines. No dynamic table (the
    /// section prefix is two zero bytes: RIC=0, base=0).
    static func qpackEncodeAuthRequest(authority: String, password: String, padding: String) -> Data {
        var out = Data([0x00, 0x00]) // required insert count 0, delta base 0
        // Indexed field lines (pattern 1 + 7-bit index): :method POST = 7,
        // :scheme https = 10.
        out.append(qpackEncodeInteger(7, prefixBits: 7, flags: 0x80))
        out.append(qpackEncodeInteger(10, prefixBits: 7, flags: 0x80))
        // Literal with static name reference (pattern 01, T=1, 6-bit index):
        // :path = 1, :authority = 0.
        out.append(qpackEncodeInteger(1, prefixBits: 6, flags: 0x40 | 0x20))
        out.append(qpackEncodeString("/_hysteria/"))
        out.append(qpackEncodeInteger(0, prefixBits: 6, flags: 0x40 | 0x20))
        out.append(qpackEncodeString(authority))
        // Literal with literal name (pattern 001, H=0, 5-bit name length).
        for (name, value) in [("hysteria-auth", password),
                              ("hysteria-cc-rx", "0"),
                              ("hysteria-padding", padding)] {
            let nameBytes = Data(name.utf8)
            out.append(qpackEncodeInteger(nameBytes.count, prefixBits: 5, flags: 0x20))
            out.append(nameBytes)
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
                // Indexed field line: 1 T iiiiiii (7-bit prefix index).
                guard byte & 0x40 != 0 else { return nil } // dynamic table: unsupported
                guard let (index, len) = qpackDecodeInteger(data, at: idx, prefixBits: 7) else { return nil }
                idx += len
                guard index < qpackStaticTable.count else {
                    fields.append(("qpack-index-\(index)", ""))
                    continue
                }
                fields.append(qpackStaticTable[index])
            } else if byte & 0xc0 == 0x40 {
                // Literal, name reference: 0 1 T iiiiii (6-bit prefix).
                let isStatic = byte & 0x20 != 0
                guard isStatic else { return nil }
                guard let (index, len) = qpackDecodeInteger(data, at: idx, prefixBits: 6) else { return nil }
                idx += len
                guard let name = qpackStaticName(index),
                      let (value, vlen) = qpackDecodeString(data, at: idx, prefixBits: 7) else { return nil }
                idx += vlen
                fields.append((name, value))
            } else if byte & 0xe0 == 0x20 {
                // Literal, literal name: 0 0 1 H lllll (5-bit prefix name len, H must be 0).
                guard byte & 0x10 == 0 else { return nil }
                guard let (nameLen, len) = qpackDecodeInteger(data, at: idx, prefixBits: 5) else { return nil }
                idx += len
                guard data.count - idx >= nameLen else { return nil }
                let name = String(decoding: data[idx..<(idx + nameLen)], as: UTF8.self)
                idx += nameLen
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

    /// Request: varint(len) + "host:port" + varint(len) + padding bytes.
    /// Padding is a parameter (not generated inside) so tests are exact.
    static func tcpRequestHeader(target: NCTarget, padding: Data) -> Data {
        let address = "\(target.host):\(target.port)"
        var out = varintEncode(UInt64(address.utf8.count))
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
    private let queue: DispatchQueue

    private(set) var state: State = .idle
    /// Set from the auth response's Hysteria-UDP header.
    private(set) var udpEnabled = false
    /// Server-declared TX cap from the auth response (bytes/s, 0 = none).
    private(set) var serverTX: Int?

    private var group: NWConnectionGroup?
    private var control: NCHy2StreamChannel?
    private var controlBuffer = Data()
    private var serverSettingsSeen = false
    private var startCompletion: ((Error?) -> Void)?
    private var streams: [ObjectIdentifier: NCHysteria2TCPStream] = [:]

    // Datagram binding (unverified point 4, see file header).
    private var datagramChannel: NCHy2StreamChannel?
    var onDatagram: (Data) -> Void = { _ in }

    init(server: String, port: Int, password: String, sni: String? = nil,
         allowInsecure: Bool = false, queue: DispatchQueue) {
        self.server = server
        self.port = port
        self.password = password
        self.sni = sni
        self.allowInsecure = allowInsecure
        self.queue = queue
    }

    convenience init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let server = proxy.server, let port = proxy.port,
              let password = proxy.password else { return nil }
        self.init(server: server, port: port, password: password,
                  sni: proxy.fields["sni"]?.string,
                  allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                  queue: queue)
    }

    private var authority: String {
        if let sni, !sni.isEmpty { return sni }
        return port == 443 ? server : "\(server):\(port)"
    }

    // MARK: Lifecycle

    /// Connect QUIC and run the auth handshake; completion fires once, with
    /// nil error on :status 233.
    func start(completion: @escaping (Error?) -> Void) {
        guard state == .idle else {
            queue.async { completion(NCConnector.Failure.handshake("hysteria2 already started")) }
            return
        }
        state = .connecting
        startCompletion = completion

        let quicOptions = NWProtocolQUIC.Options(alpn: ["h2"])
        let tlsOptions = quicOptions.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tlsOptions, .TLSv13)
        if let sni, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions, sni)
        }
        if allowInsecure {
            sec_protocol_options_set_verify_block(tlsOptions, { _, _, complete in complete(true) }, queue)
        }
        let parameters = NWParameters(quic: quicOptions)
        parameters.allowLocalEndpointReuse = true

        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let group = NWConnectionGroup(with: .endpoint(endpoint), using: parameters)
        self.group = group
        group.stateUpdateHandler = { [weak self] groupState in
            guard let self else { return }
            if case .failed(let error) = groupState, self.state == .connecting || self.state == .authenticating {
                self.finishStart(error)
            }
        }
        group.newConnectionHandler = { [weak self] incoming in
            // Server-initiated stream: hysteria2 servers do not open streams
            // to clients in v2; cancel anything unexpected.
            _ = self
            incoming.cancel()
        }
        group.start(queue: queue)

        // The auth exchange rides the first client-initiated stream.
        guard let controlConn = newStreamConnection() else {
            finishStart(NCConnector.Failure.handshake("hysteria2: cannot open control stream"))
            return
        }
        let channel = NCHy2StreamChannel(conn: controlConn)
        control = channel
        state = .authenticating
        channel.start(queue: queue) { [weak self] error in
            guard let self else { return }
            guard error == nil else { self.finishStart(error); return }
            self.sendAuth()
            self.receiveControlLoop()
        }
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.state == .connecting || self.state == .authenticating else { return }
            self.finishStart(NCConnector.Failure.handshake("hysteria2 auth timeout"))
        }
    }

    func close() {
        state = .closed
        for stream in streams.values { stream.cancelFromConnection() }
        streams.removeAll()
        control?.cancel()
        control = nil
        datagramChannel?.cancel()
        datagramChannel = nil
        group?.cancel()
        group = nil
    }

    // MARK: Streams

    private func newStreamConnection() -> NWConnection? {
        guard let group else { return nil }
        return NWConnection(from: group)
    }

    /// Open a proxied TCP flow. Returns nil unless the connection is
    /// authenticated; the returned stream performs the hysteria TCP
    /// request/response handshake internally and buffers sends until the
    /// server accepts.
    func openTCP(target: NCTarget) -> NCRelayStream? {
        guard state == .ready, let conn = newStreamConnection() else { return nil }
        let stream = NCHysteria2TCPStream(channel: NCHy2StreamChannel(conn: conn),
                                          target: target, queue: queue)
        streams[ObjectIdentifier(stream)] = stream
        stream.onFinished = { [weak self] in
            self?.streams.removeValue(forKey: ObjectIdentifier(stream))
        }
        stream.begin()
        return stream
    }

    // MARK: Datagrams (unverified binding — see file header, point 4)

    /// Send one raw QUIC datagram payload (already hy2-framed by the codec
    /// in NCHysteria2UDP.swift).
    func sendDatagram(_ payload: Data) {
        guard state == .ready, udpEnabled else { return }
        ensureDatagramChannel()?.send(payload)
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
            if let data, !data.isEmpty { self.onDatagram(data) }
            if error == nil { self.datagramReceiveLoop() }
        }
    }

    // MARK: Auth handshake

    private func sendAuth() {
        var padding = ""
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        let random = NCConnector.randomData(64)
        for byte in random { padding.append(alphabet[Int(byte) % alphabet.count]) }
        var flight = NCHy2.http3SettingsFrame()
        flight.append(NCHy2.http3HeadersFrame(fieldSection:
            NCHy2.qpackEncodeAuthRequest(authority: authority, password: password, padding: padding)))
        control?.send(flight)
    }

    private func receiveControlLoop() {
        control?.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.state == .authenticating {
                    self.finishStart(error ?? NCConnector.Failure.handshake("hysteria2 control stream closed"))
                }
                return
            }
            self.controlBuffer.append(data)
            self.parseControlFrames()
            if self.state == .authenticating || self.state == .ready {
                self.receiveControlLoop()
            }
        }
    }

    /// Incremental HTTP/3 frame walk over the control stream: SETTINGS and
    /// other frame types are skipped; the first HEADERS frame carries the
    /// auth verdict.
    private func parseControlFrames() {
        while state == .authenticating || state == .ready {
            guard let (type, l1) = NCHy2.varintDecode(controlBuffer, at: 0),
                  let (length, l2) = NCHy2.varintDecode(controlBuffer, at: l1) else { return }
            let headerLen = l1 + l2
            guard controlBuffer.count - headerLen >= Int(length) else { return }
            let payload = Data(controlBuffer[headerLen..<(headerLen + Int(length))])
            controlBuffer = Data(controlBuffer.dropFirst(headerLen + Int(length)))
            switch type {
            case 0x04: // SETTINGS
                serverSettingsSeen = true
            case 0x01: // HEADERS
                if state == .authenticating { handleAuthResponse(payload) }
            case 0x07, 0x03: // GOAWAY / CANCEL_PUSH after auth: ignore content
                break
            default:
                break
            }
            _ = serverSettingsSeen
        }
    }

    private func handleAuthResponse(_ fieldSection: Data) {
        guard let fields = NCHy2.qpackDecodeFieldSection(fieldSection) else {
            finishStart(NCConnector.Failure.handshake("hysteria2: undecodable auth response"))
            return
        }
        var status: String?
        for (name, value) in fields {
            switch name.lowercased() {
            case ":status": status = value
            case "hysteria-udp": udpEnabled = (value.lowercased() == "true")
            case "hysteria-cc-tx": serverTX = Int(value)
            default: break
            }
        }
        guard status == "233" else {
            finishStart(NCConnector.Failure.handshake("hysteria2 auth rejected (status \(status ?? "?"))"))
            return
        }
        state = .ready
        finishStart(nil)
    }

    private func finishStart(_ error: Error?) {
        if let error {
            state = .failed
        }
        let completion = startCompletion
        startCompletion = nil
        completion?(error)
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
    private let queue: DispatchQueue
    var onFinished: () -> Void = {}

    private enum Phase { case handshaking, open, failed, closed }
    private var phase: Phase = .handshaking
    private var responseBuffer = Data()
    private var outbox = Data()
    private var inbox: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?

    init(channel: NCHy2StreamChannel, target: NCTarget, queue: DispatchQueue) {
        self.channel = channel
        self.target = target
        self.queue = queue
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

    func send(_ data: Data) {
        switch phase {
        case .handshaking:
            outbox.append(data)
        case .open:
            channel.send(data)
        case .failed, .closed:
            break
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !inbox.isEmpty {
            handler(inbox.removeFirst(), nil)
            return
        }
        if phase == .failed {
            handler(nil, failure)
            return
        }
        if phase == .closed {
            handler(nil, nil)
            return
        }
        pendingReceive = handler
    }

    func cancel() {
        phase = .closed
        channel.cancel()
        onFinished()
    }

    /// Connection is going away: tear down without the onFinished callback
    /// (the connection clears its own registry).
    func cancelFromConnection() {
        phase = .closed
        channel.cancel()
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(nil, nil)
        }
    }

    private func receiveLoop() {
        channel.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else {
                if self.phase == .open || self.phase == .handshaking {
                    self.phase = .closed
                    if let handler = self.pendingReceive {
                        self.pendingReceive = nil
                        handler(nil, error)
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
                        self.channel.send(self.outbox)
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
            handler(data, nil)
        } else {
            inbox.append(data)
        }
    }

    private func fail(_ error: Error?) {
        let error = error ?? NCConnector.Failure.handshake("hysteria2 tcp failed")
        phase = .failed
        failure = error
        channel.cancel()
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(nil, error)
        }
        onFinished()
    }
}
