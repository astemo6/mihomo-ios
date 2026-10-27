import Foundation
import Network

// fix/nc-masque-ip: MASQUE CONNECT-IP (RFC 9484) control plane + packet channel.
//
// One Extended CONNECT request stream (`:protocol = connect-ip`, `capsule-protocol: ?1`) on the node's own HTTP/3
// connection (NCMASQUEConnection: QUIC group, client control stream with SETTINGS ENABLE_CONNECT_PROTOCOL +
// H3_DATAGRAM, one QUIC DATAGRAM channel). After a 2xx response the stream carries capsules (RFC 9297) inside HTTP/3
// DATA frames — ADDRESS_ASSIGN (0x01), ROUTE_ADVERTISEMENT (0x03), DATAGRAM (0x00, fallback packet path) — and every
// IP packet travels as an HTTP Datagram: quarter stream id + context id 0 + the full IPv4/IPv6 packet (RFC 9484 §6).
//
// The packet side is the PacketTunnel's job (NCMASQUEIPNetif.swift: one lwIP netif per node, like WireGuard and
// OpenConnect); this file only knows bytes. Memory: one Data per packet in each direction (header + packet in a
// single allocation on the way out), capsule buffer capped at 256 KB, uplink in-flight capped (excess dropped like a
// full interface queue — TCP retransmits). 需同步 feat/nc-kernel.

extension NCMASQUE {
    /// Set to true only after the real CONNECT-IP loopback (proto-loopback.yml job `masque-ip`) is green:
    /// mirror runs 40464266033 (cd18839) and 40468656765 (7f92c2a, MSS clamp) — 8/8 against the connect-ip-go proxy.
    static let connectIPVerified = true

    /// Shown by NCSupport for a valid CONNECT-IP node while `connectIPVerified` is false.
    static let connectIPUnverified = "MASQUE CONNECT-IP 数据面验证中（真实 RFC 9484 服务端回环通过前暂不可用）"

    /// The node needs the packet tunnel's lwIP netif; outside it (the App's 延迟测试) it cannot dial.
    static let connectIPTunnelOnly = "MASQUE CONNECT-IP 仅在 VPN 隧道内可用（隧道内 L3 网卡）"

    /// Cloudflare WARP profiles (private-key / public-key / cf-connect-ip) need an mTLS client identity built from the
    /// WARP key and server-key pinning — not wired.
    static let warpUnavailable = "MASQUE WARP（Cloudflare 私有 cf-connect-ip + mTLS 客户端证书）尚未接入；通用 RFC 9484 CONNECT-IP 请用 mode: connect-ip + uri"

    /// `:authority` and `:path` for the CONNECT-IP request: taken from the URI template (RFC 9484 §3), whose
    /// variables {target} / {ipproto} expand to `*` (full tunnel). A path-only template uses server:port.
    static func connectIPRequestTarget(_ cfg: Config) -> (authority: String, path: String) {
        var t = cfg.uri
        t = t.replacingOccurrences(of: "{target}", with: "*").replacingOccurrences(of: "{ipproto}", with: "*")
        t = t.replacingOccurrences(of: "{?target,ipproto}", with: "")
        let defaultAuthority = cfg.server.contains(":") && !cfg.server.hasPrefix("[")
            ? "[\(cfg.server)]:\(cfg.port)" : "\(cfg.server):\(cfg.port)"
        guard let schemeEnd = t.range(of: "://") else {
            return (defaultAuthority, t.hasPrefix("/") ? t : "/" + t)
        }
        let rest = t[schemeEnd.upperBound...]
        if let slash = rest.firstIndex(of: "/") {
            let auth = String(rest[..<slash])
            return (auth.isEmpty ? defaultAuthority : auth, String(rest[slash...]))
        }
        return (rest.isEmpty ? defaultAuthority : String(rest), "/")
    }

    /// Largest IP packet the netif emits: Network.framework's proven QUIC DATAGRAM payload (NCHy2UDP.maxDatagramSize,
    /// 1197 B — larger ones can be dropped silently) minus room for the quarter stream id (≤ 3 B here) + context id.
    static let connectIPMaxPacket = NCHy2UDP.maxDatagramSize - 4

    /// One HTTP Datagram for CONNECT-IP: quarter stream id + context id 0 + the IP packet, one allocation.
    static func connectIPDatagram(quarterStreamID: UInt64, packet: UnsafeBufferPointer<UInt8>) -> Data {
        let q = varintEncode(quarterStreamID)
        var d = Data(capacity: q.count + 1 + packet.count)
        d.append(q)
        d.append(0x00)
        if let base = packet.baseAddress { d.append(base, count: packet.count) }
        return d
    }

    /// A parsed HTTP/3 frame header at `offset`: (type, payload length, header length), nil when incomplete.
    static func h3FrameHeader(_ d: Data, at offset: Int) -> (type: UInt64, length: Int, header: Int)? {
        guard let (type, tLen) = varintDecode(d, at: offset),
              let (len, lLen) = varintDecode(d, at: offset + tLen), len <= UInt64(Int32.max) else { return nil }
        return (type, Int(len), tLen + lLen)
    }
}

/// CONNECT-IP session parameters announced by the proxy.
struct NCMASQUEIPParams: Equatable {
    var ipv4: String?
    var ipv6: String?
    var routes: [NCMASQUE.RouteAdvertisement] = []
}

/// One CONNECT-IP tunnel. Callbacks (`onPacket`, `onClosed`, start completion) arrive on `callbackQueue`.
final class NCMASQUEIPTunnel {
    let config: NCMASQUE.Config
    let callbackQueue: DispatchQueue
    /// One IP packet from the proxy (context id 0), on callbackQueue.
    var onPacket: (Data) -> Void = { _ in }
    /// The request stream / QUIC connection ended after start succeeded, on callbackQueue.
    var onClosed: (String) -> Void = { _ in }
    /// Updated ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT after start, on callbackQueue.
    var onParams: (NCMASQUEIPParams) -> Void = { _ in }

    private let connection: NCMASQUEConnection
    private var channel: NCMASQUEStreamChannel?
    private var quarterStreamID: UInt64 = 0
    private var buffer = Data()
    private var gotHeaders = false
    private var capsules = NCMASQUE.CapsuleParser()
    private(set) var params = NCMASQUEIPParams()
    private var gotAddress = false
    private var startDone: ((Result<NCMASQUEIPParams, Error>) -> Void)?
    private var closed = false
    private let lock = NSLock()
    private var inFlight = 0
    private(set) var txDropped = 0
    private(set) var packetsOut = 0
    private(set) var packetsIn = 0
    private static let maxInFlight = 512

    init(config: NCMASQUE.Config, callbackQueue: DispatchQueue) {
        self.config = config
        self.callbackQueue = callbackQueue
        connection = NCMASQUEConnection(config: config, queue: callbackQueue)
    }

    /// QUIC + HTTP/3 + Extended CONNECT, then waits for ADDRESS_ASSIGN (or the node's configured `ip` / `ipv6` when
    /// the proxy assigns none within 3 s). Completion exactly once, on callbackQueue.
    func start(timeout: TimeInterval = 20, _ completion: @escaping (Result<NCMASQUEIPParams, Error>) -> Void) {
        startDone = completion
        connection.start { [weak self] err in
            guard let self else { return }
            if let err { self.finishStart(.failure(err)); return }
            ncOnSessionQueue(self.connection.queue) { self.openRequest() }
        }
        callbackQueue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finishStart(.failure(NCConnector.Failure.handshake("MASQUE CONNECT-IP 握手超时")))
        }
    }

    private func finishStart(_ r: Result<NCMASQUEIPParams, Error>) {
        lock.lock()
        let done = startDone
        startDone = nil
        lock.unlock()
        guard let done else { return }
        if case .failure = r { close() }
        callbackQueue.async { done(r) }
    }

    private func openRequest() {
        guard let bidi = connection.extractRequestStream() else {
            finishStart(.failure(NCConnector.Failure.handshake("MASQUE 无法打开 CONNECT-IP 请求流")))
            return
        }
        let ch = NCMASQUEStreamChannel(conn: bidi)
        channel = ch
        ch.start(queue: connection.queue) { [weak self] err in
            guard let self else { return }
            if let err { self.finishStart(.failure(err)); return }
            guard let sid = ch.quicStreamID else {
                self.finishStart(.failure(NCConnector.Failure.handshake("MASQUE CONNECT-IP 请求流无 stream id")))
                return
            }
            self.quarterStreamID = sid / 4
            self.connection.registerIPSink(quarterStreamID: sid / 4) { [weak self] payload in
                guard let self else { return }
                self.callbackQueue.async {
                    self.packetsIn += 1
                    self.onPacket(payload)
                }
            }
            let (authority, path) = NCMASQUE.connectIPRequestTarget(self.config)
            var extra: [(String, String)] = []
            if let u = self.config.username, let p = self.config.password {
                extra.append(("authorization", "Basic " + Data("\(u):\(p)".utf8).base64EncodedString()))
            }
            let fields = NCMASQUE.qpackEncodeExtendedConnect(protocolValue: "connect-ip", authority: authority,
                                                             path: path, extraHeaders: extra)
            var frame = NCMASQUE.varintEncode(0x01)
            frame.append(NCMASQUE.varintEncode(UInt64(fields.count)))
            frame.append(fields)
            ch.send(frame) {}
            self.receiveLoop(ch)
        }
    }

    // MARK: Request stream: HEADERS, then DATA frames carrying capsules

    private func receiveLoop(_ ch: NCMASQUEStreamChannel) {
        ch.receive { [weak self] data, err in
                guard let self, !self.isClosed else { return }
            guard let data, !data.isEmpty else {
                self.streamEnded(err.map { "\($0.localizedDescription)" } ?? "EOF")
                return
            }
            self.buffer.append(data)
            guard self.buffer.count <= 256 * 1024 else {
                self.streamEnded("CONNECT-IP 请求流帧过大")
                return
            }
            if let why = self.consumeFrames() {
                self.streamEnded(why)
                return
            }
            self.receiveLoop(ch)
        }
    }

    /// Walks complete HTTP/3 frames in `buffer`; returns a fatal reason or nil.
    private func consumeFrames() -> String? {
        var off = 0
        while let (type, len, hdr) = NCMASQUE.h3FrameHeader(buffer, at: off), off + hdr + len <= buffer.count {
            let s0 = buffer.startIndex + off + hdr
            let payload = buffer[s0..<(s0 + len)]
            off += hdr + len
            if !gotHeaders {
                guard type == 0x01 else { continue } // reserved / grease frames before HEADERS are skipped
                guard let fields = NCMASQUE.qpackDecodeFieldSection(Data(payload)) else { return "CONNECT-IP 响应 QPACK 解码失败" }
                let status = fields.first(where: { $0.name == ":status" })?.value ?? "?"
                guard status.hasPrefix("2") else {
                    finishStart(.failure(NCConnector.Failure.handshake("MASQUE CONNECT-IP 被拒绝 (HTTP \(status))")))
                    return "HTTP \(status)"
                }
                gotHeaders = true
                if config.ip != nil || config.ipv6 != nil {
                    connection.queue.asyncAfter(deadline: .now() + 3) { [weak self] in self?.fallbackAddress() }
                }
                continue
            }
            guard type == 0x00 else { continue } // trailers / unknown frames: ignored
            for cap in capsules.feed(Data(payload)) { handleCapsule(cap) }
        }
        if off > 0 { buffer = off >= buffer.count ? Data() : Data(buffer[(buffer.startIndex + off)...]) }
        return nil
    }

    private func handleCapsule(_ cap: NCMASQUE.Capsule) {
        switch cap.type {
        case NCMASQUE.capsuleTypeAddressAssign:
            guard let list = NCMASQUE.AssignedAddress.decodeSequence(cap.value) else { return }
            var p = params
            for a in list {
                guard let ip = NCIP(bytes: [UInt8](a.address)) else { continue }
                // RFC 9484 §4.7.1: an all-zero address with prefix 0... is a rejection; skip it.
                if a.address.allSatisfy({ $0 == 0 }) { continue }
                if a.ipVersion == 4, p.ipv4 == nil || !gotAddress { p.ipv4 = ip.string }
                if a.ipVersion == 6, p.ipv6 == nil || !gotAddress { p.ipv6 = ip.string }
            }
            guard p.ipv4 != nil || p.ipv6 != nil else { return }
            params = p
            if !gotAddress {
                gotAddress = true
                finishStart(.success(p))
            } else {
                let snap = p
                callbackQueue.async { self.onParams(snap) }
            }
        case NCMASQUE.capsuleTypeRouteAdvertisement:
            guard let routes = NCMASQUE.RouteAdvertisement.decodeSequence(cap.value) else { return }
            params.routes = routes
            if gotAddress {
                let snap = params
                callbackQueue.async { self.onParams(snap) }
            }
        case NCMASQUE.capsuleTypeDatagram:
            // DATAGRAM capsule fallback (RFC 9297 §3.5): context id + packet.
            guard let (ctx, n) = NCMASQUE.varintDecode(cap.value, at: 0), ctx == 0 else { return }
            let pkt = Data(cap.value[(cap.value.startIndex + n)...])
            callbackQueue.async {
                self.packetsIn += 1
                self.onPacket(pkt)
            }
        default:
            break // unknown capsules are skipped (RFC 9297 §3.2)
        }
    }

    /// The proxy assigned nothing: use the node's configured address (WARP-style profiles carry it).
    private func fallbackAddress() {
        guard !gotAddress, !isClosed else { return }
        var p = params
        if let v4 = config.ip, let ip = NCIP(stripPrefix(v4)) { p.ipv4 = ip.string }
        if let v6 = config.ipv6, let ip = NCIP(stripPrefix(v6)) { p.ipv6 = ip.string }
        guard p.ipv4 != nil || p.ipv6 != nil else { return }
        params = p
        gotAddress = true
        finishStart(.success(p))
    }

    private func stripPrefix(_ s: String) -> String {
        s.split(separator: "/").first.map(String.init) ?? s
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func streamEnded(_ why: String) {
        guard !isClosed else { return }
        finishStart(.failure(NCConnector.Failure.handshake("MASQUE CONNECT-IP: \(why)")))
        close()
        callbackQueue.async { self.onClosed(why) }
    }

    // MARK: Packets out

    /// One IP packet from the netif (valid only during the call). Call on callbackQueue.
    func send(_ pkt: UnsafeBufferPointer<UInt8>) {
        lock.lock()
        let isClosed = closed
        lock.unlock()
        guard !isClosed, pkt.count > 0 else { txDropped += 1; return }
        guard inFlight < Self.maxInFlight else { txDropped += 1; return }
        inFlight += 1
        packetsOut += 1
        let wire = NCMASQUE.connectIPDatagram(quarterStreamID: quarterStreamID, packet: pkt)
        connection.sendRawDatagram(wire) { [weak self] in
            guard let self else { return }
            self.callbackQueue.async { self.inFlight = max(0, self.inFlight - 1) }
        }
    }

    func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        lock.unlock()
        connection.removeIPSink(quarterStreamID: quarterStreamID)
        channel?.cancel()
        channel = nil
        connection.close()
    }
}
