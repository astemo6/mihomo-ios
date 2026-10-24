import Foundation
import NetworkExtension

enum NCDataPlaneError: Error {
    case stackStartFailed
}

/// The native core's data plane: NEPacketTunnelFlow <-> lwIP stack <-> outbound
/// relays. Everything runs on one serial queue, matching the C stack's
/// single-threaded contract.
final class NCDataPlane {
    private let engine: NativeCoreEngine
    private let stack = NCTunStack()
    private weak var flow: NEPacketTunnelFlow?
    private let mtu: UInt16
    let queue = DispatchQueue(label: "nc.dataplane", qos: .userInitiated)

    private var timer: DispatchSourceTimer?
    private var sessions: [UInt: TCPSession] = [:]
    private var udpSessions: [UInt32: UDPSessionEntry] = [:]
    private lazy var dnsForwarder = NCDNSForwarder(queue: queue)

    private struct UDPSessionEntry {
        let session: NCUDPSession
        var lastUsed: Date
    }
    private var dnsReplies = 0
    private var udpDropped = 0
    private(set) var isRunning = false

    final class TCPSession {
        let conn: NCTunStack.TCPConn
        var target: NCTarget        // dial target (domain after deref/sniff, else the IP)
        var ruleDomain: String?     // domain fed to rule matching, when known
        var pending = Data()        // client bytes buffered before the relay is up
        var outbox = Data()         // relay bytes waiting for stack send window
        var relay: NCRelayStream?
        var state: State = .deciding
        let acceptedAt = Date()
        enum State { case deciding, connecting, open, closed }
        init(conn: NCTunStack.TCPConn, target: NCTarget, ruleDomain: String?) {
            self.conn = conn
            self.target = target
            self.ruleDomain = ruleDomain
        }
        var key: UInt { UInt(bitPattern: conn.handle) }
    }

    init(engine: NativeCoreEngine, flow: NEPacketTunnelFlow, mtu: UInt16) {
        self.engine = engine
        self.flow = flow
        self.mtu = mtu
    }

    func start() throws {
        stack.onOutput = { [weak self] packet in
            guard let self, let flow = self.flow, !packet.isEmpty else { return }
            let family: NSNumber = (packet[0] >> 4) == 6 ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
            flow.writePackets([packet], withProtocols: [family])
        }
        stack.onTCPAccept = { [weak self] conn in self?.accept(conn) ?? false }
        stack.onTCPData = { [weak self] conn, data in self?.tcpData(conn, data) }
        stack.onTCPError = { [weak self] conn in self?.tcpError(conn) }
        stack.onUDP = { [weak self] info, data in self?.udp(info, data) }
        guard stack.start(ip4: "198.18.0.1", ip6: nil, mtu: mtu) else {
            throw NCDataPlaneError.stackStartFailed
        }
        isRunning = true
        readLoop()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    func stop() {
        queue.sync {
            timer?.cancel()
            timer = nil
            for s in sessions.values {
                s.relay?.cancel()
                stack.tcpAbort(s.conn)
            }
            sessions.removeAll()
            for e in udpSessions.values { e.session.cancel() }
            udpSessions.removeAll()
            stack.stop()
            isRunning = false
        }
    }

    var statsLine: String {
        "native: sessions \(sessions.count), dns replies \(dnsReplies), udp dropped \(udpDropped)"
    }

    // MARK: Packet flow

    private func readLoop() {
        flow?.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                for p in packets { self.stack.input(p) }
                self.readLoop()
            }
        }
    }

    private func tick() {
        stack.poll()
        let now = Date()
        for s in sessions.values {
            if s.state == .deciding, now.timeIntervalSince(s.acceptedAt) > 1.5 {
                connect(s) // server-first protocol or silent client: go by IP
            }
            if s.state == .open { drain(s) }
        }
        // Mirror the C stack's 120 s UDP idle expiry on our side.
        for (id, entry) in udpSessions where now.timeIntervalSince(entry.lastUsed) > 120 {
            entry.session.cancel()
            udpSessions.removeValue(forKey: id)
        }
    }

    // MARK: TCP

    private func accept(_ conn: NCTunStack.TCPConn) -> Bool {
        let derefed = engine.derefFakeIP(conn.dst)
        let fakeDomain = derefed.host != conn.dst.host ? derefed.host : nil
        let s = TCPSession(conn: conn, target: derefed, ruleDomain: fakeDomain)
        sessions[s.key] = s
        if fakeDomain != nil {
            connect(s) // destination known from DNS: no sniffing needed
        }
        return true
    }

    private func tcpData(_ conn: NCTunStack.TCPConn, _ data: Data?) {
        guard let s = sessions[UInt(bitPattern: conn.handle)] else { return }
        guard let data else {
            close(s) // client FIN
            return
        }
        switch s.state {
        case .deciding:
            s.pending.append(data)
            decide(s)
        case .connecting:
            s.pending.append(data)
        case .open:
            s.relay?.send(data)
        case .closed:
            break
        }
    }

    private func tcpError(_ conn: NCTunStack.TCPConn) {
        guard let s = sessions.removeValue(forKey: UInt(bitPattern: conn.handle)) else { return }
        s.state = .closed
        s.relay?.cancel()
    }

    /// Learn the real domain from the first bytes (TLS SNI / HTTP Host) when the
    /// app dialed a bare IP; otherwise keep the IP as the target.
    private func decide(_ s: TCPSession) {
        switch NCSniffer.detect(s.pending) {
        case .tls(let sni, _):
            if let sni { s.ruleDomain = sni; s.target = NCTarget(host: sni, port: s.target.port) }
            connect(s)
        case .http(let host, _):
            if let host { s.ruleDomain = host; s.target = NCTarget(host: host, port: s.target.port) }
            connect(s)
        case .unknown:
            connect(s)
        }
    }

    private func connect(_ s: TCPSession) {
        guard s.state == .deciding else { return }
        s.state = .connecting
        let ctx = NCMatchContext(domain: s.ruleDomain,
                                 ip: s.target.ip,
                                 dstPort: s.target.port,
                                 network: "tcp")
        let resolution = engine.resolve(ctx)
        NCConnector.connect(target: s.target, resolution: resolution, queue: queue) { [weak self, weak s] relay, _ in
            guard let self, let s, s.state == .connecting else {
                relay?.cancel()
                return
            }
            guard let relay else {
                self.close(s)
                return
            }
            s.relay = relay
            s.state = .open
            if !s.pending.isEmpty {
                relay.send(s.pending)
                s.pending = Data()
            }
            self.receiveLoop(s)
        }
    }

    private func receiveLoop(_ s: TCPSession) {
        s.relay?.receive { [weak self, weak s] data, error in
            guard let self, let s, s.state == .open else { return }
            if let data, !data.isEmpty {
                s.outbox.append(data)
                self.drain(s)
                self.receiveLoop(s)
            } else if error == nil {
                self.close(s) // clean EOF
            } else {
                self.close(s)
            }
        }
    }

    private func drain(_ s: TCPSession) {
        guard !s.outbox.isEmpty else { return }
        let written = stack.tcpWrite(s.conn, s.outbox)
        if written < 0 {
            close(s)
            return
        }
        if written > 0 {
            s.outbox.removeFirst(written)
        }
    }

    private func close(_ s: TCPSession) {
        guard s.state != .closed else { return }
        s.state = .closed
        sessions.removeValue(forKey: s.key)
        s.relay?.cancel()
        stack.tcpClose(s.conn)
    }

    // MARK: UDP

    private func udp(_ info: NCTunStack.UDPSessionInfo, _ data: Data) {
        if info.dst.port == 53 {
            if let reply = engine.handleDNSQuery(data) {
                dnsReplies += 1
                stack.udpSend(session: info.id, reply)
                return
            }
            // Not fake-IP business (filter host, other record types): forward
            // the query to the configured nameserver, like mihomo does.
            if let server = engine.firstUDPNameserver {
                let sid = info.id
                dnsForwarder.forward(data, server: server) { [weak self] resp in
                    if let resp { self?.stack.udpSend(session: sid, resp) }
                }
            } else {
                udpDropped += 1
            }
            return
        }
        udpForward(info, data)
    }

    private func udpForward(_ info: NCTunStack.UDPSessionInfo, _ data: Data) {
        if var entry = udpSessions[info.id] {
            entry.lastUsed = Date()
            udpSessions[info.id] = entry
            entry.session.send(data, to: engine.derefFakeIP(info.dst))
            return
        }
        let target = engine.derefFakeIP(info.dst)
        let ctx = NCMatchContext(domain: target.host != info.dst.host ? target.host : nil,
                                 ip: info.dst.ip,
                                 dstPort: info.dst.port,
                                 network: "udp")
        let session: NCUDPSession
        switch engine.resolve(ctx) {
        case .direct:
            session = NCUDPDirectSession(target: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "socks5":
            session = NCUDPSocks5Session(proxy: proxy, queue: queue)
        case .proxy(let proxy) where proxy.type == "trojan":
            // Trojan UDP rides its TLS stream; lands with the SS/Trojan UDP batch.
            udpDropped += 1
            _ = proxy
            return
        default:
            udpDropped += 1
            return
        }
        let sid = info.id
        session.onReply = { [weak self] payload in
            self?.stack.udpSend(session: sid, payload)
        }
        udpSessions[info.id] = UDPSessionEntry(session: session, lastUsed: Date())
        session.send(data, to: target)
    }
}

/// Whether the tunnel should run the native core instead of the Go core.
/// Opt-in via the App Group defaults key `nativeCoreEnabled` (default off);
/// the App gains a toggle in a later batch. A native start failure falls back
/// to the Go core inside PacketTunnelProvider.
enum NativeCoreSwitch {
    static var isEnabled: Bool {
        UserDefaults(suiteName: AppShared.appGroup)?.bool(forKey: "nativeCoreEnabled") ?? false
    }
}
