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
    private(set) var totalUp: Int64 = 0
    private(set) var totalDown: Int64 = 0
    private(set) var totalProxyUp: Int64 = 0
    private(set) var totalProxyDown: Int64 = 0
    /// Lock-protected mirror of live state for the controller (other queues).
    let stats = NCDataPlaneStats()
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
        var upBytes: Int64 = 0
        var downBytes: Int64 = 0
        var chainName = ""
        var ruleText = ""
        var policyName = ""
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
        // The v6 address mirrors PacketTunnelProvider's NEIPv6Settings so
        // fake-IP v6 destinations terminate in the stack like v4 ones.
        guard stack.start(ip4: "198.18.0.1", ip6: "fdfe:dcba:9876::1", mtu: mtu) else {
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
                for p in packets {
                    // ICMP echo to fake-IP / tunnel addresses: answer in
                    // place (those destinations aren't stack addresses).
                    if let dst = NCICMPEcho.echoRequestDestination(p),
                       self.engine.shouldAnswerEcho(to: dst),
                       let reply = NCICMPEcho.reply(for: p) {
                        self.stack.onOutput(reply)
                        continue
                    }
                    self.stack.input(p)
                }
                self.readLoop()
            }
        }
    }

    private var tickCount = 0
    private static let isoFormatter = ISO8601DateFormatter()

    private func tick() {
        stack.poll()
        // The controller mirror is rebuilt once a second (was every 250 ms tick: a dictionary per connection +
        // a new date formatter each time).
        tickCount &+= 1
        if tickCount % 4 == 0 { refreshStats() }
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
            countUp(s, data.count)
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
        case .tls(let sni, let alpn):
            if let sni { s.ruleDomain = sni; s.target = NCTarget(host: sni, port: s.target.port) }
            if let sni, engine.isMitm(host: sni, port: s.target.port) {
                let alpnStr = alpn.joined(separator: ",")
                let mitmPort = MitmTLSFront.shared.listen(host: sni, alpn: alpnStr)
                if mitmPort > 0 {
                    s.state = .connecting
                    s.policyName = "MITM"
                    s.chainName = "MITM"
                    let stream = NCStream(to: "127.0.0.1", port: Int(mitmPort), queue: queue)
                    stream.start { [weak self, weak s] err in
                        guard let self, let s, s.state == .connecting else {
                            stream.cancel()
                            return
                        }
                        if let err {
                            self.close(s)
                            return
                        }
                        s.relay = stream
                        s.state = .open
                        if !s.pending.isEmpty {
                            self.countUp(s, s.pending.count)
                            stream.send(s.pending)
                            s.pending = Data()
                        }
                        self.receiveLoop(s)
                    }
                    return
                }
            }
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
        let ctx = engine.matchContext(domain: s.ruleDomain,
                                 ip: s.target.ip,
                                 dstPort: s.target.port,
                                 network: "tcp")
        let (policyName, ruleText) = engine.policyWithRule(for: ctx)
        s.policyName = policyName
        s.ruleText = ruleText ?? ""
        let resolution = engine.resolve(ctx)
        s.chainName = switch resolution {
        case .direct: "DIRECT"
        case .reject: "REJECT"
        case .proxy(let p): p.name
        case .chain(let ps): ps.map { $0.name }.joined(separator: " -> ")
        case .unknown(let n): n
        }
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
                countUp(s, s.pending.count)
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
                countDown(s, data.count)
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

    private func countUp(_ s: TCPSession, _ n: Int) {
        s.upBytes += Int64(n)
        totalUp += Int64(n)
        if s.chainName != "DIRECT" { totalProxyUp += Int64(n) }
    }

    private func countDown(_ s: TCPSession, _ n: Int) {
        s.downBytes += Int64(n)
        totalDown += Int64(n)
        if s.chainName != "DIRECT" { totalProxyDown += Int64(n) }
    }

    /// Snapshot refresh for the controller's stats mirror (called on the tick).
    private func refreshStats() {
        let fmt = Self.isoFormatter
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let conns: [[String: Any]] = sessions.values.map { s in
            [
                "id": String(s.key),
                "metadata": [
                    "network": "tcp",
                    "type": "Native",
                    "sourceIP": "198.18.0.1",
                    "sourcePort": String(s.conn.srcPort),
                    "destinationIP": s.conn.dst.host,
                    "destinationPort": String(s.conn.dst.port),
                    "host": s.ruleDomain ?? "",
                    "sniffHost": "",
                    "process": "",
                    "remoteDestination": s.target.host,
                ],
                "upload": s.upBytes,
                "download": s.downBytes,
                "start": fmt.string(from: s.acceptedAt),
                "chains": [s.chainName],
                "rule": s.ruleText,
                "rulePayload": "",
            ]
        }
        stats.update(connections: conns, up: totalUp, down: totalDown,
                     proxyUp: totalProxyUp, proxyDown: totalProxyDown)
    }

    /// Controller entry points (safe from any queue).
    func requestCloseConnection(id: String) {
        queue.async { [weak self] in
            guard let self, let key = UInt(id),
                  let s = sessions[key] else { return }
            close(s)
        }
    }

    func requestCloseAllConnections() {
        queue.async { [weak self] in
            guard let self else { return }
            for s in Array(sessions.values) { close(s) }
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
            if let reply = engine.dnsHostsReply(data) ?? engine.handleDNSQuery(data) {
                dnsReplies += 1
                stack.udpSend(session: info.id, reply)
                return
            }
            // Not fake-IP business (filter host, other record types): forward
            // the query to its assigned upstream (per-domain policy first).
            if let upstream = engine.dnsUpstream(for: data) {
                let sid = info.id
                dnsForwarder.forward(data, upstream: upstream) { [weak self] resp in
                    if let resp {
                        self?.engine.recordDNSResponse(query: data, response: resp)
                        self?.stack.udpSend(session: sid, resp)
                    }
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
        // QUIC to a MitM host is dropped so the client falls back to TCP, where the native MitM front sees it
        // (bridge/mitm Inject's UDP REJECT rule on the Go path).
        if info.dst.port == 443, target.host != info.dst.host, engine.isMitm(host: target.host, port: 443) {
            udpDropped += 1
            return
        }
        let ctx = engine.matchContext(domain: target.host != info.dst.host ? target.host : nil,
                                 ip: info.dst.ip,
                                 dstPort: info.dst.port,
                                 network: "udp")
        let session: NCUDPSession
        switch engine.resolve(ctx) {
        case .direct:
            session = NCUDPDirectSession(target: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "socks5":
            session = NCUDPSocks5Session(proxy: proxy, queue: queue)
        case .proxy(let proxy) where proxy.type == "ss":
            guard let ss = NCUDPSSSession(proxy: proxy, queue: queue) else {
                udpDropped += 1
                return
            }
            session = ss
        case .proxy(let proxy) where proxy.type == "hysteria2" || proxy.type == "hy2":
            guard let hy2 = NCUDPHysteria2Session(proxy: proxy, queue: queue) else {
                udpDropped += 1
                return
            }
            session = hy2
        case .proxy(let proxy) where (proxy.type == "vmess" || proxy.type == "vless")
            && NCConnector.smuxEnabled(proxy)
            && !(proxy.fields["smux"]?.object?["only-tcp"]?.bool ?? false):
            session = NCUDPMuxSession(proxy: proxy, queue: queue)
        case .proxy(let proxy) where proxy.type == "vmess":
            guard let vm = NCUDPVMessSession(proxy: proxy, target: target, queue: queue) else {
                udpDropped += 1
                return
            }
            session = vm
        case .proxy(let proxy) where proxy.type == "vless":
            guard let vl = NCUDPVLESSSession(proxy: proxy, target: target, queue: queue) else {
                udpDropped += 1
                return
            }
            session = vl
        case .proxy(let proxy) where proxy.type == "trojan":
            session = NCUDPTrojanSession(proxy: proxy, firstTarget: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "ssr":
            guard let ssr = NCUDPSSRSession(proxy: proxy, queue: queue) else {
                udpDropped += 1
                return
            }
            session = ssr
        case .proxy(let proxy) where proxy.type == "anytls":
            session = NCUDPAnyTLSSession(proxy: proxy, target: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "snell":
            guard let sn = NCUDPSnellSession(proxy: proxy, queue: queue) else {
                udpDropped += 1
                return
            }
            session = sn
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

/// Thread-safe stats mirror: the data plane writes on its queue (every tick),
/// the controller reads from its own queue.
final class NCDataPlaneStats {
    private let lock = NSLock()
    private var connections: [[String: Any]] = []
    private(set) var up: Int64 = 0
    private(set) var down: Int64 = 0
    private(set) var proxyUp: Int64 = 0
    private(set) var proxyDown: Int64 = 0

    func update(connections: [[String: Any]], up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) {
        lock.lock()
        self.connections = connections
        self.up = up
        self.down = down
        self.proxyUp = proxyUp
        self.proxyDown = proxyDown
        lock.unlock()
    }

    func snapshot() -> (connections: [[String: Any]], up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) {
        lock.lock()
        defer { lock.unlock() }
        return (connections, up, down, proxyUp, proxyDown)
    }
}
