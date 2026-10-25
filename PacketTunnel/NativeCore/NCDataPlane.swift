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
    /// feat/nc-wg: the shared lwIP queue — WireGuard netifs (NCWireGuard.swift) live in the same lwIP instance.
    let queue = NCLwIP.queue

    private var timer: DispatchSourceTimer?
    private var sessions: [UInt: TCPSession] = [:]
    private var udpSessions: [UInt32: UDPSessionEntry] = [:]
    private lazy var dnsForwarder = NCDNSForwarder(queue: queue)

    /// rv2-life: a class so a reply can refresh `lastUsed` without a dictionary write (the C side counts both
    /// directions as activity; this side used to count only app → relay and expired busy download flows).
    private final class UDPSessionEntry {
        let session: NCUDPSession
        var lastUsed: Date
        init(session: NCUDPSession, lastUsed: Date) {
            self.session = session
            self.lastUsed = lastUsed
        }
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

    // rv2-life (#10) back-pressure / memory caps. lwIP's own send buffer per connection is TCP_SND_BUF (16 × 1460 =
    // 23 360 B, lwipopts.h); the outbox in front of it is capped at about twice that: once a connection holds
    // `outboxCap` the relay is not read again until the app ACKed enough (tcp_sent callback / tick) to bring it
    // under `outboxResume`. One relay read is ≤ 64 KB (NCStream), so a connection holds ≤ ~112 KB worst case.
    // Pre-connect bytes are bounded by the TUN receive window (nothing is acknowledged to lwIP until the relay took
    // the bytes, nc_tcp_recved), `pendingCap` (2 × TCP_WND) is the hard stop (RST). `bufferedTotal` (all outboxes +
    // pending) is held under NCBufferBudget (4 MB normal … 256 KB critical, memory-governor tied): over budget,
    // every connection that has anything queued pauses its relay read until it drained.
    static let outboxCap = 48 << 10
    static let outboxResume = 16 << 10
    static let pendingCap = 48 << 10
    private var bufferedTotal = 0
    private var budget = NCBufferBudget.normal

    final class TCPSession {
        let conn: NCTunStack.TCPConn
        var target: NCTarget        // dial target (domain after deref/sniff, else the IP)
        var ruleDomain: String?     // domain fed to rule matching, when known
        var protocolHint: String?   // rv2-rules: sniffed "tls" / "quic" / "http" (PROTOCOL rules)
        var pending = Data()        // client bytes buffered before the relay is up
        // rv2-life: relay bytes waiting for the stack's send window, as received chunks + a read offset into the
        // first one (was one Data with removeFirst per write: a memmove of the whole outbox every time).
        var outQ: [Data] = []
        var outHead = 0
        var outBytes = 0
        var pendingCounted = 0      // pending bytes counted in bufferedTotal
        var pendingAck = 0          // pending bytes handed to the relay, tcp_recved only on its send completion
        var unacked = 0             // bytes received from lwIP not yet acknowledged (nc_tcp_recved)
        var started = false         // receiveLoop ran once (pending was handed to the relay)
        var readPaused = false      // relay read stopped by back-pressure
        var closeAfterDrain: Date?  // relay EOF: close once the outbox reached the app
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
        stack.onTCPSent = { [weak self] conn in self?.tcpSent(conn) }
        stack.onUDPClosed = { [weak self] id in self?.udpGone(id) }
        // The v6 address mirrors PacketTunnelProvider's NEIPv6Settings so
        // fake-IP v6 destinations terminate in the stack like v4 ones.
        guard stack.start(ip4: "198.18.0.1", ip6: "fdfe:dcba:9876::1", mtu: mtu) else {
            throw NCDataPlaneError.stackStartFailed
        }
        isRunning = true
        readLoop()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + Self.fastTick, repeating: Self.fastTick, leeway: .milliseconds(25))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        tickFast = true
        idleTicks = 0
    }

    // Power (feat/native-core-eval merge, 2026-10-25): the 250 ms lwIP tick only matters while relays exist. With no
    // TCP / UDP session for 2 s it drops to one wake every 5 s (lwIP timers tolerate late ticks: TIME-WAIT / UDP idle
    // just expire later); any packet from the TUN or a new session restores 250 ms at once. Proxy-only mode (data
    // plane idle) and an idle tunnel no longer wake the extension 4×/s.
    private static let fastTick: DispatchTimeInterval = .milliseconds(250)
    private static let slowTick: DispatchTimeInterval = .seconds(5)
    private var tickFast = true
    private var idleTicks = 0

    private func setTickFast(_ fast: Bool) {
        guard fast != tickFast, let timer else { return }
        tickFast = fast
        idleTicks = 0
        let interval = fast ? Self.fastTick : Self.slowTick
        timer.schedule(deadline: .now() + interval, repeating: interval,
                       leeway: fast ? .milliseconds(25) : .seconds(1))
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
            bufferedTotal = 0
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
                // rv2-life: a stopped plane stops reading (a restarted core's new plane owns the flow now)
                guard self.isRunning else { return }
                if !self.tickFast { self.setTickFast(true) }
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
        if tickCount % 4 == 0 {
            refreshStats()
            budget = NCBufferBudget.current()
        }
        let now = Date()
        for s in sessions.values {
            if s.state == .deciding, now.timeIntervalSince(s.acceptedAt) > 1.5 {
                connect(s) // server-first protocol or silent client: go by IP
            }
            if s.state == .open {
                // rv2-life: an app that stopped reading never lets a finished relay's tail drain: give up after 30 s
                if let eof = s.closeAfterDrain, now.timeIntervalSince(eof) > 30 { close(s) } else { drain(s) }
            }
        }
        // The C stack expires idle UDP sessions (120 s, both directions) and tells us (onUDPClosed); this sweep is
        // only a safety net, and closes the C side too so both tables stay in step.
        for (id, entry) in udpSessions where now.timeIntervalSince(entry.lastUsed) > 130 {
            entry.session.cancel()
            udpSessions.removeValue(forKey: id)
            stack.udpClose(session: id)
        }
        if sessions.isEmpty && udpSessions.isEmpty {
            idleTicks += 1
            if tickFast && idleTicks >= 8 { setTickFast(false) }
        } else {
            idleTicks = 0
            if !tickFast { setTickFast(true) }
        }
    }

    // MARK: TCP

    private func accept(_ conn: NCTunStack.TCPConn) -> Bool {
        let derefed = engine.derefFakeIP(conn.dst)
        let fakeDomain = derefed.host != conn.dst.host ? derefed.host : nil
        let s = TCPSession(conn: conn, target: derefed, ruleDomain: fakeDomain)
        sessions[s.key] = s
        let sniff = engine.snifferConfig
        if !sniff.enable {
            connect(s) // sniffer off (config / user toggle): no first-packet inspection
        } else if let fakeDomain {
            // Destination known from DNS: no sniffing needed — unless a
            // force-domain entry demands a look at the real SNI anyway and
            // skip-domain doesn't veto it (mihomo force-domain / skip-domain).
            if !(sniff.matchesForceDomain(fakeDomain) && !sniff.matchesSkipDomain(fakeDomain)) {
                connect(s)
            }
        } else if !sniff.parsePureIP {
            connect(s) // pure-IP destination and parse-pure-ip off: mihomo doesn't sniff
        }
        return true
    }

    private func tcpData(_ conn: NCTunStack.TCPConn, _ data: Data?) {
        guard let s = sessions[UInt(bitPattern: conn.handle)] else { return }
        guard let data else {
            close(s) // client FIN
            return
        }
        // rv2-life: received bytes are acknowledged to lwIP (window reopened toward the app) only once the relay
        // took them — the upstream back-pressure. Until then they count in `unacked`.
        s.unacked += data.count
        switch s.state {
        case .deciding, .connecting:
            // Bounded by the receive window already (nothing is acknowledged before the relay is up); the cap is the
            // hard stop for anything beyond it.
            guard s.pending.count + data.count <= Self.pendingCap else {
                reset(s)
                return
            }
            s.pending.append(data)
            s.pendingCounted += data.count
            bufferedTotal += data.count
            if s.state == .deciding { decide(s) }
        case .open:
            countUp(s, data.count)
            guard let relay = s.relay else { return }
            let n = data.count
            NCRelayFlow.send(relay, data, queue: queue) { [weak self, weak s] in
                guard let self, let s, s.state != .closed else { return }
                s.unacked -= n
                self.stack.tcpRecved(s.conn, n)
            }
        case .closed:
            break
        }
    }

    private func tcpError(_ conn: NCTunStack.TCPConn) {
        guard let s = sessions.removeValue(forKey: UInt(bitPattern: conn.handle)) else { return }
        s.state = .closed
        releaseBuffers(s)
        s.relay?.cancel()
    }

    /// rv2-life: the app ACKed data (lwIP send window opened): push more of the outbox, maybe resume the relay read.
    private func tcpSent(_ conn: NCTunStack.TCPConn) {
        guard let s = sessions[UInt(bitPattern: conn.handle)], s.state == .open else { return }
        drain(s)
    }

    /// Learn the real domain from the first bytes (TLS SNI / HTTP Host) when the
    /// app dialed a bare IP; otherwise keep the IP as the target.
    private func decide(_ s: TCPSession) {
        let sniff = engine.snifferConfig
        guard sniff.enable, !sniff.matchesSkipDomain(s.ruleDomain) else { connect(s); return }
        switch NCSniffer.detect(s.pending) {
        case .tls(let sni, let alpn):
            // The QUIC branch of NCSniffer.detect reports alpn ["h3"]; its
            // port gate is the QUIC table, plain TLS uses the TLS table.
            let isQUIC = alpn == ["h3"]
            s.protocolHint = isQUIC ? "quic" : "tls"
            guard isQUIC ? sniff.sniffQUIC(port: s.target.port) : sniff.sniffTLS(port: s.target.port) else {
                connect(s)
                return
            }
            if let sni {
                s.ruleDomain = sni
                if sniff.overridesDestination(proto: isQUIC ? "quic" : "tls") {
                    s.target = NCTarget(host: sni, port: s.target.port)
                }
            }
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
            s.protocolHint = "http"
            guard sniff.sniffHTTP(port: s.target.port) else { connect(s); return }
            if let host {
                s.ruleDomain = host
                if sniff.overridesDestination(proto: "http") {
                    s.target = NCTarget(host: host, port: s.target.port)
                }
            }
            connect(s)
        case .unknown:
            connect(s)
        }
    }

    private func connect(_ s: TCPSession) {
        guard s.state == .deciding else { return }
        s.state = .connecting
        // rv2-rules: a fake-IP destination is never matched or dialed as an
        // IP. Unmapped (pool lost) → the sniffed domain if any, else drop
        // (mihomo rejects "fake DNS record missing").
        if let ip = s.target.ip, engine.isFakeAddress(ip) {
            guard let d = s.ruleDomain else { close(s); return }
            s.target = NCTarget(host: d, port: s.target.port)
        }
        var ctx = engine.matchContext(domain: s.ruleDomain,
                                      ip: s.target.ip,
                                      dstPort: s.target.port,
                                      network: "tcp")
        ctx.protocolHint = s.protocolHint
        // One match per connection (load-balance advances once); IP rules
        // resolve the domain asynchronously when needed (mihomo semantics).
        engine.routeAsync(ctx, queue: queue) { [weak self, weak s] policyName, ruleText, resolution in
            guard let self, let s, s.state == .connecting else { return }
            self.dial(s, policyName: policyName, ruleText: ruleText, resolution: resolution)
        }
    }

    private func dial(_ s: TCPSession, policyName: String, ruleText: String?, resolution: NCGroupEngine.Resolution) {
        s.policyName = policyName
        s.ruleText = ruleText ?? ""
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
                let p = s.pending
                s.pending = Data()
                s.pendingAck = p.count
                // nc-sessions-flow: pre-connect bytes get the same treatment as the open path — they are
                // tcp_recved only once the relay's send completion fires for them.
                NCRelayFlow.send(relay, p, queue: queue) { [weak self, weak s] in
                    guard let self, let s, s.state != .closed, s.pendingAck > 0 else { return }
                    let n = s.pendingAck
                    s.pendingAck = 0
                    s.unacked -= n
                    self.stack.tcpRecved(s.conn, n)
                }
            }
            self.receiveLoop(s)
        }
    }

    private func receiveLoop(_ s: TCPSession) {
        if !s.started {
            // First call, right after connect / the MitM front handed the pre-connect bytes to the relay: they no
            // longer count against the budget, and the app's window reopens for them.
            s.started = true
            bufferedTotal -= s.pendingCounted
            s.pendingCounted = 0
            // Bytes still waiting on a relay send completion (pendingAck) stay unacked here; the
            // completion path in the connect callback recved's them when it fires.
            let ackable = s.unacked - s.pendingAck
            if ackable > 0 {
                stack.tcpRecved(s.conn, ackable)
                s.unacked -= ackable
            }
        }
        s.relay?.receive { [weak self, weak s] data, error in
            guard let self, let s, s.state == .open else { return }
            if let data, !data.isEmpty {
                countDown(s, data.count)
                s.outQ.append(data)
                s.outBytes += data.count
                self.bufferedTotal += data.count
                self.drain(s)
                guard s.state == .open, s.closeAfterDrain == nil else { return }
                // rv2-life (#10): stop reading the relay while the app is not taking what we have; drain() resumes.
                if s.outBytes >= Self.outboxCap || (self.bufferedTotal >= self.budget && s.outBytes > 0) {
                    s.readPaused = true
                } else {
                    self.receiveLoop(s)
                }
            } else if error == nil, s.outBytes > 0 {
                // clean EOF: deliver the queued tail first (it used to be dropped by an immediate close)
                s.closeAfterDrain = Date()
            } else {
                self.close(s) // clean EOF with nothing queued, or a relay error
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

    /// The local mixed proxy (gap D1), whose connections the controller lists and closes next to the TUN ones.
    /// Set once before the controller starts.
    weak var localProxy: NCLocalProxy?

    /// Controller entry points (safe from any queue).
    func requestCloseConnection(id: String) {
        if NCLocalProxy.ownsConnectionID(id) {
            localProxy?.closeConnection(id: id)
            return
        }
        queue.async { [weak self] in
            guard let self, let key = UInt(id),
                  let s = sessions[key] else { return }
            close(s)
        }
    }

    func requestCloseAllConnections() {
        localProxy?.closeAllConnections()
        queue.async { [weak self] in
            guard let self else { return }
            for s in Array(sessions.values) { close(s) }
        }
    }

    private func drain(_ s: TCPSession) {
        while let head = s.outQ.first {
            let chunk = s.outHead == 0 ? head : head[(head.startIndex + s.outHead)...]
            let written = stack.tcpWrite(s.conn, chunk)
            if written < 0 {
                close(s)
                return
            }
            if written == 0 { break } // send window / lwIP heap full: tcp_sent or the tick retries
            s.outBytes -= written
            bufferedTotal -= written
            if written >= chunk.count {
                s.outQ.removeFirst()
                s.outHead = 0
            } else {
                s.outHead += written
                break
            }
        }
        guard s.state == .open else { return }
        if s.closeAfterDrain != nil {
            if s.outBytes == 0 { close(s) }
            return
        }
        if s.readPaused, s.outBytes <= Self.outboxResume, bufferedTotal < budget || s.outBytes == 0 {
            s.readPaused = false
            receiveLoop(s)
        }
    }

    /// rv2-life: drops what a closing session still buffers from the budget.
    private func releaseBuffers(_ s: TCPSession) {
        bufferedTotal -= s.outBytes + s.pendingCounted
        s.outQ = []
        s.outHead = 0
        s.outBytes = 0
        s.pendingCounted = 0
        s.pending = Data()
    }

    private func close(_ s: TCPSession) {
        guard s.state != .closed else { return }
        s.state = .closed
        sessions.removeValue(forKey: s.key)
        releaseBuffers(s)
        s.relay?.cancel()
        // rv2-life: lwIP answers tcp_close with a RST while received data is unacknowledged (which would also drop
        // what is still queued toward the app): acknowledge it all first so a normal close stays a FIN.
        if s.unacked > 0 {
            stack.tcpRecved(s.conn, s.unacked)
            s.unacked = 0
        }
        stack.tcpClose(s.conn)
    }

    /// rv2-life: overflow (pre-connect cap): RST toward the app and drop the relay.
    private func reset(_ s: TCPSession) {
        guard s.state != .closed else { return }
        s.state = .closed
        sessions.removeValue(forKey: s.key)
        releaseBuffers(s)
        s.relay?.cancel()
        stack.tcpAbort(s.conn)
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
            // the query to its assigned upstream (per-domain policy first),
            // with mihomo's fallback / fallback-filter detour when configured.
            let route = engine.dnsRoute(for: data)
            guard let primary = route.primary else {
                udpDropped += 1
                return
            }
            forwardDNS(data, session: info.id, primary: primary,
                       fallback: route.fallback, fallbackFirst: route.fallbackFirst)
            return
        }
        udpForward(info, data)
    }

    /// Forward one DNS query honoring the fallback route: fallback-first
    /// names go straight to the fallback server; otherwise the primary
    /// answers unless it fails or its answer trips fallback-filter, in
    /// which case the fallback is asked (if the fallback also fails, the
    /// primary's answer is delivered rather than failing the query).
    private func forwardDNS(_ query: Data, session: UInt32, primary: NCDNSUpstream,
                            fallback: NCDNSUpstream?, fallbackFirst: Bool) {
        let deliver: (Data) -> Void = { [weak self] resp in
            self?.engine.recordDNSResponse(query: query, response: resp)
            self?.stack.udpSend(session: session, resp)
        }
        if fallbackFirst, let fallback {
            dnsForwarder.forward(query, upstream: fallback) { [weak self] resp in
                guard let self else { return }
                if let resp { deliver(resp); return }
                self.dnsForwarder.forward(query, upstream: primary) { resp2 in
                    if let resp2 { deliver(resp2) }
                }
            }
            return
        }
        dnsForwarder.forward(query, upstream: primary) { [weak self] resp in
            guard let self else { return }
            if let resp, !self.engine.dnsAnswerTriggersFallback(resp) { deliver(resp); return }
            guard let fallback else {
                if let resp { deliver(resp) }
                return
            }
            self.dnsForwarder.forward(query, upstream: fallback) { resp2 in
                if let resp2 { deliver(resp2) }
                else if let resp { deliver(resp) }
            }
        }
    }

    /// rv2-life: the C side ended this session (idle / evicted) or a reply found it gone: drop the relay.
    private func udpGone(_ id: UInt32) {
        udpPending.removeValue(forKey: id)
        guard let e = udpSessions.removeValue(forKey: id) else { return }
        e.session.cancel()
    }
    /// rv2-rules: first packets of a UDP flow whose rule match is waiting on
    /// a resolve (bounded per flow).
    private var udpPending: [UInt32: [Data]] = [:]

    private func udpForward(_ info: NCTunStack.UDPSessionInfo, _ data: Data) {
        if let entry = udpSessions[info.id] {
            entry.lastUsed = Date()
            entry.session.send(data, to: engine.derefFakeIP(info.dst))
            return
        }
        if udpPending[info.id] != nil {
            if udpPending[info.id]!.count < 16 { udpPending[info.id]!.append(data) } else { udpDropped += 1 }
            return
        }
        let target = engine.derefFakeIP(info.dst)
        let restored = target.host != info.dst.host
        // QUIC to a MitM host is dropped so the client falls back to TCP, where the native MitM front sees it
        // (bridge/mitm Inject's UDP REJECT rule on the Go path).
        if info.dst.port == 443, target.host != info.dst.host, engine.isMitm(host: target.host, port: 443) {
            udpDropped += 1
            return
        }
        // rv2-rules: match on the restored domain, never on the fake IP;
        // an unmapped fake destination is dropped.
        if !restored, let ip = info.dst.ip, engine.isFakeAddress(ip) {
            udpDropped += 1
            return
        }
        var ctx = engine.matchContext(domain: restored ? target.host : nil,
                                      ip: restored ? nil : info.dst.ip,
                                      dstPort: info.dst.port,
                                      network: "udp")
        if info.dst.port == 443 { ctx.protocolHint = "quic" }
        udpPending[info.id] = [data]
        engine.routeAsync(ctx, queue: queue) { [weak self] _, _, resolution in
            guard let self, let queued = self.udpPending.removeValue(forKey: info.id), self.isRunning else { return }
            self.openUDP(info, target: target, resolution: resolution, packets: queued)
        }
    }

    private func openUDP(_ info: NCTunStack.UDPSessionInfo, target: NCTarget,
                         resolution: NCGroupEngine.Resolution, packets: [Data]) {
        let session: NCUDPSession
        switch resolution {
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
        case .proxy(let proxy) where proxy.type == "tuic":
            // feat/nc-proto2: native (QUIC datagram) / quic (uni stream) relay over the shared TUIC connection.
            session = NCUDPTUICSession(proxy: proxy, queue: queue)
        case .proxy(let proxy) where proxy.type == "hysteria":
            // feat/nc-proto2: Hysteria v1 UDP over the shared session (datagrams, obfs / port hopping honoured).
            session = NCUDPHysteria1Session(proxy: proxy, queue: queue)
        case .proxy(let proxy) where proxy.type == "mieru":
            session = NCUDPMieruSession(proxy: proxy, target: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "anytls":
            session = NCUDPAnyTLSSession(proxy: proxy, target: target, queue: queue)
        case .proxy(let proxy) where proxy.type == "wireguard":
            // feat/nc-wg: UDP from the node's lwIP netif (NCUDPWireGuardSession).
            session = NCUDPWireGuardSession(proxy: proxy, queue: queue)
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
        let entry = UDPSessionEntry(session: session, lastUsed: Date())
        session.onReply = { [weak self, weak entry] payload in
            guard let self else { return }
            entry?.lastUsed = Date()
            // rv2-life: the C session is gone (evicted / expired before we heard): stop the relay instead of
            // silently dropping every further reply
            if !self.stack.udpSend(session: sid, payload) { self.udpGone(sid) }
        }
        udpSessions[info.id] = entry
        for p in packets { session.send(p, to: target) }
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

    /// Gap D1: the local mixed proxy's mirror (its own queue writes it); snapshot() reports TUN + proxy.
    private var local: (connections: [[String: Any]], up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) = ([], 0, 0, 0, 0)

    func updateLocal(connections: [[String: Any]], up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) {
        lock.lock()
        local = (connections, up, down, proxyUp, proxyDown)
        lock.unlock()
    }

    func snapshot() -> (connections: [[String: Any]], up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64) {
        lock.lock()
        defer { lock.unlock() }
        if local.connections.isEmpty && local.up == 0 && local.down == 0 {
            return (connections, up, down, proxyUp, proxyDown)
        }
        return (connections + local.connections, up + local.up, down + local.down,
                proxyUp + local.proxyUp, proxyDown + local.proxyDown)
    }
}
