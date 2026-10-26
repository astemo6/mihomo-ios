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
    // fix/nc-start-empty: strong (was weak) — the plane must never lose the flow it reads from; stop() drops it.
    private var flow: NEPacketTunnelFlow?
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
    // fix/nc-start-empty: what the plane saw, for 诊断 (startup log +15 s / +60 s). Written on `queue`; read racily
    // for the log line only, like `sessions.count` in statsLine.
    private var packetsIn = 0
    private var tcpAccepted = 0
    private var dnsQueries = 0
    private var dnsNoUpstream = 0
    private var dnsForwardFailed = 0
    private var loggedNoUpstream = false
    private var loggedFirstPacket = false
    private var loggedReadArmed = false
    private var loggedFirstPacketCallback = false
    // fix/nc-tcp0: the first packets each way, one line each in the startup log (诊断), so a device report proves
    // what iOS routes into the tunnel and what the core answers (with checksum verdicts). Counters on `queue`.
    static let traceInLimit = 40
    static let traceOutLimit = 24
    private var tracedIn = 0
    private var tracedOut = 0
    private var packetsOut = 0
    private var dnsServfail = 0
    // fix/nc-ctrl-bsd: per-connection outcome counters (+15 / +60 s statsLine) and the rate-limited
    // per-connection lines in NativeLogRing (→ /logs, 诊断包 core-log.txt). On `queue`; read racily for the log line.
    private var relayOK = 0
    private var relayDirect = 0
    private var relayFailed = 0
    private var relayRejected = 0
    private var udpOpened = 0
    static let connLogPerSecond = NCDiagLimiter.perSecond
    // fix/nc-mitm-live: MitM handoff health / counters (statsLine) and the periodic fake-ip flush.
    private var mitmDecrypted = 0
    private var mitmPassthrough = 0
    private var mitmFallbacks = 0
    private var mitmFrontFailStreak = 0
    private var mitmFrontDown = false
    private var fakeUnmappedReset = 0
    private var lastFakeIPPersist = Date()
    /// Wait for the front's first bytes (ServerHello) before falling back to a plain relay.
    static let mitmFrontTimeout: TimeInterval = 4
    /// Bytes kept for a fallback replay while the front has not answered yet.
    static let mitmReplayCap = 32 << 10

    /// One line per session outcome into the log ring, at most `connLogPerSecond` a second (the rest are counted
    /// and reported as one "suppressed" line) — the ring keeps 400 lines, so memory stays flat.
    /// fix/nc-mitm-live: through the shared NCDiagLimiter ([TCP] / [UDP] / [MITM] / [REWRITE] / [SCRIPT] together ≤ 20/s).
    private func connLog(_ line: String, level: String = "info") {
        NCDiagLimiter.shared.line(line, level: level)
    }

    private static func short(_ e: Error?) -> String {
        guard let e else { return "no relay" }
        let ns = e as NSError
        let text = "\(ns.localizedDescription) (\(ns.domain) \(ns.code))"
        return text.count > 160 ? String(text.prefix(160)) + "…" : text
    }

    private static func outcomeHead(_ s: TCPSession) -> String {
        let rule = s.ruleText.isEmpty ? "-" : s.ruleText
        let via = s.chainName == s.policyName || s.policyName.isEmpty ? s.chainName : "\(s.policyName) (\(s.chainName))"
        return "[TCP] \(s.target.host):\(s.target.port) rule \(rule) → \(via)"
    }

    /// "v4 tcp 198.18.0.1 → 17.x.x.x" for the first-packet log line (addresses are the device's own flows).
    static func describe(_ p: Data) -> String {
        guard let b = p.first else { return "empty" }
        let v = b >> 4
        if v == 4, p.count >= 20 {
            let a = [UInt8](p.prefix(20))
            let proto = a[9] == 6 ? "tcp" : a[9] == 17 ? "udp" : a[9] == 1 ? "icmp" : "proto \(a[9])"
            return "v4 \(proto) → \(a[16]).\(a[17]).\(a[18]).\(a[19]), \(p.count) B"
        }
        if v == 6, p.count >= 40 {
            let nh = p[p.startIndex + 6]
            return "v6 \(nh == 6 ? "tcp" : nh == 17 ? "udp" : nh == 58 ? "icmp6" : "nh \(nh)"), \(p.count) B"
        }
        return "version \(v), \(p.count) B"
    }
    private var loggedFirstAccept = false
    private var loggedFirstDNSReply = false
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
    /// nc-races: hard cap on live UDP relays, aligned with the C stack's NC_MAX_UDP_SESSIONS (64,
    /// nc_stack.c). The C side is the real bound — it LRU-evicts (idle DNS first) and reports the
    /// eviction via onUDPClosed, which removes the Swift entry on this same queue, so the two tables
    /// stay in step and this guard should never fire; it exists so a lost notification degrades to
    /// "new flow dropped" (the data plane's existing failure shape for unroutable UDP) instead of an
    /// unbounded Swift-side table outliving its C sessions.
    static let maxUDPSessions = 64
    private var bufferedTotal = 0
    private var budget = NCBufferBudget.normal

    final class TCPSession {
        let conn: NCTunStack.TCPConn
        var target: NCTarget        // dial target (domain after deref/sniff, else the IP)
        var ruleDomain: String?     // domain fed to rule matching, when known
        // fix/nc-tcp1: redir-host — the real destination IP the domain was mapped from (DNS answer). mihomo keeps
        // metadata.DstIP in redir-host (only fake-ip clears it), so IP rules match it without resolving the domain.
        var mappedIP: NCIP?
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
        var dialAt: DispatchTime?   // fix/nc-ctrl-bsd: connect latency for the outcome line
        // fix/nc-mitm-live
        var mitmPeek = false        // held for the ClientHello: MitM decision pending
        var unmappedFake = false    // fake-ip destination with no mapping: SNI / Host is the only way to its domain
        var mitmHost: String?       // handed to the native front for this host
        var mitmTried = false       // handoffMitm ran once (never twice per flow)
        var frontAt: Date?          // when the front stream was opened
        var frontAwaiting = false   // front opened, no byte back yet (fallback still possible)
        var frontSent = Data()      // client bytes sent to the front while awaiting (replayed on fallback)
        var frontReplayable = true  // frontSent still holds everything sent
        var replay: Data?           // bytes to resend first on the fallback relay
        var relayGen = 0            // bumped when a MitM fallback swaps the relay (stale receive callbacks ignored)
        // fix/nc-e2e-gaps: /app/stats — bytes already reported to NCStatsRecorder, and whether it counted the flow
        var statsUp: Int64 = 0
        var statsDown: Int64 = 0
        var statsOpened = false
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
            self.packetsOut &+= 1
            if self.tracedOut < Self.traceOutLimit {
                self.tracedOut += 1
                StartupLog.write("pkt out #\(self.tracedOut): \(NCPacketTrace.summary(packet, checksums: true))", mirror: false)
            }
            let family: NSNumber = (packet[0] >> 4) == 6 ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
            flow.writePackets([packet], withProtocols: [family])
        }
        stack.onTCPAccept = { [weak self] conn in self?.accept(conn) ?? false }
        stack.onTCPData = { [weak self] conn, data in self?.tcpData(conn, data) }
        stack.onTCPError = { [weak self] conn in self?.tcpError(conn) }
        stack.onUDP = { [weak self] info, data in self?.udp(info, data) }
        stack.onTCPSent = { [weak self] conn in self?.tcpSent(conn) }
        stack.onUDPClosed = { [weak self] id in self?.udpGone(id) }
        // fix/nc-mitm-live: a client that refuses our leaf shows up in 诊断 (was silent: only the pinning memory knew).
        MitmTLSFront.shared.reportHandshakeFailure = { host, kind in
            let pin = kind == "cert" || kind == "closed"
            if pin { NCPinningMemory.shared.markPinned(host) }
            let hint = kind == "cert" ? " — the client does not trust the Tern CA (install it and enable full trust: 设置 → 通用 → 关于本机 → 证书信任设置), or it pins its certificate" : ""
            NCDiagLimiter.shared.line("[MITM] \(host) → passthrough(client TLS handshake failed: \(kind)\(hint))\(pin ? "; next connections to it pass through" : "")", level: "warning")
        }
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
            udpPending.removeAll()
            bufferedTotal = 0
            // nc-lifecycle: WireGuard devices hold their own timers and peer
            // connections into the lwIP stack — tear them down (this queue
            // IS NCLwIP.queue) before the stack itself stops, or they keep
            // believing `alive` with device ids the next stack never had.
            NCWGStack.shared.teardownAll()
            stack.stop()
            isRunning = false
        }
        flow = nil
    }

    var statsLine: String {
        "native: packets in \(packetsIn), out \(packetsOut), tcp accepted \(tcpAccepted), sessions \(sessions.count), dns queries \(dnsQueries), dns replies \(dnsReplies), dns no-upstream \(dnsNoUpstream), dns failed \(dnsForwardFailed), udp dropped \(udpDropped), relay ok \(relayOK), direct \(relayDirect), relay failed \(relayFailed), rejected \(relayRejected), udp opened \(udpOpened), mitm decrypted \(mitmDecrypted), mitm passthrough \(mitmPassthrough), mitm fallback \(mitmFallbacks)\(mitmFrontDown ? " (front DOWN)" : ""), fake-ip unmapped reset \(fakeUnmappedReset), dns servfail \(dnsServfail); \(stack.cStatsLine)"
    }

    // MARK: Packet flow

    private func readLoop() {
        guard let flow else {
            StartupLog.write("data plane: no packet flow — readPackets NOT armed")
            return
        }
        if !loggedReadArmed {
            loggedReadArmed = true
            StartupLog.write("data plane: readPackets armed (mtu \(mtu))")
        }
        flow.readPackets { [weak self] packets, _ in
            guard let self else {
                StartupLog.write("data plane: packets arrived after the plane was released — dropped, reading stops")
                return
            }
            if !self.loggedFirstPacketCallback {
                self.loggedFirstPacketCallback = true
                StartupLog.write("data plane: first readPackets callback (\(packets.count) packet(s), \(packets.first?.count ?? 0) bytes) — hopping to the lwIP queue")
            }
            self.queue.async {
                // rv2-life: a stopped plane stops reading (a restarted core's new plane owns the flow now)
                guard self.isRunning else { return }
                if !self.tickFast { self.setTickFast(true) }
                self.packetsIn &+= packets.count
                if !self.loggedFirstPacket {
                    self.loggedFirstPacket = true
                    StartupLog.write("data plane: first packet processed on the lwIP queue (\(Self.describe(packets.first ?? Data())))")
                }
                for p in packets {
                    if self.tracedIn < Self.traceInLimit {
                        self.tracedIn += 1
                        StartupLog.write("pkt in #\(self.tracedIn): \(NCPacketTrace.summary(p))", mirror: false)
                    }
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
    private var memSampleTick = 0
    private static let isoFormatter = ISO8601DateFormatter()

    private func tick() {
        stack.poll()
        // The controller mirror is rebuilt once a second (was every 250 ms tick: a dictionary per connection +
        // a new date formatter each time).
        tickCount &+= 1
        if tickCount % 4 == 0 {
            refreshStats()
            budget = NCBufferBudget.current()
            // nc-lifecycle: footprint on the stats cadence, thinned to every
            // 60th refresh (~60 s on the fast tick, ~20 min idle) — a trend
            // line for jetsam headroom, never per packet.
            memSampleTick &+= 1
            if memSampleTick % 60 == 0 { NCMemorySampler.sample("tick") }
        }
        let now = Date()
        for s in sessions.values {
            if s.state == .deciding, now.timeIntervalSince(s.acceptedAt) > 1.5 {
                connect(s) // server-first protocol or silent client: go by IP
            }
            if s.state == .open, s.frontAwaiting, let at = s.frontAt, now.timeIntervalSince(at) > Self.mitmFrontTimeout {
                mitmFallback(s, reason: "no TLS answer from the front in \(Int(Self.mitmFrontTimeout)) s (loopback listener not accepting?)")
                continue
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
        if now.timeIntervalSince(lastFakeIPPersist) >= 60 {
            lastFakeIPPersist = now
            let e = engine
            DispatchQueue.global(qos: .utility).async { e.persistFakeIPIfChanged() }
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
        if fakeDomain != nil { s.mappedIP = realDstIP(conn.dst.ip) }
        sessions[s.key] = s
        tcpAccepted &+= 1
        if !loggedFirstAccept {
            loggedFirstAccept = true
            StartupLog.write("data plane: first TCP flow accepted (port \(conn.dst.port), \(fakeDomain != nil ? "fake-ip domain" : "ip"))")
        }
        // fix/nc-mitm-live: an unmapped fake-ip destination cannot be dialed; its first bytes (SNI / Host) are the only
        // way to the domain, whatever the sniffer config says — held for decide(), RST if nothing turns up.
        if fakeDomain == nil, let ip = conn.dst.ip, engine.isFakeAddress(ip) { s.unmappedFake = true }
        // fix/nc-mitm-live: the MitM decision no longer depends on the sniffer path (it used to run only for bare-IP
        // flows with parse-pure-ip on, so flows with a known domain — fake-ip or redir-host — never reached the front).
        if !mitmFrontDown {
            let engine = self.engine
            s.mitmPeek = NCMitmGate.shouldPeek(knownDomain: fakeDomain, port: conn.dst.port, mitmActive: engine.mitmActive,
                                               mitmPorts: engine.mitmPorts,
                                               isMitm: { engine.isMitm(host: $0, port: $1) })
        }
        if s.mitmPeek || s.unmappedFake { return true } // decide() runs on the first bytes; the tick bounds the wait
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

    /// fix/nc-tcp1: the packet's destination when it is a real address (redir-host), nil for a fake-ip one. Before,
    /// a redir-host flow was matched by its domain only, so the first IP rule (here RULE-SET 国内网站 = IP-ASN list,
    /// then GEOIP,cn) re-resolved the domain through the upstreams; when that lookup failed every IP rule missed
    /// and Chinese sites fell through to MATCH (proxy) — build433 self-check: www.baidu.com → MATCH, "direct 1".
    private func realDstIP(_ ip: NCIP?) -> NCIP? {
        guard let ip, !engine.isFakeAddress(ip) else { return nil }
        return ip
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
            if s.frontAwaiting, s.frontReplayable {
                if s.frontSent.count + data.count <= Self.mitmReplayCap { s.frontSent.append(data) } else { s.frontReplayable = false; s.frontSent = Data() }
            }
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
        logClose(s, "reset by the app side")
        recordClosed(s)
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
        if s.mitmPeek {
            let engine = self.engine
            let verdict = NCMitmGate.decide(firstBytes: s.pending, knownDomain: s.ruleDomain,
                                            dstIP: s.conn.dst.ip != nil ? s.conn.dst.host : nil, port: s.target.port,
                                            isMitm: { engine.isMitm(host: $0, port: $1) })
            switch verdict {
            case .needMore:
                return // the next segment calls decide() again; the tick connects after 1.5 s
            case .mitm(let host, let alpn):
                s.mitmPeek = false
                s.protocolHint = "tls"
                if s.ruleDomain == nil { s.ruleDomain = host }
                if handoffMitm(s, host: host, alpn: alpn) { return }
            case .passthrough(let reason):
                s.mitmPeek = false
                // Only flows whose known domain is a MitM host are MitM flows; a bare-IP peek that is not one is quiet.
                if let d = s.ruleDomain, engine.isMitm(host: d, port: s.target.port) {
                    mitmPassthrough &+= 1
                    connLog("[MITM] \(d):\(s.target.port) → passthrough(\(reason))", level: "warning")
                }
                if case .tls(let sni, _) = NCSniffer.detect(s.pending), let sni, !sni.isEmpty, s.ruleDomain == nil || s.unmappedFake {
                    s.ruleDomain = sni.lowercased()
                }
            }
        }
        if s.unmappedFake && s.ruleDomain == nil {
            // first TLS record split over segments: wait for the rest (bounded by the tick / pending cap)
            if s.pending.first == 0x16, !NCMitmGate.helloComplete(s.pending), s.pending.count < NCMitmGate.maxHelloBytes { return }
            switch NCSniffer.detect(s.pending) {
            case .tls(let sni, let alpn):
                s.protocolHint = alpn == ["h3"] ? "quic" : "tls"
                if let sni, !sni.isEmpty { s.ruleDomain = sni.lowercased() }
            case .http(let host, _):
                s.protocolHint = "http"
                if let host, !host.isEmpty { s.ruleDomain = host.lowercased() }
            case .unknown:
                break
            }
            connect(s) // no domain → connect() resets the flow
            return
        }
        // fix/nc-e2e-gaps: plain HTTP on port 80 to a host with rewrite work → the rewrite engine (no TLS), whatever
        // the sniffer settings say (the request line + Host are in the first segment).
        if s.target.port == 80, !s.mitmTried, !mitmFrontDown, case .http(let host, _) = NCSniffer.detect(s.pending),
           let h = (host ?? s.ruleDomain).map({ $0.lowercased() }), !h.isEmpty,
           NativeRewriteEngine.shared.wantsPlainHTTP(host: h), handoffPlain(s, host: h) {
            return
        }
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
            if let sni, !s.mitmTried, !mitmFrontDown, engine.mitmActive, engine.isMitm(host: sni, port: s.target.port),
               handoffMitm(s, host: sni.lowercased(), alpn: alpn) {
                return
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

    // MARK: MitM handoff (fix/nc-mitm-live)

    /// Hands the flow to the native MitM front (loopback TLS listener presenting the leaf for `host`). false = the
    /// front declined (pinned host, session cap, no CA / leaf, listener failed): the caller relays normally.
    private func handoffMitm(_ s: TCPSession, host: String, alpn: [String]) -> Bool {
        guard !s.mitmTried else { return false }
        s.mitmTried = true
        let mitmPort = MitmTLSFront.shared.listen(host: host, alpn: alpn.joined(separator: ","))
        guard mitmPort > 0 else {
            mitmPassthrough &+= 1
            let why = NCPinningMemory.shared.isPinned(host)
                ? "pinned: the client rejected the Tern certificate earlier"
                : (MitmTLSFront.shared.onAccept == nil ? "native front not installed" : "front declined: session cap / no CA leaf / listener")
            connLog("[MITM] \(host):\(s.target.port) → passthrough(\(why))", level: "warning")
            return false
        }
        s.state = .connecting
        s.policyName = "MITM"
        s.chainName = "MITM"
        s.ruleText = "MITM"
        recordOpened(s)
        s.mitmHost = host
        s.frontAt = Date()
        let stream = NCStream(to: "127.0.0.1", port: Int(mitmPort), queue: queue)
        stream.start { [weak self, weak s] err in
            guard let self, let s, s.state == .connecting, s.mitmHost != nil else {
                stream.cancel()
                return
            }
            if let err {
                stream.cancel()
                self.mitmFallback(s, reason: "front unreachable: \(Self.short(err))")
                return
            }
            s.relay = stream
            s.state = .open
            s.frontAwaiting = true
            s.frontAt = Date()
            if !s.pending.isEmpty {
                self.countUp(s, s.pending.count)
                s.frontSent = s.pending
                stream.send(s.pending)
                s.pending = Data()
            }
            self.receiveLoop(s)
        }
        return true
    }

    /// fix/nc-e2e-gaps: hands a port-80 HTTP flow to the plain-HTTP front (MitmPlainFront → NativeMitmSession with
    /// tls false: rewrite / reject / scripts, then the origin over plain TCP). false = declined (no session slot,
    /// MitM runtime off): the caller relays normally. A front that cannot be reached falls back to a plain relay
    /// (nothing was sent yet, so the client's bytes are still all in `pending`).
    private func handoffPlain(_ s: TCPSession, host: String) -> Bool {
        s.mitmTried = true
        let port = MitmPlainFront.shared.admit()
        guard port > 0 else { return false }
        s.state = .connecting
        s.protocolHint = "http"
        if s.ruleDomain == nil { s.ruleDomain = host }
        s.policyName = "MITM"
        s.chainName = "MITM"
        s.ruleText = "MITM"
        recordOpened(s)
        let stream = NCStream(to: "127.0.0.1", port: Int(port), queue: queue)
        stream.start { [weak self, weak s] err in
            guard let self, let s, s.state == .connecting else {
                stream.cancel()
                if err != nil { MitmPlainFront.shared.unadmit() } // connected: the front's accept claims the slot
                return
            }
            if let err {
                stream.cancel()
                MitmPlainFront.shared.unadmit()
                self.mitmFallbacks &+= 1
                self.connLog("[MITM] \(host):80 → plain relay (rewrite front unreachable: \(Self.short(err)))", level: "warning")
                s.policyName = ""
                s.chainName = ""
                s.ruleText = ""
                s.state = .deciding
                self.connect(s)
                return
            }
            self.mitmDecrypted &+= 1
            self.connLog("[MITM] \(host):80 → plain HTTP to the rewrite engine")
            s.relay = stream
            s.state = .open
            if !s.pending.isEmpty {
                self.countUp(s, s.pending.count)
                stream.send(s.pending)
                s.pending = Data()
            }
            self.receiveLoop(s)
        }
        return true
    }

    /// The front gave no byte back (timeout / EOF / error) before the TLS handshake started: nothing reached the app
    /// yet, so the flow is re-routed as a plain relay and everything the client sent is replayed. Three in a row
    /// mean the loopback front is not working in this process: MitM is bypassed for the rest of the session.
    private func mitmFallback(_ s: TCPSession, reason: String) {
        guard s.state != .closed, let host = s.mitmHost else { return }
        let replayable = s.frontReplayable
        let sent = s.frontSent
        s.relay?.cancel()
        s.relay = nil
        s.relayGen &+= 1
        s.mitmHost = nil
        s.frontAwaiting = false
        s.frontSent = Data()
        mitmFallbacks &+= 1
        mitmFrontFailStreak += 1
        connLog("[MITM] \(host):\(s.target.port) → passthrough(\(reason))", level: "warning")
        if mitmFrontFailStreak >= 3 && !mitmFrontDown {
            mitmFrontDown = true
            StartupLog.write("MITM: native front failed \(mitmFrontFailStreak)× in a row (last: \(reason)) — MitM bypassed for this session; reconnect the VPN to retry")
        }
        guard replayable else { close(s); return }
        if !sent.isEmpty { s.replay = sent }
        s.policyName = ""
        s.chainName = ""
        s.ruleText = ""
        s.state = .deciding
        connect(s)
    }

    private func connect(_ s: TCPSession) {
        guard s.state == .deciding else { return }
        s.state = .connecting
        // rv2-rules: a fake-IP destination is never matched or dialed as an
        // IP. Unmapped (pool lost) → the sniffed domain if any, else drop
        // (mihomo rejects "fake DNS record missing").
        if let ip = s.target.ip, engine.isFakeAddress(ip) {
            guard let d = s.ruleDomain else {
                // fix/nc-mitm-live: RST (was a silent FIN close) so the app fails fast and re-resolves instead of
                // retrying the stale address.
                fakeUnmappedReset &+= 1
                connLog("[TCP] \(s.target.host):\(s.target.port) reset: fake-ip without a domain mapping (no SNI / Host) — the app re-resolves", level: "warning")
                resetUnmapped(s)
                return
            }
            s.target = NCTarget(host: d, port: s.target.port)
        }
        var ctx = engine.matchContext(domain: s.ruleDomain,
                                      ip: s.target.ip ?? s.mappedIP,
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
        s.dialAt = .now()
        recordOpened(s)
        let isReject: Bool = { if case .reject = resolution { return true }; return false }()
        NCConnector.connect(target: s.target, resolution: resolution, queue: queue) { [weak self, weak s] relay, error in
            guard let self, let s, s.state == .connecting else {
                relay?.cancel()
                return
            }
            let ms = s.dialAt.map { Int((DispatchTime.now().uptimeNanoseconds &- $0.uptimeNanoseconds) / 1_000_000) } ?? -1
            guard let relay else {
                if isReject {
                    self.relayRejected &+= 1
                    self.connLog("\(Self.outcomeHead(s)) rejected")
                } else {
                    self.relayFailed &+= 1
                    self.connLog("\(Self.outcomeHead(s)) failed after \(ms) ms: \(Self.short(error))", level: "warning")
                }
                self.close(s)
                return
            }
            if s.chainName == "DIRECT" { self.relayDirect &+= 1 } else { self.relayOK &+= 1 }
            self.connLog("\(Self.outcomeHead(s)) connected in \(ms) ms")
            s.relay = relay
            s.state = .open
            if let r = s.replay {
                // fix/nc-mitm-live: MitM fallback — what the client already sent to the front (acknowledged then)
                s.replay = nil
                NCRelayFlow.send(relay, r, queue: queue) {}
            }
            if s.started, s.pendingCounted > 0 {
                // fallback after receiveLoop ran once: the pending bytes leave the budget here
                bufferedTotal -= s.pendingCounted
                s.pendingCounted = 0
            }
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
        let gen = s.relayGen
        s.relay?.receive { [weak self, weak s] data, error in
            guard let self, let s, s.state == .open, s.relayGen == gen else { return }
            if s.frontAwaiting {
                guard let data, !data.isEmpty else {
                    self.mitmFallback(s, reason: "front closed before the TLS handshake\(error.map { ": " + Self.short($0) } ?? "")")
                    return
                }
                s.frontAwaiting = false
                s.frontSent = Data()
                self.mitmDecrypted &+= 1
                self.mitmFrontFailStreak = 0
                self.connLog("[MITM] \(s.mitmHost ?? s.target.host):\(s.target.port) → decrypted")
            }
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
        // fix/nc-e2e-gaps: /app/stats — per-policy / per-host growth since the last tick, and one speed point
        // (TUN + local mixed proxy totals).
        var batch: [(policy: String, host: String, up: Int64, down: Int64)] = []
        for s in sessions.values where s.statsOpened && (s.upBytes != s.statsUp || s.downBytes != s.statsDown) {
            batch.append((Self.statsPolicy(s), Self.statsHost(s), s.upBytes - s.statsUp, s.downBytes - s.statsDown))
            s.statsUp = s.upBytes
            s.statsDown = s.downBytes
        }
        let rec = NCStatsRecorder.shared
        rec.bytesBatch(batch)
        let all = stats.snapshot()
        rec.sample(up: all.up, down: all.down, proxyUp: all.proxyUp, proxyDown: all.proxyDown)
    }

    // MARK: /app/stats (fix/nc-e2e-gaps)

    /// mihomo's chains.last: the rule's policy (group), else the dialed chain; the MitM hop is the App's
    /// engine outbound (left out of 策略 / 规则 there).
    private static func statsPolicy(_ s: TCPSession) -> String {
        if s.policyName == "MITM" { return NCStatsRecorder.engineOutbound }
        if !s.policyName.isEmpty { return s.policyName }
        return s.chainName.isEmpty ? "DIRECT" : s.chainName
    }

    /// The App's ConnectionAnalytics.hostName: host, else the destination IP.
    private static func statsHost(_ s: TCPSession) -> String {
        if let d = s.ruleDomain, !d.isEmpty { return d }
        return s.target.host
    }

    /// A flow got its rule + policy: one connection (the first time) and one rule hit.
    private func recordOpened(_ s: TCPSession) {
        NCStatsRecorder.shared.opened(rule: s.ruleText, policy: Self.statsPolicy(s), newConnection: !s.statsOpened)
        s.statsOpened = true
    }

    /// A counted flow ended: its last bytes and its closed-connection record.
    private func recordClosed(_ s: TCPSession) {
        guard s.statsOpened else { return }
        let rec = NCStatsRecorder.shared
        let policy = Self.statsPolicy(s)
        rec.bytes(policy: policy, host: Self.statsHost(s), up: s.upBytes - s.statsUp, down: s.downBytes - s.statsDown)
        s.statsUp = s.upBytes
        s.statsDown = s.downBytes
        var chains = [s.chainName.isEmpty ? "DIRECT" : s.chainName]
        if policy != chains[0] { chains.append(policy) }
        rec.closed(NCStatsRecorder.Closed(
            seq: 0, id: String(s.key), network: "tcp", srcPort: s.conn.srcPort, dstIP: s.conn.dst.host,
            dstPort: s.conn.dst.port, host: s.ruleDomain ?? "", remote: s.target.host, chains: chains,
            rule: s.ruleText, up: s.upBytes, down: s.downBytes,
            start: Int64(s.acceptedAt.timeIntervalSince1970 * 1000), closedAt: Int64(Date().timeIntervalSince1970 * 1000)))
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

    private func logClose(_ s: TCPSession, _ how: String) {
        guard s.state == .open else { return }
        let secs = Int(Date().timeIntervalSince(s.acceptedAt))
        connLog("[TCP] \(s.target.host):\(s.target.port) \(how) after \(secs) s, up \(s.upBytes) B, down \(s.downBytes) B")
    }

    private func close(_ s: TCPSession) {
        guard s.state != .closed else { return }
        logClose(s, "closed")
        recordClosed(s)
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

    /// fix/nc-mitm-live: RST toward the app (unusable destination), no outcome line.
    private func resetUnmapped(_ s: TCPSession) {
        guard s.state != .closed else { return }
        s.state = .closed
        sessions.removeValue(forKey: s.key)
        releaseBuffers(s)
        s.relay?.cancel()
        stack.tcpAbort(s.conn)
    }

    /// rv2-life: overflow (pre-connect cap): RST toward the app and drop the relay.
    private func reset(_ s: TCPSession) {
        guard s.state != .closed else { return }
        logClose(s, "aborted (buffer cap)")
        recordClosed(s)
        s.state = .closed
        sessions.removeValue(forKey: s.key)
        releaseBuffers(s)
        s.relay?.cancel()
        stack.tcpAbort(s.conn)
    }

    // MARK: UDP

    private func udp(_ info: NCTunStack.UDPSessionInfo, _ data: Data) {
        if info.dst.port == 53 {
            dnsQueries &+= 1
            if let reply = engine.dnsHostsReply(data) ?? engine.handleDNSQuery(data) {
                // nc-script-runtime: registered type=dns scripts may rewrite the finished reply before
                // it is written back (async, on the hook queue; fail-open). No dns scripts: direct send.
                if engine.hasDNSScripts {
                    engine.applyDNSScripts(query: data, reply: reply, queue: queue) { [weak self] final in
                        guard let self else { return }
                        self.dnsReplies += 1
                        self.stack.udpSend(session: info.id, final)
                    }
                } else {
                    dnsReplies += 1
                    stack.udpSend(session: info.id, reply)
                }
                return
            }
            // Not fake-IP business (filter host, other record types): forward
            // the query to its assigned upstream (per-domain policy first),
            // with mihomo's fallback / fallback-filter detour when configured.
            let route = engine.dnsRoute(for: data)
            guard let primary = route.primary else {
                udpDropped += 1
                dnsNoUpstream &+= 1
                sendServfail(data, session: info.id)
                if !loggedNoUpstream {
                    // fix/nc-start-empty: used to be silent — every lookup failed and nothing said why.
                    loggedNoUpstream = true
                    StartupLog.write("DNS: no usable upstream (dns.nameserver / default-nameserver have nothing forwardable) — queries are dropped")
                }
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
    /// fix/nc-open-6-10 #7: when every upstream failed and a core reload landed while the query was in flight
    /// (engine.dnsGeneration moved), the query is routed again on the new config and re-sent once before it is
    /// answered SERVFAIL; a final failure writes one rate-limited [DNS] line (name, type, servers tried, outcome).
    private func forwardDNS(_ query: Data, session: UInt32, primary: NCDNSUpstream,
                            fallback: NCDNSUpstream?, fallbackFirst: Bool, retried: Bool = false,
                            trace: NCDNSAttemptTrace = NCDNSAttemptTrace()) {
        let gen = engine.dnsGeneration
        let deliver: (Data) -> Void = { [weak self] resp in
            guard let self else { return }
            self.dnsReplies &+= 1
            if !self.loggedFirstDNSReply {
                self.loggedFirstDNSReply = true
                StartupLog.write("data plane: first upstream DNS reply delivered (\(resp.count) B)")
            }
            self.engine.recordDNSResponse(query: query, response: resp)
            // nc-script-runtime: type=dns scripts see the upstream reply (recorded above, pre-hook, so
            // redir-host learning keeps the resolver's real answer) and may rewrite what the client gets.
            if self.engine.hasDNSScripts {
                self.engine.applyDNSScripts(query: query, reply: resp, queue: self.queue) { [weak self] final in
                    self?.stack.udpSend(session: session, final)
                }
            } else {
                self.stack.udpSend(session: session, resp)
            }
        }
        let fail: () -> Void = { [weak self] in
            guard let self else { return }
            if !retried, self.engine.dnsGeneration != gen {
                let route = self.engine.dnsRoute(for: query)
                if let p = route.primary {
                    trace.retriedAfterReload = true
                    trace.add("core reloaded mid-query → re-sent")
                    self.forwardDNS(query, session: session, primary: p, fallback: route.fallback,
                                    fallbackFirst: route.fallbackFirst, retried: true, trace: trace)
                    return
                }
            }
            self.dnsForwardFailed &+= 1
            self.logDNSFailure(query, trace: trace)
            self.sendServfail(query, session: session)
        }
        if fallbackFirst, let fallback {
            dnsForwarder.forward(query, upstream: fallback, trace: trace) { [weak self] resp in
                guard let self else { return }
                if let resp { deliver(resp); return }
                self.dnsForwarder.forward(query, upstream: primary, trace: trace) { resp2 in
                    if let resp2 { deliver(resp2) } else { fail() }
                }
            }
            return
        }
        dnsForwarder.forward(query, upstream: primary, trace: trace) { [weak self] resp in
            guard let self else { return }
            if let resp, !self.engine.dnsAnswerTriggersFallback(resp) { deliver(resp); return }
            guard let fallback else {
                if let resp { deliver(resp) } else { fail() }
                return
            }
            self.dnsForwarder.forward(query, upstream: fallback, trace: trace) { resp2 in
                if let resp2 { deliver(resp2) }
                else if let resp { deliver(resp) }
                else { fail() }
            }
        }
    }

    /// fix/nc-open-6-10 #7: at most 6 [DNS] failure lines per 10 s into the core log (the rest counted and
    /// reported as one "suppressed" line); the first 8 per tunnel session also go to the startup log, which the
    /// diagnostics export always carries.
    private let dnsFailLimiter = NCLineLimiter(perWindow: 6, window: 10)
    private var dnsFailStartupLines = 0

    private func logDNSFailure(_ query: Data, trace: NCDNSAttemptTrace) {
        let line = Self.dnsFailureLine(query, trace: trace)
        if dnsFailStartupLines < 8 {
            dnsFailStartupLines += 1
            StartupLog.write(line)
        }
        let (ok, suppressed) = dnsFailLimiter.admit()
        guard ok else { return }
        if suppressed > 0 { connLog("[DNS] \(suppressed) failure line(s) suppressed", level: "warning") }
        connLog(line, level: "warning")
    }

    static func dnsFailureLine(_ query: Data, trace: NCDNSAttemptTrace) -> String {
        let q = NCDNSMessage.parse(query)?.questions.first
        let name = q?.name ?? "?"
        let t = q?.type ?? 0
        let type: String
        switch t {
        case 1: type = "A"
        case 28: type = "AAAA"
        case 65: type = "HTTPS"
        case 5: type = "CNAME"
        case 12: type = "PTR"
        case 16: type = "TXT"
        case 33: type = "SRV"
        default: type = q == nil ? "?" : "type \(t)"
        }
        return "[DNS] \(name) \(type) failed (SERVFAIL to client): \(trace.summary)"
    }

    /// fix/nc-tcp0: every upstream failed — answer SERVFAIL (mihomo's DNS server does) instead of dropping the query;
    /// a silent drop leaves iOS's resolver waiting and then backing off from the tunnel DNS server.
    private func sendServfail(_ query: Data, session: UInt32) {
        guard let reply = NCPacketTrace.dnsServfail(for: query) else { return }
        dnsServfail &+= 1
        stack.udpSend(session: session, reply)
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
                                      ip: restored ? realDstIP(info.dst.ip) : info.dst.ip,
                                      dstPort: info.dst.port,
                                      network: "udp")
        if info.dst.port == 443 { ctx.protocolHint = "quic" }
        udpPending[info.id] = [data]
        engine.routeAsync(ctx, queue: queue) { [weak self] policyName, ruleText, resolution in
            guard let self, let queued = self.udpPending.removeValue(forKey: info.id), self.isRunning else { return }
            self.openUDP(info, target: target, resolution: resolution, packets: queued)
            let via: String = switch resolution {
            case .direct: "DIRECT"
            case .reject: "REJECT"
            case .proxy(let p): "\(policyName) (\(p.name) \(p.type))"
            case .chain(let ps): "\(policyName) (\(ps.map { $0.name }.joined(separator: " -> ")))"
            case .unknown(let n): "\(policyName) (unknown \(n))"
            }
            let opened = self.udpSessions[info.id] != nil
            if opened { self.udpOpened &+= 1 }
            self.connLog("[UDP] \(target.host):\(target.port) rule \(ruleText ?? "-") → \(via) \(opened ? "opened" : "dropped (no UDP relay for this policy)")",
                         level: opened ? "info" : "warning")
        }
    }

    private func openUDP(_ info: NCTunStack.UDPSessionInfo, target: NCTarget,
                         resolution: NCGroupEngine.Resolution, packets: [Data]) {
        // nc-races: aligned with NC_MAX_UDP_SESSIONS — see maxUDPSessions. A dropped first packet is
        // consistent with the other unroutable paths below (udpDropped, no ICMP unreachable anywhere
        // in the UDP path); the flow's next datagram retries once a slot frees.
        guard udpSessions.count < Self.maxUDPSessions else {
            udpDropped += 1
            return
        }
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
