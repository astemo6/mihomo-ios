import Foundation
import Network

// fix/nc-openconnect-dp: the OpenConnect (AnyConnect / ocserv) data plane.
//
// OpenConnect is an L3 VPN: after `CONNECT /CSCOSSLC/tunnel` every CSTP DATA frame on the TLS stream carries one IPv4
// or IPv6 packet. A per-flow NCRelayStream therefore needs a TCP/IP stack *inside* the tunnel. Like WireGuard, each
// OpenConnect node is one extra lwIP netif (lwip/nc_wg.c) in the shared lwIP instance, addressed with the server's
// X-CSTP-Address / X-CSTP-Address-IP6 and sized by X-CSTP-MTU; NativeCore originates TCP (NCWGTCPStream) and UDP
// (NCUDPWireGuardSession) from it, names resolve through X-CSTP-DNS over the tunnel first.
//
//   lwIP netif output ──► CSTP DATA frame (8-byte header + packet, ONE frame per TLS write) ──► ocserv / ASA
//   ocserv ──► TLS byte stream ──► frames parsed in place ──► nc_wg_input (DATA) / DPD-RESP / terminate
//
// One frame per TLS record matters: ocserv reads a record and rejects it unless it is exactly one CSTP frame
// ("error parsing CSTP data"), so frames are never coalesced into one Data / one send. fix/nc-oc-dtls: up to
// `maxInFlight` frames are handed to the NWConnection at once (each its own send → its own TLS record) instead of
// one per .contentProcessed round trip, which bounded throughput to one packet per callback hop. Memory: one Data per outgoing packet (header + payload in a single allocation), zero copies for
// incoming packets beyond lwIP's pbuf; the uplink queue is capped (packets beyond it are dropped like a full
// interface queue, TCP retransmits).
//
// Liveness: DPD-REQ after X-CSTP-DPD seconds without inbound traffic, the channel is declared dead after 2×DPD;
// KEEPALIVE after X-CSTP-Keepalive seconds without outbound traffic. A dead / closed channel reconnects with the
// session cookie (same address → the netif and its lwIP flows survive), re-authenticating when the cookie expired;
// backoff 0.5 s … 30 s, 6 attempts. DTLS is not used (Network.framework cannot put X-DTLS-App-ID into the DTLS
// ClientHello session id; NCOpenConnectSession falls back to CSTP explicitly).
//
// Threading: NCLwIP.queue only (the session, its NCStreams and every nc_wg_* call). Auth / framing basis: astemo6's
// PR #159 (feat/nc-openconnect).

/// The OpenConnect devices by node identity. NCLwIP.queue only.
final class NCOCStack {
    static let shared = NCOCStack()
    private var devices: [String: NCOCDevice] = [:]

    /// The node's device, created (and connecting) on first use.
    func device(for proxy: NCProxy) -> (NCOCDevice?, String?) {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        let key = Self.identity(proxy)
        if let d = devices[key], d.alive { return (d, nil) }
        let (cfg, why) = NCOpenConnect.Config.parse(proxy)
        guard let cfg else { return (nil, why ?? "OpenConnect 配置无效") }
        let d = NCOCDevice(key: key, cfg: cfg)
        devices[key] = d
        d.connect()
        return (d, nil)
    }

    /// NCUDPWireGuardSession's acquire hook.
    func acquire(_ proxy: NCProxy) -> (NCLwIPDevice?, String?) {
        let r = device(for: proxy)
        return (r.0, r.1)
    }

    /// The live device for a node without creating one (tests / diagnostics).
    func debugExisting(_ proxy: NCProxy) -> NCOCDevice? {
        guard let d = devices[Self.identity(proxy)], d.alive else { return nil }
        return d
    }

    fileprivate func forget(_ d: NCOCDevice) {
        if devices[d.key] === d { devices.removeValue(forKey: d.key) }
    }

    /// Tunnel stop / plane teardown (caller is on NCLwIP.queue, before the lwIP stack stops).
    func teardownAll() {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        let all = Array(devices.values)
        devices.removeAll()
        for d in all { d.teardown("tunnel stop") }
    }

    /// Everything that changes the session (server, credentials, options): a different value is a different device.
    static func identity(_ p: NCProxy) -> String {
        var parts = [p.type, p.name, p.server ?? "", "\(p.port ?? 0)", p.password ?? ""]
        for k in p.fields.keys.sorted() where k != "name" {
            parts.append("\(k)=\(p.fields[k].map { "\($0)" } ?? "")")
        }
        return parts.joined(separator: "\u{1f}")
    }
}

/// One OpenConnect node: the CSTP channel + its lwIP netif. NCLwIP.queue only.
final class NCOCDevice: NCLwIPDevice {
    let key: String
    let cfg: NCOpenConnect.Config
    private let session: NCOpenConnectSession

    private(set) var devID: Int32 = 0
    private(set) var alive = true
    /// CSTP channel up and the netif attached.
    private(set) var ready = false
    private(set) var params: NCOpenConnect.TunnelParameters?
    private(set) var lastError: String?
    var has4: Bool { devID != 0 && ip4 != nil }
    var has6: Bool { devID != 0 && ip6 != nil }
    private var ip4: String?
    private var ip6: String?

    // Stats (diagnostics + the loopback test).
    private(set) var reconnects = 0
    private(set) var dpdRequestsSent = 0
    private(set) var dpdResponsesReceived = 0
    private(set) var txDropped = 0
    private(set) var framesIn = 0
    private(set) var framesOut = 0
    /// Flows that went DIRECT because the server's split-tunnel routes put the destination outside the tunnel.
    private(set) var splitDirect = 0
    /// Most frames ever in flight at once (diagnostics + the throughput test).
    private(set) var maxInFlightSeen = 0

    private var stream: NCStream?
    private var rx = Data()
    private var rxOff = 0
    private var txQueue: [Data] = []
    private var txHead = 0
    private var txQueuedBytes = 0
    private var txInFlight = 0
    /// Frames handed to the TLS connection before their .contentProcessed (each frame is a separate send).
    static let maxInFlight = 32
    /// Uplink queue cap: what lwIP may hand us faster than the TLS stream drains (several flows' windows).
    private static let txCap = 512 * 1024

    private var waiters: [(String?) -> Void] = []
    private var attempt = 0
    private var connectingSince: Date?
    private var reconnectTry = 0
    private var reconnectPending = false

    private var lastRx = Date()
    private var lastTx = Date()
    private var lastDPD = Date.distantPast
    private var users = 0
    var lastUse = Date()
    private var timer: DispatchSourceTimer?
    private var tickFast = true
    private var dnsCache: [String: ([NCIP], Date)] = [:]

    init(key: String, cfg: NCOpenConnect.Config) {
        self.key = key
        self.cfg = cfg
        session = NCOpenConnectSession(config: cfg, queue: NCLwIP.queue)
        let t = DispatchSource.makeTimerSource(queue: NCLwIP.queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25, leeway: .milliseconds(25))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    // MARK: Lifecycle

    /// First connection: auth + CONNECT, then the netif. Waiters (flows) are answered when it is up or failed.
    func connect() {
        attempt += 1
        let a = attempt
        connectingSince = Date()
        session.start { [weak self] r in self?.tunnelResult(r, attempt: a) }
    }

    private func tunnelResult(_ r: Result<NCOpenConnectTunnel, Error>, attempt a: Int) {
        guard alive, a == attempt else {
            if case .success(let t) = r { t.stream.cancel() }
            return
        }
        connectingSince = nil
        switch r {
        case .success(let t):
            session.releaseTunnelStream()
            attach(t)
        case .failure(let e):
            let why = (e as? LocalizedError)?.errorDescription ?? "\(e)"
            lastError = why
            if devID == 0 && reconnects == 0 && !reconnectPending {
                teardown(why) // the first connection failed: report it to the waiting flows
            } else {
                StartupLog.write("openconnect: \(cfg.name) reconnect failed: \(why)")
                scheduleReconnect()
            }
        }
    }

    private func attach(_ t: NCOpenConnectTunnel) {
        let p = t.params
        let new4 = p.assignedIPv4.flatMap { NCIP($0) != nil ? $0 : nil }
        let new6 = p.assignedIPv6.flatMap { NCIP($0) != nil ? $0 : nil }
        let mtu = UInt16(clamping: max(576, min(p.mtu > 0 ? p.mtu : cfg.mtu, 4000)))
        if devID != 0, new4 != ip4 || new6 != ip6 || params?.mtu != p.mtu {
            // A different address: flows bound to the old one cannot continue (lwIP aborts them).
            StartupLog.write("openconnect: \(cfg.name) address changed on reconnect, netif re-created")
            NCWGStack.shared.unregisterOther(self)
            nc_wg_dev_remove(devID)
            devID = 0
        }
        if devID == 0 {
            let id: Int32
            switch (new4, new6) {
            case let (a?, b?): id = a.withCString { pa in b.withCString { pb in nc_wg_dev_add(pa, pb, mtu) } }
            case let (a?, nil): id = a.withCString { pa in nc_wg_dev_add(pa, nil, mtu) }
            case let (nil, b?): id = b.withCString { pb in nc_wg_dev_add(nil, pb, mtu) }
            default: id = 0
            }
            guard id > 0 else {
                t.stream.cancel()
                teardown("OpenConnect 隧道地址无效或 lwIP 接口不足 (\(p.assignedIPv4 ?? "-") / \(p.assignedIPv6 ?? "-"))")
                return
            }
            devID = id
            ip4 = new4
            ip6 = new6
            NCWGStack.shared.registerOther(self)
        }
        params = p
        stream = t.stream
        rx = t.leftover
        rxOff = 0
        clearTx()
        let now = Date()
        lastRx = now
        lastTx = now
        lastDPD = .distantPast
        ready = true
        reconnectTry = 0
        reconnectPending = false
        lastError = nil
        StartupLog.write("openconnect: \(cfg.name) up — \(ip4 ?? "-")\(ip6.map { " / \($0)" } ?? ""), mtu \(mtu), "
            + "dns \(p.dnsServers.joined(separator: ",")), dpd \(p.dpd)s, keepalive \(p.keepalive)s"
            + (reconnects > 0 ? ", reconnect #\(reconnects)" : ""))
        if !rx.isEmpty { consume(Data()) }
        if let s = stream { pump(s) }
        let w = waiters
        waiters = []
        w.forEach { $0(nil) }
    }

    /// The channel died (EOF, error, DPD timeout): drop it, keep the netif, reconnect while the device is in use.
    private func transportLost(_ why: String) {
        guard let s = stream else { return }
        stream = nil
        ready = false
        s.cancel()
        rx = Data()
        rxOff = 0
        clearTx()
        guard alive else { return }
        StartupLog.write("openconnect: \(cfg.name) channel lost (\(why))")
        if users == 0 && waiters.isEmpty {
            teardown("idle, channel lost")
            return
        }
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        guard alive else { return }
        reconnectTry += 1
        guard reconnectTry <= 6 else {
            teardown("OpenConnect 重连失败: \(lastError ?? "-")")
            return
        }
        reconnectPending = true
        let delay = reconnectTry == 1 ? 0.5 : min(30, pow(2, Double(reconnectTry - 1)))
        attempt += 1
        let a = attempt
        NCLwIP.queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.alive, a == self.attempt else { return }
            self.reconnects += 1
            self.connectingSince = Date()
            self.session.reconnect { [weak self] r in self?.tunnelResult(r, attempt: a) }
        }
    }

    func teardown(_ why: String) {
        guard alive else { return }
        alive = false
        ready = false
        timer?.cancel()
        timer = nil
        if let s = stream {
            // Polite DISCONNECT (reason 0xb0 = user requested), then close.
            let bye = NCOpenConnect.encodeCSTP(type: .disconnect, payload: Data([0xb0]))
            s.conn.send(content: bye, completion: .contentProcessed { _ in s.cancel() })
            NCLwIP.queue.asyncAfter(deadline: .now() + 1) { s.cancel() }
        }
        stream = nil
        session.cancel()
        clearTx()
        rx = Data()
        NCOCStack.shared.forget(self)
        if devID != 0 {
            NCWGStack.shared.unregisterOther(self)
            nc_wg_dev_remove(devID) // fires tcp_err for every open flow
            devID = 0
        }
        if lastError == nil { lastError = why }
        let w = waiters
        waiters = []
        w.forEach { $0(why) }
        StartupLog.write("openconnect: \(cfg.name) down (\(why))")
    }

    /// `done(nil)` once the channel is up (now, or after connect / reconnect), `done(reason)` when it failed.
    func whenReady(_ done: @escaping (String?) -> Void) {
        if ready { done(nil); return }
        guard alive else { done(lastError ?? "OpenConnect 已断开"); return }
        waiters.append(done)
    }

    func retain() {
        users += 1
        lastUse = Date()
        setTickFast(true)
    }

    func release() {
        users = max(0, users - 1)
        lastUse = Date()
    }

    // MARK: Receive (CSTP frames, parsed in place)

    private func pump(_ s: NCStream) {
        s.receive { [weak self] data, err in
            guard let self, self.stream === s else { return }
            if let data, !data.isEmpty {
                self.lastRx = Date()
                self.consume(data)
                if self.stream === s { self.pump(s) }
            } else {
                self.transportLost(err.map { "\($0.localizedDescription)" } ?? "EOF")
            }
        }
    }

    private enum Control { case dpdReq(Data), terminate(String), bad }

    private func consume(_ data: Data) {
        if !data.isEmpty { rx.append(data) }
        var control: [Control] = []
        let dev = devID
        var dataFrames = 0
        var stop = false
        rx.withUnsafeBytes { raw in
            let b = raw.bindMemory(to: UInt8.self)
            guard let base = b.baseAddress else { return }
            var off = rxOff
            while !stop, b.count - off >= NCOpenConnect.cstpHeaderSize {
                guard b[off] == 0x53, b[off + 1] == 0x54, b[off + 2] == 0x46, b[off + 3] == 0x01 else {
                    control.append(.bad)
                    break
                }
                let len = Int(b[off + 4]) << 8 | Int(b[off + 5])
                guard b.count - off >= NCOpenConnect.cstpHeaderSize + len else { break }
                let type = b[off + 6]
                let payload = base + off + NCOpenConnect.cstpHeaderSize
                switch type {
                case NCOpenConnect.PayloadType.data.rawValue:
                    // lwIP copies into a pbuf; never retained past this call.
                    if dev != 0, len > 0 { nc_wg_input(dev, payload, UInt32(len)) }
                    dataFrames += 1
                case NCOpenConnect.PayloadType.dpdReq.rawValue:
                    control.append(.dpdReq(Data(bytes: payload, count: len)))
                case NCOpenConnect.PayloadType.dpdResp.rawValue:
                    dpdResponsesReceived += 1
                case NCOpenConnect.PayloadType.disconnect.rawValue:
                    control.append(.terminate("服务端断开会话 (DISCONNECT\(len > 0 ? " reason \(b[off + 8])" : ""))"))
                    stop = true
                case NCOpenConnect.PayloadType.terminate.rawValue:
                    control.append(.terminate("服务端终止 (TERMINATE)"))
                    stop = true
                default:
                    break // KEEPALIVE, COMPRESSED (not negotiated), unknown types: skipped by length
                }
                off += NCOpenConnect.cstpHeaderSize + len
            }
            rxOff = off
        }
        framesIn += dataFrames
        // Compact: drop consumed bytes (keeps the buffer at one partial frame + the last chunk).
        if rxOff >= rx.count {
            rx.removeAll(keepingCapacity: rx.count <= 128 * 1024)
            rxOff = 0
        } else if rxOff >= 32 * 1024 {
            rx.removeSubrange(0..<rxOff)
            rxOff = 0
        }
        for c in control {
            switch c {
            case .dpdReq(let p):
                sendFrame(.dpdResp, p)
            case .terminate(let why):
                lastError = why
                teardown(why)
                return
            case .bad:
                transportLost("CSTP 报文魔数不匹配")
                return
            }
        }
    }

    // MARK: Send (one frame per TLS write)

    /// NCLwIPDevice: a packet from the netif → one CSTP DATA frame (single allocation).
    func lwipOutput(_ pkt: UnsafeBufferPointer<UInt8>) {
        guard ready, let base = pkt.baseAddress, pkt.count > 0, pkt.count <= 0xffff else {
            txDropped += 1
            return
        }
        if txQueuedBytes + pkt.count > Self.txCap {
            txDropped += 1
            return
        }
        var d = Data(capacity: NCOpenConnect.cstpHeaderSize + pkt.count)
        d.append(contentsOf: [0x53, 0x54, 0x46, 0x01, UInt8(pkt.count >> 8), UInt8(pkt.count & 0xff),
                              NCOpenConnect.PayloadType.data.rawValue, 0])
        d.append(base, count: pkt.count)
        lastUse = Date()
        enqueue(d)
    }

    private func sendFrame(_ type: NCOpenConnect.PayloadType, _ payload: Data = Data()) {
        guard stream != nil else { return }
        enqueue(NCOpenConnect.encodeCSTP(type: type, payload: payload))
    }

    private func enqueue(_ frame: Data) {
        txQueue.append(frame)
        txQueuedBytes += frame.count
        kick()
    }

    private func kick() {
        while txInFlight < Self.maxInFlight, stream != nil, txHead < txQueue.count { sendNext() }
    }

    private func sendNext() {
        guard let s = stream else { return }
        let frame = txQueue[txHead]
        txQueue[txHead] = Data()
        txHead += 1
        if txHead == txQueue.count {
            txQueue.removeAll(keepingCapacity: true)
            txHead = 0
        } else if txHead >= 256 {
            txQueue.removeFirst(txHead)
            txHead = 0
        }
        txInFlight += 1
        if txInFlight > maxInFlightSeen { maxInFlightSeen = txInFlight }
        lastTx = Date()
        framesOut += 1
        let n = frame.count
        s.conn.send(content: frame, completion: .contentProcessed { [weak self] err in
            // NCStream's connection runs on NCLwIP.queue.
            guard let self, self.stream === s else { return }
            self.txInFlight = max(0, self.txInFlight - 1)
            self.txQueuedBytes = max(0, self.txQueuedBytes - n)
            if let err {
                self.transportLost("send: \(err.localizedDescription)")
                return
            }
            self.kick()
        })
    }

    private func clearTx() {
        txQueue.removeAll()
        txHead = 0
        txQueuedBytes = 0
        txInFlight = 0
    }

    // MARK: Timers (lwIP, DPD, keepalive, idle)

    private func setTickFast(_ fast: Bool) {
        guard fast != tickFast, let timer else { return }
        tickFast = fast
        let interval: DispatchTimeInterval = fast ? .milliseconds(250) : .seconds(1)
        timer.schedule(deadline: .now() + interval, repeating: interval,
                       leeway: fast ? .milliseconds(25) : .milliseconds(200))
    }

    private func tick() {
        guard alive else { return }
        nc_wg_poll()
        let now = Date()
        if let since = connectingSince, now.timeIntervalSince(since) > 30 {
            connectingSince = nil
            attempt += 1 // the hung attempt's late result is ignored
            lastError = "OpenConnect 连接超时 (30 s)"
            session.cancel()
            if devID == 0 && reconnects == 0 && !reconnectPending { teardown(lastError!); return }
            scheduleReconnect()
        }
        if ready, let p = params {
            let dpd = TimeInterval(max(p.dpd, 5))
            let idleRx = now.timeIntervalSince(lastRx)
            if idleRx > 2 * dpd + 5 {
                transportLost("DPD 超时 (\(Int(idleRx)) s 无数据)")
            } else if idleRx > dpd, now.timeIntervalSince(lastDPD) > dpd {
                lastDPD = now
                dpdRequestsSent += 1
                sendFrame(.dpdReq)
            } else if p.keepalive > 0, now.timeIntervalSince(lastTx) > TimeInterval(p.keepalive) {
                sendFrame(.keepalive)
            }
        }
        // Memory first: an unused node (no flow for 3 min) is torn down; the next flow re-authenticates.
        if users == 0, waiters.isEmpty, connectingSince == nil, now.timeIntervalSince(lastUse) > 180 {
            teardown("idle")
            return
        }
        setTickFast(users > 0)
    }

    // MARK: Names

    private static let fakeV4 = NCCIDR("198.18.0.0/15")!
    private static let fakeV6 = NCCIDR("fdfe:dcba:9876::/48")!

    /// Waits for the channel, then: IP literal → itself; else X-CSTP-DNS over the tunnel (the VPN's own resolver, so
    /// intranet names work), falling back to the system resolver (fake-IP answers filtered).
    func resolve(_ host0: String, _ done: @escaping ([NCIP]) -> Void) {
        let host = host0.hasPrefix("[") && host0.hasSuffix("]") ? String(host0.dropFirst().dropLast()) : host0
        whenReady { [weak self] err in
            guard let self, err == nil, self.alive else { done([]); return }
            if let ip = NCIP(host) { done([ip]); return }
            let key = host.lowercased()
            if let hit = self.dnsCache[key], hit.1 > Date() { done(hit.0); return }
            let finish: ([NCIP]) -> Void = { [weak self] ips in
                if let self, !ips.isEmpty {
                    if self.dnsCache.count > 128 { self.dnsCache.removeAll() }
                    self.dnsCache[key] = (ips, Date().addingTimeInterval(120))
                }
                done(ips)
            }
            let system: () -> Void = {
                DispatchQueue.global(qos: .userInitiated).async {
                    let sys = NCWGDevice.systemResolve(host)
                    NCLwIP.queue.async {
                        finish(sys.filter { !NCOCDevice.fakeV4.contains($0) && !NCOCDevice.fakeV6.contains($0) })
                    }
                }
            }
            let servers = self.params?.dnsServers ?? []
            if servers.isEmpty { system(); return }
            self.dnsOverTunnel(host, servers: servers) { ips in
                if ips.isEmpty { system() } else { finish(ips) }
            }
        }
    }

    var label: String { "openconnect" }

    /// fix/nc-oc-dtls: whether a destination goes through this node's tunnel (server split-tunnel routes, unless the
    /// node sets `split-routes: false`). Before the channel is up everything counts as inside.
    func routesThroughTunnel(_ ip: NCIP) -> Bool {
        guard cfg.splitRoutes, let p = params else { return true }
        return p.routesThroughTunnel(ip)
    }

    fileprivate func noteSplitDirect() { splitDirect += 1 }

    // MARK: Test hooks (NCOpenConnectLoopbackTests)

    /// Drops the TLS channel as if the network had failed (the reconnect path).
    func debugDropChannel() { transportLost("test: channel dropped") }

    /// Sends one DPD request now.
    func debugSendDPD() {
        lastDPD = Date()
        dpdRequestsSent += 1
        sendFrame(.dpdReq)
    }
}

// MARK: - Connector entry

extension NCConnector {
    /// Hooks openconnectStream into the shared connector (PacketTunnel only; NCConnector lives in Shared/).
    static func installOpenConnectDialer() {
        openconnectDialer = { proxy, target, queue, completion in
            openconnectStream(proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    /// TCP through an OpenConnect node (fix/nc-openconnect-dp). Completion on `queue`, exactly once.
    static func openconnectStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                  completion: @escaping (NCRelayStream?, Error?) -> Void) {
        NCLwIP.queue.async {
            let (dev, why) = NCOCStack.shared.device(for: proxy)
            guard let dev else {
                queue.async { completion(nil, Failure.unsupported("openconnect: \(why ?? "-")")) }
                return
            }
            dev.retain()
            dev.resolve(target.host) { ips in
                guard dev.alive, dev.devID != 0, let ip = dev.pick(ips) else {
                    let why = dev.alive ? "cannot resolve \(target.host)" : (dev.lastError ?? "down")
                    dev.release()
                    queue.async { completion(nil, Failure.handshake("openconnect: \(why)")) }
                    return
                }
                if !dev.routesThroughTunnel(ip) {
                    // Outside the server's split-include (or inside a split-exclude): the VPN does not carry it,
                    // so the flow goes direct like with the AnyConnect / openconnect clients.
                    dev.noteSplitDirect()
                    dev.release()
                    StartupLog.write("openconnect: \(proxy.name) \(ip.string):\(target.port) outside split routes → direct")
                    let d = NCStream(to: ip.string, port: target.port, queue: queue)
                    d.start { err in completion(err == nil ? d : nil, err) }
                    return
                }
                let s = NCWGTCPStream(device: dev, callerQueue: queue)
                s.start(ip: ip, port: target.port) { err in completion(err == nil ? s : nil, err) }
            }
        }
    }
}
