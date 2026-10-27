import Foundation
import Network

// fix/nc-masque-ip: the MASQUE CONNECT-IP (RFC 9484) data plane.
//
// CONNECT-IP carries IP packets, so a per-flow NCRelayStream needs a TCP/IP stack inside the tunnel. Like WireGuard
// and OpenConnect, each CONNECT-IP node is one extra lwIP netif (lwip/nc_wg.c) in the shared lwIP instance, addressed
// with the proxy's ADDRESS_ASSIGN (or the node's `ip` / `ipv6`), MTU = node `mtu` clamped 576…1193 (a QUIC DATAGRAM
// must hold the whole packet; NCMASQUE.connectIPMaxPacket); NativeCore originates TCP (NCWGTCPStream) and UDP (NCUDPWireGuardSession) from it, and
// names resolve through the node's `dns` over the tunnel first.
//
//   lwIP netif output ──► HTTP Datagram (quarter stream id + context 0 + packet) ──► QUIC DATAGRAM ──► proxy
//   proxy ──► QUIC DATAGRAM ──► NCMASQUEIPTunnel.onPacket ──► nc_wg_input
//
// Lifecycle (memory first): the tunnel opens on the first flow; a lost tunnel tears the netif down (open flows get
// tcp_err) and the next flow dials a fresh one; a node without flows for 3 min is closed.
// Threading: NCLwIP.queue only (every nc_wg_* call, the device state, tunnel callbacks). 需同步 feat/nc-kernel.

/// The CONNECT-IP devices by node identity. NCLwIP.queue only.
final class NCMQIPStack {
    static let shared = NCMQIPStack()
    private var devices: [String: NCMQIPDevice] = [:]

    func device(for proxy: NCProxy) -> (NCMQIPDevice?, String?) {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        let key = Self.identity(proxy)
        if let d = devices[key], d.alive { return (d, nil) }
        if let why = NCSupport.masqueUnsupported(proxy) { return (nil, why) }
        guard let cfg = NCMASQUE.Config(proxy: proxy), cfg.mode == .connectIP else {
            return (nil, "MASQUE 节点不是 CONNECT-IP 模式")
        }
        let d = NCMQIPDevice(key: key, cfg: cfg)
        devices[key] = d
        d.connect()
        return (d, nil)
    }

    /// NCUDPWireGuardSession's acquire hook.
    func acquire(_ proxy: NCProxy) -> (NCLwIPDevice?, String?) {
        let r = device(for: proxy)
        return (r.0, r.1)
    }

    func debugExisting(_ proxy: NCProxy) -> NCMQIPDevice? {
        guard let d = devices[Self.identity(proxy)], d.alive else { return nil }
        return d
    }

    fileprivate func forget(_ d: NCMQIPDevice) {
        if devices[d.key] === d { devices.removeValue(forKey: d.key) }
    }

    func teardownAll() {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        let all = Array(devices.values)
        devices.removeAll()
        for d in all { d.teardown("tunnel stop") }
    }

    static func identity(_ p: NCProxy) -> String {
        var parts = [p.type, p.name, p.server ?? "", "\(p.port ?? 0)", p.password ?? ""]
        for k in p.fields.keys.sorted() where k != "name" {
            parts.append("\(k)=\(p.fields[k].map { "\($0)" } ?? "")")
        }
        return parts.joined(separator: "\u{1f}")
    }
}

/// One CONNECT-IP node: the HTTP/3 tunnel + its lwIP netif. NCLwIP.queue only.
final class NCMQIPDevice: NCLwIPDevice {
    let key: String
    let cfg: NCMASQUE.Config
    private var tunnel: NCMASQUEIPTunnel?

    private(set) var devID: Int32 = 0
    private(set) var alive = true
    private(set) var ready = false
    private(set) var params: NCMASQUEIPParams?
    private(set) var lastError: String?
    private(set) var mtu: UInt16 = 1280
    var has4: Bool { devID != 0 && ip4 != nil }
    var has6: Bool { devID != 0 && ip6 != nil }
    private var ip4: String?
    private var ip6: String?

    private(set) var packetsIn = 0
    private(set) var packetsOut = 0
    private(set) var txDropped = 0

    private var waiters: [(String?) -> Void] = []
    private var users = 0
    var lastUse = Date()
    private var timer: DispatchSourceTimer?
    private var tickFast = true
    private var dnsCache: [String: ([NCIP], Date)] = [:]

    init(key: String, cfg: NCMASQUE.Config) {
        self.key = key
        self.cfg = cfg
        mtu = UInt16(clamping: max(576, min(cfg.mtu, NCMASQUE.connectIPMaxPacket)))
        let t = DispatchSource.makeTimerSource(queue: NCLwIP.queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25, leeway: .milliseconds(25))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    // MARK: Lifecycle

    func connect() {
        let t = NCMASQUEIPTunnel(config: cfg, callbackQueue: NCLwIP.queue)
        tunnel = t
        t.onPacket = { [weak self] pkt in self?.input(pkt) }
        t.onClosed = { [weak self, weak t] why in
            guard let self, let t, self.tunnel === t else { return }
            self.teardown("MASQUE CONNECT-IP 隧道断开: \(why)")
        }
        t.onParams = { [weak self] p in self?.params = p }
        t.start { [weak self, weak t] r in
            guard let self, let t, self.tunnel === t, self.alive else { return }
            switch r {
            case .success(let p): self.attach(p)
            case .failure(let e): self.teardown((e as? LocalizedError)?.errorDescription ?? "\(e)")
            }
        }
    }

    private func attach(_ p: NCMASQUEIPParams) {
        let id: Int32
        switch (p.ipv4, p.ipv6) {
        case let (a?, b?): id = a.withCString { pa in b.withCString { pb in nc_wg_dev_add(pa, pb, mtu) } }
        case let (a?, nil): id = a.withCString { pa in nc_wg_dev_add(pa, nil, mtu) }
        case let (nil, b?): id = b.withCString { pb in nc_wg_dev_add(nil, pb, mtu) }
        default: id = 0
        }
        guard id > 0 else {
            teardown("MASQUE CONNECT-IP 地址无效或 lwIP 接口不足 (\(p.ipv4 ?? "-") / \(p.ipv6 ?? "-"))")
            return
        }
        devID = id
        ip4 = p.ipv4
        ip6 = p.ipv6
        params = p
        NCWGStack.shared.registerOther(self)
        ready = true
        StartupLog.write("masque-ip: \(cfg.name) up — \(ip4 ?? "-")\(ip6.map { " / \($0)" } ?? ""), mtu \(mtu), "
            + "routes \(p.routes.count), dns \(cfg.dns.joined(separator: ","))")
        let w = waiters
        waiters = []
        w.forEach { $0(nil) }
    }

    func teardown(_ why: String) {
        guard alive else { return }
        alive = false
        ready = false
        timer?.cancel()
        timer = nil
        tunnel?.close()
        tunnel = nil
        NCMQIPStack.shared.forget(self)
        if devID != 0 {
            NCWGStack.shared.unregisterOther(self)
            nc_wg_dev_remove(devID) // fires tcp_err for every open flow
            devID = 0
        }
        if lastError == nil { lastError = why }
        let w = waiters
        waiters = []
        w.forEach { $0(why) }
        StartupLog.write("masque-ip: \(cfg.name) down (\(why))")
    }

    func whenReady(_ done: @escaping (String?) -> Void) {
        if ready { done(nil); return }
        guard alive else { done(lastError ?? "MASQUE CONNECT-IP 已断开"); return }
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

    // MARK: Packets

    private func input(_ pkt: Data) {
        guard alive, devID != 0, !pkt.isEmpty else { return }
        packetsIn += 1
        lastUse = Date()
        pkt.withUnsafeBytes { raw in
            let b = raw.bindMemory(to: UInt8.self)
            if let base = b.baseAddress { nc_wg_input(devID, base, UInt32(b.count)) }
        }
    }

    /// NCLwIPDevice: a packet from the netif → one HTTP Datagram.
    func lwipOutput(_ pkt: UnsafeBufferPointer<UInt8>) {
        guard ready, let t = tunnel, pkt.count > 0 else { txDropped += 1; return }
        packetsOut += 1
        lastUse = Date()
        t.send(pkt)
    }

    // MARK: Timers

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
        if users == 0, waiters.isEmpty, ready, Date().timeIntervalSince(lastUse) > 180 {
            teardown("idle")
            return
        }
        setTickFast(users > 0)
    }

    // MARK: Names

    private static let fakeV4 = NCCIDR("198.18.0.0/15")!
    private static let fakeV6 = NCCIDR("fdfe:dcba:9876::/48")!

    /// Waits for the tunnel, then: IP literal → itself; else the node's `dns` over the tunnel, falling back to the
    /// system resolver (fake-IP answers filtered).
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
                        finish(sys.filter { !NCMQIPDevice.fakeV4.contains($0) && !NCMQIPDevice.fakeV6.contains($0) })
                    }
                }
            }
            if self.cfg.dns.isEmpty { system(); return }
            self.dnsOverTunnel(host, servers: self.cfg.dns) { ips in
                if ips.isEmpty { system() } else { finish(ips) }
            }
        }
    }
}

// MARK: - Connector entry

extension NCConnector {
    /// Hooks masqueIPStream into the shared connector (PacketTunnel only; NCConnector lives in Shared/).
    static func installMASQUEIPDialer() {
        masqueIPDialer = { proxy, target, queue, completion in
            masqueIPStream(proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    /// TCP through a MASQUE CONNECT-IP node (fix/nc-masque-ip). Completion on `queue`, exactly once.
    static func masqueIPStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                               completion: @escaping (NCRelayStream?, Error?) -> Void) {
        NCLwIP.queue.async {
            let (dev, why) = NCMQIPStack.shared.device(for: proxy)
            guard let dev else {
                queue.async { completion(nil, Failure.unsupported("masque: \(why ?? "-")")) }
                return
            }
            dev.retain()
            dev.resolve(target.host) { ips in
                guard dev.alive, dev.devID != 0, let ip = dev.pick(ips) else {
                    let why = dev.alive ? "cannot resolve \(target.host)" : (dev.lastError ?? "down")
                    dev.release()
                    queue.async { completion(nil, Failure.handshake("masque: \(why)")) }
                    return
                }
                let s = NCWGTCPStream(device: dev, callerQueue: queue)
                s.start(ip: ip, port: target.port) { err in completion(err == nil ? s : nil, err) }
            }
        }
    }
}
