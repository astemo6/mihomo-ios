import Foundation

/// fix/nc-e2e-gaps: mihomo `listeners:` entries with a fixed `proxy` on the loopback — in practice the App's 节点探测
/// listener (NCRuntimeDNS.applyProbe: name mihomo-ios-probe, type mixed, 127.0.0.1:<probePort, 7899>, proxy
/// MIHOMO-PROBE). The App selects the policy in MIHOMO-PROBE over the controller, then sends URLSession requests
/// with HTTP / HTTPS proxy = 127.0.0.1:probePort (PolicyProbe.configuration). NativeCore had no listener there, so
/// every exit-IP / 解锁检测 probe failed fast with kCFErrorDomainCFNetwork 310 (device diag, build419).
///
/// Lean on purpose: BSD loopback socket (NCLoopbackListener — NWListener on the loopback did not deliver connections
/// inside the tunnel on iOS 18.7, fix/nc-ctrl-bsd), HTTP `CONNECT host:port` and absolute-form plain HTTP only (what
/// CFNetwork sends to an HTTP/HTTPS proxy; no SOCKS), no rules, no MitM, no sniffing: every connection goes to the
/// listener's `proxy` policy, resolved at connect time (so a new selection applies to the next request). ≤ 32
/// connections, 16 KB request head cap; nothing is buffered beyond one relay read per direction.
final class NCProbeProxy {
    typealias Spec = NCProbeListener.Spec

    let spec: Spec
    private let engine: NativeCoreEngine
    private let queue = DispatchQueue(label: "nc.probeproxy", qos: .userInitiated)
    private var listener: NCLoopbackListener?
    private var conns: [ObjectIdentifier: Conn] = [:]
    private static let maxConnections = 32
    private static let maxHead = 16 * 1024
    private var nextID: UInt64 = 1

    private final class Conn {
        let client: NCLoopbackConn
        var head = Data()
        var relay: NCRelayStream?
        var closed = false
        /// fix/nc-tails: /app/stats accounting (these flows never touch the TUN, so nothing else counts them).
        var flow = NCListenerFlowStats()
        var target = NCTarget(host: "", port: 0)
        var connect = false
        let start = Date()
        var lastFlush = Date()
        var flushedUp: Int64 = 0, flushedDown: Int64 = 0
        let id: UInt64
        init(_ c: NCLoopbackConn, id: UInt64) { client = c; self.id = id }
    }

    init(engine: NativeCoreEngine, spec: Spec) {
        self.engine = engine
        self.spec = spec
    }

    /// nil = listening, else why not.
    func start() -> String? {
        let l = NCLoopbackListener(queue: queue)
        l.onAccept = { [weak self] c in self?.accept(c) }
        l.onAcceptError = { why in StartupLog.write("probe listener: \(why)") }
        var failure: String?
        queue.sync {
            failure = l.start(port: spec.port)
            if failure == nil { listener = l }
        }
        return failure
    }

    func stop() {
        queue.sync {
            listener?.stop()
            listener = nil
            for c in Array(conns.values) { close(c) }
            conns.removeAll()
        }
    }

    // MARK: per connection (on `queue`)

    private func accept(_ client: NCLoopbackConn) {
        guard listener != nil, conns.count < Self.maxConnections else { client.cancel(); return }
        let c = Conn(client, id: nextID)
        nextID &+= 1
        conns[ObjectIdentifier(c)] = c
        client.onClose = { [weak self, weak c] in
            guard let self, let c else { return }
            self.queue.async { self.close(c) }
        }
        queue.asyncAfter(deadline: .now() + 30) { [weak self, weak c] in
            guard let self, let c, !c.closed, c.relay == nil else { return }
            self.close(c) // never sent a request head / never connected
        }
        readHead(c)
    }

    private func readHead(_ c: Conn) {
        c.client.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self, weak c] data, _, done, err in
            guard let self, let c, !c.closed else { return }
            if let data, !data.isEmpty { c.head.append(data) } else if done || err != nil { return self.close(c) }
            guard let end = c.head.range(of: Data("\r\n\r\n".utf8)) else {
                return c.head.count > Self.maxHead ? self.close(c) : self.readHead(c)
            }
            self.request(c, headEnd: end)
        }
    }

    private func request(_ c: Conn, headEnd: Range<Data.Index>) {
        guard let req = NCProbeListener.parse(head: c.head, headEnd: headEnd) else { return reply(c, 400, "Bad Request", close: true) }
        c.head = Data()
        if NCOutboundBinding.isLoopback(req.host), req.port == Int(spec.port) { return reply(c, 403, "Forbidden", close: true) }
        let target = engine.derefFakeIP(NCTarget(host: req.host.lowercased(), port: req.port))
        guard let resolution = engine.resolve(policyName: spec.policy) else {
            return reply(c, 502, "Bad Gateway", close: true)
        }
        c.target = target
        c.connect = req.connect
        let chain = NCListenerFlowStats.chainName(resolution)
        c.flow.open(rule: "", policy: spec.policy, chain: chain, host: target.host)
        if case .reject = resolution { return reply(c, 403, "Forbidden", close: true) }
        NCConnector.connect(target: target, resolution: resolution, queue: queue) { [weak self, weak c] relay, error in
            guard let self, let c, !c.closed else { relay?.cancel(); return }
            guard let relay else {
                NCDialTrace.logSink?("[PROBE] \(target.host):\(target.port) via \(self.spec.policy) failed: \(error.map { "\($0.localizedDescription)" } ?? "no relay")", true)
                return self.reply(c, 502, "Bad Gateway", close: true)
            }
            c.relay = relay
            if req.connect {
                c.client.send(content: Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8), completion: .idempotent)
            }
            if !req.upstream.isEmpty {
                self.count(c, up: req.upstream.count)
                relay.send(req.upstream)
            }
            self.pumpUp(c)
            self.pumpDown(c)
        }
    }

    private func pumpUp(_ c: Conn) {
        c.client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self, weak c] data, _, done, err in
            guard let self, let c, !c.closed, let relay = c.relay else { return }
            if let data, !data.isEmpty {
                self.count(c, up: data.count)
                NCRelayFlow.send(relay, data, queue: self.queue) { [weak self, weak c] in
                    guard let self, let c, !c.closed else { return }
                    if done || err != nil { self.close(c) } else { self.pumpUp(c) }
                }
            } else if done || err != nil {
                self.close(c)
            } else {
                self.pumpUp(c)
            }
        }
    }

    private func pumpDown(_ c: Conn) {
        c.relay?.receive { [weak self, weak c] data, _ in
            guard let self else { return }
            self.queue.async {
                guard let c, !c.closed else { return }
                guard let data, !data.isEmpty else {
                    // upstream EOF / error: close once what is queued reached the client
                    c.client.send(content: Data(), completion: .contentProcessed { [weak self] _ in self?.queue.async { self?.close(c) } })
                    return
                }
                self.count(c, down: data.count)
                c.client.send(content: data, completion: .contentProcessed { [weak self, weak c] err in
                    guard let self else { return }
                    self.queue.async {
                        guard let c, !c.closed else { return }
                        if err != nil { self.close(c) } else { self.pumpDown(c) }
                    }
                })
            }
        }
    }

    private func reply(_ c: Conn, _ code: Int, _ text: String, close: Bool) {
        let body = "\(code) \(text)\n"
        let resp = "HTTP/1.1 \(code) \(text)\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
        c.client.send(content: Data(resp.utf8), completion: .contentProcessed { [weak self] _ in
            if close { self?.queue.async { self?.close(c) } }
        })
    }

    // MARK: stats (fix/nc-tails)

    private func count(_ c: Conn, up: Int = 0, down: Int = 0) {
        c.flow.count(up: up, down: down)
        if Date().timeIntervalSince(c.lastFlush) >= 1 { flush(c) }
    }

    /// Per-host / policy bytes and the speed-series totals, at most once a second per connection and at close.
    private func flush(_ c: Conn) {
        c.lastFlush = Date()
        let rec = NCStatsRecorder.shared
        rec.sideBytes(up: c.flow.up - c.flushedUp, down: c.flow.down - c.flushedDown,
                      proxied: NCListenerFlowStats.isProxied(c.flow.chain))
        c.flushedUp = c.flow.up
        c.flushedDown = c.flow.down
        if let p = c.flow.takePending() { rec.bytes(policy: p.policy, host: p.host, up: p.up, down: p.down) }
    }

    private func close(_ c: Conn) {
        guard !c.closed else { return }
        c.closed = true
        conns.removeValue(forKey: ObjectIdentifier(c))
        flush(c)
        c.flow.close(id: "probe\(c.id)", type: c.connect ? "HTTPS" : "HTTP", srcIP: "127.0.0.1", srcPort: 0,
                     dstIP: c.target.ip != nil ? c.target.host : "", dstPort: c.target.port, remote: c.target.host,
                     start: c.start)
        c.relay?.cancel()
        c.relay = nil
        c.client.onClose = nil
        c.client.cancel()
    }
}
