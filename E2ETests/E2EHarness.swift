import Foundation
import Network
import Security

// Tern E2E replay, stage 2 helpers: the provider-side process setup, a controller client that talks to NCController
// the way the App's ControllerClient does (Bearer secret, JSON, websocket streams), the TLS probe for MitM flows and
// the memory sampler.

enum E2EHarness {
    /// What PacketTunnelProvider.startTunnel does before NativeTunnelCore.start (keep in step with it; the provider
    /// file itself is not compiled into a callable form here — it is an NEPacketTunnelProvider subclass that needs
    /// the system to instantiate it).
    static func prepareProcess(log: @escaping (String) -> Void) {
        StartupLog.begin("E2E replay (in-process NativeCore)")
        NativeLogRing.install()
        let geo = GeoBootstrap.install { log("geo: \($0)") }
        log("geo databases copied: \(geo)")
        _ = JSCScriptEngine.register()
        NativeBodyStore.register()
        if #available(iOS 17, *) {
            let on = NativeMitmRuntime.install(front: MitmTLSFront.shared, upstream: NCUpstreamConnector.shared,
                                               codec: HTTPLaneCodec(), force: true, selective: false)
            log("native MitM runtime: \(on ? "on" : "off")")
        }
        NCOutboundBinding.start(includeAllNetworks: false)
        NCConnector.installWireGuardDialer()
        NCConnector.installTailscaleDialer()
    }

    static func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return 19_390 }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard ok == 0 else { return 19_391 }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    /// TCP connect from the test process (not through the tunnel): is a node reachable from this runner at all?
    static func tcpReachable(host: String, port: Int, timeout: TimeInterval = 3) -> Bool {
        guard port > 0, let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return false }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        let box = Flag()
        c.stateUpdateHandler = { st in
            switch st {
            case .ready: box.set(1)
            case .failed, .waiting, .cancelled: box.set(2)
            default: break
            }
        }
        c.start(queue: DispatchQueue(label: "e2e.reach"))
        _ = E2ENet.waitUntil(timeout) { box.get() != 0 }
        c.cancel()
        return box.get() == 1
    }

    /// HTTP GET from the test process (not through the tunnel): the status a subscription host gives this runner, and
    /// whether the body is a Cloudflare block page ("error code: 1005" = the runner's ASN is banned). nil = no answer.
    static func httpStatus(_ urlString: String, timeout: TimeInterval = 10) -> (status: Int, cfBlock: Bool)? {
        guard let url = URL(string: urlString) else { return nil }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.setValue("clash.meta", forHTTPHeaderField: "User-Agent")
        final class Box { let lock = NSLock(); var v: (Int, Bool)?; var done = false }
        let box = Box()
        let task = URLSession.shared.dataTask(with: req) { data, resp, _ in
            let st = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let body = data.map { String(decoding: $0.prefix(4096), as: UTF8.self) } ?? ""
            box.lock.lock(); box.v = st > 0 ? (st, body.contains("error code: 10")) : nil; box.done = true; box.lock.unlock()
        }
        task.resume()
        _ = E2ENet.waitUntil(timeout + 1) { box.lock.lock(); defer { box.lock.unlock() }; return box.done }
        task.cancel()
        box.lock.lock(); defer { box.lock.unlock() }
        return box.v.map { (status: $0.0, cfBlock: $0.1) }
    }

    final class Flag {
        private let lock = NSLock()
        private var v = 0
        func set(_ x: Int) { lock.lock(); if v == 0 { v = x }; lock.unlock() }
        func get() -> Int { lock.lock(); defer { lock.unlock() }; return v }
    }
}

/// NCController client (same auth / shapes as App/Core/ControllerClient.swift).
final class E2EController {
    let port: Int
    let secret: String
    private let session: URLSession

    init(port: Int, secret: String) {
        self.port = port
        self.secret = secret
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 40
        session = URLSession(configuration: cfg)
    }

    struct Reply {
        var status: Int
        var data: Data
        var ms: Int
        var error: String?
        var json: Any? { try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) }
        var object: [String: Any]? { json as? [String: Any] }
        var ok: Bool { (200..<300).contains(status) }
        var message: String { (object?["message"] as? String) ?? error ?? String(decoding: data.prefix(160), as: UTF8.self) }
    }

    static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/?#"))) ?? s
    }

    func call(_ method: String, _ path: String, query: [String: String] = [:], body: Any? = nil, timeout: TimeInterval = 15) -> Reply {
        var comps = URLComponents()
        comps.scheme = "http"; comps.host = "127.0.0.1"; comps.port = port
        comps.percentEncodedPath = path
        if !query.isEmpty { comps.queryItems = query.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) } }
        guard let url = comps.url else { return Reply(status: -1, data: Data(), ms: 0, error: "bad url") }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = timeout
        req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        if let body, let d = try? JSONSerialization.data(withJSONObject: body) {
            req.httpBody = d
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let t0 = Date()
        let box = ReplyBox()
        session.dataTask(with: req) { data, resp, err in
            box.set(Reply(status: (resp as? HTTPURLResponse)?.statusCode ?? -1, data: data ?? Data(),
                          ms: Int(Date().timeIntervalSince(t0) * 1000), error: err?.localizedDescription))
        }.resume()
        _ = E2ENet.waitUntil(timeout + 2) { box.get() != nil }
        return box.get() ?? Reply(status: -1, data: Data(), ms: Int(Date().timeIntervalSince(t0) * 1000), error: "no answer in \(Int(timeout)) s")
    }

    /// First message of a websocket stream (/traffic, /memory, /connections, /logs) within `timeout`.
    /// `trigger` runs every 0.5 s while waiting — /logs only streams lines written after it attaches, so the caller
    /// writes one (fix/nc-e2e-real: run 40278215218 had nothing to log during the 4 s wait → false FAIL).
    func firstStreamMessage(_ path: String, timeout: TimeInterval = 4, trigger: (() -> Void)? = nil) -> (ok: Bool, detail: String) {
        guard let url = URL(string: "ws://127.0.0.1:\(port)\(path)?token=\(secret)") else { return (false, "bad url") }
        let task = session.webSocketTask(with: url)
        let box = StringBox()
        task.resume()
        task.receive { result in
            switch result {
            case .success(let m):
                switch m {
                case .string(let s): box.set("ok:" + String(s.prefix(120)))
                case .data(let d): box.set("ok:" + String(decoding: d.prefix(120), as: UTF8.self))
                @unknown default: box.set("ok:?")
                }
            case .failure(let e): box.set("err:" + e.localizedDescription)
            }
        }
        var lastTrigger = Date.distantPast
        _ = E2ENet.waitUntil(timeout) {
            if let trigger, Date().timeIntervalSince(lastTrigger) >= 0.5 { lastTrigger = Date(); trigger() }
            return box.get() != nil
        }
        task.cancel(with: .goingAway, reason: nil)
        let v = box.get() ?? "err:no message in \(Int(timeout)) s"
        return (v.hasPrefix("ok:"), String(v.dropFirst(3)))
    }

    private final class ReplyBox {
        private let lock = NSLock(); private var v: Reply?
        func set(_ r: Reply) { lock.lock(); if v == nil { v = r }; lock.unlock() }
        func get() -> Reply? { lock.lock(); defer { lock.unlock() }; return v }
    }
    final class StringBox {
        private let lock = NSLock(); private var v: String?
        func set(_ r: String) { lock.lock(); if v == nil { v = r }; lock.unlock() }
        func get() -> String? { lock.lock(); defer { lock.unlock() }; return v }
    }
}

/// A TLS client over a synthetic TUN flow: a loopback listener in the test process relays one accepted socket into an
/// E2ETCP connection (device → fake-IP:443), and a Network.framework TLS client (SNI = the MitM host, trust anchored
/// at the MitM CA only) talks HTTP/1.1 through it. A finished handshake that verifies against the CA alone proves the
/// flow was decrypted by Tern's MitM front, not passed through to the origin.
final class E2ETLSProbe {
    struct Result {
        var relayEstablished = false
        var handshake = false
        var trustedByCA = false
        var trustError: String?
        var text = ""
        var error: String?
        var ms = 0
        var status: Int? {
            guard text.hasPrefix("HTTP/") else { return nil }
            let parts = text.split(separator: " ", maxSplits: 2)
            return parts.count > 1 ? Int(parts[1]) : nil
        }
    }

    static func get(net: E2ENet, ip: String, port: UInt16 = 443, sni: String, path: String, caDER: Data?, timeout: TimeInterval = 15) -> Result {
        var res = Result()
        let t0 = Date()
        let q = DispatchQueue(label: "e2e.tls.relay")
        let listener = NCLoopbackListener(queue: q)
        let relayUp = E2EHarness.Flag()
        var keep: [AnyObject] = []
        let keepLock = NSLock()
        listener.onAccept = { conn in
            keepLock.lock(); keep.append(conn); keepLock.unlock()
            guard let flow = net.connect(ip, port) else { conn.cancel(); return }
            keepLock.lock(); keep.append(flow); keepLock.unlock()
            DispatchQueue.global().async {
                guard E2ENet.waitUntil(5, { flow.established || flow.reset }), flow.established else {
                    relayUp.set(2)
                    conn.cancel()
                    return
                }
                relayUp.set(1)
                flow.onData = { d in conn.send(content: d, completion: .idempotent) }
                flow.onEnd = { _ in conn.cancel() }
                func pump() {
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, eof, err in
                        if let data, !data.isEmpty { flow.send(data) }
                        if eof || err != nil { flow.close(); return }
                        pump()
                    }
                }
                pump()
            }
        }
        if let why = listener.start(port: 0) {
            res.error = "relay listener: \(why)"
            return res
        }
        defer { q.sync { listener.stop() } }
        let ca = caDER.flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, sni)
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        let trustBox = EResultBox()
        sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
            guard let ca else { trustBox.set(false, "no CA"); complete(false); return }
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, sni as CFString))
            SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var err: CFError?
            let ok = SecTrustEvaluateWithError(trust, &err)
            trustBox.set(ok, err.map { ($0 as Error).localizedDescription })
            complete(ok)
        }, q)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: listener.port)!, using: params)
        let state = E2EHarness.Flag()
        let failure = E2EController.StringBox()
        let buf = DataBox()
        conn.stateUpdateHandler = { st in
            switch st {
            case .ready: state.set(1)
            case .failed(let e): failure.set("\(e)"); state.set(2)
            case .waiting(let e): failure.set("waiting: \(e)"); state.set(2)
            default: break
            }
        }
        conn.start(queue: q)
        _ = E2ENet.waitUntil(min(timeout, 10)) { state.get() != 0 }
        res.relayEstablished = relayUp.get() == 1
        let tb = trustBox.get()
        res.trustedByCA = tb.ok
        res.trustError = tb.error
        guard state.get() == 1 else {
            res.error = failure.get() ?? "TLS handshake did not finish"
            res.ms = Int(Date().timeIntervalSince(t0) * 1000)
            conn.cancel()
            return res
        }
        res.handshake = true
        let req = "GET \(path) HTTP/1.1\r\nHost: \(sni)\r\nUser-Agent: TernE2E/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        conn.send(content: Data(req.utf8), completion: .contentProcessed { _ in })
        func recv() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, err in
                if let data { buf.append(data) }
                if done || err != nil { buf.finish(); return }
                recv()
            }
        }
        recv()
        _ = E2ENet.waitUntil(timeout) { buf.finished || Self.complete(buf.data) }
        conn.cancel()
        res.text = String(decoding: buf.data, as: UTF8.self)
        res.ms = Int(Date().timeIntervalSince(t0) * 1000)
        keepLock.lock(); keep.removeAll(); keepLock.unlock()
        return res
    }

    /// Headers plus Content-Length bytes of body received.
    private static func complete(_ d: Data) -> Bool {
        guard let r = d.range(of: Data("\r\n\r\n".utf8)) else { return false }
        let head = String(decoding: d[..<r.lowerBound], as: UTF8.self).lowercased()
        for line in head.split(separator: "\r\n") where line.hasPrefix("content-length:") {
            if let n = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) {
                return d.count - r.upperBound >= n
            }
        }
        return false
    }

    final class DataBox {
        private let lock = NSLock(); private var d = Data(); private var f = false
        func append(_ x: Data) { lock.lock(); d.append(x); lock.unlock() }
        func finish() { lock.lock(); f = true; lock.unlock() }
        var data: Data { lock.lock(); defer { lock.unlock() }; return d }
        var finished: Bool { lock.lock(); defer { lock.unlock() }; return f }
    }
    final class EResultBox {
        private let lock = NSLock(); private var ok = false; private var e: String?; private var set_ = false
        func set(_ o: Bool, _ err: String?) { lock.lock(); if !set_ { ok = o; e = err; set_ = true }; lock.unlock() }
        func get() -> (ok: Bool, error: String?) { lock.lock(); defer { lock.unlock() }; return (ok, e) }
    }
}

/// Footprint of this process every 100 ms while the replay runs (phys_footprint, as jetsam counts it).
final class E2EMemory {
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private(set) var baseline: UInt64 = 0
    private var peak: UInt64 = 0

    func start() {
        baseline = ProcessMemory.footprintBytes()
        peak = baseline
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "e2e.mem"))
        t.schedule(deadline: .now() + 0.1, repeating: 0.1)
        t.setEventHandler { [weak self] in
            let f = ProcessMemory.footprintBytes()
            self?.lock.lock(); if f > self?.peak ?? 0 { self?.peak = f }; self?.lock.unlock()
        }
        t.resume()
        timer = t
    }

    /// fix/nc-e2e-real: a named reading — current footprint and the peak so far, both minus the baseline (MB).
    private(set) var checkpoints: [(label: String, nowMB: Double, peakMB: Double)] = []
    @discardableResult
    func checkpoint(_ label: String) -> (nowMB: Double, peakMB: Double) {
        let f = ProcessMemory.footprintBytes()
        lock.lock(); if f > peak { peak = f }; let p = peak; lock.unlock()
        let b = Double(baseline)
        let c = (nowMB: (Double(f) - b) / 1_048_576, peakMB: (Double(p) - b) / 1_048_576)
        checkpoints.append((label, c.nowMB, c.peakMB))
        return c
    }

    var checkpointLine: String {
        checkpoints.map { String(format: "%@ +%.1f (peak +%.1f)", $0.label, $0.nowMB, $0.peakMB) }.joined(separator: ", ")
    }

    func stop() -> (baselineMB: Double, peakMB: Double, deltaMB: Double) {
        timer?.cancel(); timer = nil
        lock.lock(); let p = max(peak, ProcessMemory.footprintBytes()); lock.unlock()
        let b = Double(baseline) / 1_048_576, pk = Double(p) / 1_048_576
        return (b, pk, pk - b)
    }
}
