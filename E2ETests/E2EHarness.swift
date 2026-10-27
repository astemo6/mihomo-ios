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
        NCConnector.installMASQUEIPDialer()
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

    /// fix/nc-mem-2: one autorelease pool per request (see E2ENet.waitUntil) — the URLSession task, request and
    /// response objects of a call are gone when it returns instead of piling up until the test method ends.
    func call(_ method: String, _ path: String, query: [String: String] = [:], body: Any? = nil, timeout: TimeInterval = 15) -> Reply {
        autoreleasepool { callUnpooled(method, path, query: query, body: body, timeout: timeout) }
    }

    private func callUnpooled(_ method: String, _ path: String, query: [String: String], body: Any?, timeout: TimeInterval) -> Reply {
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
    /// fix/nc-mem-2: when the peak was sampled and the malloc heap in use at the baseline — so a reading says which
    /// phase the peak fell in and how much of a delta is live heap (vs. pages malloc / frameworks keep).
    private var started = Date()
    private var peakAt = Date()
    private var baselineHeap: UInt64 = 0

    static func heapInUse() -> UInt64 {
        var st = malloc_statistics_t()
        malloc_zone_statistics(nil, &st)
        return UInt64(st.size_in_use)
    }

    /// fix/nc-mem-4: the kernel's lifetime peak (ledger_phys_footprint_peak) when the window opened. The 100 ms sampler
    /// misses short transients (gate 3a: sampled +40.9 MB while the kernel peak was +65.6 MB), so each checkpoint also
    /// records the kernel peak minus the baseline, and the gate is judged on that.
    private(set) var kernelPeakAtStart: UInt64 = 0

    /// fix/nc-mem-4: one `[nc-mem] scene=e2e:<label>` line in the stage-2 log (footprint + kernel peak), so the test's
    /// own steps sit on the same timeline as the core's `[nc-mem]` lines.
    static func mark(_ label: String) {
        let fp = Double(ProcessMemory.footprintBytes()) / 1_048_576, pk = Double(ProcessMemory.peakBytes()) / 1_048_576
        NSLog("[nc-mem] scene=e2e:%@ footprint=%.1fMB peak=%.1fMB heap=%.1fMB", label, fp, pk, Double(heapInUse()) / 1_048_576)
    }

    func start() {
        baseline = ProcessMemory.footprintBytes()
        kernelPeakAtStart = ProcessMemory.peakBytes()
        baselineHeap = Self.heapInUse()
        peak = baseline
        started = Date(); peakAt = started
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "e2e.mem"))
        t.schedule(deadline: .now() + 0.1, repeating: 0.1)
        t.setEventHandler { [weak self] in
            guard let self else { return }
            let f = ProcessMemory.footprintBytes()
            self.lock.lock(); if f > self.peak { self.peak = f; self.peakAt = Date() }; self.lock.unlock()
        }
        t.resume()
        timer = t
    }

    /// fix/nc-e2e-real: a named reading — current footprint and the peak so far, both minus the baseline (MB).
    private(set) var checkpoints: [(label: String, nowMB: Double, peakMB: Double, heapMB: Double, at: Double, kpeakMB: Double)] = []
    /// `kpeakMB`: kernel lifetime peak minus the baseline (fix/nc-mem-4) — catches what the 100 ms sampler misses.
    @discardableResult
    func checkpoint(_ label: String) -> (nowMB: Double, peakMB: Double, kpeakMB: Double) {
        let f = ProcessMemory.footprintBytes()
        let k = ProcessMemory.peakBytes()
        let h = Self.heapInUse()
        lock.lock(); if f > peak { peak = f; peakAt = Date() }; let p = peak; lock.unlock()
        let b = Double(baseline)
        let c = (nowMB: (Double(f) - b) / 1_048_576, peakMB: (Double(p) - b) / 1_048_576, kpeakMB: (Double(max(k, p)) - b) / 1_048_576)
        checkpoints.append((label, c.nowMB, c.peakMB, (Double(h) - Double(baselineHeap)) / 1_048_576,
                            Date().timeIntervalSince(started), c.kpeakMB))
        Self.mark("checkpoint-" + label)
        return c
    }

    var checkpointLine: String {
        lock.lock(); let pAt = peakAt.timeIntervalSince(started); lock.unlock()
        let phase = checkpoints.first { $0.at >= pAt }?.label ?? "after the last checkpoint"
        let rows = checkpoints.map { String(format: "%@ +%.1f (peak +%.1f, kernel peak +%.1f, heap %+.1f, t+%.0fs)", $0.label, $0.nowMB, $0.peakMB, $0.kpeakMB, $0.heapMB, $0.at) }
        let pre = (Double(kernelPeakAtStart) - Double(baseline)) / 1_048_576
        return rows.joined(separator: ", ") + String(format: "; peak sampled at t+%.1fs (phase %@); kernel peak at window start +%.1f", pAt, phase, pre)
    }

    func stop() -> (baselineMB: Double, peakMB: Double, deltaMB: Double, kpeakMB: Double) {
        timer?.cancel(); timer = nil
        lock.lock(); let p = max(peak, ProcessMemory.footprintBytes()); lock.unlock()
        let b = Double(baseline) / 1_048_576, pk = Double(p) / 1_048_576
        let k = Double(max(ProcessMemory.peakBytes(), p)) / 1_048_576
        return (b, pk, pk - b, k)
    }
}

/// fix/nc-mem-4 (diagnostic): run 40419441795 showed the +55 MB transient in a 2 s window where the test's main thread
/// did not come back from a 21 ms controller call and no core work was counted (no probes, no controller request,
/// no new NCStream); the footprint fell back the moment the main thread resumed. This watches the main thread from a
/// background thread and logs what it is doing:
///   * main-thread stall ≥ 300 ms → `[nc-mem] scene=e2e:main-stall` + the main thread's frame-pointer backtrace,
///   * footprint up ≥ 8 MB since the last dump → `[nc-mem] scene=e2e:jump` + every thread's top frames (≤ 4 dumps).
/// Threads are suspended only while their registers / frame chain are read (no locks, no allocation in that window);
/// symbols are resolved with dladdr after resuming.
final class E2EStackWatch {
    private var mainPort: thread_act_t = 0
    private var beat: UInt64 = 0          // bumped by a main run-loop observer
    private let lock = NSLock()
    private var observer: CFRunLoopObserver?
    private var timer: DispatchSourceTimer?
    private var lastBeat: UInt64 = 0
    private var lastBeatAt = DispatchTime.now()
    private var stallsLogged = 0
    private var stallDumpedFor: UInt64 = .max
    private var lastDumpFootprint: UInt64 = 0
    private var jumpsLogged = 0
    private let frames = UnsafeMutablePointer<UInt>.allocate(capacity: 64)

    /// Call on the main thread.
    func start() {
        mainPort = mach_thread_self()
        lastDumpFootprint = ProcessMemory.footprintBytes()
        let obs = CFRunLoopObserverCreateWithHandler(nil, CFRunLoopActivity.allActivities.rawValue, true, 0) { [weak self] _, _ in
            guard let self else { return }
            self.lock.lock(); self.beat &+= 1; self.lock.unlock()
        }
        CFRunLoopAddObserver(CFRunLoopGetMain(), obs, .commonModes)
        observer = obs
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "e2e.stackwatch", qos: .userInteractive))
        t.schedule(deadline: .now() + 0.05, repeating: 0.05)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    func stop() {
        timer?.cancel(); timer = nil
        if let o = observer { CFRunLoopRemoveObserver(CFRunLoopGetMain(), o, .commonModes) }
        observer = nil
    }

    private func tick() {
        lock.lock(); let b = beat; lock.unlock()
        let now = DispatchTime.now()
        if b != lastBeat { lastBeat = b; lastBeatAt = now }
        let stalledMs = Int((now.uptimeNanoseconds - lastBeatAt.uptimeNanoseconds) / 1_000_000)
        let fp = ProcessMemory.footprintBytes()
        // Main thread inside one callout for ≥ 300 ms: dump it (at most twice per stall, 12 stalls in all).
        if stalledMs >= 300, stallsLogged < 24, stallDumpedFor != b || stalledMs % 1000 < 50 {
            stallDumpedFor = b
            stallsLogged += 1
            let st = backtrace(mainPort)
            // main asleep in its run loop (no observer callbacks while it waits) is not a stall
            if st.contains("__CFRunLoopServiceMachPort") { return }
            NSLog("[nc-mem] scene=e2e:main-stall ms=%d footprint=%.1fMB peak=%.1fMB main: %@", stalledMs,
                  Double(fp) / 1_048_576, Double(ProcessMemory.peakBytes()) / 1_048_576, String(st.prefix(700)))
            // NSLog cuts a message at ~1 KB: the outer frames (who called) on their own line
            let outer = st.components(separatedBy: " < ").suffix(10).joined(separator: " < ")
            NSLog("[nc-mem] scene=e2e:main-stall-outer %@", String(outer.suffix(900)))
        }
        if fp > lastDumpFootprint &+ (8 << 20), jumpsLogged < 4 {
            jumpsLogged += 1
            lastDumpFootprint = fp
            dumpAll(reason: String(format: "footprint %.1fMB", Double(fp) / 1_048_576))
        } else if fp < lastDumpFootprint {
            lastDumpFootprint = max(fp, lastDumpFootprint &- (8 << 20))
        }
    }

    private func dumpAll(reason: String) {
        var list: thread_act_array_t?
        var n: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &n) == KERN_SUCCESS, let list else { return }
        let me = mach_thread_self()
        var out: [String] = []
        for i in 0..<Int(n) {
            let t = list[i]
            if t == me { continue }
            let s = backtrace(t, max: t == mainPort ? 60 : 14)
            if !s.isEmpty { out.append("T\(i)\(t == mainPort ? "(main)" : ""): \(s.prefix(800))") }
            if t == mainPort, !s.isEmpty {
                out.append("T\(i)(main, outer): " + s.components(separatedBy: " < ").suffix(10).joined(separator: " < ").suffix(900))
            }
        }
        for i in 0..<Int(n) { mach_port_deallocate(mach_task_self_, list[i]) }
        mach_port_deallocate(mach_task_self_, me)
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: list)), vm_size_t(Int(n) * MemoryLayout<thread_act_t>.stride))
        NSLog("[nc-mem] scene=e2e:jump %@ peak=%.1fMB threads=%d", reason, Double(ProcessMemory.peakBytes()) / 1_048_576, Int(n))
        for l in out { NSLog("[nc-mem] scene=e2e:jump-thread %@", l) }
    }

    /// Frame-pointer walk of a suspended thread; symbolized after resume.
    private func backtrace(_ t: thread_act_t, max limit: Int = 60) -> String {
        guard t != 0 else { return "" }
        var lo: UInt = 0, hi: UInt = 0
        if let pt = pthread_from_mach_thread_np(t) {
            hi = UInt(bitPattern: pthread_get_stackaddr_np(pt))
            lo = hi &- UInt(pthread_get_stacksize_np(pt))
        }
        guard thread_suspend(t) == KERN_SUCCESS else { return "" }
        var count = 0
        #if arch(arm64)
        var st = arm_thread_state64_t()
        var c = mach_msg_type_number_t(MemoryLayout<arm_thread_state64_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &st) {
            $0.withMemoryRebound(to: natural_t.self, capacity: Int(c)) { thread_get_state(t, thread_state_flavor_t(6), $0, &c) }
        }
        if kr == KERN_SUCCESS {
            frames[0] = UInt(st.__pc); frames[1] = UInt(st.__lr); count = 2
            var fp = UInt(st.__fp)
            while count < limit, fp != 0, fp & 7 == 0, lo == 0 || (fp >= lo && fp + 16 <= hi) {
                let p = UnsafePointer<UInt>(bitPattern: fp)!
                let ret = p[1], next = p[0]
                if ret == 0 { break }
                frames[count] = ret; count += 1
                if next <= fp { break }
                fp = next
            }
        }
        #elseif arch(x86_64)
        var st = x86_thread_state64_t()
        var c = mach_msg_type_number_t(MemoryLayout<x86_thread_state64_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &st) {
            $0.withMemoryRebound(to: natural_t.self, capacity: Int(c)) { thread_get_state(t, thread_state_flavor_t(4), $0, &c) }
        }
        if kr == KERN_SUCCESS {
            frames[0] = UInt(st.__rip); count = 1
            var fp = UInt(st.__rbp)
            while count < limit, fp != 0, fp & 7 == 0, lo == 0 || (fp >= lo && fp + 16 <= hi) {
                let p = UnsafePointer<UInt>(bitPattern: fp)!
                let ret = p[1], next = p[0]
                if ret == 0 { break }
                frames[count] = ret; count += 1
                if next <= fp { break }
                fp = next
            }
        }
        #endif
        thread_resume(t)
        var parts: [String] = []
        for i in 0..<count {
            var info = Dl_info()
            let pc = frames[i]
            if dladdr(UnsafeRawPointer(bitPattern: pc), &info) != 0 {
                let img = info.dli_fname.map { (String(cString: $0) as NSString).lastPathComponent } ?? "?"
                let sym = info.dli_sname.map { String(cString: $0) } ?? "?"
                let off = pc &- UInt(bitPattern: info.dli_saddr)
                parts.append("\(img)`\(sym.prefix(110))+\(off)")
            } else {
                parts.append(String(format: "0x%lx", pc))
            }
        }
        return parts.joined(separator: " < ")
    }
}
