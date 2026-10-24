import Darwin
import Network
import Security
import XCTest
@testable import Mihomo

/// Process-wide memory readings for the native MitM footprint work (feat/native-slim).
enum FootprintProbe {
    /// Bytes in use across every malloc zone (Swift objects, Network.framework / boringssl / Security allocations;
    /// not Go, not thread stacks).
    static func mallocInUse() -> Int {
        var s = malloc_statistics_t()
        malloc_zone_statistics(nil, &s)
        return Int(s.size_in_use)
    }

    static func threadCount() -> Int {
        var list: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS, let list else { return -1 }
        for i in 0..<Int(count) { mach_port_deallocate(mach_task_self_, list[i]) }
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: list)), vm_size_t(Int(count) * MemoryLayout<thread_act_t>.stride))
        return Int(count)
    }

    /// Returns free malloc pages to the OS, so "after teardown" shows what is still held, not what is cached.
    static func relieve() { _ = malloc_zone_pressure_relief(nil, 0) }
}

/// feat/native-slim: what one native MitM session's pieces cost, each measured alone (100 units, idle 1 s, whole
/// process phys_footprint + malloc + threads, 1 warm-up + 3 counted runs, medians). Pieces:
///   - dispatch: 100 own serial queues vs 100 queues on one shared target, each blocking 50 ms (a Go call);
///   - loopback pairs: NWListener + NWConnection, plain TCP vs TLS (the native front's server side + a TLS client),
///     with / without a pending receive of 64 KB / 16 KB on the server side;
///   - upstream: TLS NWConnection to the origin through the Go relay's CONNECT proxy, one PrivacyContext per
///     connection vs one shared;
///   - leaf identities: 100 SecPKCS12Import'ed hosts;
///   - alternative TLS stack: SecureTransport server contexts on plain BSD sockets (no NWConnection on the server
///     side), against NW TLS pairs pinned to TLS 1.2 so both sides match.
/// Prints "[s2-attr]" rows; asserts only that the setups worked.
@available(iOS 17.0, *)
final class NativeMitmFootprintTests: XCTestCase {
    static let n = 100

    struct Sample { var fp: Int64; var malloc: Int64; var threads: Int64; var residual: Int64; var goHeap: Int64; var ok: Int }

    private var benchStarted = false

    override func setUpWithError() throws {
        struct Start: Decodable { var enginePort: Int?; var error: String? }
        let st = try JSONDecoder().decode(Start.self, from: Data(NativeMitmBench.start().utf8))
        guard st.enginePort != nil, st.error == nil else { throw XCTSkip("bench engine: \(st.error ?? "?")") }
        benchStarted = true
    }

    override func tearDown() {
        if benchStarted { NativeMitmBench.stop() }
        UpstreamConnection.trustAnyOriginForTesting = false
    }

    private func goHeap() -> Int64 {
        struct M: Decodable { var heapInuse: Int64 }
        return (try? JSONDecoder().decode(M.self, from: Data(NativeMitmBench.goMemory().utf8)).heapInuse) ?? 0
    }

    /// setup returns (units that worked, teardown).
    private func attr(_ name: String, unit: String = "conn", _ setup: () throws -> (Int, () -> Void)) rethrows -> Sample {
        var samples: [Sample] = []
        for round in 0..<4 {
            Thread.sleep(forTimeInterval: 0.3)
            FootprintProbe.relieve()
            let fp0 = Int64(ProcessMemory.footprintBytes()), m0 = Int64(FootprintProbe.mallocInUse())
            let t0 = Int64(FootprintProbe.threadCount()), g0 = goHeap()
            let (ok, teardown) = try setup()
            Thread.sleep(forTimeInterval: 1.0)
            let fp1 = Int64(ProcessMemory.footprintBytes()), m1 = Int64(FootprintProbe.mallocInUse())
            let t1 = Int64(FootprintProbe.threadCount()), g1 = goHeap()
            teardown()
            Thread.sleep(forTimeInterval: 1.0)
            FootprintProbe.relieve()
            let fp2 = Int64(ProcessMemory.footprintBytes())
            if round > 0 { samples.append(Sample(fp: fp1 - fp0, malloc: m1 - m0, threads: t1 - t0, residual: fp2 - fp0, goHeap: g1 - g0, ok: ok)) }
        }
        func med(_ f: (Sample) -> Int64) -> Int64 { let v = samples.map(f).sorted(); return v[v.count / 2] }
        let s = Sample(fp: med(\.fp), malloc: med(\.malloc), threads: med(\.threads), residual: med(\.residual),
                       goHeap: med(\.goHeap), ok: samples.map(\.ok).min() ?? 0)
        let kb = { (b: Int64) in String(format: "%+.1f", Double(b) / 1024 / Double(Self.n)) }
        let mb = { (b: Int64) in String(format: "%+.2f", Double(b) / 1_048_576) }
        let line = "[s2-attr] \(name.padding(toLength: 30, withPad: " ", startingAt: 0)) footprint \(kb(s.fp)) KB/\(unit) (\(mb(s.fp)) MB) | malloc \(kb(s.malloc)) KB/\(unit) | threads \(s.threads >= 0 ? "+" : "")\(s.threads) | after teardown \(mb(s.residual)) MB | Go heap \(mb(s.goHeap)) MB | ok \(s.ok)/\(Self.n)"
        print(line)
        NSLog("%@", line)
        return s
    }

    private func identity() throws -> SecIdentity {
        switch LeafIdentityCache().identity(for: "api.bench.test") {
        case .success(let l): return l.identity
        case .failure(let e): throw XCTSkip("bench leaf identity: \(e)")
        }
    }

    func testAttributePerSessionFootprint() throws {
        let id = try identity()
        print("[s2-attr] per-unit costs, \(Self.n) units each, idle 1 s, medians of 3 (whole-process phys_footprint)")

        // 1. dispatch queues with a blocking call each (the session's Go calls)
        let ownQ = attr("dispatch: own serial queues", unit: "queue") { (dispatchBurst(shared: false), {}) }
        let sharedQ = attr("dispatch: shared target", unit: "queue") { (dispatchBurst(shared: true), {}) }

        // 2. loopback pairs (client + server NWConnection each)
        let tcp = try attr("pair: TCP (NW both sides)") { try LoopbackPairs.make(n: Self.n, identity: nil).result() }
        let tls = try attr("pair: TLS (NW both sides)") { try LoopbackPairs.make(n: Self.n, identity: id).result() }
        let tls64 = try attr("pair: TLS + server recv 64 KB") { try LoopbackPairs.make(n: Self.n, identity: id, serverRecv: 64 << 10).result() }
        let tls16 = try attr("pair: TLS + server recv 16 KB") { try LoopbackPairs.make(n: Self.n, identity: id, serverRecv: 16 << 10).result() }
        let tls12 = try attr("pair: TLS1.2 (NW both sides)") { try LoopbackPairs.make(n: Self.n, identity: id, tls12: true).result() }
        let st = try attr("pair: TLS1.2 SecureTransport srv") { try SecureTransportPairs.make(n: Self.n, identity: id).result() }

        // 3. upstream through the Go relay (TLS to the bench origin)
        UpstreamConnection.trustAnyOriginForTesting = true
        let relay = NativeMitmBench.relayPort()
        XCTAssertGreaterThan(relay, 0, "relay port")
        let upOwn = attr("upstream: own PrivacyContext") { RelayUpstreams.make(n: Self.n, relay: relay, shared: false).result() }
        let upShared = attr("upstream: shared PrivacyContext") { RelayUpstreams.make(n: Self.n, relay: relay, shared: true).result() }

        // 4. leaf identities
        let ids = attr("leaf identities (SecPKCS12Import)", unit: "host") {
            let cache = LeafIdentityCache(maxCount: 1000, maxBytes: 64 << 20)
            var ok = 0
            for i in 0..<Self.n { if case .success = cache.identity(for: "h\(i).bench.test") { ok += 1 } }
            return (ok, { cache.cache.removeAll() })
        }

        let kb = { (b: Int64) in String(format: "%+.1f KB", Double(b) / 1024 / Double(Self.n)) }
        let derived = [
            "TLS over plain TCP, both ends (pair TLS − pair TCP): \(kb(tls.fp - tcp.fp)) per pair",
            "one NW TCP pair (client+server NWConnection): \(kb(tcp.fp))",
            "pending 64 KB server receive: \(kb(tls64.fp - tls.fp)); 16 KB: \(kb(tls16.fp - tls.fp))",
            "SecureTransport server on a BSD socket vs NW TLS server (TLS 1.2 pairs): \(kb(st.fp - tls12.fp)) per conn",
            "shared vs own session queue: \(kb(sharedQ.fp - ownQ.fp)) per session, threads \(sharedQ.threads) vs \(ownQ.threads)",
            "shared vs own PrivacyContext: \(kb(upShared.fp - upOwn.fp)) per upstream",
            "leaf identity: \(kb(ids.fp)) per host",
        ]
        for d in derived { print("[s2-attr] derived: \(d)"); NSLog("[s2-attr] derived: %@", d) }

        XCTAssertGreaterThanOrEqual(tcp.ok, Self.n * 9 / 10, "TCP pairs")
        XCTAssertGreaterThanOrEqual(tls.ok, Self.n * 9 / 10, "TLS pairs")
        XCTAssertGreaterThanOrEqual(upShared.ok, Self.n * 9 / 10, "relay upstreams")
    }

    private func dispatchBurst(shared: Bool) -> Int {
        var qs: [DispatchQueue] = []
        let g = DispatchGroup()
        for i in 0..<Self.n {
            let q = shared ? DispatchQueue(label: "test.fp.q", target: NativeMitmRuntime.sessionTarget)
                           : DispatchQueue(label: "test.fp.q.\(i)")
            qs.append(q)
            g.enter()
            q.async { usleep(50_000); g.leave() }
        }
        let ok = g.wait(timeout: .now() + 30) == .success
        _ = qs
        return ok ? Self.n : 0
    }
}

// MARK: - loopback NW pairs

@available(iOS 17.0, *)
final class LoopbackPairs {
    private let q = DispatchQueue(label: "test.fp.pairs")
    private var listener: NWListener?
    private var servers: [NWConnection] = [] // q-confined
    private var clients: [NWConnection] = []
    private let lock = NSLock()
    private var ready = 0

    static func make(n: Int, identity: SecIdentity?, serverRecv: Int? = nil, tls12: Bool = false) throws -> LoopbackPairs {
        let p = LoopbackPairs()
        try p.start(n: n, identity: identity, serverRecv: serverRecv, tls12: tls12)
        return p
    }

    func result() -> (Int, () -> Void) {
        lock.lock(); let ok = ready; lock.unlock()
        return (ok, { self.close() })
    }

    private func start(n: Int, identity: SecIdentity?, serverRecv: Int?, tls12: Bool) throws {
        let params: NWParameters
        if let identity {
            guard let o = MitmTLSFront.tlsOptions(identity: identity) else { throw XCTSkip("tls options") }
            params = NWParameters(tls: o, tcp: NWProtocolTCP.Options())
        } else {
            params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        }
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let l = try NWListener(using: params)
        listener = l
        let up = DispatchSemaphore(value: 0)
        l.stateUpdateHandler = { st in if case .ready = st { up.signal() } }
        l.newConnectionHandler = { [weak self] c in
            guard let self else { c.cancel(); return }
            self.servers.append(c)
            c.stateUpdateHandler = { st in
                if case .ready = st, let m = serverRecv { c.receive(minimumIncompleteLength: 1, maximumLength: m) { _, _, _, _ in } }
            }
            c.start(queue: self.q)
        }
        l.start(queue: q)
        guard up.wait(timeout: .now() + 5) == .success, let port = l.port else { throw XCTSkip("listener did not start") }
        let g = DispatchGroup()
        for _ in 0..<n {
            let cp: NWParameters
            if identity != nil {
                let t = NWProtocolTLS.Options()
                let sec = t.securityProtocolOptions
                sec_protocol_options_set_tls_server_name(sec, "api.bench.test")
                sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
                if tls12 { sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv12) }
                sec_protocol_options_set_verify_block(sec, { _, _, done in done(true) }, q)
                cp = NWParameters(tls: t, tcp: NWProtocolTCP.Options())
            } else {
                cp = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
            }
            let c = NWConnection(host: "127.0.0.1", port: port, using: cp)
            g.enter()
            var once = false // q-confined
            c.stateUpdateHandler = { [weak self] st in
                switch st {
                case .ready, .failed, .cancelled, .waiting:
                    if once { return }
                    once = true
                    if case .ready = st, let self { self.lock.lock(); self.ready += 1; self.lock.unlock() }
                    g.leave()
                default: break
                }
            }
            c.start(queue: q)
            clients.append(c)
        }
        _ = g.wait(timeout: .now() + 30)
    }

    private func close() {
        for c in clients { c.cancel() }
        clients.removeAll()
        q.sync {
            for s in servers { s.cancel() }
            servers.removeAll()
        }
        listener?.cancel()
        listener = nil
    }
}

// MARK: - SecureTransport server on BSD sockets (alternative TLS stack, no NWConnection server side)

@available(iOS 17.0, *)
final class SecureTransportPairs {
    private var fds: [Int32] = []
    private var contexts: [SSLContext] = []
    private var clients: [NWConnection] = []
    private var listenFD: Int32 = -1
    private var handshaken = 0
    private let q = DispatchQueue(label: "test.fp.st.clients")

    static func make(n: Int, identity: SecIdentity) throws -> SecureTransportPairs {
        let p = SecureTransportPairs()
        try p.start(n: n, identity: identity)
        return p
    }

    func result() -> (Int, () -> Void) { (handshaken, { self.close() }) }

    private static let readFn: SSLReadFunc = { conn, data, len in
        let fd = Int32(Int(bitPattern: conn))
        let want = len.pointee
        var got = 0
        while got < want {
            let r = Darwin.read(fd, data + got, want - got)
            if r > 0 { got += r; continue }
            len.pointee = got
            return r == 0 ? errSSLClosedGraceful : errSSLClosedAbort
        }
        len.pointee = got
        return errSecSuccess
    }

    private static let writeFn: SSLWriteFunc = { conn, data, len in
        let fd = Int32(Int(bitPattern: conn))
        let want = len.pointee
        var put = 0
        while put < want {
            let r = Darwin.write(fd, data + put, want - put)
            if r > 0 { put += r; continue }
            len.pointee = put
            return errSSLClosedAbort
        }
        len.pointee = put
        return errSecSuccess
    }

    private func start(n: Int, identity: SecIdentity) throws {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { throw XCTSkip("socket") }
        listenFD = s
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, Darwin.listen(s, 128) == 0 else { throw XCTSkip("bind/listen") }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        let port = UInt16(bigEndian: addr.sin_port)

        // server: accept + handshake one at a time on a plain thread (blocking sockets)
        let done = DispatchSemaphore(value: 0)
        let server = Thread { [self] in
            for _ in 0..<n {
                let fd = accept(s, nil, nil)
                if fd < 0 { break }
                guard let ctx = SSLCreateContext(nil, .serverSide, .streamType) else { Darwin.close(fd); continue }
                SSLSetIOFuncs(ctx, Self.readFn, Self.writeFn)
                SSLSetConnection(ctx, UnsafeRawPointer(bitPattern: Int(fd)))
                SSLSetCertificate(ctx, [identity] as CFArray)
                SSLSetProtocolVersionMax(ctx, .tlsProtocol12)
                var st: OSStatus = errSSLWouldBlock
                var tries = 0
                repeat { st = SSLHandshake(ctx); tries += 1 } while st == errSSLWouldBlock && tries < 50
                fds.append(fd)
                contexts.append(ctx)
                if st == errSecSuccess { handshaken += 1 }
            }
            done.signal()
        }
        server.start()

        for _ in 0..<n {
            let t = NWProtocolTLS.Options()
            let sec = t.securityProtocolOptions
            sec_protocol_options_set_tls_server_name(sec, "api.bench.test")
            sec_protocol_options_set_max_tls_protocol_version(sec, .TLSv12)
            sec_protocol_options_set_verify_block(sec, { _, _, ok in ok(true) }, q)
            let c = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: NWParameters(tls: t, tcp: NWProtocolTCP.Options()))
            c.start(queue: q)
            clients.append(c)
        }
        if done.wait(timeout: .now() + 30) == .timedOut {
            Darwin.shutdown(s, SHUT_RDWR) // unblocks accept
            _ = done.wait(timeout: .now() + 5)
        }
    }

    private func close() {
        for c in clients { c.cancel() }
        clients.removeAll()
        for ctx in contexts { SSLClose(ctx) }
        contexts.removeAll()
        for fd in fds { Darwin.close(fd) }
        fds.removeAll()
        if listenFD >= 0 { Darwin.close(listenFD); listenFD = -1 }
    }
}

// MARK: - upstream TLS connections through the Go relay

@available(iOS 17.0, *)
final class RelayUpstreams {
    private let q = DispatchQueue(label: "test.fp.relay")
    private var conns: [NWConnection] = []
    private var ready = 0
    private let lock = NSLock()

    static func make(n: Int, relay: Int, shared: Bool) -> RelayUpstreams {
        let r = RelayUpstreams()
        r.start(n: n, relay: relay, shared: shared)
        return r
    }

    func result() -> (Int, () -> Void) {
        lock.lock(); let ok = ready; lock.unlock()
        return (ok, { for c in self.conns { c.cancel() }; self.conns.removeAll() })
    }

    private func start(n: Int, relay: Int, shared: Bool) {
        guard let rport = NWEndpoint.Port(rawValue: UInt16(relay)) else { return }
        let saved = NativeMitmRuntime.slim
        var s = saved; s.sharedPrivacyContext = shared
        NativeMitmRuntime.slim = s
        defer { NativeMitmRuntime.slim = saved }
        let g = DispatchGroup()
        for _ in 0..<n {
            let t = NWProtocolTLS.Options()
            let sec = t.securityProtocolOptions
            sec_protocol_options_set_tls_server_name(sec, "api.bench.test")
            sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
            sec_protocol_options_set_verify_block(sec, { _, _, ok in ok(true) }, q)
            let p = NWParameters(tls: t, tcp: NWProtocolTCP.Options())
            p.setPrivacyContext(UpstreamConnection.privacyContext(relay: rport))
            let c = NWConnection(host: "api.bench.test", port: 443, using: p)
            g.enter()
            var once = false
            c.stateUpdateHandler = { [weak self] st in
                switch st {
                case .ready, .failed, .cancelled, .waiting:
                    if once { return }
                    once = true
                    if case .ready = st, let self { self.lock.lock(); self.ready += 1; self.lock.unlock() }
                    g.leave()
                default: break
                }
            }
            c.start(queue: q)
            conns.append(c)
        }
        _ = g.wait(timeout: .now() + 30)
    }
}
