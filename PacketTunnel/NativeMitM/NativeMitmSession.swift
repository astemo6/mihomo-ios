// native-only (nc-integrate): one build of this file — the NativeCore tunnel; the app target compiles the same code
// for its unit tests (tunnel-engine calls behind TERN_TUNNEL). The old-core variant is gone with the retired bridge
// Native MitM STAGE 2 — B9: one decrypted MitM connection, end to end (lane `wire`).
//
//   old engine (nativeterm: peek ClientHello, MitM host list, pinning memory) → MitmTLSFronting.listen →
//   TLS lane terminates TLS → acceptHandler → NativeMitmSession:
//     HTTPCodec parses the request head → MitmFlowDriving.requestPhase (the old core decided: rewrite / reject / redirect /
//     map local / request script / admission — nothing is decided here) → [request body pushed to the old core when asked]
//     → forward via MitmUpstreamConnecting (old relay → Tern rules/proxies) → response head → responsePhase
//     (the old core: header/body rewrites, response scripts, body lane) → body from upstream / the old core pipe / NativeBodyStore
//     → client. Keep-alive loop; pipelined bytes stay in the client buffer.
//
// Stage 3 lane s3-h2 (H2/NativeH2Session.swift): a connection whose TLS handshake negotiated h2 (offered only
// while the switch `nativeMitmH2` is on, default OFF) is served by NativeH2Session with the same driver.
//
// Stage 3a (Rewrite/NativeRewriteDriver.swift): the default driver asks the native rewrite engine first when the
// separate switch `nativeMitmRewrite` is on (default OFF); a native decision never reaches the old core, a deferral or the
// switch off goes to MitmFlowDriverAdapter exactly as before.
//
// Fallback: the session only exists after the old core handed the connection over (first byte from the TLS lane). Before
// that every failure is the old core's first-byte fallback. The runtime switch (NativeMitmRuntime, default
// `defaultOn`, iOS 17+; app-group key nativeMitmStage2 overrides) decides whether the TLS front is registered at all; when off, or past the session cap, listen() answers 0
// and the old core terminates TLS itself — the old path is the fallback for everything unsupported.
// After the handover an error answers 502 if no response byte went out yet, else cuts the connection (never a
// truncated body presented as complete).
//
// Cleanup: every exit goes through finish(); an active flow gets MitmFlowCancel (client gone) or MitmFlowEnd, which
// frees what the old core holds for it, including lane handles (never freed here). Leases go back non-reusable unless the
// exchange completed cleanly.

import Foundation

// MARK: - Upstream failure memory (fix/nc-diag-439)

/// build 439: every forwarded request of a MitM host answered 502 when its upstream failed, so the apps whose hosts
/// were decrypted (小红书 / YouTube / 喜马拉雅 modules) lost the network while every other app worked. QuanX / Surge keep
/// such an app online: a host that cannot be served through the decrypting path is connected without decryption.
/// Here: `threshold` upstream failures of one host within `window` seconds, with no successful response in between,
/// pass the host through (NCPinningMemory, reason stated) for `passFor` seconds — scripts / rewrites do not apply to it
/// meanwhile, but the app connects. One log line when it trips. Bounded (≤ 128 hosts).
enum NativeMitmUpstreamHealth {
    static var threshold = 3
    static var window: TimeInterval = 60
    static var passFor: TimeInterval = 600
    private static let lock = NSLock()
    private static var fails: [String: [TimeInterval]] = [:]

    /// Records one failure; true when this one tripped the pass-through.
    @discardableResult
    static func failure(host: String, why: String, now: TimeInterval = Date().timeIntervalSince1970,
                        pin: (String, String) -> Void = { h, r in NCPinningMemory.shared.markPinned(h, duration: passFor, reason: r) }) -> Bool {
        let h = NCPinningMemory.normalize(host)
        guard !h.isEmpty else { return false }
        lock.lock()
        var list = (fails[h] ?? []).filter { now - $0 < window }
        list.append(now)
        let trip = list.count >= threshold
        if trip { fails.removeValue(forKey: h) } else { fails[h] = list }
        if fails.count > 128 {
            for k in fails.filter({ ($0.value.last ?? 0) < now - window }).map({ $0.key }) { fails.removeValue(forKey: k) }
            if fails.count > 128 { fails.removeAll() }
        }
        lock.unlock()
        if trip {
            let reason = "upstream failing (\(threshold)× in \(Int(window)) s, last: \(why.prefix(120))) — passed through for \(Int(passFor / 60)) min, rewrites / scripts paused for it"
            pin(h, reason)
            NCDiagLimiter.shared.line("[MITM] \(h) → \(reason)", level: "warning")
        }
        return trip
    }

    static func success(host: String) {
        let h = NCPinningMemory.normalize(host)
        lock.lock(); fails.removeValue(forKey: h); lock.unlock()
    }

    static func reset() { lock.lock(); fails.removeAll(); lock.unlock() }

    /// Upstream-side failures (connect / TLS / read / closed before the head / head timeout).
    static func isUpstream(_ error: Error) -> Bool {
        switch error as? S2Error {
        case .upstream?: return true
        case .timeout(let what)?: return what == "upstream head" || what == "upstream connect"
        default: return false
        }
    }
}

// MARK: - Runtime switch

enum NativeMitmRuntime {
    /// App-group override key; an explicit value wins over `defaultOn`. iOS 17+ only (installDefault's caller).
    static let defaultsKey = "nativeMitmStage2"
    /// Default when the key is absent. OFF until the memory comparison (UnitTests/NativeMitmMemoryTests,
    /// the retired bridge) shows the native front lowering the tunnel's footprint.
    static let defaultOn = false
    static let appGroup = "group.com.astemo6.tern"

    static var enabled: Bool { enabled(in: UserDefaults(suiteName: appGroup)) }

    /// Absent key → `defaultOn`; an explicit value wins (false disables, true enables).
    static func enabled(in defaults: UserDefaults?) -> Bool {
        guard let defaults, defaults.object(forKey: defaultsKey) != nil else { return defaultOn }
        return defaults.bool(forKey: defaultsKey)
    }

    /// feat/selective-native: how the front is used. `.all` every eligible connection (nativeMitmStage2 on);
    /// `.selective` only hosts with a body / jq / json rewrite or a script rule (NativeMitmSelective, the old core decided per
    /// host: the retired bridge); `.off` the old core terminates everything. An explicit nativeMitmStage2 wins both ways
    /// (false also turns selective mode off).
    enum Mode: Equatable { case off, selective, all }

    static func mode(in defaults: UserDefaults?) -> Mode {
        if let defaults, defaults.object(forKey: defaultsKey) != nil { return defaults.bool(forKey: defaultsKey) ? .all : .off }
        if defaultOn { return .all }
        return NativeMitmSelective.enabled(in: defaults) ? .selective : .off
    }
    static var mode: Mode { mode(in: UserDefaults(suiteName: appGroup)) }
    /// The front is wanted at all (full or selective).
    static var active: Bool { mode != .off }

    /// Selective mode is installed: the native rewrite / body / script engines default ON (their own app-group keys
    /// still win) — only heavy hosts reach the front, and those are what the engines are for.
    static var selectiveEngines: Bool { lock.lock(); defer { lock.unlock() }; return _selectiveEngines }
    private static var _selectiveEngines = false

    /// A native engine switch: an explicit app-group value wins, else ON while selective mode is installed.
    /// `explicit` is the cached app-group value (nil: key absent).
    /// feat/native-core-eval: in the native-only tunnel the native rewrite / body / script engines are the only ones — an
    /// engine "off" would leave its rules unapplied with nothing behind it, so they are always on (an app-group value
    /// left over from the old core builds is ignored).
    static func engineSwitch(explicit: Bool?) -> Bool { true }

    /// Reads an engine's app-group key (nil: absent).
    static func explicitSwitch(_ key: String) -> Bool? {
        guard let d = UserDefaults(suiteName: appGroup), d.object(forKey: key) != nil else { return nil }
        return d.bool(forKey: key)
    }

    /// Bounds (memory cap): live sessions, bytes buffered per session.
    static var maxSessions = 48
    static var maxBufferedPerSession = 256 << 10
    /// Largest piece one read / the old core pull / lane read asks for. 16 KB = one TLS record (feat/native-slim; was 64 KB):
    /// a bigger max only makes Network.framework / dispatch_data hand over (and Swift copy) bigger contiguous slabs.
    static var ioChunk: Int { slim.smallChunks ? 16 << 10 : 64 << 10 }

    /// feat/native-slim: per-session footprint reductions, each switchable so NativeMitmMemoryTests can measure
    /// what it saves (all on in production; `legacy` = the 13f6c41 behaviour).
    struct Slim: Equatable {
        /// Session queues target one shared concurrent (non-overcommit) queue instead of each being its own
        /// overcommit root: a burst whose sessions block in the old core calls no longer spawns a GCD thread per session.
        var sharedQueues = true
        /// ioChunk 16 KB instead of 64 KB.
        var smallChunks = true
        /// Drop the session's client / upstream buffers (capacity included) whenever they are empty between
        /// exchanges, so an idle keep-alive session holds no buffer at all.
        var releaseIdleBuffers = true
        /// Upstream TLS connections through the relay share one NWParameters.PrivacyContext per relay port instead
        /// of creating one per connection.
        var sharedPrivacyContext = true
        /// After a burst of native connections closed (sessions + upstream connections, ≥ 16, then 250 ms quiet),
        /// give malloc's free pages back (malloc_zone_pressure_relief). Measured 2026-10-24 (NativeMitmMemoryTests):
        /// most of a burst's footprint right after it is freed-but-dirty malloc memory (Network.framework / TLS
        /// buffers of the connections that already closed), which jetsam counts until malloc returns it.
        var reliefAfterBurst = true
        /// Upstream dials (TCP + relay CONNECT + TLS handshake) in flight at once (UpstreamPool); nil = no limit.
        /// 8 (cdd2ae2, NativeMitmMemoryTests, 100-connection burst, every connection native): peak footprint
        /// +19.4 MB unlimited → +11.6 MB at 24 → +7.5 MB at 8 (old path +7.0). Each Network.framework TLS dial through
        /// the relay's CONNECT proxy costs ~130 KB of malloc while it handshakes; a burst of them is the whole native
        /// excess. Cost: a burst of more than 8 new upstream connections waits for dial slots (FIFO; a connection
        /// released meanwhile serves a waiter first).
        var maxConcurrentDials: Int? = 8
        static let legacy = Slim(sharedQueues: false, smallChunks: false, releaseIdleBuffers: false, sharedPrivacyContext: false,
                                 reliefAfterBurst: false, maxConcurrentDials: nil)
    }
    static var slim = Slim()

    /// Shared target of every session queue (Slim.sharedQueues). Concurrent custom queues are non-overcommit, so the
    /// serial session queues that target it run on GCD's width-limited pool.
    static let sessionTarget = DispatchQueue(label: "tern.mitm.s2.sessions", qos: .userInitiated, attributes: .concurrent)

    private static let lock = NSLock()
    private static var live = 0

    // MARK: malloc relief after a burst (Slim.reliefAfterBurst)
    private static var churn = 0
    private static var churnGen: UInt64 = 0
    private static let reliefQueue = DispatchQueue(label: "tern.mitm.s2.relief", qos: .utility)
    /// Reliefs done (tests / diagnostics).
    private(set) static var reliefs = 0

    /// One native connection (session or upstream) closed.
    static func noteChurn() {
        guard slim.reliefAfterBurst else { return }
        lock.lock()
        churn += 1
        churnGen &+= 1
        let gen = churnGen
        let now = churn >= 256 // never quiet: don't wait for it
        if now { churn = 0 }
        lock.unlock()
        if now { reliefQueue.async { relieve() }; return }
        reliefQueue.asyncAfter(deadline: .now() + 0.25) {
            lock.lock()
            let fire = gen == churnGen && churn >= 16
            if fire { churn = 0 }
            lock.unlock()
            if fire { relieve() }
        }
    }

    private static func relieve() {
        _ = malloc_zone_pressure_relief(nil, 0)
        lock.lock(); reliefs += 1; lock.unlock()
    }
    private static var ids: Int64 = 0

    /// listen()-time reservations not yet claimed by a session (oldest first). the old core asks listen() and then hands the
    /// connection over; without a reservation a burst could pass listen() far beyond the cap and the sessions
    /// over it would be refused after the handshake — too late for the old core's fallback, the client saw a closed
    /// connection. A reservation nobody claims (the old core fell back before the handshake) expires.
    private static var reserved: [Date] = []
    static var reservationTTL: TimeInterval = 15

    private static func pruneLocked() {
        let now = Date()
        reserved.removeAll { now.timeIntervalSince($0) > reservationTTL }
    }

    /// Whether another session may start: live + reserved below the cap, then (feat/s3-mem) the native memory
    /// governor, when on, admits it as small work; declined → old path.
    static var canAccept: Bool {
        lock.lock()
        pruneLocked()
        let room = live + reserved.count < maxSessions
        lock.unlock()
        return room && governorAdmitsSession()
    }

    /// feat/s3-mem: nil governor (switch nativeMemGovernor off) admits everything.
    private static func governorAdmitsSession() -> Bool {
        NativeMemoryGovernor.active?.admit(.session, bytes: NativeMemoryGovernor.sessionCost) ?? true
    }
    static var liveSessions: Int { lock.lock(); defer { lock.unlock() }; return live }

    /// listen(): hold a slot for the connection the old core is about to hand over. false → decline (the old core terminates TLS).
    /// Order: reservation room (cap) → governor admission (feat/s3-mem) → the session runs with the installed
    /// driver (NativeRewriteDriver, feat/s3-rewrite).
    static func reserve() -> Bool {
        lock.lock()
        pruneLocked()
        guard live + reserved.count < maxSessions else { lock.unlock(); return false }
        lock.unlock()
        guard governorAdmitsSession() else { return false }
        lock.lock(); defer { lock.unlock() }
        pruneLocked()
        guard live + reserved.count < maxSessions else { return false }
        reserved.append(Date())
        return true
    }

    /// listen() failed after reserve(): give the slot back.
    static func unreserve() { lock.lock(); if !reserved.isEmpty { reserved.removeLast() }; lock.unlock() }

    /// A session starts: claims the oldest reservation, else needs a free slot.
    static func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        pruneLocked()
        if !reserved.isEmpty { reserved.removeFirst(); live += 1; return true }
        guard live < maxSessions else { return false }
        live += 1; return true
    }
    /// Started sessions, held here: everything a session waits on (stream reads, upstream opens, timers) refers to
    /// it weakly, so without this the session was freed right after start() and its connection hung (found by
    /// the memory bench, 2026-10-24: every native connection timed out and the live count leaked to the cap).
    private static var running: [Int64: NativeMitmSession] = [:]
    static func retain(_ s: NativeMitmSession) { lock.lock(); running[s.id] = s; lock.unlock() }
    static func drop(_ id: Int64) { lock.lock(); running[id] = nil; lock.unlock() }
    /// Cancels every started session (uninstall: tunnel stop / switch off).
    static func cancelAll(_ why: String) {
        lock.lock(); let all = Array(running.values); lock.unlock()
        for s in all { s.cancel(why) }
    }

    static func release() { lock.lock(); live = max(0, live - 1); lock.unlock() }

    /// The last few exchange failures ("<status> <error>", newest last): 隧道内存 diagnostics and the memory bench.
    private static var errors: [String] = []
    static func noteError(_ s: String) { lock.lock(); errors.append(s); if errors.count > 16 { errors.removeFirst(errors.count - 16) }; lock.unlock() }
    static var recentErrors: [String] { lock.lock(); defer { lock.unlock() }; return errors }
    static func clearErrors() { lock.lock(); errors.removeAll(); lock.unlock() }
    static func nextID() -> Int64 { lock.lock(); defer { lock.unlock() }; ids += 1; return ids }

    /// Wire the lanes together.
    @discardableResult
    static func install(front: MitmTLSFronting, upstream: MitmUpstreamConnecting,
                        codec: HTTPCodec, bodies: NativeBodyReading = NativeBodyStore.shared,
                        driver: MitmFlowDriving = NativeRewriteDriver(inner: NativeMitmFlowDriver.shared), force: Bool = false,
                        h2Opener: H2UpstreamOpening? = nil, selective: Bool? = nil) -> Bool {
        let m = mode
        forced = force
        // feat/selective-native: selective = the old core hands over only hosts with heavy rules; the engines default ON then.
        // nil: from the switches (never for a forced install unless asked — the memory benches pick explicitly).
        let sel = selective ?? (!force && m == .selective)
        lock.lock(); _selectiveEngines = sel; lock.unlock()
        if let f = front as? MitmTLSFront {
            f.admit = { (NativeMitmRuntime.forced || NativeMitmRuntime.active) && NativeMitmRuntime.reserve() }
            f.unadmit = { NativeMitmRuntime.unreserve() }
        }
        // s3-h2: connections that negotiated h2 get the native h2 session.
        let opener = h2Opener ?? H2RelayUpstreamOpener(h1: upstream)
        front.acceptHandler = { conn in
            if conn.alpn == "h2" {
                NativeH2Session(conn: conn, codec: codec, opener: opener, driver: driver, bodies: bodies)?.start()
            } else {
                NativeMitmSession(conn: conn, codec: codec, upstream: upstream, driver: driver, bodies: bodies)?.start()
            }
        }
        // fix/nc-e2e-gaps: plain HTTP (port 80) from the TUN data plane — the same HTTP/1.1 session, no TLS.
        MitmPlainFront.shared.onAccept = { conn in
            NativeMitmSession(conn: conn, codec: codec, upstream: upstream, driver: driver, bodies: bodies)?.start()
        }
        NativeH2Runtime.resetBreaker()
        return true
    }

    static func uninstall() {
        forced = false
        MitmPlainFront.shared.onAccept = nil
        MitmPlainFront.shared.stop()
        lock.lock(); _selectiveEngines = false; lock.unlock()
        cancelAll("native MitM off")
        NativeH2Runtime.cancelAll()
    }

    /// install(force:) (the memory bench): listen() accepts regardless of the switch.
    private(set) static var forced = false
}

// MARK: - Selective switch (feat/selective-native)

enum NativeMitmSelective {
    /// App-group key; an explicit value wins over `defaultOn`. Only used while nativeMitmStage2 is absent.
    static let defaultsKey = "nativeMitmSelective"
    /// Default when the key is absent — decided by UnitTests/NativeMitmSelectiveTests (78837e9, Self-test 40102633460,
    /// light:1 + dark:0, medians of 4, footprint Δ peak / 1 s after, selective − all the old core): script 2 MB −18…−20 / −40 MB,
    /// script 3.5 MB −7…−16 / −22…−26 MB, jq 960 KB −3…−9 / −4…−30 MB, jq 200 KB +1.2…+1.5 / −2…−4.5 MB,
    /// mixed 90 plain + 10 script −20…−26 / −24…−28 MB, plain 100 +0.3 / −0.8 MB (noise: no host qualifies, the code
    /// path is the old core one). ON.
    static let defaultOn = true
    /// Which rules make a host native: 1 = body / jq / json rewrites + scripts,
    /// 2 = scripts only.
    static let kinds = 1

    static func enabled(in defaults: UserDefaults?) -> Bool {
        guard let defaults, defaults.object(forKey: defaultsKey) != nil else { return defaultOn }
        return defaults.bool(forKey: defaultsKey)
    }
}

extension NativeBodyStore: NativeBodyReading {}

// MARK: - Flow driver adapter (forwards to NativeMitmFlowDriver)

final class MitmFlowDriverAdapter: MitmFlowDriving {
    private let inner = NativeMitmFlowDriver.shared

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        inner.requestPhase(head: head, conn: conn)
    }
    func await(_ id: Int64) -> FlowDecision { inner.await(id) }
    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        inner.responsePhase(id, head: head, length: length)
    }
    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        inner.write(id, which, data)
    }
    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) { inner.closeBody(id, which, error: error) }
    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data { inner.read(id, which, max: max) }
    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { inner.readState(id, which) }
    func upstreamFailed(_ id: Int64, why: String) { inner.upstreamFailed(id, why: why) }
    func end(_ id: Int64, sent: Int64, error: String) { inner.end(id, sent: sent, error: error) }
    func cancel(_ id: Int64, why: String) { inner.cancel(id, why: why) }

    static func json(_ o: [String: Any]) -> String {
        (try? JSONSerialization.data(withJSONObject: o)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }
}

extension MitmFlowDriverAdapter: MitmScriptedFlowStarting {
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]]) -> FlowDecision {
        inner.requestPhase(head: head, conn: conn, gen: gen, scripted: scripted)
    }
}

// MARK: - Session

final class NativeMitmSession {
    struct Timeouts {
        var firstHead: TimeInterval = 30     // first request head after the handshake
        var keepAliveIdle: TimeInterval = 60 // between requests
        var upstreamHead: TimeInterval = 60  // origin's response head
        var bodyStall: TimeInterval = 120    // no progress on a body in either direction
    }
    static var timeouts = Timeouts()

    let id: Int64
    private let conn: MitmAcceptedConnection
    private let codec: HTTPCodec
    private let upstream: MitmUpstreamConnecting
    private let driver: MitmFlowDriving
    private let bodies: NativeBodyReading
    private let queue: DispatchQueue

    private var clientBuf = Data()
    private let releaseIdle: Bool
    private var clientEOF = false
    private var finished = false
    private var flowID: Int64 = 0
    private var lease: MitmUpstreamLease?
    private var upBuf = Data()
    private var responseStarted = false   // a response byte went to the client for the current exchange
    private var curRequest = ""          // fix/nc-diag-439: "METHOD /target" of the current exchange, for the 5xx log line
    private var sentBody: Int64 = 0       // body bytes delivered natively (FlowEnd "sent")
    private var timer: DispatchWorkItem?
    private(set) var requestsServed = 0
    /// Test hook: called once when the session is fully torn down.
    var onFinish: ((String) -> Void)?

    init?(conn: MitmAcceptedConnection, codec: HTTPCodec, upstream: MitmUpstreamConnecting,
          driver: MitmFlowDriving, bodies: NativeBodyReading) {
        guard NativeMitmRuntime.acquire() else { conn.stream.close(); return nil }
        id = NativeMitmRuntime.nextID()
        self.conn = conn; self.codec = codec; self.upstream = upstream; self.driver = driver; self.bodies = bodies
        queue = NativeMitmRuntime.slim.sharedQueues
            ? DispatchQueue(label: "tern.mitm.s2.session", target: NativeMitmRuntime.sessionTarget)
            : DispatchQueue(label: "tern.mitm.s2.session.\(id)")
        releaseIdle = NativeMitmRuntime.slim.releaseIdleBuffers
    }

    func start() {
        NativeMitmRuntime.retain(self)
        queue.async { [self] in nextRequest() }
    }

    /// External cancellation (tunnel stop, reload).
    func cancel(_ why: String = "cancelled") { queue.async { [self] in finish(cancelled: why) } }

    /// Another request may follow: the client is still open, or it half-closed after pipelining more requests.
    private var clientMayContinue: Bool { !clientEOF || !clientBuf.isEmpty }

    private var connInfo: MitmConnInfo { MitmConnInfo(host: conn.host, port: conn.port, tls: conn.tls, connID: conn.connID) }

    // MARK: timers

    private func arm(_ seconds: TimeInterval, _ what: String) {
        timer?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.timedOut(what) }
        timer = w
        queue.asyncAfter(deadline: .now() + seconds, execute: w)
    }
    private func disarm() { timer?.cancel(); timer = nil }
    private func timedOut(_ what: String) {
        guard !finished else { return }
        fail(S2Error.timeout(what), status: what == "upstream head" ? 504 : nil)
    }

    // MARK: client reads

    /// Reads more client bytes into clientBuf. cb(false) on EOF with nothing new, or error (session finished).
    private func readClient(_ cb: @escaping (Bool) -> Void) {
        if clientEOF { return cb(false) }
        if clientBuf.count >= NativeMitmRuntime.maxBufferedPerSession { return fail(S2Error.tooLarge("client buffer"), status: 431) }
        conn.stream.read(min: 1, max: NativeMitmRuntime.ioChunk) { [weak self] data, eof, err in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let err { return self.finish(cancelled: "client read: \(err)") }
                let data = data ?? Data()
                self.clientBuf.append(data)
                if eof { self.clientEOF = true }
                cb(!data.isEmpty)
            }
        }
    }

    private func readUpstream(_ cb: @escaping (Bool) -> Void) {
        guard let lease else { return fail(S2Error.upstream("no lease"), status: 502) }
        lease.stream.read(min: 1, max: NativeMitmRuntime.ioChunk) { [weak self] data, eof, err in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let err { return self.fail(S2Error.upstream("read: \(err)"), status: 502) }
                let data = data ?? Data()
                self.upBuf.append(data)
                cb(!(eof && data.isEmpty))
            }
        }
    }

    private func writeClient(_ d: Data, _ next: @escaping () -> Void) {
        if d.isEmpty { return next() }
        responseStarted = true
        conn.stream.write(d) { [weak self] err in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let err { return self.finish(cancelled: "client write: \(err)") }
                next()
            }
        }
    }

    private func writeUpstream(_ d: Data, _ next: @escaping () -> Void) {
        guard let lease else { return fail(S2Error.upstream("no lease"), status: 502) }
        if d.isEmpty { return next() }
        lease.stream.write(d) { [weak self] err in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { return }
                if let err { return self.fail(S2Error.upstream("write: \(err)"), status: 502) }
                next()
            }
        }
    }

    // MARK: request loop

    private func nextRequest() {
        guard !finished else { return }
        flowID = 0; sentBody = 0; responseStarted = false
        if releaseIdle {
            // An emptied Data keeps its capacity (removeFirst / removeSubrange): an idle keep-alive session would
            // hold the largest piece it ever buffered.
            if clientBuf.isEmpty { clientBuf = Data() }
            if upBuf.isEmpty { upBuf = Data() }
        }
        arm(requestsServed == 0 ? Self.timeouts.firstHead : Self.timeouts.keepAliveIdle, "request head")
        parseRequestHead()
    }

    private func parseRequestHead() {
        do {
            if let head = try codec.parseRequestHead(&clientBuf) { disarm(); return handle(head) }
        } catch {
            var status = 400
            if case S2Error.tooLarge = error { status = 431 }
            switch error as? HTTPParseError {
            case .headTooLarge?, .lineTooLong?, .tooManyHeaders?: status = 431
            default: break
            }
            return fail(error, status: status)
        }
        readClient { [self] more in
            if !more && clientEOF && clientBuf.isEmpty { return finish(cancelled: nil) } // clean keep-alive close / half-close
            if !more && clientEOF { return fail(S2Error.closed, status: 400) }           // truncated head
            parseRequestHead() // also after a read that delivered nothing without EOF (a non-data TLS record): read on
        }
    }

    private func handle(_ head: HTTPRequestHead) {
        curRequest = head.method + " " + String(head.target.prefix(96))
        let d = driver.requestPhase(head: head, conn: connInfo)
        flowID = d.id
        let reqFraming = codec.requestFraming(head)
        apply(d, head: head, reqFraming: reqFraming, requestBodyConsumed: reqFraming == .none)
    }

    private func apply(_ d: FlowDecision, head: HTTPRequestHead, reqFraming: HTTPBodyFraming, requestBodyConsumed: Bool) {
        switch d.action {
        case .needBody:
            guard d.which == FlowBodyWhich.request.rawValue else { return fail(S2Error.flow("need-body \(d.which) in request phase"), status: 502) }
            let go = { [self] in
                pushClientBody(reqFraming) { [self] in
                    apply(driver.await(flowID), head: head, reqFraming: reqFraming, requestBodyConsumed: true)
                }
            }
            if head.expectsContinue { writeClient(Data("HTTP/1.1 100 Continue\r\n\r\n".utf8), go) } else { go() }
        case .forward:
            forward(d, head: head, reqFraming: reqFraming, requestBodyConsumed: requestBodyConsumed)
        case .local:
            // the old core answered itself (reject / redirect / map local / script mock). Unread request body → close after.
            let keep = requestBodyConsumed && head.keepAlive && clientMayContinue
            sendResponse(status: d.status ?? 200, headers: d.headerFields, mode: d.body ?? .none, length: d.length,
                         lane: d.lane, method: head.method, clientVersion: head.version, keepAlive: keep) { [self] ok in
                endFlow(ok ? "" : "client write")
                if keep && ok { requestsServed += 1; nextRequest() } else { finish(cancelled: nil) }
            }
        case .drop:
            endFlow("drop"); finish(cancelled: nil)
        case .busy:
            fail(S2Error.flow("busy"), status: 503)
        case .error, .respond, .upgrade, .unknown:
            fail(S2Error.flow(d.note ?? "error"), status: 502)
        }
    }

    // MARK: request body → the old core

    private func pushClientBody(_ framing: HTTPBodyFraming, done: @escaping () -> Void) {
        let dec = codec.makeDecoder(framing)
        var stopped = false
        func step() {
            arm(Self.timeouts.bodyStall, "request body")
            do {
                let c = try dec.feed(clientBuf)
                clientBuf.removeFirst(c.consumed)
                if !c.payload.isEmpty && !stopped {
                    switch pushToGo(.request, c.payload) {
                    case .stop: stopped = true
                    case .gone: return fail(S2Error.flow("flow gone"), status: 502)
                    default: break
                    }
                }
                if c.done { disarm(); driver.closeBody(flowID, .request, error: ""); return done() }
            } catch { driver.closeBody(flowID, .request, error: "\(error)"); return fail(error, status: 400) }
            readClient { [self] more in
                if !more && clientEOF {
                    driver.closeBody(flowID, .request, error: "client closed mid-body")
                    return finish(cancelled: "client closed mid-body")
                }
                step()
            }
        }
        step()
    }

    /// FlowWrite with back-pressure: "full" → the old core's phase thread is behind; wait a little and retry.
    private func pushToGo(_ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        var delay: useconds_t = 1000
        for _ in 0..<400 {   // ≤ ~10 s backstop; flowAwaitMax/budgets in the old core are shorter
            let r = driver.write(flowID, which, data)
            if r != .full { return r }
            usleep(delay); delay = min(delay * 2, 50_000)
        }
        return .gone
    }

    // MARK: forward

    private func forward(_ d: FlowDecision, head: HTTPRequestHead, reqFraming: HTTPBodyFraming, requestBodyConsumed: Bool) {
        guard let urlStr = d.url, let url = URLComponents(string: urlStr), let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http" else {
            return fail(S2Error.unsupported("forward url \(d.url ?? "nil")"), status: 502)
        }
        let host = url.host ?? conn.host
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        var target = url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath
        if let q = url.percentEncodedQuery { target += "?" + q }
        let mode = d.body ?? .none
        if mode == .client && requestBodyConsumed && reqFraming != .none {
            return fail(S2Error.flow("body client after the body was pushed"), status: 502)
        }
        var headers = d.headerFields.filter { !Self.framingHeader($0.name) }
        let hostValue = d.host ?? (url.port.map { "\(host):\($0)" } ?? host)
        if headerValue(headers, "Host") == nil { headers.insert(("Host", hostValue), at: 0) }
        if head.isUpgrade, let up = head.value(for: "Upgrade") {
            headers.append(("Connection", "Upgrade")); headers.append(("Upgrade", up))
        }
        var len = d.length
        if mode == .client { if case .contentLength(let n) = reqFraming { len = n } else { len = -1 } }
        switch mode {
        case .none:
            if ["POST", "PUT", "PATCH"].contains(d.method ?? head.method) { headers.append(("Content-Length", "0")) }
        case .client, .read, .lane:
            headers.append(len >= 0 ? ("Content-Length", String(len)) : ("Transfer-Encoding", "chunked"))
        case .upstream:
            return fail(S2Error.flow("body upstream in forward"), status: 502)
        }
        let method = d.method ?? head.method
        let upHead = HTTPRequestHead(method: method, target: target, version: "HTTP/1.1", headers: headers)
        arm(Self.timeouts.upstreamHead, "upstream connect")
        upstream.open(host: host, port: port, tls: scheme == "https") { [weak self] r in
            guard let self else { return }
            self.queue.async {
                guard !self.finished else { if case .success(let l) = r { l.release(reusable: false) }; return }
                switch r {
                case .failure(let e):
                    self.driver.upstreamFailed(self.flowID, why: "\(e)")
                    self.fail(S2Error.upstream("\(e)"), status: 502)
                case .success(let l):
                    self.lease = l; self.upBuf.removeAll()
                    guard let wire = self.serialized(upHead) else { return }
                    self.writeUpstream(wire) {
                        self.sendRequestBody(mode, len: len, reqFraming: reqFraming, lane: d.lane, bodyPushed: requestBodyConsumed) {
                            self.arm(Self.timeouts.upstreamHead, "upstream head")
                            self.readResponseHead(head)
                        }
                    }
                }
            }
        }
    }

    /// Serializes a head the session built from the old core's decision; a head the old core's values made unserializable (CR/LF in a
    /// header) fails the exchange (502 if nothing went out yet) instead of putting bad bytes on the wire.
    private func serialized(_ h: HTTPRequestHead) -> Data? {
        do { return try codec.serialize(h) } catch { fail(error, status: 502); return nil }
    }
    private func serialized(_ h: HTTPResponseHead) -> Data? {
        do { return try codec.serialize(h) } catch { fail(error, status: 502); return nil }
    }

    static func reason(_ s: Int) -> String {
        switch s {
        case 100: return "Continue"; case 101: return "Switching Protocols"; case 200: return "OK"; case 201: return "Created"
        case 204: return "No Content"; case 206: return "Partial Content"; case 301: return "Moved Permanently"; case 302: return "Found"
        case 303: return "See Other"; case 304: return "Not Modified"; case 307: return "Temporary Redirect"; case 308: return "Permanent Redirect"
        case 400: return "Bad Request"; case 403: return "Forbidden"; case 404: return "Not Found"; case 431: return "Request Header Fields Too Large"
        case 500: return "Internal Server Error"; case 502: return "Bad Gateway"; case 503: return "Service Unavailable"; case 504: return "Gateway Timeout"
        default: return "Status"
        }
    }

    private static func framingHeader(_ n: String) -> Bool {
        ["content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection", "upgrade"].contains(n.lowercased())
    }

    private func sendRequestBody(_ mode: FlowBodyMode, len: Int64, reqFraming: HTTPBodyFraming, lane: FlowDecision.Lane?, bodyPushed: Bool = true,
                                 done: @escaping () -> Void) {
        let chunked = len < 0
        let out: (Data, @escaping () -> Void) -> Void = { [self] d, n in writeUpstream(chunked ? codec.chunk(d) : d, n) }
        let fin = { [self] in if chunked { writeUpstream(codec.lastChunk, done) } else { done() } }
        switch mode {
        case .none, .upstream: done()
        case .client:
            let dec = codec.makeDecoder(reqFraming)
            func step() {
                arm(Self.timeouts.bodyStall, "request body")
                do {
                    let c = try dec.feed(clientBuf)
                    clientBuf.removeFirst(c.consumed)
                    let next = { [self] in
                        if c.done { return fin() }
                        readClient { [self] more in
                            if !more && clientEOF { return finish(cancelled: "client closed mid-body") }
                            step()
                        }
                    }
                    if c.payload.isEmpty { next() } else { out(c.payload, next) }
                } catch { fail(error, status: 400) }
            }
            step()
        case .read:
            pullFromGo(.request, feed: bodyPushed ? nil : BodyFeed(codec.makeDecoder(reqFraming)), out: out, done: fin)
        case .lane:
            guard let lane else { return fail(S2Error.flow("lane without handle"), status: 502) }
            pullFromLane(lane, out: out, done: fin)
        }
    }

    /// Streams a body the old core produced (FlowRead / FlowReadState).
    /// The source body of a streaming "read": the client's request body (.request) or the upstream's response
    /// body (.response), de-framed and pushed to the old core piece by piece when FlowReadState says "more".
    final class BodyFeed {
        let dec: HTTPBodyDecoding
        var pending = Data()
        var closed = false
        var cleanEnd = false   // the source body ended at its framing (the upstream connection is reusable)
        init(_ dec: HTTPBodyDecoding) { self.dec = dec }
    }

    /// Pushes the next piece of `which`'s source body to the old core (or closes it at the end), then cont(). A piece the old core
    /// refuses ("full") stays pending and goes first next time — the old core wants a FlowRead before it takes more.
    private func feedGo(_ which: FlowBodyWhich, _ f: BodyFeed, _ cont: @escaping () -> Void) {
        if f.closed { return cont() }
        let end = { [self] (err: String) in
            f.closed = true
            driver.closeBody(flowID, which, error: err)
            if which == .response && !f.cleanEnd { lease?.release(reusable: false); lease = nil }
            cont()
        }
        if !f.pending.isEmpty {
            switch driver.write(flowID, which, f.pending) {
            case .taken: f.pending = Data(); return cont()
            case .full: return cont()
            case .stop: f.pending = Data(); f.cleanEnd = false; return end("")
            case .gone: return fail(S2Error.flow("flow gone"), status: nil)
            }
        }
        do {
            let c = try f.dec.feed(which == .response ? upBuf : clientBuf)
            if which == .response { upBuf.removeFirst(c.consumed) } else { clientBuf.removeFirst(c.consumed) }
            if c.done && c.payload.isEmpty { f.cleanEnd = true; return end("") }
            if !c.payload.isEmpty {
                f.pending = c.payload
                if c.done { f.cleanEnd = true }
                return feedGo(which, f) { [self] in
                    // a piece that completed the body: close it once the old core took it
                    if f.cleanEnd && f.pending.isEmpty && !f.closed { f.closed = true; driver.closeBody(flowID, which, error: "") }
                    cont()
                }
            }
        } catch { return end("\(error)") }
        let more: (Bool) -> Void = { [self] got in
            if got { return feedGo(which, f, cont) }
            if which == .response {
                do {
                    let tail = try f.dec.finishAtEOF()
                    if tail.isEmpty { return end("") }
                    f.pending = tail
                    return feedGo(which, f) { if f.pending.isEmpty { end("") } else { cont() } }
                } catch { return end("upstream truncated") }
            }
            end("client closed mid-body")
        }
        if which == .response { readUpstream(more) } else { readClient { [self] got in more(got || !clientEOF) } }
    }

    private func pullFromGo(_ which: FlowBodyWhich, feed: BodyFeed? = nil, out: @escaping (Data, @escaping () -> Void) -> Void,
                            done: @escaping () -> Void) {
        arm(Self.timeouts.bodyStall, "go body")
        let d = driver.read(flowID, which, max: NativeMitmRuntime.ioChunk)
        if !d.isEmpty { sentBody += Int64(which == .response ? d.count : 0); return out(d) { [self] in pullFromGo(which, feed: feed, out: out, done: done) } }
        switch driver.readState(flowID, which) {
        case .again: queue.asyncAfter(deadline: .now() + 0.002) { [self] in if !finished { pullFromGo(which, feed: feed, out: out, done: done) } }
        case .eof: done()
        case .more:
            // Streaming "read" (design §12: "more" → push the next piece of the same body): the old core reads the source body
            // as it is pushed. Before 2026-10-24 this was fatal, so every plain response through the native front
            // got its head and then a cut (memory bench: native 0/100).
            guard let feed else { return fail(S2Error.flow("read wants more of a body native does not push"), status: 502) }
            feedGo(which, feed) { [self] in pullFromGo(which, feed: feed, out: out, done: done) }
        case .failed(let e): fail(S2Error.flow(e), status: 502)
        }
    }

    private func pullFromLane(_ lane: FlowDecision.Lane, off: Int64 = 0, out: @escaping (Data, @escaping () -> Void) -> Void,
                              done: @escaping () -> Void) {
        let total = bodies.len(lane.handle, raw: lane.raw)
        if total < 0 { return fail(S2Error.flow("lane handle gone"), status: 502) }
        if off >= total { return done() }
        guard let d = bodies.read(lane.handle, raw: lane.raw, off: off, n: Int64(NativeMitmRuntime.ioChunk)), !d.isEmpty else {
            return fail(S2Error.flow("lane read failed"), status: 502)
        }
        arm(Self.timeouts.bodyStall, "lane body")
        out(d) { [self] in pullFromLane(lane, off: off + Int64(d.count), out: out, done: done) }
    }

    // MARK: response

    private func readResponseHead(_ req: HTTPRequestHead) {
        do {
            if let h = try codec.parseResponseHead(&upBuf) {
                if h.isInterim { return readResponseHead(req) } // drop interim 1xx
                disarm()
                NativeMitmUpstreamHealth.success(host: conn.host)
                let framing = codec.responseFraming(h, requestMethod: req.method)
                let length: Int64
                switch framing { case .none: length = 0; case .contentLength(let n): length = n; default: length = -1 }
                return applyResponse(driver.responsePhase(flowID, head: h, length: length), req: req, up: h, framing: framing,
                                     bodyPushed: false)
            }
        } catch { driver.upstreamFailed(flowID, why: "\(error)"); return fail(error, status: 502) }
        readUpstream { [self] more in
            if !more { driver.upstreamFailed(flowID, why: "closed before head"); return fail(S2Error.upstream("closed before head"), status: 502) }
            readResponseHead(req)
        }
    }

    private func applyResponse(_ d: FlowDecision, req: HTTPRequestHead, up: HTTPResponseHead, framing: HTTPBodyFraming,
                               bodyPushed: Bool) {
        switch d.action {
        case .needBody:
            pushUpstreamBody(framing) { [self] in
                applyResponse(driver.await(flowID), req: req, up: up, framing: framing, bodyPushed: true)
            }
        case .respond:
            let mode = d.body ?? .none
            if mode == .upstream && bodyPushed { return fail(S2Error.flow("body upstream after push"), status: 502) }
            var len = d.length
            if mode == .upstream { switch framing { case .contentLength(let n): len = n; case .none: len = 0; default: len = -1 } }
            // read over a body not pushed yet: the old core streams it, the session feeds it on "more"
            let feed = mode == .read && !bodyPushed ? BodyFeed(codec.makeDecoder(framing)) : nil
            let keep = req.keepAlive && up.keepAlive && clientMayContinue && framing != .untilClose
            sendResponse(status: d.status ?? up.status, headers: d.headerFields, mode: mode, length: len, lane: d.lane,
                         method: req.method, clientVersion: req.version, keepAlive: keep, upFraming: framing, feed: feed) { [self] ok in
                endFlow(ok ? "" : "client write")
                let upstreamClean = mode == .upstream || bodyPushed || framing == .none || (feed?.cleanEnd ?? false)
                lease?.release(reusable: ok && keep && upstreamClean && upBuf.isEmpty); lease = nil
                if ok && keep { requestsServed += 1; nextRequest() } else { finish(cancelled: nil) }
            }
        case .upgrade:
            guard up.status == 101 else { return fail(S2Error.flow("upgrade on \(up.status)"), status: 502) }
            var hs = d.headerFields.filter { !Self.framingHeader($0.name) }
            hs.append(("Connection", "Upgrade"))
            if let u = up.value(for: "Upgrade") { hs.append(("Upgrade", u)) }
            let h = HTTPResponseHead(status: 101, reason: "Switching Protocols", headers: hs)
            guard let wire = serialized(h) else { return }
            writeClient(wire) { [self] in tunnel() }
        case .error, .busy, .drop, .unknown, .forward, .local:
            fail(S2Error.flow(d.note ?? "response \(d.action)"), status: 502)
        }
    }

    private func pushUpstreamBody(_ framing: HTTPBodyFraming, done: @escaping () -> Void) {
        let dec = codec.makeDecoder(framing)
        var stopped = false
        func step() {
            arm(Self.timeouts.bodyStall, "response body")
            do {
                let c = try dec.feed(upBuf)
                upBuf.removeFirst(c.consumed)
                if !c.payload.isEmpty && !stopped {
                    switch pushToGo(.response, c.payload) {
                    case .stop: stopped = true   // the old core no longer wants it: stop reading the origin
                    case .gone: return fail(S2Error.flow("flow gone"), status: 502)
                    default: break
                    }
                }
                if c.done || stopped {
                    disarm(); driver.closeBody(flowID, .response, error: "")
                    if stopped { lease?.release(reusable: false); lease = nil }
                    return done()
                }
            } catch { driver.closeBody(flowID, .response, error: "\(error)"); return fail(error, status: 502) }
            readUpstream { [self] more in
                if !more {
                    do {
                        let tail = try dec.finishAtEOF()
                        if !tail.isEmpty { _ = pushToGo(.response, tail) }
                        driver.closeBody(flowID, .response, error: "")
                        lease?.release(reusable: false); lease = nil
                        return done()
                    } catch {
                        driver.closeBody(flowID, .response, error: "upstream truncated")
                        return fail(S2Error.upstream("truncated body"), status: 502)
                    }
                }
                step()
            }
        }
        step()
    }

    /// Writes a response head + body to the client. done(false) when the body could not be sent completely.
    private func sendResponse(status: Int, headers: HTTPHeaderList, mode: FlowBodyMode, length: Int64,
                              lane: FlowDecision.Lane?, method: String, clientVersion: String, keepAlive: Bool,
                              upFraming: HTTPBodyFraming = .none, feed: BodyFeed? = nil, done: @escaping (Bool) -> Void) {
        var hs = headers.filter { !Self.framingHeader($0.name) }
        let bodyless = method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status)
        let http10 = clientVersion == "HTTP/1.0"
        var chunked = false
        var keep = keepAlive
        if !bodyless || method == "HEAD" {
            if length >= 0 { hs.append(("Content-Length", String(length))) }
            else if !bodyless && !http10 { hs.append(("Transfer-Encoding", "chunked")); chunked = true }
            else if !bodyless { keep = false } // close-delimited towards an HTTP/1.0 client
        }
        if !keep { hs.append(("Connection", "close")) }
        else if http10 { hs.append(("Connection", "keep-alive")) }
        let reason = Self.reason(status)
        let head = HTTPResponseHead(status: status, reason: reason, headers: hs)
        let out: (Data, @escaping () -> Void) -> Void = { [self] d, n in writeClient(chunked ? codec.chunk(d) : d, n) }
        let fin = { [self] in
            if chunked { writeClient(codec.lastChunk) { done(true) } } else { done(true) }
        }
        guard let headWire = serialized(head) else { return }
        writeClient(headWire) { [self] in
            if bodyless { return done(true) }
            switch mode {
            case .none: fin()
            case .read: pullFromGo(.response, feed: feed, out: out, done: fin)
            case .lane:
                guard let lane else { return fail(S2Error.flow("lane without handle"), status: nil) }
                pullFromLane(lane, out: { [self] d, n in sentBody += Int64(d.count); out(d, n) }, done: fin)
            case .upstream: relayUpstreamBody(upFraming, out: out, done: fin)
            case .client: fail(S2Error.flow("body client in response"), status: nil)
            }
        }
    }

    private func relayUpstreamBody(_ framing: HTTPBodyFraming, out: @escaping (Data, @escaping () -> Void) -> Void,
                                   done: @escaping () -> Void) {
        let dec = codec.makeDecoder(framing)
        func step() {
            arm(Self.timeouts.bodyStall, "response body")
            do {
                let c = try dec.feed(upBuf)
                upBuf.removeFirst(c.consumed)
                let next = { [self] in
                    if c.done { disarm(); return done() }
                    readUpstream { [self] more in
                        if !more {
                            do {
                                let tail = try dec.finishAtEOF()
                                lease?.release(reusable: false); lease = nil
                                if tail.isEmpty { return done() }
                                sentBody += Int64(tail.count); out(tail, done)
                            } catch { fail(S2Error.upstream("truncated body"), status: nil) }
                            return
                        }
                        step()
                    }
                }
                if c.payload.isEmpty { next() } else { sentBody += Int64(c.payload.count); out(c.payload, next) }
            } catch { fail(error, status: nil) }
        }
        step()
    }

    // MARK: upgrade (WebSocket etc.): raw bidirectional pipe after the old core said "upgrade"

    private func tunnel() {
        guard let lease else { return fail(S2Error.upstream("no lease"), status: nil) }
        disarm()
        var open = 2
        let closeOne = { [self] in open -= 1; if open == 0 { endFlow(""); finish(cancelled: nil) } }
        func pump(from: ByteStream, to: ByteStream, pending: Data) {
            let go: () -> Void = {
                from.read(min: 1, max: NativeMitmRuntime.ioChunk) { [weak self] d, eof, err in
                    guard let self else { return }
                    self.queue.async {
                        guard !self.finished else { return }
                        if err != nil { return self.finish(cancelled: "tunnel read") }
                        to.write(d ?? Data()) { [weak self] werr in
                            self?.queue.async {
                                guard let self, !self.finished else { return }
                                if werr != nil { return self.finish(cancelled: "tunnel write") }
                                if eof { to.closeWrite(); return closeOne() }   // half-close propagates
                                pump(from: from, to: to, pending: Data())
                            }
                        }
                    }
                }
            }
            if pending.isEmpty { go() } else { to.write(pending) { _ in self.queue.async(execute: go) } }
        }
        let c2u = clientBuf, u2c = upBuf
        clientBuf.removeAll(); upBuf.removeAll()
        pump(from: conn.stream, to: lease.stream, pending: c2u)
        pump(from: lease.stream, to: conn.stream, pending: u2c)
    }

    // MARK: teardown

    private func endFlow(_ err: String) {
        guard flowID != 0 else { return }
        driver.end(flowID, sent: sentBody, error: err)
        flowID = 0
    }

    /// Error after the handover: 502/504/400 if nothing of this response went out, else cut.
    private func fail(_ error: Error, status: Int?) {
        guard !finished else { return }
        NativeMitmRuntime.noteError("\(status.map(String.init) ?? "cut") \(conn.host): \(error)")
        // fix/nc-diag-439 (B): the reason of a MitM 5xx was only in the response body; now in the core log too.
        if let status, status >= 500 {
            NCDiagLimiter.shared.line("[MITM] \(conn.host) \(curRequest) → \(status) (\(error))", level: "warning")
        }
        if NativeMitmUpstreamHealth.isUpstream(error) {
            NativeMitmUpstreamHealth.failure(host: conn.host, why: "\(error)")
        }
        if let status, !responseStarted {
            let body = Data("Tern native MitM: \(error)\n".utf8)
            let reason = Self.reason(status)
            let h = HTTPResponseHead(status: status, reason: reason,
                                     headers: [("Content-Type", "text/plain; charset=utf-8"),
                                               ("Content-Length", String(body.count)), ("Connection", "close")])
            responseStarted = true
            conn.stream.write(((try? codec.serialize(h)) ?? Data()) + body) { [weak self] _ in
                self?.queue.async { self?.finish(cancelled: nil, error: "\(error)") }
            }
            return
        }
        finish(cancelled: nil, error: "\(error)")
    }

    /// The one exit. cancelled non-nil: the client went away / external cancel (the old core sees MitmFlowCancel).
    private func finish(cancelled: String?, error: String = "") {
        guard !finished else { return }
        finished = true
        disarm()
        if flowID != 0 {
            if let why = cancelled { driver.cancel(flowID, why: why) } else { driver.end(flowID, sent: sentBody, error: error.isEmpty ? "closed" : error) }
            flowID = 0
        }
        lease?.release(reusable: false); lease = nil
        conn.stream.closeWrite()
        conn.stream.close()
        clientBuf = Data(); upBuf = Data()
        NativeMitmRuntime.release()
        NativeMitmRuntime.drop(id)
        NativeMitmRuntime.noteChurn()
        onFinish?(cancelled ?? error)
        onFinish = nil
    }
}
