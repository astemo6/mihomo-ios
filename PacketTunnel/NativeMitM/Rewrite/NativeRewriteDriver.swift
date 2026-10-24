// Native MitM stage 3a — plugs the native rewrite engine into NativeMitmSession.
//
// NativeRewriteDriver is a MitmFlowDriving in front of the Go driver. For each request it asks the native engine
// first (only when the switch `nativeMitmRewrite` is on — default OFF — and a snapshot for the running engine's
// current generation is loaded); a native decision gets a negative flow id and every later call for that id
// (response head, local body reads, end / cancel) is answered here without Go. A deferral (.go), the switch off, no
// snapshot, an unknown snapshot version or any inconsistency → the Go flow exactly as before. The session is not
// changed: it cannot tell a native decision from a Go one.
//
// Snapshot freshness: MitmRewriteGeneration() is checked on every request (an int from Go); the JSON is fetched and
// decoded only when it moved (engine reload). A request racing a reload may use the previous rule set — the same
// window the Go path has between reading its state pointer and the reload storing a new one.

import Foundation
import Libmihomo

// MARK: - Switch

enum NativeRewriteRuntime {
    /// App-group key; default OFF (integration is decided by measurement).
    static let defaultsKey = "nativeMitmRewrite"

    /// Tests force it; nil = read the app-group default (cached for a second).
    static var override: Bool?

    private static let lock = NSLock()
    private static var cached = false
    private static var readAt: TimeInterval = 0

    static var enabled: Bool {
        if let o = override { return o }
        lock.lock(); defer { lock.unlock() }
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = UserDefaults(suiteName: NativeMitmRuntime.appGroup)?.bool(forKey: defaultsKey) ?? false
        }
        return cached
    }
}

// MARK: - Snapshot source

protocol RewriteSnapshotSource: AnyObject {
    /// Current snapshot generation (0: engine not running).
    func generation() -> Int64
    /// The snapshot JSON ("" none).
    func snapshotJSON() -> String
}

final class GoRewriteSnapshotSource: RewriteSnapshotSource {
    func generation() -> Int64 { LibmihomoMitmRewriteGeneration() }
    func snapshotJSON() -> String { LibmihomoMitmRewriteSnapshot() }
}

/// Holds the engine for the current generation.
final class NativeRewriteProvider {
    private let source: RewriteSnapshotSource
    private let lock = NSLock()
    private var engine: NativeRewriteEngine?
    private var failedGen: Int64 = 0
    private(set) var loads = 0

    init(source: RewriteSnapshotSource) { self.source = source }

    func current() -> NativeRewriteEngine? {
        let gen = source.generation()
        if gen == 0 { return nil }
        lock.lock(); defer { lock.unlock() }
        if let e = engine, e.generation == gen { return e }
        if failedGen == gen { return nil }
        guard let s = RWSnapshot.decode(source.snapshotJSON()), (s.gen ?? 0) == gen else {
            failedGen = gen
            engine = nil
            return nil
        }
        let e = NativeRewriteEngine(snapshot: s)
        engine = e
        loads += 1
        return e
    }
}

// MARK: - Driver

final class NativeRewriteDriver: MitmFlowDriving {
    private enum NativeFlow {
        case local(body: Data, offset: Int)
        case forward(plan: RewriteDecision.ResponsePlan, method: String, engine: NativeRewriteEngine)
        case responded(body: Data, offset: Int)
        case done
    }

    struct Stats: Equatable {
        var local = 0, forward = 0, drop = 0, deferred = 0, off = 0
        var reasons: [String: Int] = [:]
    }

    let inner: MitmFlowDriving
    let provider: NativeRewriteProvider
    private let lock = NSLock()
    private var flows: [Int64: NativeFlow] = [:]
    private var nextID: Int64 = 0
    private var counters = Stats()

    init(inner: MitmFlowDriving, provider: NativeRewriteProvider = NativeRewriteProvider(source: GoRewriteSnapshotSource())) {
        self.inner = inner
        self.provider = provider
    }

    var stats: Stats { lock.lock(); defer { lock.unlock() }; return counters }
    var liveNativeFlows: Int { lock.lock(); defer { lock.unlock() }; return flows.count }

    private func newID(_ f: NativeFlow) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        nextID -= 1
        flows[nextID] = f
        return nextID
    }

    private func count(_ k: WritableKeyPath<Stats, Int>, reason: String? = nil) {
        lock.lock()
        counters[keyPath: k] += 1
        if let reason { counters.reasons[reason, default: 0] += 1 }
        lock.unlock()
    }

    static func request(_ head: HTTPRequestHead, _ conn: MitmConnInfo) -> RewriteRequest {
        // the same head GoMitmFlowDriver.requestPhase sends to MitmFlowBegin
        let length: Int64 = head.isChunked ? -1 : (head.contentLength ?? 0)
        return RewriteRequest(method: head.method, target: head.target, host: head.host ?? "", headers: headerPairs(head.headers),
                              length: length, connHost: conn.host, connPort: conn.port, tls: conn.tls)
    }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        guard NativeRewriteRuntime.enabled else { count(\.off); return inner.requestPhase(head: head, conn: conn) }
        guard let engine = provider.current() else { count(\.deferred, reason: "no snapshot"); return inner.requestPhase(head: head, conn: conn) }
        switch engine.decide(Self.request(head, conn)) {
        case .go(let why):
            count(\.deferred, reason: why)
            return inner.requestPhase(head: head, conn: conn)
        case .drop:
            count(\.drop)
            return FlowDecision(id: newID(.done), action: .drop)
        case .local(let l):
            count(\.local)
            var d = FlowDecision(id: newID(.local(body: l.body, offset: 0)), action: .local)
            d.status = l.status; d.headers = l.headers; d.body = l.bodyMode; d.length = l.length
            return d
        case .forward(let f):
            count(\.forward)
            var d = FlowDecision(id: newID(.forward(plan: f.response, method: f.method, engine: engine)), action: .forward)
            d.method = f.method; d.url = f.url; d.host = f.host; d.headers = f.headers; d.body = f.bodyMode; d.length = f.length
            return d
        }
    }

    func await(_ id: Int64) -> FlowDecision {
        if id >= 0 { return inner.await(id) }
        return FlowDecision(id: id, action: .error, note: "native flow has no pending decision")
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        if id >= 0 { return inner.responsePhase(id, head: head, length: length) }
        lock.lock()
        let f = flows[id]
        lock.unlock()
        guard case .forward(let plan, let method, let engine)? = f,
              let r = engine.respond(plan, status: head.status, headers: headerPairs(head.headers), length: length, method: method) else {
            return FlowDecision(id: id, action: .error, note: "native flow is not waiting for a response")
        }
        lock.lock()
        flows[id] = .responded(body: Data(), offset: 0)
        lock.unlock()
        var d = FlowDecision(id: id, action: r.action)
        d.status = r.status; d.headers = r.headers; d.body = r.bodyMode; d.length = r.length; d.note = r.note
        return d
    }

    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        id >= 0 ? inner.write(id, which, data) : .stop
    }

    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {
        if id >= 0 { inner.closeBody(id, which, error: error) }
    }

    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        if id >= 0 { return inner.read(id, which, max: max) }
        guard which == .response else { return Data() }
        lock.lock(); defer { lock.unlock() }
        switch flows[id] {
        case .local(let body, let off)?:
            let n = Swift.min(Swift.max(max, 1), body.count - off)
            if n <= 0 { return Data() }
            flows[id] = .local(body: body, offset: off + n)
            return body.subdata(in: off..<(off + n))
        case .responded(let body, let off)?:
            let n = Swift.min(Swift.max(max, 1), body.count - off)
            if n <= 0 { return Data() }
            flows[id] = .responded(body: body, offset: off + n)
            return body.subdata(in: off..<(off + n))
        default:
            return Data()
        }
    }

    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState {
        if id >= 0 { return inner.readState(id, which) }
        guard which == .response else { return .failed("err: no body to read") }
        lock.lock(); defer { lock.unlock() }
        switch flows[id] {
        case .local?, .responded?: return .eof // read() returned empty: the (in-memory) body is complete
        default: return .failed("err: unknown flow")
        }
    }

    func upstreamFailed(_ id: Int64, why: String) {
        if id >= 0 { inner.upstreamFailed(id, why: why) }
    }

    func end(_ id: Int64, sent: Int64, error: String) {
        if id >= 0 { return inner.end(id, sent: sent, error: error) }
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
    }

    func cancel(_ id: Int64, why: String) {
        if id >= 0 { return inner.cancel(id, why: why) }
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
    }
}
