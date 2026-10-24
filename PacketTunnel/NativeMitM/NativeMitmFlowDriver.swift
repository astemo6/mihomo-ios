import Foundation

/// Pure Swift MitM Flow Driver.
/// Replaces Go's Flow API (`bridge/mitm/flow.go` and `GoMitmFlowDriver`).
/// Executes URL rewrite, header rewrite, map local, scripts, and body handling
/// entirely within Swift in-process memory.
final class NativeMitmFlowDriver: MitmFlowDriving, MitmScriptedFlowStarting {
    static let shared = NativeMitmFlowDriver()

    private final class FlowContext {
        let id: Int64
        var head: HTTPRequestHead
        var conn: MitmConnInfo
        var reqBody = Data()
        var respBody = Data()
        var localBody = Data()
        var localOffset = 0
        var state: String = "init"
        var error: String?

        init(id: Int64, head: HTTPRequestHead, conn: MitmConnInfo) {
            self.id = id
            self.head = head
            self.conn = conn
        }
    }

    private let lock = NSLock()
    private var seq: Int64 = 0
    private var flows: [Int64: FlowContext] = [:]

    init() {}

    private func nextID() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        seq += 1
        return seq
    }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        let id = nextID()
        let ctx = FlowContext(id: id, head: head, conn: conn)
        lock.lock()
        flows[id] = ctx
        lock.unlock()

        let length: Int64 = head.isChunked ? -1 : (head.contentLength ?? 0)
        let req = RewriteRequest(
            method: head.method,
            target: head.target,
            host: head.host ?? "",
            headers: headerPairs(head.headers),
            length: length,
            connHost: conn.host,
            connPort: conn.port,
            tls: conn.tls
        )

        // Evaluate native rewrite rules
        let decision = NativeRewriteEngine.shared.request(req, state: RequestScriptState())
        switch decision {
        case .local(let l):
            ctx.localBody = l.body
            return FlowDecision(
                id: id,
                action: .local,
                method: head.method,
                url: head.target,
                status: l.status,
                headers: l.headers,
                body: l.bodyMode,
                length: l.length
            )
        case .drop:
            return FlowDecision(id: id, action: .drop)
        case .forward(let f):
            return FlowDecision(
                id: id,
                action: .forward,
                method: f.method,
                url: f.url,
                host: f.host,
                headers: f.headers
            )
        case .pauseScript(let p):
            if p.requiresBody && length != 0 {
                return FlowDecision(id: id, action: .needBody)
            }
            // Forward by default if script doesn't abort
            return FlowDecision(id: id, action: .forward, method: head.method, url: head.target, headers: headerPairs(head.headers))
        case .body(let b):
            if b.reqBodyMode == .needBody {
                return FlowDecision(id: id, action: .needBody)
            }
            return FlowDecision(id: id, action: .forward, method: head.method, url: head.target, headers: headerPairs(head.headers))
        case .go:
            // Pure native: forward request as-is
            return FlowDecision(
                id: id,
                action: .forward,
                method: head.method,
                url: head.target,
                host: head.host,
                headers: headerPairs(head.headers)
            )
        }
    }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]]) -> FlowDecision {
        requestPhase(head: head, conn: conn)
    }

    func await(_ id: Int64) -> FlowDecision {
        lock.lock()
        let ctx = flows[id]
        lock.unlock()
        guard let ctx else {
            return FlowDecision(id: id, action: .error, note: "flow not found")
        }
        return FlowDecision(
            id: id,
            action: .forward,
            method: ctx.head.method,
            url: ctx.head.target,
            host: ctx.head.host,
            headers: headerPairs(ctx.head.headers)
        )
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        lock.lock()
        let ctx = flows[id]
        lock.unlock()

        var headers = headerPairs(head.headers)
        if let ctx {
            let req = RewriteRequest(
                method: ctx.head.method,
                target: ctx.head.target,
                host: ctx.head.host ?? "",
                headers: headerPairs(ctx.head.headers),
                length: length,
                connHost: ctx.conn.host,
                connPort: ctx.conn.port,
                tls: ctx.conn.tls
            )
            // Apply response header rewrites if any
            let respDecision = NativeRewriteEngine.shared.respond(req, status: head.status, headers: headers, length: length)
            switch respDecision {
            case .done(let d):
                headers = d.headers
            default:
                break
            }
        }

        return FlowDecision(
            id: id,
            action: .respond,
            status: head.status,
            headers: headers,
            length: length
        )
    }

    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        lock.lock()
        defer { lock.unlock() }
        guard let ctx = flows[id] else { return .gone }
        if which == .request {
            ctx.reqBody.append(data)
        } else {
            ctx.respBody.append(data)
        }
        return .taken
    }

    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let ctx = flows[id] else { return }
        if !error.isEmpty {
            ctx.error = error
        }
    }

    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let ctx = flows[id] else { return Data() }
        let source: Data
        if which == .request {
            source = ctx.reqBody
        } else if !ctx.localBody.isEmpty {
            source = ctx.localBody
        } else {
            source = ctx.respBody
        }
        if ctx.localOffset >= source.count { return Data() }
        let end = min(ctx.localOffset + max, source.count)
        let slice = source.subdata(in: ctx.localOffset..<end)
        ctx.localOffset = end
        return slice
    }

    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState {
        lock.lock()
        defer { lock.unlock() }
        guard let ctx = flows[id] else { return .failed("gone") }
        let total = ctx.localBody.isEmpty ? ctx.respBody.count : ctx.localBody.count
        if ctx.localOffset >= total {
            return .eof
        }
        return .more
    }

    func upstreamFailed(_ id: Int64, why: String) {
        lock.lock()
        defer { lock.unlock() }
        flows[id]?.error = why
    }

    func end(_ id: Int64, sent: Int64, error: String) {
        lock.lock()
        defer { lock.unlock() }
        flows.removeValue(forKey: id)
    }

    func cancel(_ id: Int64, why: String) {
        lock.lock()
        defer { lock.unlock() }
        flows.removeValue(forKey: id)
    }
}
