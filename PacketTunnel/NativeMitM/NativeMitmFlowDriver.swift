import Foundation

/// feat/native-core-eval: pass-through flow driver behind NativeRewriteDriver (the inner driver of the Go-free tunnel).
///
/// NativeRewriteDriver (main's stage 3a, s3-full, s3-script) already decides every rewrite / reject / redirect /
/// map local / header / body / script rule natively. What it defers used to go to Go's flow API
/// (bridge/mitm/flow.go via GoMitmFlowDriver). With no Go in the extension, a deferred flow is forwarded unchanged:
/// the request goes to its origin as the client sent it (body streamed from the client) and the response comes back
/// as the origin sent it (body streamed from upstream). Nothing is buffered here; the driver only remembers each
/// flow's head to build the forward URL. Flows the native engine cannot handle are therefore not rewritten — that is
/// the documented regression (work/native-core-eval.md), never a broken connection.
final class NativeMitmFlowDriver: MitmFlowDriving, MitmScriptedFlowStarting {
    static let shared = NativeMitmFlowDriver()

    private struct Flow {
        var method: String
        var url: String
        var host: String?
        var headers: [[String]]
    }

    private let lock = NSLock()
    private var seq: Int64 = 0
    private var flows: [Int64: Flow] = [:]
    /// Bodies this driver serves (read): a request script's body (bodySet) or its local answer (mock).
    private var served: [Int64: [FlowBodyWhich: (data: Data, off: Int)]] = [:]
    /// Deferred flows forwarded unchanged since start (diagnostics).
    private(set) var passed: Int64 = 0

    init() {}

    /// Absolute URL for a request head: absolute-form targets as is, else scheme from the connection + Host.
    static func forwardURL(head: HTTPRequestHead, conn: MitmConnInfo) -> String {
        let target = head.target
        let lower = target.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") { return target }
        let scheme = conn.tls ? "https" : "http"
        var authority = head.host ?? ""
        if authority.isEmpty {
            let h = conn.host.contains(":") && !conn.host.hasPrefix("[") ? "[\(conn.host)]" : conn.host
            let defaultPort = conn.tls ? 443 : 80
            authority = conn.port == defaultPort || conn.port == 0 ? h : "\(h):\(conn.port)"
        }
        let path = target.isEmpty ? "/" : (target.hasPrefix("/") ? target : "/" + target)
        return "\(scheme)://\(authority)\(path)"
    }

    private static func pairs(_ h: HTTPHeaderList) -> [[String]] { h.map { [$0.name, $0.value] } }

    private func decision(_ id: Int64, _ action: FlowDecision.Action, _ f: Flow) -> FlowDecision {
        var d = FlowDecision(id: id, action: action)
        d.method = f.method
        d.url = f.url
        d.host = f.host
        d.headers = f.headers
        d.body = .client
        return d
    }

    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        let f = Flow(method: head.method, url: Self.forwardURL(head: head, conn: conn), host: head.host,
                     headers: Self.pairs(head.headers))
        return register(f) { [self] id in decision(id, .forward, f) }
    }

    /// Request scripts already ran natively (NativeRequestScripts); `scripted` holds their outcomes in run order
    /// (FlowHead.Scripted, bridge/mitm/flowscripted.go). Go applied them in its request phase; here they are folded
    /// onto the forward: abort → drop, a local answer (mock) → local, else the last url / method / headers / body.
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]]) -> FlowDecision {
        var f = Flow(method: head.method, url: Self.forwardURL(head: head, conn: conn), host: head.host,
                     headers: Self.pairs(head.headers))
        var body: Data?
        for o in scripted {
            if o["abort"] as? Bool == true {
                return register(f) { id in FlowDecision(id: id, action: .drop) }
            }
            if let m = o["mock"] as? [String: Any] {
                let mb = (m["body"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
                let st = (m["status"] as? Int).flatMap { $0 == 0 ? nil : $0 } ?? 200
                let hs = Self.stringPairs(m["headers"]) ?? [["Content-Type", "text/plain; charset=utf-8"]]
                return register(f, serve: (.response, mb)) { id in
                    var d = FlowDecision(id: id, action: .local)
                    d.status = st
                    d.headers = hs.filter { $0.count == 2 && $0[0].lowercased() != "content-length" && $0[0].lowercased() != "transfer-encoding" }
                    d.body = mb.isEmpty ? FlowBodyMode.none : .read
                    d.length = Int64(mb.count)
                    return d
                }
            }
            if let u = o["url"] as? String, !u.isEmpty, let c = URLComponents(string: u), let h = c.host, !h.isEmpty {
                // a new URL: the request goes to its host (Go sets req.Host from it)
                let authority = c.port.map { "\(h):\($0)" } ?? h
                f.url = u
                f.host = authority
                f.headers = f.headers.map { $0.count == 2 && $0[0].lowercased() == "host" ? [$0[0], authority] : $0 }
            }
            if let m = o["method"] as? String, !m.isEmpty { f.method = m }
            if let h = Self.stringPairs(o["headers"]) { f.headers = h }
            if o["bodySet"] as? Bool == true {
                body = (o["body"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
            }
        }
        if let body {
            f.headers = f.headers.filter { $0.count == 2 && $0[0].lowercased() != "content-length" && $0[0].lowercased() != "transfer-encoding" }
            return register(f, serve: (.request, body)) { [self] id in
                var d = decision(id, .forward, f)
                d.body = body.isEmpty ? FlowBodyMode.none : .read
                d.length = Int64(body.count)
                return d
            }
        }
        return register(f) { [self] id in decision(id, .forward, f) }
    }

    private static func stringPairs(_ v: Any?) -> [[String]]? {
        guard let a = v as? [[Any]] else { return nil }
        return a.compactMap { p in p.count == 2 ? [String(describing: p[0]), String(describing: p[1])] : nil }
    }

    private func register(_ f: Flow, serve: (FlowBodyWhich, Data)? = nil, _ make: (Int64) -> FlowDecision) -> FlowDecision {
        lock.lock()
        seq += 1
        let id = seq
        flows[id] = f
        if let sv = serve { served[id] = [sv.0: (data: sv.1, off: 0)] }
        passed += 1
        lock.unlock()
        return make(id)
    }

    /// Only reached after a need-body, which this driver never asks for; forward what we have.
    func await(_ id: Int64) -> FlowDecision {
        lock.lock()
        let f = flows[id]
        lock.unlock()
        guard let f else { return FlowDecision(id: id, action: .error, note: "flow not found") }
        var d = decision(id, .forward, f)
        d.body = FlowBodyMode.none
        return d
    }

    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        lock.lock()
        let known = flows[id] != nil
        lock.unlock()
        // (a local answer never reaches the response phase)
        guard known else { return FlowDecision(id: id, action: .error, note: "flow not found") }
        var d = FlowDecision(id: id, action: head.status == 101 ? .upgrade : .respond)
        d.status = head.status
        d.headers = Self.pairs(head.headers)
        d.body = .upstream
        d.length = length
        return d
    }

    // Client / upstream bodies never go through this driver (forward .client / respond .upstream stream past it);
    // only a request script's body or local answer is served from here.
    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult { .stop }
    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {}
    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let b = served[id]?[which], b.off < b.data.count else { return Data() }
        let end = Swift.min(b.off + Swift.max(max, 1), b.data.count)
        let piece = b.data.subdata(in: (b.data.startIndex + b.off)..<(b.data.startIndex + end))
        served[id]?[which] = (b.data, end)
        return piece
    }
    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { .eof }
    func upstreamFailed(_ id: Int64, why: String) {}

    func end(_ id: Int64, sent: Int64, error: String) {
        lock.lock(); flows.removeValue(forKey: id); served.removeValue(forKey: id); lock.unlock()
    }

    func cancel(_ id: Int64, why: String) {
        lock.lock(); flows.removeValue(forKey: id); served.removeValue(forKey: id); lock.unlock()
    }

    var openFlows: Int { lock.lock(); defer { lock.unlock() }; return flows.count }
}
