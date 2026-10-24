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
        lock.lock()
        seq += 1
        let id = seq
        flows[id] = f
        passed += 1
        lock.unlock()
        return decision(id, .forward, f)
    }

    /// Request scripts already ran natively (NativeRequestScripts) and their outcome is in `head`; forward it.
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo, gen: Int64, scripted: [[String: Any]]) -> FlowDecision {
        requestPhase(head: head, conn: conn)
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
        guard known else { return FlowDecision(id: id, action: .error, note: "flow not found") }
        var d = FlowDecision(id: id, action: head.status == 101 ? .upgrade : .respond)
        d.status = head.status
        d.headers = Self.pairs(head.headers)
        d.body = .upstream
        d.length = length
        return d
    }

    // No body ever goes through this driver (forward .client / respond .upstream stream past it).
    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult { .stop }
    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) {}
    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data { Data() }
    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { .eof }
    func upstreamFailed(_ id: Int64, why: String) {}

    func end(_ id: Int64, sent: Int64, error: String) {
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
    }

    func cancel(_ id: Int64, why: String) {
        lock.lock(); flows.removeValue(forKey: id); lock.unlock()
    }

    var openFlows: Int { lock.lock(); defer { lock.unlock() }; return flows.count }
}
