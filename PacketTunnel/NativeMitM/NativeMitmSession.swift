// Native MitM STAGE 2 — B9: one decrypted MitM connection, end to end (lane `wire`).
//
//   Go engine (nativeterm.go: peek ClientHello, MitM host list, pinning memory) → MitmTLSFronting.listen →
//   TLS lane terminates TLS → acceptHandler → NativeMitmSession:
//     HTTPCodec parses the request head → MitmFlowDriving.requestPhase (Go decides: rewrite / reject / redirect /
//     map local / request script / admission — nothing is decided here) → [request body pushed to Go when asked]
//     → forward via MitmUpstreamConnecting (Go relay → mihomo rules/proxies) → response head → responsePhase
//     (Go: header/body rewrites, response scripts, body lane) → body from upstream / Go pipe / NativeBodyStore
//     → client. Keep-alive loop; pipelined bytes stay in the client buffer.
//
// Stage 3 lane s3-h2 (H2/NativeH2Session.swift): a connection whose TLS handshake negotiated h2 (offered only
// while the switch `nativeMitmH2` is on, default OFF) is served by NativeH2Session with the same driver.
//
// Stage 3a (Rewrite/NativeRewriteDriver.swift): the default driver asks the native rewrite engine first when the
// separate switch `nativeMitmRewrite` is on (default OFF); a native decision never reaches Go, a deferral or the
// switch off goes to GoMitmFlowDriver exactly as before.
//
// Fallback: the session only exists after Go handed the connection over (first byte from the TLS lane). Before
// that every failure is Go's first-byte fallback (nativeterm.go). The runtime switch (NativeMitmRuntime, default
// OFF) decides whether the TLS front is registered at all; when off, or past the session cap, listen() answers 0
// and Go terminates TLS itself — the Go path is the fallback for everything unsupported.
// After the handover an error answers 502 if no response byte went out yet, else cuts the connection (never a
// truncated body presented as complete).
//
// Cleanup: every exit goes through finish(); an active flow gets MitmFlowCancel (client gone) or MitmFlowEnd, which
// frees what Go holds for it, including lane handles (never freed here). Leases go back non-reusable unless the
// exchange completed cleanly.

import Foundation
import Libmihomo

// MARK: - Runtime switch

enum NativeMitmRuntime {
    /// App-group default key; default OFF until device-verified.
    static let defaultsKey = "nativeMitmStage2"
    static let appGroup = "group.com.astemo6.mihomo"

    static var enabled: Bool {
        UserDefaults(suiteName: appGroup)?.bool(forKey: defaultsKey) ?? false
    }

    /// Bounds (memory cap): live sessions, bytes buffered per session.
    static var maxSessions = 48
    static var maxBufferedPerSession = 256 << 10
    static let ioChunk = 64 << 10

    private static let lock = NSLock()
    private static var live = 0
    private static var ids: Int64 = 0

    /// Whether another session may start (the TLS lane checks this in listen(); false → return 0 → Go path).
    static var canAccept: Bool { lock.lock(); defer { lock.unlock() }; return live < maxSessions }
    static var liveSessions: Int { lock.lock(); defer { lock.unlock() }; return live }

    static func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard live < maxSessions else { return false }
        live += 1; return true
    }
    static func release() { lock.lock(); live = max(0, live - 1); lock.unlock() }
    static func nextID() -> Int64 { lock.lock(); defer { lock.unlock() }; ids += 1; return ids }

    /// Wire the lanes together. Registers the front with Go only when the switch is on; returns whether it did.
    @discardableResult
    static func install(front: MitmTLSFronting & LibmihomoNativeTLSFrontProtocol, upstream: MitmUpstreamConnecting,
                        codec: HTTPCodec, bodies: NativeBodyReading = NativeBodyStore.shared,
                        driver: MitmFlowDriving = NativeRewriteDriver(inner: GoMitmFlowDriver()),
                        h2Opener: H2UpstreamOpening? = nil) -> Bool {
        guard enabled else { LibmihomoSetNativeTLSFront(nil); LibmihomoMitmSetNativeH2(false); return false }
        // s3-h2: connections that negotiated h2 (only offered while nativeMitmH2 is on) get the native h2 session.
        let opener = h2Opener ?? H2RelayUpstreamOpener(h1: upstream)
        front.acceptHandler = { conn in
            if conn.alpn == "h2" {
                NativeH2Session(conn: conn, codec: codec, opener: opener, driver: driver, bodies: bodies)?.start()
            } else {
                NativeMitmSession(conn: conn, codec: codec, upstream: upstream, driver: driver, bodies: bodies)?.start()
            }
        }
        NativeH2Runtime.resetBreaker()
        LibmihomoMitmSetNativeH2(NativeH2Runtime.enabled)
        LibmihomoSetNativeTLSFront(front)
        return true
    }

    static func uninstall() { LibmihomoSetNativeTLSFront(nil); LibmihomoMitmSetNativeH2(false); NativeH2Runtime.cancelAll() }
}

extension NativeBodyStore: NativeBodyReading {}

// MARK: - Go driver (B6 gomobile API)

final class GoMitmFlowDriver: MitmFlowDriving {
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision {
        let length: Int64 = head.isChunked ? -1 : (head.contentLength ?? 0)
        let obj: [String: Any] = [
            "method": head.method, "target": head.target, "host": head.host ?? "",
            "headers": headerPairs(head.headers), "length": length,
            "connHost": conn.host, "connPort": conn.port, "tls": conn.tls, "connId": conn.connID,
        ]
        return FlowDecision.decode(LibmihomoMitmFlowBegin(Self.json(obj)))
    }
    func await(_ id: Int64) -> FlowDecision { FlowDecision.decode(LibmihomoMitmFlowAwait(id)) }
    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision {
        let obj: [String: Any] = ["status": head.status, "headers": headerPairs(head.headers), "length": length]
        return FlowDecision.decode(LibmihomoMitmFlowResponse(id, Self.json(obj)))
    }
    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        FlowWriteResult(rawValue: LibmihomoMitmFlowWrite(id, which.rawValue, data)) ?? .gone
    }
    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String) { LibmihomoMitmFlowClose(id, which.rawValue, error) }
    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data { LibmihomoMitmFlowRead(id, which.rawValue, max) ?? Data() }
    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState { FlowReadState(LibmihomoMitmFlowReadState(id, which.rawValue)) }
    func upstreamFailed(_ id: Int64, why: String) { LibmihomoMitmFlowUpstreamFailed(id, why) }
    func end(_ id: Int64, sent: Int64, error: String) { LibmihomoMitmFlowEnd(id, sent, error) }
    func cancel(_ id: Int64, why: String) { LibmihomoMitmFlowCancel(id, why) }

    static func json(_ o: [String: Any]) -> String {
        (try? JSONSerialization.data(withJSONObject: o)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
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
    private var clientEOF = false
    private var finished = false
    private var flowID: Int64 = 0
    private var lease: MitmUpstreamLease?
    private var upBuf = Data()
    private var responseStarted = false   // a response byte went to the client for the current exchange
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
        queue = DispatchQueue(label: "tern.mitm.s2.session.\(id)")
    }

    func start() { queue.async { [self] in nextRequest() } }

    /// External cancellation (tunnel stop, reload).
    func cancel(_ why: String = "cancelled") { queue.async { [self] in finish(cancelled: why) } }

    /// Another request may follow: the client is still open, or it half-closed after pipelining more requests.
    private var clientMayContinue: Bool { !clientEOF || !clientBuf.isEmpty }

    private var connInfo: MitmConnInfo { MitmConnInfo(host: conn.host, port: conn.port, tls: true, connID: conn.connID) }

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
            if !more && clientBuf.isEmpty { return finish(cancelled: nil) } // clean keep-alive close / half-close
            if !more { return fail(S2Error.closed, status: 400) }           // truncated head
            parseRequestHead()
        }
    }

    private func handle(_ head: HTTPRequestHead) {
        let d = driver.requestPhase(head: head, conn: connInfo)
        flowID = d.id
        let reqFraming = codec.requestFraming(head)
        apply(d, head: head, reqFraming: reqFraming, requestBodyConsumed: reqFraming == .none)
    }

    private func apply(_ d: FlowDecision, head: HTTPRequestHead, reqFraming: HTTPBodyFraming, requestBodyConsumed: Bool) {
        switch d.action {
        case .needBody:
            guard d.which == FlowBodyWhich.request.rawValue else { return fail(S2Error.go("need-body \(d.which) in request phase"), status: 502) }
            let go = { [self] in
                pushClientBody(reqFraming) { [self] in
                    apply(driver.await(flowID), head: head, reqFraming: reqFraming, requestBodyConsumed: true)
                }
            }
            if head.expectsContinue { writeClient(Data("HTTP/1.1 100 Continue\r\n\r\n".utf8), go) } else { go() }
        case .forward:
            forward(d, head: head, reqFraming: reqFraming, requestBodyConsumed: requestBodyConsumed)
        case .local:
            // Go answered itself (reject / redirect / map local / script mock). Unread request body → close after.
            let keep = requestBodyConsumed && head.keepAlive && clientMayContinue
            sendResponse(status: d.status ?? 200, headers: d.headerFields, mode: d.body ?? .none, length: d.length,
                         lane: d.lane, method: head.method, clientVersion: head.version, keepAlive: keep) { [self] ok in
                endFlow(ok ? "" : "client write")
                if keep && ok { requestsServed += 1; nextRequest() } else { finish(cancelled: nil) }
            }
        case .drop:
            endFlow("drop"); finish(cancelled: nil)
        case .busy:
            fail(S2Error.go("busy"), status: 503)
        case .error, .respond, .upgrade, .unknown:
            fail(S2Error.go(d.note ?? "error"), status: 502)
        }
    }

    // MARK: request body → Go

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
                    case .gone: return fail(S2Error.go("flow gone"), status: 502)
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

    /// FlowWrite with back-pressure: "full" → Go's phase goroutine is behind; wait a little and retry.
    private func pushToGo(_ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult {
        var delay: useconds_t = 1000
        for _ in 0..<400 {   // ≤ ~10 s backstop; flowAwaitMax/budgets in Go are shorter
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
            return fail(S2Error.go("body client after the body was pushed"), status: 502)
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
            return fail(S2Error.go("body upstream in forward"), status: 502)
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
                        self.sendRequestBody(mode, len: len, reqFraming: reqFraming, lane: d.lane) {
                            self.arm(Self.timeouts.upstreamHead, "upstream head")
                            self.readResponseHead(head)
                        }
                    }
                }
            }
        }
    }

    /// Serializes a head the session built from Go's decision; a head Go's values made unserializable (CR/LF in a
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

    private func sendRequestBody(_ mode: FlowBodyMode, len: Int64, reqFraming: HTTPBodyFraming, lane: FlowDecision.Lane?,
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
            pullFromGo(.request, out: out, done: fin)
        case .lane:
            guard let lane else { return fail(S2Error.go("lane without handle"), status: 502) }
            pullFromLane(lane, out: out, done: fin)
        }
    }

    /// Streams a body Go produced (FlowRead / FlowReadState).
    private func pullFromGo(_ which: FlowBodyWhich, out: @escaping (Data, @escaping () -> Void) -> Void,
                            done: @escaping () -> Void) {
        arm(Self.timeouts.bodyStall, "go body")
        let d = driver.read(flowID, which, max: NativeMitmRuntime.ioChunk)
        if !d.isEmpty { sentBody += Int64(which == .response ? d.count : 0); return out(d) { [self] in pullFromGo(which, out: out, done: done) } }
        switch driver.readState(flowID, which) {
        case .again: queue.asyncAfter(deadline: .now() + 0.002) { [self] in if !finished { pullFromGo(which, out: out, done: done) } }
        case .eof: done()
        case .more: fail(S2Error.go("read wants more of a body native does not push"), status: 502)
        case .failed(let e): fail(S2Error.go(e), status: 502)
        }
    }

    private func pullFromLane(_ lane: FlowDecision.Lane, off: Int64 = 0, out: @escaping (Data, @escaping () -> Void) -> Void,
                              done: @escaping () -> Void) {
        let total = bodies.len(lane.handle, raw: lane.raw)
        if total < 0 { return fail(S2Error.go("lane handle gone"), status: 502) }
        if off >= total { return done() }
        guard let d = bodies.read(lane.handle, raw: lane.raw, off: off, n: Int64(NativeMitmRuntime.ioChunk)), !d.isEmpty else {
            return fail(S2Error.go("lane read failed"), status: 502)
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
            if mode == .upstream && bodyPushed { return fail(S2Error.go("body upstream after push"), status: 502) }
            var len = d.length
            if mode == .upstream { switch framing { case .contentLength(let n): len = n; case .none: len = 0; default: len = -1 } }
            let upstreamClean = mode == .upstream || bodyPushed || framing == .none
            let keep = req.keepAlive && up.keepAlive && clientMayContinue && framing != .untilClose
            sendResponse(status: d.status ?? up.status, headers: d.headerFields, mode: mode, length: len, lane: d.lane,
                         method: req.method, clientVersion: req.version, keepAlive: keep, upFraming: framing) { [self] ok in
                endFlow(ok ? "" : "client write")
                lease?.release(reusable: ok && keep && upstreamClean && upBuf.isEmpty); lease = nil
                if ok && keep { requestsServed += 1; nextRequest() } else { finish(cancelled: nil) }
            }
        case .upgrade:
            guard up.status == 101 else { return fail(S2Error.go("upgrade on \(up.status)"), status: 502) }
            var hs = d.headerFields.filter { !Self.framingHeader($0.name) }
            hs.append(("Connection", "Upgrade"))
            if let u = up.value(for: "Upgrade") { hs.append(("Upgrade", u)) }
            let h = HTTPResponseHead(status: 101, reason: "Switching Protocols", headers: hs)
            guard let wire = serialized(h) else { return }
            writeClient(wire) { [self] in tunnel() }
        case .error, .busy, .drop, .unknown, .forward, .local:
            fail(S2Error.go(d.note ?? "response \(d.action)"), status: 502)
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
                    case .stop: stopped = true   // Go no longer wants it: stop reading the origin
                    case .gone: return fail(S2Error.go("flow gone"), status: 502)
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
                              upFraming: HTTPBodyFraming = .none, done: @escaping (Bool) -> Void) {
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
            case .read: pullFromGo(.response, out: out, done: fin)
            case .lane:
                guard let lane else { return fail(S2Error.go("lane without handle"), status: nil) }
                pullFromLane(lane, out: { [self] d, n in sentBody += Int64(d.count); out(d, n) }, done: fin)
            case .upstream: relayUpstreamBody(upFraming, out: out, done: fin)
            case .client: fail(S2Error.go("body client in response"), status: nil)
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

    // MARK: upgrade (WebSocket etc.): raw bidirectional pipe after Go said "upgrade"

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

    /// The one exit. cancelled non-nil: the client went away / external cancel (Go sees MitmFlowCancel).
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
        onFinish?(cancelled ?? error)
        onFinish = nil
    }
}
