// Native MitM stage 3 lane s3-h2: one decrypted HTTP/2 client connection, served natively.
//
//   old engine (nativeterm: CONNECT, MitM host list, pinning; ALPN offer incl. "h2" only when the engine's h2
//   option and this switch are on) → MitmTLSFront (h2 listener: ALPN "h2, http/1.1") → TLS → ALPN h2 →
//   NativeH2Session: H2Connection (server role) demultiplexes streams; every stream is an H2Exchange that maps
//   onto the SAME flow API as an HTTP/1.1 request (MitmFlowDriving: the old core — or the native rewrite engine when
//   nativeMitmRewrite is on — decides rewrite / reject / redirect / map local / header + body rewrites /
//   scripts / admission / body lane; nothing is decided here) → origin over h2 (one multiplexed connection per
//   authority) or HTTP/1.1 (pooled), whatever the origin negotiates (H2Upstream.swift).
//
// Switch: app-group bool `nativeMitmH2`, default OFF. Off → the TLS front never offers h2 and the old core never hands
// over h2-only clients: every h2 connection stays on the old path exactly as before. A breaker turns native h2
// off for the run after repeated connection-level failures (new connections then fall back to the old path /
// native HTTP/1.1 before any stream starts). Per stream, anything unsupported is refused cleanly:
// extended CONNECT (:protocol, never advertised) → RST_STREAM(PROTOCOL_ERROR); CONNECT → 501; malformed
// requests → RST_STREAM(PROTOCOL_ERROR); an "upgrade" decision → 502; errors before the response head → 502 /
// 503 / 504, after it → RST_STREAM(INTERNAL_ERROR) (never a truncated body presented as complete); a "drop"
// decision → RST_STREAM(INTERNAL_ERROR) (what the old core's h2 server does for http.ErrAbortHandler).
//
// Memory: streams per connection are capped (SETTINGS_MAX_CONCURRENT_STREAMS, H2Limits); client DATA is held at
// most up to the windows we grant (64 KB per stream, 256 KB per connection) and window is returned only after
// the bytes moved on; outbound DATA waits for the peer's windows (per-stream queue ≤ low-water + one chunk);
// old flow pipes are bounded on the old side (flowPipeCap / flowPipeBudget). The memory governor (feat/s3-mem)
// plugs in through NativeH2Runtime.admitStream (false → REFUSED_STREAM) and the shared session cap.

import Foundation

// MARK: - Switch, limits, breaker

enum NativeH2Runtime {
    /// App-group key; default OFF (integration decided by measurement).
    static let defaultsKey = "nativeMitmH2"
    /// Tests force it; nil = read the app-group default (cached for a second).
    static var override: Bool?

    static var limits: H2Limits = {
        var l = H2Limits()
        l.maxConcurrentStreams = 16
        l.streamWindow = 64 << 10 - 1
        l.connectionWindow = 256 << 10
        return l
    }()
    /// Towards origins: same windows, the origin's own stream limit applies on top.
    static var upstreamLimits: H2Limits = limits
    static var ioChunk = 16 << 10

    /// Memory governor hook: false → the new stream is refused with REFUSED_STREAM (the client retries it later /
    /// elsewhere). nil = admit. Default (native-final integration): the native memory governor (feat/s3-mem, switch
    /// nativeMemGovernor) admits each stream as small work of streamCost bytes; governor off → admit.
    static var admitStream: (() -> Bool)? = { NativeMemoryGovernor.active?.admit(.session, bytes: streamCost) ?? true }
    /// Admission size of one stream: its outbound queue (low-water 16 KB + one chunk) and request head state.
    static let streamCost = 48 << 10

    private static let lock = NSLock()
    private static var cached = false
    private static var readAt: TimeInterval = 0
    private static var failures: [TimeInterval] = []
    private static var tripped = false
    private static var live: [Int64: NativeH2Session] = [:]
    private(set) static var counters = Counters()

    struct Counters: Equatable {
        var sessions = 0, streams = 0, refused = 0, resets = 0, connErrors = 0, upstreamH2 = 0, upstreamH1 = 0
    }

    static var enabled: Bool {
        lock.lock(); defer { lock.unlock() }
        if tripped { return false }
        if let o = override { return o }
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = UserDefaults(suiteName: NativeMitmRuntime.appGroup)?.bool(forKey: defaultsKey) ?? false
        }
        return cached
    }

    /// Connection-level failure we caused or could not handle (not a client going away). 3 in 60 s → off.
    static func noteConnectionError() {
        lock.lock()
        let now = Date().timeIntervalSince1970
        failures = failures.filter { now - $0 < 60 } + [now]
        counters.connErrors += 1
        let trip = failures.count >= 3 && !tripped
        if trip { tripped = true; failures = [] }
        lock.unlock()
    }

    /// Re-arm (tests; a reload re-installs the front).
    static func resetBreaker() { lock.lock(); tripped = false; failures = []; lock.unlock() }

    static func count(_ f: (inout Counters) -> Void) { lock.lock(); f(&counters); lock.unlock() }

    static func retain(_ s: NativeH2Session) { lock.lock(); live[s.id] = s; lock.unlock() }
    static func drop(_ s: NativeH2Session) { lock.lock(); live[s.id] = nil; lock.unlock() }
    static var liveSessions: Int { lock.lock(); defer { lock.unlock() }; return live.count }
    static func cancelAll() {
        lock.lock(); let all = Array(live.values); lock.unlock()
        all.forEach { $0.cancel("tunnel stopping") }
    }
}

// MARK: - Request validation (RFC 9113 §8.3)

struct H2ParsedRequest {
    var head: HTTPRequestHead   // version "HTTP/2.0"; Host first; regular fields lowercase; cookies joined
    var length: Int64           // Content-Length, 0 when the HEADERS ended the stream, -1 unknown
    var scheme: String
    var authority: String
}

enum H2RequestReject: Error, Equatable {
    case malformed(String)
    case connect
    case extendedConnect
}

enum H2Request {
    static let connectionSpecific: Set<String> = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"]

    static func parse(_ fields: HTTPHeaderList, endStream: Bool) -> Result<H2ParsedRequest, H2RequestReject> {
        var method: String?, scheme: String?, authority: String?, path: String?
        var regular: HTTPHeaderList = []
        var cookies: [String] = []
        var cookieAt: Int?
        var seenRegular = false
        var contentLength: Int64?
        for (name, value) in fields {
            if name.hasPrefix(":") {
                if seenRegular { return .failure(.malformed("pseudo-header after regular fields")) }
                func set(_ v: inout String?) -> Bool { if v != nil { return false }; v = value; return true }
                let ok: Bool
                switch name {
                case ":method": ok = set(&method)
                case ":scheme": ok = set(&scheme)
                case ":authority": ok = set(&authority)
                case ":path": ok = set(&path)
                case ":protocol": return .failure(.extendedConnect)
                default: return .failure(.malformed("unknown pseudo-header \(name)"))
                }
                if !ok { return .failure(.malformed("duplicate \(name)")) }
                continue
            }
            seenRegular = true
            if name.isEmpty || name.utf8.contains(where: { ($0 >= 0x41 && $0 <= 0x5A) || $0 <= 0x20 || $0 == 0x7f }) {
                return .failure(.malformed("bad field name"))
            }
            if value.utf8.contains(where: { $0 == 0 || $0 == 0x0A || $0 == 0x0D }) { return .failure(.malformed("bad field value")) }
            if connectionSpecific.contains(name) { return .failure(.malformed("connection-specific field \(name)")) }
            if name == "te" && value.lowercased() != "trailers" { return .failure(.malformed("te: \(value)")) }
            if name == "content-length" {
                guard let n = Int64(value.trimmingCharacters(in: .whitespaces)), n >= 0, contentLength == nil || contentLength == n else {
                    return .failure(.malformed("content-length"))
                }
                contentLength = n
            }
            if name == "host" {
                if authority == nil { authority = value }
                continue
            }
            if name == "cookie" {
                if cookieAt == nil { cookieAt = regular.count; regular.append(("cookie", "")) }
                cookies.append(value)
                continue
            }
            regular.append((name, value))
        }
        guard let m = method, !m.isEmpty else { return .failure(.malformed("no :method")) }
        if m == "CONNECT" { return .failure(.connect) }
        guard let sch = scheme, !sch.isEmpty, let p = path, !p.isEmpty else { return .failure(.malformed("no :scheme / :path")) }
        if let i = cookieAt { regular[i].value = cookies.joined(separator: "; ") } // RFC 9113 §8.2.3, as the old core's h2 server
        let host = authority ?? ""
        let length: Int64 = contentLength ?? (endStream ? 0 : -1)
        var headers: HTTPHeaderList = host.isEmpty ? [] : [("Host", host)]
        headers.append(contentsOf: regular)
        // Unknown length: what the old core's h2 server reports as ContentLength -1; the flow API's head JSON expresses it as
        // chunked (the old core removes Transfer-Encoding exactly like net/http's server does).
        if length < 0 { headers.append(("Transfer-Encoding", "chunked")) }
        let head = HTTPRequestHead(method: m, target: p, version: "HTTP/2.0", headers: headers)
        return .success(H2ParsedRequest(head: head, length: length, scheme: sch, authority: host))
    }

    /// Request / response fields for an h2 peer from the old core's decision headers: lowercase, no hop-by-hop (te only as
    /// "trailers").
    static func h2Fields(_ headers: HTTPHeaderList, dropContentLength: Bool) -> HTTPHeaderList {
        var out: HTTPHeaderList = []
        for (n, v) in headers {
            let ln = H2Text.lower(n)
            if connectionSpecific.contains(ln) || ln == "host" || ln.hasPrefix(":") { continue }
            if ln == "te" && v.lowercased() != "trailers" { continue } // gRPC needs "te: trailers" towards h2 origins
            if dropContentLength && ln == "content-length" { continue }
            out.append((ln, v))
        }
        return out
    }
}

// MARK: - Session

final class NativeH2Session: H2ConnectionOwner {
    static var timeouts = NativeMitmSession.Timeouts()
    static let flowTarget = DispatchQueue(label: "tern.mitm.h2.flow", qos: .utility, attributes: .concurrent)

    let id: Int64
    let conn: MitmAcceptedConnection
    let codec: HTTPCodec
    let driver: MitmFlowDriving
    let bodies: NativeBodyReading
    let queue: DispatchQueue
    private(set) var h2: H2Connection!
    private(set) var upstreams: H2UpstreamManager!
    private var exchanges: [UInt32: H2Exchange] = [:]
    private var finished = false
    private var timer: DispatchSourceTimer?
    private var idleSince = DispatchTime.now()
    private(set) var streamsServed = 0
    /// Test hook: called once when the session is torn down.
    var onFinish: ((String) -> Void)?

    init?(conn: MitmAcceptedConnection, codec: HTTPCodec, opener: H2UpstreamOpening, driver: MitmFlowDriving,
          bodies: NativeBodyReading) {
        guard NativeMitmRuntime.acquire() else { conn.stream.close(); return nil }
        id = NativeMitmRuntime.nextID()
        self.conn = conn; self.codec = codec; self.driver = driver; self.bodies = bodies
        queue = DispatchQueue(label: "tern.mitm.h2.session.\(id)")
        h2 = H2Connection(role: .server, io: conn.stream, queue: queue, limits: NativeH2Runtime.limits)
        upstreams = H2UpstreamManager(queue: queue, opener: opener, limits: NativeH2Runtime.upstreamLimits)
        h2.owner = self
        NativeH2Runtime.count { $0.sessions += 1 }
    }

    var connInfo: MitmConnInfo { MitmConnInfo(host: conn.host, port: conn.port, tls: true, connID: conn.connID) }
    var openExchanges: Int { exchanges.count }

    func start() {
        NativeH2Runtime.retain(self)
        queue.async { [self] in
            h2.start()
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
            t.setEventHandler { [weak self] in self?.tick() }
            t.resume()
            timer = t
        }
    }

    func cancel(_ why: String = "cancelled") { queue.async { [self] in finish(why) } }

    private func tick() {
        guard !finished else { return }
        let now = DispatchTime.now()
        if exchanges.isEmpty {
            let limit = streamsServed == 0 ? Self.timeouts.firstHead : Self.timeouts.keepAliveIdle
            if Double(now.uptimeNanoseconds - idleSince.uptimeNanoseconds) / 1e9 > limit {
                h2.goAway(.noError)
                // the connection closes after GOAWAY is flushed (.closed → finish)
            }
            return
        }
        for (_, ex) in exchanges { ex.tick(now) }
    }

    func exchangeDone(_ sid: UInt32) {
        guard exchanges.removeValue(forKey: sid) != nil else { return }
        streamsServed += 1
        if exchanges.isEmpty { idleSince = .now() }
    }

    // MARK: H2ConnectionOwner

    func h2Event(_ c: H2Connection, _ event: H2Event) {
        guard !finished else { return }
        switch event {
        case .headers(let sid, let fields, let endStream, let trailers):
            if trailers { exchanges[sid]?.clientTrailers(fields); return }
            newStream(sid, fields, endStream)
        case .refused(let sid, _, let reason):
            NativeH2Runtime.count { $0.refused += 1 }
            if h2.streams[sid] != nil { // answerable (header list too large): 431 like the old core's h2 server
                h2.sendHeaders(sid, [(":status", "431"), ("content-length", "0")], endStream: true)
                h2.resetWhenSent(sid, .noError)
            }
            _ = reason
        case .data(let sid, let bytes, let endStream):
            if let ex = exchanges[sid] { ex.clientData(bytes, endStream: endStream) } else { h2.consumed(sid, bytes.count) }
        case .reset(let sid, let code, let byPeer):
            NativeH2Runtime.count { $0.resets += 1 }
            exchanges[sid]?.abort(byPeer ? "client reset the stream (\(code))" : "stream error (\(code))")
        case .writable(let sid):
            exchanges[sid]?.clientSink.writable()
        case .goaway:
            break // the client will open no new streams; open ones finish
        case .closed(let err):
            if let err, [.protocolError, .compressionError, .flowControlError, .frameSizeError].contains(err.code) {
                NativeH2Runtime.noteConnectionError()
            }
            finish(err.map { "\($0)" } ?? "closed")
        }
    }

    private func newStream(_ sid: UInt32, _ fields: HTTPHeaderList, _ endStream: Bool) {
        switch H2Request.parse(fields, endStream: endStream) {
        case .failure(.connect):
            simpleAnswer(sid, status: 501, text: "Tern native MitM: CONNECT over HTTP/2 is not supported\n", requestOpen: !endStream)
        case .failure(.extendedConnect), .failure(.malformed):
            h2.resetStream(sid, .protocolError)
        case .success(let p):
            if let admit = NativeH2Runtime.admitStream, !admit() {
                NativeH2Runtime.count { $0.refused += 1 }
                h2.resetStream(sid, .refusedStream)
                return
            }
            NativeH2Runtime.count { $0.streams += 1 }
            let ex = H2Exchange(session: self, sid: sid, request: p, endStream: endStream)
            exchanges[sid] = ex
            ex.begin()
        }
    }

    /// A local answer that never involves the old core (CONNECT refusal).
    func simpleAnswer(_ sid: UInt32, status: Int, text: String, requestOpen: Bool) {
        let body = Data(text.utf8)
        h2.sendHeaders(sid, [(":status", String(status)), ("content-type", "text/plain; charset=utf-8"),
                             ("content-length", String(body.count))], endStream: false)
        h2.sendData(sid, body)
        h2.endStream(sid)
        if requestOpen { h2.resetWhenSent(sid, .noError) }
    }

    private func finish(_ why: String) {
        guard !finished else { return }
        finished = true
        timer?.cancel(); timer = nil
        let all = exchanges
        exchanges.removeAll()
        for (_, ex) in all { ex.abort("connection closed: \(why)") }
        upstreams.closeAll()
        if !h2.closed { h2.close() }
        NativeMitmRuntime.release()
        NativeH2Runtime.drop(self)
        onFinish?(why)
        onFinish = nil
    }
}

// MARK: - One stream

final class H2Exchange {
    let s: NativeH2Session
    let sid: UInt32
    let req: HTTPRequestHead
    let reqLength: Int64
    let queue: DispatchQueue
    let driver: MitmFlowDriving
    let clientIn: H2InboundBody
    let clientSink: H2StreamSink
    let flowQ: DispatchQueue
    private(set) var flowID: Int64 = 0
    private(set) var finished = false
    private var responseStarted = false
    private var sentBody: Int64 = 0
    private var call: H2UpstreamCall?
    private var upstreamLength: Int64 = -1
    private var reqRest: H2BodySource?       // request body left after a need-body phase
    private var respRest: H2BodySource?      // response body left after a need-body phase
    private var bodyPushed = false
    private var upTrailers: HTTPHeaderList?
    private var waitingHeadSince: DispatchTime?
    private var lastProgress = DispatchTime.now()

    init(session: NativeH2Session, sid: UInt32, request p: H2ParsedRequest, endStream: Bool) {
        s = session
        self.sid = sid
        req = p.head
        reqLength = p.length
        queue = session.queue
        driver = session.driver
        let h2 = session.h2!
        clientIn = H2InboundBody(queue: session.queue) { [weak h2] n in h2?.consumed(sid, n) }
        if p.length >= 0 { clientIn.expectedLength = p.length }
        clientSink = H2StreamSink(conn: h2, stream: sid)
        flowQ = DispatchQueue(label: "tern.mitm.h2.flow.\(session.id).\(sid)", target: NativeH2Session.flowTarget)
        if endStream { clientIn.finish(trailers: nil) }
    }

    func touch() { lastProgress = .now() }

    /// Runs a (possibly blocking) driver call off the session queue; `then` runs on the session queue unless the
    /// exchange finished meanwhile.
    func onFlow<T>(_ work: @escaping () -> T, _ then: @escaping (T) -> Void) {
        flowQ.async { [self] in
            let r = work()
            queue.async { [self] in
                guard !finished else { return }
                then(r)
            }
        }
    }

    // MARK: client side events

    func clientData(_ d: Data, endStream: Bool) {
        if !d.isEmpty { clientIn.push(d) }
        if endStream { clientIn.finish(trailers: nil) }
        touch()
    }

    func clientTrailers(_ fields: HTTPHeaderList) { clientIn.finish(trailers: fields) }

    // MARK: request phase

    func begin() {
        let head = req, info = s.connInfo, drv = driver
        flowQ.async { [self] in
            let d = drv.requestPhase(head: head, conn: info)
            queue.async { [self] in
                if finished {
                    if d.id != 0 { let id = d.id; DispatchQueue.global(qos: .utility).async { drv.cancel(id, why: "client gone") } }
                    return
                }
                flowID = d.id
                touch()
                applyRequest(d)
            }
        }
    }

    private func applyRequest(_ d: FlowDecision) {
        switch d.action {
        case .needBody:
            guard d.which == FlowBodyWhich.request.rawValue else { return fail("need-body \(d.which) in request phase", status: 502) }
            feedGo(.request, reqRest ?? clientIn) { [self] d2, rest in
                reqRest = rest
                applyRequest(d2)
            }
        case .forward:
            forward(d)
        case .local:
            let source = bodySource(mode: d.body ?? .none, which: .response, lane: d.lane, feed: nil)
            sendResponse(status: d.status ?? 200, headers: d.headerFields, length: d.length, source: source)
        case .drop:
            endFlow("drop")
            s.h2.resetStream(sid, .internalError)
            close(clean: false)
        case .busy:
            fail("busy", status: 503)
        case .error, .respond, .upgrade, .unknown:
            fail(d.note ?? "error", status: 502)
        }
    }

    /// Pushes a body the old core asked for (need-body) until the old core decided; then(decision, the rest of the body).
    private func feedGo(_ which: FlowBodyWhich, _ src: H2BodySource, then: @escaping (FlowDecision, H2BodySource) -> Void) {
        src.pull { [self] chunk in
            guard !finished else { return }
            let id = flowID, drv = driver
            switch chunk {
            case .data(let d):
                touch()
                onFlow({ drv.write(id, which, d) }) { [self] r in
                    switch r {
                    case .taken:
                        feedGo(which, src, then: then)
                    case .stop:   // the old core no longer wants it: stop reading the source
                        src.abandon()
                        onFlow({ drv.await(id) }) { [self] d2 in then(d2, H2PrependSource(queue: queue, first: nil, rest: nil)) }
                    case .full:   // the decision is out: take it, keep this chunk for "more"
                        onFlow({ drv.await(id) }) { [self] d2 in then(d2, H2PrependSource(queue: queue, first: d, rest: src)) }
                    case .gone:
                        fail("flow gone", status: 502)
                    }
                }
            case .end(let t):
                if which == .response { upTrailers = t }
                onFlow({ () -> FlowDecision in drv.closeBody(id, which, error: ""); return drv.await(id) }) { [self] d2 in
                    then(d2, H2PrependSource(queue: queue, first: nil, rest: nil, trailers: t))
                }
            case .failed(let e):
                onFlow({ drv.closeBody(id, which, error: e) }) { _ in }
                fail(e, status: which == .request ? 400 : 502)
            }
        }
    }

    private func bodySource(mode: FlowBodyMode, which: FlowBodyWhich, lane: FlowDecision.Lane?, feed: H2BodySource?) -> H2BodySource {
        switch mode {
        case .read:
            let g = H2GoReadSource(ex: self, which: which, feed: feed)
            if which == .response { g.trailers = { [weak self] in self?.upTrailers } }
            return g
        case .lane:
            guard let lane else { return H2FailSource(queue: queue, why: "lane without handle") }
            let l = H2LaneSource(queue: queue, bodies: s.bodies, lane: lane, chunk: NativeH2Runtime.ioChunk)
            if which == .response { l.trailers = { [weak self] in self?.upTrailers } }
            return l
        case .client:
            return feed ?? H2PrependSource(queue: queue, first: nil, rest: nil)
        case .upstream:
            return feed ?? H2FailSource(queue: queue, why: "no upstream body")
        case .none:
            return H2PrependSource(queue: queue, first: nil, rest: nil)
        }
    }

    // MARK: forward

    private func forward(_ d: FlowDecision) {
        guard let urlStr = d.url, let url = URLComponents(string: urlStr), let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http" else {
            return fail("forward url \(d.url ?? "nil")", status: 502)
        }
        let host = url.host ?? s.conn.host
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        var target = url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath
        if let q = url.percentEncodedQuery { target += "?" + q }
        let mode = d.body ?? .none
        if mode == .client && reqRest != nil { return fail("body client after the body was pushed", status: 502) }
        if mode == .upstream { return fail("body upstream in forward", status: 502) }
        let authority = d.host ?? (url.port.map { "\(host):\($0)" } ?? host)
        let length: Int64
        switch mode {
        case .client: length = reqLength
        case .read, .lane: length = d.length
        default: length = 0
        }
        let hasBody = mode != .none && length != 0
        let method = d.method ?? req.method
        let headers = d.headerFields.filter { let n = $0.name.lowercased(); return !H2Request.connectionSpecific.contains(n) && n != "host" && n != "content-length" && (n != "te" || $0.value.lowercased() == "trailers") }
        let upReq = H2UpstreamRequest(method: method, scheme: scheme, authority: authority, target: target, headers: headers,
                                      bodyLength: length, hasBody: hasBody)
        if !hasBody && mode != .client { clientIn.abandon() }
        waitingHeadSince = .now()
        s.upstreams.link(host: host, port: port, tls: scheme == "https") { [self] r in
            guard !finished else { if case .success(.h1(let t)) = r { t.release(reusable: false) }; return }
            switch r {
            case .failure(let e):
                upstreamFailed("\(e)")
            case .success(.h2(let c)):
                var h2req = upReq
                h2req.headers = H2Request.h2Fields(upReq.headers, dropContentLength: true)
                guard let call = s.upstreams.call(on: c, h2req) else { return upstreamFailed("no h2 stream available") }
                NativeH2Runtime.count { $0.upstreamH2 += 1 }
                started(call, mode: mode, decision: d, hasBody: hasBody)
            case .success(.h1(let t)):
                NativeH2Runtime.count { $0.upstreamH1 += 1 }
                let call = H1UpstreamCall(queue: queue, transport: t, codec: s.codec, method: method)
                started(call, mode: mode, decision: d, hasBody: hasBody)
                call.send(upReq)
            }
        }
    }

    private func started(_ call: H2UpstreamCall, mode: FlowBodyMode, decision d: FlowDecision, hasBody: Bool) {
        self.call = call
        call.onHead = { [self] r in
            guard !finished else { return }
            switch r {
            case .failure(let e):
                upstreamFailed("\(e)")
            case .success(let x):
                waitingHeadSince = nil
                upstreamLength = x.length
                touch()
                let id = flowID, drv = driver
                onFlow({ drv.responsePhase(id, head: x.head, length: x.length) }) { [self] d2 in applyResponse(d2, head: x.head) }
            }
        }
        guard hasBody else { return }
        let feed: H2BodySource = reqRest ?? clientIn
        let src = bodySource(mode: mode, which: .request, lane: d.lane, feed: feed)
        h2Pump(src, call.requestSink, progress: { [weak self] _ in self?.touch() }) { [self] r in
            guard !finished else { return }
            if case .sourceFailed(let e) = r { fail(e, status: 400) }
            // sinkFailed: the origin went away; the response side reports it.
        }
    }

    private func upstreamFailed(_ why: String) {
        guard !finished else { return }
        let id = flowID, drv = driver
        if id != 0 { flowQ.async { drv.upstreamFailed(id, why: why) } }
        fail(why, status: 502)
    }

    // MARK: response phase

    private func applyResponse(_ d: FlowDecision, head: HTTPResponseHead) {
        switch d.action {
        case .needBody:
            guard let call else { return fail("need-body without an upstream", status: 502) }
            bodyPushed = true
            feedGo(.response, respRest ?? call.responseBody) { [self] d2, rest in
                respRest = rest
                applyResponse(d2, head: head)
            }
        case .respond:
            let mode = d.body ?? .none
            if mode == .upstream && bodyPushed { return fail("body upstream after push", status: 502) }
            var len = d.length
            if mode == .upstream { len = upstreamLength }
            if mode == .none || mode == .lane { if !bodyPushed { call?.responseBody.abandon() } }
            let feed: H2BodySource? = respRest ?? call?.responseBody
            let source = bodySource(mode: mode, which: .response, lane: d.lane, feed: feed)
            sendResponse(status: d.status ?? head.status, headers: d.headerFields, length: len, source: source)
        case .upgrade:
            fail("upgrade over HTTP/2", status: 502)
        case .error, .busy, .drop, .unknown, .forward, .local:
            fail(d.note ?? "response \(d.action)", status: 502)
        }
    }

    private func sendResponse(status: Int, headers: HTTPHeaderList, length: Int64, source: H2BodySource) {
        let bodyless = req.method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status)
        var fields: HTTPHeaderList = [(":status", String(status))]
        fields.append(contentsOf: H2Request.h2Fields(headers, dropContentLength: !bodyless))
        if length >= 0 && !bodyless { fields.append(("content-length", String(length))) }
        responseStarted = true
        touch()
        if bodyless {
            s.h2.sendHeaders(sid, fields, endStream: true)
            source.abandon()
            return complete()
        }
        s.h2.sendHeaders(sid, fields, endStream: false)
        h2Pump(source, clientSink, progress: { [weak self] n in self?.sentBody += Int64(n); self?.touch() }) { [self] r in
            guard !finished else { return }
            switch r {
            case .ok: complete()
            case .sourceFailed(let e): fail(e, status: nil)
            case .sinkFailed: abort("client stream gone")
            }
        }
    }

    // MARK: endings

    private func complete() {
        endFlow("")
        close(clean: true)
    }

    private func endFlow(_ err: String) {
        guard flowID != 0 else { return }
        let id = flowID, sent = sentBody, drv = driver
        flowID = 0
        flowQ.async { drv.end(id, sent: sent, error: err) }
    }

    private func close(clean: Bool) {
        guard !finished else { return }
        finished = true
        call?.finish(clean: clean)
        call = nil
        reqRest?.abandon(); respRest?.abandon()
        let requestOpen = !clientIn.isEnded
        clientIn.abandon()
        if requestOpen, s.h2.streams[sid] != nil {
            if clean { s.h2.resetWhenSent(sid, .noError) } else { s.h2.resetStream(sid, .cancel) }
        }
        clientSink.kill()
        s.exchangeDone(sid)
    }

    /// Error: an answer if nothing of the response went out yet (status non-nil), else a stream reset.
    func fail(_ why: String, status: Int?) {
        guard !finished else { return }
        endFlow(why)
        if let status, !responseStarted, s.h2.streams[sid] != nil {
            responseStarted = true
            s.simpleAnswer(sid, status: status, text: "Tern native MitM: \(why)\n", requestOpen: false)
        } else if s.h2.streams[sid] != nil {
            s.h2.resetStream(sid, .internalError)
        }
        close(clean: false)
    }

    /// The client reset the stream / the connection is gone: cancel the flow (the old core wakes its waits).
    func abort(_ why: String) {
        guard !finished else { return }
        if flowID != 0 {
            let id = flowID, drv = driver
            flowID = 0
            DispatchQueue.global(qos: .utility).async { drv.cancel(id, why: why) }
        }
        close(clean: false)
    }

    func tick(_ now: DispatchTime) {
        guard !finished else { return }
        func secs(_ t: DispatchTime) -> Double { Double(now.uptimeNanoseconds &- t.uptimeNanoseconds) / 1e9 }
        if let w = waitingHeadSince, secs(w) > NativeH2Session.timeouts.upstreamHead {
            return upstreamFailedTimeout()
        }
        if secs(lastProgress) > NativeH2Session.timeouts.bodyStall {
            fail("no progress for \(Int(NativeH2Session.timeouts.bodyStall)) s", status: 504)
        }
    }

    private func upstreamFailedTimeout() {
        let id = flowID, drv = driver
        if id != 0 { flowQ.async { drv.upstreamFailed(id, why: "upstream head timeout") } }
        fail("upstream head timeout", status: 504)
    }
}

/// A body the old core produces (FlowRead) — a local answer, or a rewritten request / response body. When the old core answers
/// "more" it needs the next piece of the original body first (feed), pushed with FlowWrite.
final class H2GoReadSource: H2BodySource {
    let ex: H2Exchange
    let which: FlowBodyWhich
    private let feed: H2BodySource?
    private var pending: Data?
    private var feedEnded = false
    private var feedTrailers: HTTPHeaderList?
    private var abandoned = false
    var trailers: () -> HTTPHeaderList? = { nil }

    init(ex: H2Exchange, which: FlowBodyWhich, feed: H2BodySource?) {
        self.ex = ex; self.which = which; self.feed = feed
    }

    func pull(_ cb: @escaping (H2Chunk) -> Void) {
        let id = ex.flowID, drv = ex.driver, which = self.which, max = NativeH2Runtime.ioChunk
        ex.onFlow({ () -> (Data, FlowReadState) in
            let d = drv.read(id, which, max: max)
            return (d, d.isEmpty ? drv.readState(id, which) : .again)
        }) { [self] r in
            if abandoned { return }
            if !r.0.isEmpty { return cb(.data(r.0)) }
            switch r.1 {
            case .again: later(cb)
            case .eof: cb(.end(feedTrailers ?? trailers()))
            case .failed(let e): cb(.failed(e))
            case .more: feedOne(cb)
            }
        }
    }

    private func later(_ cb: @escaping (H2Chunk) -> Void) {
        ex.queue.asyncAfter(deadline: .now() + .milliseconds(2)) { [self] in
            if !abandoned && !ex.finished { pull(cb) }
        }
    }

    private func feedOne(_ cb: @escaping (H2Chunk) -> Void) {
        if let p = pending { pending = nil; return push(p, cb) }
        guard let feed, !feedEnded else { return later(cb) }
        feed.pull { [self] c in
            if abandoned || ex.finished { return }
            let id = ex.flowID, drv = ex.driver, which = self.which
            switch c {
            case .data(let d):
                ex.touch()
                push(d, cb)
            case .end(let t):
                feedEnded = true
                feedTrailers = t
                ex.onFlow({ drv.closeBody(id, which, error: "") }) { [self] _ in pull(cb) }
            case .failed(let e):
                feedEnded = true
                ex.onFlow({ drv.closeBody(id, which, error: e) }) { _ in cb(.failed(e)) }
            }
        }
    }

    private func push(_ d: Data, _ cb: @escaping (H2Chunk) -> Void) {
        let id = ex.flowID, drv = ex.driver, which = self.which
        ex.onFlow({ drv.write(id, which, d) }) { [self] r in
            switch r {
            case .taken: pull(cb)
            case .full: pending = d; later(cb)     // drain with FlowRead first, then push it again
            case .stop: feedEnded = true; feed?.abandon(); pull(cb)
            case .gone: cb(.failed("flow gone"))
            }
        }
    }

    func abandon() {
        abandoned = true
        feed?.abandon()
    }
}

final class H2FailSource: H2BodySource {
    private let queue: DispatchQueue
    private let why: String
    init(queue: DispatchQueue, why: String) { self.queue = queue; self.why = why }
    func pull(_ cb: @escaping (H2Chunk) -> Void) { let w = why; queue.async { cb(.failed(w)) } }
    func abandon() {}
}
