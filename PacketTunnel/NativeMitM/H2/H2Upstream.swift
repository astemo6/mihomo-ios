// Native MitM stage 3 lane s3-h2: the origin side of a native HTTP/2 session.
//
// The origin speaks h2 or HTTP/1.1 — whatever it negotiates via ALPN. HTTPS origins are opened offering
// "h2, http/1.1" through the Go relay (UpstreamConnection, so mihomo's rules / proxies still pick the route);
// an h2 origin gets one multiplexed H2Connection (client role) per authority per session, shared by that
// session's streams; an HTTP/1.1 origin gets one pooled connection per in-flight stream (UpstreamPool, exactly
// like the stage-2 session). Plain-http forward URLs (a rewrite to http://) always use HTTP/1.1.
//
// Calls: H2UpstreamCall is one request/response on either kind; the exchange sees only requestSink /
// responseBody / onHead and never which protocol carried it.

import Foundation
#if !TERN_NO_GO
import Libmihomo
#endif

/// An opened origin connection.
final class H2UpstreamTransport {
    let stream: ByteStream
    let alpn: String?
    private let releaseFn: (Bool) -> Void
    private var released = false
    init(stream: ByteStream, alpn: String?, release: @escaping (Bool) -> Void) {
        self.stream = stream; self.alpn = alpn; releaseFn = release
    }
    /// HTTP/1.1: back to the pool when reusable; h2: closes.
    func release(reusable: Bool) {
        guard !released else { return }
        released = true
        releaseFn(reusable)
    }
}

protocol H2UpstreamOpening: AnyObject {
    /// offerH2: ALPN "h2, http/1.1" (TLS only); else HTTP/1.1. Completion on any queue.
    func open(host: String, port: Int, tls: Bool, offerH2: Bool, completion: @escaping (Result<H2UpstreamTransport, Error>) -> Void)
}

/// Production: through the Go relay. h2 offers dial a dedicated UpstreamConnection; HTTP/1.1 goes through the
/// stage-2 pool (UpstreamPoolConnector); an h2 offer the origin answered with http/1.1 is handed back to the pool.
final class H2RelayUpstreamOpener: H2UpstreamOpening {
    let pool: UpstreamPool
    let h1: MitmUpstreamConnecting
    private let lock = NSLock()
    private var ids: UInt64 = 1 << 40

    init(pool: UpstreamPool = .shared, h1: MitmUpstreamConnecting? = nil) {
        self.pool = pool
        self.h1 = h1 ?? UpstreamPoolConnector(pool: pool)
    }

    func open(host: String, port: Int, tls: Bool, offerH2: Bool, completion: @escaping (Result<H2UpstreamTransport, Error>) -> Void) {
        guard (1...65535).contains(port) else { return completion(.failure(UpstreamError.invalidTarget("port"))) }
        if !(tls && offerH2) {
            h1.open(host: host, port: port, tls: tls) { r in
                completion(r.map { lease in H2UpstreamTransport(stream: lease.stream, alpn: nil) { lease.release(reusable: $0) } })
            }
            return
        }
        #if TERN_NO_GO
        // Gap C6 (astemo6/Muse NativeCore): the dedicated h2 dial below has no relay in the Go-free tunnel and went
        // straight to the origin whatever the rules said. Only a DIRECT route keeps it; a proxied (or rejected)
        // origin goes through NCUpstreamConnector — rules, groups, the proxy, origin TLS over the relay — offering
        // "h2, http/1.1"; NCTLSClientStream reports the origin's ALPN, so an h2 origin gets the multiplexed h2
        // connection here too (feat/nc-proto2) and an h1 origin the per-stream HTTP/1.1 path.
        if let engine = NativeCoreEngine.active {
            let ctx = engine.matchContext(domain: NCIP(host) == nil ? host : nil, ip: NCIP(host), dstPort: port, network: "tcp")
            if case .direct = engine.resolve(ctx) {} else {
                NCUpstreamConnector.shared.open(host: host, port: port, tls: true, policy: nil, insecure: false,
                                                alpn: ["h2", "http/1.1"]) { r in
                    completion(r.map { lease in
                        let alpn = (lease as? NCRelayUpstreamLease)?.negotiatedALPN
                        return H2UpstreamTransport(stream: lease.stream, alpn: alpn == "h2" ? "h2" : nil) {
                            lease.release(reusable: $0)
                        }
                    })
                }
                return
            }
        }
        #endif
        lock.lock(); ids += 1; let id = ids; lock.unlock()
        let pool = self.pool
        UpstreamConnection.open(target: UpstreamTarget(host: host, port: UInt16(port), tls: true),
                                relayPort: H2UpstreamRelay.port(pool), queue: pool.queue, id: id,
                                connectTimeout: pool.config.connectTimeout, alpn: ["h2", "http/1.1"]) { r in
            switch r {
            case .failure(let e): completion(.failure(e))
            case .success(let c):
                let alpn = c.negotiatedALPN
                let isH2 = alpn == "h2"
                completion(.success(H2UpstreamTransport(stream: UpstreamStreamAdapter(c), alpn: alpn) { reusable in
                    if isH2 { c.close() } else { pool.release(c, reusable: reusable) }
                }))
            }
        }
    }
}

/// What the exchange sends upstream.
struct H2UpstreamRequest {
    var method: String
    var scheme: String
    var authority: String
    var target: String
    var headers: HTTPHeaderList     // regular fields only (no pseudo, no hop-by-hop, no Host)
    var bodyLength: Int64           // -1 unknown, 0 none
    var hasBody: Bool
}

protocol H2UpstreamCall: AnyObject {
    var requestSink: H2BodySink { get }
    var responseBody: H2BodySource { get }
    /// Set by the exchange before anything can arrive; fires once.
    var onHead: ((Result<(head: HTTPResponseHead, length: Int64), S2Error>) -> Void)? { get set }
    /// The exchange is done with it. clean: request and response completed (an h1 connection may be reused).
    func finish(clean: Bool)
    var protocolName: String { get }
}

// MARK: - h2 origin

final class H2UpstreamStreamCall: H2UpstreamCall {
    let conn: H2Connection
    let sid: UInt32
    let sink: H2StreamSink
    let body: H2InboundBody
    var onHead: ((Result<(head: HTTPResponseHead, length: Int64), S2Error>) -> Void)?
    private var gotHead = false
    private var done = false
    private weak var manager: H2UpstreamManager?
    var requestSink: H2BodySink { sink }
    var responseBody: H2BodySource { body }
    var protocolName: String { "h2" }

    init(conn: H2Connection, sid: UInt32, manager: H2UpstreamManager) {
        self.conn = conn
        self.sid = sid
        self.manager = manager
        sink = H2StreamSink(conn: conn, stream: sid)
        let c = conn
        body = H2InboundBody(queue: conn.queue) { [weak c] n in c?.consumed(sid, n) }
    }

    func send(_ r: H2UpstreamRequest) {
        var fields: HTTPHeaderList = [(":method", r.method), (":scheme", r.scheme), (":authority", r.authority), (":path", r.target)]
        fields.append(contentsOf: r.headers)
        if r.bodyLength >= 0 && (r.hasBody || ["POST", "PUT", "PATCH"].contains(r.method)) {
            fields.append(("content-length", String(r.bodyLength)))
        }
        conn.sendHeaders(sid, fields, endStream: !r.hasBody)
    }

    func event(_ e: H2Event) {
        switch e {
        case .headers(_, let fields, let endStream, let trailers):
            if trailers { body.finish(trailers: fields.filter { !$0.name.hasPrefix(":") }); return }
            guard !gotHead else { return }
            gotHead = true
            guard let st = fields.first(where: { $0.name == ":status" })?.value, let status = Int(st), (200...999).contains(status) else {
                onHead?(.failure(.upstream("bad :status")))
                onHead = nil
                return
            }
            let hs = fields.filter { !$0.name.hasPrefix(":") }
            var length: Int64 = -1
            if endStream { length = 0 }
            else if let cl = hs.first(where: { $0.name == "content-length" })?.value, let n = Int64(cl.trimmingCharacters(in: .whitespaces)), n >= 0 {
                length = n
                body.expectedLength = n
            }
            let head = HTTPResponseHead(status: status, reason: NativeMitmSession.reason(status), version: "HTTP/2.0", headers: hs)
            if endStream { body.finish(trailers: nil) }
            onHead?(.success((head, length)))
            onHead = nil
        case .data(_, let bytes, let endStream):
            if !bytes.isEmpty { body.push(bytes) }
            if endStream { body.finish(trailers: nil) }
        case .reset(_, let code, _):
            sink.kill()
            if !gotHead { onHead?(.failure(.upstream("origin reset the stream (\(code))"))); onHead = nil }
            body.fail("origin reset the stream (\(code))")
            manager?.forget(self)
        case .writable:
            sink.writable()
        case .closed(let err):
            sink.kill()
            let why = err.map { "\($0)" } ?? "origin closed the connection"
            if !gotHead { onHead?(.failure(.upstream(why))); onHead = nil }
            body.fail(why)
        default:
            break
        }
    }

    func finish(clean: Bool) {
        guard !done else { return }
        done = true
        if !clean, conn.streams[sid] != nil { conn.resetStream(sid, .cancel) }
        body.abandon()
        manager?.forget(self)
    }
}

// MARK: - HTTP/1.1 origin

final class H1UpstreamCall: H2UpstreamCall {
    private let queue: DispatchQueue
    private let transport: H2UpstreamTransport
    private let codec: HTTPCodec
    private let method: String
    private var upBuf = Data()
    private var responseFraming: HTTPBodyFraming = .none
    private var keepAlive = false
    private var bodyComplete = false
    private var requestComplete = false
    private var done = false
    private var dead = false
    private var source: H1ResponseSource!
    private var sinkImpl: H1RequestSink!
    var onHead: ((Result<(head: HTTPResponseHead, length: Int64), S2Error>) -> Void)?
    var requestSink: H2BodySink { sinkImpl }
    var responseBody: H2BodySource { source }
    var protocolName: String { "http/1.1" }

    init(queue: DispatchQueue, transport: H2UpstreamTransport, codec: HTTPCodec, method: String) {
        self.queue = queue
        self.transport = transport
        self.codec = codec
        self.method = method
        source = H1ResponseSource(call: self)
        sinkImpl = H1RequestSink(call: self)
    }

    fileprivate var chunked = false

    func send(_ r: H2UpstreamRequest) {
        var headers: HTTPHeaderList = [("Host", r.authority)]
        headers.append(contentsOf: r.headers)
        if r.hasBody {
            if r.bodyLength >= 0 { headers.append(("Content-Length", String(r.bodyLength))) }
            else { headers.append(("Transfer-Encoding", "chunked")); chunked = true }
        } else if ["POST", "PUT", "PATCH"].contains(r.method) {
            headers.append(("Content-Length", "0"))
        }
        let head = HTTPRequestHead(method: r.method, target: r.target, version: "HTTP/1.1", headers: headers)
        guard let wire = try? codec.serialize(head) else { return die("request head not serializable") }
        if !r.hasBody { requestComplete = true }
        write(wire) { _ in }
        readHead()
    }

    fileprivate func write(_ d: Data, _ cb: @escaping (Bool) -> Void) {
        guard !dead else { return queue.async { cb(false) } }
        transport.stream.write(d) { [weak self] err in
            guard let self else { return }
            self.queue.async {
                if err != nil { self.die("write: \(err!)"); return cb(false) }
                cb(!self.dead)
            }
        }
    }

    fileprivate func requestFinished() { requestComplete = true }

    fileprivate func read(_ cb: @escaping (Bool) -> Void) {
        guard !dead else { return queue.async { cb(false) } }
        transport.stream.read(min: 1, max: 32 << 10) { [weak self] data, eof, err in
            guard let self else { return }
            self.queue.async {
                if let err { self.die("read: \(err)"); return cb(false) }
                let d = data ?? Data()
                self.upBuf.append(d)
                cb(!(eof && d.isEmpty))
            }
        }
    }

    private func readHead() {
        do {
            if let h = try codec.parseResponseHead(&upBuf) {
                if h.isInterim { return readHead() }
                responseFraming = codec.responseFraming(h, requestMethod: method)
                keepAlive = h.keepAlive && responseFraming != .untilClose
                let length: Int64
                switch responseFraming { case .none: length = 0; case .contentLength(let n): length = n; default: length = -1 }
                source.start(decoder: codec.makeDecoder(responseFraming))
                onHead?(.success((h, length)))
                onHead = nil
                return
            }
        } catch {
            return die("response head: \(error)")
        }
        read { [weak self] more in
            guard let self else { return }
            if !more { return self.die("closed before the response head") }
            self.readHead()
        }
    }

    fileprivate func takeBuffered() -> Data { let d = upBuf; upBuf = Data(); return d }
    fileprivate func putBack(_ d: Data) { upBuf = d + upBuf }
    fileprivate func bodyDone(clean: Bool) { bodyComplete = clean }

    fileprivate func die(_ why: String) {
        guard !dead else { return }
        dead = true
        if let cb = onHead { onHead = nil; cb(.failure(.upstream(why))) }
        source.fail(why)
    }

    func finish(clean: Bool) {
        guard !done else { return }
        done = true
        let reusable = clean && !dead && keepAlive && bodyComplete && requestComplete && upBuf.isEmpty
        transport.release(reusable: reusable)
    }
}

final class H1ResponseSource: H2BodySource {
    private unowned let call: H1UpstreamCall
    private var decoder: HTTPBodyDecoding?
    private var failure: String?
    private var finished = false
    private var waiter: ((H2Chunk) -> Void)?
    init(call: H1UpstreamCall) { self.call = call }

    func start(decoder: HTTPBodyDecoding) { self.decoder = decoder }

    func fail(_ why: String) {
        failure = why
        if let cb = waiter { waiter = nil; cb(.failed(why)) }
    }

    func pull(_ cb: @escaping (H2Chunk) -> Void) {
        if let f = failure { return asyncCB(cb, .failed(f)) }
        guard let dec = decoder, !finished else { return asyncCB(cb, .end(nil)) }
        let buf = call.takeBuffered()
        do {
            let c = try dec.feed(buf)
            if c.consumed < buf.count { call.putBack(buf.subdata(in: (buf.startIndex + c.consumed)..<buf.endIndex)) }
            if c.done {
                finished = true
                call.bodyDone(clean: true)
                if c.payload.isEmpty { return asyncCB(cb, .end(nil)) }
                return asyncCB(cb, .data(c.payload))
            }
            if !c.payload.isEmpty { return asyncCB(cb, .data(c.payload)) }
        } catch {
            return asyncCB(cb, .failed("response body: \(error)"))
        }
        waiter = cb
        call.read { [weak self] more in
            guard let self, let w = self.waiter else { return }
            self.waiter = nil
            if !more {
                do {
                    let tail = try dec.finishAtEOF()
                    self.finished = true
                    self.call.bodyDone(clean: false)
                    w(tail.isEmpty ? .end(nil) : .data(tail))
                } catch {
                    w(.failed("upstream truncated the body"))
                }
                return
            }
            self.pull(w)
        }
    }

    private func asyncCB(_ cb: @escaping (H2Chunk) -> Void, _ c: H2Chunk) { call.queueAsync { cb(c) } }

    func abandon() { waiter = nil; finished = true }
}

extension H1UpstreamCall {
    fileprivate func queueAsync(_ f: @escaping () -> Void) { queue.async(execute: f) }
}

final class H1RequestSink: H2BodySink {
    private unowned let call: H1UpstreamCall
    init(call: H1UpstreamCall) { self.call = call }
    func write(_ d: Data, _ cb: @escaping (Bool) -> Void) {
        call.write(call.chunked ? HTTPChunkedEncoder.chunk(d) : d, cb)
    }
    func finish(trailers: HTTPHeaderList?, _ cb: @escaping (Bool) -> Void) {
        call.requestFinished()
        if call.chunked { call.write(Data("0\r\n\r\n".utf8), cb) } else { call.queueAsync { cb(true) } }
    }
}

// MARK: - per-session manager

/// The origin connections of one native h2 session: one shared H2Connection per h2 authority (bounded), HTTP/1.1
/// connections per call. Lives on the session queue; closed with the session.
final class H2UpstreamManager: H2ConnectionOwner {
    enum Link { case h2(H2Connection), h1(H2UpstreamTransport) }

    let queue: DispatchQueue
    let opener: H2UpstreamOpening
    let limits: H2Limits
    var maxConnections = 4
    private var conns: [String: H2Connection] = [:]
    private var h1Only: Set<String> = []
    private var waiting: [String: [(Result<Link, Error>) -> Void]] = [:]
    private var calls: [ObjectIdentifier: [UInt32: H2UpstreamStreamCall]] = [:]
    private var closedAll = false
    private(set) var opened = 0

    init(queue: DispatchQueue, opener: H2UpstreamOpening, limits: H2Limits) {
        self.queue = queue; self.opener = opener; self.limits = limits
    }

    var h2Connections: Int { conns.count }

    /// A link for one call. Completion on the session queue.
    func link(host: String, port: Int, tls: Bool, completion: @escaping (Result<Link, Error>) -> Void) {
        guard !closedAll else { return queue.async { completion(.failure(S2Error.cancelled)) } }
        let key = "\(host.lowercased()):\(port)"
        if !tls || h1Only.contains(key) { return openH1(host, port, tls, completion) }
        if let c = conns[key] {
            if c.canOpenStream { return queue.async { completion(.success(.h2(c))) } }
            if !c.closed && !c.goingAway && c.peerGoAway == nil {
                // At the origin's stream limit: wait for this connection rather than opening more.
                waiting[key, default: []].append(completion)
                return
            }
            conns[key] = nil
        }
        if waiting[key] != nil { waiting[key]!.append(completion); return }
        if conns.count >= maxConnections { return openH1(host, port, tls, completion) }
        waiting[key] = [completion]
        opened += 1
        opener.open(host: host, port: port, tls: true, offerH2: true) { [weak self] r in
            guard let self else { if case .success(let t) = r { t.release(reusable: false) }; return }
            self.queue.async { self.opened(key, host, port, r) }
        }
    }

    private func opened(_ key: String, _ host: String, _ port: Int, _ r: Result<H2UpstreamTransport, Error>) {
        let ws = waiting.removeValue(forKey: key) ?? []
        if closedAll {
            if case .success(let t) = r { t.release(reusable: false) }
            ws.forEach { $0(.failure(S2Error.cancelled)) }
            return
        }
        switch r {
        case .failure(let e):
            ws.forEach { $0(.failure(e)) }
        case .success(let t):
            if t.alpn == "h2" {
                let c = H2Connection(role: .client, io: t.stream, queue: queue, limits: limits)
                c.owner = self
                conns[key] = c
                c.start()
                ws.forEach { $0(.success(.h2(c))) }
            } else {
                h1Only.insert(key)
                guard let first = ws.first else { return t.release(reusable: true) }
                first(.success(.h1(t)))
                for w in ws.dropFirst() { openH1(host, port, true, w) }
            }
        }
    }

    private func openH1(_ host: String, _ port: Int, _ tls: Bool, _ completion: @escaping (Result<Link, Error>) -> Void) {
        opener.open(host: host, port: port, tls: tls, offerH2: false) { [weak self] r in
            guard let self else { if case .success(let t) = r { t.release(reusable: false) }; return }
            self.queue.async {
                if self.closedAll { if case .success(let t) = r { t.release(reusable: false) }; return completion(.failure(S2Error.cancelled)) }
                completion(r.map { .h1($0) })
            }
        }
    }

    /// Opens a stream on c and sends the request head.
    func call(on c: H2Connection, _ r: H2UpstreamRequest) -> H2UpstreamStreamCall? {
        guard let sid = c.openStream() else { return nil }
        let call = H2UpstreamStreamCall(conn: c, sid: sid, manager: self)
        calls[ObjectIdentifier(c), default: [:]][sid] = call
        call.send(r)
        return call
    }

    func forget(_ call: H2UpstreamStreamCall) {
        calls[ObjectIdentifier(call.conn)]?[call.sid] = nil
        wakeWaiters(for: call.conn)
    }

    private func wakeWaiters(for c: H2Connection) {
        guard let key = conns.first(where: { $0.value === c })?.key, var ws = waiting[key], !ws.isEmpty else { return }
        // Only waiters queued behind a full connection (not an open in progress, which has no entry in conns).
        while c.canOpenStream, !ws.isEmpty {
            let w = ws.removeFirst()
            queue.async { w(.success(.h2(c))) }
        }
        waiting[key] = ws.isEmpty ? nil : ws
    }

    // H2ConnectionOwner
    func h2Event(_ c: H2Connection, _ event: H2Event) {
        let id = ObjectIdentifier(c)
        switch event {
        case .headers(let sid, _, _, _), .data(let sid, _, _), .reset(let sid, _, _), .writable(let sid):
            calls[id]?[sid]?.event(event)
        case .refused:
            break
        case .goaway:
            if let key = conns.first(where: { $0.value === c })?.key { conns[key] = nil; failWaiters(key) }
        case .closed:
            let cs = calls.removeValue(forKey: id) ?? [:]
            if let key = conns.first(where: { $0.value === c })?.key { conns[key] = nil; failWaiters(key) }
            for (_, call) in cs { call.event(event) }
        }
    }

    private func failWaiters(_ key: String) {
        // Re-dispatch queued waiters: they will open a fresh connection.
        guard let ws = waiting.removeValue(forKey: key) else { return }
        let parts = key.split(separator: ":")
        let host = parts.dropLast().joined(separator: ":")
        let port = Int(parts.last ?? "443") ?? 443
        for w in ws { link(host: host, port: port, tls: true, completion: w) }
    }

    /// Session over: close everything (open streams were already reset by their exchanges).
    func closeAll() {
        closedAll = true
        for (_, c) in conns { c.goAway(.noError); c.close() }
        conns.removeAll()
        calls.removeAll()
        let ws = waiting
        waiting.removeAll()
        for (_, list) in ws { list.forEach { w in queue.async { w(.failure(S2Error.cancelled)) } } }
    }
}

/// The relay port for h2 upstreams: Go's CONNECT relay in the app-hosted tests; in the Go-free tunnel there is no relay
/// (native h2 is not offered there — NativeH2Runtime.enabled stays false — so this is never dialled).
enum H2UpstreamRelay {
    static func port(_ pool: UpstreamPool) -> Int {
        #if TERN_NO_GO
        return pool.relayPort() > 0 ? pool.relayPort() : 0
        #else
        return Int(LibmihomoMitmRelayPort())
        #endif
    }
}
