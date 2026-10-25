import Foundation
import Network

/// A proxied/direct UDP association for one stack session. `send` carries the
/// per-datagram target because SOCKS5-style relays are target-agnostic.
protocol NCUDPSession: AnyObject {
    var onReply: (Data) -> Void { get set }
    func send(_ data: Data, to target: NCTarget)
    func cancel()
}

/// DIRECT UDP via NWConnection to the (single) first target; later datagrams
/// to other targets on the same stack session spawn their own association in
/// the data plane, so this stays one-to-one.
final class NCUDPDirectSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let conn: NWConnection
    private var cancelled = false

    init(target: NCTarget, queue: DispatchQueue) {
        let port = NWEndpoint.Port(rawValue: UInt16(clamping: target.port)) ?? .any
        conn = NWConnection(host: NWEndpoint.Host(target.host), port: port, using: NCOutboundBinding.params(.udp, host: target.host))
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, !data.isEmpty { self.onReply(data) }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        conn.send(content: data, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}

/// SOCKS5 UDP associate (RFC 1928): a TCP control connection performs the
/// greeting/auth and the UDP ASSOCIATE request; datagrams then go to the
/// relay address the server returns, wrapped in the SOCKS UDP header.
final class NCUDPSocks5Session: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    var onReady: (Bool) -> Void = { _ in }

    private let control: NCStream
    private let serverHost: String
    private var udp: NWConnection?
    private var ready = false
    private var queued: [(Data, NCTarget)] = []
    private var cancelled = false

    init(proxy: NCProxy, queue: DispatchQueue) {
        serverHost = proxy.server ?? ""
        control = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        control.start { [weak self] err in
            guard let self, err == nil else {
                self?.onReady(false)
                return
            }
            self.handshake(proxy: proxy, queue: queue)
        }
    }

    private func handshake(proxy: NCProxy, queue: DispatchQueue) {
        let username = proxy.fields["username"]?.string
        let password = proxy.fields["password"]?.string
        let buf = NCByteBuffer()
        control.send(NCSOCKS5.greeting(username: username, password: password))
        readAtLeast(buf, 2, queue: queue) { [weak self] ok in
            guard let self, ok else { self?.onReady(false); return }
            let head = buf.take(2)
            guard head[0] == 0x05 else { self.onReady(false); return }
            if head[1] == 0x02 {
                guard let u = username else { self.onReady(false); return }
                self.control.send(NCSOCKS5.authRequest(username: u, password: password ?? ""))
                self.readAtLeast(buf, 2, queue: queue) { [weak self] ok in
                    guard let self, ok, buf.take(2)[1] == 0x00 else { self?.onReady(false); return }
                    self.associate(buf: buf, queue: queue)
                }
            } else if head[1] == 0x00 {
                self.associate(buf: buf, queue: queue)
            } else {
                self.onReady(false)
            }
        }
    }

    private func associate(buf: NCByteBuffer, queue: DispatchQueue) {
        // UDP ASSOCIATE with a zero bind address.
        control.send(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        func step() {
            if buf.count >= 4 {
                let atyp = buf.data[3]
                let need = 4 + (atyp == 0x01 ? 4 : atyp == 0x04 ? 16 : atyp == 0x03 ? 1 + Int(buf.count > 4 ? buf.data[4] : 0) : 0) + 2
                if buf.count >= need {
                    let resp = buf.take(need)
                    guard resp[1] == 0x00 else { onReady(false); return }
                    openRelay(resp: resp, atyp: atyp, queue: queue)
                    return
                }
            }
            control.receive { [weak self] data, error in
                guard let self, let data else { self?.onReady(false); return }
                buf.append(data)
                step()
            }
        }
        step()
    }

    private func openRelay(resp: Data, atyp: UInt8, queue: DispatchQueue) {
        let host: String
        let port: Int
        switch atyp {
        case 0x01:
            host = "\(resp[4]).\(resp[5]).\(resp[6]).\(resp[7])"
            port = Int(resp[8]) << 8 | Int(resp[9])
        case 0x03:
            let len = Int(resp[4])
            host = String(decoding: resp[5..<(5 + len)], as: UTF8.self)
            port = Int(resp[5 + len]) << 8 | Int(resp[6 + len])
        default:
            onReady(false)
            return
        }
        // A 0.0.0.0 bind address means "same host as the control connection".
        let relayHost = host == "0.0.0.0" ? serverHost : host
        let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(relayHost),
                                     port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let conn = NWConnection(to: ep, using: NCOutboundBinding.params(.udp, host: relayHost))
        udp = conn
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            if case .ready = state {
                self.ready = true
                self.onReady(true)
                for (data, target) in self.queued { self.send(data, to: target) }
                self.queued = []
                self.receiveLoop()
            }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        udp?.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, let payload = Self.unwrap(data) {
                self.onReply(payload)
            }
            if error == nil { self.receiveLoop() }
        }
    }

    /// SOCKS UDP header: RSV(2) FRAG(1) ATYP + addr + port, then payload.
    private static func unwrap(_ data: Data) -> Data? {
        guard data.count >= 4, data[0] == 0, data[1] == 0, data[2] == 0 else { return nil }
        var offset = 4
        switch data[3] {
        case 0x01: offset += 4
        case 0x04: offset += 16
        case 0x03:
            guard data.count > 4 else { return nil }
            offset += 1 + Int(data[4])
        default: return nil
        }
        offset += 2
        guard data.count > offset else { return nil }
        return Data(data[offset...])
    }

    func send(_ data: Data, to target: NCTarget) {
        guard ready, let udp else {
            if queued.count < 64 { queued.append((data, target)) }
            return
        }
        var packet = Data([0x00, 0x00, 0x00])
        packet.append(target.atypEncoded)
        packet.append(data)
        udp.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        udp?.cancel()
        control.cancel()
    }

    private func readAtLeast(_ buf: NCByteBuffer, _ n: Int, queue: DispatchQueue, done: @escaping (Bool) -> Void) {
        if buf.count >= n { done(true); return }
        control.receive { [weak self] data, _ in
            guard let self, let data else { done(false); return }
            buf.append(data)
            self.readAtLeast(buf, n, queue: queue, done: done)
        }
    }
}

/// One-shot upstream DNS forwarding over UDP, with TCP retry on truncation.
/// Used for queries the fake-IP responder declines (filter hosts, non-A types).
final class NCDNSForwarder {
    private let queue: DispatchQueue

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func forward(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        // nc-dns: identical in-flight queries coalesce and the global upstream cap applies
        // (see NCDNSUpstreamCoordinator); the one-shot UDP exchange is forwardUDPOnce.
        NCDNSUpstreamCoordinator.shared.submit(
            key: "udp://\(server):\(port)|" + Self.mergeKeySuffix(query),
            id: Self.transactionID(query), callerQueue: queue,
            execute: { [weak self] done in
                guard let self else { done(nil); return }
                self.forwardUDPOnce(query, server: server, port: port, completion: done)
            }, completion: completion)
    }

    static func transactionID(_ query: Data) -> UInt16? {
        guard query.count >= 2 else { return nil }
        return UInt16(query[0]) << 8 | UInt16(query[1])
    }

    /// Coalescing key material: the whole wire query minus its transaction ID — two queries
    /// merge only when flags, question and additional (EDNS) bytes are all identical.
    static func mergeKeySuffix(_ query: Data) -> String {
        Data(query.dropFirst(min(2, query.count))).base64EncodedString()
    }

    private func forwardUDPOnce(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any
        let conn = NWConnection(host: NWEndpoint.Host(server), port: nwPort, using: NCOutboundBinding.params(.udp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: query, completion: .contentProcessed { _ in
                    conn.receiveMessage { data, _, _, _ in
                        guard let data else {
                            finish(nil)
                            return
                        }
                        // Truncated bit (TC) set: retry over TCP like resolvers do.
                        if data.count > 2, data[2] & 0x02 != 0 {
                            Self.forwardTCP(query, server: server, port: port, queue: self.queue) { finish($0 ?? data) }
                        } else {
                            finish(data)
                        }
                    }
                })
            case .failed:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    static func forwardTCP(_ query: Data, server: String, port: Int = 53, queue: DispatchQueue, completion: @escaping (Data?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any, using: NCOutboundBinding.params(.tcp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            if case .ready = state {
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
                            finish(data)
                        }
                    }
                })
            } else if case .failed = state {
                finish(nil)
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }
}

/// nc-dns: coalescing + a global cap for upstream DNS queries, shared by every
/// NCDNSForwarder instance (data plane, rule resolver). Identical in-flight queries —
/// same destination and same wire bytes apart from the transaction ID — are sent upstream
/// once; the answer fans out with each waiter's own transaction ID written back (the ID is
/// the only per-waiter byte: flags/question/additional were part of the merge key, so the
/// rest of the response is valid for every waiter).
///
/// Concurrency: at most `maxInFlight` upstream exchanges run at once. 32 matches the
/// resolver behaviour of mainstream clients and bounds sockets/tasks in the memory-tight
/// extension while staying far above what a page load bursts (a few dozen distinct names,
/// most of which coalesce). Excess distinct queries wait FIFO for up to `maxQueueWait`,
/// then fail as nil — the same failure the callers already handle for a dead upstream.
final class NCDNSUpstreamCoordinator {
    static let shared = NCDNSUpstreamCoordinator()
    static let maxInFlight = 32
    static let maxQueueWait: TimeInterval = 6

    private final class Entry {
        let key: String
        let execute: (@escaping (Data?) -> Void) -> Void
        var waiters: [(id: UInt16?, queue: DispatchQueue, completion: (Data?) -> Void)] = []
        var started = false
        init(key: String, execute: @escaping (@escaping (Data?) -> Void) -> Void) {
            self.key = key
            self.execute = execute
        }
    }

    private let queue = DispatchQueue(label: "nc.dns.coordinator")
    private var entries: [String: Entry] = [:]
    private var pending: [Entry] = []
    private var active = 0

    func submit(key: String, id: UInt16?, callerQueue: DispatchQueue,
                execute: @escaping (@escaping (Data?) -> Void) -> Void,
                completion: @escaping (Data?) -> Void) {
        queue.async {
            if let e = self.entries[key] {
                e.waiters.append((id, callerQueue, completion))
                return
            }
            let e = Entry(key: key, execute: execute)
            e.waiters.append((id, callerQueue, completion))
            self.entries[key] = e
            if self.active < Self.maxInFlight {
                self.start(e)
            } else {
                self.pending.append(e)
                self.queue.asyncAfter(deadline: .now() + Self.maxQueueWait) { [weak self, weak e] in
                    guard let self, let e, !e.started, self.entries[e.key] === e else { return }
                    self.entries.removeValue(forKey: e.key)
                    self.pending.removeAll { $0 === e }
                    self.deliver(e, nil)
                }
            }
        }
    }

    private func start(_ e: Entry) {
        e.started = true
        active += 1
        e.execute { [weak self, weak e] resp in
            guard let self, let e else { return }
            self.queue.async {
                guard self.entries[e.key] === e else { return }
                self.entries.removeValue(forKey: e.key)
                self.active -= 1
                self.deliver(e, resp)
                while self.active < Self.maxInFlight, let next = self.pending.first {
                    self.pending.removeFirst()
                    if self.entries[next.key] === next { self.start(next) }
                }
            }
        }
    }

    /// Fan the (single) upstream answer out to every waiter, restoring each waiter's own
    /// transaction ID — the coalescing correctness key: a waiter must never see another
    /// query's ID, or resolvers will discard the answer as mismatched.
    private func deliver(_ e: Entry, _ resp: Data?) {
        for w in e.waiters {
            var out = resp
            if var r = resp, let id = w.id, r.count >= 2 {
                r[r.startIndex] = UInt8(id >> 8)
                r[r.startIndex + 1] = UInt8(id & 0xff)
                out = r
            }
            let c = w.completion
            w.queue.async { c(out) }
        }
    }
}

/// nc-dns: one reused TLS stream per DoT upstream (host, port). Queries run strictly
/// sequentially over the stream (length-framed, no pipelining — every mainstream DoT
/// server accepts this, and ordering makes response matching trivial). Any error or the
/// per-query timeout discards the stream; queued queries retry on a fresh one. All state
/// lives on the pool queue (the NCStream is created with it, so its callbacks land here).
final class NCDNSDoTPool {
    static let shared = NCDNSDoTPool()
    private let queue = DispatchQueue(label: "nc.dns.dot")

    private struct Current {
        let callerQueue: DispatchQueue
        let completion: (Data?) -> Void
        var buffer = Data()
        let timeout: DispatchWorkItem
    }
    private final class Conn {
        var stream: NCStream?
        var connecting = false
        var pending: [(query: Data, callerQueue: DispatchQueue, completion: (Data?) -> Void)] = []
        var current: Current?
    }
    private var conns: [String: Conn] = [:]

    func forward(_ query: Data, host: String, port: Int, callerQueue: DispatchQueue,
                 completion: @escaping (Data?) -> Void) {
        let key = "\(host):\(port)"
        queue.async {
            let c: Conn
            if let existing = self.conns[key] { c = existing } else { c = Conn(); self.conns[key] = c }
            c.pending.append((query, callerQueue, completion))
            self.pump(key: key, conn: c, host: host, port: port)
        }
    }

    private func pump(key: String, conn c: Conn, host: String, port: Int) {
        guard c.current == nil, !c.pending.isEmpty else { return }
        guard let stream = c.stream else {
            guard !c.connecting else { return }
            c.connecting = true
            let s = NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
            s.start { [weak self, weak c] err in
                guard let self, let c else { return }
                c.connecting = false
                guard err == nil else {
                    if !c.pending.isEmpty {
                        let head = c.pending.removeFirst()
                        head.callerQueue.async { head.completion(nil) }
                    }
                    if c.pending.isEmpty { self.conns.removeValue(forKey: key) }
                    else { self.pump(key: key, conn: c, host: host, port: port) }
                    return
                }
                c.stream = s
                self.pump(key: key, conn: c, host: host, port: port)
            }
            return
        }
        let req = c.pending.removeFirst()
        var framed = Data()
        framed.appendBE16(UInt16(req.query.count))
        framed.append(req.query)
        stream.send(framed)
        let timeout = DispatchWorkItem { [weak self, weak c] in
            guard let self, let c, c.current != nil else { return }
            self.failCurrent(key: key, conn: c, host: host, port: port)
        }
        c.current = Current(callerQueue: req.callerQueue, completion: req.completion, timeout: timeout)
        queue.asyncAfter(deadline: .now() + 5, execute: timeout)
        receiveNext(key: key, conn: c, host: host, port: port)
    }

    private func receiveNext(key: String, conn c: Conn, host: String, port: Int) {
        guard let stream = c.stream, c.current != nil else { return }
        stream.receive { [weak self, weak c] data, _ in
            guard let self, let c, var cur = c.current else { return }
            guard let data else { self.failCurrent(key: key, conn: c, host: host, port: port); return }
            cur.buffer.append(data)
            c.current = cur
            if cur.buffer.count >= 2 {
                let len = Int(cur.buffer[cur.buffer.startIndex]) << 8 | Int(cur.buffer[cur.buffer.startIndex + 1])
                if cur.buffer.count >= 2 + len {
                    let resp = Data(cur.buffer.dropFirst(2).prefix(len))
                    cur.timeout.cancel()
                    c.current = nil
                    cur.callerQueue.async { cur.completion(resp) }
                    self.pump(key: key, conn: c, host: host, port: port)
                    return
                }
            }
            self.receiveNext(key: key, conn: c, host: host, port: port)
        }
    }

    private func failCurrent(key: String, conn c: Conn, host: String, port: Int) {
        guard let cur = c.current else { return }
        cur.timeout.cancel()
        c.current = nil
        c.stream?.cancel()
        c.stream = nil
        cur.callerQueue.async { cur.completion(nil) }
        if c.pending.isEmpty { conns.removeValue(forKey: key) }
        else { pump(key: key, conn: c, host: host, port: port) }
    }
}

/// nc-dns: one reused HTTPS connection per DoH endpoint. Requests are sent one at a time
/// with `Connection: keep-alive`; each response is consumed exactly (Content-Length or
/// chunked framing), so leftover bytes belong to the next response. A response that says
/// `Connection: close`, any error, or the per-query timeout discards the stream; queued
/// queries retry on a fresh one. All state lives on the pool queue.
final class NCDNSDoHPool {
    static let shared = NCDNSDoHPool()
    private let queue = DispatchQueue(label: "nc.dns.doh")

    private struct Current {
        let callerQueue: DispatchQueue
        let completion: (Data?) -> Void
        var buffer = Data()
        let timeout: DispatchWorkItem
    }
    private final class Conn {
        var stream: NCStream?
        var connecting = false
        var pending: [(query: Data, callerQueue: DispatchQueue, completion: (Data?) -> Void)] = []
        var current: Current?
    }
    private var conns: [String: Conn] = [:]

    func forward(_ query: Data, urlString: String, host: String, port: Int, path: String,
                 callerQueue: DispatchQueue, completion: @escaping (Data?) -> Void) {
        queue.async {
            let c: Conn
            if let existing = self.conns[urlString] { c = existing } else { c = Conn(); self.conns[urlString] = c }
            c.pending.append((query, callerQueue, completion))
            self.pump(key: urlString, conn: c, host: host, port: port, path: path)
        }
    }

    private func pump(key: String, conn c: Conn, host: String, port: Int, path: String) {
        guard c.current == nil, !c.pending.isEmpty else { return }
        guard let stream = c.stream else {
            guard !c.connecting else { return }
            c.connecting = true
            let s = NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
            s.start { [weak self, weak c] err in
                guard let self, let c else { return }
                c.connecting = false
                guard err == nil else {
                    if !c.pending.isEmpty {
                        let head = c.pending.removeFirst()
                        head.callerQueue.async { head.completion(nil) }
                    }
                    if c.pending.isEmpty { self.conns.removeValue(forKey: key) }
                    else { self.pump(key: key, conn: c, host: host, port: port, path: path) }
                    return
                }
                c.stream = s
                self.pump(key: key, conn: c, host: host, port: port, path: path)
            }
            return
        }
        let req = c.pending.removeFirst()
        let head = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: \(req.query.count)\r\nConnection: keep-alive\r\n\r\n"
        var request = Data(head.utf8)
        request.append(req.query)
        stream.send(request)
        let timeout = DispatchWorkItem { [weak self, weak c] in
            guard let self, let c, c.current != nil else { return }
            self.failCurrent(key: key, conn: c, host: host, port: port, path: path)
        }
        c.current = Current(callerQueue: req.callerQueue, completion: req.completion, timeout: timeout)
        queue.asyncAfter(deadline: .now() + 6, execute: timeout)
        receiveNext(key: key, conn: c, host: host, port: port, path: path)
    }

    private func receiveNext(key: String, conn c: Conn, host: String, port: Int, path: String) {
        guard let stream = c.stream, c.current != nil else { return }
        stream.receive { [weak self, weak c] data, _ in
            guard let self, let c, var cur = c.current else { return }
            guard let data else { self.failCurrent(key: key, conn: c, host: host, port: port, path: path); return }
            cur.buffer.append(data)
            if let (body, consumed, keepAlive) = Self.parseResponse(cur.buffer) {
                cur.timeout.cancel()
                c.current = nil
                if !keepAlive {
                    c.stream?.cancel()
                    c.stream = nil
                }
                cur.callerQueue.async { cur.completion(body) }
                if c.pending.isEmpty, c.stream == nil { self.conns.removeValue(forKey: key) }
                else { self.pump(key: key, conn: c, host: host, port: port, path: path) }
                return
            }
            c.current = cur
            self.receiveNext(key: key, conn: c, host: host, port: port, path: path)
        }
    }

    private func failCurrent(key: String, conn c: Conn, host: String, port: Int, path: String) {
        guard let cur = c.current else { return }
        cur.timeout.cancel()
        c.current = nil
        c.stream?.cancel()
        c.stream = nil
        cur.callerQueue.async { cur.completion(nil) }
        if c.pending.isEmpty { conns.removeValue(forKey: key) }
        else { pump(key: key, conn: c, host: host, port: port, path: path) }
    }

    /// One complete HTTP response at the head of `buffer`: its body, how many bytes it
    /// consumed (so the stream stays in sync for the next response), and whether the
    /// connection may be reused. nil = more bytes needed.
    private static func parseResponse(_ buffer: Data) -> (body: Data, consumed: Int, keepAlive: Bool)? {
        guard let headEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: buffer[buffer.startIndex..<headEnd.lowerBound], as: UTF8.self).lowercased()
        let keepAlive = !head.contains("connection: close")
        let bodyStart = headEnd.upperBound
        if head.contains("transfer-encoding: chunked") {
            var out = Data()
            var pos = bodyStart
            while true {
                guard let lineEnd = buffer.range(of: Data("\r\n".utf8), range: pos..<buffer.endIndex) else { return nil }
                let sizeText = String(decoding: buffer[pos..<lineEnd.lowerBound], as: UTF8.self)
                guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else { return nil }
                let chunkStart = lineEnd.upperBound
                if size == 0 {
                    // Terminal chunk: optional trailers end at the first empty line.
                    if buffer.distance(from: chunkStart, to: buffer.endIndex) >= 2,
                       buffer[chunkStart] == 0x0d, buffer[chunkStart + 1] == 0x0a {
                        return (out, buffer.distance(from: buffer.startIndex, to: chunkStart) + 2, keepAlive)
                    }
                    guard let tailEnd = buffer.range(of: Data("\r\n\r\n".utf8), range: chunkStart..<buffer.endIndex) else { return nil }
                    return (out, buffer.distance(from: buffer.startIndex, to: tailEnd.upperBound), keepAlive)
                }
                guard buffer.distance(from: chunkStart, to: buffer.endIndex) >= size + 2 else { return nil }
                out.append(Data(buffer[chunkStart..<(chunkStart + size)]))
                pos = chunkStart + size + 2
            }
        }
        if let match = head.range(of: "content-length:"),
           let end = head[match.upperBound...].range(of: "\r\n") {
            let lenText = head[match.upperBound..<end.lowerBound].trimmingCharacters(in: .whitespaces)
            if let len = Int(lenText) {
                let bodyOff = buffer.distance(from: buffer.startIndex, to: bodyStart)
                guard buffer.count >= bodyOff + len else { return nil }
                return (Data(buffer[bodyStart..<(bodyStart + len)]), bodyOff + len, keepAlive)
            }
        }
        return nil
    }
}

/// Shadowsocks UDP: every datagram is an independent SIP022 AEAD packet
/// (fresh salt, target header inside), so the stream encoder/decoder are
/// re-created per packet.
final class NCUDPSSSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let conn: NWConnection
    private let cipher: String
    private let password: String
    private var cancelled = false
    /// Set for 2022-blake3-* ciphers: per-session packet crypto (one UDP
    /// session per app flow, matching the session model of the spec).
    private let ss2022: NCSS2022UDPCrypto?

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let cipherName = proxy.cipher, let pw = proxy.password,
              let server = proxy.server, let port = proxy.port,
              NCShadowsocks.spec(for: cipherName) != nil || NCSS2022.isMethod2022(cipherName)
        else { return nil }
        self.cipher = cipherName
        self.password = pw
        if NCSS2022.isMethod2022(cipherName) {
            guard let crypto = NCSS2022UDPCrypto(method: cipherName, password: pw) else { return nil }
            ss2022 = crypto
        } else {
            ss2022 = nil
        }
        conn = NWConnection(host: NWEndpoint.Host(server),
                            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any,
                            using: NCOutboundBinding.params(.udp, host: server))
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data {
                if let ss2022 {
                    if let decoded = ss2022.decodePacket(data) { self.onReply(decoded.1) }
                } else if let dec = NCSSDecoder(cipher: cipher, password: password),
                          let plain = dec.feed(data), let payload = Self.stripTargetHeader(plain) {
                    self.onReply(payload)
                }
            }
            if error == nil { self.receiveLoop() }
        }
    }

    /// Parse a SOCKS-style ATYP header off the front of a decrypted packet.
    static func stripTargetHeader(_ data: Data) -> Data? {
        guard let first = data.first else { return nil }
        var offset: Int
        switch first {
        case 0x01: offset = 1 + 4 + 2
        case 0x04: offset = 1 + 16 + 2
        case 0x03:
            guard data.count >= 2 else { return nil }
            offset = 1 + 1 + Int(data[1]) + 2
        default: return nil
        }
        guard data.count > offset else { return nil }
        return Data(data[offset...])
    }

    func send(_ data: Data, to target: NCTarget) {
        if let ss2022 {
            guard let packet = ss2022.encodePacket(target: target, payload: data,
                                                   timestamp: UInt64(Date().timeIntervalSince1970))
            else { return }
            conn.send(content: packet, completion: .idempotent)
            return
        }
        guard let enc = NCSSEncoder(cipher: cipher, password: password) else { return }
        var plain = target.atypEncoded
        plain.append(data)
        guard plain.count <= 0x3fff, let packet = enc.encode(plain) else { return }
        conn.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}

/// UDP over a sing-mux (h2mux) session: one packet-addr stream; packets
/// are framed [target][len][payload] in both directions.
final class NCUDPMuxSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCMuxStream?
    private var pending: [(Data, NCTarget)] = []
    private var buffer = Data()
    private var requestWritten = false
    private var cancelled = false

    init(proxy: NCProxy, queue: DispatchQueue) {
        guard let server = proxy.server, let port = proxy.port else { return }
        NCConnector.muxSession(proxy: proxy, server: server, port: port, queue: queue) { [weak self] session, _ in
            guard let self, !self.cancelled, let session else { return }
            let stream = session.openStream(target: NCMux.destination, callerQueue: queue, rawMode: true)
            self.stream = stream
            let queued = self.pending
            self.pending = []
            for (data, target) in queued { self.sendNow(data, to: target) }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        stream?.receive { [weak self] data, _ in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            self.buffer.append(data)
            self.drain()
            self.receiveLoop()
        }
    }

    private func drain() {
        // The stream status byte is consumed inside NCMuxStream; what
        // arrives here is pure packet frames.
        while let (_, payload, consumed) = NCMux.parseUDPPacketFrame(buffer) {
            buffer = Data(buffer.dropFirst(consumed))
            onReply(payload)
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        if stream == nil {
            pending.append((data, target))
            return
        }
        sendNow(data, to: target)
    }

    private func sendNow(_ data: Data, to target: NCTarget) {
        guard let stream else { return }
        var out = Data()
        if !requestWritten {
            requestWritten = true
            out.append(NCMux.streamRequestUDPPacketAddr())
        }
        out.append(NCMux.udpPacketFrame(target: target, payload: data))
        stream.sendRaw(out)
    }

    func cancel() {
        cancelled = true
        stream?.cancel()
    }
}

/// UDP over AnyTLS: a UoT v2 stream on the shared AnyTLS session. The
/// stream's target is the UoT magic address; the first bytes inside are
/// the UoT request for this flow's destination, then framed packets.
final class NCUDPAnyTLSSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCAnyTLSStream?
    private var pending: [(Data, NCTarget)] = []
    private var buffer = Data()
    private var requestWritten = false
    private var cancelled = false
    private let flowTarget: NCTarget

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        flowTarget = target
        guard let server = proxy.server, let port = proxy.port else { return }
        NCConnector.anytlsSession(proxy: proxy, server: server, port: port, queue: queue) { [weak self] session, _ in
            guard let self, !self.cancelled, let session else { return }
            self.stream = session.openStream(target: NCUoT.magicTarget, callerQueue: queue)
            let queued = self.pending
            self.pending = []
            for (data, t) in queued { self.sendNow(data, to: t) }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        stream?.receive { [weak self] data, _ in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            self.buffer.append(data)
            while let (_, payload, consumed) = NCUoT.parsePacket(self.buffer) {
                self.buffer = Data(self.buffer.dropFirst(consumed))
                self.onReply(payload)
            }
            self.receiveLoop()
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        if stream == nil {
            pending.append((data, target))
            return
        }
        sendNow(data, to: target)
    }

    private func sendNow(_ data: Data, to target: NCTarget) {
        guard let stream else { return }
        if !requestWritten {
            requestWritten = true
            stream.send(NCUoT.request(destination: flowTarget))
        }
        stream.send(NCUoT.packet(target: target, payload: data))
    }

    func cancel() {
        cancelled = true
        stream?.cancel()
    }
}

/// Snell UDP (v3+): packets ride a dedicated TCP connection that begins
/// with the UDP command header. v3 carries each packet as one AEAD stream
/// chunk; v4 as one frame. Responses use Snell's response address format.
final class NCUDPSnellSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private let version: Int
    private let encoder: NCSnellStreamEncoder?
    private let decoder: NCSnellStreamDecoder?
    private let v4Writer: NCSnellV4Writer?
    private let v4Reader: NCSnellV4Reader?
    private var cancelled = false

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let password = proxy.password, let server = proxy.server, let port = proxy.port
        else { return nil }
        let version = proxy.fields["version"]?.int ?? 1
        guard version >= 3 else { return nil }
        self.version = version
        let psk = Data(password.utf8)
        if version >= 4 {
            v4Writer = NCSnellV4Writer(psk: psk)
            v4Reader = NCSnellV4Reader(psk: psk)
            encoder = nil
            decoder = nil
        } else {
            v4Writer = nil
            v4Reader = nil
            encoder = NCSnellStreamEncoder(psk: psk, version: version)
            decoder = NCSnellStreamDecoder(psk: psk, version: version)
        }
        raw = NCStream(to: server, port: port, queue: queue)
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            if let v4Writer {
                if let wire = v4Writer.write(NCSnell.udpHeader()) { self.raw.send(wire) }
            } else if let encoder {
                if let wire = encoder.encode(NCSnell.udpHeader()) { self.raw.send(wire) }
            }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            if let v4Reader {
                if let pieces = v4Reader.feed(data) {
                    for piece in pieces {
                        if case .data(let plain) = piece,
                           let parsed = NCSnell.parseUDPResponse(plain) {
                            self.onReply(parsed.1)
                        }
                    }
                }
            } else if let decoder, let pieces = decoder.feed(data) {
                for plain in pieces {
                    if let parsed = NCSnell.parseUDPResponse(plain) {
                        self.onReply(parsed.1)
                    }
                }
            }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        let frame = NCSnell.udpFrame(target: target, payload: data)
        if let v4Writer {
            if let wire = v4Writer.frame(frame) { raw.send(wire) }
        } else if let encoder {
            if let wire = encoder.encode(frame) { raw.send(wire) }
        }
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}

/// Trojan UDP: packets ride the TLS stream (UDP command in the request head),
/// framed as ATYP + length + CRLF + payload.
final class NCUDPTrojanSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private var buffer = Data()
    private var cancelled = false

    init(proxy: NCProxy, firstTarget: NCTarget, queue: DispatchQueue) {
        raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                       tlsServerName: proxy.fields["sni"]?.string ?? proxy.server ?? "",
                       allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                       queue: queue)
        raw.start { [weak self] err in
            guard let self, err == nil, let password = proxy.password else { return }
            self.raw.send(NCTrojan.requestHead(password: password, target: firstTarget, udp: true))
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            self.buffer.append(data)
            self.parseFrames()
            if error == nil { self.receiveLoop() }
        }
    }

    private func parseFrames() {
        while let (payload, consumed) = Self.parseFrame(buffer) {
            buffer = Data(buffer.dropFirst(consumed))
            onReply(payload)
        }
    }

    /// One frame: ATYP header + len(2) + CRLF + payload. nil = need more bytes
    /// (or a malformed frame, which also just waits — the stream is trusted
    /// past the TLS layer in practice; a bad frame resyncs never, matching
    /// other clients' simple parsers).
    static func parseFrame(_ data: Data) -> (payload: Data, consumed: Int)? {
        guard let first = data.first else { return nil }
        var headerLen: Int
        switch first {
        case 0x01: headerLen = 1 + 4 + 2
        case 0x04: headerLen = 1 + 16 + 2
        case 0x03:
            guard data.count >= 2 else { return nil }
            headerLen = 1 + 1 + Int(data[1]) + 2
        default: return nil
        }
        guard data.count >= headerLen + 2 + 2 else { return nil }
        let len = Int(data[headerLen]) << 8 | Int(data[headerLen + 1])
        guard data[headerLen + 2] == 0x0d, data[headerLen + 3] == 0x0a else { return nil }
        let total = headerLen + 2 + 2 + len
        guard data.count >= total else { return nil }
        return (Data(data[(headerLen + 4)..<total]), total)
    }

    func send(_ data: Data, to target: NCTarget) {
        raw.send(NCTrojan.udpPacket(target: target, payload: data))
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}

// NCDNSUpstream moved to Shared/NativeCore/NCDNSUpstream.swift (pure logic; the app unit tests use it).

extension NCDNSForwarder {
    /// Forward via any upstream kind. nc-dns: single upstreams go through the shared
    /// coordinator (identical in-flight queries coalesce, the global in-flight cap
    /// applies — DoQ included, it just does not reuse connections yet). Groups keep
    /// their own sequential failover; each attempt is a separate coordinated query.
    func forward(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) {
        if case .group(let list) = upstream {
            forwardGroup(query, list: list, completion: completion)
            return
        }
        NCDNSUpstreamCoordinator.shared.submit(
            key: "\(upstream)|" + Self.mergeKeySuffix(query),
            id: Self.transactionID(query), callerQueue: queue,
            execute: { [weak self] done in
                guard let self else { done(nil); return }
                self.dispatchOnce(query, upstream: upstream, completion: done)
            }, completion: completion)
    }

    /// One real upstream exchange (the coordinator's execute step; no coalescing here).
    private func dispatchOnce(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) {
        switch upstream {
        case .udp(let host, let port):
            forwardUDPOnce(query, server: host, port: port, completion: completion)
        case .tcp(let host, let port):
            Self.forwardTCP(query, server: host, port: port, queue: queue, completion: completion)
        case .dot(let host, let port):
            Self.forwardDoT(query, host: host, port: port, queue: queue, completion: completion)
        case .doh(let url):
            Self.forwardDoH(query, urlString: url, queue: queue, completion: completion)
        case .doq(let host, let port):
            Self.forwardDoQ(query, host: host, port: port, queue: queue, completion: completion)
        case .group:
            completion(nil) // unreachable: groups are handled in forward()
        }
    }

    private static let groupLock = NSLock()
    private static var groupLastGood: [String: Int] = [:]

    /// rv2-rules: every configured nameserver, tried sequentially with a
    /// short per-server timeout (2.5 s); the server that answered last time
    /// is tried first (mihomo / Surge use all nameservers; sequential
    /// failover is the leaner of race vs failover). A late answer from a
    /// server already given up on is ignored.
    private func forwardGroup(_ query: Data, list: [NCDNSUpstream], completion: @escaping (Data?) -> Void) {
        guard !list.isEmpty else { completion(nil); return }
        let key = "\(list)"
        Self.groupLock.lock()
        let start = (Self.groupLastGood[key] ?? 0) % list.count
        Self.groupLock.unlock()
        func attempt(_ n: Int) {
            guard n < list.count else { completion(nil); return }
            let idx = (start + n) % list.count
            var settled = false
            forward(query, upstream: list[idx]) { resp in
                guard !settled else { return }
                settled = true
                guard let resp else { attempt(n + 1); return }
                if idx != start {
                    Self.groupLock.lock()
                    if Self.groupLastGood.count > 64 { Self.groupLastGood.removeAll() }
                    Self.groupLastGood[key] = idx
                    Self.groupLock.unlock()
                }
                completion(resp)
            }
            queue.asyncAfter(deadline: .now() + 2.5) {
                guard !settled else { return }
                settled = true
                attempt(n + 1)
            }
        }
        attempt(0)
    }

    /// DoQ (RFC 9250): one bidirectional QUIC stream per query inside a
    /// throwaway connection group; the message is length-prefixed exactly
    /// like DNS-over-TCP, and the send side is closed after the query.
    private static func forwardDoQ(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        // QUIC is TLS 1.3-only by construction; no min-version pinning needed.
        let quicOptions = NWProtocolQUIC.Options(alpn: ["doq"])
        let params = NWParameters(quic: quicOptions)
        NCOutboundBinding.apply(params, host: host)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            group.cancel()
            completion(data)
        }
        group.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let conn = group.extract(connectionTo: nil, using: nil) else {
                    finish(nil)
                    return
                }
                conn.stateUpdateHandler = { cstate in
                    if case .failed = cstate { finish(nil) }
                }
                conn.start(queue: queue)
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, contentContext: .defaultMessage, isComplete: true,
                          completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
                            finish(data)
                        }
                    }
                })
            case .failed:
                finish(nil)
            default:
                break
            }
        }
        group.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    /// DoT (RFC 7858): length-framed queries over the pooled per-upstream TLS stream
    /// (NCDNSDoTPool: connection reuse, strict sequencing, discard on error/timeout).
    private static func forwardDoT(_ query: Data, host: String, port: Int, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        NCDNSDoTPool.shared.forward(query, host: host, port: port, callerQueue: queue, completion: completion)
    }

    /// DoH (RFC 8484): POST the wire query over the pooled per-endpoint HTTPS connection
    /// (NCDNSDoHPool: keep-alive reuse, one query at a time, exact response framing).
    private static func forwardDoH(_ query: Data, urlString: String, queue: DispatchQueue,
                                   completion: @escaping (Data?) -> Void) {
        guard let url = URL(string: urlString), let host = url.host else {
            completion(nil)
            return
        }
        let port = url.port ?? 443
        let path = url.path.isEmpty ? "/dns-query" : url.path
        NCDNSDoHPool.shared.forward(query, urlString: urlString, host: host, port: port, path: path,
                                    callerQueue: queue, completion: completion)
    }

}

/// VMess UDP: a dedicated VMess connection (command 0x02) per destination —
/// the sing-vmess packet connection: the body is the AEAD chunk stream, one
/// record per datagram, target only in the request header.
final class NCUDPVMessSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private let encoder: NCVMessChunkEncoder?
    private let respReader: NCVMessResponseReader
    private let respKeys: (key: Data, nonce: Data)
    private let security: UInt8
    private var decoder: NCVMessChunkDecoder?
    private var responseStarted = false
    private var cancelled = false

    init?(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        let uuidBytesOpt: Data? = proxy.uuid.flatMap { uuidString in
            NCVLESS.uuidBytes(uuidString).map { Data($0) } ?? NCSHA1.uuidV5NilNamespace(uuidString)
        }
        let sec: UInt8
        switch (proxy.fields["cipher"]?.string ?? "auto").lowercased() {
        case "auto", "aes-128-gcm": sec = NCVMess.securityAESGCM
        case "chacha20-poly1305": sec = NCVMess.securityChaCha
        case "none": sec = NCVMess.securityNone
        default: return nil
        }
        guard (proxy.fields["alterId"]?.int ?? 0) == 0, let uuidBytes = uuidBytesOpt else { return nil }
        security = sec
        if proxy.fields["tls"]?.bool ?? false {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                           tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? proxy.server ?? "",
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        } else {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        }
        let reqKey = NCConnector.randomData(16)
        let reqNonce = NCConnector.randomData(16)
        let respV = NCConnector.randomData(1)[0]
        encoder = sec == NCVMess.securityNone ? nil
            : NCVMessChunkEncoder(bodyKey: reqKey, nonceBase: reqNonce, security: sec)
        respKeys = NCVMess.responseKeys(reqKey: reqKey, reqNonce: reqNonce)
        respReader = NCVMessResponseReader(respKey: respKeys.key, respNonce: respKeys.nonce, expectedV: respV)
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            let option: UInt8 = sec == NCVMess.securityNone ? 0
                : NCVMess.optionChunkStream | NCVMess.optionChunkMasking
            let plain = NCVMess.plainHeader(reqNonce: reqNonce, reqKey: reqKey, respV: respV,
                                            option: option, security: sec,
                                            padding: NCConnector.randomData(Int(NCConnector.randomData(1)[0]) % 16),
                                            target: target, command: 0x02)
            let sealed = NCVMess.sealHeader(cmdKey: NCVMess.cmdKey(uuidBytes: uuidBytes),
                                            plainHeader: plain,
                                            time: Int64(Date().timeIntervalSince1970),
                                            authRandom4: NCConnector.randomData(4),
                                            connNonce: NCConnector.randomData(8))
            self.raw.send(sealed)
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            if !responseStarted {
                respReader.feed(data)
                switch respReader.state {
                case .failed:
                    return
                case .reading:
                    break
                case .done:
                    responseStarted = true
                    if security != NCVMess.securityNone {
                        decoder = NCVMessChunkDecoder(bodyKey: respKeys.key, nonceBase: respKeys.nonce, security: security)
                    }
                    let rest = respReader.bodyRemainder
                    if !rest.isEmpty { deliver(rest) }
                }
            } else {
                deliver(data)
            }
            if error == nil { self.receiveLoop() }
        }
    }

    private func deliver(_ data: Data) {
        guard let decoder else {
            onReply(data) // security none: the datagram stream is raw (rare)
            return
        }
        guard let messages = decoder.feedMessages(data) else { return }
        for m in messages { onReply(m) }
    }

    func send(_ data: Data, to target: NCTarget) {
        if let encoder {
            raw.send(encoder.encode(data))
        } else {
            raw.send(data)
        }
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}

/// VLESS UDP: dedicated connection per destination (command 0x02); datagrams
/// are framed as BE16 length + payload in both directions after the response
/// head (version + addon length).
final class NCUDPVLESSSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let raw: NCStream
    private var buffer = Data()
    private var responseHeadConsumed = false
    private var cancelled = false

    init?(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        let headOpt: Data? = proxy.uuid.flatMap { NCVLESS.requestHead(uuid: $0, target: target, command: 0x02) }
        guard let head = headOpt else { return nil }
        if proxy.fields["tls"]?.bool ?? false {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0,
                           tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? proxy.server ?? "",
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        } else {
            raw = NCStream(to: proxy.server ?? "", port: proxy.port ?? 0, queue: queue)
        }
        raw.start { [weak self] err in
            guard let self, err == nil else { return }
            self.raw.send(head)
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        raw.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { return }
            self.buffer.append(data)
            self.parseFrames()
            if error == nil { self.receiveLoop() }
        }
    }

    private func parseFrames() {
        if !responseHeadConsumed {
            guard buffer.count >= 2 else { return }
            let addonLen = Int(buffer[1])
            guard buffer.count >= 2 + addonLen else { return }
            buffer = Data(buffer.dropFirst(2 + addonLen))
            responseHeadConsumed = true
        }
        while buffer.count >= 2 {
            let len = Int(buffer[0]) << 8 | Int(buffer[1])
            guard buffer.count >= 2 + len else { return }
            let payload = Data(buffer[2..<(2 + len)])
            buffer = Data(buffer.dropFirst(2 + len))
            onReply(payload)
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        var framed = Data()
        framed.appendBE16(UInt16(clamping: data.count))
        framed.append(data)
        raw.send(framed)
    }

    func cancel() {
        cancelled = true
        raw.cancel()
    }
}

/// ShadowsocksR UDP: every packet gets a fresh IV prepended and the
/// whole [atyp + payload] is stream-ciphered (origin / auth_sha1_v4 add
/// nothing at the packet layer, like the reference).
final class NCUDPSSRSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let conn: NWConnection
    private let method: String
    private let key: Data
    private let ivSize: Int
    private var cancelled = false

    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let cipherName = proxy.cipher?.lowercased(), let pw = proxy.password,
              let server = proxy.server, let port = proxy.port,
              NCSSStreamCipher.isStreamMethod(cipherName),
              let probe = NCSSStreamCipher(method: cipherName, key: Data(count: 32))
        else { return nil }
        method = cipherName
        ivSize = probe.ivSize
        key = NCShadowsocks.masterKey(password: pw, keyLen: NCSSStreamCipher.keyLength(for: cipherName))
        conn = NWConnection(host: NWEndpoint.Host(server),
                            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any,
                            using: NCOutboundBinding.params(.udp, host: server))
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !cancelled else { return }
            if let data, data.count > ivSize,
               let cipher = NCSSStreamCipher(method: method, key: key) {
                cipher.forEncryption = false
                cipher.setIV(Data(data.prefix(ivSize)))
                let plain = cipher.process(Data(data.dropFirst(ivSize)))
                if let payload = NCUDPSSSession.stripTargetHeader(plain) {
                    onReply(payload)
                }
            }
            if error == nil { receiveLoop() }
        }
    }

    func send(_ payload: Data, to target: NCTarget) {
        guard let cipher = NCSSStreamCipher(method: method, key: key) else { return }
        let iv = Data((0..<ivSize).map { _ in UInt8.random(in: 0...255) })
        cipher.forEncryption = true
        cipher.setIV(iv)
        var packet = iv
        var plain = target.atypEncoded
        plain.append(payload)
        packet.append(cipher.process(plain))
        conn.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}
