import Foundation

/// Byte-stream surface the upstream DNS pools in this file need from a
/// transport. Production streams are NCStream (TLS) instances; the protocol
/// exists so unit tests can inject a fake transport — NCStream itself
/// conforms unchanged, and pool behavior is identical either way.
///
/// This file lives in Shared (moved from PacketTunnel/NativeCore/
/// NCUDPSessions.swift, where the classes were unreachable from the unit
/// tests): the coordinator and pools depend only on NCStream and Data
/// helpers, both already in Shared, and NCDNSForwarder (which stays in the
/// tunnel target) calls them through the exact same type names/signatures.
protocol NCDNSPoolStream: AnyObject {
    func start(ready: @escaping (Error?) -> Void)
    func send(_ data: Data)
    func receive(_ handler: @escaping (Data?, Error?) -> Void)
    func cancel()
}

extension NCStream: NCDNSPoolStream {}

/// How a pool opens its transport stream to (host, port), with callbacks on
/// the pool's own queue. The production default builds the same TLS
/// NCStream the pools always used.
typealias NCDNSStreamFactory = (_ host: String, _ port: Int, _ queue: DispatchQueue) -> NCDNSPoolStream

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
    /// nc-memory: cap on distinct queries waiting for a slot. Each pending entry lives at most
    /// maxQueueWait, but a burst of distinct names could otherwise pin thousands of entries
    /// (key + closures each) for those 6 s; past the cap a new distinct query fails as nil at
    /// once — the failure shape callers already handle. Coalesced waiters on an existing entry
    /// are not capped (they add one closure to an entry that already exists).
    static let maxPendingEntries = 512

    /// Test seam: the limits are init parameters defaulting to the production
    /// constants above, so unit tests can drive the cap and queue-timeout
    /// paths with small numbers instead of 32 real exchanges / a real 6 s
    /// wait. The shared instance — and therefore production behavior — uses
    /// the defaults and is unchanged.
    private let limitInFlight: Int
    private let limitQueueWait: TimeInterval
    private let limitPendingEntries: Int

    init(maxInFlight: Int = NCDNSUpstreamCoordinator.maxInFlight,
         maxQueueWait: TimeInterval = NCDNSUpstreamCoordinator.maxQueueWait,
         maxPendingEntries: Int = NCDNSUpstreamCoordinator.maxPendingEntries) {
        self.limitInFlight = maxInFlight
        self.limitQueueWait = maxQueueWait
        self.limitPendingEntries = maxPendingEntries
    }

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
            if self.active >= self.limitInFlight, self.pending.count >= self.limitPendingEntries {
                callerQueue.async { completion(nil) }
                return
            }
            let e = Entry(key: key, execute: execute)
            e.waiters.append((id, callerQueue, completion))
            self.entries[key] = e
            if self.active < self.limitInFlight {
                self.start(e)
            } else {
                self.pending.append(e)
                self.queue.asyncAfter(deadline: .now() + self.limitQueueWait) { [weak self, weak e] in
                    guard let self, let e, !e.started, self.entries[e.key] === e else { return }
                    self.entries.removeValue(forKey: e.key)
                    self.pending.removeAll { $0 === e }
                    self.deliver(e, nil)
                }
            }
        }
    }

    /// nc-lifecycle: how much work the coordinator still holds (stop log /
    /// lifecycle self-test; read on the coordinator queue).
    func inFlightCounts() -> (entries: Int, active: Int, pending: Int) {
        queue.sync { (self.entries.count, self.active, self.pending.count) }
    }

    /// nc-lifecycle: tunnel stop — fail every waiter at once with nil (the
    /// failure shape callers already handle) instead of letting in-flight
    /// exchanges and queued entries drain through their upstream timeouts
    /// into a core that is already gone. Entries are removed first, so a
    /// late upstream answer finds no entry (start's callback identity-checks
    /// the entry before touching `active`) and is dropped; the coordinator
    /// is immediately reusable by the next core.
    func cancelAll() {
        queue.async {
            let all = Array(self.entries.values)
            self.entries.removeAll()
            self.pending.removeAll()
            self.active = 0
            for e in all { self.deliver(e, nil) }
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
                while self.active < self.limitInFlight, let next = self.pending.first {
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

    /// Test seam: transport creation (see NCDNSStreamFactory). The shared
    /// instance uses the default — the same TLS NCStream as before — so
    /// production behavior is unchanged; unit tests inject a fake transport.
    private let streamFactory: NCDNSStreamFactory

    init(streamFactory: @escaping NCDNSStreamFactory = { host, port, queue in
        NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
    }) {
        self.streamFactory = streamFactory
    }

    private struct Current {
        let callerQueue: DispatchQueue
        let completion: (Data?) -> Void
        var buffer = Data()
        let timeout: DispatchWorkItem
    }
    private final class Conn {
        var stream: NCDNSPoolStream?
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
            // nc-memory: per-connection pending cap. The 5 s timeout applies to the in-flight
            // query only; with a hung upstream the queue behind it grew at query arrival rate.
            // Past the cap the query fails as nil at once (the callers' existing failure shape).
            guard c.pending.count < 64 else {
                callerQueue.async { completion(nil) }
                return
            }
            c.pending.append((query, callerQueue, completion))
            self.pump(key: key, conn: c, host: host, port: port)
        }
    }

    /// nc-lifecycle: how many upstream connections the pool currently holds
    /// (stop log / lifecycle self-test; read on the pool queue).
    func pooledConnectionCount() -> Int {
        queue.sync { self.conns.count }
    }

    /// nc-lifecycle: tunnel stop — drop every pooled stream and fail the
    /// queries on it at once with nil. Before this, an idle pooled TLS
    /// stream survived the core that created it indefinitely, and up to 64
    /// queued queries per upstream waited out the 5 s in-flight timeout one
    /// after another behind a hung stream. A connection still being
    /// established is abandoned together with its Conn (its start callback
    /// holds the Conn weakly and no-ops).
    func reset() {
        queue.async {
            let all = Array(self.conns.values)
            self.conns.removeAll()
            for c in all {
                if let cur = c.current {
                    cur.timeout.cancel()
                    c.current = nil
                    cur.callerQueue.async { cur.completion(nil) }
                }
                for p in c.pending {
                    p.callerQueue.async { p.completion(nil) }
                }
                c.pending.removeAll()
                c.stream?.cancel()
                c.stream = nil
            }
        }
    }

    private func pump(key: String, conn c: Conn, host: String, port: Int) {
        guard c.current == nil, !c.pending.isEmpty else { return }
        guard let stream = c.stream else {
            guard !c.connecting else { return }
            c.connecting = true
            let s = streamFactory(host, port, queue)
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

    /// Test seam: transport creation (see NCDNSStreamFactory). The shared
    /// instance uses the default — the same TLS NCStream as before — so
    /// production behavior is unchanged; unit tests inject a fake transport.
    private let streamFactory: NCDNSStreamFactory

    init(streamFactory: @escaping NCDNSStreamFactory = { host, port, queue in
        NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
    }) {
        self.streamFactory = streamFactory
    }

    private struct Current {
        let callerQueue: DispatchQueue
        let completion: (Data?) -> Void
        var buffer = Data()
        let timeout: DispatchWorkItem
    }
    private final class Conn {
        var stream: NCDNSPoolStream?
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
            // nc-memory: per-connection pending cap (see NCDNSDoTPool.forward).
            guard c.pending.count < 64 else {
                callerQueue.async { completion(nil) }
                return
            }
            c.pending.append((query, callerQueue, completion))
            self.pump(key: urlString, conn: c, host: host, port: port, path: path)
        }
    }

    /// nc-lifecycle: how many endpoint connections the pool currently holds
    /// (stop log / lifecycle self-test; read on the pool queue).
    func pooledConnectionCount() -> Int {
        queue.sync { self.conns.count }
    }

    /// nc-lifecycle: tunnel stop — same contract as NCDNSDoTPool.reset():
    /// drop every pooled connection and fail the queries on it at once with
    /// nil, instead of leaving a keep-alive stream (and its queued queries)
    /// behind for the stopped core.
    func reset() {
        queue.async {
            let all = Array(self.conns.values)
            self.conns.removeAll()
            for c in all {
                if let cur = c.current {
                    cur.timeout.cancel()
                    c.current = nil
                    cur.callerQueue.async { cur.completion(nil) }
                }
                for p in c.pending {
                    p.callerQueue.async { p.completion(nil) }
                }
                c.pending.removeAll()
                c.stream?.cancel()
                c.stream = nil
            }
        }
    }

    private func pump(key: String, conn c: Conn, host: String, port: Int, path: String) {
        guard c.current == nil, !c.pending.isEmpty else { return }
        guard let stream = c.stream else {
            guard !c.connecting else { return }
            c.connecting = true
            let s = streamFactory(host, port, queue)
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
            // nc-memory: a declared Content-Length / chunked body is only bounded by the 6 s
            // timeout; a DNS response never approaches 256 KB, so past it the stream is junk.
            guard cur.buffer.count <= 256 * 1024 else {
                self.failCurrent(key: key, conn: c, host: host, port: port, path: path)
                return
            }
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
                guard let lineEnd = buffer.range(of: Data("\r\n".utf8), options: [], in: pos..<buffer.endIndex) else { return nil }
                let sizeText = String(decoding: buffer[pos..<lineEnd.lowerBound], as: UTF8.self)
                guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else { return nil }
                let chunkStart = lineEnd.upperBound
                if size == 0 {
                    // Terminal chunk: optional trailers end at the first empty line.
                    if buffer.distance(from: chunkStart, to: buffer.endIndex) >= 2,
                       buffer[chunkStart] == 0x0d, buffer[chunkStart + 1] == 0x0a {
                        return (out, buffer.distance(from: buffer.startIndex, to: chunkStart) + 2, keepAlive)
                    }
                    guard let tailEnd = buffer.range(of: Data("\r\n\r\n".utf8), options: [], in: chunkStart..<buffer.endIndex) else { return nil }
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
