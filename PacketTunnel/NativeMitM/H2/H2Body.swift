// Native MitM stage 3 lane s3-h2: body plumbing for one HTTP/2 exchange.
//
// A body moves from a source to a sink, one chunk at a time, pulled only when the sink took the previous one —
// so every hop applies back-pressure: client DATA is granted window only after it moved on (H2InboundBody →
// H2Connection.consumed), an h2 sink waits for .writable when the peer's window is closed, an HTTP/1.1 upstream
// waits for its socket, the old core's flow pipes answer "full". Nothing here buffers more than one chunk per hop beyond
// what the h2 windows already bound.
//
// All callbacks run on the session queue and are always asynchronous (no recursion through pump()).

import Foundation

enum H2Chunk {
    case data(Data)
    case end(HTTPHeaderList?)   // trailers, if any
    case failed(String)
}

protocol H2BodySource: AnyObject {
    /// At most one pull outstanding. cb runs on the session queue, asynchronously.
    func pull(_ cb: @escaping (H2Chunk) -> Void)
    /// The consumer gives up on the rest: drop buffered bytes (granting their window back) and stop reading.
    func abandon()
}

protocol H2BodySink: AnyObject {
    /// cb(false): the sink is dead (peer reset / connection gone).
    func write(_ d: Data, _ cb: @escaping (Bool) -> Void)
    func finish(trailers: HTTPHeaderList?, _ cb: @escaping (Bool) -> Void)
}

enum H2PumpResult: Equatable {
    case ok
    case sourceFailed(String)
    case sinkFailed
}

/// Moves source → sink until the end. progress(n) per chunk (stall timers, byte counts).
func h2Pump(_ src: H2BodySource, _ sink: H2BodySink, progress: @escaping (Int) -> Void,
            done: @escaping (H2PumpResult) -> Void) {
    src.pull { chunk in
        switch chunk {
        case .data(let d):
            progress(d.count)
            sink.write(d) { ok in
                if ok { h2Pump(src, sink, progress: progress, done: done) } else { done(.sinkFailed) }
            }
        case .end(let t):
            sink.finish(trailers: t) { ok in done(ok ? .ok : .sinkFailed) }
        case .failed(let e):
            done(.sourceFailed(e))
        }
    }
}

// MARK: - Sources

/// DATA arriving on an h2 stream (the client's request body, or an h2 origin's response body). Window credit is
/// returned as chunks are pulled. expectedLength: Content-Length to enforce (RFC 9113 §8.1.1).
final class H2InboundBody: H2BodySource {
    private let queue: DispatchQueue
    private let onConsumed: (Int) -> Void
    private var chunks: [Data] = []
    private var buffered = 0
    private var ended = false
    private var trailers: HTTPHeaderList?
    private var failure: String?
    private var waiter: ((H2Chunk) -> Void)?
    private var abandoned = false
    private(set) var received: Int64 = 0
    var expectedLength: Int64?
    /// Called when the body completed or failed (the exchange learns the request side is done).
    var onComplete: (() -> Void)?

    init(queue: DispatchQueue, onConsumed: @escaping (Int) -> Void) {
        self.queue = queue
        self.onConsumed = onConsumed
    }

    var isEnded: Bool { ended || failure != nil }

    func push(_ d: Data) {
        guard !ended, failure == nil else { onConsumed(d.count); return }
        received += Int64(d.count)
        if let e = expectedLength, received > e {
            onConsumed(d.count)
            return fail("body longer than Content-Length")
        }
        if abandoned { onConsumed(d.count); return }
        chunks.append(d)
        buffered += d.count
        serve()
    }

    func finish(trailers t: HTTPHeaderList?) {
        guard !ended, failure == nil else { return }
        if let e = expectedLength, received != e { return fail("body shorter than Content-Length") }
        ended = true
        trailers = t
        serve()
        onComplete?()
    }

    func fail(_ why: String) {
        guard failure == nil, !ended else { return }
        failure = why
        serve()
        onComplete?()
    }

    func pull(_ cb: @escaping (H2Chunk) -> Void) {
        waiter = cb
        serve()
    }

    private func serve() {
        guard let cb = waiter else { return }
        if !chunks.isEmpty {
            let d = chunks.removeFirst()
            buffered -= d.count
            waiter = nil
            onConsumed(d.count)
            queue.async { cb(.data(d)) }
        } else if let f = failure {
            waiter = nil
            queue.async { cb(.failed(f)) }
        } else if ended {
            waiter = nil
            let t = trailers
            queue.async { cb(.end(t)) }
        }
    }

    func abandon() {
        abandoned = true
        waiter = nil
        if buffered > 0 { onConsumed(buffered) }
        chunks.removeAll()
        buffered = 0
    }
}

/// A fixed sequence: optional first chunk, then another source (or the end).
final class H2PrependSource: H2BodySource {
    private let queue: DispatchQueue
    private var first: Data?
    private let rest: H2BodySource?
    private let trailers: HTTPHeaderList?
    init(queue: DispatchQueue, first: Data?, rest: H2BodySource?, trailers: HTTPHeaderList? = nil) {
        self.queue = queue; self.first = first; self.rest = rest; self.trailers = trailers
    }
    func pull(_ cb: @escaping (H2Chunk) -> Void) {
        if let f = first {
            first = nil
            queue.async { cb(.data(f)) }
        } else if let rest {
            rest.pull(cb)
        } else {
            let t = trailers
            queue.async { cb(.end(t)) }
        }
    }
    func abandon() { first = nil; rest?.abandon() }
}

/// A body held by the old core in NativeBodyStore (flow decision body "lane"). The handle belongs to the old core (freed at FlowEnd).
final class H2LaneSource: H2BodySource {
    private let queue: DispatchQueue
    private let bodies: NativeBodyReading
    private let lane: FlowDecision.Lane
    private let chunk: Int
    private var off: Int64 = 0
    var trailers: () -> HTTPHeaderList? = { nil }
    init(queue: DispatchQueue, bodies: NativeBodyReading, lane: FlowDecision.Lane, chunk: Int) {
        self.queue = queue; self.bodies = bodies; self.lane = lane; self.chunk = chunk
    }
    func pull(_ cb: @escaping (H2Chunk) -> Void) {
        let total = bodies.len(lane.handle, raw: lane.raw)
        if total < 0 { return queue.async { cb(.failed("lane handle gone")) } }
        if off >= total { let t = trailers(); return queue.async { cb(.end(t)) } }
        guard let d = bodies.read(lane.handle, raw: lane.raw, off: off, n: Int64(chunk)), !d.isEmpty else {
            return queue.async { cb(.failed("lane read failed")) }
        }
        off += Int64(d.count)
        queue.async { cb(.data(d)) }
    }
    func abandon() {}
}

// MARK: - Sinks

/// DATA out on an h2 stream (towards the client, or towards an h2 origin), respecting the peer's windows: the
/// next chunk is accepted once the stream's queue is at or below the low-water mark.
final class H2StreamSink: H2BodySink {
    private let conn: H2Connection
    private let stream: UInt32
    private var waiting: ((Bool) -> Void)?
    private(set) var dead = false

    init(conn: H2Connection, stream: UInt32) { self.conn = conn; self.stream = stream }

    func write(_ d: Data, _ cb: @escaping (Bool) -> Void) {
        guard !dead, !conn.closed, conn.streams[stream] != nil else { return conn.queue.async { cb(false) } }
        conn.sendData(stream, d)
        if conn.outbound(stream) <= conn.limits.lowWater {
            conn.queue.async { cb(true) }
        } else {
            waiting = cb
            conn.wantWritable(stream)
        }
    }

    func finish(trailers: HTTPHeaderList?, _ cb: @escaping (Bool) -> Void) {
        guard !dead, !conn.closed, conn.streams[stream] != nil else { return conn.queue.async { cb(false) } }
        conn.endStream(stream, trailers: trailers)
        conn.queue.async { cb(true) }
    }

    /// The connection reported .writable for this stream.
    func writable() {
        guard let cb = waiting else { return }
        waiting = nil
        cb(true)
    }

    /// The stream died (reset / connection closed).
    func kill() {
        dead = true
        if let cb = waiting { waiting = nil; conn.queue.async { cb(false) } }
    }
}
