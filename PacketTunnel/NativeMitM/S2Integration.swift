// Native MitM STAGE 2 — integration glue (lane `wire`): maps the tls / http / upstream lanes onto the contract in
// S2Contract.swift so NativeMitmSession drives them. No behaviour of its own beyond the body de-framer.

import Foundation
import Libmihomo

// MARK: - http lane → HTTPCodec

/// Heads come from the http lane's HTTPParser (byte-faithful, limits, smuggling checks), fed exactly one head at a
/// time so a following body or pipelined message never reaches it; serialization and chunk encoding are the lane's.
/// Body de-framing is HTTPBodyDecoder below (one instance per body; the lane's parser is a whole-stream state machine).
struct HTTPLaneCodec: HTTPCodec {
    var limits = HTTPParserLimits()
    private static let crlf2 = Data("\r\n\r\n".utf8)

    /// Drops stray CRLFs between messages, then returns the head slice (incl. CRLFCRLF) if complete.
    private func headSlice(_ buffer: inout Data) throws -> Data? {
        while let f = buffer.first, f == 0x0D || f == 0x0A { buffer.removeFirst() }
        guard let r = buffer.range(of: Self.crlf2) else {
            if buffer.count > limits.maxHeadBytes { throw HTTPParseError.headTooLarge(limit: limits.maxHeadBytes) }
            return nil
        }
        let head = buffer.subdata(in: buffer.startIndex..<r.upperBound)
        if head.count > limits.maxHeadBytes { throw HTTPParseError.headTooLarge(limit: limits.maxHeadBytes) }
        buffer.removeSubrange(buffer.startIndex..<r.upperBound)
        return head
    }

    func parseRequestHead(_ buffer: inout Data) throws -> HTTPRequestHead? {
        var probe = buffer
        guard let slice = try headSlice(&probe) else { return nil }
        let p = HTTPParser(role: .request, limits: limits)
        for ev in try p.feed(slice) { if case .request(let h, _) = ev { buffer = probe; return h } }
        throw HTTPParseError.malformedStartLine
    }

    func parseResponseHead(_ buffer: inout Data) throws -> HTTPResponseHead? {
        var probe = buffer
        guard let slice = try headSlice(&probe) else { return nil }
        let p = HTTPParser(role: .response, limits: limits)
        p.expectResponse(toMethod: "GET") // framing is decided by responseFraming(_:requestMethod:)
        for ev in try p.feed(slice) {
            switch ev {
            case .response(let h, _), .interim(let h): buffer = probe; return h
            default: continue
            }
        }
        throw HTTPParseError.malformedStartLine
    }

    func requestFraming(_ h: HTTPRequestHead) -> HTTPBodyFraming {
        if h.isChunked { return .chunked }
        if let n = h.contentLength { return n > 0 ? .contentLength(n) : .none }
        return .none
    }

    func responseFraming(_ h: HTTPResponseHead, requestMethod: String) -> HTTPBodyFraming {
        if requestMethod == "HEAD" || h.status == 204 || h.status == 304 || (100..<200).contains(h.status) { return .none }
        if h.isChunked { return .chunked }
        if let n = h.contentLength { return n > 0 ? .contentLength(n) : .none }
        return .untilClose
    }

    func makeDecoder(_ f: HTTPBodyFraming) -> HTTPBodyDecoding { HTTPBodyDecoder(f) }
    func serialize(_ h: HTTPRequestHead) throws -> Data { try h.serialized() }
    func serialize(_ h: HTTPResponseHead) throws -> Data { try h.serialized() }
    func chunk(_ p: Data) -> Data { HTTPChunkedEncoder.chunk(p) }
    var lastChunk: Data { Data("0\r\n\r\n".utf8) }
}

/// Incremental de-framer for one body. Content-Length, chunked (extensions ignored, trailers skipped) and
/// close-delimited. Input may be any slice; partial chunk-size lines are left unconsumed for the next feed.
final class HTTPBodyDecoder: HTTPBodyDecoding {
    private enum State { case fixed(Int64), size, data(Int64), dataCRLF, trailers, untilClose, done }
    private var state: State
    private static let maxLine = 4 << 10

    init(_ f: HTTPBodyFraming) {
        switch f {
        case .none: state = .done
        case .contentLength(let n): state = n > 0 ? .fixed(n) : .done
        case .chunked: state = .size
        case .untilClose: state = .untilClose
        }
    }

    func feed(_ wire: Data) throws -> HTTPBodyChunk {
        var out = Data()
        var i = wire.startIndex
        loop: while true {
            switch state {
            case .done:
                break loop
            case .untilClose:
                out.append(wire[i...]); i = wire.endIndex; break loop
            case .fixed(let left):
                let n = Int(min(Int64(wire.endIndex - i), left))
                out.append(wire[i..<(i + n)]); i += n
                state = left - Int64(n) == 0 ? .done : .fixed(left - Int64(n))
                break loop
            case .size:
                guard let lf = wire[i...].firstIndex(of: 0x0A) else {
                    if wire.endIndex - i > Self.maxLine { throw HTTPParseError.badChunkSize }
                    break loop
                }
                var line = String(decoding: wire[i..<lf], as: UTF8.self)
                if line.hasSuffix("\r") { line.removeLast() }
                if let semi = line.firstIndex(of: ";") { line = String(line[..<semi]) }
                guard let size = Int64(line.trimmingCharacters(in: .whitespaces), radix: 16), size >= 0 else {
                    throw HTTPParseError.badChunkSize
                }
                i = lf + 1
                state = size == 0 ? .trailers : .data(size)
            case .data(let left):
                if i == wire.endIndex { break loop }
                let n = Int(min(Int64(wire.endIndex - i), left))
                out.append(wire[i..<(i + n)]); i += n
                state = left - Int64(n) == 0 ? .dataCRLF : .data(left - Int64(n))
            case .dataCRLF:
                guard let lf = wire[i...].firstIndex(of: 0x0A) else {
                    if wire.endIndex - i > 2 { throw HTTPParseError.badChunkTerminator }
                    break loop
                }
                if lf - i > 1 || (lf - i == 1 && wire[i] != 0x0D) { throw HTTPParseError.badChunkTerminator }
                i = lf + 1; state = .size
            case .trailers:
                guard let lf = wire[i...].firstIndex(of: 0x0A) else {
                    if wire.endIndex - i > Self.maxLine { throw HTTPParseError.trailersTooLarge(limit: Self.maxLine) }
                    break loop
                }
                let empty = lf == i || (lf - i == 1 && wire[i] == 0x0D)
                i = lf + 1
                if empty { state = .done }
            }
        }
        var done = false
        if case .done = state { done = true }
        return HTTPBodyChunk(payload: out, consumed: i - wire.startIndex, done: done)
    }

    func finishAtEOF() throws -> Data {
        switch state {
        case .untilClose, .done: state = .done; return Data()
        default: throw HTTPParseError.unexpectedEOF
        }
    }
}

// MARK: - tls lane → MitmTLSFronting

extension MitmTLSFront: MitmTLSFronting {
    func listen(host: String, alpn: String) -> Int64 {
        // Session cap (memory) + switch: MitmTLSFront.admit, installed by NativeMitmRuntime.install, declines before the
        // handshake so Go keeps the connection (first-byte fallback is not even needed).
        listen(host, alpn: alpn) // admission (switch + session cap) runs inside, as for Go's own call
    }

    var acceptHandler: ((MitmAcceptedConnection) -> Void)? {
        get {
            guard let h = onAccept else { return nil }
            return { conn in
                if let s = conn.stream as? TLSByteStream { h(s) } else { conn.stream.close() }
            }
        }
        set {
            guard let newValue else { onAccept = nil; return }
            onAccept = { s in
                // Origin port: Go hands over host only; MitM'd HTTPS is 443 unless the request's Host says otherwise
                // (the session uses Go's forward URL, which carries the real port).
                newValue(MitmAcceptedConnection(stream: s, host: s.routingHost, port: 443, alpn: s.alpn,
                                                connID: NativeMitmRuntime.nextID()))
            }
        }
    }
}

// MARK: - upstream lane → MitmUpstreamConnecting

/// UpstreamConnection as the contract's ByteStream.
final class UpstreamStreamAdapter: ByteStream {
    let conn: UpstreamConnection
    init(_ c: UpstreamConnection) { conn = c }
    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) { conn.read(min: min, max: max, completion: completion) }
    func write(_ data: Data, completion: @escaping (Error?) -> Void) { conn.write(data, completion: completion) }
    func closeWrite() { conn.shutdownWrite { _ in } }
    func close() { conn.close() }
}

final class UpstreamPoolLease: MitmUpstreamLease {
    private let pool: UpstreamPool
    private let conn: UpstreamConnection
    let stream: ByteStream
    private var done = false
    private let lock = NSLock()
    init(pool: UpstreamPool, conn: UpstreamConnection) { self.pool = pool; self.conn = conn; stream = UpstreamStreamAdapter(conn) }
    func release(reusable: Bool) {
        lock.lock(); let first = !done; done = true; lock.unlock()
        guard first else { return }
        pool.release(conn, reusable: reusable)
    }
}

final class UpstreamPoolConnector: MitmUpstreamConnecting {
    let pool: UpstreamPool
    /// The engine's skip-cert-verify, read per open (a reload can change it).
    let skipVerify: () -> Bool
    init(pool: UpstreamPool = .shared, skipVerify: @escaping () -> Bool = { LibmihomoMitmSkipCertVerify() }) {
        self.pool = pool; self.skipVerify = skipVerify
    }
    func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        guard (1...65535).contains(port) else { return completion(.failure(UpstreamError.invalidTarget("port"))) }
        _ = pool.acquire(UpstreamTarget(host: host, port: UInt16(port), tls: tls, skipVerify: tls && skipVerify())) { [pool] r in
            switch r {
            case .success(let c): completion(.success(UpstreamPoolLease(pool: pool, conn: c)))
            case .failure(let e): completion(.failure(e))
            }
        }
    }
}

extension NativeMitmRuntime {
    /// Production wiring: the lanes' shared instances. Call once the engine runs (and again after a reload).
    @discardableResult
    static func installDefault() -> Bool {
        install(front: MitmTLSFront.shared, upstream: UpstreamPoolConnector(), codec: HTTPLaneCodec())
    }
}

// MARK: - memory bench (UnitTests/NativeMitmMemoryTests only)

/// Thin wrapper over the Go bench (bridge/s2bench.go) so the unit tests reach it through `@testable import`.
/// Never called by the app or the tunnel.
enum NativeMitmBench {
    /// JSON {enginePort, ca} or {error}.
    static func start() -> String { LibmihomoMitmBenchStart() }
    /// JSON {heapInuse, sys, stack, goroutines, handed, fellBack} after a GC.
    static func goMemory() -> String { LibmihomoMitmBenchMem() }
    static func stop() { LibmihomoMitmBenchStop() }
    static func relayPort() -> Int { Int(LibmihomoMitmRelayPort()) }
}
