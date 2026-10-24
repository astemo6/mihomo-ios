// Native MitM stage 2, lane `http` (B8a): incremental HTTP/1.1 parser, one instance per direction per connection.
//
//   let p = HTTPParser(role: .request)
//   for ev in try p.feed(bytes) { … }        // any split of the stream yields the same events (body may be re-sliced)
//   try p.finish()                            // at EOF: ends a close-delimited body, throws on a truncated message
//
// Events per message: head → body* → trailers? → end(keepAlive:). Pipelined messages follow back to back.
// Response side: call `expectResponse(toMethod:)` once per forwarded request (FIFO) so HEAD / CONNECT responses are
// framed correctly; interim 1xx heads arrive as `.interim` and do not consume a method.
//
// Upgrade / CONNECT:
//   • request side: after `.end` of a request that asks for an upgrade (CONNECT, or Upgrade + Connection: upgrade) the
//     parser emits `.upgradeRequested` and buffers everything after it. The caller sees the response, then calls
//     `acceptUpgrade()` (101 / 2xx-to-CONNECT: returns the buffered bytes; later feeds yield `.passthrough`) or
//     `rejectUpgrade()` (resumes HTTP parsing over the buffered bytes).
//   • response side: a 101, or a 2xx to CONNECT, emits the head then `.upgrade(rest)`; later feeds yield `.passthrough`.
//
// Errors are fail-closed and sticky: once `feed` throws, every later call throws the same error (kill the connection;
// the Go path is the fallback). Events produced earlier in the throwing call are dropped.
//
// Zero copy: body bytes are handed out as the caller's own Data when a whole read is body (the common streaming case);
// otherwise as a compact copy with startIndex 0. Heads keep their exact original bytes in `rawBytes`.

import Foundation

enum HTTPParserEvent: Equatable {
    case request(HTTPRequestHead, HTTPBodyFraming)
    case response(HTTPResponseHead, HTTPBodyFraming)
    case interim(HTTPResponseHead)
    case body(Data)
    case trailers(HTTPHeaderList, raw: Data)
    case end(keepAlive: Bool)
    case upgradeRequested
    case upgrade(Data)
    case passthrough(Data)

    static func == (a: Self, b: Self) -> Bool {
        switch (a, b) {
        case let (.request(x, f), .request(y, g)): return x == y && f == g
        case let (.response(x, f), .response(y, g)): return x == y && f == g
        case let (.interim(x), .interim(y)): return x == y
        case let (.body(x), .body(y)): return x == y
        case let (.trailers(x, r), .trailers(y, s)): return HTTPWire.same(x, y) && r == s
        case let (.end(x), .end(y)): return x == y
        case (.upgradeRequested, .upgradeRequested): return true
        case let (.upgrade(x), .upgrade(y)): return x == y
        case let (.passthrough(x), .passthrough(y)): return x == y
        default: return false
        }
    }
}

struct HTTPParserLimits: Equatable {
    var maxHeadBytes = 64 << 10       // whole head incl. start line and terminating empty line
    var maxLineBytes = 16 << 10       // any single start / header / trailer line
    var maxHeaderCount = 256
    var maxChunkLineBytes = 4 << 10   // chunk-size line incl. extensions
    var maxTrailerBytes = 64 << 10
}

final class HTTPParser {
    enum Role { case request, response }
    /// `.decoded`: chunked bodies are emitted as payload only. `.raw`: body events carry the exact wire bytes (chunk
    /// framing and trailers included), so heads' rawBytes + body bytes reproduce the stream byte for byte.
    enum BodyMode { case decoded, raw }

    let role: Role
    let limits: HTTPParserLimits
    let bodyMode: BodyMode

    private enum State {
        case head
        case fixedBody(Int64)
        case untilClose
        case chunkSize
        case chunkData(Int64)
        case chunkDataEnd
        case trailers
        case upgradePending
        case passthrough
        case failed(HTTPParseError)
        case finished
    }

    private var state: State = .head
    private var pending = Data()            // unconsumed bytes, always startIndex 0
    // Line scanner state for head / trailers (offsets relative to the unit start = pending start).
    private var scanned = 0
    private var lineStart = 0
    private var unitStart = 0               // skips leading empty lines before a request line
    private var lines: [Range<Int>] = []
    // Current message.
    private var keepAlive = true
    private var upgradeAfterEnd = false
    private var methods: [String] = []      // response side FIFO

    init(role: Role, limits: HTTPParserLimits = HTTPParserLimits(), bodyMode: BodyMode = .decoded) {
        self.role = role
        self.limits = limits
        self.bodyMode = bodyMode
    }

    /// Response side: the method of the next forwarded request, in send order.
    func expectResponse(toMethod method: String) { methods.append(method) }

    /// Bytes buffered but not yet parsed (diagnostics / memory accounting).
    var bufferedByteCount: Int { pending.count }

    var isPassthrough: Bool { if case .passthrough = state { return true }; return false }

    func feed(_ data: Data) throws -> [HTTPParserEvent] {
        switch state {
        case .failed(let e): throw e
        case .finished: return []
        case .passthrough: return data.isEmpty ? [] : [.passthrough(data)]
        case .upgradePending: pending.append(data); return []
        default: break
        }
        var buf: Data
        if pending.isEmpty {
            buf = data
        } else {
            pending.append(data)
            buf = pending
        }
        pending = Data()
        var events: [HTTPParserEvent] = []
        var pos = 0
        do {
            try run(buf, &pos, &events)
        } catch let e as HTTPParseError {
            state = .failed(e)
            pending = Data()
            throw e
        }
        if pos < buf.count { pending = sub(buf, pos, buf.count) }
        return events
    }

    /// EOF from the peer. Ends a close-delimited body; throws `.unexpectedEOF` for a truncated head or body.
    func finish() throws -> [HTTPParserEvent] {
        defer { if case .failed = state {} else { state = .finished } }
        switch state {
        case .failed(let e): throw e
        case .untilClose: return [.end(keepAlive: false)]
        case .head:
            // Only stray empty lines between messages may be left.
            if pending.allSatisfy({ $0 == 0x0D || $0 == 0x0A }) { return [] }
            state = .failed(.unexpectedEOF); throw HTTPParseError.unexpectedEOF
        case .fixedBody, .chunkSize, .chunkData, .chunkDataEnd, .trailers:
            state = .failed(.unexpectedEOF); throw HTTPParseError.unexpectedEOF
        case .upgradePending, .passthrough, .finished:
            return []
        }
    }

    /// Upgrade / CONNECT accepted by the peer: returns the bytes buffered since `.upgradeRequested`; from now on every
    /// feed yields `.passthrough`.
    func acceptUpgrade() -> Data {
        guard case .upgradePending = state else { return Data() }
        state = .passthrough
        let rest = pending
        pending = Data()
        return rest
    }

    /// Upgrade refused (the response was not 101 / 2xx): parse the buffered bytes as the next pipelined messages.
    func rejectUpgrade() throws -> [HTTPParserEvent] {
        guard case .upgradePending = state else { return [] }
        resetHead()
        let rest = pending
        pending = Data()
        return try feed(rest)
    }

    // MARK: - Engine

    private func run(_ buf: Data, _ pos: inout Int, _ ev: inout [HTTPParserEvent]) throws {
        while true {
            switch state {
            case .head:
                guard try scanLines(buf, pos, maxBytes: limits.maxHeadBytes, isHead: true) else { return }
                let headEnd = pos + scanned
                try emitHead(buf, pos, headEnd, &ev)
                pos = headEnd
            case .fixedBody(let remaining):
                let avail = buf.count - pos
                if avail == 0 { return }
                let n = Int(min(remaining, Int64(avail)))
                emitBody(buf, pos, pos + n, &ev)
                pos += n
                if remaining == Int64(n) { endMessage(&ev) } else { state = .fixedBody(remaining - Int64(n)); return }
            case .untilClose:
                if pos < buf.count { emitBody(buf, pos, buf.count, &ev); pos = buf.count }
                return
            case .chunkSize:
                guard let lf = findLF(buf, from: pos, limit: limits.maxChunkLineBytes) else {
                    if buf.count - pos > limits.maxChunkLineBytes { throw HTTPParseError.lineTooLong(limit: limits.maxChunkLineBytes) }
                    return
                }
                let size = try parseChunkSize(buf, pos, lf)
                if bodyMode == .raw { emitBody(buf, pos, lf + 1, &ev) }
                pos = lf + 1
                if size == 0 { resetLines(); state = .trailers } else { state = .chunkData(size) }
            case .chunkData(let remaining):
                let avail = buf.count - pos
                if avail == 0 { return }
                let n = Int(min(remaining, Int64(avail)))
                emitBody(buf, pos, pos + n, &ev)
                pos += n
                if remaining == Int64(n) { state = .chunkDataEnd } else { state = .chunkData(remaining - Int64(n)); return }
            case .chunkDataEnd:
                if buf.count - pos < 2 {
                    if buf.count - pos == 1 && byte(buf, pos) != 0x0D { throw HTTPParseError.badChunkTerminator }
                    return
                }
                guard byte(buf, pos) == 0x0D, byte(buf, pos + 1) == 0x0A else { throw HTTPParseError.badChunkTerminator }
                if bodyMode == .raw { emitBody(buf, pos, pos + 2, &ev) }
                pos += 2
                state = .chunkSize
            case .trailers:
                guard try scanLines(buf, pos, maxBytes: limits.maxTrailerBytes, isHead: false) else { return }
                let end = pos + scanned
                var fields: HTTPHeaderList = []
                for r in lines { fields.append(try parseField(buf, pos + r.lowerBound, pos + r.upperBound)) }
                if bodyMode == .raw { emitBody(buf, pos, end, &ev) }
                if !fields.isEmpty || bodyMode == .raw { ev.append(.trailers(fields, raw: sub(buf, pos, end))) }
                pos = end
                endMessage(&ev)
            case .upgradePending:
                return   // the remainder is kept in `pending` by feed()
            case .passthrough:
                pos = buf.count   // the remainder already went out with `.upgrade`
                return
            case .failed(let e):
                throw e
            case .finished:
                pos = buf.count
                return
            }
        }
    }

    private func endMessage(_ ev: inout [HTTPParserEvent]) {
        ev.append(.end(keepAlive: keepAlive))
        if upgradeAfterEnd {
            upgradeAfterEnd = false
            ev.append(.upgradeRequested)
            state = .upgradePending
        } else {
            resetHead()
        }
    }

    private func resetHead() {
        state = .head
        resetLines()
    }

    private func resetLines() {
        scanned = 0; lineStart = 0; unitStart = 0; lines = []
    }

    /// Scans CRLF- (or LF-) terminated lines from `base` until an empty line. Returns true when the unit is complete;
    /// `scanned` is then its total length and `lines` the non-empty line content ranges (relative to `base`).
    private func scanLines(_ buf: Data, _ base: Int, maxBytes: Int, isHead: Bool) throws -> Bool {
        let tooLarge: HTTPParseError = isHead ? .headTooLarge(limit: maxBytes) : .trailersTooLarge(limit: maxBytes)
        let count = buf.count - base
        var i = scanned
        while i < count {
            if byte(buf, base + i) != 0x0A { i += 1; continue }
            var contentEnd = i
            if contentEnd > lineStart && byte(buf, base + contentEnd - 1) == 0x0D { contentEnd -= 1 }
            let lineLen = contentEnd - lineStart
            if lineLen > limits.maxLineBytes { throw HTTPParseError.lineTooLong(limit: limits.maxLineBytes) }
            if i + 1 - unitStart > maxBytes { throw tooLarge }
            for k in lineStart..<contentEnd where byte(buf, base + k) == 0x0D { throw HTTPParseError.bareCR }
            if lineLen == 0 {
                if isHead && lines.isEmpty && role == .request {
                    // RFC 9112 §2.2: ignore empty line(s) received before the request-line.
                    lineStart = i + 1; unitStart = i + 1; i += 1
                    continue
                }
                if isHead && lines.isEmpty { throw HTTPParseError.malformedStartLine }
                scanned = i + 1
                return true
            }
            lines.append(lineStart..<contentEnd)
            if lines.count > limits.maxHeaderCount + 1 { throw HTTPParseError.tooManyHeaders(limit: limits.maxHeaderCount) }
            lineStart = i + 1
            i += 1
        }
        scanned = count
        // +1: the line's CR may already be here while its LF is not (keeps any split of the stream equivalent).
        if count - lineStart > limits.maxLineBytes + 1 { throw HTTPParseError.lineTooLong(limit: limits.maxLineBytes) }
        if count - unitStart > maxBytes { throw tooLarge }
        return false
    }

    private func emitHead(_ buf: Data, _ base: Int, _ end: Int, _ ev: inout [HTTPParserEvent]) throws {
        let startLine = lines[0]
        let slBytes = sub(buf, base + startLine.lowerBound, base + startLine.upperBound)
        var headers: HTTPHeaderList = []
        headers.reserveCapacity(lines.count - 1)
        for r in lines.dropFirst() { headers.append(try parseField(buf, base + r.lowerBound, base + r.upperBound)) }
        let raw = sub(buf, base + unitStart, end)
        switch role {
        case .request:
            try validateRequestLine(slBytes)
            let head = HTTPRequestHead(parsedStartLine: HTTPWire.latin1(slBytes), headers: headers, rawBytes: raw)
            let framing = try requestFraming(head)
            keepAlive = head.wantsKeepAlive
            upgradeAfterEnd = head.requestsUpgrade
            ev.append(.request(head, framing))
            begin(framing, &ev)
        case .response:
            try validateStatusLine(slBytes)
            let head = HTTPResponseHead(parsedStartLine: HTTPWire.latin1(slBytes), headers: headers, rawBytes: raw)
            if head.isInterim {
                ev.append(.interim(head))
                resetLines()
                return
            }
            let method = methods.isEmpty ? "GET" : methods.removeFirst()
            let status = head.status
            if status == 101 || (method == "CONNECT" && (200..<300).contains(status)) {
                ev.append(.response(head, .none))
                ev.append(.upgrade(sub(buf, end, buf.count)))
                state = .passthrough
                return
            }
            let framing = try responseFraming(head, method: method)
            keepAlive = head.wantsKeepAlive && framing != .untilClose
            upgradeAfterEnd = false
            ev.append(.response(head, framing))
            begin(framing, &ev)
        }
    }

    private func begin(_ framing: HTTPBodyFraming, _ ev: inout [HTTPParserEvent]) {
        resetLines()
        switch framing {
        case .none, .contentLength(0): endMessage(&ev)
        case .contentLength(let n): state = .fixedBody(n)
        case .chunked: state = .chunkSize
        case .untilClose: state = .untilClose
        }
    }

    // MARK: - Framing (RFC 9112 §6.1–6.3)

    private func requestFraming(_ head: HTTPRequestHead) throws -> HTTPBodyFraming {
        let te = head.tokens(for: "Transfer-Encoding")
        let hasTE = head.contains("Transfer-Encoding")
        let cl = try contentLength(head)
        if head.isConnect { return .none }
        if hasTE {
            if cl != nil { throw HTTPParseError.conflictingFraming }
            // Like Go's server: "chunked" is the only transfer coding accepted on requests.
            guard te == ["chunked"] else { throw HTTPParseError.unsupportedTransferEncoding }
            return .chunked
        }
        if let cl { return .contentLength(cl) }
        return .none
    }

    private func responseFraming(_ head: HTTPResponseHead, method: String) throws -> HTTPBodyFraming {
        let status = head.status
        if method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status) { return .none }
        if head.contains("Transfer-Encoding") {
            // chunked wins over Content-Length; any other final coding is close-delimited (§6.3 rule 4).
            return head.tokens(for: "Transfer-Encoding").last == "chunked" ? .chunked : .untilClose
        }
        if let cl = try contentLength(head) { return .contentLength(cl) }
        return .untilClose
    }

    /// All Content-Length fields (and comma lists inside them) must be 1*DIGIT and agree.
    private func contentLength<H: HTTPHead>(_ head: H) throws -> Int64? {
        let raw = head.values(for: "Content-Length")
        if raw.isEmpty { return nil }
        var value: Int64?
        for field in raw {
            for part in field.split(separator: ",", omittingEmptySubsequences: false) {
                let t = part.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
                guard !t.isEmpty, t.count <= 18, t.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let n = Int64(t) else {
                    throw HTTPParseError.badContentLength
                }
                if let v = value, v != n { throw HTTPParseError.badContentLength }
                value = n
            }
        }
        return value
    }

    // MARK: - Lines

    private func validateRequestLine(_ sl: Data) throws {
        let b = [UInt8](sl)
        guard let sp1 = b.firstIndex(of: 0x20), let sp2 = b.lastIndex(of: 0x20), sp1 < sp2, sp1 > 0, sp2 > sp1 + 1 else {
            throw HTTPParseError.malformedStartLine
        }
        guard b[0..<sp1].allSatisfy(HTTPWire.isTokenByte) else { throw HTTPParseError.malformedStartLine }
        guard b[(sp1 + 1)..<sp2].allSatisfy({ $0 > 0x20 && $0 != 0x7F }) else { throw HTTPParseError.malformedStartLine }
        try validateVersion(b[(sp2 + 1)...])
    }

    private func validateStatusLine(_ sl: Data) throws {
        let b = [UInt8](sl)
        guard let sp = b.firstIndex(of: 0x20) else { throw HTTPParseError.malformedStartLine }
        try validateVersion(b[0..<sp])
        let rest = b[(sp + 1)...]
        guard rest.count >= 3, rest.prefix(3).allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), rest.first != 0x30 else {
            throw HTTPParseError.malformedStartLine
        }
        if rest.count > 3 {
            guard rest[rest.startIndex + 3] == 0x20, rest.dropFirst(4).allSatisfy(HTTPWire.isValueByte) else {
                throw HTTPParseError.malformedStartLine
            }
        }
    }

    private func validateVersion(_ v: ArraySlice<UInt8>) throws {
        let s = Array(v)
        guard s.count == 8, s.prefix(5).elementsEqual("HTTP/".utf8), s[6] == UInt8(ascii: "."),
              s[5] >= 0x30, s[5] <= 0x39, s[7] >= 0x30, s[7] <= 0x39 else {
            throw HTTPParseError.malformedStartLine
        }
        guard s[5] == UInt8(ascii: "1") else { throw HTTPParseError.unsupportedVersion }
    }

    private func parseField(_ buf: Data, _ from: Int, _ to: Int) throws -> (name: String, value: String) {
        let first = byte(buf, from)
        if first == 0x20 || first == 0x09 { throw HTTPParseError.obsFold }
        var colon = -1
        var i = from
        while i < to {
            let c = byte(buf, i)
            if c == UInt8(ascii: ":") { colon = i; break }
            guard HTTPWire.isTokenByte(c) else { throw HTTPParseError.malformedHeaderLine }
            i += 1
        }
        guard colon > from else { throw HTTPParseError.malformedHeaderLine }
        var vs = colon + 1, ve = to
        while vs < ve, byte(buf, vs) == 0x20 || byte(buf, vs) == 0x09 { vs += 1 }
        while ve > vs, byte(buf, ve - 1) == 0x20 || byte(buf, ve - 1) == 0x09 { ve -= 1 }
        for k in vs..<ve where !HTTPWire.isValueByte(byte(buf, k)) { throw HTTPParseError.invalidHeaderValue }
        return (HTTPWire.latin1(sub(buf, from, colon)), HTTPWire.latin1(sub(buf, vs, ve)))
    }

    /// chunk-size [ BWS ; ext ] — hex, at most 15 digits (fits Int64), extensions ignored.
    private func parseChunkSize(_ buf: Data, _ from: Int, _ lf: Int) throws -> Int64 {
        var end = lf
        if end > from && byte(buf, end - 1) == 0x0D { end -= 1 }
        var size: Int64 = 0
        var digits = 0
        var i = from
        while i < end, let d = hexValue(byte(buf, i)) {
            size = size << 4 | Int64(d)
            digits += 1
            if digits > 15 { throw HTTPParseError.badChunkSize }
            i += 1
        }
        guard digits > 0 else { throw HTTPParseError.badChunkSize }
        while i < end, byte(buf, i) == 0x20 || byte(buf, i) == 0x09 { i += 1 }
        if i < end {
            guard byte(buf, i) == UInt8(ascii: ";") else { throw HTTPParseError.badChunkSize }
            for k in i..<end where byte(buf, k) == 0x0D || byte(buf, k) == 0 { throw HTTPParseError.badChunkSize }
        }
        return size
    }

    private func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }

    // MARK: - Bytes

    @inline(__always) private func byte(_ buf: Data, _ i: Int) -> UInt8 { buf[buf.startIndex + i] }

    private func findLF(_ buf: Data, from: Int, limit: Int) -> Int? {
        let end = min(buf.count, from + limit + 1)   // LF at most `limit` bytes in
        var i = from
        while i < end { if byte(buf, i) == 0x0A { return i }; i += 1 }
        return nil
    }

    /// Compact copy with startIndex 0 — or the buffer itself when the range covers all of it (zero copy).
    private func sub(_ buf: Data, _ from: Int, _ to: Int) -> Data {
        if from == 0 && to == buf.count { return buf }
        if from >= to { return Data() }
        return buf.subdata(in: (buf.startIndex + from)..<(buf.startIndex + to))
    }

    private func emitBody(_ buf: Data, _ from: Int, _ to: Int, _ ev: inout [HTTPParserEvent]) {
        guard to > from else { return }
        let piece = sub(buf, from, to)
        if case .body(let prev)? = ev.last {
            ev[ev.count - 1] = .body(prev + piece)   // coalesce (raw chunked framing, back-to-back chunks)
        } else {
            ev.append(.body(piece))
        }
    }
}
