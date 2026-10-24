import Foundation

/// B8 draft (native MitM lane): incremental HTTP/1.1 head parsing, body framing and
/// serialization for the Swift side of the tunnel.
///
/// Scope: this file knows nothing about rules or scripts. It turns bytes from the
/// client-facing TLS stream (B7) into a request head + a framed body stream, and
/// serializes the (possibly rewritten) head back out — towards the Go relay
/// (`Upstream.swift`) or back to the client. Rule matching and script semantics
/// stay in Go (B6); Go hands this layer a parsed rule table and receives bodies
/// through the body channel (B1–B3).
///
/// Framing rules implemented (RFC 9112 §6):
///   - requests: Content-Length, or Transfer-Encoding: chunked; no body otherwise
///     (a request with neither has no body, whatever the method).
///   - responses: 1xx / 204 / 304 and responses to HEAD never carry a body;
///     chunked wins over Content-Length when both appear; a response with
///     neither is delimited by connection close ("until close" — the caller
///     must not reuse that connection).
///   - interim 1xx responses (100 Continue, 103 Early Hints) precede the final
///     response head; the parser emits them as `.interim` heads and keeps going.
///
/// Errors are typed and fail-closed: a malformed head or chunk must kill the
/// connection, never be "repaired" — the Go path is the fallback (B6 circuit
/// breaker decides per host / per app launch).

// MARK: - Headers

/// Ordered, case-insensitive header list. Order and duplicates are preserved:
/// relaying must not fold Set-Cookie or reorder fields the way a dictionary
/// would (the Go side sorts nothing either — `http.Header` keeps insertion
/// order per key and wire order across keys is lost there; here we keep full
/// wire order, which is strictly more faithful).
struct HTTPHeaders: Equatable {
    private(set) var fields: [(name: String, value: String)] = []

    init() {}

    init(_ fields: [(String, String)]) {
        for (n, v) in fields { append(n, v) }
    }

    /// All values for `name` (case-insensitive), in wire order.
    func values(_ name: String) -> [String] {
        let key = name.lowercased()
        return fields.filter { $0.name.lowercased() == key }.map { $0.value }
    }

    func first(_ name: String) -> String? { values(name).first }

    func contains(_ name: String) -> Bool { first(name) != nil }

    /// Replace every existing field of this name with a single one (position of
    /// the first occurrence is kept, matching Go's `Header.Set`).
    mutating func set(_ name: String, _ value: String) {
        let key = name.lowercased()
        if let idx = fields.firstIndex(where: { $0.name.lowercased() == key }) {
            fields.removeAll { $0.name.lowercased() == key }
            fields.insert((name, value), at: idx)
        } else {
            fields.append((name, value))
        }
    }

    mutating func append(_ name: String, _ value: String) {
        fields.append((name, value))
    }

    mutating func remove(_ name: String) {
        let key = name.lowercased()
        fields.removeAll { $0.name.lowercased() == key }
    }

    /// Serialize as wire bytes: `Name: value\r\n` per field. Values are written
    /// verbatim; callers must not put CR/LF in a value (rewrite ops validate).
    func serialize(into data: inout Data) {
        for f in fields {
            data.append(contentsOf: f.name.utf8)
            data.append(contentsOf: ": ".utf8)
            data.append(contentsOf: f.value.utf8)
            data.append(contentsOf: "\r\n".utf8)
        }
    }
}

// MARK: - Heads

struct HTTPRequestHead: Equatable {
    var method: String
    var target: String          // origin-form, or absolute-form from a proxy-style request line
    var version: String         // "HTTP/1.1" / "HTTP/1.0"
    var headers: HTTPHeaders

    func serialize() -> Data {
        var d = Data()
        d.append(contentsOf: "\(method) \(target) \(version)\r\n".utf8)
        headers.serialize(into: &d)
        d.append(contentsOf: "\r\n".utf8)
        return d
    }
}

struct HTTPResponseHead: Equatable {
    var version: String
    var status: Int
    var reason: String
    var headers: HTTPHeaders

    var isInterim: Bool { (100..<200).contains(status) && status != 101 }

    func serialize() -> Data {
        var d = Data()
        let r = reason.isEmpty ? "" : " \(reason)"
        d.append(contentsOf: "\(version) \(status)\(r)\r\n".utf8)
        headers.serialize(into: &d)
        d.append(contentsOf: "\r\n".utf8)
        return d
    }
}

enum HTTPParseError: Error, Equatable {
    case headTooLarge(limit: Int)
    case malformedStartLine(String)
    case malformedHeaderLine(String)
    case badContentLength(String)
    case badChunkSize(String)
    case badChunkTerminator
    case unsupportedTransferEncoding(String)
}

// MARK: - Incremental head parser

/// Feed bytes; each `parse` call consumes exactly one head (start line +
/// headers) from the front of the buffer and returns the leftover bytes
/// (body bytes / pipelined next head). Returns nil while the head is
/// incomplete. One parser instance per direction per connection.
struct HTTPHeadParser {
    /// Heads beyond this are a hard error (Go's server caps at 10 MB by
    /// default; a MitM relay should be far stricter — a head is cookies and
    /// metadata, never payload).
    static let maxHeadBytes = 64 * 1024

    private var buffer = Data()
    private(set) var bufferedByteCount: Int = 0

    mutating func feed(_ data: Data) {
        buffer.append(data)
        bufferedByteCount = buffer.count
    }

    private mutating func takeHeadBytes() throws -> Data? {
        guard let range = buffer.range(of: Data("\r\n\r\n".utf8)) else {
            if buffer.count > Self.maxHeadBytes { throw HTTPParseError.headTooLarge(limit: Self.maxHeadBytes) }
            return nil
        }
        let head = buffer.subdata(in: buffer.startIndex..<range.upperBound)
        if head.count > Self.maxHeadBytes { throw HTTPParseError.headTooLarge(limit: Self.maxHeadBytes) }
        buffer.removeSubrange(buffer.startIndex..<range.upperBound)
        bufferedByteCount = buffer.count
        return head
    }

    mutating func parseRequest() throws -> (head: HTTPRequestHead, rest: Data)? {
        guard let raw = try takeHeadBytes() else { return nil }
        let lines = Self.lines(raw)
        guard let start = lines.first, !start.isEmpty else {
            throw HTTPParseError.malformedStartLine("")
        }
        let parts = start.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/") else {
            throw HTTPParseError.malformedStartLine(start)
        }
        let headers = try Self.parseHeaders(Array(lines.dropFirst()))
        let rest = buffer
        buffer.removeAll(); bufferedByteCount = 0
        return (HTTPRequestHead(method: String(parts[0]), target: String(parts[1]),
                                version: String(parts[2]), headers: headers), rest)
    }

    mutating func parseResponse() throws -> (head: HTTPResponseHead, rest: Data)? {
        guard let raw = try takeHeadBytes() else { return nil }
        let lines = Self.lines(raw)
        guard let start = lines.first, start.hasPrefix("HTTP/") else {
            throw HTTPParseError.malformedStartLine(lines.first ?? "")
        }
        let afterVersion = start.drop(while: { $0 != " " }).dropFirst()
        let statusStr = afterVersion.prefix(while: { $0 != " " })
        guard let status = Int(statusStr), (100...999).contains(status) else {
            throw HTTPParseError.malformedStartLine(start)
        }
        let reason = afterVersion.count > statusStr.count
            ? String(afterVersion.dropFirst(statusStr.count + 1)) : ""
        let headers = try Self.parseHeaders(Array(lines.dropFirst()))
        let rest = buffer
        buffer.removeAll(); bufferedByteCount = 0
        return (HTTPResponseHead(version: String(start.prefix(while: { $0 != " " })),
                                 status: status, reason: reason, headers: headers), rest)
    }

    private static func lines(_ head: Data) -> [String] {
        // The head is decoded lossily (invalid sequences become U+FFFD):
        // start lines and header names are ASCII in practice, so parsing is
        // unaffected. KNOWN LIMITATION (see README, OPEN #5): a header VALUE
        // carrying obs-text / non-UTF-8 bytes would not survive a
        // parse → serialize round trip byte-identically, where Go's parser
        // keeps the raw bytes. Such values are vanishingly rare (some
        // cookies, legacy filename headers); until the byte-faithful parser
        // lands, hosts known to need it stay on the Go path.
        let text = String(decoding: head, as: UTF8.self)
        return text.components(separatedBy: "\r\n").filter { !$0.isEmpty }
    }

    private static func parseHeaders(_ lines: [String]) throws -> HTTPHeaders {
        var h = HTTPHeaders()
        for line in lines {
            if line.isEmpty { continue }
            // obs-fold (line starting with SP/HTAB) is rejected outright:
            // Go's parser rejects it too, and accepting it is a smuggling risk.
            if line.hasPrefix(" ") || line.hasPrefix("\t") {
                throw HTTPParseError.malformedHeaderLine(line)
            }
            guard let colon = line.firstIndex(of: ":") else {
                throw HTTPParseError.malformedHeaderLine(line)
            }
            let name = String(line[line.startIndex..<colon])
            var value = String(line[line.index(after: colon)...])
            while value.hasPrefix(" ") || value.hasPrefix("\t") { value.removeFirst() }
            while value.hasSuffix(" ") || value.hasSuffix("\t") { value.removeLast() }
            guard !name.isEmpty, !name.contains(" ") else {
                throw HTTPParseError.malformedHeaderLine(line)
            }
            h.append(name, value)
        }
        return h
    }
}

// MARK: - Body framing

enum HTTPBodyFraming: Equatable {
    case none                                   // no body follows this head
    case contentLength(Int)                     // exactly N bytes
    case chunked                                // Transfer-Encoding: chunked
    case untilClose                             // responses only; body ends at EOF

    static func forRequest(_ head: HTTPRequestHead) throws -> HTTPBodyFraming {
        if let te = head.headers.first("Transfer-Encoding") {
            let tokens = te.lowercased().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if tokens.last == "chunked" { return .chunked }
            throw HTTPParseError.unsupportedTransferEncoding(te)
        }
        if let cl = head.headers.first("Content-Length") {
            return .contentLength(try parseContentLength(cl))
        }
        return .none
    }

    static func forResponse(_ head: HTTPResponseHead, requestMethod: String) throws -> HTTPBodyFraming {
        if requestMethod == "HEAD" || head.status == 204 || head.status == 304
            || (100..<200).contains(head.status) {
            return .none
        }
        if let te = head.headers.first("Transfer-Encoding") {
            let tokens = te.lowercased().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if tokens.last == "chunked" { return .chunked }
            // A non-chunked final transfer coding on a response means the body
            // runs to close (RFC 9112 §6.3) — e.g. old "chunked" mislabels.
            return .untilClose
        }
        if let cl = head.headers.first("Content-Length") {
            return .contentLength(try parseContentLength(cl))
        }
        return .untilClose
    }

    private static func parseContentLength(_ raw: String) throws -> Int {
        // Multiple Content-Length fields arrive already joined by the header
        // accessor in some paths; accept only one consistent value.
        let parts = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, let n = Int(first), n >= 0,
              parts.allSatisfy({ Int($0) == n }) else {
            throw HTTPParseError.badContentLength(raw)
        }
        return n
    }
}

// MARK: - Chunked body decoder

/// Incremental chunked transfer decoder. Feed body bytes; it emits decoded
/// payload and, at the terminal chunk, the trailer fields. One instance per
/// body. (The matching encoder is `HTTPChunked.encode` below — relaying a
/// decoded body re-chunks it; bodies that go through the body channel come
/// back with a known length instead, see README.)
struct HTTPChunkedDecoder {
    private enum State { case sizeLine, chunk(Int), chunkCRLF, trailers, done }
    private var state: State = .sizeLine
    private var buffer = Data()
    private(set) var trailers = HTTPHeaders()
    private(set) var isDone = false

    mutating func feed(_ data: Data) throws -> Data {
        buffer.append(data)
        var out = Data()
        while !isDone {
            switch state {
            case .sizeLine:
                guard let eol = buffer.range(of: Data("\r\n".utf8)) else { return out }
                let lineData = buffer.subdata(in: buffer.startIndex..<eol.lowerBound)
                buffer.removeSubrange(buffer.startIndex..<eol.upperBound)
                let line = String(decoding: lineData, as: UTF8.self)
                let sizePart = line.split(separator: ";", maxSplits: 1).first.map(String.init) ?? line
                guard let size = Int(sizePart.trimmingCharacters(in: .whitespaces), radix: 16),
                      size >= 0 else {
                    throw HTTPParseError.badChunkSize(line)
                }
                state = size == 0 ? .trailers : .chunk(size)
            case .chunk(let remaining):
                if buffer.isEmpty { return out }
                let take = min(remaining, buffer.count)
                out.append(buffer.prefix(take))
                buffer.removeFirst(take)
                state = take == remaining ? .chunkCRLF : .chunk(remaining - take)
            case .chunkCRLF:
                if buffer.count < 2 { return out }
                guard buffer.prefix(2).elementsEqual("\r\n".utf8) else {
                    throw HTTPParseError.badChunkTerminator
                }
                buffer.removeFirst(2)
                state = .sizeLine
            case .trailers:
                guard let eol = buffer.range(of: Data("\r\n".utf8)) else { return out }
                let lineData = buffer.subdata(in: buffer.startIndex..<eol.lowerBound)
                buffer.removeSubrange(buffer.startIndex..<eol.upperBound)
                if lineData.isEmpty {
                    state = .done
                    isDone = true
                } else {
                    let line = String(decoding: lineData, as: UTF8.self)
                    guard let colon = line.firstIndex(of: ":") else {
                        throw HTTPParseError.malformedHeaderLine(line)
                    }
                    trailers.append(String(line[line.startIndex..<colon]),
                                    String(line[line.index(after: colon)...])
                                        .trimmingCharacters(in: .whitespaces))
                }
            case .done:
                return out
            }
        }
        return out
    }
}

enum HTTPChunked {
    static func encode(_ payload: Data) -> Data {
        var d = Data()
        d.append(contentsOf: String(payload.count, radix: 16).utf8)
        d.append(contentsOf: "\r\n".utf8)
        d.append(payload)
        d.append(contentsOf: "\r\n".utf8)
        return d
    }

    static func terminal(trailerFields: HTTPHeaders = HTTPHeaders()) -> Data {
        var d = Data(contentsOf: "0\r\n".utf8)
        trailerFields.serialize(into: &d)
        d.append(contentsOf: "\r\n".utf8)
        return d
    }
}
