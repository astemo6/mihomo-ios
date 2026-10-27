// Native MitM stage 2, lane `http` (B8a): HTTP/1.1 message heads + serializer.
//
// HTTPRequestHead / HTTPResponseHead follow the S2 shared contract (work/native-s2-lanes.md): rawStartLine, headers as
// [(name, value)] in wire order and wire case, rawBytes = the exact bytes read. Lane `wire` owns S2Contract.swift; it did
// not exist when this lane was written, so the structs live here — at integration either keep them here or move them
// verbatim into S2Contract.swift (nothing else in this folder depends on where they are declared).
//
// Byte faithfulness: start lines and header lines are decoded as ISO-8859-1, which maps every byte 0x00–0xFF to exactly
// one scalar, so obs-text / non-UTF-8 header values survive parse → modify → serialize unchanged (this closes OPEN #5 of
// astemo6's B8 draft, which decoded lossily as UTF-8). A head nobody modified serializes as its original rawBytes.
//
// Credits: header semantics (the old core `Header.Set` position rule, never folding duplicates, obs-fold rejection, fail-closed
// typed errors, re-framing rules) follow astemo6's draft drafts/native-mitm/HTTPMessage.swift (origin/draft/native-mitm-
// b7b8 6b53dc6); the parser itself was rewritten byte-level and incremental (HTTPParser.swift).

import Foundation

typealias HTTPHeaderList = [(name: String, value: String)]

enum HTTPParseError: Error, Equatable {
    case headTooLarge(limit: Int)
    case lineTooLong(limit: Int)
    case tooManyHeaders(limit: Int)
    case malformedStartLine
    case unsupportedVersion
    case malformedHeaderLine
    case obsFold
    case invalidHeaderValue
    case bareCR
    case badContentLength
    case conflictingFraming          // request with both Transfer-Encoding and Content-Length (smuggling vector)
    case unsupportedTransferEncoding
    case badChunkSize
    case badChunkTerminator
    case trailersTooLarge(limit: Int)
    case unexpectedEOF
    case invalidForSerialization     // a modified head carries CR / LF / NUL or a non-token name
}

/// How the body following a head is delimited (RFC 9112 §6).
enum HTTPBodyFraming: Equatable {
    case none
    case contentLength(Int64)
    case chunked
    case untilClose                  // responses only: body ends at EOF, connection not reusable
}

/// Shared helpers for both heads. Names compare ASCII case-insensitively; order and duplicates are always preserved.
protocol HTTPHead {
    var rawStartLine: String { get set }
    var headers: HTTPHeaderList { get set }
    var rawBytes: Data { get }
    var versionMinor: Int { get }
}

extension HTTPHead {
    func values(for name: String) -> [String] {
        let key = name.lowercased()
        return headers.filter { $0.name.lowercased() == key }.map { $0.value }
    }

    func value(for name: String) -> String? { values(for: name).first }

    func contains(_ name: String) -> Bool {
        let key = name.lowercased()
        return headers.contains { $0.name.lowercased() == key }
    }

    /// Comma-separated tokens across every field of `name`, lowercased, empties dropped (e.g. Connection, TE).
    func tokens(for name: String) -> [String] {
        values(for: name).flatMap { $0.split(separator: ",") }
            .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " \t")).lowercased() }
            .filter { !$0.isEmpty }
    }

    /// Replace all fields of `name` with one, at the first occurrence's position (the old core `Header.Set`).
    mutating func setHeader(_ name: String, _ value: String) {
        let key = name.lowercased()
        if let idx = headers.firstIndex(where: { $0.name.lowercased() == key }) {
            headers.removeAll { $0.name.lowercased() == key }
            headers.insert((name, value), at: idx)
        } else {
            headers.append((name, value))
        }
    }

    mutating func addHeader(_ name: String, _ value: String) { headers.append((name, value)) }

    mutating func removeHeader(_ name: String) {
        let key = name.lowercased()
        headers.removeAll { $0.name.lowercased() == key }
    }

    /// HTTP/1.1: persistent unless `Connection: close`; HTTP/1.0: only with `Connection: keep-alive`.
    var wantsKeepAlive: Bool {
        let conn = tokens(for: "Connection")
        if versionMinor >= 1 { return !conn.contains("close") }
        return conn.contains("keep-alive") && !conn.contains("close")
    }
}

struct HTTPRequestHead: HTTPHead, Equatable {
    var rawStartLine: String { didSet { pristine = false } }
    var headers: HTTPHeaderList { didSet { pristine = false } }
    /// Exact bytes this head was parsed from (start line through the empty line). Empty for a constructed head.
    private(set) var rawBytes: Data
    private var pristine: Bool

    /// `method SP target SP HTTP/1.x`, as parsed from rawStartLine.
    var method: String { String(rawStartLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false).first ?? "") }
    var target: String {
        let p = rawStartLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        return p.count == 3 ? String(p[1]) : ""
    }
    var version: String { String(rawStartLine.split(separator: " ").last ?? "") }
    var versionMinor: Int { version == "HTTP/1.0" ? 0 : 1 }

    var isModified: Bool { !pristine }
    var expectsContinue: Bool { versionMinor >= 1 && (value(for: "Expect")?.lowercased() == "100-continue") }
    var isConnect: Bool { method == "CONNECT" }
    /// `Upgrade:` plus `Connection: upgrade` (RFC 9110 §7.8), or CONNECT.
    var requestsUpgrade: Bool { isConnect || (contains("Upgrade") && tokens(for: "Connection").contains("upgrade")) }

    init(method: String, target: String, version: String = "HTTP/1.1", headers: HTTPHeaderList) {
        rawStartLine = "\(method) \(target) \(version)"
        self.headers = headers
        rawBytes = Data()
        pristine = false
    }

    init(parsedStartLine: String, headers: HTTPHeaderList, rawBytes: Data) {
        rawStartLine = parsedStartLine
        self.headers = headers
        self.rawBytes = rawBytes
        pristine = true
    }

    mutating func setStartLine(method: String? = nil, target: String? = nil, version: String? = nil) {
        rawStartLine = "\(method ?? self.method) \(target ?? self.target) \(version ?? self.version)"
    }

    /// Wire bytes: the original rawBytes if untouched, else rebuilt as `Name: value` CRLF lines in list order.
    func serialized() throws -> Data {
        if pristine { return rawBytes }
        return try HTTPWire.build(startLine: rawStartLine, headers: headers)
    }

    static func == (a: Self, b: Self) -> Bool {
        a.rawStartLine == b.rawStartLine && a.rawBytes == b.rawBytes && HTTPWire.same(a.headers, b.headers)
    }
}

struct HTTPResponseHead: HTTPHead, Equatable {
    var rawStartLine: String { didSet { pristine = false } }
    var headers: HTTPHeaderList { didSet { pristine = false } }
    private(set) var rawBytes: Data
    private var pristine: Bool

    var version: String { String(rawStartLine.prefix { $0 != " " }) }
    var versionMinor: Int { version == "HTTP/1.0" ? 0 : 1 }
    var status: Int {
        let rest = rawStartLine.drop { $0 != " " }.dropFirst()
        return Int(rest.prefix(3)) ?? 0
    }
    var reason: String {
        let rest = rawStartLine.drop { $0 != " " }.dropFirst()
        return rest.count > 4 ? String(rest.dropFirst(4)) : ""
    }
    var isModified: Bool { !pristine }
    /// 1xx other than 101: precedes the final response (100 Continue, 103 Early Hints).
    var isInterim: Bool { (100..<200).contains(status) && status != 101 }

    init(status: Int, reason: String, version: String = "HTTP/1.1", headers: HTTPHeaderList) {
        rawStartLine = reason.isEmpty ? "\(version) \(status)" : "\(version) \(status) \(reason)"
        self.headers = headers
        rawBytes = Data()
        pristine = false
    }

    init(parsedStartLine: String, headers: HTTPHeaderList, rawBytes: Data) {
        rawStartLine = parsedStartLine
        self.headers = headers
        self.rawBytes = rawBytes
        pristine = true
    }

    func serialized() throws -> Data {
        if pristine { return rawBytes }
        return try HTTPWire.build(startLine: rawStartLine, headers: headers)
    }

    /// `HTTP/1.1 100 Continue` CRLF CRLF, for answering `Expect: 100-continue` locally.
    static let continueBytes = Data("HTTP/1.1 100 Continue\r\n\r\n".utf8)

    static func == (a: Self, b: Self) -> Bool {
        a.rawStartLine == b.rawStartLine && a.rawBytes == b.rawBytes && HTTPWire.same(a.headers, b.headers)
    }
}

/// Byte-level helpers shared by the parser and serializer.
enum HTTPWire {
    static func isTokenByte(_ b: UInt8) -> Bool {
        switch b {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"):
            return true
        default:
            return "!#$%&'*+-.^_`|~".utf8.contains(b)
        }
    }

    /// field-value bytes: VCHAR / obs-text / SP / HTAB (no other CTLs, no DEL).
    static func isValueByte(_ b: UInt8) -> Bool { b == 0x09 || (b >= 0x20 && b != 0x7F) }

    static func latin1(_ bytes: Data) -> String { String(bytes: bytes, encoding: .isoLatin1) ?? "" }

    /// Exact inverse of `latin1`; scalars above U+00FF (only possible in caller-built strings) fall back to UTF-8.
    static func bytes(_ s: String) -> Data {
        if let d = s.data(using: .isoLatin1) { return d }
        return Data(s.utf8)
    }

    static func same(_ a: HTTPHeaderList, _ b: HTTPHeaderList) -> Bool {
        a.count == b.count && zip(a, b).allSatisfy { $0.0.name == $0.1.name && $0.0.value == $0.1.value }
    }

    static func build(startLine: String, headers: HTTPHeaderList) throws -> Data {
        var d = Data()
        let sl = bytes(startLine)
        guard !sl.isEmpty, !sl.contains(where: { $0 == 0x0D || $0 == 0x0A || $0 == 0 }) else {
            throw HTTPParseError.invalidForSerialization
        }
        d.append(sl)
        d.append(0x0D); d.append(0x0A)
        try appendFields(headers, to: &d)
        d.append(0x0D); d.append(0x0A)
        return d
    }

    static func appendFields(_ headers: HTTPHeaderList, to d: inout Data) throws {
        for (name, value) in headers {
            let n = bytes(name), v = bytes(value)
            guard !n.isEmpty, n.allSatisfy(isTokenByte), v.allSatisfy(isValueByte) else {
                throw HTTPParseError.invalidForSerialization
            }
            d.append(n)
            d.append(contentsOf: [UInt8(ascii: ":"), UInt8(ascii: " ")])
            d.append(v)
            d.append(0x0D); d.append(0x0A)
        }
    }
}

/// Chunked transfer-coding output (re-framing a body whose length is unknown).
enum HTTPChunkedEncoder {
    static func chunk(_ payload: Data) -> Data {
        guard !payload.isEmpty else { return Data() }   // a zero-size chunk would terminate the body
        var d = Data(String(payload.count, radix: 16).utf8)
        d.append(0x0D); d.append(0x0A)
        d.append(payload)
        d.append(0x0D); d.append(0x0A)
        return d
    }

    static func lastChunk(trailers: HTTPHeaderList = []) throws -> Data {
        var d = Data("0\r\n".utf8)
        try HTTPWire.appendFields(trailers, to: &d)
        d.append(0x0D); d.append(0x0A)
        return d
    }
}
