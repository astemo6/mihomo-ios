// Native MitM STAGE 2 — shared contract between the four lanes (tls / http / upstream / wire).
// Owned by lane `wire` (feat/s2-wire). Other lanes code against these names; ask in work/native-s2-lanes.md
// before changing a signature. Design: work/native-mitm-design.md §4 (TLS front handoff) and §12 (flow API).
//
// Directory: PacketTunnel/NativeMitM/ (capital M — the existing dir; macOS checkouts are case-insensitive, so a
// second "NativeMitm" dir would silently merge into it). Lane subdirs: TLS/, HTTP/, Upstream/.
//
// Shape of one MitM connection (NativeMitmSession.swift):
//   Go engine (nativeterm.go) peeks ClientHello → MitmTLSFronting.listen(host, alpn) → loopback port
//   → TLS lane terminates TLS, hands a decrypted ByteStream to acceptHandler
//   → NativeMitmSession: HTTP lane parses heads/bodies, MitmFlowDriving asks Go for every decision
//     (rewrite / reject / redirect / map local / scripts / body lane all stay in Go), upstream lane carries bytes
//     to the origin through the Go relay (so rules/proxies stay in mihomo), bodies the Go side kept come from
//     NativeBodyStore (B1 lane).
// Credit: astemo6's draft origin/draft/native-mitm-b7b8 (6b53dc6) — HTTPMessage/Upstream/CertCache shapes.

import Foundation

// MARK: - Byte streams

/// Errors any lane may surface. `closed` = orderly EOF where data was still required.
enum S2Error: Error, Equatable {
    case closed
    case timeout(String)
    case cancelled
    case tooLarge(String)
    case protocolError(String)
    case unsupported(String)   // → the session falls back (before first byte) or cuts (after)
    case upstream(String)
    case go(String)
}

/// A bidirectional byte stream. NWConnection (plain), the TLS lane's decrypted client side and the upstream
/// lane's origin side all conform. Completion handlers may run on any queue; implementations must tolerate
/// close() racing an outstanding read/write (complete it with S2Error.cancelled, never twice).
protocol ByteStream: AnyObject {
    /// Delivers between `min` and `max` bytes, or fewer at EOF. `isEOF` true: the peer half-closed (no more data
    /// will follow; data may still be non-empty). error non-nil: the stream is dead.
    func read(min: Int, max: Int, completion: @escaping (_ data: Data?, _ isEOF: Bool, _ error: Error?) -> Void)
    /// Writes all of `data` (empty data is allowed and completes immediately).
    func write(_ data: Data, completion: @escaping (_ error: Error?) -> Void)
    /// Half-close: send FIN / close_notify after pending writes; reads keep working.
    func closeWrite()
    /// Tear down both directions now (idempotent).
    func close()
}

// MARK: - HTTP heads
// Canonical types are the http lane's (HTTP/HTTPMessage.swift): HTTPRequestHead / HTTPResponseHead (byte-faithful,
// rawBytes kept while unmodified), HTTPHeaderList = [(name, value)] (order and case preserved), HTTPBodyFraming
// (.none / .contentLength / .chunked / .untilClose). The helpers below are what the session needs on top.

func headerValue(_ h: HTTPHeaderList, _ name: String) -> String? {
    h.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
}
func headerPairs(_ h: HTTPHeaderList) -> [[String]] { h.map { [$0.name, $0.value] } }
func headerList(_ p: [[String]]) -> HTTPHeaderList { p.compactMap { $0.count == 2 ? ($0[0], $0[1]) : nil } }

extension HTTPRequestHead {
    var host: String? { value(for: "Host") }
    var contentLength: Int64? { value(for: "Content-Length").flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) } }
    var isChunked: Bool { tokens(for: "Transfer-Encoding").contains("chunked") }
    var isUpgrade: Bool { requestsUpgrade && !isConnect }
    var keepAlive: Bool { wantsKeepAlive }
}

extension HTTPResponseHead {
    var contentLength: Int64? { value(for: "Content-Length").flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) } }
    var isChunked: Bool { tokens(for: "Transfer-Encoding").contains("chunked") }
    var keepAlive: Bool { wantsKeepAlive }
}

/// Result of feeding wire bytes into a body decoder.
struct HTTPBodyChunk {
    var payload: Data     // de-framed body bytes (chunk sizes / trailers stripped)
    var consumed: Int     // wire bytes consumed from the input; the rest belongs to the next message
    var done: Bool        // body complete
}

/// Incremental de-framer for one body (http lane implements; one instance per body).
protocol HTTPBodyDecoding: AnyObject {
    func feed(_ wire: Data) throws -> HTTPBodyChunk
    /// The peer closed: finish a close-delimited body, or throw for a truncated one.
    func finishAtEOF() throws -> Data
}

/// The codec as the session uses it (HTTPLaneCodec wraps the http lane). Parsers return nil when more bytes are
/// needed and remove the consumed head bytes from `buffer`. Limits throw (HTTPParseError.headTooLarge etc).
protocol HTTPCodec {
    func parseRequestHead(_ buffer: inout Data) throws -> HTTPRequestHead?
    func parseResponseHead(_ buffer: inout Data) throws -> HTTPResponseHead?
    func requestFraming(_ head: HTTPRequestHead) -> HTTPBodyFraming
    func responseFraming(_ head: HTTPResponseHead, requestMethod: String) -> HTTPBodyFraming
    func makeDecoder(_ framing: HTTPBodyFraming) -> HTTPBodyDecoding
    func serialize(_ head: HTTPRequestHead) throws -> Data
    func serialize(_ head: HTTPResponseHead) throws -> Data
    func chunk(_ payload: Data) -> Data       // one chunk; empty payload is not allowed (use lastChunk)
    var lastChunk: Data { get }               // "0\r\n\r\n"
}

// MARK: - TLS lane

/// Connection facts the session needs from the TLS front.
struct MitmAcceptedConnection {
    let stream: ByteStream     // decrypted client side
    let host: String           // SNI / CONNECT host Go passed to listen()
    let port: Int              // origin port (443 unless the TLS lane learns otherwise)
    let alpn: String?          // negotiated ALPN (http/1.1 only in stage 2)
    let connID: Int64          // stable id for logs / Go flow heads
}

/// The TLS lane's front.
protocol MitmTLSFronting: AnyObject {
    /// Go → native: loopback port presenting a leaf for host, 0 declines (Go terminates TLS itself).
    func listen(host: String, alpn: String) -> Int64
    /// Set by the wire lane before registration; called once per decrypted client connection.
    var acceptHandler: ((MitmAcceptedConnection) -> Void)? { get set }
}

// MARK: - Upstream lane

/// One origin connection the session borrowed from the upstream lane.
protocol MitmUpstreamLease: AnyObject {
    var stream: ByteStream { get }
    /// Give it back: reusable true only after a complete, keep-alive response with nothing pending.
    func release(reusable: Bool)
}

/// The upstream lane: origin connections through the Go relay (loopback CONNECT → mihomo rules/proxies), TLS
/// to the origin with system trust, bounded reuse pool. Raw bytes only (no URLSession).
protocol MitmUpstreamConnecting: AnyObject {
    func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void)
}

// MARK: - Body lane (B1 NativeBodyStore)

/// The subset of NativeBodyStore a session reads (Go owns the handle; freed at MitmFlowEnd).
protocol NativeBodyReading: AnyObject {
    func len(_ h: Int64, raw: Bool) -> Int64
    func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data?
}

// MARK: - Go flow API (B6, bridge/nativeflow.go)

/// Body mode of a decision (bridge/mitm/flow.go "Body modes").
enum FlowBodyMode: String, Decodable {
    case none, client, upstream, read, lane
}

/// A decision from MitmFlowBegin / MitmFlowAwait / MitmFlowResponse (JSON flowDecision).
struct FlowDecision: Decodable, Equatable {
    enum Action: String, Decodable {
        case needBody = "need-body", forward, local, drop, busy, error, respond, upgrade
        case unknown
        init(from decoder: Decoder) throws {
            self = Action(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
        }
    }
    struct Lane: Decodable, Equatable { var handle: Int64; var raw: Bool }

    var id: Int64
    var action: Action
    var which: Int = 0
    var method: String?
    var url: String?
    var host: String?
    var status: Int?
    var headers: [[String]]?
    var body: FlowBodyMode?
    var length: Int64 = -1
    var lane: Lane?
    var note: String?

    var headerFields: HTTPHeaderList { headerList(headers ?? []) }

    static func decode(_ json: String) -> FlowDecision {
        if let d = try? JSONDecoder().decode(FlowDecision.self, from: Data(json.utf8)) { return d }
        return FlowDecision(id: 0, action: .error, note: "bad decision JSON")
    }

    enum CodingKeys: String, CodingKey { case id, action, which, method, url, host, status, headers, body, length, lane, note }
    init(id: Int64, action: Action, note: String? = nil) { self.id = id; self.action = action; self.note = note }
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        action = try c.decodeIfPresent(Action.self, forKey: .action) ?? .unknown
        which = try c.decodeIfPresent(Int.self, forKey: .which) ?? 0
        method = try c.decodeIfPresent(String.self, forKey: .method)
        url = try c.decodeIfPresent(String.self, forKey: .url)
        host = try c.decodeIfPresent(String.self, forKey: .host)
        status = try c.decodeIfPresent(Int.self, forKey: .status)
        headers = try c.decodeIfPresent([[String]].self, forKey: .headers)
        body = try c.decodeIfPresent(FlowBodyMode.self, forKey: .body)
        length = try c.decodeIfPresent(Int64.self, forKey: .length) ?? -1
        lane = try c.decodeIfPresent(Lane.self, forKey: .lane)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

enum FlowWriteResult: String { case taken = "", full, stop, gone }
enum FlowReadState: Equatable {
    case again, more, eof, failed(String)
    init(_ s: String) {
        switch s { case "": self = .again; case "more": self = .more; case "eof": self = .eof; default: self = .failed(s) }
    }
}
enum FlowBodyWhich: Int { case request = 0, response = 1 }

/// Facts about the client connection Go needs in each flow head.
struct MitmConnInfo {
    var host: String
    var port: Int
    var tls: Bool
    var connID: Int64
}

/// Wraps the B6 MitmFlow* gomobile API. All calls may block (never on the main thread); the session calls them
/// on its own serial queue. Production: GoMitmFlowDriver (NativeMitmSession.swift); tests: a fake.
protocol MitmFlowDriving: AnyObject {
    /// Request phase (MitmFlowBegin): need-body | forward | local | drop | busy | error.
    func requestPhase(head: HTTPRequestHead, conn: MitmConnInfo) -> FlowDecision
    /// After need-body + the body pushed (MitmFlowAwait).
    func await(_ id: Int64) -> FlowDecision
    /// Response phase (MitmFlowResponse): need-body | respond | upgrade | error.
    func responsePhase(_ id: Int64, head: HTTPResponseHead, length: Int64) -> FlowDecision
    func write(_ id: Int64, _ which: FlowBodyWhich, _ data: Data) -> FlowWriteResult
    func closeBody(_ id: Int64, _ which: FlowBodyWhich, error: String)
    func read(_ id: Int64, _ which: FlowBodyWhich, max: Int) -> Data
    func readState(_ id: Int64, _ which: FlowBodyWhich) -> FlowReadState
    func upstreamFailed(_ id: Int64, why: String)
    func end(_ id: Int64, sent: Int64, error: String)
    func cancel(_ id: Int64, why: String)
}
