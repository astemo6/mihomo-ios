import Foundation
import Libmihomo
import Network
import Security
import XCTest
@testable import Mihomo

/// Native MitM stage 3 lane s3-h2, end to end on loopback against Go:
///   Go's HTTP/2 client → the Go engine's CONNECT front (bridge/nativeh2.go self-test engine, real rules) →
///   (a) Go path: Go terminates TLS and serves h2 itself, or
///   (b) native: Go hands the connection to MitmTLSFront (h2 listener) → NativeH2Session → the real flow API
///       (GoMitmFlowDriver) → Swift's upstream h2 / HTTP/1.1 client → Go's TLS origins (h2 and h1-only).
/// The same requests go both ways and the answers are compared (status, body bytes, trailers, the headers that
/// matter, what the origin saw).
final class NativeMitmH2LoopbackTests: XCTestCase {
    private struct Start: Decodable { var proxy: Int?; var h2: Int?; var h1: Int?; var error: String? }
    private struct Fetch: Decodable { var conns: Int?; var results: [Answer]?; var error: String? }
    private struct Answer: Decodable {
        var status: Int?; var proto: String?; var headers: [[String]]?; var body: String?
        var bodyLen: Int?; var bodySHA: String?; var trailers: [[String]]?; var error: String?
        func header(_ n: String) -> String? { headers?.first { $0.first == n }?.last }
    }

    private var front: MitmTLSFront?
    private var ports: Start?

    override func setUpWithError() throws {
        let st = try JSONDecoder().decode(Start.self, from: Data(LibmihomoMitmH2SelfTestStart("").utf8))
        if let e = st.error { throw XCTSkip("Go self-test unavailable: \(e)") }
        ports = st
    }

    override func tearDown() {
        LibmihomoSetNativeTLSFront(nil)
        LibmihomoMitmSetNativeH2(false)
        front?.reset()
        front = nil
        NativeH2Runtime.override = nil
        NativeH2Runtime.cancelAll()
        LibmihomoMitmH2SelfTestStop()
    }

    private func fetch(_ spec: [String: Any]) throws -> Fetch {
        let data = try JSONSerialization.data(withJSONObject: spec)
        let out = LibmihomoMitmH2SelfTestFetch(String(decoding: data, as: UTF8.self))
        let f = try JSONDecoder().decode(Fetch.self, from: Data(out.utf8))
        if let e = f.error { XCTFail("fetch: \(e)") }
        return f
    }

    /// Registers the Swift front with the self-test engine; h2 connections get NativeH2Session with the real Go
    /// flow driver, upstream straight to the self-test origins.
    private func installNative() throws {
        let p = try XCTUnwrap(ports)
        NativeH2Runtime.override = true
        NativeH2Runtime.resetBreaker()
        let f = MitmTLSFront(identities: LeafIdentityCache())
        let opener = LoopbackOriginOpener(ports: ["h2.test": p.h2 ?? 0, "h1.test": p.h1 ?? 0])
        f.onAccept = { s in
            let conn = MitmAcceptedConnection(stream: s, host: s.routingHost, port: 443, alpn: s.alpn, connID: NativeMitmRuntime.nextID())
            if s.alpn == "h2" {
                NativeH2Session(conn: conn, codec: HTTPLaneCodec(), opener: opener, driver: GoMitmFlowDriver(),
                                bodies: NativeBodyStore.shared)?.start()
            } else {
                s.close() // the test client always negotiates h2
            }
        }
        front = f
        LibmihomoMitmSetNativeH2(true)
        LibmihomoSetNativeTLSFront(f)
    }

    private func uninstallNative() {
        LibmihomoSetNativeTLSFront(nil)
        LibmihomoMitmSetNativeH2(false)
    }

    private static let requests: [[String: Any]] = [
        ["path": "/json"],
        ["path": "/r200"],                                         // reject-200 (local answer in Go)
        ["path": "/old/abc"],                                      // 302 redirect (local)
        ["path": "/echo", "method": "POST", "body": "abc", "repeat": 1000, "headers": [["X-Up", "1"]]], // header-add + request body
        ["path": "/json?rb"],                                      // response-body rewrite (need-body → read)
        ["path": "/json?jd"],                                      // response-body-json-del
        ["path": "/big?n=700000"],                                 // large body, flow control end to end
        ["path": "/trailers"],                                     // response trailers (gRPC style)
        ["path": "/stream?n=40"],                                  // flushed pieces, no Content-Length
        ["path": "/nocontent"],                                    // 204
        ["path": "/gzip"],                                         // Content-Encoding untouched
        ["host": "h1.test", "path": "/echo"],                      // HTTP/1.1-only origin behind native h2
        ["path": "/big?n=5000", "method": "HEAD"],
    ]

    private static let comparedHeaders = ["content-type", "content-encoding", "location", "x-added"]

    func testNativeH2MatchesGoPath() throws {
        let spec: [String: Any] = ["concurrent": true, "requests": Self.requests]
        uninstallNative()
        let goRun = try fetch(spec)
        let goOrigin = LibmihomoMitmH2SelfTestOriginRequests()

        let before = NativeH2Runtime.counters
        try installNative()
        let nativeRun = try fetch(spec)
        let nativeOrigin = LibmihomoMitmH2SelfTestOriginRequests() - goOrigin
        let after = NativeH2Runtime.counters

        // the native side really served it: sessions for both hosts, every stream through the flow API
        XCTAssertGreaterThanOrEqual(after.sessions - before.sessions, 2, "native h2 sessions")
        XCTAssertEqual(after.streams - before.streams, Self.requests.count, "native streams")
        XCTAssertGreaterThanOrEqual(after.upstreamH2 - before.upstreamH2, 1)
        XCTAssertGreaterThanOrEqual(after.upstreamH1 - before.upstreamH1, 1)
        XCTAssertEqual(nativeOrigin, goOrigin, "the origins saw a different number of requests")
        XCTAssertEqual(nativeRun.conns, goRun.conns, "client connections (one per host)")

        let a = try XCTUnwrap(goRun.results), b = try XCTUnwrap(nativeRun.results)
        XCTAssertEqual(a.count, b.count)
        for (i, (g, n)) in zip(a, b).enumerated() {
            let what = "\(i) \(Self.requests[i]["path"] ?? "")"
            XCTAssertNil(g.error, "go \(what)")
            XCTAssertNil(n.error, "native \(what)")
            XCTAssertEqual(n.proto, "HTTP/2.0", what)
            XCTAssertEqual(n.status, g.status, what)
            XCTAssertEqual(n.bodyLen, g.bodyLen, what)
            XCTAssertEqual(n.bodySHA, g.bodySHA, what)
            XCTAssertEqual(n.trailers ?? [], g.trailers ?? [], what)
            for h in Self.comparedHeaders { XCTAssertEqual(n.header(h), g.header(h), "\(what) \(h)") }
            let gh = Set((g.headers ?? []).map { $0.joined(separator: ": ") }), nh = Set((n.headers ?? []).map { $0.joined(separator: ": ") })
            if gh != nh { print("H2LOOPBACK header diff \(what): go-only \(gh.subtracting(nh).sorted()) native-only \(nh.subtracting(gh).sorted())") }
        }
        // spot checks that the rules actually ran on the native path
        XCTAssertTrue(b[3].body?.contains("x-added: hello") ?? false, b[3].body ?? "")
        XCTAssertTrue(b[3].body?.contains("\"bodyLen\":3000") ?? false, b[3].body ?? "")
        XCTAssertTrue(b[4].body?.contains("\"ad\":false") ?? false, b[4].body ?? "")
        XCTAssertFalse(b[5].body?.contains("\"ads\"") ?? true, b[5].body ?? "")
        XCTAssertEqual(b[2].status, 302)
        XCTAssertEqual(b[7].trailers?.count, 2)
        XCTAssertTrue(b[11].body?.contains("\"origin\":\"h1\"") ?? false, b[11].body ?? "")
        print("H2LOOPBACK counters \(after)")
    }

    /// Many concurrent streams on one client connection: one native session, one upstream h2 connection, the
    /// stream cap respected (the Go client queues beyond SETTINGS_MAX_CONCURRENT_STREAMS).
    func testNativeH2ConcurrentStreamsOneConnection() throws {
        try installNative()
        let before = NativeH2Runtime.counters
        var reqs: [[String: Any]] = []
        for i in 0..<40 { reqs.append(["path": i % 4 == 0 ? "/big?n=\(100_000 + i)" : "/echo?i=\(i)"]) }
        let run = try fetch(["concurrent": true, "requests": reqs])
        let after = NativeH2Runtime.counters
        XCTAssertEqual(run.conns, 1)
        XCTAssertEqual(after.sessions - before.sessions, 1)
        XCTAssertEqual(after.streams - before.streams, 40)
        XCTAssertEqual(after.upstreamH2 - before.upstreamH2, 40)
        for (i, r) in (run.results ?? []).enumerated() {
            XCTAssertNil(r.error, "\(i)")
            XCTAssertEqual(r.status, 200, "\(i)")
            if i % 4 == 0 { XCTAssertEqual(r.bodyLen, 100_000 + i, "\(i)") } else { XCTAssertTrue(r.body?.contains("/echo?i=\(i)") ?? false, "\(i)") }
        }
    }

    /// Switch off: Go never offers h2 to the native front; an h2-only client is served by Go.
    func testSwitchOffKeepsH2OnGoPath() throws {
        try installNative()
        NativeH2Runtime.override = false
        LibmihomoMitmSetNativeH2(false)
        let before = NativeH2Runtime.counters
        let run = try fetch(["protos": ["h2"], "requests": [["path": "/json"]]])
        XCTAssertEqual(run.results?.first?.status, 200)
        XCTAssertEqual(run.results?.first?.proto, "HTTP/2.0")
        XCTAssertEqual(NativeH2Runtime.counters.sessions, before.sessions)
    }
}

/// Upstream for the loopback test: straight to the self-test's TLS origins (their certificate is a test one, so
/// verification is skipped here; production goes through the Go relay with system trust).
final class LoopbackOriginOpener: H2UpstreamOpening {
    let ports: [String: Int]
    let queue = DispatchQueue(label: "h2.loopback.origin")
    init(ports: [String: Int]) { self.ports = ports }

    func open(host: String, port: Int, tls: Bool, offerH2: Bool, completion: @escaping (Swift.Result<H2UpstreamTransport, Error>) -> Void) {
        guard let p = ports[host], p > 0, let nwPort = NWEndpoint.Port(rawValue: UInt16(p)) else {
            return completion(.failure(S2Error.upstream("no origin for \(host)")))
        }
        let opts = NWProtocolTLS.Options()
        let sec = opts.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, host)
        if offerH2 { sec_protocol_options_add_tls_application_protocol(sec, "h2") }
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_verify_block(sec, { _, _, done in done(true) }, queue)
        let conn = NWConnection(host: "127.0.0.1", port: nwPort, using: NWParameters(tls: opts, tcp: NWProtocolTCP.Options()))
        var done = false
        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                guard !done else { return }
                done = true
                let alpn = TLSByteStream.handshakeInfo(conn).alpn
                let s = TLSByteStream(connection: conn, host: host, sni: host, alpn: alpn)
                completion(.success(H2UpstreamTransport(stream: s, alpn: alpn) { _ in s.close() }))
            case .failed(let e), .waiting(let e):
                guard !done else { return }
                done = true
                conn.cancel()
                completion(.failure(S2Error.upstream("\(e)")))
            default:
                break
            }
        }
        conn.start(queue: queue)
    }
}
