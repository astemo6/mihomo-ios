import Network
import Security
import XCTest
@testable import Mihomo

/// fix/nc-mitm-live (build 404 device: 「重写脚本一个都用不了」, 脚本日志 empty, stale fake-ip dropped): the TUN MitM
/// decision (NCMitmGate, independent of the sniffer), the host list matching it consults (wildcards, exclusions,
/// QX %APPEND%, explicit ports), a real ClientHello handed through a relay into the native front (what NCDataPlane
/// does), the shared diagnostics limiter, script-log folding and fake-ip persistence.
final class NativeCoreMitmLiveTests: XCTestCase {

    // MARK: helpers

    private func u16(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }

    /// A minimal but well-formed TLS 1.2/1.3 ClientHello record.
    private func clientHello(sni: String?, alpn: [String]) -> Data {
        var ext = Data()
        if let sni {
            let n = Data(sni.utf8)
            var list = Data([0x00]) + u16(n.count) + n
            list = u16(list.count) + list
            ext += u16(0x0000) + u16(list.count) + list
        }
        if !alpn.isEmpty {
            var list = Data()
            for a in alpn { list.append(UInt8(a.utf8.count)); list += Data(a.utf8) }
            let body = u16(list.count) + list
            ext += u16(0x0010) + u16(body.count) + body
        }
        var hs = Data([0x03, 0x03]) + Data(repeating: 7, count: 32)
        hs += Data([0x00])                       // session id
        hs += u16(2) + Data([0x13, 0x01])        // cipher suites
        hs += Data([0x01, 0x00])                 // compression
        hs += u16(ext.count) + ext
        let msg = Data([0x01, UInt8((hs.count >> 16) & 0xff), UInt8((hs.count >> 8) & 0xff), UInt8(hs.count & 0xff)]) + hs
        return Data([0x16, 0x03, 0x01]) + u16(msg.count) + msg
    }

    private func snapshot() -> RWSnapshot {
        let json = """
        {"version":1,"gen":7,"on":true,"capture":false,"rules":[],
         "inc":[{"pat":"%APPEND% api.example.com"},{"pat":"*.example.org"},{"pat":"svc.example.net","port":8443},{"pat":"10.0.0.9"}],
         "exc":[{"pat":"skip.example.org"}]}
        """
        return RWSnapshot.decode(json)!
    }

    private func fixtures() throws -> [String: String] {
        let bundle = Bundle(for: NativeCoreMitmLiveTests.self)
        let url = try XCTUnwrap(bundle.url(forResource: "NativeMitmTLSFixtures", withExtension: "json"),
                                "NativeMitmTLSFixtures.json missing from the test bundle")
        return try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
    }

    // MARK: host list

    func testInterceptsWildcardsExclusionsAppendAndPorts() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        XCTAssertTrue(e.hasMitmHosts)
        XCTAssertEqual(e.mitmHostCount, 4)
        XCTAssertTrue(e.intercepts(host: "api.example.com", port: 443), "%APPEND% prefix must be stripped")
        XCTAssertTrue(e.intercepts(host: "API.Example.COM.", port: 443))
        XCTAssertTrue(e.intercepts(host: "a.b.example.org", port: 443))
        XCTAssertFalse(e.intercepts(host: "example.org", port: 443))
        XCTAssertFalse(e.intercepts(host: "skip.example.org", port: 443), "-exclusion wins")
        XCTAssertFalse(e.intercepts(host: "svc.example.net", port: 443))
        XCTAssertTrue(e.intercepts(host: "svc.example.net", port: 8443))
        XCTAssertFalse(e.intercepts(host: "api.example.com", port: 80))
        XCTAssertEqual(e.mitmPorts, [443, 8443])
    }

    // MARK: gate

    func testShouldPeekIgnoresSnifferAndUsesKnownDomain() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        let isMitm: (String, Int) -> Bool = { e.intercepts(host: $0, port: $1) }
        // redir-host / fake-ip domain known: the list decides (this is what never happened before the fix)
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: "api.example.com", port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: "www.apple.com", port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        // bare IP / unmapped fake-ip: the SNI decides on MitM ports only
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: nil, port: 443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: nil, port: 8443, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: nil, port: 5222, mitmActive: true, mitmPorts: e.mitmPorts, isMitm: isMitm))
        XCTAssertFalse(NCMitmGate.shouldPeek(knownDomain: "api.example.com", port: 443, mitmActive: false, mitmPorts: e.mitmPorts, isMitm: isMitm))
    }

    func testVerdictsOnClientHello() {
        let e = NativeRewriteEngine(snapshot: snapshot())
        let isMitm: (String, Int) -> Bool = { e.intercepts(host: $0, port: $1) }
        let hello = clientHello(sni: "api.example.com", alpn: ["h2", "http/1.1"])
        XCTAssertEqual(NCMitmGate.decide(firstBytes: hello, knownDomain: nil, dstIP: "1.2.3.4", port: 443, isMitm: isMitm),
                       .mitm(host: "api.example.com", alpn: ["h2", "http/1.1"]))
        // split over segments: wait for the rest at every cut
        for cut in [1, 4, 5, 20, hello.count - 1] {
            XCTAssertEqual(NCMitmGate.decide(firstBytes: hello.prefix(cut), knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm), .needMore, "cut \(cut)")
        }
        XCTAssertEqual(NCMitmGate.decide(firstBytes: Data("GET / HTTP/1.1\r\n".utf8), knownDomain: "api.example.com", dstIP: nil, port: 443, isMitm: isMitm),
                       .passthrough(reason: "not TLS"))
        // SNI is authoritative: a DNS-derived domain in the list does not MitM a different SNI (shared CDN IPs)
        let other = clientHello(sni: "www.apple.com", alpn: [])
        if case .passthrough(let why) = NCMitmGate.decide(firstBytes: other, knownDomain: "api.example.com", dstIP: nil, port: 443, isMitm: isMitm) {
            XCTAssertTrue(why.contains("www.apple.com"))
        } else { XCTFail("expected passthrough") }
        // no SNI: known domain, then the IP literal
        let bare = clientHello(sni: nil, alpn: ["http/1.1"])
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: "x.example.org", dstIP: "5.6.7.8", port: 443, isMitm: isMitm),
                       .mitm(host: "x.example.org", alpn: ["http/1.1"]))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: nil, dstIP: "10.0.0.9", port: 443, isMitm: isMitm),
                       .mitm(host: "10.0.0.9", alpn: ["http/1.1"]))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: bare, knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm),
                       .passthrough(reason: "no SNI"))
        // a first record that claims more than the cap and never completes
        var huge = Data([0x16, 0x03, 0x01, 0xff, 0xff])
        huge += Data(repeating: 0, count: NCMitmGate.maxHelloBytes)
        if case .passthrough = NCMitmGate.decide(firstBytes: huge, knownDomain: nil, dstIP: nil, port: 443, isMitm: isMitm) {} else {
            XCTFail("oversized first record must pass through")
        }
    }

    /// The data plane's handoff with a real client: the relay buffers the client's actual ClientHello until the gate
    /// decides, opens the native front for the SNI and replays the bytes; the client's TLS handshake completes with
    /// the leaf for that host and data flows both ways.
    func testRealClientHelloHandedThroughRelayIntoFront() throws {
        let fx = try fixtures()
        let engine = NativeRewriteEngine(snapshot: snapshot())
        let front = MitmTLSFront(identities: LeafIdentityCache { fx[$0].flatMap { Data(base64Encoded: $0) } })
        let accepted = expectation(description: "front accepted")
        var server: TLSByteStream?
        front.onAccept = { s in
            server = s
            s.read(min: 1, max: 1024) { data, _, _ in
                s.write(Data("echo:".utf8) + (data ?? Data())) { _ in }
            }
            accepted.fulfill()
        }
        defer { front.reset() }

        let q = DispatchQueue(label: "mitm-live.relay")
        let relay = NCLoopbackListener(queue: q)
        XCTAssertNil(relay.start(port: 0))
        defer { relay.stop() }
        var verdict: NCMitmGate.Verdict?
        var keep: [AnyObject] = []
        relay.onAccept = { conn in
            keep.append(conn)
            var buf = Data()
            func toFront(_ up: NCStream) {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, _ in
                    if let data, !data.isEmpty { up.send(data) }
                    if !done { toFront(up) }
                }
            }
            func toClient(_ up: NCStream) {
                up.receive { data, _ in
                    guard let data else { conn.cancel(); return }
                    conn.send(content: data, completion: .idempotent)
                    toClient(up)
                }
            }
            func peek() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, _ in
                    if let data { buf.append(data) }
                    let v = NCMitmGate.decide(firstBytes: buf, knownDomain: nil, dstIP: "127.0.0.1", port: 443,
                                              isMitm: { engine.intercepts(host: $0, port: $1) })
                    if v == .needMore { peek(); return }
                    verdict = v
                    guard case .mitm(let host, let alpn) = v else { conn.cancel(); return }
                    let port = front.listen(host, alpn: alpn.joined(separator: ","))
                    guard port > 0 else { conn.cancel(); return }
                    let up = NCStream(to: "127.0.0.1", port: Int(port), queue: q)
                    keep.append(up)
                    up.start { err in
                        guard err == nil else { conn.cancel(); return }
                        up.send(buf)
                        toFront(up)
                        toClient(up)
                    }
                }
            }
            peek()
        }

        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, "api.example.com")
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_verify_block(sec, { _, _, done in done(true) }, .global()) // test CA is not trusted
        let client = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: relay.port)!,
                                  using: NWParameters(tls: tls, tcp: .init()))
        let ready = expectation(description: "client TLS ready")
        client.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        client.start(queue: .global())
        wait(for: [ready, accepted], timeout: 15)
        q.sync {}
        XCTAssertEqual(verdict, .mitm(host: "api.example.com", alpn: ["http/1.1"]))
        XCTAssertEqual(server?.routingHost, "api.example.com")

        let echoed = expectation(description: "echo")
        client.send(content: Data("hi".utf8), completion: .contentProcessed { _ in })
        client.receive(minimumIncompleteLength: 7, maximumLength: 64) { data, _, _, _ in
            XCTAssertEqual(data.map { String(decoding: $0, as: UTF8.self) }, "echo:hi")
            echoed.fulfill()
        }
        wait(for: [echoed], timeout: 10)
        client.cancel()
        server?.close()
        _ = keep
    }

    // MARK: diagnostics

    func testDiagLimiterSharedWindowAndSuppressedLine() {
        var out: [(String, String)] = []
        let lim = NCDiagLimiter(sink: { out.append(($0, $1)) })
        let t0: UInt64 = 5_000_000_000
        var admitted = 0
        for i in 0..<25 where lim.line("[MITM] line \(i)", now: t0 + UInt64(i)) { admitted += 1 }
        XCTAssertEqual(admitted, NCDiagLimiter.perSecond)
        XCTAssertEqual(out.count, NCDiagLimiter.perSecond)
        XCTAssertTrue(lim.line("[SCRIPT] next window", now: t0 + 1_100_000_000))
        XCTAssertEqual(out.count, NCDiagLimiter.perSecond + 2)
        XCTAssertEqual(out[NCDiagLimiter.perSecond].0, "warning")
        XCTAssertTrue(out[NCDiagLimiter.perSecond].1.contains("5 line(s) suppressed"))
        XCTAssertEqual(out.last?.1, "[SCRIPT] next window")
    }

    func testScriptLogFoldsRepeatsAndKeepsLevels() {
        let ring = NativeLogRing.shared
        ring.clearScripts()
        for _ in 0..<3 { ring.addScript(script: "a.js", level: "error", msg: "boom") }
        ring.addScript(script: "a.js", level: "notify", msg: "title — body")
        ring.addScript(script: "Tern", level: "info", msg: "脚本引擎已加载")
        let lines = ring.scriptLines(since: 0)
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0].count, 3)
        XCTAssertEqual(lines[0].level, "error")
        XCTAssertEqual(lines[1].level, "notify")
        // a folded repeat gets a new id so `since` pollers see it
        let last = lines[2].id
        ring.addScript(script: "Tern", level: "info", msg: "脚本引擎已加载")
        let again = ring.scriptLines(since: last)
        XCTAssertEqual(again.count, 1)
        XCTAssertEqual(again[0].count, 2)
        ring.clearScripts()
    }

    // MARK: fake-ip persistence

    func testFakeIPMutationsCountAndPersistRoundTrip() throws {
        let pool = NCFakeIPPool()
        let m0 = pool.mutations
        let ip = pool.address(for: "app.example.com")
        XCTAssertEqual(pool.mutations, m0 + 1)
        _ = pool.address(for: "app.example.com") // existing mapping: no change to persist
        XCTAssertEqual(pool.mutations, m0 + 1)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("mitm-live-fakeip-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        pool.persist(to: url)
        let next = NCFakeIPPool()
        next.restore(data: try Data(contentsOf: url))
        XCTAssertEqual(next.host(for: ip), "app.example.com", "a restarted tunnel must still map the address apps cached")
        XCTAssertTrue(next.isFakeAddress(ip))
    }
}
