import XCTest
@testable import Mihomo

/// fix/nc-e2e-gaps: /app/stats recorder (shape the App decodes), the probe listener spec / request parse, and the
/// plain-HTTP rewrite gate's literal-host extraction.
final class NativeCoreE2EGapsTests: XCTestCase {

    // MARK: NCStatsRecorder

    private func decodeStats(_ o: [String: Any]) throws -> TunnelStats {
        try JSONDecoder().decode(TunnelStats.self, from: JSONSerialization.data(withJSONObject: o))
    }

    func testStatsShapeDecodesAsTunnelStats() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        r.opened(rule: "DOMAIN-SUFFIX,example.com,Proxy", policy: "Proxy")
        r.opened(rule: "MATCH", policy: "DIRECT")
        r.bytesBatch([(policy: "Proxy", host: "a.example.com", up: 100, down: 1000),
                      (policy: "DIRECT", host: "b.test", up: 1, down: 2)])
        r.closed(.init(seq: 0, id: "42", network: "tcp", srcPort: 51000, dstIP: "198.18.0.4", dstPort: 443,
                       host: "a.example.com", remote: "a.example.com", chains: ["HK 01", "Proxy"],
                       rule: "DOMAIN-SUFFIX,example.com,Proxy", up: 100, down: 1000,
                       start: 1_700_000_000_000, closedAt: 1_700_000_002_000))
        let s = try decodeStats(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 600, ruleLimit: 300))
        XCTAssertEqual(s.totalConnections, 2)
        XCTAssertEqual(s.policies.first?.name, "Proxy", "busiest first")
        XCTAssertEqual(s.hosts.first?.name, "a.example.com")
        XCTAssertEqual(s.hostCount, 2)
        XCTAssertEqual(s.ruleCount, 2)
        XCTAssertTrue(s.full, "another session → the whole ring")
        XCTAssertEqual(s.closedSeq, 1)
        XCTAssertEqual(s.closed.count, 1)
        let c = s.closed[0].item
        XCTAssertEqual(c.id, "42")
        XCTAssertEqual(c.chains?.last, "Proxy")
        XCTAssertEqual(c.closedAt, Date(timeIntervalSince1970: 1_700_000_002))
        XCTAssertNotNil(c.startDate)
        XCTAssertEqual(c.metadata.destinationPort, "443")
    }

    func testClosedIsIncrementalAndRingBounded() throws {
        let r = NCStatsRecorder()
        func close(_ i: Int) {
            r.closed(.init(seq: 0, id: "\(i)", network: "tcp", srcPort: 1, dstIP: "1.1.1.1", dstPort: 80, host: "h\(i).test",
                           remote: "h\(i).test", chains: ["DIRECT"], rule: "MATCH", up: 1, down: 1, start: 1, closedAt: 2))
        }
        for i in 1...5 { close(i) }
        let first = try decodeStats(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0))
        close(6)
        let next = try decodeStats(r.statsJSON(session: first.session, closedAfter: first.closedSeq, hostLimit: 0, ruleLimit: 0))
        XCTAssertFalse(next.full)
        XCTAssertEqual(next.closed.map(\.seq), [6])
        for i in 7...(NCStatsRecorder.closedCap + 50) { close(i) }
        let all = try decodeStats(r.statsJSON(session: first.session, closedAfter: 2, hostLimit: 0, ruleLimit: 0))
        XCTAssertTrue(all.full, "asked seq left the ring")
        XCTAssertEqual(all.closed.count, NCStatsRecorder.closedCap)
        XCTAssertEqual(all.closed.first?.seq, Int64(NCStatsRecorder.closedCap + 50), "newest first")
    }

    func testHostAndRuleCapsHold() throws {
        let r = NCStatsRecorder()
        for i in 0..<(NCStatsRecorder.hostCap + 200) {
            r.bytes(policy: "P\(i % 3)", host: "h\(i).example.com", up: 1, down: 1)
            r.opened(rule: "DOMAIN,h\(i).example.com,P", policy: "P")
        }
        let s = try decodeStats(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0))
        XCTAssertLessThanOrEqual(s.hostCount, NCStatsRecorder.hostCap)
        XCTAssertLessThanOrEqual(s.ruleCount, NCStatsRecorder.ruleCap)
        XCTAssertEqual(s.policies.count, 3)
        XCTAssertEqual(s.totalConnections, NCStatsRecorder.hostCap + 200)
    }

    func testResetKeepsSpeedNewSession() throws {
        let r = NCStatsRecorder()
        r.opened(rule: "MATCH", policy: "DIRECT")
        r.speed(t: 1_700_000_000, up: 1, down: 2, pUp: 0, pDown: 0)
        let before = try decodeStats(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0))
        r.reset()
        let after = try decodeStats(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0))
        XCTAssertNotEqual(before.session, after.session)
        XCTAssertEqual(after.totalConnections, 0)
        let h = try JSONDecoder().decode(TunnelSpeedHistory.self,
                                         from: JSONSerialization.data(withJSONObject: r.speedJSON(lastSeconds: 0, buckets: true)))
        XCTAssertEqual(h.seconds.count, 1)
    }

    func testSpeedSamplesAndBuckets() throws {
        let r = NCStatsRecorder()
        let t0 = Date(timeIntervalSince1970: 1_700_000_040) // minute boundary at …020 / …080
        r.sample(now: t0, up: 0, down: 0, proxyUp: 0, proxyDown: 0) // baseline only
        r.sample(now: t0.addingTimeInterval(1), up: 100, down: 1000, proxyUp: 50, proxyDown: 500)
        r.sample(now: t0.addingTimeInterval(2), up: 300, down: 3000, proxyUp: 50, proxyDown: 500)
        r.sample(now: t0.addingTimeInterval(3), up: 10, down: 10, proxyUp: 0, proxyDown: 0) // totals reset: new baseline
        r.sample(now: t0.addingTimeInterval(5), up: 30, down: 50, proxyUp: 0, proxyDown: 0) // 2 s → per-second rate
        let h = try JSONDecoder().decode(TunnelSpeedHistory.self,
                                         from: JSONSerialization.data(withJSONObject: r.speedJSON(lastSeconds: 0, buckets: true)))
        XCTAssertEqual(h.seconds.map { $0[1] }, [100, 200, 10])
        XCTAssertEqual(h.seconds.last?[2], 20)
        XCTAssertEqual(h.seconds[1][3], 0)
        XCTAssertEqual(h.at, 1_700_000_045)
        XCTAssertEqual(h.minutes.count, 1)
        XCTAssertEqual(h.minutes[0][5], 3, "n points in the minute bucket")
        XCTAssertEqual(h.minutes[0][1], 310)
        XCTAssertEqual(h.hours.count, 1)
        let last2 = try JSONDecoder().decode(TunnelSpeedHistory.self,
                                             from: JSONSerialization.data(withJSONObject: r.speedJSON(lastSeconds: 2, buckets: false)))
        XCTAssertEqual(last2.seconds.count, 2)
        XCTAssertTrue(last2.minutes.isEmpty)
    }

    func testSecondsRingBounded() {
        let r = NCStatsRecorder()
        for i in 0..<(NCStatsRecorder.secCap + 30) { r.speed(t: Int64(1_700_000_000 + i), up: 1, down: 1, pUp: 0, pDown: 0) }
        let o = r.speedJSON(lastSeconds: 0, buckets: true)
        XCTAssertEqual((o["seconds"] as? [[Int64]])?.count, NCStatsRecorder.secCap)
        XCTAssertEqual((o["seconds"] as? [[Int64]])?.first?.first, Int64(1_700_000_030))
    }

    // MARK: probe listener (节点探测 127.0.0.1:7899 → MIHOMO-PROBE)

    func testProbeListenerSpecs() {
        let raw: [String: NCJSONValue] = ["listeners": .array([
            .object(["name": .string("mihomo-ios-probe"), "type": .string("mixed"), "listen": .string("127.0.0.1"),
                     "port": .number(7899), "udp": .bool(false), "proxy": .string("MIHOMO-PROBE")]),
            .object(["name": .string("lan"), "type": .string("mixed"), "listen": .string("0.0.0.0"), "port": .number(7000),
                     "proxy": .string("X")]),
            .object(["name": .string("noproxy"), "type": .string("mixed"), "port": .number(7001)]),
            .object(["name": .string("tun"), "type": .string("tun"), "proxy": .string("X"), "port": .number(7002)]),
        ])]
        XCTAssertEqual(NCProbeListener.specs(raw), [.init(name: "mihomo-ios-probe", port: 7899, policy: "MIHOMO-PROBE")])
        XCTAssertEqual(NCProbeListener.specs(nil), [])
    }

    private func parse(_ s: String) -> (host: String, port: Int, upstream: Data, connect: Bool)? {
        let d = Data(s.utf8)
        guard let end = d.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        return NCProbeListener.parse(head: d, headEnd: end)
    }

    func testProbeParseConnect() throws {
        let r = try XCTUnwrap(parse("CONNECT api.ip.sb:443 HTTP/1.1\r\nHost: api.ip.sb:443\r\n\r\n\u{16}\u{03}"))
        XCTAssertEqual(r.host, "api.ip.sb")
        XCTAssertEqual(r.port, 443)
        XCTAssertTrue(r.connect)
        XCTAssertEqual(r.upstream, Data([0x16, 0x03]), "bytes after the head go upstream")
        XCTAssertEqual(parse("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n")?.host, "2001:db8::1")
        XCTAssertNil(parse("CONNECT nohostport HTTP/1.1 extra\r\n\r\n"))
    }

    func testProbeParseAbsoluteHTTP() throws {
        let r = try XCTUnwrap(parse("GET http://ip-api.com/json?lang=zh HTTP/1.1\r\nHost: ip-api.com\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n"))
        XCTAssertEqual(r.host, "ip-api.com")
        XCTAssertEqual(r.port, 80)
        XCTAssertFalse(r.connect)
        let text = String(decoding: r.upstream, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("GET /json?lang=zh HTTP/1.1\r\n"))
        XCTAssertFalse(text.lowercased().contains("proxy-connection"))
        XCTAssertTrue(text.hasSuffix("Connection: close\r\n\r\n"))
        XCTAssertNil(parse("GET /relative HTTP/1.1\r\nHost: x\r\n\r\n"), "origin-form is not a proxy request")
    }

    // MARK: plain-HTTP rewrite gate

    func testHTTPLiteralHost() {
        XCTAssertEqual(NativeRewriteEngine.httpLiteralHost(#"^http://ads\.example\.com/x"#), "ads.example.com")
        XCTAssertEqual(NativeRewriteEngine.httpLiteralHost(#"^http:\/\/api\.example\.com\/v1"#), "api.example.com")
        XCTAssertEqual(NativeRewriteEngine.httpLiteralHost(#"^https?://Img.Example.com:8080/a"#), "img.example.com")
        XCTAssertEqual(NativeRewriteEngine.httpLiteralHost(#"^http(s)?:\/\/m\.test\.cn$"#), "m.test.cn")
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"^https://only\.tls\.com/"#))
        XCTAssertEqual(NativeRewriteEngine.httpLiteralHost(#"^http://api.example.com/v2"#), "api.example.com")
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"^http://.*\.example\.com/"#))
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"^http://a.+\.example\.com/"#))
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"^http://(a|b)\.example\.com/"#))
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"^http://ad\d\.example\.com/"#))
        XCTAssertNil(NativeRewriteEngine.httpLiteralHost(#"example\.com/ad"#))
    }

    func testAcceptedConnectionDefaultsToTLS() {
        final class Null: ByteStream {
            func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) { completion(nil, true, nil) }
            func write(_ data: Data, completion: @escaping (Error?) -> Void) { completion(nil) }
            func closeWrite() {}
            func close() {}
        }
        XCTAssertTrue(MitmAcceptedConnection(stream: Null(), host: "a", port: 443, alpn: nil, connID: 1).tls)
        XCTAssertFalse(MitmAcceptedConnection(stream: Null(), host: "", port: 80, alpn: nil, connID: 2, tls: false).tls)
    }
}
