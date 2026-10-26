import XCTest
@testable import Mihomo

/// fix/nc-open-6-10: #6 rule-list trailing comments, #7 upstream DNS race (NCDNSRace), #9 script / UDP traffic in
/// NCStatsRecorder.
final class NativeCoreOpen610Tests: XCTestCase {

    // MARK: - #6 trailing comments in rule lists

    func testTrailingCommentStart() {
        func strip(_ s: String) -> String {
            guard let i = NCRuleSetIndex.trailingCommentStart(s) else { return s }
            return String(s[..<i]).trimmingCharacters(in: .whitespaces)
        }
        XCTAssertEqual(strip("IP-ASN,4134 // China Telecom"), "IP-ASN,4134")
        XCTAssertEqual(strip("IP-ASN,4134 // 中国电信"), "IP-ASN,4134")
        XCTAssertEqual(strip("DOMAIN-SUFFIX,example.com # note"), "DOMAIN-SUFFIX,example.com")
        XCTAssertEqual(strip("DOMAIN,a.example.com\t// tab"), "DOMAIN,a.example.com")
        XCTAssertEqual(strip("IP-CIDR,1.2.3.0/24,no-resolve  #x"), "IP-CIDR,1.2.3.0/24,no-resolve")
        // not comments: URLs and markers inside a token
        XCTAssertNil(NCRuleSetIndex.trailingCommentStart("https://example.com/path"))
        XCTAssertNil(NCRuleSetIndex.trailingCommentStart("URL-REGEX,^https?://a\\.com/x#y"))
        XCTAssertNil(NCRuleSetIndex.trailingCommentStart("DOMAIN-KEYWORD,c#sharp"))
        XCTAssertNil(NCRuleSetIndex.trailingCommentStart("IP-ASN,4134 / x"))
    }

    func testASNListWithInlineCommentsMatches() {
        // VirgilClyne ASN.China shape
        let body = """
        # ASN.China
        IP-ASN,4134 // China Telecom
        IP-ASN,4837 // 中国联通
        IP-ASN,9808 # China Mobile
        IP-ASN,AS56040
        DOMAIN-SUFFIX,example.cn // trailing
        """
        var idx = NCRuleSetIndex()
        XCTAssertTrue(idx.addData(Data(body.utf8), flavor: .classical))
        idx.finalize()
        XCTAssertEqual(idx.entryCount, 5)
        XCTAssertEqual(idx.asns, [4134, 4837, 9808, 56040])
        XCTAssertTrue(idx.needsIP)
        var c = NCMatchContext(); c.ip = NCIP("36.110.1.1")
        for asn in [4134, 4837, 9808, 56040] {
            c.asnOf = { _ in asn }
            XCTAssertTrue(idx.contains(c), "AS\(asn)")
        }
        c.asnOf = { _ in 13335 }
        XCTAssertFalse(idx.contains(c))
        var d = NCMatchContext(); d.domain = "www.example.cn"
        XCTAssertTrue(idx.contains(d))
    }

    func testDomainSetURLLineKeepsHost() {
        var idx = NCRuleSetIndex()
        idx.addText("https://ads.example.com/banner\n.tracker.example # c\n", flavor: .domainSet)
        idx.finalize()
        var c = NCMatchContext(); c.domain = "ads.example.com"
        XCTAssertTrue(idx.contains(c))
        c.domain = "x.tracker.example"
        XCTAssertTrue(idx.contains(c))
    }

    // MARK: - #7 NCDNSRace

    private static func answer(rcode: UInt8 = 0, tag: UInt8 = 0) -> Data {
        var d = Data(count: 12)
        d[0] = tag
        d[2] = 0x81
        d[3] = 0x80 | rcode
        return d
    }

    private let servers: [NCDNSUpstream] = [.udp(host: "13.78.100.57", port: 53), .udp(host: "119.29.29.29", port: 53),
                                            .doh(url: "https://doh.pub/dns-query")]

    /// Fake upstreams: per server index an optional (delay, response); nil delay = never answers.
    private final class Fake {
        let lock = NSLock()
        var calls: [Int] = []
        let behaviour: [Int: (TimeInterval?, Data?)]
        let servers: [NCDNSUpstream]
        init(_ servers: [NCDNSUpstream], _ b: [Int: (TimeInterval?, Data?)]) { self.servers = servers; behaviour = b }
        func exchange(_ u: NCDNSUpstream, _ done: @escaping (Data?) -> Void) {
            let i = servers.firstIndex(of: u)!
            lock.lock(); calls.append(i); lock.unlock()
            guard let b = behaviour[i], let delay = b.0 else { return }
            let resp = b.1
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) { done(resp) }
        }
        var callList: [Int] { lock.lock(); defer { lock.unlock() }; return calls }
    }

    private func race(_ fake: Fake, start: Int = 0, list: [NCDNSUpstream]? = nil, attemptTimeout: TimeInterval = 2.5,
                      overall: TimeInterval = 5, trace: NCDNSAttemptTrace? = nil) -> (Data?, Int?, TimeInterval) {
        let q = DispatchQueue(label: "race.test")
        let exp = expectation(description: "race")
        var out: (Data?, Int?) = (nil, nil)
        var fired = 0
        let t0 = Date()
        NCDNSRace.run(list: list ?? servers, start: start, queue: q, trace: trace, stagger: 0.3,
                      attemptTimeout: attemptTimeout, overallTimeout: overall,
                      exchange: { u, done in fake.exchange(u, done) },
                      completion: { r, w in out = (r, w); fired += 1; exp.fulfill() })
        wait(for: [exp], timeout: overall + 2)
        let dt = Date().timeIntervalSince(t0)
        // completion fires exactly once, even when late answers arrive afterwards
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(fired, 1)
        return (out.0, out.1, dt)
    }

    func testFastFirstServerSendsOnePacket() {
        let fake = Fake(servers, [0: (0.05, Self.answer(tag: 1)), 1: (0.01, Self.answer(tag: 2))])
        let (r, w, dt) = race(fake)
        XCTAssertEqual(r?.first, 1)
        XCTAssertEqual(w, 0)
        XCTAssertLessThan(dt, 0.3)
        Thread.sleep(forTimeInterval: 0.35)
        XCTAssertEqual(fake.callList, [0], "an answer inside the stagger window never asks the second server")
    }

    func testSlowFirstServerLosesToSecondAfterStagger() {
        // build433: 13.78.100.57 never answered in time; the old sequential failover waited 2.5 s per query.
        let fake = Fake(servers, [0: (nil, nil), 1: (0.05, Self.answer(tag: 2))])
        let (r, w, dt) = race(fake)
        XCTAssertEqual(r?.first, 2)
        XCTAssertEqual(w, 1)
        XCTAssertGreaterThanOrEqual(dt, 0.3)
        XCTAssertLessThan(dt, 1.0, "answered ~350 ms, not after the 2.5 s per-server timeout")
        XCTAssertEqual(Array(fake.callList.prefix(2)), [0, 1])
    }

    func testFailedFirstServerStartsNextImmediately() {
        let fake = Fake(servers, [0: (0.01, nil), 1: (0.02, Self.answer(tag: 2))])
        let (r, w, dt) = race(fake)
        XCTAssertEqual(r?.first, 2)
        XCTAssertEqual(w, 1)
        XCTAssertLessThan(dt, 0.25, "no stagger wait after a hard failure")
    }

    func testServfailIsLastResortNotWinner() {
        let fake = Fake(servers, [0: (0.01, Self.answer(rcode: 2, tag: 1)), 1: (0.05, Self.answer(tag: 2))])
        let (r, w, _) = race(fake)
        XCTAssertEqual(r?.first, 2, "SERVFAIL from one server must not beat a real answer")
        XCTAssertEqual(w, 1)
        // NXDOMAIN is a real answer and wins
        let nx = Fake(servers, [0: (0.01, Self.answer(rcode: 3, tag: 1)), 1: (0.05, Self.answer(tag: 2))])
        let (r2, w2, _) = race(nx)
        XCTAssertEqual(r2?.first, 1)
        XCTAssertEqual(w2, 0)
    }

    func testAllServfailDeliversLastResort() {
        let list = Array(servers.prefix(2))
        let fake = Fake(servers, [0: (0.01, Self.answer(rcode: 2, tag: 1)), 1: (0.02, Self.answer(rcode: 5, tag: 2))])
        let trace = NCDNSAttemptTrace()
        let (r, w, _) = race(fake, list: list, trace: trace)
        XCTAssertEqual(r?.first, 1)
        XCTAssertNil(w)
        XCTAssertTrue(trace.summary.contains("SERVFAIL"))
        XCTAssertTrue(trace.summary.contains("REFUSED"))
    }

    func testAllFailedTraceNamesEveryServer() {
        let fake = Fake(servers, [0: (nil, nil), 1: (0.01, nil), 2: (nil, nil)])
        let trace = NCDNSAttemptTrace()
        let (r, w, dt) = race(fake, attemptTimeout: 0.4, overall: 3, trace: trace)
        XCTAssertNil(r)
        XCTAssertNil(w)
        XCTAssertLessThan(dt, 1.5)
        XCTAssertEqual(Set(fake.callList), [0, 1, 2])
        let s = trace.summary
        XCTAssertTrue(s.contains("13.78.100.57 timeout"), s)
        XCTAssertTrue(s.contains("119.29.29.29 no answer"), s)
        XCTAssertTrue(s.contains("https://doh.pub/dns-query timeout"), s)
    }

    func testThirdServerAfterTwoTimeouts() {
        let fake = Fake(servers, [0: (nil, nil), 1: (nil, nil), 2: (0.02, Self.answer(tag: 3))])
        let (r, w, dt) = race(fake, attemptTimeout: 0.3, overall: 3)
        XCTAssertEqual(r?.first, 3)
        XCTAssertEqual(w, 2)
        XCTAssertLessThan(dt, 1.2)
    }

    func testStartIndexGoesFirst() {
        let fake = Fake(servers, [0: (0.01, Self.answer(tag: 1)), 1: (0.01, Self.answer(tag: 2))])
        let (r, w, _) = race(fake, start: 1, list: Array(servers.prefix(2)))
        XCTAssertEqual(r?.first, 2)
        XCTAssertEqual(w, 1)
        XCTAssertEqual(fake.callList.first, 1)
    }

    func testOverallTimeoutFires() {
        let fake = Fake(servers, [:])
        let trace = NCDNSAttemptTrace()
        let (r, _, dt) = race(fake, list: Array(servers.prefix(1)), attemptTimeout: 5, overall: 0.5, trace: trace)
        XCTAssertNil(r)
        XCTAssertLessThan(dt, 1.2)
        XCTAssertTrue(trace.summary.contains("gave up"))
    }

    func testUpstreamLabels() {
        XCTAssertEqual(NCDNSUpstream.udp(host: "1.1.1.1", port: 53).label, "1.1.1.1")
        XCTAssertEqual(NCDNSUpstream.udp(host: "1.1.1.1", port: 5353).label, "1.1.1.1:5353")
        XCTAssertEqual(NCDNSUpstream.dot(host: "dns.google", port: 853).label, "tls://dns.google")
        XCTAssertEqual(NCDNSUpstream.tcp(host: "8.8.8.8", port: 53).label, "tcp://8.8.8.8")
    }

    func testRcodeHelpers() {
        XCTAssertTrue(NCDNSRace.isUsable(Self.answer()))
        XCTAssertTrue(NCDNSRace.isUsable(Self.answer(rcode: 3)))
        XCTAssertFalse(NCDNSRace.isUsable(Self.answer(rcode: 2)))
        XCTAssertFalse(NCDNSRace.isUsable(Self.answer(rcode: 5)))
        XCTAssertFalse(NCDNSRace.isUsable(Data([0, 1, 2])))
    }
    // MARK: - #8 prepare: shared resource cache, failure memory, prefetch

    private func tempHome() -> String {
        let d = NSTemporaryDirectory() + "open610-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        return d
    }

    func testFailedDownloadIsNotRetried() {
        let home = tempHome()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let res = NCResources(home: home)
        res.fetchTimeout = 5
        let url = "https://tern-open610.invalid/script.js"
        XCTAssertThrowsError(try res.get(path: url))
        XCTAssertEqual(res.failedCount, 1)
        let t0 = Date()
        for _ in 0..<5 { XCTAssertThrowsError(try res.get(path: url)) }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 0.5, "same instance: the failed URL is not downloaded again")
        XCTAssertEqual(res.failedCount, 1)
        // another prepare (new instance) within the TTL skips it too, unless the failure was "offline"
        let res2 = NCResources(home: home)
        if FileManager.default.fileExists(atPath: (home as NSString).appendingPathComponent(NCResources.failureFile)) {
            XCTAssertThrowsError(try res2.get(path: url)) { e in
                XCTAssertEqual((e as NSError).code, -2)
            }
            XCTAssertEqual(res2.skippedRecentFailure, 1)
        }
        XCTAssertTrue(NativeRuntimePrepCache.isExcluded(relative: NCResources.failureFile),
                      "the failure memory must not invalidate the prepare cache")
    }

    func testPrefetchSkipsCachedAndDedupes() {
        let home = tempHome()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let cached = "https://example.invalid/cached.js"
        let cp = NCResources.cachePath(home: home, cached)
        try? FileManager.default.createDirectory(atPath: (cp as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: cp, contents: Data("1".utf8))
        let res = NCResources(home: home)
        res.fetchTimeout = 5
        let dead = "https://tern-open610-b.invalid/x.js"
        res.prefetch([cached, dead, dead, dead, "local.js"], maxConcurrent: 4, deadline: 8)
        XCTAssertEqual(res.fetchedCount + res.failedCount, 1, "one download for three references, none for the cached copy")
        XCTAssertEqual(try res.get(path: cached), Data("1".utf8))
    }

    func testRemoteResourcesCollectsScriptsAndBodies() {
        let rs = NCEngineRuleset()
        var a = NCEngineRule(); a.kind = "script"; var sa = NCEngineScript(); sa.path = "https://x.test/a.js"; a.script = sa
        var b = NCEngineRule(); b.kind = "script"; var sb = NCEngineScript(); sb.path = "local.js"; b.script = sb
        var c = NCEngineRule(); c.kind = "mock"; c.data = "https://x.test/body.json"
        var d = NCEngineRule(); d.kind = "mock"; d.data = "https://x.test/t.txt"; d.dataType = "text"
        var e = NCEngineRule(); e.kind = "script"; var se = NCEngineScript(); se.path = "https://x.test/inline.js"; se.source = Data("x".utf8); e.script = se
        rs.rules = [a, b, c, d, e]
        var t = NCEngineTask(); var st = NCEngineScript(); st.path = "https://x.test/task.js"; t.script = st
        rs.tasks = [t]
        XCTAssertEqual(NativeRuntimePrep.remoteResources(rs), ["https://x.test/a.js", "https://x.test/body.json", "https://x.test/task.js"])
    }
    // MARK: - #9 script / UDP traffic in /app/stats

    private func decode(_ o: [String: Any]) throws -> TunnelStats {
        try JSONDecoder().decode(TunnelStats.self, from: JSONSerialization.data(withJSONObject: o))
    }

    func testScriptRequestRecordedAsOneShot() throws {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        let t0 = Date(timeIntervalSince1970: 1_700_000_001)
        r.oneShot(idPrefix: "script", rule: "DOMAIN-SUFFIX,example.com,Proxy", policy: "Proxy", chain: "HK 01",
                  host: "api.example.com", dstPort: 443, up: 300, down: 4000, start: t0, end: t0.addingTimeInterval(1))
        r.oneShot(idPrefix: "script", rule: "", policy: "", chain: "", host: "sign.test", dstPort: 80,
                  up: 10, down: 20, start: t0, end: t0)
        let s = try decode(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 600, ruleLimit: 300))
        XCTAssertEqual(s.totalConnections, 2)
        XCTAssertEqual(s.hosts.first?.name, "api.example.com")
        XCTAssertEqual(s.hosts.first?.down, 4000)
        XCTAssertEqual(Set(s.policies.map(\.name)), ["Proxy", "DIRECT"])
        XCTAssertEqual(s.ruleCount, 2)
        XCTAssertEqual(s.closed.count, 2)
        let raw = r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
        let closed = raw["closed"] as? [[String: Any]] ?? []
        let ids = closed.compactMap { $0["id"] as? String }
        XCTAssertTrue(ids.allSatisfy { $0.hasPrefix("script-") }, "\(ids)")
        let chains = closed.last?["chains"] as? [String]
        XCTAssertEqual(chains, ["HK 01", "Proxy"])
    }

    func testOneShotBytesReachSpeedSeries() {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        let t = Date(timeIntervalSince1970: 1_700_000_100)
        r.sample(now: t, up: 1000, down: 1000, proxyUp: 0, proxyDown: 0)
        r.oneShot(idPrefix: "script", rule: "MATCH", policy: "Proxy", chain: "JP", host: "x.test", dstPort: 443,
                  up: 500, down: 5000, start: t)
        // the plane's own totals did not move; the script's bytes still show as rate
        r.sample(now: t.addingTimeInterval(1), up: 1000, down: 1000, proxyUp: 0, proxyDown: 0)
        let sp = r.speedJSON(lastSeconds: 0, buckets: false)
        let rows = sp["seconds"] as? [[Int64]] ?? []
        XCTAssertEqual(rows.last?[1], 500)
        XCTAssertEqual(rows.last?[2], 5000)
        XCTAssertEqual(rows.last?[3], 500, "proxied (chain JP)")
        XCTAssertEqual(rows.last?[4], 5000)
        // a plane reload (totals restart lower) must not produce a negative / bogus point from the side counters
        r.sample(now: t.addingTimeInterval(2), up: 10, down: 10, proxyUp: 0, proxyDown: 0)
        XCTAssertEqual((r.speedJSON(lastSeconds: 0, buckets: false)["seconds"] as? [[Int64]])?.count, rows.count)
    }

    func testUDPClosedRecordShape() throws {
        // the data plane writes UDP flows as network "udp" closed records (NCDataPlane.recordUDPClosed)
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        r.opened(rule: "GEOIP,CN,DIRECT", policy: "DIRECT")
        r.bytes(policy: "DIRECT", host: "stun.example.cn", up: 120, down: 240)
        r.closed(.init(seq: 0, id: "udp-7", network: "udp", srcPort: 53000, dstIP: "1.2.3.4", dstPort: 3478,
                       host: "stun.example.cn", remote: "stun.example.cn", chains: ["DIRECT"], rule: "GEOIP,CN,DIRECT",
                       up: 120, down: 240, start: 1_700_000_000_000, closedAt: 1_700_000_005_000))
        let s = try decode(r.statsJSON(session: 0, closedAfter: 0, hostLimit: 600, ruleLimit: 300))
        XCTAssertEqual(s.closed.count, 1)
        let raw = r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
        let md = ((raw["closed"] as? [[String: Any]])?.first?["metadata"]) as? [String: Any]
        XCTAssertEqual(md?["network"] as? String, "udp")
        XCTAssertEqual(s.hosts.first?.name, "stun.example.cn")
    }

    func testOneShotMemoryBounded() {
        let r = NCStatsRecorder(now: Date(timeIntervalSince1970: 1_700_000_000))
        let t = Date(timeIntervalSince1970: 1_700_000_001)
        for i in 0..<2000 {
            r.oneShot(idPrefix: "script", rule: "DOMAIN,h\(i).test,P", policy: "P", chain: "N", host: "h\(i).test",
                      dstPort: 443, up: 1, down: 1, start: t)
        }
        let raw = r.statsJSON(session: 0, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
        XCTAssertLessThanOrEqual((raw["closed"] as? [Any])?.count ?? 0, NCStatsRecorder.closedCap)
        XCTAssertLessThanOrEqual(raw["hostCount"] as? Int ?? 0, NCStatsRecorder.hostCap)
        XCTAssertLessThanOrEqual(raw["ruleCount"] as? Int ?? 0, NCStatsRecorder.ruleCap)
        XCTAssertEqual(raw["totalConnections"] as? Int, 2000)
    }
}
