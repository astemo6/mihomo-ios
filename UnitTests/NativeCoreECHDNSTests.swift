import XCTest
@testable import Mihomo

final class NativeCoreECHDNSTests: XCTestCase {

    private let testQueue = DispatchQueue(label: "nc.test.ech.dns")
    private let dummyUpstream = NCDNSUpstream.udp(host: "127.0.0.1", port: 53)

    private func mockResponse(for query: Data, answers: [NCDNSRecord], rcode: UInt16 = 0) -> Data {
        let qMsg = NCDNSMessage.parse(query)
        var resp = NCDNSMessage()
        resp.id = qMsg?.id ?? 1
        resp.isResponse = true
        resp.rcode = rcode
        resp.questions = qMsg?.questions ?? []
        resp.answers = answers
        return resp.serialized()
    }

    private func makeHTTPSRecord(name: String, ttl: UInt32, candidate: NCSVCCandidate) -> NCDNSRecord {
        NCDNSRecord(
            name: name,
            type: NCDNSMessage.typeHTTPS,
            klass: NCDNSMessage.classIN,
            ttl: ttl,
            rdata: candidate.serializedRData()
        )
    }

    // MARK: - 1. SVCB / SvcParams Parsing & Serialization

    func testSVCB_SvcParams_ParsingAndSerialization() {
        let rawECH = Data([0xfe, 0x0d, 0x00, 0x24, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        let candidate = NCSVCCandidate(
            priority: 1,
            targetName: ".",
            alpn: ["h2", "h3"],
            noDefaultALPN: true,
            port: 8443,
            ipv4Hints: [.v4(0x01020304), .v4(0x0a000001)],
            echConfigList: rawECH,
            ipv6Hints: [.v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])],
            mandatoryKeys: [1, 3, 5],
            rawParams: [:]
        )

        let rdata = candidate.serializedRData()
        XCTAssertGreaterThan(rdata.count, 0)

        guard let parsed = NCDNSRecord.parseSVCBRData(rdata) else {
            XCTFail("Failed to parse serialized SVCB RDATA")
            return
        }

        XCTAssertEqual(parsed.priority, 1)
        XCTAssertEqual(parsed.targetName, ".")
        XCTAssertEqual(parsed.effectiveTarget(for: "example.com"), "example.com")
        XCTAssertEqual(parsed.alpn, ["h2", "h3"])
        XCTAssertTrue(parsed.noDefaultALPN)
        XCTAssertEqual(parsed.port, 8443)
        XCTAssertEqual(parsed.ipv4Hints, [.v4(0x01020304), .v4(0x0a000001)])
        XCTAssertEqual(parsed.echConfigList, rawECH)
        XCTAssertEqual(parsed.ipv6Hints, [.v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])])
        XCTAssertEqual(parsed.mandatoryKeys, [1, 3, 5])
        XCTAssertFalse(parsed.isAliasMode)
    }

    func testSVCB_MalformedSvcParamsDefenses() {
        // AliasMode (priority 0) with targetName "." is invalid per RFC 9460 §2.4.1
        var aliasRoot = Data([0x00, 0x00, 0x00]) // priority 0, root target "."
        XCTAssertNil(NCDNSRecord.parseSVCBRData(aliasRoot))

        // AliasMode with trailing SvcParams is invalid per RFC 9460 §2.4.1
        var aliasWithParam = Data([0x00, 0x00, 0x04])
        aliasWithParam.append(contentsOf: "host".utf8)
        aliasWithParam.append(0x00) // target "host"
        aliasWithParam.append(contentsOf: [0x00, 0x03, 0x00, 0x02, 0x01, 0xbb]) // port 443
        XCTAssertNil(NCDNSRecord.parseSVCBRData(aliasWithParam))

        // Empty ech parameter (length 0) is invalid per RFC 9460 §7.5
        var emptyECH = Data([0x00, 0x01, 0x00]) // priority 1, target "."
        emptyECH.append(contentsOf: [0x00, 0x05, 0x00, 0x00]) // key 5 (ech), len 0
        XCTAssertNil(NCDNSRecord.parseSVCBRData(emptyECH))

        // Duplicate keys is invalid per RFC 9460 §2.1
        var dupKey = Data([0x00, 0x01, 0x00])
        dupKey.append(contentsOf: [0x00, 0x03, 0x00, 0x02, 0x01, 0xbb]) // port 443
        dupKey.append(contentsOf: [0x00, 0x03, 0x00, 0x02, 0x01, 0xbc]) // port 444
        XCTAssertNil(NCDNSRecord.parseSVCBRData(dupKey))

        // Mandatory contains key 0 is invalid per RFC 9460 §8
        var mandZero = Data([0x00, 0x01, 0x00])
        mandZero.append(contentsOf: [0x00, 0x00, 0x00, 0x02, 0x00, 0x00]) // mandatory = [0]
        XCTAssertNil(NCDNSRecord.parseSVCBRData(mandZero))

        // Mandatory keys not strictly ascending is invalid
        var mandDesc = Data([0x00, 0x01, 0x00])
        mandDesc.append(contentsOf: [0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x01]) // mandatory = [5, 1]
        XCTAssertNil(NCDNSRecord.parseSVCBRData(mandDesc))

        // Mandatory key listed but missing from params is invalid
        var mandMissing = Data([0x00, 0x01, 0x00])
        mandMissing.append(contentsOf: [0x00, 0x00, 0x00, 0x02, 0x00, 0x05]) // mandatory = [5], but key 5 omitted
        XCTAssertNil(NCDNSRecord.parseSVCBRData(mandMissing))
    }

    // MARK: - 2. Multi-Candidate Priority Sorting

    func testSVCB_CandidatePrioritySorting() {
        let echLow = Data([0xfe, 0x0d, 0x01])
        let echHigh = Data([0xfe, 0x0d, 0x02])

        let candHigh = NCSVCCandidate(priority: 10, targetName: ".", alpn: ["h2"], noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: echHigh, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let candLow = NCSVCCandidate(priority: 1, targetName: ".", alpn: ["h2"], noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: echLow, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let candAlias = NCSVCCandidate(priority: 0, targetName: "alias.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])

        var msg = NCDNSMessage()
        msg.answers = [
            makeHTTPSRecord(name: "example.com", ttl: 300, candidate: candHigh),
            makeHTTPSRecord(name: "example.com", ttl: 300, candidate: candAlias),
            makeHTTPSRecord(name: "example.com", ttl: 300, candidate: candLow),
        ]

        let answers = msg.svcbAnswers
        XCTAssertEqual(answers.count, 3)
        XCTAssertEqual(answers[0].priority, 0)
        XCTAssertEqual(answers[1].priority, 1)
        XCTAssertEqual(answers[2].priority, 10)

        // Resolver evaluates ServiceMode candidates in priority order (priority 1 picked first)
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { query, _, completion in
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: "sort.example.com", ttl: 300, candidate: candHigh),
                self.makeHTTPSRecord(name: "sort.example.com", ttl: 300, candidate: candLow),
            ]))
        }

        let exp = expectation(description: "pick priority 1")
        resolver.resolveECH(for: "sort.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success(let res):
                XCTAssertEqual(res.echConfigList, echLow)
            case .failure(let err):
                XCTFail("Unexpected failure: \(err)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)
    }

    // MARK: - 3. AliasMode Loop and Hop Limit Defenses

    func testAliasMode_DirectSelfLoopDefense() {
        let aliasSelf = NCSVCCandidate(priority: 0, targetName: "loop.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { query, _, completion in
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: "loop.example.com", ttl: 300, candidate: aliasSelf)
            ]))
        }

        let exp = expectation(description: "self loop detected")
        resolver.resolveECH(for: "loop.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Loop resolution should have failed")
            case .failure(let err):
                if case .aliasLoop(let chain) = err {
                    XCTAssertTrue(chain.contains("loop.example.com"))
                } else {
                    XCTFail("Expected .aliasLoop, got: \(err)")
                }
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)
    }

    func testAliasMode_MutualLoopDefense() {
        let aliasB = NCSVCCandidate(priority: 0, targetName: "b.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let aliasA = NCSVCCandidate(priority: 0, targetName: "a.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])

        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { query, _, completion in
            let qname = NCDNSMessage.parse(query)?.questions.first?.name.lowercased() ?? ""
            if qname.contains("a.example.com") {
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: "a.example.com", ttl: 300, candidate: aliasB)
                ]))
            } else {
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: "b.example.com", ttl: 300, candidate: aliasA)
                ]))
            }
        }

        let exp = expectation(description: "mutual loop detected")
        resolver.resolveECH(for: "a.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Mutual loop resolution should have failed")
            case .failure(let err):
                if case .aliasLoop(let chain) = err {
                    XCTAssertTrue(chain.contains("a.example.com"))
                    XCTAssertTrue(chain.contains("b.example.com"))
                } else {
                    XCTFail("Expected .aliasLoop, got: \(err)")
                }
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)
    }

    func testAliasMode_HopLimitDefense() {
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { query, _, completion in
            let qname = NCDNSMessage.parse(query)?.questions.first?.name.lowercased() ?? ""
            // chain: hop0 -> hop1 -> hop2 -> hop3 -> hop4 -> hop5 -> hop6
            if let idx = ["hop0", "hop1", "hop2", "hop3", "hop4", "hop5", "hop6"].firstIndex(where: { qname.hasPrefix($0) }) {
                let nextHop = "hop\(idx + 1).example.com"
                let alias = NCSVCCandidate(priority: 0, targetName: nextHop, alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: qname, ttl: 300, candidate: alias)
                ]))
            } else {
                completion(nil)
            }
        }

        let exp = expectation(description: "hop limit exceeded")
        resolver.resolveECH(for: "hop0.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Hop limit exceeded resolution should have failed")
            case .failure(let err):
                if case .aliasHopLimitExceeded(let chain) = err {
                    XCTAssertGreaterThanOrEqual(chain.count, 5)
                } else {
                    XCTFail("Expected .aliasHopLimitExceeded, got: \(err)")
                }
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)
    }

    // MARK: - 4. TTL Clamping [30s, 3600s]

    func testECHResolver_TTLClampingLowAndHigh() {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let echBytes = Data([0xfe, 0x0d, 0xaa, 0xbb])
        let cand = NCSVCCandidate(priority: 1, targetName: ".", alpn: ["h2"], noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: echBytes, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])

        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.now = { fixedNow }

        // Case A: TTL 5s (too low) -> clamped to 30s
        resolver.queryForwarder = { query, _, completion in
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: "low.example.com", ttl: 5, candidate: cand)
            ]))
        }
        let expLow = expectation(description: "ttl clamped to 30")
        resolver.resolveECH(for: "low.example.com", callerQueue: testQueue) { result in
            if case .success(let res) = result {
                XCTAssertEqual(res.ttl, 30)
                XCTAssertEqual(res.expires, fixedNow.addingTimeInterval(30))
            } else {
                XCTFail("Expected success")
            }
            expLow.fulfill()
        }
        wait(for: [expLow], timeout: 2)

        // Case B: TTL 86400s (too high) -> clamped to 3600s
        resolver.queryForwarder = { query, _, completion in
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: "high.example.com", ttl: 86400, candidate: cand)
            ]))
        }
        let expHigh = expectation(description: "ttl clamped to 3600")
        resolver.resolveECH(for: "high.example.com", callerQueue: testQueue) { result in
            if case .success(let res) = result {
                XCTAssertEqual(res.ttl, 3600)
                XCTAssertEqual(res.expires, fixedNow.addingTimeInterval(3600))
            } else {
                XCTFail("Expected success")
            }
            expHigh.fulfill()
        }
        wait(for: [expHigh], timeout: 2)

        // Case C: TTL 300s (within range) -> stays 300s
        resolver.queryForwarder = { query, _, completion in
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: "mid.example.com", ttl: 300, candidate: cand)
            ]))
        }
        let expMid = expectation(description: "ttl stays 300")
        resolver.resolveECH(for: "mid.example.com", callerQueue: testQueue) { result in
            if case .success(let res) = result {
                XCTAssertEqual(res.ttl, 300)
                XCTAssertEqual(res.expires, fixedNow.addingTimeInterval(300))
            } else {
                XCTFail("Expected success")
            }
            expMid.fulfill()
        }
        wait(for: [expMid], timeout: 2)
    }

    func testECHResolver_AliasTTLClampingTakesMinimum() {
        let fixedNow = Date(timeIntervalSince1970: 1_700_000_000)
        let echBytes = Data([0xfe, 0x0d, 0xaa, 0xbb])
        let candTarget = NCSVCCandidate(priority: 1, targetName: ".", alpn: ["h2"], noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: echBytes, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let candAlias = NCSVCCandidate(priority: 0, targetName: "target.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])

        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.now = { fixedNow }

        // Alias TTL 60s, Target TTL 1200s -> effective TTL = min(60, 1200) = 60s
        resolver.queryForwarder = { query, _, completion in
            let qname = NCDNSMessage.parse(query)?.questions.first?.name.lowercased() ?? ""
            if qname.contains("alias") {
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: "alias.example.com", ttl: 60, candidate: candAlias)
                ]))
            } else {
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: "target.example.com", ttl: 1200, candidate: candTarget)
                ]))
            }
        }

        let exp = expectation(description: "alias min TTL clamped")
        resolver.resolveECH(for: "alias.example.com", callerQueue: testQueue) { result in
            if case .success(let res) = result {
                XCTAssertEqual(res.ttl, 60)
                XCTAssertEqual(res.echConfigList, echBytes)
            } else {
                XCTFail("Expected success, got: \(result)")
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)
    }

    // MARK: - 5. Negative Cache vs. Query Failure

    func testECHResolver_NegativeCacheVsQueryFailure() {
        var queryCount = 0
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })

        // 1. Negative Cache (NOERROR with no HTTPS records)
        resolver.queryForwarder = { query, _, completion in
            queryCount += 1
            // Return NOERROR with 0 answers (NODATA)
            completion(self.mockResponse(for: query, answers: []))
        }

        let expNeg1 = expectation(description: "negative cache 1st query")
        resolver.resolveECH(for: "nodata.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success(let res):
                XCTAssertFalse(res.hasECH)
                XCTAssertNil(res.echConfigList)
                if case .noECH(let name, let ttl, _) = res {
                    XCTAssertEqual(name, "nodata.example.com")
                    XCTAssertGreaterThanOrEqual(ttl, 10)
                } else {
                    XCTFail("Expected .noECH resolution")
                }
            case .failure(let err):
                XCTFail("Unexpected failure: \(err)")
            }
            expNeg1.fulfill()
        }
        wait(for: [expNeg1], timeout: 2)
        XCTAssertEqual(queryCount, 1)

        // Second query must hit cache and NOT invoke queryForwarder
        let expNeg2 = expectation(description: "negative cache 2nd hit")
        resolver.resolveECH(for: "nodata.example.com", callerQueue: testQueue) { result in
            if case .success(let res) = result {
                XCTAssertFalse(res.hasECH)
            } else {
                XCTFail("Expected cached .noECH")
            }
            expNeg2.fulfill()
        }
        wait(for: [expNeg2], timeout: 2)
        XCTAssertEqual(queryCount, 1, "Cached query must not query upstream")

        // 2. Query Failure (network error / nil response)
        var failureQueryCount = 0
        let failureResolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        failureResolver.queryForwarder = { _, _, completion in
            failureQueryCount += 1
            completion(nil) // network failure
        }

        let expFail1 = expectation(description: "failure 1st query")
        failureResolver.resolveECH(for: "fail.example.com", callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Expected failure on nil upstream response")
            case .failure(let err):
                if case .networkError = err {
                    // expected
                } else {
                    XCTFail("Expected .networkError, got: \(err)")
                }
            }
            expFail1.fulfill()
        }
        wait(for: [expFail1], timeout: 2)
        XCTAssertEqual(failureQueryCount, 1)

        // Cached lookup must return nil
        XCTAssertNil(failureResolver.cachedECH(for: "fail.example.com"))

        // Second query MUST dispatch upstream again (no negative cache written)
        let expFail2 = expectation(description: "failure 2nd retry query")
        failureResolver.resolveECH(for: "fail.example.com", callerQueue: testQueue) { result in
            XCTAssertTrue(result.isFailure)
            expFail2.fulfill()
        }
        wait(for: [expFail2], timeout: 2)
        XCTAssertEqual(failureQueryCount, 2, "Failed queries must not be cached")
    }

    // MARK: - 6. Cache Capacity Eviction

    func testECHResolver_CacheCapacityEviction() {
        var currentTime = Date(timeIntervalSince1970: 1_700_000_000)
        let resolver = NCECHResolver(capacity: 3, upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.now = { currentTime }

        let cand = NCSVCCandidate(priority: 1, targetName: ".", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: Data([1]), ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        resolver.queryForwarder = { query, _, completion in
            let name = NCDNSMessage.parse(query)?.questions.first?.name ?? "test"
            completion(self.mockResponse(for: query, answers: [
                self.makeHTTPSRecord(name: name, ttl: 60, candidate: cand)
            ]))
        }

        let domains = ["d1.com", "d2.com", "d3.com"]
        for d in domains {
            let exp = expectation(description: "fill \(d)")
            resolver.resolveECH(for: d, callerQueue: testQueue) { _ in exp.fulfill() }
            wait(for: [exp], timeout: 2)
        }
        XCTAssertEqual(resolver.cacheCount, 3)

        // Advance time past 60s so all existing entries expire
        currentTime = currentTime.addingTimeInterval(70)

        // Adding 4th entry purges expired entries first
        let exp4 = expectation(description: "add 4th")
        resolver.resolveECH(for: "d4.com", callerQueue: testQueue) { _ in exp4.fulfill() }
        wait(for: [exp4], timeout: 2)

        XCTAssertEqual(resolver.cacheCount, 1)
        XCTAssertNotNil(resolver.cachedECH(for: "d4.com"))
        XCTAssertNil(resolver.cachedECH(for: "d1.com"))

        // Fill up to 3 again with unexpired entries
        for d in ["d5.com", "d6.com"] {
            let exp = expectation(description: "fill \(d)")
            resolver.resolveECH(for: d, callerQueue: testQueue) { _ in exp.fulfill() }
            wait(for: [exp], timeout: 2)
        }
        XCTAssertEqual(resolver.cacheCount, 3)

        // Insert 7th entry when all 3 entries are unexpired -> evicts earliest expiring entry
        let exp7 = expectation(description: "evict oldest")
        resolver.resolveECH(for: "d7.com", callerQueue: testQueue) { _ in exp7.fulfill() }
        wait(for: [exp7], timeout: 2)

        XCTAssertLessThanOrEqual(resolver.cacheCount, 3)
        XCTAssertNotNil(resolver.cachedECH(for: "d7.com"))
    }

    // MARK: - 7. In-Flight Query Coalescing

    func testECHResolver_InFlightCoalescing() {
        var queryCount = 0
        var pendingCompletion: ((Data?) -> Void)?
        let lock = NSLock()

        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { _, _, completion in
            lock.lock()
            queryCount += 1
            pendingCompletion = completion
            lock.unlock()
        }

        let exp1 = expectation(description: "caller 1")
        let exp2 = expectation(description: "caller 2")
        let exp3 = expectation(description: "caller 3")

        let echData = Data([0xfe, 0x0d, 0x99, 0x88])
        var r1: NCECHResolution?
        var r2: NCECHResolution?
        var r3: NCECHResolution?

        resolver.resolveECH(for: "coalesce.example.com", callerQueue: testQueue) { res in
            r1 = try? res.get()
            exp1.fulfill()
        }
        resolver.resolveECH(for: "coalesce.example.com", callerQueue: testQueue) { res in
            r2 = try? res.get()
            exp2.fulfill()
        }
        resolver.resolveECH(for: "coalesce.example.com", callerQueue: testQueue) { res in
            r3 = try? res.get()
            exp3.fulfill()
        }

        // Wait brief moment on testQueue to allow all 3 calls to register in resolver.waiters
        let pauseExp = expectation(description: "pause")
        testQueue.asyncAfter(deadline: .now() + 0.05) { pauseExp.fulfill() }
        wait(for: [pauseExp], timeout: 1)

        lock.lock()
        XCTAssertEqual(queryCount, 1, "Only 1 in-flight network query should be issued for identical target")
        let comp = pendingCompletion
        lock.unlock()

        guard let comp else {
            XCTFail("Missing pending completion")
            return
        }

        let cand = NCSVCCandidate(priority: 1, targetName: ".", alpn: ["h2"], noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: echData, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let respData = mockResponse(for: Data(), answers: [
            makeHTTPSRecord(name: "coalesce.example.com", ttl: 300, candidate: cand)
        ])
        comp(respData)

        wait(for: [exp1, exp2, exp3], timeout: 2)

        XCTAssertEqual(r1?.echConfigList, echData)
        XCTAssertEqual(r2?.echConfigList, echData)
        XCTAssertEqual(r3?.echConfigList, echData)
    }

    // MARK: - 8. Overall Timeout Covering All Upstreams & Alias Hops

    func testECHResolver_OverallTimeoutReturnsFailureAndDoesNotWriteNegativeCache() {
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        // Upstream drops packet / never replies
        resolver.queryForwarder = { _, _, _ in }

        let exp = expectation(description: "overall timeout")
        resolver.resolveECH(for: "timeout.example.com", timeout: 0.1, callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Query should have timed out")
            case .failure(let err):
                XCTAssertEqual(err, .timeout)
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)

        // Must NOT write negative cache
        XCTAssertNil(resolver.cachedECH(for: "timeout.example.com"), "Timed out resolution must not write negative cache")
    }

    func testECHResolver_OverallTimeoutCoversAliasHopChain() {
        let alias = NCSVCCandidate(priority: 0, targetName: "slow.example.com", alpn: nil, noDefaultALPN: false, port: nil, ipv4Hints: nil, echConfigList: nil, ipv6Hints: nil, mandatoryKeys: nil, rawParams: [:])
        let resolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        resolver.queryForwarder = { query, _, completion in
            let qname = NCDNSMessage.parse(query)?.questions.first?.name.lowercased() ?? ""
            if qname.contains("fast") {
                // First hop answers immediately with AliasMode
                completion(self.mockResponse(for: query, answers: [
                    self.makeHTTPSRecord(name: "fast.example.com", ttl: 300, candidate: alias)
                ]))
            } else {
                // Second hop (slow.example.com) hangs and never answers
            }
        }

        let exp = expectation(description: "alias hop timeout")
        resolver.resolveECH(for: "fast.example.com", timeout: 0.12, callerQueue: testQueue) { result in
            switch result {
            case .success:
                XCTFail("Alias chain should have timed out")
            case .failure(let err):
                XCTAssertEqual(err, .timeout)
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2)

        XCTAssertNil(resolver.cachedECH(for: "fast.example.com"))
        XCTAssertNil(resolver.cachedECH(for: "slow.example.com"))
    }

    // MARK: - 9. Single-Copy Memory Representation

    func testECHResolver_SingleCopyDataRepresentation() {
        let rawECH = Data([0xfe, 0x0d, 0x12, 0x34, 0x56, 0x78])
        let expDate = Date(timeIntervalSince1970: 1_700_000_100)
        let rec = NCECHRecord(
            queryName: "memory.example.com",
            echConfigList: rawECH,
            ttl: 300,
            expires: expDate,
            aliasChain: ["prev.example.com"]
        )

        // Verify stored properties
        XCTAssertEqual(rec.queryName, "memory.example.com")
        XCTAssertEqual(rec.echConfigList, rawECH)
        XCTAssertEqual(rec.ttl, 300)
        XCTAssertEqual(rec.expires, expDate)
        XCTAssertEqual(rec.aliasChain, ["prev.example.com"])

        // Verify derived candidate view generated on demand
        let cand = rec.candidate
        XCTAssertEqual(cand.priority, 1)
        XCTAssertEqual(cand.targetName, ".")
        XCTAssertEqual(cand.echConfigList, rawECH)

        // Verify derived source record generated on demand
        let src = rec.sourceRecord
        XCTAssertEqual(src.name, "memory.example.com")
        XCTAssertEqual(src.type, NCDNSMessage.typeHTTPS)
        XCTAssertEqual(src.ttl, 300)
    }

    // MARK: - 10. NativeCoreEngine Integration & Eager Let Holder

    func testNativeCoreEngine_ECHResolverHolderAndInjection() {
        let mockResolver = NCECHResolver(upstreamProvider: { _, _ in (self.dummyUpstream, nil, false) })
        let engineWithMock = NativeCoreEngine(echResolver: mockResolver)
        XCTAssertTrue(engineWithMock.echResolver === mockResolver)

        let defaultEngine = NativeCoreEngine()
        XCTAssertNotNil(defaultEngine.echResolver)
    }
}

private extension Result {
    var isFailure: Bool {
        if case .failure = self { return true }
        return false
    }
}
