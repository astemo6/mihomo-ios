import XCTest
@testable import Tern

/// fix/nc-0.20.3-geoip: IPv4 lookups in an IPv6 MaxMind tree start at the `::a.b.c.d` subtree (96 zero bits), not at
/// `::ffff:a.b.c.d`. MetaCubeX geoip.metadb (Meta-geoip0) has no ::ffff alias, so before the fix every IPv4 lookup
/// returned nil on device (`geo -` for 180.163.x / 120.233.x / 58.218.x) and `GEOIP,cn,DIRECT` never matched.
final class NativeCoreGeoIPLookupTests: XCTestCase {

    // MARK: synthetic IPv6 tree laid out like Meta-geoip0 (no ::ffff:0:0/96 alias)

    private static func str(_ s: String) -> [UInt8] {
        var b: [UInt8] = [0x40 | UInt8(s.utf8.count)]
        b.append(contentsOf: Array(s.utf8))
        return b
    }

    private static func rec24(_ v: Int) -> [UInt8] {
        [UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }

    /// Nodes 0…95 chain on bit 0 (the 96 zero bits of `::a.b.c.d`); node 0's 1-branch (8000::/1) → "jp".
    /// Node 96 is the IPv4 root: 0.0.0.0/1 → "cn", 128.0.0.0/1 → "us". Every other branch is empty, so a walk along
    /// `::ffff:…` (bit 80 = 1) finds nothing.
    private static func v6TreeWithoutMappedAlias() -> Data {
        let nodeCount = 97
        let recCN: [UInt8] = str("cn")
        let recUS: [UInt8] = str("us")
        let recJP: [UInt8] = str("jp")
        let base = nodeCount + 16
        let ptrCN = base
        let ptrUS = base + recCN.count
        let ptrJP = base + recCN.count + recUS.count
        var out: [UInt8] = []
        for i in 0..<96 {
            out.append(contentsOf: rec24(i + 1))
            out.append(contentsOf: rec24(i == 0 ? ptrJP : nodeCount))
        }
        out.append(contentsOf: rec24(ptrCN))
        out.append(contentsOf: rec24(ptrUS))
        out.append(contentsOf: [UInt8](repeating: 0, count: 16))
        out.append(contentsOf: recCN)
        out.append(contentsOf: recUS)
        out.append(contentsOf: recJP)
        out.append(contentsOf: [0xab, 0xcd, 0xef] as [UInt8])
        out.append(contentsOf: Array("MaxMind.com".utf8))
        out.append(0xE3)
        out.append(contentsOf: str("node_count"))
        out.append(contentsOf: [0xA1, UInt8(nodeCount)] as [UInt8])
        out.append(contentsOf: str("record_size"))
        out.append(contentsOf: [0xA1, 24] as [UInt8])
        out.append(contentsOf: str("ip_version"))
        out.append(contentsOf: [0xA1, 6] as [UInt8])
        return Data(out)
    }

    private func ip(_ s: String) throws -> NCIP { try XCTUnwrap(NCIP(s), s) }

    func testIPv4InIPv6TreeStartsAtIPv4Subtree() throws {
        let db = try XCTUnwrap(NCMMDB(data: Self.v6TreeWithoutMappedAlias()))
        XCTAssertEqual(db.countryCodes(for: try ip("58.218.0.1")), ["cn"])
        XCTAssertEqual(db.countryCodes(for: try ip("1.1.1.1")), ["cn"])
        XCTAssertEqual(db.countryCodes(for: try ip("180.163.0.1")), ["us"])
        XCTAssertEqual(db.countryCode(for: try ip("8.8.8.8")), "cn")
        // IPv4-mapped IPv6 (NCIP keeps it as .v6) takes the IPv4 subtree too.
        XCTAssertEqual(db.countryCodes(for: try ip("::ffff:58.218.0.1")), ["cn"])
        // Real IPv6 still walks from the root.
        XCTAssertEqual(db.countryCodes(for: try ip("8000::1")), ["jp"])
        XCTAssertEqual(db.countryCodes(for: try ip("2001:db8::1")), [])
    }

    func testGEOIPRuleMatchesThroughIPv4Subtree() throws {
        let db = try XCTUnwrap(NCMMDB(data: Self.v6TreeWithoutMappedAlias()))
        let cn = try XCTUnwrap(NCRule.parse("GEOIP,CN,DIRECT"))
        var c = NCMatchContext()
        c.countryOf = { db.countryCode(for: $0) }
        c.countryCodesOf = { db.countryCodes(for: $0) }
        c.ip = NCIP("49.71.0.1")
        XCTAssertTrue(NCRuleMatcher.matches(cn, c))
        c.ip = NCIP("200.1.1.1")
        XCTAssertFalse(NCRuleMatcher.matches(cn, c))
    }

    // MARK: the real MetaCubeX geoip.metadb (latest release asset)

    private static let realDBURL = URL(string: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb")!

    private func downloadRealDB() throws -> Data {
        let done = expectation(description: "geoip.metadb download")
        var body: Data?
        var failure: String?
        var req = URLRequest(url: Self.realDBURL)
        req.timeoutInterval = 90
        URLSession.shared.dataTask(with: req) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if let data, status == 200, data.count > 1_000_000 {
                body = data
            } else {
                failure = "HTTP \(status) \(error?.localizedDescription ?? "") bytes \(data?.count ?? 0)"
            }
            done.fulfill()
        }.resume()
        wait(for: [done], timeout: 120)
        guard let body else { throw XCTSkip("geoip.metadb download failed: \(failure ?? "timeout")") }
        return body
    }

    func testRealMetaGeoIPDatabaseResolvesChinaAndUS() throws {
        let data = try downloadRealDB()
        let db = try XCTUnwrap(NCMMDB(data: data))
        XCTAssertEqual(db.databaseType, "Meta-geoip0")
        for addr in ["180.163.0.1", "120.233.0.1", "58.218.0.1", "49.71.0.1", "120.46.0.1"] {
            let codes = db.countryCodes(for: try ip(addr))
            XCTAssertTrue(codes.contains("cn"), "\(addr) → \(codes)")
        }
        let google = db.countryCodes(for: try ip("8.8.8.8"))
        XCTAssertTrue(google.contains("us"), "8.8.8.8 → \(google)")
        XCTAssertFalse(google.contains("cn"))

        let rule = try XCTUnwrap(NCRule.parse("GEOIP,CN,DIRECT"))
        var c = NCMatchContext()
        c.countryOf = { db.countryCode(for: $0) }
        c.countryCodesOf = { db.countryCodes(for: $0) }
        c.ip = NCIP("180.163.0.1")
        XCTAssertTrue(NCRuleMatcher.matches(rule, c))
        c.ip = NCIP("8.8.8.8")
        XCTAssertFalse(NCRuleMatcher.matches(rule, c))
        // An IPv6 address in a CN range resolves too (240e::/20 China Telecom).
        let v6 = db.countryCodes(for: try ip("240e::1"))
        XCTAssertTrue(v6.contains("cn"), "240e::1 → \(v6)")
    }
}
