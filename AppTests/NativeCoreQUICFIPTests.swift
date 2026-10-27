import XCTest
@testable import Tern

/// QUIC SNI sniffing (packet built independently with an independent implementation per
/// RFC 9001; intermediate keys cross-checked against RFC 9001 App. A),
/// fake-IP v6, redir-host map, and ICMP echo replies.
final class NativeCoreQUICFIPTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return d
    }

    func testQUICSniff() {
        // Keys for DCID 8394c8f03e515708 (RFC 9001 App. A values, generated
        // with the old core): key 1f369613…, iv fa044b2f…, hp 9f50449e….
        let packet = hex("c600000001088394c8f03e5157080000405ef046b451939b7ca362c0a5e53f6c22dd6988baba5401fabdb11bdc15c4308caa1ea6df4ec4eea1ddf3d6bd27fb13e5e574e90272d731e3b576aadddbee49087943c635759b966e8e966e428f7fde7e84aa4bd6c26c790c451d0215f69394")
        XCTAssertEqual(NCQUICSniffer.sni(from: packet), "example.com")
        if case .tls(let sni, let alpn) = NCSniffer.detect(packet) {
            XCTAssertEqual(sni, "example.com")
            XCTAssertEqual(alpn, ["h3"])
        } else {
            XCTFail("sniffer should classify the QUIC initial as TLS/h3")
        }
        // Garbage and short packets fail closed.
        XCTAssertNil(NCQUICSniffer.sni(from: Data([0xc0, 0, 0, 0, 1])))
        XCTAssertNil(NCQUICSniffer.sni(from: Data(repeating: 0xff, count: 100)))
    }

    func testFakeIP6() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16", range6: "fd00:1234::/48", filter: [])
        XCTAssertTrue(pool.hasRange6)
        let a = pool.address6(for: "Example.COM")
        XCTAssertNotNil(a)
        XCTAssertEqual(a, pool.address6(for: "example.com")) // stable + case-insensitive
        if case .v6(let bytes) = a! {
            XCTAssertEqual(Array(bytes[0..<6]), [0xfd, 0x00, 0x12, 0x34, 0, 0])
            XCTAssertEqual(bytes[15], 1) // first offset
        } else { XCTFail("expected v6") }
        let b = pool.address6(for: "other.com")
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(pool.host(for: a!), "example.com")
        XCTAssertTrue(pool.isFakeAddress(a!))
        XCTAssertFalse(pool.isFakeAddress(NCIP("fd00:9999::1")!))
        // No range6 configured -> nil.
        let pool4 = NCFakeIPPool(range: "198.18.0.1/16", filter: [])
        XCTAssertNil(pool4.address6(for: "example.com"))
        XCTAssertFalse(pool4.hasRange6)
    }

    func testResponderAAAA() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16", range6: "fd00:1234::/48", filter: [])
        let responder = NCFakeIPResponder(pool: pool)
        let query = makeQuery(name: "example.com", type: 28)
        let respData = responder.respond(to: query)
        XCTAssertNotNil(respData)
        let resp = NCDNSMessage.parse(respData!)
        XCTAssertEqual(resp?.answers.count, 1)
        XCTAssertEqual(resp?.answers.first?.rdata.count, 16)
        // Without range6 -> empty NOERROR.
        let responder4 = NCFakeIPResponder(pool: NCFakeIPPool(range: "198.18.0.1/16", filter: []))
        let resp4 = NCDNSMessage.parse(responder4.respond(to: query)!)
        XCTAssertEqual(resp4?.answers.count, 0)
    }

    func testRealIPMap() {
        let map = NCRealIPMap()
        var clock = Date(timeIntervalSince1970: 1_000_000)
        map.now = { clock }
        map.record(host: "Example.com", answers: [(.v4(0x0102_0304), 60), (.v6([UInt8](repeating: 1, count: 16)), 60)])
        XCTAssertEqual(map.host(for: .v4(0x0102_0304)), "example.com")
        XCTAssertEqual(map.host(for: .v6([UInt8](repeating: 1, count: 16))), "example.com")
        XCTAssertNil(map.host(for: .v4(0x0506_0708)))
        clock = clock.addingTimeInterval(120) // beyond TTL 60 (clamped >= 30)
        XCTAssertNil(map.host(for: .v4(0x0102_0304)))
        // addressAnswers extraction from a parsed response.
        let respData = makeResponse(name: "example.com", ip: [1, 2, 3, 4], ttl: 300)
        let parsed = NCDNSMessage.parse(respData)
        XCTAssertEqual(parsed?.addressAnswers.count, 1)
        XCTAssertEqual(parsed?.addressAnswers.first?.0, NCIP.v4(0x0102_0304))
        XCTAssertEqual(parsed?.addressAnswers.first?.1, 300)
    }

    func testICMPEcho() {
        // IPv4 echo request 10.0.0.9 -> 198.18.0.5, id 0x1234 seq 1, payload "abc".
        var pkt = Data()
        pkt.append(contentsOf: [0x45, 0x00, 0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0])
        pkt.append(contentsOf: [10, 0, 0, 9, 198, 18, 0, 5])
        pkt.append(contentsOf: [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01])
        pkt.append(contentsOf: "abc".utf8)
        // Fill checksums properly so the round trip validates: compute and inject.
        var bytes = [UInt8](pkt)
        let hc = NCICMPEcho.checksum(Data(bytes[0..<20]))
        bytes[10] = UInt8(hc >> 8); bytes[11] = UInt8(hc & 0xff)
        let ic = NCICMPEcho.checksum(Data(bytes[20...]))
        bytes[22] = UInt8(ic >> 8); bytes[23] = UInt8(ic & 0xff)
        pkt = Data(bytes)
        XCTAssertEqual(NCICMPEcho.echoRequestDestination(pkt), NCIP("198.18.0.5"))
        let reply = NCICMPEcho.reply(for: pkt)
        XCTAssertNotNil(reply)
        let r = [UInt8](reply!)
        XCTAssertEqual(Array(r[12..<16]), [198, 18, 0, 5]) // source = old dst
        XCTAssertEqual(Array(r[16..<20]), [10, 0, 0, 9])
        XCTAssertEqual(r[20], 0) // echo reply
        // Checksums validate (checksum over the finished message == 0).
        XCTAssertEqual(NCICMPEcho.checksum(Data(r[0..<20])), 0)
        XCTAssertEqual(NCICMPEcho.checksum(Data(r[20...])), 0)
        // Not echo -> nil.
        var tcp = pkt
        tcp[9] = 6
        XCTAssertNil(NCICMPEcho.echoRequestDestination(tcp))

        // IPv6 echo request fd00::9 -> fd00::5.
        var p6 = Data()
        p6.append(contentsOf: [0x60, 0, 0, 0, 0, 11, 58, 64])
        var src = [UInt8](repeating: 0, count: 16); src[0] = 0xfd; src[15] = 9
        var dst = [UInt8](repeating: 0, count: 16); dst[0] = 0xfd; dst[15] = 5
        p6.append(contentsOf: src); p6.append(contentsOf: dst)
        p6.append(contentsOf: [128, 0, 0, 0, 0x00, 0x2a, 0x00, 0x01])
        p6.append(contentsOf: "xyz".utf8)
        XCTAssertEqual(NCICMPEcho.echoRequestDestination(p6), NCIP.v6(dst))
        let reply6 = NCICMPEcho.reply(for: p6)
        XCTAssertNotNil(reply6)
        let r6 = [UInt8](reply6!)
        XCTAssertEqual(r6[40], 129)
        XCTAssertEqual(Array(r6[8..<24]), dst)
    }

    // MARK: DNS message builders

    private func makeQuery(name: String, type: UInt16) -> Data {
        var msg = NCDNSMessage()
        msg.id = 0x4242
        msg.recursionDesired = true
        msg.questions = [NCDNSQuestion(name: name, type: type, klass: 1)]
        return msg.serialized()
    }

    private func makeResponse(name: String, ip: [UInt8], ttl: UInt32) -> Data {
        var msg = NCDNSMessage()
        msg.id = 0x4242
        msg.isResponse = true
        msg.questions = [NCDNSQuestion(name: name, type: 1, klass: 1)]
        msg.answers = [NCDNSRecord(name: name, type: 1, klass: 1, ttl: ttl, rdata: Data(ip))]
        return msg.serialized()
    }
}
