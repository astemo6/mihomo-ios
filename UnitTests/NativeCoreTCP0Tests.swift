import XCTest
@testable import Mihomo

/// fix/nc-tcp0 (build419 device report: packets in ~70/min, tcp accepted 0, Home 「正在查询…」 forever).
/// The C fixes (nc_udp_send checksums, IPv6 peek byte order, ip6_input_accept patch) are covered by
/// tools/nc-stack-test (Checks → nc-stack-c); these cover the Swift side: the packet trace that 诊断 logs, the
/// checksum verdict it prints for what the core emits, the SERVFAIL answer, and the exit-info deadline.
final class NativeCoreTCP0Tests: XCTestCase {

    // MARK: helpers

    private func sum(_ b: [UInt8], _ acc0: UInt32 = 0) -> UInt32 {
        var acc = acc0
        var i = 0
        while i + 1 < b.count { acc += UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
        if i < b.count { acc += UInt32(b[i]) << 8 }
        return acc
    }
    private func csum(_ b: [UInt8], _ acc0: UInt32 = 0) -> UInt16 {
        var acc = sum(b, acc0)
        while acc >> 16 != 0 { acc = (acc & 0xffff) + (acc >> 16) }
        return ~UInt16(acc)
    }

    /// A v4 TCP SYN 198.18.0.1:50000 → 93.184.216.34:443 with valid checksums.
    private func syn4() -> [UInt8] {
        var ip: [UInt8] = [0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 198, 18, 0, 1, 93, 184, 216, 34]
        var tcp = [UInt8](repeating: 0, count: 20)
        tcp[0] = 0xc3; tcp[1] = 0x50; tcp[2] = 0x01; tcp[3] = 0xbb; tcp[7] = 1
        tcp[12] = 5 << 4; tcp[13] = 0x02; tcp[14] = 0xff; tcp[15] = 0xff
        let hc = csum(ip); ip[10] = UInt8(hc >> 8); ip[11] = UInt8(hc & 0xff)
        let pseudo = sum(Array(ip[12..<20])) + 6 + 20
        let tc = csum(tcp, pseudo); tcp[16] = UInt8(tc >> 8); tcp[17] = UInt8(tc & 0xff)
        return ip + tcp
    }

    /// A v6 UDP datagram [fdfe:dcba:9876::1]:5353 → [2404:6800::2004]:443.
    private func udp6(validChecksum: Bool = true) -> [UInt8] {
        var p = [UInt8](repeating: 0, count: 40 + 12)
        p[0] = 0x60; p[5] = 12; p[6] = 17; p[7] = 64
        let src: [UInt8] = [0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let dst: [UInt8] = [0x24, 0x04, 0x68, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x04]
        p.replaceSubrange(8..<24, with: src)
        p.replaceSubrange(24..<40, with: dst)
        p[40] = 0x14; p[41] = 0xe9; p[42] = 0x01; p[43] = 0xbb; p[45] = 12
        p[48] = 1; p[49] = 2; p[50] = 3; p[51] = 4
        let pseudo = sum(Array(p[8..<40])) + 17 + 12
        var c = csum(Array(p[40...]), pseudo)
        if !validChecksum { c ^= 0x0101 }
        p[46] = UInt8(c >> 8); p[47] = UInt8(c & 0xff)
        return p
    }

    // MARK: packet trace

    func testSummaryV4SynShowsPortsAndFlags() {
        let s = NCPacketTrace.summary(Data(syn4()))
        XCTAssertEqual(s, "v4 tcp 198.18.0.1:50000 → 93.184.216.34:443 [S] 40 B")
    }

    func testSummaryV6UDP() {
        let s = NCPacketTrace.summary(Data(udp6()))
        XCTAssertTrue(s.hasPrefix("v6 udp [fdfe:dcba:9876:0:0:0:0:1]:5353 → [2404:6800:0:0:0:0:0:2004]:443"), s)
    }

    func testChecksumVerdictOkAndBad() {
        XCTAssertEqual(NCPacketTrace.checksumVerdict(syn4()), "csum ok")
        XCTAssertEqual(NCPacketTrace.checksumVerdict(udp6()), "csum ok")
        XCTAssertEqual(NCPacketTrace.checksumVerdict(udp6(validChecksum: false)), "csum BAD (udp)")
        var badIP = syn4()
        badIP[10] ^= 0xff
        XCTAssertTrue(NCPacketTrace.checksumVerdict(badIP).contains("ip"))
        // the build419 bug: header checksum written byte-swapped
        var swapped = syn4()
        swapped.swapAt(10, 11)
        if swapped[10] != swapped[11] {
            XCTAssertNotEqual(NCPacketTrace.checksumVerdict(swapped), "csum ok")
        }
    }

    func testSummaryHandlesGarbage() {
        XCTAssertEqual(NCPacketTrace.summary(Data()), "empty")
        XCTAssertEqual(NCPacketTrace.summary(Data([0x45, 0, 0])), "version 4, 3 B")
        XCTAssertEqual(NCPacketTrace.flags(0x12), "SA")
        XCTAssertEqual(NCPacketTrace.flags(0x14), "AR")
    }

    // MARK: SERVFAIL

    func testServfailKeepsIdAndQuestion() throws {
        var q = NCDNSMessage()
        q.id = 0xbeef
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: "www.baidu.com", type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        let wire = q.serialized()
        let reply = try XCTUnwrap(NCPacketTrace.dnsServfail(for: wire))
        let m = try XCTUnwrap(NCDNSMessage.parse(reply))
        XCTAssertEqual(m.id, 0xbeef)
        XCTAssertTrue(m.isResponse)
        XCTAssertTrue(m.recursionDesired)
        XCTAssertTrue(m.recursionAvailable)
        XCTAssertEqual(m.rcode, 2)
        XCTAssertEqual(m.questions, q.questions)
        XCTAssertTrue(m.answers.isEmpty)
    }

    func testServfailRefusesResponsesAndJunk() {
        XCTAssertNil(NCPacketTrace.dnsServfail(for: Data([1, 2, 3])))
        var r = NCDNSMessage()
        r.isResponse = true
        r.questions = [NCDNSQuestion(name: "a.b", type: 1, klass: 1)]
        XCTAssertNil(NCPacketTrace.dnsServfail(for: r.serialized()))
    }

    // MARK: exit-info deadline (Home 「正在查询…」)

    /// The old task-group deadline waited for a body that ignores cancellation; the new one returns on time.
    func testWithDeadlineReturnsOnTimeForUncancellableBody() async {
        let t0 = Date()
        let r = await IPInfoModel.withDeadline(0.3) {
            // ignores cancellation: blocks a detached thread for 3 s
            await Task.detached { Thread.sleep(forTimeInterval: 3); return IPInfo(ip: "203.0.113.9") }.value
        }
        XCTAssertNil(r)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0)
    }

    func testWithDeadlinePassesFastResult() async {
        let r = await IPInfoModel.withDeadline(5) { IPInfo(ip: "203.0.113.7") }
        XCTAssertEqual(r?.ip, "203.0.113.7")
    }

    func testDeadlinesAreBounded() {
        XCTAssertLessThanOrEqual(IPInfoModel.lookupDeadline, IPInfoModel.hardDeadline)
        XCTAssertLessThanOrEqual(IPInfoModel.hardDeadline, 20)
    }
}
