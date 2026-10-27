import XCTest
@testable import Tern

/// fix/nc-wloc-tunnel: 本机隧道 (LocalDevVPN compatible loopback). Packets to the peer (default 10.7.0.1) get their
/// IPv4 source / destination swapped and go straight back to the TUN; checksums must stay valid without being
/// recomputed; anything else passes through untouched; the peer /32 is carved out of the excluded routes.
final class NativeCoreLocalDeviceTunnelTests: XCTestCase {

    // MARK: packet helpers

    private func sum16(_ b: [UInt8], _ acc0: UInt32 = 0) -> UInt32 {
        var acc = acc0
        var i = 0
        while i + 1 < b.count { acc += UInt32(b[i]) << 8 | UInt32(b[i + 1]); i += 2 }
        if i < b.count { acc += UInt32(b[i]) << 8 }
        return acc
    }

    private func fold(_ a: UInt32) -> UInt16 {
        var acc = a
        while acc >> 16 != 0 { acc = (acc & 0xffff) + (acc >> 16) }
        return UInt16(acc & 0xffff)
    }

    private func checksum(_ b: [UInt8], _ acc0: UInt32 = 0) -> UInt16 { ~fold(sum16(b, acc0)) }

    /// A valid IPv4 packet (header checksum + TCP/UDP checksum over the pseudo-header).
    private func packet(proto: UInt8, src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, payload: [UInt8]) -> Data {
        var l4: [UInt8]
        if proto == 6 {
            l4 = [UInt8](repeating: 0, count: 20)
            l4[12] = 5 << 4            // data offset
            l4[13] = 0x02              // SYN
            l4[14] = 0xff; l4[15] = 0xff // window
            l4[4] = 0x12; l4[5] = 0x34; l4[6] = 0x56; l4[7] = 0x78 // seq
        } else {
            l4 = [UInt8](repeating: 0, count: 8)
        }
        l4[0] = UInt8(sport >> 8); l4[1] = UInt8(sport & 0xff)
        l4[2] = UInt8(dport >> 8); l4[3] = UInt8(dport & 0xff)
        l4 += payload
        if proto == 17 { l4[4] = UInt8(l4.count >> 8); l4[5] = UInt8(l4.count & 0xff) }
        let pseudo = src + dst + [0, proto, UInt8(l4.count >> 8), UInt8(l4.count & 0xff)]
        let ck = checksum(l4, sum16(pseudo))
        let ckOff = proto == 6 ? 16 : 6
        l4[ckOff] = UInt8(ck >> 8); l4[ckOff + 1] = UInt8(ck & 0xff)
        var ip = [UInt8](repeating: 0, count: 20)
        ip[0] = 0x45
        let total = 20 + l4.count
        ip[2] = UInt8(total >> 8); ip[3] = UInt8(total & 0xff)
        ip[4] = 0xbe; ip[5] = 0xef
        ip[8] = 64; ip[9] = proto
        ip.replaceSubrange(12..<16, with: src)
        ip.replaceSubrange(16..<20, with: dst)
        let hc = checksum(ip)
        ip[10] = UInt8(hc >> 8); ip[11] = UInt8(hc & 0xff)
        return Data(ip + l4)
    }

    /// Both checksums verify (a correct one's-complement sum folds to 0xffff).
    private func checksumsValid(_ d: Data) -> Bool {
        let b = [UInt8](d)
        let ihl = Int(b[0] & 0x0f) * 4
        guard fold(sum16(Array(b[0..<ihl]))) == 0xffff else { return false }
        let l4 = Array(b[ihl...])
        let pseudo = Array(b[12..<20]) + [0, b[9], UInt8(l4.count >> 8), UInt8(l4.count & 0xff)]
        return fold(sum16(l4, sum16(pseudo))) == 0xffff
    }

    private let device: [UInt8] = [198, 18, 0, 1]   // Tern's tunnel address (the source iOS picks)
    private let peer: [UInt8] = [10, 7, 0, 1]
    private var tunnel: NCLocalDeviceTunnel { NCLocalDeviceTunnel(peer: "10.7.0.1")! }

    // MARK: reflection

    func testTCPSynToPeerIsReflectedWithValidChecksums() {
        let p = packet(proto: 6, src: device, dst: peer, sport: 51234, dport: 62078, payload: [])
        XCTAssertTrue(checksumsValid(p), "fixture")
        guard let r = tunnel.reflected(p) else { return XCTFail("not reflected") }
        let b = [UInt8](r)
        XCTAssertEqual(Array(b[12..<16]), peer, "source is now the peer")
        XCTAssertEqual(Array(b[16..<20]), device, "destination is now the device")
        XCTAssertEqual(Array(b[20..<24]), Array([UInt8](p)[20..<24]), "ports untouched (LocalDevVPN swaps addresses only)")
        XCTAssertEqual(r.count, p.count)
        XCTAssertTrue(checksumsValid(r), "IPv4 header + TCP checksums stay valid without recomputing")
        // The device's reply (to the peer) is reflected back the same way.
        let reply = packet(proto: 6, src: device, dst: peer, sport: 62078, dport: 51234, payload: [1, 2, 3])
        XCTAssertNotNil(tunnel.reflected(reply))
    }

    func testUDPToPeerIsReflectedWithValidChecksums() {
        for payload in [[UInt8](), [0x42], [UInt8](repeating: 0xa5, count: 1201)] {  // even, odd, large
            let p = packet(proto: 17, src: [192, 168, 1, 23], dst: peer, sport: 5353, dport: 49152, payload: payload)
            XCTAssertTrue(checksumsValid(p))
            guard let r = tunnel.reflected(p) else { return XCTFail("not reflected") }
            XCTAssertEqual(Array([UInt8](r)[12..<20]), peer + [192, 168, 1, 23])
            XCTAssertTrue(checksumsValid(r), "UDP payload \(payload.count)")
        }
    }

    func testInPlaceReflectIsInvolution() {
        let p = packet(proto: 6, src: device, dst: peer, sport: 1, dport: 2, payload: [9, 9])
        var q = p
        NCLocalDeviceTunnel.reflect(&q)
        XCTAssertNotEqual(q, p)
        NCLocalDeviceTunnel.reflect(&q)
        XCTAssertEqual(q, p)
    }

    func testNonMatchingPacketsPassThrough() {
        let t = tunnel
        XCTAssertNil(t.reflected(packet(proto: 6, src: device, dst: [10, 7, 0, 2], sport: 1, dport: 2, payload: [])), "other 10.7.0.x")
        XCTAssertNil(t.reflected(packet(proto: 17, src: device, dst: [8, 8, 8, 8], sport: 1, dport: 53, payload: [0])), "ordinary traffic")
        XCTAssertNil(t.reflected(packet(proto: 6, src: peer, dst: peer, sport: 1, dport: 2, payload: [])), "src == dst == peer never loops")
        XCTAssertNil(t.reflected(Data([0x45, 0, 0, 20])), "short packet")
        XCTAssertNil(t.reflected(Data()), "empty")
        var v6 = [UInt8](repeating: 0, count: 60)
        v6[0] = 0x60
        v6.replaceSubrange(16..<20, with: peer) // peer bytes at the IPv4 dst offset of an IPv6 packet
        XCTAssertNil(t.reflected(Data(v6)), "IPv6 is not reflected")
        var badIHL = [UInt8](packet(proto: 6, src: device, dst: peer, sport: 1, dport: 2, payload: []))
        badIHL[0] = 0x44
        XCTAssertNil(t.reflected(Data(badIHL)), "IHL < 5")
    }

    func testCustomPeer() {
        let t = NCLocalDeviceTunnel(peer: "10.8.0.1/32")!
        XCTAssertEqual(t.peerString, "10.8.0.1")
        XCTAssertNotNil(t.reflected(packet(proto: 6, src: device, dst: [10, 8, 0, 1], sport: 1, dport: 2, payload: [])))
        XCTAssertNil(t.reflected(packet(proto: 6, src: device, dst: peer, sport: 1, dport: 2, payload: [])))
    }

    // MARK: settings

    func testPeerValidation() {
        XCTAssertEqual(NCLocalDeviceTunnel.defaultPeer, "10.7.0.1")
        XCTAssertNotNil(NCLocalDeviceTunnel(peer: " 10.7.0.1 "))
        for bad in ["", "10.7.0", "10.7.0.1.2", "10.7.0.256", "a.b.c.d", "10.7.0.1/24", "0.0.0.0", "127.0.0.1",
                    "169.254.1.1", "224.0.0.1", "255.255.255.255", "198.18.0.1", "198.19.255.1", "::1", "1..2.3"] {
            XCTAssertNil(NCLocalDeviceTunnel(peer: bad), bad)
        }
        XCTAssertTrue(NCLocalDeviceTunnel.isValidPeer(""))
        XCTAssertFalse(NCLocalDeviceTunnel.isValidPeer("10.7"))
        XCTAssertNil(NCLocalDeviceTunnel.from(enabled: false, peer: "10.7.0.1"))
        XCTAssertEqual(NCLocalDeviceTunnel.from(enabled: true, peer: "")?.peerString, "10.7.0.1")
    }

    func testOverridesDefaultOffAndRejectJunk() throws {
        let d = CoreOverrides()
        XCTAssertFalse(d.localDeviceTunnel)
        XCTAssertEqual(d.localDeviceTunnelPeer, "10.7.0.1")
        let o = try JSONDecoder().decode(CoreOverrides.self, from: Data(#"{"localDeviceTunnel":true,"localDeviceTunnelPeer":"198.18.0.9"}"#.utf8))
        XCTAssertTrue(o.localDeviceTunnel)
        XCTAssertEqual(o.localDeviceTunnelPeer, "10.7.0.1", "an unusable peer falls back to LocalDevVPN's")
        var e = CoreOverrides()
        e.localDeviceTunnel = true
        e.localDeviceTunnelPeer = "10.9.0.1"
        let back = try JSONDecoder().decode(CoreOverrides.self, from: JSONEncoder().encode(e))
        XCTAssertTrue(back.localDeviceTunnel, "round trip")
        XCTAssertEqual(back.localDeviceTunnelPeer, "10.9.0.1", "round trip")
    }

    // MARK: routes

    private func covers(_ cidr: String, _ ip: UInt32) -> Bool {
        let parts = cidr.split(separator: "/")
        let q = parts[0].split(separator: ".").map { UInt32($0)! }
        let net = q[0] << 24 | q[1] << 16 | q[2] << 8 | q[3]
        let len = Int(parts[1])!
        let m: UInt32 = len == 0 ? 0 : UInt32.max << UInt32(32 - len)
        return ip & m == net & m
    }

    func testCarveExcludedRoutes() {
        let t = tunnel
        let out = t.carve(excluded: CoreOverrides.defaultExcludedRoutes + ["fd00::/8", "junk"])
        XCTAssertFalse(out.contains("10.0.0.0/8"))
        for keep in ["172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "fd00::/8", "junk"] {
            XCTAssertTrue(out.contains(keep), keep)
        }
        let pieces = out.filter { $0.hasPrefix("10.") }
        XCTAssertEqual(pieces.count, 24, "/8 minus a /32 = 24 CIDRs")
        XCTAssertFalse(pieces.contains { covers($0, t.peer) }, "the peer is no longer excluded")
        for ip: UInt32 in [0x0A00_0000, 0x0A07_0000, 0x0A07_0002, 0x0A07_00FF, 0x0AFF_FFFF, 0x0A06_FFFF, 0x0A08_0000] {
            XCTAssertEqual(pieces.filter { covers($0, ip) }.count, 1, "\(NCLocalDeviceTunnel.dotted(ip)) covered exactly once")
        }
        XCTAssertTrue(out.allSatisfy { RouteSpec($0) != nil || $0 == "junk" }, "pieces are valid route lines")
        XCTAssertEqual(t.carve(excluded: ["10.7.0.1/32", "10.7.0.1"]), [], "an exact host exclusion is dropped")
        XCTAssertEqual(t.carve(excluded: ["192.168.0.0/16"]), ["192.168.0.0/16"])
    }
}
