import XCTest
@testable import Tern

/// fix/nc-masque-ip: MASQUE CONNECT-IP (RFC 9484) wire helpers, node classification and the App-side refusal. The data
/// plane itself (lwIP netif) is PacketTunnel code, exercised by E2ETests/NCMASQUEIPLoopbackTests against a real proxy.
final class NativeCoreMASQUEIPTests: XCTestCase {
    private func node(_ extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = [
            "server": .string("203.0.113.7"), "port": .number(443),
            "mode": .string("connect-ip"), "uri": .string("https://proxy.example:4433/vpn"),
        ]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "mq-ip", type: "masque", fields: f)
    }

    func testGenericConnectIPNodeParses() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node()))
        XCTAssertEqual(cfg.mode, .connectIP)
        XCTAssertNil(NCSupport.masqueUnsupported(node()), "credential-less RFC 9484 node is structurally valid")
    }

    func testConnectIPGatedUntilVerified() {
        let why = NCSupport.unsupportedReason(node())
        if NCMASQUE.connectIPVerified {
            XCTAssertNil(why)
        } else {
            XCTAssertEqual(why, NCMASQUE.connectIPUnverified)
        }
    }

    func testWARPKeyPairStaysUnavailable() {
        let warp = node([
            "private-key": .string("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTESTPRIV"),
            "public-key": .string("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETESTPUB"),
            "ip": .string("172.16.0.2"),
        ])
        XCTAssertEqual(NCSupport.masqueUnsupported(warp), NCMASQUE.warpUnavailable)
        XCTAssertEqual(NCSupport.unsupportedReason(warp), NCMASQUE.warpUnavailable)
    }

    func testConnectIPOverH2Unavailable() {
        XCTAssertEqual(NCSupport.masqueUnsupported(node(["network": .string("h2")]))?.contains("HTTP/2"), true)
    }

    func testRequestTargetFromAbsoluteTemplate() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node()))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "proxy.example:4433")
        XCTAssertEqual(t.path, "/vpn")
    }

    func testRequestTargetExpandsWildcards() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node(["uri": .string("https://h.example/.well-known/masque/ip/{target}/{ipproto}/")])))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "h.example")
        XCTAssertEqual(t.path, "/.well-known/masque/ip/*/*/")
    }

    func testRequestTargetPathOnlyUsesServerPort() throws {
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: node(["uri": .string("/vpn")])))
        let t = NCMASQUE.connectIPRequestTarget(cfg)
        XCTAssertEqual(t.authority, "203.0.113.7:443")
        XCTAssertEqual(t.path, "/vpn")
    }

    func testConnectIPDatagramLayout() {
        let pkt: [UInt8] = [0x45, 0, 0, 20] + [UInt8](repeating: 0, count: 16)
        let d = pkt.withUnsafeBufferPointer { NCMASQUE.connectIPDatagram(quarterStreamID: 100, packet: $0) }
        // quarter stream id 100 -> 2-byte varint 0x40 0x64, context id 0, then the packet unchanged
        XCTAssertEqual([UInt8](d.prefix(3)), [0x40, 0x64, 0x00])
        XCTAssertEqual([UInt8](d.dropFirst(3)), pkt)
        let back = NCMASQUE.decodeH3Datagram(d)
        XCTAssertEqual(back?.streamID, 400)
        XCTAssertEqual(back?.contextID, 0)
        XCTAssertEqual(back.map { [UInt8]($0.payload) }, pkt)
    }

    func testFrameHeaderIncomplete() {
        XCTAssertNil(NCMASQUE.h3FrameHeader(Data([0x00]), at: 0))
        let h = NCMASQUE.h3FrameHeader(Data([0x00, 0x05, 1, 2]), at: 0)
        XCTAssertEqual(h?.type, 0)
        XCTAssertEqual(h?.length, 5)
        XCTAssertEqual(h?.header, 2)
    }

    func testAddressAssignAndRouteCapsulesRoundTrip() {
        let a = NCMASQUE.AssignedAddress(requestID: 0, ipVersion: 4, address: Data([10, 89, 0, 2]), prefixLength: 32)
        XCTAssertEqual(NCMASQUE.AssignedAddress.decodeSequence(a.encode()), [a])
        let r = NCMASQUE.RouteAdvertisement(ipVersion: 4, startIP: Data([10, 89, 1, 0]), endIP: Data([10, 89, 1, 255]), ipProtocol: 0)
        XCTAssertEqual(NCMASQUE.RouteAdvertisement.decodeSequence(r.encode()), [r])
        var p = NCMASQUE.CapsuleParser()
        let wire = NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeAddressAssign, value: a.encode())
            + NCMASQUE.encodeCapsule(type: NCMASQUE.capsuleTypeRouteAdvertisement, value: r.encode())
        let caps = p.feed(wire.prefix(5)) + p.feed(wire.dropFirst(5))
        XCTAssertEqual(caps.map(\.type), [1, 3])
    }

    /// Outside the packet tunnel (the App's 延迟测试) there is no netif: the connector refuses explicitly.
    func testAppConnectorRefusesTunnelOnly() {
        let exp = expectation(description: "refused")
        NCConnector.connect(target: NCTarget(host: "10.0.0.1", port: 80), proxy: node(), queue: DispatchQueue(label: "t")) { s, e in
            XCTAssertNil(s)
            XCTAssertTrue("\(String(describing: e))".contains("CONNECT-IP"), "\(String(describing: e))")
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }
}
