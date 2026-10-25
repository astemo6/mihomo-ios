import XCTest
@testable import Mihomo

/// fix/nc-followup-b: numeric-boundary sweep (Shared/NativeCore + App/Core). Every case below used to trap
/// (Int(Double) past 2^63, Int overflow, a reversed range, a huge reserveCapacity, unbounded recursion) on a
/// value that comes from a config, a subscription, a module or a downloaded / network-parsed file.
final class NativeCoreNumericBoundaryTests: XCTestCase {

    // MARK: NCJSONValue.int / NCProxy.port / ncInt / InspectProxy

    func testJSONIntRejectsNonFiniteAndOutOfRange() {
        XCTAssertNil(NCJSONValue.number(1e30).int)
        XCTAssertNil(NCJSONValue.number(9_223_372_036_854_775_808.0).int) // 2^63 == Double(Int.max)
        XCTAssertNil(NCJSONValue.number(-1e19).int)
        XCTAssertNil(NCJSONValue.number(.nan).int)
        XCTAssertNil(NCJSONValue.number(.infinity).int)
        XCTAssertEqual(NCJSONValue.number(-9_223_372_036_854_775_808.0).int, Int.min) // -2^63 is representable
        XCTAssertEqual(NCJSONValue.number(443.9).int, 443) // in range: truncation unchanged
        XCTAssertEqual(NCJSONValue.string("8080").int, 8080)
    }

    func testProxyPortOutsideU16ReadsAsAbsent() {
        func port(_ v: NCJSONValue) -> Int? { NCProxy(name: "n", type: "ss", fields: ["port": v]).port }
        XCTAssertEqual(port(.number(443)), 443)
        XCTAssertEqual(port(.number(0)), 0)
        XCTAssertEqual(port(.number(65535)), 65535)
        XCTAssertNil(port(.number(65536)))
        XCTAssertNil(port(.number(-1)))
        XCTAssertNil(port(.number(1e30)))
        XCTAssertNil(port(.string("70000")))
    }

    func testNcIntNeverTraps() {
        XCTAssertEqual(ncInt(.number(42)), 42)
        XCTAssertEqual(ncInt(.number(1e300)), 0)
        XCTAssertEqual(ncInt(.number(-1e19)), 0)
        XCTAssertEqual(ncInt(.number(9_223_372_036_854_775_808.0)), 0)
        XCTAssertEqual(ncInt(.number(.nan)), 0)
    }

    func testInspectProxyHugeDoublePort() {
        let huge = NCProfileInspectorPort.toInspectProxy(["name": "a", "type": "ss", "port": 1e30] as [String: Any])
        XCTAssertNil(huge.port)
        let ok = NCProfileInspectorPort.toInspectProxy(["name": "a", "type": "ss", "port": 443.0] as [String: Any])
        XCTAssertEqual(ok.port, 443)
    }

    // MARK: Sniffer ports

    func testSnifferNumericPortsSkipNonPorts() {
        let ports = NCSnifferConfig.parsePorts(.array([.number(1e30), .number(80), .number(.nan), .number(-1),
                                                       .number(70000), .string("8000-9000")]))
        XCTAssertEqual(ports, [80...80, 8000...9000])
    }

    // MARK: Hysteria v1 / TUIC config arithmetic

    func testHy1SpeedMultiplicationOverflow() {
        XCTAssertEqual(NCHy1.mbpsToBytes(100), 12_500_000)
        XCTAssertEqual(NCHy1.mbpsToBytes(Int.max), 0)
        XCTAssertEqual(NCHy1.mbpsToBytes(-5), 0)
        let q = DispatchQueue(label: "nb.hy1")
        let hugeUp = NCProxy(name: "h", type: "hysteria", fields: [
            "server": .string("1.2.3.4"), "port": .number(443),
            "up-speed": .number(1e17), "down-speed": .number(10),
        ])
        XCTAssertNil(NCHysteria1Connection(proxy: hugeUp, queue: q)) // overflow → 0 → invalid, no trap
    }

    func testHy1OversizedAuthRejected() {
        let p = NCProxy(name: "h", type: "hysteria", fields: [
            "server": .string("1.2.3.4"), "port": .number(443),
            "up": .string("10"), "down": .string("10"),
            "auth-str": .string(String(repeating: "a", count: 70_000)),
        ])
        XCTAssertNil(NCHysteria1Connection(proxy: p, queue: DispatchQueue(label: "nb.hy1a")))
        XCTAssertEqual(NCHy1.clientHello(sendBPS: 1, recvBPS: 1, auth: Data(repeating: 1, count: 70_000)).count,
                       1 + 8 + 8 + 2 + 0xffff) // builder caps, never traps
    }

    func testTUICRelayPacketSizeNearIntMax() {
        let p = NCProxy(name: "t", type: "tuic", fields: [
            "server": .string("1.2.3.4"), "port": .number(443), "token": .string("tk"),
            "max-udp-relay-packet-size": .string("9223372036854775807"),
        ])
        let c = NCTUICConnection(proxy: p, queue: DispatchQueue(label: "nb.tuic"))
        XCTAssertNotNil(c)
        XCTAssertEqual(c?.udpMaxPacket, 1400 - NCTUICUDP.overheadV4)
    }

    // MARK: Wire builders fed config strings

    func testClientHelloWithHugeServerNameAndALPN() {
        let hello = NCTLS13.buildClientHello(random: Data(count: 32), sessionID: Data(count: 32),
                                             serverName: String(repeating: "a", count: 70_000),
                                             alpn: Array(repeating: String(repeating: "h", count: 255), count: 300),
                                             keyShare: Data(count: 32))
        XCTAssertLessThan(hello.count, 65_536)
    }

    func testSimpleObfsTLSHugeHost() {
        let hello = NCSSPlugin.obfsTLSClientHello(host: String(repeating: "a", count: 70_000), payload: Data([1, 2, 3]))
        XCTAssertGreaterThan(hello.count, 0)
    }

    func testSnellHeadersCapHostLength() {
        let long = String(repeating: "a", count: 300)
        let udp = NCSnell.udpFrame(target: NCTarget(host: long, port: 70_000), payload: Data())
        XCTAssertEqual(udp[1], 255)
        let tcp = NCSnell.connectHeader(host: long, port: 443, version: 2)
        XCTAssertEqual(tcp[3], 255)
    }

    // MARK: Downloaded files: MaxMind DB, MRS rule sets

    private static let mmdbMarker: [UInt8] = [0xab, 0xcd, 0xef] + Array("MaxMind.com".utf8)
    private static func mmdbKey(_ s: String) -> [UInt8] { [0x40 | UInt8(s.utf8.count)] + Array(s.utf8) }
    private static func mmdb(_ meta: [UInt8], prefix: Int = 64) -> Data {
        Data(repeating: 0, count: prefix) + Data(mmdbMarker) + Data(meta)
    }

    func testMMDBHugeNodeCountRejected() {
        // {node_count: uint64 2^62, record_size: uint16 24}: node_count * record_size * 2 overflowed Int.
        let meta = [0xE2] + Self.mmdbKey("node_count") + [0x08, 0x02, 0x40, 0, 0, 0, 0, 0, 0, 0]
            + Self.mmdbKey("record_size") + [0xA1, 24]
        XCTAssertNil(NCMMDB(data: Self.mmdb(meta)))
    }

    func testMMDBTreeLargerThanFileOrBadRecordSize() {
        let big = [0xE2] + Self.mmdbKey("node_count") + [0xA2, 0x03, 0xE8] + Self.mmdbKey("record_size") + [0xA1, 24]
        XCTAssertNil(NCMMDB(data: Self.mmdb(big)))
        let odd = [0xE2] + Self.mmdbKey("node_count") + [0xA1, 1] + Self.mmdbKey("record_size") + [0xA1, 7]
        XCTAssertNil(NCMMDB(data: Self.mmdb(odd)))
        let ok = [0xE2] + Self.mmdbKey("node_count") + [0xA1, 1] + Self.mmdbKey("record_size") + [0xA1, 24]
        XCTAssertNotNil(NCMMDB(data: Self.mmdb(ok)))
    }

    func testMMDBSelfReferencingPointerTerminates() {
        // {"a": pointer 0} where pointer 0 is the map itself: recursed until the stack overflowed.
        let meta = [0xE1] + Self.mmdbKey("a") + [0x20, 0x00]
        XCTAssertNil(NCMMDB(data: Self.mmdb(meta)))
    }

    private static func be64(_ v: Int64) -> [UInt8] {
        let u = UInt64(bitPattern: v)
        return (0..<8).map { UInt8(truncatingIfNeeded: u >> (56 - 8 * UInt64($0))) }
    }

    func testMRSHugeExtraLengthThrows() {
        let data = Data(NCMRS.mrsMagic + [0] + Self.be64(0) + Self.be64(Int64.max))
        XCTAssertThrowsError(try NCMRS.parseHeader(from: data))
    }

    func testMRSHugeLeavesLengthThrows() {
        var reader = NCMRSByteReader(data: Data([1] + Self.be64(1 << 60) + Self.be64(0)))
        XCTAssertThrowsError(try NCMRSDomainSet.decode(reader: &reader, ruleCount: 0))
    }

    // MARK: DoH HTTP framing (network-parsed integers)

    func testDoHChunkSizeAndContentLengthBounds() {
        func parse(_ s: String) -> NCDNSDoHPool.ResponseParse { NCDNSDoHPool.parseResponse(Data(s.utf8)) }
        XCTAssertEqual(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nabc\r\n"), .malformed)
        XCTAssertEqual(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7fffffffffffffff\r\nabc\r\n"), .malformed)
        XCTAssertEqual(parse("HTTP/1.1 200 OK\r\nContent-Length: -1\r\nX-A: b\r\n\r\nabc"), .malformed)
        XCTAssertEqual(parse("HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\nX-A: b\r\n\r\nabc"), .malformed)
        let okText = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-A: b\r\n\r\nabc"
        XCTAssertEqual(parse(okText), .complete(body: Data("abc".utf8), consumed: okText.utf8.count, keepAlive: true))
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        XCTAssertEqual(parse(chunked), .complete(body: Data("abc".utf8), consumed: chunked.utf8.count, keepAlive: true))
        XCTAssertEqual(parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nX-A: b\r\n\r\nabc"), .incomplete)
    }

    // MARK: Script timeout (module `timeout=`)

    func testScriptTimeoutOverflowClamps() {
        var sc = NCEngineScript()
        sc.timeout = 9_999_999_999_999_999
        XCTAssertEqual(NCScriptManifest.scriptTimeout(sc: sc, maxTimeoutMs: 60_000, defTimeoutMs: 10_000), 60_000)
        sc.timeout = -9_999_999_999_999_999
        XCTAssertEqual(NCScriptManifest.scriptTimeout(sc: sc, maxTimeoutMs: 60_000, defTimeoutMs: 10_000), 10_000)
        sc.timeout = 5
        XCTAssertEqual(NCScriptManifest.scriptTimeout(sc: sc, maxTimeoutMs: 60_000, defTimeoutMs: 10_000), 5_000)
    }
}
