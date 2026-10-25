import XCTest
@testable import Mihomo

/// Pure wire vectors for the hysteria2 auth exchange (QPACK, RFC 9204) and the
/// TCP request header. Vectors cross-checked off-device: the request block is
/// decoded by pylsqpack (ls-qpack) to exactly the expected field list, and the
/// response block was produced by pylsqpack's encoder (Huffman literals, the
/// shape quic-go/qpack emits from sing-box / hysteria servers).
final class NativeCoreHysteria2WireTests: XCTestCase {

    private static func hex(_ s: String) -> Data {
        var out = Data()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }

    func testAuthRequestEncoding() {
        let block = NCHy2.qpackEncodeAuthRequest(password: "pw", padding: "pp")
        XCTAssertEqual(block, Self.hex(
            "0000d4d751052f6175746850086879737465726961270668797374657269612d61757468027077"
            + "270768797374657269612d63632d72780130270968797374657269612d70616464696e67027070"))
    }

    func testAuthRequestRoundTrip() throws {
        let block = NCHy2.qpackEncodeAuthRequest(password: "nc-loop-hy2-pw", padding: "abc")
        let fields = try XCTUnwrap(NCHy2.qpackDecodeFieldSection(block))
        XCTAssertEqual(fields.map { "\($0.name)=\($0.value)" }, [
            ":method=POST", ":scheme=https", ":path=/auth", ":authority=hysteria",
            "hysteria-auth=nc-loop-hy2-pw", "hysteria-cc-rx=0", "hysteria-padding=abc",
        ])
    }

    func testAuthResponseDecodingHuffman() throws {
        let block = Self.hex(
            "00005f09033233332f029fd2125b0c35ad92bf834d96972f039fd2125b0c358845acf301302f059fd2125b0c35ab1c921aa9bf88f3ebdf9f5efcfaf7")
        let fields = try XCTUnwrap(NCHy2.qpackDecodeFieldSection(block))
        XCTAssertEqual(fields.map { "\($0.name)=\($0.value)" }, [
            ":status=233", "hysteria-udp=true", "hysteria-cc-rx=0", "hysteria-padding=xyzxyzxyz",
        ])
    }

    func testStaticTableMatchesRFC9204() {
        XCTAssertEqual(NCHy2.qpackStaticTable.count, 99)
        XCTAssertEqual(NCHy2.qpackStaticTable[20].name, ":method")
        XCTAssertEqual(NCHy2.qpackStaticTable[20].value, "POST")
        XCTAssertEqual(NCHy2.qpackStaticTable[23].value, "https")
        XCTAssertEqual(NCHy2.qpackStaticTable[24].name, ":status")
        XCTAssertEqual(NCHy2.qpackStaticTable[98].value, "sameorigin")
    }

    func testTCPRequestHeaderCarriesFrameType() {
        let header = NCHy2.tcpRequestHeader(target: NCTarget(host: "127.0.0.1", port: 18080), padding: Data())
        var expected = Data([0x44, 0x01, 0x0f])
        expected.append(Data("127.0.0.1:18080".utf8))
        expected.append(0x00)
        XCTAssertEqual(header, expected)
    }
}
