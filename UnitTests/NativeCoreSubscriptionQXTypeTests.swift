import XCTest
@testable import Mihomo

/// fix/nc-followup-b task 2: QX `ss=` / `snell=` / `tuic=` lines in plain-text subscriptions go to the QX
/// builder; a Surge line whose NAME is such a word still goes to the Surge parser.
final class NativeCoreSubscriptionQXTypeTests: XCTestCase {

    private let body = """
    ss=1.2.3.4:8388, method=aes-128-gcm, password=pw, tag=QX SS
    snell=5.6.7.8:443, psk=abc123, version=4, tag=QX Snell
    tuic=9.9.9.9:443, uuid=00000000-0000-0000-0000-000000000001, password=123456, sni=t.example.com, tag=QX TUIC
    ss=[2001:db8::1]:8389, method=aes-256-gcm, password=pw6, tag=QX V6
    snell = snell, 6.6.6.6, 444, psk=xyz, version=3
    http = http, 7.7.7.7, 8080
    """

    func testQXLinesAndSurgeLinesNamedLikeQXTypes() {
        let nodes = NCSubscriptionParser.parse(body)
        XCTAssertEqual(nodes.map { $0.name }, ["QX SS", "QX Snell", "QX TUIC", "QX V6", "snell", "http"])
        XCTAssertEqual(nodes.map { $0.type }, ["ss", "snell", "tuic", "ss", "snell", "http"])

        let ss = nodes[0]
        XCTAssertEqual(ss.server, "1.2.3.4"); XCTAssertEqual(ss.port, 8388)
        XCTAssertEqual(ss.cipher, "aes-128-gcm"); XCTAssertEqual(ss.password, "pw")

        let snell = nodes[1]
        XCTAssertEqual(snell.server, "5.6.7.8"); XCTAssertEqual(snell.port, 443)
        XCTAssertEqual(snell.password, "abc123"); XCTAssertEqual(snell.fields["version"]?.int, 4)

        let tuic = nodes[2]
        XCTAssertEqual(tuic.server, "9.9.9.9"); XCTAssertEqual(tuic.port, 443)
        XCTAssertEqual(tuic.uuid, "00000000-0000-0000-0000-000000000001")
        XCTAssertEqual(tuic.fields["password"], .string("123456")) // stays a string, not coerced to a number
        XCTAssertEqual(tuic.fields["sni"], .string("t.example.com"))

        let v6 = nodes[3]
        XCTAssertEqual(v6.server, "2001:db8::1"); XCTAssertEqual(v6.port, 8389)

        let surgeSnell = nodes[4]
        XCTAssertEqual(surgeSnell.server, "6.6.6.6"); XCTAssertEqual(surgeSnell.port, 444)
        XCTAssertEqual(surgeSnell.password, "xyz"); XCTAssertEqual(surgeSnell.fields["version"]?.int, 3)

        let surgeHTTP = nodes[5]
        XCTAssertEqual(surgeHTTP.server, "7.7.7.7"); XCTAssertEqual(surgeHTTP.port, 8080)
    }

    func testIsQXNodeLineDisambiguatesByValueShape() {
        XCTAssertTrue(NCSubscriptionParser.isQXNodeLine(key: "snell", value: "1.2.3.4:443, psk=x"))
        XCTAssertTrue(NCSubscriptionParser.isQXNodeLine(key: "ss", value: "[::1]:443, method=a"))
        XCTAssertFalse(NCSubscriptionParser.isQXNodeLine(key: "snell", value: " snell, 1.2.3.4, 443"))
        XCTAssertFalse(NCSubscriptionParser.isQXNodeLine(key: "snell", value: " snell, 2001:db8::1, 443"))
        XCTAssertFalse(NCSubscriptionParser.isQXNodeLine(key: "my node", value: "1.2.3.4:443"))
        XCTAssertFalse(NCSubscriptionParser.isQXNodeLine(key: "wireguard", value: "1.2.3.4:443"))
    }
}
