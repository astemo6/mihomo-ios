import XCTest
@testable import Tern

/// parse-pure-ip gates whether a bare-IP flow's SNI is read before routing.
/// With it off, the rule engine matches such flows by IP only and every DOMAIN
/// rule in every rule-set is dead for HTTPDNS apps (device 2026-10-28: Baidu
/// Maps ads — QX rejected a dozen ad domains from the fmz200 list, Tern only
/// its IP-CIDR lines). QX-style configs carry no such switch, so an absent
/// field must mean ON; an explicit false stays honored.
final class NativeCoreSnifferConfigTests: XCTestCase {

    func testParsePureIPDefaultsOnWhenAbsent() {
        let cfg = NCSnifferConfig(fields: ["enable": .bool(true)])
        XCTAssertTrue(cfg.parsePureIP, "absent parse-pure-ip must default on (QX parity)")
    }

    func testParsePureIPHonorsExplicitValues() {
        XCTAssertFalse(NCSnifferConfig(fields: ["parse-pure-ip": .bool(false)]).parsePureIP)
        XCTAssertTrue(NCSnifferConfig(fields: ["parse-pure-ip": .bool(true)]).parsePureIP)
    }
}
