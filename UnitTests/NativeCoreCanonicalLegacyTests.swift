import XCTest
@testable import Mihomo

/// The canonical → legacy bridge must carry DNS semantics across, since
/// the .conf runtime-load path feeds the engine through it.
final class NativeCoreCanonicalLegacyTests: XCTestCase {
    func testLegacyConfigCarriesDNS() {
        var canonical = NCCanonicalConfig(sourceFormat: "surge")
        canonical.dns.mode = .redirHost
        canonical.dns.fakeIPRange4 = "198.18.0.1/16"
        canonical.dns.fakeIPRange6 = "fd00::/64"
        canonical.dns.alwaysRealIP = ["*.lan", "time.apple.com"]
        canonical.dns.defaultServers = [NCDNSServerRef.parse("8.8.8.8"),
                                         NCDNSServerRef.parse("https://dns.google/dns-query")]
        let legacy = canonical.legacyConfig()
        XCTAssertEqual(legacy.dns.enhancedMode, "redir-host")
        XCTAssertEqual(legacy.dns.fakeIPRange, "198.18.0.1/16")
        XCTAssertEqual(legacy.dns.fakeIPRange6, "fd00::/64")
        XCTAssertEqual(legacy.dns.fakeIPFilter, ["*.lan", "time.apple.com"])
        XCTAssertEqual(legacy.dns.nameservers, ["8.8.8.8", "https://dns.google/dns-query"])

        var fake = NCCanonicalConfig(sourceFormat: "loon")
        fake.dns.mode = .fakeIP
        XCTAssertEqual(fake.legacyConfig().dns.enhancedMode, "fake-ip")
    }
}
