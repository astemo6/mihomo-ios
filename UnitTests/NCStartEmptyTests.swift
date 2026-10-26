import XCTest
@testable import Tern

/// fix/nc-start-empty (build 382 device report): DNS default upstream when `nameserver` has nothing forwardable,
/// page loads cancelled by navigation are not errors, and a stuck start no longer blocks 启动 forever.
final class NCStartEmptyTests: XCTestCase {

    // MARK: DNS default upstream

    func testSystemOnlyNameserverFallsBackToDefaultNameserver() {
        let u = NCDNSUpstream.firstUsable([["system"], ["223.5.5.5", "119.29.29.29"], []])
        XCTAssertEqual(u, .group([.udp(host: "223.5.5.5", port: 53), .udp(host: "119.29.29.29", port: 53)]))
    }

    func testDHCPOnlyNameserverFallsBackToProxyServerNameserver() {
        let u = NCDNSUpstream.firstUsable([["dhcp://en0", "system"], [], ["1.1.1.1"]])
        XCTAssertEqual(u, .udp(host: "1.1.1.1", port: 53))
    }

    func testForwardableNameserverWinsOverBootstrapLists() {
        let u = NCDNSUpstream.firstUsable([["system", "https://dns.alidns.com/dns-query"], ["223.5.5.5"]])
        XCTAssertEqual(u, .doh(url: "https://dns.alidns.com/dns-query"))
    }

    func testNothingForwardableAnywhereIsNil() {
        XCTAssertNil(NCDNSUpstream.firstUsable([["system"], ["dhcp://system"], []]))
        XCTAssertNil(NCDNSUpstream.firstUsable([]))
    }

    func testDNSConfigExposesBootstrapLists() {
        let dns = NCDNSConfig(fields: [
            "nameserver": .array([.string("system")]),
            "default-nameserver": .array([.string("223.5.5.5")]),
            "proxy-server-nameserver": .array([.string("119.29.29.29")]),
        ])
        XCTAssertEqual(dns.nameservers, ["system"])
        XCTAssertEqual(dns.defaultNameservers, ["223.5.5.5"])
        XCTAssertEqual(dns.proxyServerNameservers, ["119.29.29.29"])
        XCTAssertEqual(NCDNSUpstream.firstUsable([dns.nameservers, dns.defaultNameservers, dns.proxyServerNameservers]),
                       .udp(host: "223.5.5.5", port: 53))
    }

    // MARK: cancellation is not an error

    func testCancellationDetection() {
        XCTAssertTrue(ControllerClient.isCancellation(CancellationError()))
        XCTAssertTrue(ControllerClient.isCancellation(URLError(.cancelled)))
        XCTAssertTrue(ControllerClient.isCancellation(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)))
        XCTAssertFalse(ControllerClient.isCancellation(URLError(.timedOut)))
        XCTAssertFalse(ControllerClient.isCancellation(ControllerClient.APIError.unreachable))
    }

    // MARK: start re-entrancy guard

    func testStartAllowedWhenNothingInFlight() {
        XCTAssertTrue(VPNManager.mayStart(inFlightSince: nil))
    }

    func testStartIgnoredWhileARecentStartRuns() {
        let now = Date()
        XCTAssertFalse(VPNManager.mayStart(inFlightSince: now.addingTimeInterval(-5), now: now))
    }

    func testStuckStartNoLongerBlocks() {
        let now = Date()
        XCTAssertTrue(VPNManager.mayStart(inFlightSince: now.addingTimeInterval(-(VPNManager.startStuckAfter + 1)), now: now))
    }
}
