import XCTest
@testable import Tern

// Coverage for PR #117 (fix/nc-dns) at the layer the unit-test target can
// see. The coalescing coordinator, the in-flight cap and the DoT/DoH pools
// themselves live in PacketTunnel/NativeCore/NCUDPSessions.swift, which is
// NOT part of the app / TernUnitTests target, so their behavior cannot be
// exercised from here without changing production project structure (out of
// scope for a test-only change; see the PR body). What CAN be pinned here
// is the wire-format contract the coordinator's correctness rests on:
//
//  - two queries that differ only in transaction ID are byte-identical
//    after the first two bytes (that is exactly the coordinator's merge
//    key), and
//  - a response whose first two bytes are replaced with a waiter's ID
//    still parses, carrying that ID and the untouched question / answers
//    (that is exactly the coordinator's fan-out rewrite).
final class NativeCoreDNSWireTests: XCTestCase {

    private func query(id: UInt16, name: String, type: UInt16 = NCDNSMessage.typeA) -> Data {
        var q = NCDNSMessage()
        q.id = id
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        return q.serialized()
    }

    func testQueriesDifferingOnlyInIDAreIdenticalPastTheID() {
        let a = query(id: 0x1234, name: "www.example.com")
        let b = query(id: 0xabcd, name: "www.example.com")
        XCTAssertEqual(a.count, b.count)
        XCTAssertNotEqual(Data(a.prefix(2)), Data(b.prefix(2)))
        XCTAssertEqual(Data(a.dropFirst(2)), Data(b.dropFirst(2)))
        // A different question is NOT the same query past the ID.
        let c = query(id: 0x1234, name: "other.example.com")
        XCTAssertNotEqual(Data(a.dropFirst(2)), Data(c.dropFirst(2)))
        // Neither is the same name with a different qtype.
        let d = query(id: 0x1234, name: "www.example.com", type: NCDNSMessage.typeAAAA)
        XCTAssertNotEqual(Data(a.dropFirst(2)), Data(d.dropFirst(2)))
    }

    func testResponseIDRewriteParsesWithWaiterID() {
        // Build one upstream response (ID 0x9000) with a compressed answer
        // name, then fan it out to two waiters by replacing the ID bytes,
        // exactly like NCDNSUpstreamCoordinator.deliver does.
        var resp = NCDNSMessage()
        resp.id = 0x9000
        resp.isResponse = true
        resp.recursionDesired = true
        resp.recursionAvailable = true
        resp.questions = [NCDNSQuestion(name: "www.example.com", type: NCDNSMessage.typeA, klass: NCDNSMessage.classIN)]
        resp.answers = [NCDNSRecord(name: "www.example.com", type: NCDNSMessage.typeA,
                                    klass: NCDNSMessage.classIN, ttl: 300,
                                    rdata: Data([93, 184, 216, 34]))]
        let wire = resp.serialized()
        for waiterID: UInt16 in [0x0001, 0xbeef] {
            var fanned = wire
            fanned[0] = UInt8(waiterID >> 8)
            fanned[1] = UInt8(waiterID & 0xff)
            let parsed = NCDNSMessage.parse(fanned)
            XCTAssertEqual(parsed?.id, waiterID)
            XCTAssertEqual(parsed?.questions, resp.questions)
            XCTAssertEqual(parsed?.answers, resp.answers)
            XCTAssertEqual(parsed?.isResponse, true)
        }
        // The untouched original still parses with the upstream ID.
        XCTAssertEqual(NCDNSMessage.parse(wire)?.id, 0x9000)
    }

    /// Parse → serialize is a fixed point for a plain query, so the
    /// coordinator can treat the question section as opaque bytes.
    func testQueryParseSerializeRoundTrip() {
        let wire = query(id: 42, name: "a.b.example.org", type: NCDNSMessage.typeAAAA)
        let parsed = NCDNSMessage.parse(wire)
        XCTAssertEqual(parsed?.id, 42)
        XCTAssertEqual(parsed?.questions.first?.name, "a.b.example.org")
        XCTAssertEqual(parsed?.questions.first?.type, NCDNSMessage.typeAAAA)
        XCTAssertEqual(parsed?.serialized(), wire)
    }
}

// The upstream value the forwarder keys its pools by: `NCDNSUpstream.of`
// flattens groups, dedupes identical servers and collapses a single server
// to itself — the preference order the failover walk (and #117's per-attempt
// coordination) relies on. Parsing itself is covered by
// NativeCoreDNSPolicyTests; grouping was not.
final class NativeCoreDNSUpstreamGroupTests: XCTestCase {
    func testOfFlattensDedupesAndCollapses() {
        let a = NCDNSUpstream.udp(host: "1.1.1.1", port: 53)
        let b = NCDNSUpstream.dot(host: "dns.example", port: 853)
        XCTAssertNil(NCDNSUpstream.of([]))
        XCTAssertEqual(NCDNSUpstream.of([a]), a)
        XCTAssertEqual(NCDNSUpstream.of([a, a, b]), .group([a, b]))
        XCTAssertEqual(NCDNSUpstream.of([.group([a, b]), a]), .group([a, b]))
        XCTAssertEqual(NCDNSUpstream.of([b, a])?.members, [b, a]) // order preserved
        XCTAssertEqual(a.members, [a])
    }
}
