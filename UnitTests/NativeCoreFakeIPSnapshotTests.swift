import XCTest
@testable import Mihomo

// Coverage for PR #117 (fix/nc-dns), fake-IP persistence half: the snapshot
// format went to v2 (version field + IPv6 offset pairs), restore is bounded
// by the pool capacity, and reload now persists the outgoing pool before it
// is swapped (engine side — here only the pool contract is exercised).
// The basic v4 snapshot round trip already lives in
// NativeCoreTests.NativeCoreFakeIPTests.testPool; this file covers what
// #117 changed or added on top of it.
final class NativeCoreFakeIPSnapshotTests: XCTestCase {

    private func tempFile() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-fakeip-\(UUID().uuidString).json")
    }

    /// v2 round trip through the real file path (persist(to:) + restore(data:)),
    /// including IPv6 mappings — v6 pairs were not persisted at all before v2.
    func testPersistRestoreFileRoundTripWithV6() throws {
        let url = tempFile()
        defer { try? FileManager.default.removeItem(at: url) }
        let pool = NCFakeIPPool(range: "198.18.0.1/16", range6: "fd00::/120")
        let a4 = pool.address(for: "alpha.example")
        let b4 = pool.address(for: "beta.example")
        let a6 = pool.address6(for: "alpha.example")
        let b6 = pool.address6(for: "beta.example")
        XCTAssertNotNil(a6)
        XCTAssertNotNil(b6)
        pool.persist(to: url)
        let data = try Data(contentsOf: url)
        // On-disk shape: v2 stamps its version; both pair tables are present.
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["version"] as? Int, 2)
        XCTAssertNotNil(obj["pairs"])
        XCTAssertNotNil(obj["pairs6"])

        let restored = NCFakeIPPool(range: "198.18.0.1/16", range6: "fd00::/120")
        restored.restore(data: data)
        XCTAssertEqual(restored.address(for: "alpha.example"), a4)
        XCTAssertEqual(restored.address(for: "beta.example"), b4)
        XCTAssertEqual(restored.address6(for: "alpha.example"), a6)
        XCTAssertEqual(restored.address6(for: "beta.example"), b6)
        XCTAssertEqual(restored.host(for: a4), "alpha.example")
        if let a6 { XCTAssertEqual(restored.host(for: a6), "alpha.example") }
    }

    /// A pre-v2 file (no version field — the v1 layout) must be silently
    /// dropped, not resurrected: restore leaves the pool empty and the pool
    /// keeps allocating from the start of the usable range.
    func testV1SnapshotIsSilentlyDiscarded() throws {
        let base: UInt32 = 0xc612_0000 // 198.18.0.0
        let v1: [String: Any] = ["base": base, "pairs": ["old.example": base + 4]]
        let v1Data = try JSONSerialization.data(withJSONObject: v1)
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        pool.restore(data: v1Data)
        XCTAssertEqual(pool.size, 0)
        XCTAssertNil(pool.host(for: .v4(base + 4)))
        // First allocation is the first usable offset (.4), unaffected by the file.
        XCTAssertEqual(pool.address(for: "fresh.example"), .v4(base + 4))
    }

    /// A stamped-but-wrong version is dropped the same way.
    func testWrongVersionIsSilentlyDiscarded() throws {
        let base: UInt32 = 0xc612_0000
        let v3: [String: Any] = ["version": 3, "base": base, "pairs": ["old.example": base + 4], "pairs6": [String: Int]()]
        let v3Data = try JSONSerialization.data(withJSONObject: v3)
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        pool.restore(data: v3Data)
        XCTAssertEqual(pool.size, 0)
    }

    /// Corrupt / truncated / non-JSON payloads never throw and never
    /// partially restore.
    func testCorruptSnapshotIsSilentlyDiscarded() {
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        pool.restore(data: Data([0x00, 0xff, 0x10, 0x80]))
        pool.restore(data: Data("{\"version\":2,\"base\":".utf8))
        pool.restore(data: Data())
        XCTAssertEqual(pool.size, 0)
    }

    /// A snapshot written for a different range (base mismatch) is dropped.
    func testBaseMismatchIsDiscarded() throws {
        let src = NCFakeIPPool(range: "198.18.0.1/16")
        _ = src.address(for: "alpha.example")
        let data = try XCTUnwrap(src.snapshotData())
        let other = NCFakeIPPool(range: "198.19.0.1/16")
        other.restore(data: data)
        XCTAssertEqual(other.size, 0)
    }

    /// Restore is capped by the receiving pool's capacity: a snapshot with
    /// more live mappings than the pool may hold restores only the lowest
    /// `capacity` addresses (restore walks pairs in address order).
    func testRestoreRespectsReceivingPoolCapacity() throws {
        let src = NCFakeIPPool(range: "198.18.0.1/16")
        var addrs: [NCIP] = []
        for i in 0..<6 { addrs.append(src.address(for: "h\(i).example")) }
        let data = try XCTUnwrap(src.snapshotData())
        // Same base, /29 range (offsets 1...6 usable) but maxEntries 2: the
        // cap — not the range — is what drops h2 (offset 6 is in range).
        let small = NCFakeIPPool(range: "198.18.0.1/29", maxEntries: 2)
        small.restore(data: data)
        XCTAssertEqual(small.size, 2)
        for i in 0..<2 { XCTAssertEqual(small.host(for: addrs[i]), "h\(i).example") }
        for i in 2..<6 { XCTAssertNil(small.host(for: addrs[i])) }
    }

    /// Addresses a pool may never hand out (network / gateway / reserved,
    /// offsets below firstOff) are filtered on restore even when a (stale or
    /// hand-edited) v2 file contains them.
    func testRestoreDropsReservedAddresses() throws {
        let base: UInt32 = 0xc612_0000
        let craftedObj: [String: Any] = ["version": 2, "base": base,
            "pairs": ["net.example": base, "gw.example": base + 1, "ok.example": base + 4],
            "pairs6": [String: Int]()]
        let crafted = try JSONSerialization.data(withJSONObject: craftedObj)
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        pool.restore(data: crafted)
        XCTAssertEqual(pool.size, 1)
        XCTAssertEqual(pool.host(for: .v4(base + 4)), "ok.example")
        XCTAssertNil(pool.host(for: .v4(base)))
        XCTAssertNil(pool.host(for: .v4(base + 1)))
    }

    /// Duplicate addresses in a file (two hosts, one address) keep only one
    /// mapping — the pool never reports an address for two hosts.
    func testRestoreDedupesAddresses() throws {
        let base: UInt32 = 0xc612_0000
        let craftedObj: [String: Any] = ["version": 2, "base": base,
            "pairs": ["one.example": base + 4, "two.example": base + 4],
            "pairs6": [String: Int]()]
        let crafted = try JSONSerialization.data(withJSONObject: craftedObj)
        let pool = NCFakeIPPool(range: "198.18.0.1/16")
        pool.restore(data: crafted)
        XCTAssertEqual(pool.size, 1)
        XCTAssertNotNil(pool.host(for: .v4(base + 4)))
    }
}
