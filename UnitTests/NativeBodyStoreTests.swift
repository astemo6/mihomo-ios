import CryptoKit
import XCTest
@testable import Mihomo

/// feat/native-mitm stage 1: NativeBodyStore (the native body lane) must decode exactly like the Go path. The
/// corpus NativeBodyFixtures.json is written by Go (bridge/mitm/nativelane_fixtures_test.go), every "ok" case
/// checked against the Go decoder there. Each case is fed in several chunk sizes so header / block / scratch
/// boundaries land everywhere.
final class NativeBodyStoreTests: XCTestCase {
    private struct Fixture: Decodable {
        let name: String
        let enc: String
        let data: String
        let limit: Int64
        let expect: String
        let len: Int?
        let sha256: String?
    }

    private func fixtures() throws -> [Fixture] {
        let bundle = Bundle(for: NativeBodyStoreTests.self)
        guard let url = bundle.url(forResource: "NativeBodyFixtures", withExtension: "json") else {
            XCTFail("NativeBodyFixtures.json missing from the test bundle")
            return []
        }
        return try JSONDecoder().decode([Fixture].self, from: Data(contentsOf: url))
    }

    private static func hex(_ d: Data) -> String {
        SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
    }

    func testDecodeCorpusInChunks() throws {
        let store = NativeBodyStore.shared
        for f in try fixtures() {
            guard let data = Data(base64Encoded: f.data) else { XCTFail("\(f.name): base64"); continue }
            for chunk in [1, 7, 333, 4096, 32 << 10, max(data.count, 1)] {
                let h = store.open(f.enc, limit: f.limit, hint: Int64(data.count))
                XCTAssertGreaterThan(h, 0, "\(f.name): refused")
                defer { store.free(h) }
                var verdict = ""
                var off = 0
                while off < data.count {
                    let end = min(data.count, off + chunk)
                    let r = store.write(h, b: data.subdata(in: off..<end))
                    off = end
                    if !r.isEmpty { verdict = r; break }
                }
                var n: Int64 = 0
                if verdict.isEmpty {
                    n = store.finish(h)
                    verdict = n >= 0 ? "ok" : (n == -2 ? "too-big" : (n == -1 ? "decode" : "internal"))
                } else {
                    verdict = verdict == "too-big" ? "too-big" : (verdict.hasPrefix("decode:") ? "decode" : "internal: " + verdict)
                }
                XCTAssertEqual(verdict, f.expect, "\(f.name) chunk \(chunk): \(store.err(h))")
                guard f.expect == "ok", verdict == "ok" else { continue }
                XCTAssertEqual(Int(n), f.len, "\(f.name) chunk \(chunk): length")
                // read back in pieces, as Go streams it to the client
                var out = Data()
                while true {
                    guard let piece = store.read(h, raw: false, off: Int64(out.count), n: 32 << 10), !piece.isEmpty else { break }
                    out.append(piece)
                }
                XCTAssertEqual(Self.hex(out), f.sha256, "\(f.name) chunk \(chunk): content")
                XCTAssertEqual(store.len(h, raw: true), Int64(data.count), "\(f.name): raw length")
                XCTAssertEqual(store.read(h, raw: true, off: 0, n: Int64(data.count)), data, "\(f.name): raw bytes kept")
            }
        }
    }

    func testRefusesUnknownEncodingAndForgetsHandles() {
        let store = NativeBodyStore.shared
        XCTAssertEqual(store.open("zstd", limit: 1 << 20, hint: -1), 0)
        XCTAssertEqual(store.open("gzip, br", limit: 1 << 20, hint: -1), 0)
        let h = store.open("", limit: 100, hint: -1)
        XCTAssertEqual(store.write(h, b: Data("hello".utf8)), "")
        XCTAssertEqual(store.finish(h), 5)
        store.free(h)
        XCTAssertEqual(store.len(h, raw: false), -1)
        XCTAssertNil(store.read(h, raw: false, off: 0, n: 10))
        XCTAssertEqual(store.write(h, b: Data([1])), "gone")
    }

    func testEngineSideStoreAndText() {
        let store = NativeBodyStore.shared
        let text = String(repeating: "数据", count: 50_000)
        var s = text
        let h = s.withUTF8 { store.store(UnsafeRawBufferPointer($0)) }
        XCTAssertGreaterThan(h, 0)
        defer { store.free(h) }
        XCTAssertEqual(store.text(h), text)
        var seen = 0
        XCTAssertTrue(store.withDecoded(h) { seen = $0.count })
        XCTAssertEqual(seen, text.utf8.count)
        // invalid UTF-8: no native text (the Go host owns the U+FFFD rules)
        let bad = [UInt8]([0xff, 0xfe, 0x41]).withUnsafeBytes { store.store($0) }
        defer { store.free(bad) }
        XCTAssertNil(store.text(bad))
    }
}
