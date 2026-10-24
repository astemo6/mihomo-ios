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

    /// Feeds data in chunks; "ok" / "too-big" / "decode" / "internal: …" and the decoded length.
    private static func run(_ store: NativeBodyStore, _ h: Int64, _ data: Data, chunk: Int) -> (String, Int64) {
        var off = 0
        while off < data.count {
            let end = min(data.count, off + chunk)
            let r = store.write(h, b: data.subdata(in: off..<end))
            off = end
            if !r.isEmpty { return (r == "too-big" ? "too-big" : (r.hasPrefix("decode:") ? "decode" : "internal: " + r), -1) }
        }
        let n = store.finish(h)
        return (n >= 0 ? "ok" : (n == -2 ? "too-big" : (n == -1 ? "decode" : "internal")), n)
    }

    private func fixture(_ name: String) throws -> (Fixture, Data) {
        let f = try XCTUnwrap(try fixtures().first { $0.name == name }, name)
        return (f, try XCTUnwrap(Data(base64Encoded: f.data), name))
    }

    /// Like Go's compress/gzip: the CRC-32 / ISIZE trailer of every member is checked.
    func testGzipTrailerChecked() throws {
        let store = NativeBodyStore.shared
        let (f, data) = try fixture("gzip-plain")
        for (what, at) in [("crc", data.count - 8), ("isize", data.count - 4)] {
            var bad = data
            bad[bad.startIndex + at] ^= 0x5a
            for chunk in [1, 4096, bad.count] {
                let h = store.open(f.enc, limit: f.limit, hint: -1)
                XCTAssertEqual(Self.run(store, h, bad, chunk: chunk).0, "decode", "\(what) chunk \(chunk): \(store.err(h))")
                store.free(h)
            }
        }
        // a trailer cut short
        let h = store.open(f.enc, limit: f.limit, hint: -1)
        XCTAssertEqual(Self.run(store, h, data.prefix(data.count - 3), chunk: 333).0, "decode")
        store.free(h)
    }

    /// Bytes after a complete gzip member that do not start another member are ignored (design §3.6).
    func testGzipTrailingGarbageIgnored() throws {
        let store = NativeBodyStore.shared
        let (f, data) = try fixture("gzip-plain")
        for tail in [Data([0x00]), Data(repeating: 0x41, count: 40), Data([0x1f, 0x8b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])] {
            for chunk in [1, 7, 4096] {
                let h = store.open(f.enc, limit: f.limit, hint: -1)
                let (verdict, n) = Self.run(store, h, data + tail, chunk: chunk)
                // a second "member" with a bad method byte is invalid -> garbage; Go errors there too, we pass the body
                XCTAssertEqual(verdict, "ok", "tail \(tail.count) chunk \(chunk): \(store.err(h))")
                XCTAssertEqual(Int(n), f.len)
                store.free(h)
            }
        }
    }

    /// Native text keeps a leading BOM (Go's string(b) does; String(data:encoding:) would drop it).
    func testTextKeepsBOM() {
        let store = NativeBodyStore.shared
        let h = [UInt8]([0xef, 0xbb, 0xbf, 0x7b, 0x7d]).withUnsafeBytes { store.store($0) }
        defer { store.free(h) }
        XCTAssertEqual(store.text(h), "\u{FEFF}{}")
        // a truncated 4-byte sequence (one U+FFFD under maximal-subpart rules, same byte count) is not valid text
        let bad = [UInt8]([0x61, 0xf0, 0x9f, 0x98, 0x62]).withUnsafeBytes { store.store($0) }
        defer { store.free(bad) }
        XCTAssertNil(store.text(bad))
    }

    /// Several bodies decoded at once from different threads (Go calls from many goroutines), plus a free racing reads.
    func testConcurrentHandles() throws {
        let store = NativeBodyStore.shared
        let cases = try ["br", "gzip-multi-member", "deflate-zlib", "gzip-header-fields"].map { try fixture($0) }
        let failures = NSLock()
        var problems: [String] = []
        DispatchQueue.concurrentPerform(iterations: 32) { i in
            let (f, data) = cases[i % cases.count]
            let h = store.open(f.enc, limit: f.limit, hint: Int64(data.count))
            let (verdict, n) = Self.run(store, h, data, chunk: [1, 333, 4096, 32 << 10][i % 4])
            var out = Data()
            while let piece = store.read(h, raw: false, off: Int64(out.count), n: 32 << 10), !piece.isEmpty { out.append(piece) }
            let ok = verdict == "ok" && Int(n) == f.len && Self.hex(out) == f.sha256
            if !ok {
                failures.lock()
                problems.append("\(f.name) #\(i): \(verdict) \(n)")
                failures.unlock()
            }
            // free while another thread may still look the handle up: it must just see a dead handle
            DispatchQueue.global().async { _ = store.withDecoded(h) { _ in } }
            store.free(h)
            if store.read(h, raw: false, off: 0, n: 1) != nil || store.withDecoded(h, { _ in }) {
                failures.lock()
                problems.append("\(f.name) #\(i): readable after free")
                failures.unlock()
            }
        }
        XCTAssertEqual(problems, [])
    }
}
