import XCTest
import CryptoKit
@testable import Mihomo

// Coverage for PR #118 (fix/nc-perf): the frame parsers in NCVision,
// NCSSRProtocols and NCShadowsocks stopped consuming their input buffers
// with per-frame dropFirst copies (O(n^2)) and now walk a read offset,
// compacting only once more than half the buffer is consumed. The behavior
// contract that change must preserve: feeding a stream in ANY pieces —
// whole, byte by byte, or arbitrary splits — yields exactly the same
// plaintext as feeding it whole. Splits here are driven by a fixed-seed
// LCG so the cases are deterministic.

private struct SplitRNG {
    var state: UInt64
    mutating func next(_ bound: Int) -> Int {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return Int((state >> 33) % UInt64(bound))
    }
}

/// Deterministic non-TLS-looking payload (printable ASCII only, so the
/// Vision filter never classifies it and framing behavior stays stable).
private func payload(_ n: Int, seed: Int = 0) -> [UInt8] {
    (0..<n).map { UInt8(0x21 + (($0 &* 7 &+ seed) % 0x5e)) }
}

final class NativeCoreSSDecoderFragmentTests: XCTestCase {
    private func roundTrip(cipher: String, plain: [UInt8], mode: Int, seed: UInt64) -> [UInt8]? {
        let salt = Data((0..<32).map { UInt8($0 &+ 1) })
        guard let enc = NCSSEncoder(cipher: cipher, password: "frag-pw", salt: salt) else { return nil }
        // Encode in two calls so the stream holds several AEAD chunks,
        // including one larger than the 0x3FFF chunk cap.
        let half = plain.count / 2
        guard let w1 = enc.encode(Data(plain[..<half])), let w2 = enc.encode(Data(plain[half...])) else { return nil }
        let wire = w1 + w2
        guard let dec = NCSSDecoder(cipher: cipher, password: "frag-pw") else { return nil }
        var out = Data()
        switch mode {
        case 0: // whole
            guard let r = dec.feed(wire) else { return nil }
            out = r
        case 1: // byte by byte
            for i in 0..<wire.count {
                guard let r = dec.feed(wire[i..<(i + 1)]) else { return nil }
                out += r
            }
        default: // LCG splits of 1...97 bytes
            var rng = SplitRNG(state: seed)
            var i = 0
            while i < wire.count {
                let n = min(1 + rng.next(97), wire.count - i)
                guard let r = dec.feed(wire[i..<(i + n)]) else { return nil }
                out += r
                i += n
            }
        }
        return [UInt8](out)
    }

    func testFragmentedFeedMatchesWhole() {
        // > 0x3FFF forces multiple AEAD chunks; crosses several compaction
        // thresholds in the read-offset buffer.
        let plain = payload(0x3fff + 1234)
        for cipher in ["aes-256-gcm", "chacha20-ietf-poly1305"] {
            for (mode, seed) in [(0, UInt64(0)), (1, UInt64(0)), (2, UInt64(42)), (2, UInt64(7))] {
                XCTAssertEqual(roundTrip(cipher: cipher, plain: plain, mode: mode, seed: seed), plain,
                               "\(cipher) mode \(mode) seed \(seed)")
            }
        }
    }

    func testDecoderRejectsCorruptedStream() {
        let salt = Data((0..<32).map { UInt8($0 &+ 1) })
        let enc = NCSSEncoder(cipher: "aes-256-gcm", password: "frag-pw", salt: salt)!
        var wire = enc.encode(Data(payload(64)))!
        wire[wire.count - 1] ^= 0xff
        let dec = NCSSDecoder(cipher: "aes-256-gcm", password: "frag-pw")!
        XCTAssertNil(dec.feed(wire))
    }
}

final class NativeCoreVisionReaderFragmentTests: XCTestCase {
    private func wireBytes() -> (wire: [UInt8], plain: [UInt8]) {
        let uuid = (0..<16).map { UInt8($0 &+ 0xa0) }
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 } // deterministic padding
        var wire: [UInt8] = []
        var plain: [UInt8] = []
        // Several framed chunks (plain ASCII keeps the TLS filter idle):
        // a small one, one over the 900-byte padding threshold, one over
        // the 8192-byte reshape limit, and an empty write (long padding).
        for chunk in [payload(37), payload(1200, seed: 3), payload(9000, seed: 5), []] as [[UInt8]] {
            for piece in writer.process(chunk) { wire += piece }
            plain += chunk
        }
        return (wire, plain)
    }

    private func collect(_ slices: [[UInt8]]) throws -> [UInt8] {
        let uuid = (0..<16).map { UInt8($0 &+ 0xa0) }
        var reader = NCVisionReader(userUUID: uuid)
        var out: [UInt8] = []
        for s in slices { for piece in try reader.feed(s) { out += piece } }
        return out
    }

    func testFragmentedFeedMatchesWhole() throws {
        let (wire, plain) = wireBytes()
        XCTAssertEqual(try collect([wire]), plain)
        XCTAssertEqual(try collect(wire.map { [$0] }), plain)
        var rng = SplitRNG(state: 99)
        var slices: [[UInt8]] = []
        var i = 0
        while i < wire.count {
            let n = min(1 + rng.next(211), wire.count - i)
            slices.append(Array(wire[i..<(i + n)]))
            i += n
        }
        XCTAssertEqual(try collect(slices), plain)
    }
}

final class NativeCoreSSRFragmentTests: XCTestCase {
    private func makeCodec(sha1: Bool) -> NCSSRAuthAES128 {
        let key = NCShadowsocks.masterKey(password: "frag-ssr", keyLen: 16)
        let user = NCSSRUserData(param: "4242:userpass", key: key, hashKey: { pass in
            sha1 ? Data(Insecure.SHA1.hash(data: pass)) : Data(Insecure.MD5.hash(data: pass))
        })
        return NCSSRAuthAES128(sha1: sha1, key: key, iv: Data((0..<16).map { UInt8($0 &+ 0x40) }),
                               overhead: 9, user: user,
                               auth: (clientID: Data([1, 2, 3, 4]), connectionID: 7))
    }

    /// The encoder's first call emits the auth header block (which a server
    /// consumes during its handshake, never via decode). Priming with an
    /// empty write burns the header without emitting bytes, so what follows
    /// is pure packData frames — the decode loop's input.
    private func wire(sha1: Bool, chunks: [Data]) -> Data {
        let enc = makeCodec(sha1: sha1)
        _ = enc.encode(Data())
        var out = Data()
        for c in chunks { out += enc.encode(c) }
        return out
    }

    func testAuthAES128FragmentedDecodeMatchesWhole() throws {
        let chunks = [Data(payload(300)), Data(payload(5000, seed: 9)), Data(payload(17, seed: 2))]
        let expected = chunks.reduce(Data()) { $0 + $1 }
        for sha1 in [false, true] {
            let w = wire(sha1: sha1, chunks: chunks)
            XCTAssertEqual(try makeCodec(sha1: sha1).decode(w), expected, "whole, sha1=\(sha1)")

            let bytewise = makeCodec(sha1: sha1)
            var out = Data()
            for i in 0..<w.count { out += try bytewise.decode(w[i..<(i + 1)]) }
            XCTAssertEqual(out, expected, "bytewise, sha1=\(sha1)")

            var rng = SplitRNG(state: sha1 ? 5 : 6)
            let split = makeCodec(sha1: sha1)
            out = Data()
            var i = 0
            while i < w.count {
                let n = min(1 + rng.next(53), w.count - i)
                out += try split.decode(w[i..<(i + n)])
                i += n
            }
            XCTAssertEqual(out, expected, "split, sha1=\(sha1)")
        }
    }

    /// auth_chain's decode loop shares the same inbuf + read-offset
    /// machinery. A full round trip needs a server peer (the decode chain
    /// state is seeded from the received auth block, which a client codec
    /// never produces), so here only the partial-frame contract is pinned:
    /// fewer bytes than a frame header are held silently — no output, no
    /// throw — across several feeds.
    func testAuthChainDecodeHoldsPartialFrame() throws {
        let key = NCShadowsocks.masterKey(password: "frag-ssr", keyLen: 16)
        let user = NCSSRUserData(param: "4242:userpass", key: key, hashKey: { $0 })
        let chain = NCSSRAuthChain(variantB: false, key: key, iv: Data((0..<16).map { UInt8($0 &+ 0x40) }),
                                   overhead: 4, user: user,
                                   auth: (clientID: Data([1, 2, 3, 4]), connectionID: 7))
        // Total stays at the 4-byte frame-header floor: the decode loop only
        // starts once more than a header's worth of bytes is buffered.
        XCTAssertEqual(try chain.decode(Data([0x10, 0x00])), Data())
        XCTAssertEqual(try chain.decode(Data([0x20])), Data())
        XCTAssertEqual(try chain.decode(Data([0x30])), Data())
    }
}
