import XCTest
@testable import Tern

/// kcptun layers (Shared/NativeCore/NCKcptun*.swift) against kcp-go / kcptun wire behaviour.
/// Crypt vectors: work/nc/kcptun-vec/gen.py (PBKDF2-SHA1 "kcp-go" 4096, AES-CFB with kcp-go's fixed IV,
/// nonce(16) + crc32 LE + payload; salsa20 over buf[8:] with nonce buf[:8]; AES-GCM nonce || ct || tag).
final class NativeCoreKcptunTests: XCTestCase {
    private func unhex(_ s: String) -> Data {
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    private let payload = Data((0..<40).map { UInt8($0) })
    private let pass = "it's a secrect"

    func testOpenKcpGoVectors() {
        let vectors: [(String, String)] = [
            ("aes", "e2e727275f377ae0cd75db3c367985ecc86aec0ed7f38452bc769be24c38f7c2345abdd0865cf8d3dacb46f814fd651497cb2d070e9e7d1b4fd9c23d"),
            ("aes-128", "b9b384c3f477cf8ec392b17b565a1f64370a70024b0d224736983a9bf78cbf21efce08bfa1b2455aa31c6e3737a6b0d027ad94bd8d356eed9e7fcbad"),
            ("none", "6465666768696a6b6c6d6e6f707172733c2ea60d000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"),
            ("salsa20", "6465666768696a6b6d12131a666fd14a96203288974b07ba415334506911e9467249e40a5cb74f2ea716436b85acca6837a6ca9304b3b8d4b38b0381"),
            ("aes-128-gcm", "c8c9cacbcccdcecfd0d1d2d35f4522ab7bd2d034df94dda02f0a555d8e90f48bc20d1d59a8b30b63d1c9ea7a60a961d267c1f1fbe323d86848602f06da89d85d32d22ad2"),
        ]
        for (crypt, hex) in vectors {
            guard let c = NCKcptunBlockCrypt(crypt: crypt, password: pass) else { XCTFail(crypt); continue }
            XCTAssertEqual(c.open(unhex(hex)), payload, crypt)
            // seal -> open round trip with a random nonce
            XCTAssertEqual(c.open(c.seal(payload)), payload, crypt + " round trip")
            // a flipped byte is rejected (crc32 / AEAD tag)
            var bad = unhex(hex)
            bad[bad.count - 1] ^= 0x01
            XCTAssertNil(c.open(bad), crypt + " tamper")
        }
        let null = NCKcptunBlockCrypt(crypt: "null", password: pass)
        XCTAssertEqual(null?.seal(payload), payload)
        XCTAssertEqual(null?.overhead, 0)
        XCTAssertEqual(NCKcptunBlockCrypt(crypt: "none", password: pass)?.overhead, 20)
        XCTAssertEqual(NCKcptunBlockCrypt(crypt: "aes-128-gcm", password: pass)?.overhead, 28)
    }

    func testUnportedCryptIsReported() {
        XCTAssertNil(NCKcptunBlockCrypt(crypt: "blowfish", password: pass))
        let (opts, err) = NCKcptunOptions.parse(["crypt": .string("tea")])
        XCTAssertNil(opts)
        XCTAssertNotNil(err)
        XCTAssertNotNil(NCKcptunOptions.parse(["crypt": .string("salsa20")]).0)
        // String-typed flags from SIP002 / conf plugin args.
        XCTAssertEqual(NCKcptunOptions.parse(["nocomp": .string("true")]).0?.noComp, true)
        XCTAssertEqual(NCKcptunOptions.parse(["nocomp": .string("")]).0?.noComp, true)
        XCTAssertEqual(NCKcptunOptions.parse(["nocomp": .bool(false)]).0?.noComp, false)
        XCTAssertEqual(NCKcptunOptions.parse(["mtu": .string("1200")]).0?.mtu, 1200)
    }

    func testFECHeaderAndRecovery() {
        let fec = NCKcptunFEC(dataShards: 3, parityShards: 2)
        let pkts = [Data([1, 2, 3, 4]), Data([5, 6]), Data([7, 8, 9])]
        var wire: [Data] = []
        for p in pkts {
            let (d, parity) = fec.encode(packet: p)
            wire.append(d)
            wire.append(contentsOf: parity)
        }
        XCTAssertEqual(wire.count, 5)
        // kcp-go header: seqid u32 LE, 0xf1 0x00, size u16 LE = payload + 2
        XCTAssertEqual(Array(wire[0].prefix(8)), [0, 0, 0, 0, 0xf1, 0x00, 6, 0])
        XCTAssertEqual(Array(wire[1].prefix(8)), [1, 0, 0, 0, 0xf1, 0x00, 4, 0])
        XCTAssertEqual(Array(wire[3].prefix(6)), [3, 0, 0, 0, 0xf2, 0x00])

        // Intact data packets pass straight through.
        let rx = NCKcptunFEC(dataShards: 3, parityShards: 2)
        XCTAssertEqual(rx.decode(packet: wire[0]), [pkts[0]])
        // Lose data shard 1, recover it from the parities.
        XCTAssertEqual(rx.decode(packet: wire[2]), [pkts[2]])
        let recovered = rx.decode(packet: wire[3])
        XCTAssertEqual(recovered, [pkts[1]])
        XCTAssertEqual(rx.decode(packet: wire[4]), [])
    }

    func testKCPLoopbackAndAckRemoval() {
        let a = NCKCP(conv: 7, output: nil)
        let b = NCKCP(conv: 7, output: nil)
        a.output = { _ = b.input(data: $0) }
        b.output = { _ = a.input(data: $0) }
        a.setNoDelay(nodelay: 1, interval: 10, resend: 2, nc: 1)
        b.setNoDelay(nodelay: 1, interval: 10, resend: 2, nc: 1)
        let msg = Data((0..<5000).map { UInt8($0 & 0xff) })
        a.send(data: msg)
        a.flush()
        var got = Data()
        while let chunk = b.recv() { got.append(chunk) }
        XCTAssertEqual(got, msg)
        XCTAssertGreaterThan(a.waitSnd, 0)
        b.flush() // ACKs back to a
        XCTAssertEqual(a.waitSnd, 0, "acknowledged segments must leave snd_buf")
        XCTAssertFalse(a.isDeadLink)
    }

    func testSmuxDemuxAndBackPressureAccounting() {
        let opts = NCKcptunOptions.parse(["smuxver": .number(2), "streambuf": .number(65536)]).0!
        guard let session = NCKcptunSession(server: "127.0.0.1", port: 9, options: opts, poolKey: "test"),
              let smux = session.smux else { return XCTFail("session") }
        let q = DispatchQueue(label: "kcptun.test")
        guard let stream = smux.openStream(callerQueue: q) else { return XCTFail("stream") }
        XCTAssertEqual(stream.sid, 1)
        XCTAssertEqual(smux.activeStreamCount, 1)

        // cmdPSH for sid 1 with smux v2 header: ver 2, cmd 2, len LE, sid LE.
        var frame = Data([2, 2, 3, 0, 1, 0, 0, 0])
        frame.append(contentsOf: [0xaa, 0xbb, 0xcc])
        smux.feedBytes(frame)
        XCTAssertEqual(smux.unreadBytes, 3)

        let got = expectation(description: "read")
        stream.receive { data, err in
            XCTAssertNil(err)
            XCTAssertEqual(data, Data([0xaa, 0xbb, 0xcc]))
            got.fulfill()
        }
        wait(for: [got], timeout: 5)
        XCTAssertEqual(smux.unreadBytes, 0)

        // cmdFIN ends the stream: a pending read sees EOF.
        let eof = expectation(description: "eof")
        stream.receive { data, err in
            XCTAssertNil(data)
            XCTAssertNil(err)
            eof.fulfill()
        }
        smux.feedBytes(Data([2, 1, 0, 0, 1, 0, 0, 0]))
        wait(for: [eof], timeout: 5)
        XCTAssertEqual(smux.activeStreamCount, 0)
        session.close(error: nil)
        XCTAssertTrue(session.isClosed)
    }
}
