import XCTest
@testable import Tern

/// fix/nc-socks-domain-len (#170): domain-length audit of every SOCKS-style
/// address codec. Two failure shapes are pinned down here:
///   - silent truncation of >255-byte hosts on encode (prefix(255)) — the
///     encoders now return nil instead, and the AnyTLS UoT `UInt8(host.count)`
///     trap on the same input is gone;
///   - the inbound (LAN-share / mixed-port) SOCKS5 request parser, now the
///     pure NCLanShare.parseSocksRequest: strict-UTF-8 domains, no
///     replacement-character decoding, port read at 5 + len for any len.
/// Boundary values (len 0/1/252–255/256) plus a deterministic fuzz pass over
/// every pure decoder.
final class NativeCoreSocksAddressTests: XCTestCase {

    private func host(_ n: Int) -> String { String(repeating: "a", count: n) }

    private func socksDomainRequest(_ domain: [UInt8], cmd: UInt8 = 0x01, port: Int = 443,
                                    payload: [UInt8] = []) -> [UInt8] {
        [0x05, cmd, 0x00, 0x03, UInt8(domain.count)] + domain
            + [UInt8(port >> 8), UInt8(port & 0xff)] + payload
    }

    // MARK: Inbound parser — domain length boundaries

    func testInboundDomainLengths() {
        for len in [1, 252, 253, 254, 255] {
            let domain = [UInt8](repeating: 0x61, count: len)
            let req = socksDomainRequest(domain, payload: [0xaa, 0xbb])
            XCTAssertEqual(NCLanShare.parseSocksRequest(req),
                           .ok(cmd: 0x01, host: host(len), port: 443, consumed: 5 + len + 2),
                           "len \(len)")
        }
    }

    func testInboundPortPositionAt255() {
        // Port must be read at 5 + len even at the maximum length, and bytes
        // past `consumed` stay the caller's payload.
        let domain = [UInt8](repeating: 0x62, count: 255)
        let req = socksDomainRequest(domain, port: 0x1f90, payload: [1, 2, 3, 4])
        guard case .ok(_, _, let port, let consumed) = NCLanShare.parseSocksRequest(req) else {
            return XCTFail("255-byte domain must parse")
        }
        XCTAssertEqual(port, 0x1f90)
        XCTAssertEqual(consumed, 262)
        XCTAssertEqual([UInt8](req[consumed...]), [1, 2, 3, 4])
    }

    func testInboundFragmentationIsNeedMore() {
        let full = socksDomainRequest([UInt8](repeating: 0x61, count: 255))
        for cut in 0..<full.count {
            XCTAssertEqual(NCLanShare.parseSocksRequest([UInt8](full[..<cut])), .needMore, "cut \(cut)")
        }
        let v4: [UInt8] = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb]
        for cut in 0..<v4.count {
            XCTAssertEqual(NCLanShare.parseSocksRequest([UInt8](v4[..<cut])), .needMore, "v4 cut \(cut)")
        }
        let v6: [UInt8] = [0x05, 0x01, 0x00, 0x04] + [UInt8](repeating: 0, count: 16) + [0x01, 0xbb]
        for cut in 0..<v6.count {
            XCTAssertEqual(NCLanShare.parseSocksRequest([UInt8](v6[..<cut])), .needMore, "v6 cut \(cut)")
        }
    }

    func testInboundZeroLengthDomain() {
        // Parses as an empty host; the caller rejects it (REP 0x01) after the
        // command check, exactly as the old inline parser ordered it.
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([])),
                       .ok(cmd: 0x01, host: "", port: 443, consumed: 7))
    }

    func testInboundRejectsBadDomains() {
        // NUL and other control bytes.
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0x61, 0x00, 0x62])),
                       .invalid(reply: 0x01))
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0x61, 0x1f, 0x62])),
                       .invalid(reply: 0x01))
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0x61, 0x7f, 0x62])),
                       .invalid(reply: 0x01))
        // Invalid UTF-8 must be rejected, not decoded with replacement chars.
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0xff, 0xfe])),
                       .invalid(reply: 0x01))
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0xc3])),
                       .invalid(reply: 0x01))
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0xe2, 0x82])),
                       .invalid(reply: 0x01))
        // Valid multibyte UTF-8 is fine.
        guard case .ok(_, let h, _, _) = NCLanShare.parseSocksRequest(
            socksDomainRequest([UInt8]("bücher.example".utf8))) else {
            return XCTFail("valid UTF-8 domain must parse")
        }
        XCTAssertEqual(h, "bücher.example")
    }

    func testInboundAtypVersionAndCmd() {
        XCTAssertEqual(NCLanShare.parseSocksRequest([0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 5, 6]),
                       .invalid(reply: 0x08))
        XCTAssertEqual(NCLanShare.parseSocksRequest([0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]),
                       .invalid(reply: nil))
        // Non-CONNECT commands parse; rejecting them (REP 0x07) is the caller's job.
        XCTAssertEqual(NCLanShare.parseSocksRequest(socksDomainRequest([0x61], cmd: 0x03, port: 1080)),
                       .ok(cmd: 0x03, host: "a", port: 1080, consumed: 8))
    }

    func testInboundIPv4AndIPv6() {
        XCTAssertEqual(NCLanShare.parseSocksRequest([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb]),
                       .ok(cmd: 0x01, host: "1.2.3.4", port: 443, consumed: 10))
        var v6: [UInt8] = [0x05, 0x01, 0x00, 0x04] + [UInt8](repeating: 0, count: 15) + [1]
        v6 += [0x01, 0xbb]
        XCTAssertEqual(NCLanShare.parseSocksRequest(v6),
                       .ok(cmd: 0x01, host: "::1", port: 443, consumed: 22))
    }

    // MARK: Inbound HTTP host validation

    func testInboundHostValidator() {
        XCTAssertFalse(NCLanShare.isValidInboundHost(""))
        XCTAssertTrue(NCLanShare.isValidInboundHost("example.com"))
        XCTAssertTrue(NCLanShare.isValidInboundHost("::1"))
        XCTAssertTrue(NCLanShare.isValidInboundHost("127.0.0.1"))
        XCTAssertTrue(NCLanShare.isValidInboundHost(host(255)))
        XCTAssertFalse(NCLanShare.isValidInboundHost(host(256)))
        XCTAssertFalse(NCLanShare.isValidInboundHost("exa mple.com"))
        XCTAssertFalse(NCLanShare.isValidInboundHost("a\u{07}b"))
        XCTAssertFalse(NCLanShare.isValidInboundHost("a\u{7f}b"))
    }

    // MARK: Decoders — length boundaries

    func testSOCKS5ResponseDomain255() {
        var resp: [UInt8] = [0x05, 0x00, 0x00, 0x03, 0xff]
        resp += [UInt8](repeating: 0x61, count: 255)
        resp += [0x1f, 0x90]
        let parsed = NCSOCKS5.parseResponse(Data(resp))
        XCTAssertEqual(parsed?.0, 262)
        XCTAssertEqual(parsed?.1, 0)
    }

    func testSS2022ParseTargetBoundaries() {
        var wire: [UInt8] = [0x03, 0xff]
        wire += [UInt8](repeating: 0x61, count: 255)
        wire += [0x01, 0xbb, 0xde, 0xad]
        let parsed = NCShadowsocks2022.parseTarget(Data(wire))
        XCTAssertEqual(parsed?.0.host, host(255))
        XCTAssertEqual(parsed?.0.port, 443)
        XCTAssertEqual(parsed?.1, 259)
        // Zero-length domain is not a target (was: parsed as an empty host).
        XCTAssertNil(NCShadowsocks2022.parseTarget(Data([0x03, 0x00, 0x01, 0xbb])))
        // Truncated 255-byte domain.
        XCTAssertNil(NCShadowsocks2022.parseTarget(Data(wire[..<100])))
    }

    // MARK: Encoders — 255 encodes, 256 fails cleanly (no truncation, no trap)

    func testEncodersRejectOverlongHost() {
        let t255 = NCTarget(host: host(255), port: 443)
        let t256 = NCTarget(host: host(256), port: 443)

        XCTAssertTrue(t255.isWireEncodable)
        XCTAssertFalse(t256.isWireEncodable)
        XCTAssertEqual(t255.atypEncoded?.count, 259)
        XCTAssertNil(t256.atypEncoded)

        XCTAssertEqual(NCSOCKS5.connectRequest(target: t255)?.count, 262)
        XCTAssertNil(NCSOCKS5.connectRequest(target: t256))

        XCTAssertNotNil(NCVLESS.addressEncoded(t255))
        XCTAssertNil(NCVLESS.addressEncoded(t256))
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
        XCTAssertNotNil(NCVLESS.requestHead(uuid: uuid, target: t255))
        XCTAssertNil(NCVLESS.requestHead(uuid: uuid, target: t256))

        XCTAssertNotNil(NCTrojan.requestHead(password: "pw", target: t255))
        XCTAssertNil(NCTrojan.requestHead(password: "pw", target: t256))
        XCTAssertNotNil(NCTrojan.udpPacket(target: t255, payload: Data([1])))
        XCTAssertNil(NCTrojan.udpPacket(target: t256, payload: Data([1])))

        XCTAssertNotNil(NCSnell.connectHeader(host: host(255), port: 443, version: 2))
        XCTAssertNil(NCSnell.connectHeader(host: host(256), port: 443, version: 2))
        XCTAssertNotNil(NCSnell.udpFrame(target: t255, payload: Data()))
        XCTAssertNil(NCSnell.udpFrame(target: t256, payload: Data()))

        // The AnyTLS crash from the issue: NCUoT.packet built
        // UInt8(host.count) and trapped on a 256-byte host. Now nil.
        XCTAssertNotNil(NCUoT.packet(target: t255, payload: Data([1])))
        XCTAssertNil(NCUoT.packet(target: t256, payload: Data([1])))
        XCTAssertNotNil(NCUoT.request(destination: t255))
        XCTAssertNil(NCUoT.request(destination: t256))

        XCTAssertNotNil(NCJuicityWire.tcpRequestHeader(target: t255))
        XCTAssertNil(NCJuicityWire.tcpRequestHeader(target: t256))
        XCTAssertNotNil(NCJuicityWire.sealUDPPacket(target: t255, payload: Data([1])))
        XCTAssertNil(NCJuicityWire.sealUDPPacket(target: t256, payload: Data([1])))

        XCTAssertNotNil(NCMux.streamRequestTCP(target: t255))
        XCTAssertNil(NCMux.streamRequestTCP(target: t256))

        XCTAssertNotNil(NCSudokuKIP.openTCP(target: t255))
        XCTAssertNil(NCSudokuKIP.openTCP(target: t256))

        XCTAssertNotNil(NCTUICWire.address(t255))
        XCTAssertNil(NCTUICWire.address(t256))
        XCTAssertNotNil(NCTUICUDP.address(t255))
        XCTAssertNil(NCTUICUDP.address(t256))

        XCTAssertNotNil(NCVMess.plainHeader(reqNonce: Data(count: 16), reqKey: Data(count: 16),
                                            respV: 0, option: 0, security: NCVMess.securityNone,
                                            padding: Data(), target: t255))
        XCTAssertNil(NCVMess.plainHeader(reqNonce: Data(count: 16), reqKey: Data(count: 16),
                                         respV: 0, option: 0, security: NCVMess.securityNone,
                                         padding: Data(), target: t256))
    }

    // MARK: Deterministic fuzz — decoders must never trap or over-consume

    private struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e3779b97f4a7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
            z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
            return z ^ (z >> 31)
        }
    }

    func testDecoderFuzz() {
        var rng = SplitMix64(state: 0x170_5eed)
        func randomBytes(_ maxLen: Int) -> [UInt8] {
            let n = Int(rng.next() % UInt64(maxLen + 1))
            return (0..<n).map { _ in UInt8(rng.next() & 0xff) }
        }
        let iterations = 10_000
        for _ in 0..<iterations {
            let raw = randomBytes(300)
            let data = Data(raw)

            if case .ok(_, _, _, let consumed) = NCLanShare.parseSocksRequest(raw) {
                XCTAssertTrue((7...262).contains(consumed) && consumed <= raw.count)
            }
            // Structured variant: plausible header, hostile domain bytes.
            var structured: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(rng.next() & 0xff)]
            structured += randomBytes(280)
            if case .ok(_, _, _, let consumed) = NCLanShare.parseSocksRequest(structured) {
                XCTAssertTrue(consumed <= structured.count)
            }

            if let (consumed, _) = NCSOCKS5.parseResponse(data) {
                XCTAssertTrue(consumed <= data.count)
            }
            if let (_, consumed) = NCShadowsocks2022.parseTarget(data) {
                XCTAssertTrue(consumed <= data.count)
            }
            _ = NCSudokuUoT.decodeAddress(data, 0..<data.count)
            if !raw.isEmpty {
                let lo = Int(rng.next() % UInt64(raw.count))
                let hi = lo + Int(rng.next() % UInt64(raw.count - lo + 1))
                _ = NCSudokuUoT.decodeAddress(data, lo..<hi)
            }
            if let n = NCBrook.addressLength(data) {
                XCTAssertTrue(n <= data.count)
            }
            if let n = NCBrook.addressLength(data, at: Int(rng.next() % 8)) {
                XCTAssertTrue(n <= data.count)
            }
            if let (_, consumed) = NCJuicityWire.unsealUDPPacket(data) {
                XCTAssertTrue(consumed <= data.count)
            }
            if let (_, _, consumed) = NCUoT.parsePacket(data) {
                XCTAssertTrue(consumed <= data.count)
            }
        }
    }

    func testEncoderFuzz() {
        var rng = SplitMix64(state: 0x170_e11c)
        for _ in 0..<2_000 {
            let len = 240 + Int(rng.next() % 30) // 240...269, straddling 255
            let bytes = (0..<len).map { _ in UInt8(0x61 + rng.next() % 26) }
            let target = NCTarget(host: String(decoding: bytes, as: UTF8.self), port: 443)
            if len <= 255 {
                XCTAssertNotNil(target.atypEncoded)
                XCTAssertNotNil(NCUoT.packet(target: target, payload: Data([1])))
            } else {
                XCTAssertNil(target.atypEncoded)
                XCTAssertNil(NCUoT.packet(target: target, payload: Data([1])))
                XCTAssertNil(NCSOCKS5.connectRequest(target: target))
            }
        }
    }
}
