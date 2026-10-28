import XCTest
@testable import Tern

/// feat/nc-sudoku-udp: Sudoku UDP = UoT inside the tunnel (KIP StartUoT, then
/// addrLen u16 ‖ payloadLen u16 ‖ SOCKS5-style address ‖ payload, both directions).
final class NativeCoreSudokuUoTTests: XCTestCase {

    // MARK: - Framing

    func testFrameIPv4Layout() throws {
        let f = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "127.0.0.1", port: 53), payload: Data([0xaa, 0xbb])))
        XCTAssertEqual([UInt8](f), [0x00, 0x07, 0x00, 0x02, 0x01, 127, 0, 0, 1, 0x00, 0x35, 0xaa, 0xbb])
    }

    func testFrameDomainLayout() throws {
        let f = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "dns.google", port: 853), payload: Data([1])))
        var want: [UInt8] = [0x00, UInt8(1 + 1 + 10 + 2), 0x00, 0x01, 0x03, 10]
        want += Array("dns.google".utf8)
        want += [0x03, 0x55, 0x01]
        XCTAssertEqual([UInt8](f), want)
    }

    func testIPv4MappedIPv6IsSentAsIPv4() throws {
        let f = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "::ffff:10.0.0.9", port: 443), payload: Data()))
        XCTAssertEqual([UInt8](f), [0x00, 0x07, 0x00, 0x00, 0x01, 10, 0, 0, 9, 0x01, 0xbb])
    }

    func testRoundTripAllAddressKindsAndSizes() throws {
        let targets = [NCTarget(host: "8.8.4.4", port: 53), NCTarget(host: "2001:db8::1", port: 5353),
                       NCTarget(host: "example.com", port: 65535)]
        let sizes = [0, 1, 45, 1400, 65535]
        for t in targets {
            for n in sizes {
                let payload = Data((0..<n).map { UInt8(($0 * 7 + n) & 0xff) })
                let f = try XCTUnwrap(NCSudokuUoT.frame(target: t, payload: payload), "\(t) \(n)")
                guard case .frame(let peer, let range, let consumed) = NCSudokuUoT.parse(f) else {
                    return XCTFail("\(t) \(n): not parsed")
                }
                XCTAssertEqual(consumed, f.count)
                XCTAssertEqual(peer?.port, t.port)
                XCTAssertEqual(peer.flatMap { NCIP($0.host) }, NCIP(t.host))
                if NCIP(t.host) == nil { XCTAssertEqual(peer?.host, t.host) }
                XCTAssertEqual(f.subdata(in: range), payload)
            }
        }
    }

    func testUnencodableDatagramsAreRefused() {
        XCTAssertNil(NCSudokuUoT.frame(target: NCTarget(host: "1.1.1.1", port: 53), payload: Data(count: 65536)))
        XCTAssertNil(NCSudokuUoT.frame(target: NCTarget(host: String(repeating: "a", count: 256), port: 53), payload: Data()))
        XCTAssertNil(NCSudokuUoT.frame(target: NCTarget(host: "1.1.1.1", port: 70000), payload: Data()))
    }

    func testParseIncompleteInvalidAndOffsets() throws {
        let a = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "1.2.3.4", port: 9), payload: Data("one".utf8)))
        let b = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "a.b", port: 10), payload: Data("two!".utf8)))
        XCTAssertEqual(NCSudokuUoT.parse(Data()), .incomplete)
        XCTAssertEqual(NCSudokuUoT.parse(a.prefix(3)), .incomplete)
        XCTAssertEqual(NCSudokuUoT.parse(a.prefix(a.count - 1)), .incomplete)
        XCTAssertEqual(NCSudokuUoT.parse(Data([0, 0, 0, 1, 0xff])), .invalid, "addrLen 0 ends the session")

        // Two frames back to back, inside a slice whose startIndex is not 0.
        var wire = Data([0xee, 0xee])
        wire.append(a)
        wire.append(b)
        let slice = wire.dropFirst(2)
        XCTAssertNotEqual(slice.startIndex, 0)
        guard case .frame(let p1, let r1, let c1) = NCSudokuUoT.parse(slice) else { return XCTFail("frame 1") }
        XCTAssertEqual(p1, NCTarget(host: "1.2.3.4", port: 9))
        XCTAssertEqual(slice.subdata(in: r1), Data("one".utf8))
        guard case .frame(let p2, let r2, let c2) = NCSudokuUoT.parse(slice, at: c1) else { return XCTFail("frame 2") }
        XCTAssertEqual(p2, NCTarget(host: "a.b", port: 10))
        XCTAssertEqual(slice.subdata(in: r2), Data("two!".utf8))
        XCTAssertEqual(c1 + c2, slice.count)
        XCTAssertEqual(NCSudokuUoT.parse(slice, at: c1 + c2), .incomplete)
    }

    func testAddressPaddingIgnoredAndUnknownTypeSkipped() {
        // addrLen 10 for a 7-byte IPv4 address: the 3 trailing bytes are padding.
        let padded = Data([0x00, 0x0a, 0x00, 0x02, 0x01, 10, 1, 2, 3, 0x00, 0x50, 0xff, 0xff, 0xff, 0x41, 0x42])
        guard case .frame(let peer, let range, _) = NCSudokuUoT.parse(padded) else { return XCTFail("padded") }
        XCTAssertEqual(peer, NCTarget(host: "10.1.2.3", port: 80))
        XCTAssertEqual(padded.subdata(in: range), Data("AB".utf8))
        let unknown = Data([0x00, 0x03, 0x00, 0x01, 0x09, 0x00, 0x00, 0x41])
        guard case .frame(let none, _, let used) = NCSudokuUoT.parse(unknown) else { return XCTFail("unknown") }
        XCTAssertNil(none, "an undecodable peer is reported as nil (the datagram is skipped)")
        XCTAssertEqual(used, unknown.count)
    }

    func testStartUoTKIPMessage() {
        XCTAssertEqual([UInt8](NCSudokuKIP.startUoT()), [0x6b, 0x69, 0x70, 0x12, 0x00, 0x00])
        XCTAssertEqual(NCSudokuKIP.MessageType.startUoT.rawValue, 0x12)
    }

    // MARK: - Session over an in-memory UoT stream

    func testSessionRoundTripWithSplitAndCoalescedReads() throws {
        let raw = MemoryUoTStream()
        let s = NCSudokuUDPSession(attached: raw)
        var replies: [Data] = []
        var peers: [NCTarget?] = []
        s.onReply = { replies.append($0) }
        s.onDatagram = { p, _ in peers.append(p) }

        let dns = NCTarget(host: "1.1.1.1", port: 53)
        let big = Data((0..<1400).map { UInt8($0 & 0xff) })
        s.send(Data("q".utf8), to: dns)
        s.send(big, to: NCTarget(host: "example.org", port: 443))
        XCTAssertEqual(raw.sent.count, 2, "one write per frame (one AEAD record each)")
        XCTAssertEqual(raw.sent[0], NCSudokuUoT.frame(target: dns, payload: Data("q".utf8)))
        XCTAssertEqual(raw.sent[1], NCSudokuUoT.frame(target: NCTarget(host: "example.org", port: 443), payload: big))

        // Downlink: one frame byte by byte, then two frames in one read.
        let r1 = try XCTUnwrap(NCSudokuUoT.frame(target: dns, payload: big))
        for byte in r1 { raw.deliver(Data([byte])) }
        XCTAssertEqual(replies, [big])
        XCTAssertEqual(s.bufferedBytes, 0, "a drained read buffer is released")
        var two = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "9.9.9.9", port: 53), payload: Data("a".utf8)))
        let f2 = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "2001:db8::2", port: 53), payload: Data()))
        let f3 = try XCTUnwrap(NCSudokuUoT.frame(target: dns, payload: Data("c".utf8)))
        two.append(f2)
        two.append(f3.prefix(5))
        raw.deliver(two)
        XCTAssertEqual(replies, [big, Data("a".utf8), Data()])
        XCTAssertEqual(peers.last??.host, "2001:db8:0:0:0:0:0:2")
        XCTAssertEqual(s.bufferedBytes, 5, "only the partial third frame stays buffered")
        raw.deliver(f3.dropFirst(5))
        XCTAssertEqual(replies.last, Data("c".utf8))
        XCTAssertEqual(s.bufferedBytes, 0)
        XCTAssertFalse(raw.cancelled)
    }

    func testSessionEndsOnInvalidFrameAndEOF() {
        let raw = MemoryUoTStream()
        let s = NCSudokuUDPSession(attached: raw)
        var closed = 0
        s.onClose = { _ in closed += 1 }
        raw.deliver(Data([0x00, 0x00, 0x00, 0x01, 0x41]))
        XCTAssertTrue(raw.cancelled, "addrLen 0 tears the tunnel down")
        XCTAssertEqual(closed, 1)
        s.send(Data("late".utf8), to: NCTarget(host: "1.1.1.1", port: 53))
        XCTAssertTrue(raw.sent.isEmpty, "nothing is written after the session ended")

        let raw2 = MemoryUoTStream()
        let s2 = NCSudokuUDPSession(attached: raw2)
        var closed2 = 0
        s2.onClose = { _ in closed2 += 1 }
        raw2.deliver(nil)
        XCTAssertEqual(closed2, 1)
        XCTAssertTrue(raw2.cancelled)
    }

    func testSessionCapsInFlightUplinkBytes() {
        let raw = MemoryUoTStream()
        raw.holdCompletions = true
        let s = NCSudokuUDPSession(attached: raw)
        let t = NCTarget(host: "1.1.1.1", port: 443)
        let gram = Data(count: 1400)
        for _ in 0..<400 { s.send(gram, to: t) }
        let written = raw.sent.reduce(0) { $0 + $1.count }
        XCTAssertLessThanOrEqual(written, NCSudokuUDPSession.maxInFlightBytes)
        XCTAssertGreaterThan(written, NCSudokuUDPSession.maxInFlightBytes - 1500)
        XCTAssertEqual(s.dropped, 400 - raw.sent.count, "datagrams past the cap are dropped, not queued")
        raw.completeAll()
        let before = raw.sent.count
        s.send(gram, to: t)
        XCTAssertEqual(raw.sent.count, before + 1, "acknowledged bytes free the window again")
    }

    func testSessionCancelStopsReplies() throws {
        let raw = MemoryUoTStream()
        let s = NCSudokuUDPSession(attached: raw)
        var replies = 0
        s.onReply = { _ in replies += 1; s.cancel() }
        var wire = try XCTUnwrap(NCSudokuUoT.frame(target: NCTarget(host: "1.1.1.1", port: 53), payload: Data([1])))
        wire.append(wire)
        raw.deliver(wire)
        XCTAssertEqual(replies, 1, "cancel from inside onReply stops the parse loop")
        XCTAssertTrue(raw.cancelled)
        XCTAssertEqual(s.bufferedBytes, 0)
    }

    func testSudokuNodeIsUDPCapableInSupport() {
        let p = NCProxy(name: "s", type: "sudoku", fields: [
            "server": .string("1.2.3.4"), "port": .number(443),
            "key": .string("3388f6b59b225f4e41cd14f445b73b6568711ce536832217b15649253612451d"),
        ])
        XCTAssertNil(NCSupport.unsupportedReason(p))
        XCTAssertNil(NCSupport.sudokuUnsupported(p), "NCDataPlane opens NCSudokuUDPSession only for available nodes")
    }

    // MARK: - feat/nc-sudoku-udp-wire: the UDP switch

    private func proxy(_ type: String, _ extra: [String: NCJSONValue] = [:]) -> NCProxy {
        var f: [String: NCJSONValue] = ["server": .string("1.2.3.4"), "port": .number(443)]
        for (k, v) in extra { f[k] = v }
        return NCProxy(name: "n", type: type, fields: f)
    }

    func testEffectiveUDPDefaults() {
        // Sudoku without a udp field: on (the reference outbound always offers UDP).
        XCTAssertTrue(proxy("sudoku").effectiveUDP)
        XCTAssertFalse(proxy("sudoku").udp, "the raw field stays absent; only the effective value defaults")
        // An explicit field always wins, both ways.
        XCTAssertFalse(proxy("sudoku", ["udp": .bool(false)]).effectiveUDP)
        XCTAssertTrue(proxy("sudoku", ["udp": .bool(true)]).effectiveUDP)
        // Other protocols keep the historical semantics.
        XCTAssertFalse(proxy("vmess").effectiveUDP)
        XCTAssertTrue(proxy("vmess", ["udp": .bool(true)]).effectiveUDP)
        XCTAssertFalse(proxy("ss", ["udp": .bool(false)]).effectiveUDP)
    }

    func testNormalizeSudokuUDPFillsDefaultAndPreservesFalse() {
        var raw: [String: NCJSONValue] = ["proxies": .array([
            .object(["name": .string("a"), "type": .string("sudoku")]),
            .object(["name": .string("b"), "type": .string("sudoku"), "udp": .bool(false)]),
            .object(["name": .string("c"), "type": .string("vmess")]),
        ])]
        XCTAssertEqual(NCRuntimeSteps.normalizeSudokuUDP(&raw), 1)
        let proxies = raw.list("proxies").map { $0.object ?? [:] }
        XCTAssertEqual(proxies[0]["udp"], .bool(true), "absent udp is written as true for Sudoku")
        XCTAssertEqual(proxies[1]["udp"], .bool(false), "an explicit udp: false survives runtime generation")
        XCTAssertNil(proxies[2]["udp"], "other types are untouched")
        // And the generated config parses back to the same effective values (export keeps the field).
        XCTAssertTrue(NCProxy(name: "a", type: "sudoku", fields: proxies[0]).effectiveUDP)
        XCTAssertFalse(NCProxy(name: "b", type: "sudoku", fields: proxies[1]).effectiveUDP)
    }

    func testSudokuURICarriesUDPFlag() {
        let p = NCSudoku.parseURI("mykey@127.0.0.1:18090?udp=false#n1")
        XCTAssertEqual(p?.fields["udp"], .bool(false))
        XCTAssertEqual(p?.effectiveUDP, false)
        let q = NCSudoku.parseURI("mykey@127.0.0.1:18090#n2")
        XCTAssertNil(q?.fields["udp"])
        XCTAssertEqual(q?.effectiveUDP, true)
    }

    func testChainedUoTIsRejectedWithExplicitError() {
        let exp = expectation(description: "chain rejected")
        let queue = DispatchQueue(label: "nc.sudoku-uot.chain-test")
        NCConnector.sudokuUoTStream(proxy: proxy("sudoku", ["key": .string("3388f6b59b225f4e41cd14f445b73b6568711ce536832217b15649253612451d")]), queue: queue,
                                    transport: MemoryUoTStream()) { stream, err in
            XCTAssertNil(stream)
            XCTAssertTrue(err?.localizedDescription.contains("暂不支持代理链") ?? false,
                          "got: \(String(describing: err))")
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }
}

/// In-memory stand-in for the Sudoku tunnel after StartUoT.
private final class MemoryUoTStream: NCRelayStream {
    var sent: [Data] = []
    var cancelled = false
    var holdCompletions = false
    private var held: [() -> Void] = []
    private var handler: ((Data?, Error?) -> Void)?

    func send(_ data: Data) { sent.append(data) }
    func send(_ data: Data, completion: @escaping () -> Void) {
        sent.append(data)
        if holdCompletions { held.append(completion) } else { completion() }
    }
    func completeAll() {
        let h = held
        held = []
        h.forEach { $0() }
    }
    func receive(_ handler: @escaping (Data?, Error?) -> Void) { self.handler = handler }
    func deliver(_ data: Data?) {
        guard let h = handler else { return XCTFail("no receive pending") }
        handler = nil
        h(data, nil)
    }
    func cancel() { cancelled = true }
}
