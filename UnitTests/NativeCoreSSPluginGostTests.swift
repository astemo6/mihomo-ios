import XCTest
@testable import Tern

/// feat/nc-ss-plugins2: Shadowsocks gost-plugin (Clash.Meta v1.19.33 adapter/outbound/shadowsocks.go
/// gostObfsOption + transport/gost/websocket.go NewGostWebsocket) and the kcptun gate.
/// Expected wire bytes come from the smux v1 frame layout (metacubex/smux frame.go: ver | cmd | LE16 len |
/// LE32 sid) and smux's client stream numbering (nextStreamID starts at 1, OpenStream adds 2 → 3), never
/// from the Swift implementation under test.
final class NativeCoreSSPluginGostTests: XCTestCase {

    // MARK: - Helpers

    private func ss(_ plugin: String, _ opts: [String: NCJSONValue]) -> NCProxy {
        NCProxy(name: "n", type: "ss", fields: [
            "server": .string("1.2.3.4"), "port": .number(443), "cipher": .string("aes-128-gcm"),
            "password": .string("pw"), "plugin": .string(plugin), "plugin-opts": .object(opts),
        ])
    }

    private func unhex(_ s: String) -> Data {
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let n = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<n], radix: 16)!)
            i = n
        }
        return out
    }

    /// Scripted raw stream: records what is sent, replays queued inbound chunks, then EOF.
    final class FakeRaw: NCRelayStream {
        var sent: [Data] = []
        var inbound: [Data] = []
        var cancelled = false
        let queue: DispatchQueue
        init(queue: DispatchQueue) { self.queue = queue }
        func send(_ data: Data) { sent.append(data) }
        func send(_ data: Data, completion: @escaping () -> Void) { sent.append(data); queue.async(execute: completion) }
        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            queue.async {
                if self.inbound.isEmpty { handler(nil, nil) } else { handler(self.inbound.removeFirst(), nil) }
            }
        }
        func cancel() { cancelled = true }
    }

    /// Server→client websocket binary frame (unmasked, RFC 6455 §5.2).
    private func wsFrame(_ payload: Data) -> Data {
        var f = Data([0x82])
        if payload.count < 126 { f.append(UInt8(payload.count)) } else {
            f.append(126); f.append(UInt8(payload.count >> 8)); f.append(UInt8(payload.count & 0xff))
        }
        f.append(payload)
        return f
    }

    /// Decode one client→server (masked) websocket frame.
    private func unmaskWS(_ d: Data) -> Data? {
        let b = [UInt8](d)
        guard b.count >= 2, b[1] & 0x80 != 0 else { return nil }
        var len = Int(b[1] & 0x7f), off = 2
        if len == 126 { len = Int(b[2]) << 8 | Int(b[3]); off = 4 }
        guard b.count >= off + 4 + len else { return nil }
        let key = Array(b[off..<(off + 4)])
        off += 4
        return Data((0..<len).map { b[off + $0] ^ key[$0 % 4] })
    }

    private func drain(_ s: NCRelayStream, timeout: TimeInterval = 3) -> (Data, Error?) {
        var got = Data()
        var failure: Error?
        let done = expectation(description: "drain")
        func next() {
            s.receive { d, e in
                if let d { got.append(d); next() } else { failure = e; done.fulfill() }
            }
        }
        next()
        wait(for: [done], timeout: timeout)
        return (got, failure)
    }

    // MARK: - plugin-opts decode (Clash.Meta gostObfsOption)

    func testWebsocketDefaultsMirrorUpstream() {
        let (o, why) = NCGostPluginOptions.parse(["mode": .string("websocket")])
        XCTAssertNil(why)
        XCTAssertEqual(o?.host, "bing.com")    // preset Host
        XCTAssertEqual(o?.mux, true)           // preset Mux
        XCTAssertEqual(o?.tls, false)
        XCTAssertEqual(o?.requestHost, "bing.com")
        XCTAssertNil(NCSupport.unsupportedReason(ss("gost-plugin", ["mode": .string("websocket")])))
    }

    func testAllFourClashShapesSupported() {
        for tls in [false, true] {
            for mux in [false, true] {
                let p = ss("gost-plugin", ["mode": .string("websocket"), "tls": .bool(tls), "mux": .bool(mux),
                                           "host": .string("cdn.example.com"), "path": .string("/ws")])
                XCTAssertNil(NCSupport.unsupportedReason(p), "tls=\(tls) mux=\(mux)")
                let o = NCGostPluginOptions.parse(["mode": .string("websocket"), "tls": .bool(tls), "mux": .bool(mux)]).0
                XCTAssertEqual(o?.tls, tls)
                XCTAssertEqual(o?.mux, mux)
            }
        }
    }

    func testNonWebsocketModesRejectedLikeUpstream() {
        // Clash.Meta: `if opts.Mode != "websocket" { obfs mode error }` — gost binary modes are not reachable.
        for mode in ["", "tls", "mws", "wss", "quic", "grpc", "kcp", "Websocket"] {
            var opts: [String: NCJSONValue] = [:]
            if !mode.isEmpty { opts["mode"] = .string(mode) }
            XCTAssertNotNil(NCGostPluginOptions.parse(opts).1, mode)
            let why = NCSupport.unsupportedReason(ss("gost-plugin", opts))
            XCTAssertNotNil(why, mode)
            XCTAssertTrue(why?.contains("gost-plugin mode") ?? false, why ?? "")
        }
    }

    func testHostHeaderOverridesRequestHostAndSNI() {
        let o = NCGostPluginOptions.parse([
            "mode": .string("websocket"), "tls": .bool(true), "host": .string("a.example"),
            "headers": .object(["host": .string("b.example"), "X-Foo": .string("1")]),
        ]).0
        XCTAssertEqual(o?.requestHost, "b.example")
        XCTAssertEqual(o?.sni, "b.example")
        XCTAssertEqual(o?.headers, ["X-Foo": "1"]) // Host never duplicated as an extra header
    }

    func testFingerprintPinning() {
        let fp = "AB:CD:EF:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
        let o = NCGostPluginOptions.parse(["mode": .string("websocket"), "tls": .bool(true),
                                           "fingerprint": .string(fp), "name-cert-verify": .string("real.example")]).0
        XCTAssertEqual(o?.pinnedCertSHA256, unhex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
        XCTAssertEqual(o?.nameCertVerify, "real.example")
        XCTAssertEqual(o?.needsCustomTLS, true)
        // Browser names / wrong length are Clash.Meta config errors.
        for bad in ["chrome", "abcd", String(repeating: "zz", count: 32)] {
            XCTAssertNotNil(NCGostPluginOptions.parse(["mode": .string("websocket"), "tls": .bool(true),
                                                       "fingerprint": .string(bad)]).1, bad)
        }
        // Clash.Meta only reads TLS options when tls: true.
        XCTAssertNil(NCGostPluginOptions.parse(["mode": .string("websocket"), "fingerprint": .string("chrome")]).1)
        XCTAssertEqual(NCGostPluginOptions.parse(["mode": .string("websocket")]).0?.needsCustomTLS, false)
    }

    func testClientCertificateAndECHAreExplicitGaps() {
        XCTAssertNotNil(NCSupport.unsupportedReason(ss("gost-plugin", [
            "mode": .string("websocket"), "tls": .bool(true), "certificate": .string("-----BEGIN CERTIFICATE-----"),
        ])))
        XCTAssertNotNil(NCSupport.unsupportedReason(ss("gost-plugin", [
            "mode": .string("websocket"), "tls": .bool(true), "ech-opts": .object(["enable": .bool(true)]),
        ])))
        XCTAssertNil(NCSupport.unsupportedReason(ss("gost-plugin", [
            "mode": .string("websocket"), "tls": .bool(true), "ech-opts": .object(["enable": .bool(false)]),
        ])))
    }

    /// kcptun was an explicit gap here; PR #146 (feat/nc-ss-cloak-kcptun, NCKcptunOptions) implements it, so a
    /// valid key / crypt node is supported now (option validation itself is covered by NativeCoreKcptunTests).
    func testKcptunIsSupportedAfterPR146() {
        XCTAssertNil(NCSupport.unsupportedReason(ss("kcptun", ["key": .string("k"), "crypt": .string("aes")])))
    }

    // MARK: - smux v1 framing

    func testSmuxSynUsesFirstClientStreamID3() {
        let q = DispatchQueue(label: "gost.syn")
        let raw = FakeRaw(queue: q)
        let m = NCGostSmuxStream(raw: raw)
        m.open()
        m.open() // idempotent
        XCTAssertEqual(raw.sent, [Data([1, 0, 0, 0, 3, 0, 0, 0])])
        m.send(Data("hi".utf8))
        XCTAssertEqual(raw.sent.last, Data([1, 2, 2, 0, 3, 0, 0, 0]) + Data("hi".utf8))
        m.cancel()
        XCTAssertEqual(raw.sent.last, Data([1, 1, 0, 0, 3, 0, 0, 0]))
        XCTAssertTrue(raw.cancelled)
    }

    func testSmuxSplitsAtMaxFrameSize() {
        let q = DispatchQueue(label: "gost.split")
        let raw = FakeRaw(queue: q)
        let m = NCGostSmuxStream(raw: raw)
        let payload = Data((0..<40000).map { UInt8($0 & 0xff) })
        m.send(payload)
        XCTAssertEqual(raw.sent.count, 2) // SYN, then one write holding both PSH frames
        let wire = raw.sent[1]
        XCTAssertEqual(wire.count, 8 + 32768 + 8 + (40000 - 32768))
        XCTAssertEqual(Array(wire.prefix(8)), [1, 2, 0x00, 0x80, 3, 0, 0, 0])            // len 32768 LE
        let second = wire.index(wire.startIndex, offsetBy: 8 + 32768)
        XCTAssertEqual(Array(wire[second..<(second + 8)]), [1, 2, 0x40, 0x1c, 3, 0, 0, 0]) // len 7232 LE
        XCTAssertEqual(wire[(wire.startIndex + 8)..<second] + wire[(second + 8)...], payload)
    }

    func testSmuxInboundFragmentsOtherStreamsNopAndCleanFIN() {
        let q = DispatchQueue(label: "gost.in")
        let raw = FakeRaw(queue: q)
        var wire = Data()
        wire += NCGostSmuxStream.frame(3)                               // NOP
        wire += NCGostSmuxStream.frame(2, Data("abc".utf8))
        wire += NCGostSmuxStream.frame(2, Data("zzz".utf8), sid: 5)     // other stream: dropped
        wire += NCGostSmuxStream.frame(2, Data("def".utf8))
        wire += NCGostSmuxStream.frame(1)                               // FIN → EOF, not an error
        // Deliver one byte at a time: frame reassembly across arbitrary chunk boundaries.
        raw.inbound = wire.map { Data([$0]) }
        let m = NCGostSmuxStream(raw: raw)
        let (got, err) = drain(m)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "abcdef")
        XCTAssertNil(err)
    }

    func testSmuxBadVersionIsAnError() {
        let q = DispatchQueue(label: "gost.bad")
        let raw = FakeRaw(queue: q)
        raw.inbound = [Data([2, 2, 0, 0, 3, 0, 0, 0])]
        let (_, err) = drain(NCGostSmuxStream(raw: raw))
        XCTAssertNotNil(err)
    }

    // MARK: - Connector glue: websocket upgrade + smux over a scripted transport

    func testConnectorWebsocketPlusSmuxEndToEnd() {
        let q = DispatchQueue(label: "gost.e2e")
        let raw = FakeRaw(queue: q)
        raw.inbound = [
            Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".utf8),
            wsFrame(NCGostSmuxStream.frame(2, Data("pong".utf8))),
            wsFrame(NCGostSmuxStream.frame(1)),
        ]
        let p = ss("gost-plugin", ["mode": .string("websocket"), "host": .string("cdn.example.com"),
                                   "path": .string("ws?ed=1"), "headers": .object(["X-Id": .string("7")])])
        let ready = expectation(description: "dial")
        var stream: NCRelayStream?
        q.async {
            NCConnector.ssPluginStream(proxy: p, server: "1.2.3.4", port: 443, queue: q, transport: raw) { s, e in
                XCTAssertNil(e)
                stream = s
                ready.fulfill()
            }
        }
        wait(for: [ready], timeout: 3)
        guard let stream else { return XCTFail("no stream") }
        XCTAssertTrue(stream is NCGostSmuxStream)

        let req = String(decoding: raw.sent[0], as: UTF8.self)
        XCTAssertTrue(req.hasPrefix("GET /ws?ed=1 HTTP/1.1\r\n"), req)
        XCTAssertTrue(req.contains("\r\nHost: cdn.example.com\r\n"), req)
        XCTAssertTrue(req.contains("\r\nX-Id: 7\r\n"), req)
        XCTAssertTrue(req.contains("\r\nUpgrade: websocket\r\n"), req)
        // After the upgrade the smux SYN for stream 3 goes out inside a masked binary ws frame.
        XCTAssertEqual(raw.sent.count, 2)
        XCTAssertEqual(unmaskWS(raw.sent[1]), Data([1, 0, 0, 0, 3, 0, 0, 0]))

        q.sync { stream.send(Data("ping".utf8)) }
        let (got, err) = drain(stream)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "pong")
        XCTAssertNil(err)
        q.sync {
            XCTAssertEqual(unmaskWS(raw.sent[2]), Data([1, 2, 4, 0, 3, 0, 0, 0]) + Data("ping".utf8))
        }
    }

    func testConnectorWebsocketWithoutMuxIsRawWS() {
        let q = DispatchQueue(label: "gost.nomux")
        let raw = FakeRaw(queue: q)
        raw.inbound = [Data("HTTP/1.1 101 Switching Protocols\r\n\r\n".utf8) + wsFrame(Data("hello".utf8))]
        let p = ss("gost-plugin", ["mode": .string("websocket"), "mux": .bool(false)])
        let ready = expectation(description: "dial")
        var stream: NCRelayStream?
        q.async {
            NCConnector.ssPluginStream(proxy: p, server: "1.2.3.4", port: 80, queue: q, transport: raw) { s, _ in
                stream = s
                ready.fulfill()
            }
        }
        wait(for: [ready], timeout: 3)
        guard let stream else { return XCTFail("no stream") }
        XCTAssertTrue(stream is NCWebSocketStream)
        XCTAssertTrue(String(decoding: raw.sent[0], as: UTF8.self).contains("\r\nHost: bing.com\r\n"))
        XCTAssertEqual(raw.sent.count, 1) // no SYN
        let (got, _) = drain(stream)
        XCTAssertEqual(String(decoding: got, as: UTF8.self), "hello")
    }

    func testConnectorRejectsUnsupportedModeWithoutDialing() {
        let q = DispatchQueue(label: "gost.reject")
        let raw = FakeRaw(queue: q)
        let done = expectation(description: "reject")
        NCConnector.ssPluginStream(proxy: ss("gost-plugin", ["mode": .string("quic")]), server: "1.2.3.4", port: 443,
                                   queue: q, transport: raw) { s, e in
            XCTAssertNil(s)
            XCTAssertNotNil(e)
            done.fulfill()
        }
        wait(for: [done], timeout: 3)
        XCTAssertTrue(raw.sent.isEmpty)
    }
}
