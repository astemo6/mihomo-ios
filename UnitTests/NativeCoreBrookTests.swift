import CryptoKit
import XCTest
@testable import Mihomo

/// feat/nc-brook: Brook wire vectors + link / support gates. The vectors come from a Python port of
/// txthinking/brook's streamclient.go / streamserver.go / packetclient.go / packetserver.go /
/// simplestreamclient.go (HKDF-SHA256 + AES-256-GCM via `cryptography`, Go semantics byte for byte:
/// work/brook/vectors.py in the project workspace). sing-box has no brook server, so there is no loopback case.
final class NativeCoreBrookTests: XCTestCase {

    private static func hex(_ s: String) -> Data {
        var out = Data()
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            out.append(UInt8(s[idx..<next], radix: 16)!)
            idx = next
        }
        return out
    }

    private static func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private let pw = Data("hello".utf8)
    private let clientNonce = Data(0..<12)
    private let now: UInt32 = 1_700_000_001
    /// 0x03 | 11 | "example.com" | 443
    private var dst: Data { Data([0x03, 11]) + Data("example.com".utf8) + Data([0x01, 0xbb]) }

    // MARK: Key derivation

    func testHKDFKeyVector() {
        let k = NCBrook.key(password: pw, nonce: clientNonce, info: NCBrook.defaultHKDFInfo)
        XCTAssertEqual(k.withUnsafeBytes { Self.hexString(Data($0)) },
                       "75652f4ea2aa5fd096c94350f7a3dcbe7e89fe286bb6f87cfc50a8f4c7bb5900")
        let custom = NCBrook.key(password: pw, nonce: clientNonce, info: Data("custom".utf8))
        XCTAssertEqual(custom.withUnsafeBytes { Self.hexString(Data($0)) },
                       "bd1747a27c6838b883a604e20c1cb95af54403e416a86913199d248bec75c5a3")
    }

    func testNonceCounterIsLittleEndianU64() {
        var n = Data([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4])
        NCBrook.nextNonce(&n)
        XCTAssertEqual(Self.hexString(n), "000000000000000001020304")
        var m = Data([0xff, 0x00, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9])
        NCBrook.nextNonce(&m)
        XCTAssertEqual(Self.hexString(m), "000100000000000009090909")
    }

    func testRequestTimeParity() {
        XCTAssertEqual(NCBrook.requestTime(udp: false, now: 1_700_000_001), 1_700_000_002)
        XCTAssertEqual(NCBrook.requestTime(udp: false, now: 1_700_000_002), 1_700_000_002)
        XCTAssertEqual(NCBrook.requestTime(udp: true, now: 1_700_000_001), 1_700_000_001)
        XCTAssertEqual(NCBrook.requestTime(udp: true, now: 1_700_000_002), 1_700_000_003)
    }

    // MARK: Stream frames

    func testStreamHeadAndFrameVectors() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: false, dst: dst, nonce: clientNonce, now: now))
        XCTAssertEqual(Self.hexString(codec.head),
                       "000102030405060708090a0b0dba28631e5ce514b8e5d9ebdd29b36d2ef224831730f5a9620da37f4f552c3284fe53259a4fd23666cf39a09409f85de742aa2fcf")
        let f2 = try XCTUnwrap(codec.encode(Data("GET /".utf8)))
        XCTAssertEqual(Self.hexString(f2),
                       "a341538ab1178517c5bf4c5f167b30d3668b9c18f2aed8a7dc70b529a456d454bdfe6ad9b46ab7")
    }

    func testUDPOverStreamHeadUsesOddTime() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: true, dst: dst, nonce: clientNonce, now: now))
        XCTAssertEqual(Self.hexString(codec.head),
                       "000102030405060708090a0b0dba28631e5ce514b8e5d9ebdd29b36d2ef224831733f5a9620da37f4f552c3284fe53259a874211d2fc565c4b8031609a7d6cb37f")
    }

    private let serverWire = "a0a1a2a3a4a5a6a7a8a9aaabd03e38c571cfa63fafeb1b48d0e5ee63ebf74a77a695f389ef758f3f332f28dca284f4760ae77312f630479e904085a514b6ff1a9c8280209f92a39a52eea9f54eca069ae2d61fd841aa42b3b345e34779c70c2b"

    func testServerStreamDecodeWhole() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: false, dst: dst, nonce: clientNonce, now: now))
        let pieces = try XCTUnwrap(codec.feed(Self.hex(serverWire)))
        XCTAssertEqual(pieces, [Data("HTTP/1.1 200 OK".utf8), Data("!".utf8)])
    }

    func testServerStreamDecodeByteByByte() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: false, dst: dst, nonce: clientNonce, now: now))
        var out: [Data] = []
        for b in Self.hex(serverWire) { out += try XCTUnwrap(codec.feed(Data([b]))) }
        XCTAssertEqual(out, [Data("HTTP/1.1 200 OK".utf8), Data("!".utf8)])
    }

    func testServerStreamTamperFails() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: false, dst: dst, nonce: clientNonce, now: now))
        var wire = Self.hex(serverWire)
        wire[20] ^= 0x01
        XCTAssertNil(codec.feed(wire))
        XCTAssertNil(codec.feed(Data([0])), "a failed codec stays failed")
        let wrongPw = try XCTUnwrap(NCBrookStreamCodec(password: Data("nope".utf8), udp: false, dst: dst, nonce: clientNonce, now: now))
        XCTAssertNil(wrongPw.feed(Self.hex(serverWire)))
    }

    func testTCPPayloadSplitsAt2014() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: false, dst: dst, nonce: clientNonce, now: now))
        let big = Data(repeating: 0x41, count: 5000)
        let wire = try XCTUnwrap(codec.encode(big))
        // 2014 + 2014 + 972, each with 18 (sealed BE16) + 16 (tag) overhead.
        XCTAssertEqual(wire.count, 5000 + 3 * 34)
        XCTAssertEqual(NCBrook.maxTCPPayload, 2014)
        // Decrypt with the server's view of the client key: frames continue at counter 2 (head used 0 and 1).
        let k = NCBrook.key(password: pw, nonce: clientNonce, info: NCBrook.defaultHKDFInfo)
        var n = clientNonce
        NCBrook.nextNonce(&n); NCBrook.nextNonce(&n)
        var off = 0
        var lens: [Int] = []
        var plain = Data()
        while off < wire.count {
            let l = try XCTUnwrap(NCBrook.open(Data(wire[off..<(off + 18)]), key: k, nonce: n))
            NCBrook.nextNonce(&n)
            let len = Int(l[0]) << 8 | Int(l[1])
            lens.append(len)
            off += 18
            plain += try XCTUnwrap(NCBrook.open(Data(wire[off..<(off + len + 16)]), key: k, nonce: n))
            NCBrook.nextNonce(&n)
            off += len + 16
        }
        XCTAssertEqual(lens, [2014, 2014, 972])
        XCTAssertEqual(plain, big)
    }

    func testUDPDatagramIsOneFrameAndOversizeRejected() throws {
        let codec = try XCTUnwrap(NCBrookStreamCodec(password: pw, udp: true, dst: dst, nonce: clientNonce, now: now))
        let d = Data(repeating: 7, count: 3000)
        XCTAssertEqual(codec.encode(d)?.count, 3000 + 34)
        XCTAssertNil(codec.encode(Data(count: NCBrook.maxUDPPayload + 1)))
    }

    func testDstTooLongOrMalformedRejected() {
        XCTAssertNil(NCBrookStreamCodec(password: pw, udp: false, dst: Data([0x09, 1, 2]), nonce: clientNonce, now: now))
        XCTAssertNil(NCBrookStreamCodec(password: pw, udp: false, dst: Data([0x01, 1, 2, 3]), nonce: clientNonce, now: now))
    }

    // MARK: Packets

    func testPacketEncodeVector() throws {
        let d4 = Data([0x01, 8, 8, 8, 8, 0x00, 53])
        let p = try XCTUnwrap(NCBrook.packetEncode(password: pw, dst: d4, payload: Data("dnsq".utf8),
                                                   nonce: Data((0..<12).map { 0x10 + $0 }), now: now))
        XCTAssertEqual(Self.hexString(p), "101112131415161718191a1b648ef6594d1f339c17450252d3bfeb36a8a7cb51b9d8a3527742f150177c2b")
    }

    func testPacketDecodeVector() throws {
        let r = try XCTUnwrap(NCBrook.packetDecode(password: pw, packet: Self.hex("202122232425262728292a2b0b886252e3ecad0eca70062caeb5f102619f84ac1642ce1e199e9b")))
        XCTAssertEqual(r.address, Data([0x01, 8, 8, 8, 8, 0x00, 53]))
        XCTAssertEqual(r.payload, Data("dnsr".utf8))
        XCTAssertNil(NCBrook.packetDecode(password: Data("x".utf8), packet: Self.hex("202122232425262728292a2b0b886252e3ecad0eca70062caeb5f102619f84ac1642ce1e199e9b")))
        XCTAssertNil(NCBrook.packetDecode(password: pw, packet: Data(count: 20)))
    }

    // MARK: withoutBrookProtocol

    func testSimpleHeadVectorAndFraming() throws {
        let h = NCBrook.sha256("hello")
        let codec = try XCTUnwrap(NCBrookSimpleCodec(passwordHash: h, udp: false, dst: dst, now: now))
        XCTAssertEqual(Self.hexString(codec.head),
                       "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b982400136553f102030b6578616d706c652e636f6d01bb")
        XCTAssertEqual(codec.encode(Data("raw".utf8)), Data("raw".utf8))
        let udp = try XCTUnwrap(NCBrookSimpleCodec(passwordHash: h, udp: true, dst: dst, now: now))
        XCTAssertEqual(udp.encode(Data([1, 2, 3])), Data([0, 3, 1, 2, 3]))
        XCTAssertEqual(udp.feed(Data([0, 2, 9])), [])
        XCTAssertEqual(udp.feed(Data([8, 0, 1, 7])), [Data([9, 8]), Data([7])])
        let sp = NCBrook.simplePacketEncode(passwordHash: h, dst: Data([0x01, 1, 1, 1, 1, 0, 53]), payload: Data([0xaa]), now: 5)
        XCTAssertEqual(sp.count, 32 + 4 + 7 + 1)
        XCTAssertEqual(NCBrook.simplePacketDecode(Data([0x01, 1, 1, 1, 1, 0, 53, 0xbb]))?.payload, Data([0xbb]))
    }

    // MARK: WebSocket upgrade

    func testWebSocketAcceptAndValidation() {
        // RFC 6455 §1.3 sample.
        XCTAssertEqual(NCBrookWebSocket.acceptValue(key: "dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        let key = "dGhlIHNhbXBsZSBub25jZQ=="
        XCTAssertTrue(NCBrookWebSocket.validate(head: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", key: key))
        XCTAssertTrue(NCBrookWebSocket.validate(head: "HTTP/1.1 101 Switching Protocols", key: key))
        XCTAssertFalse(NCBrookWebSocket.validate(head: "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: bogus", key: key))
        XCTAssertFalse(NCBrookWebSocket.validate(head: "HTTP/1.1 400 Bad Request", key: key))
        let req = String(decoding: NCBrookWebSocket.request(path: "/ws", hostHeader: "example.com:443", key: key), as: UTF8.self)
        XCTAssertTrue(req.hasPrefix("GET /ws HTTP/1.1\r\nHost: example.com:443\r\n"))
        XCTAssertTrue(req.contains("Sec-WebSocket-Key: \(key)\r\n"))
        XCTAssertTrue(req.hasSuffix("Sec-WebSocket-Version: 13\r\n\r\n"))
    }

    // MARK: Options / support

    private func node(_ f: [String: NCJSONValue]) -> NCProxy {
        var fields: [String: NCJSONValue] = ["server": .string("1.2.3.4"), "port": .number(443), "password": .string("hello")]
        for (k, v) in f { fields[k] = v }
        return NCProxy(name: "b", type: "brook", fields: fields)
    }

    func testSupportGates() {
        XCTAssertTrue(NCSupport.types.contains("brook"))
        XCTAssertNil(NCSupport.unsupportedReason(node([:])))
        for t in ["server", "wsserver", "wssserver", "quicserver", "ws", "wss", "quic"] {
            XCTAssertNil(NCSupport.unsupportedReason(node(["transport": .string(t)])), t)
        }
        XCTAssertNotNil(NCSupport.unsupportedReason(node(["transport": .string("kcp")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(node(["password": .string("")])))
        XCTAssertNotNil(NCSupport.unsupportedReason(node(["token": .string("abcd")])))
        // `network` is not a brook field and must not trip the generic transport gate.
        XCTAssertNil(NCSupport.unsupportedReason(node(["network": .string("quic")])))
    }

    func testOptionsDefaultsAndOverrides() throws {
        let o = try XCTUnwrap(NCBrookOptions(proxy: node(["transport": .string("wssserver"), "host": .string("cdn.example.com")])))
        XCTAssertEqual(o.kind, .wssserver)
        XCTAssertEqual(o.hostName, "cdn.example.com")
        XCTAssertEqual(o.hostHeader, "cdn.example.com:443")
        XCTAssertEqual(o.path, "/ws")
        XCTAssertEqual(o.password, Data("hello".utf8))
        XCTAssertFalse(o.udpUsesPackets)
        let o2 = try XCTUnwrap(NCBrookOptions(proxy: node(["transport": .string("wsserver"), "host": .string("h.example:8080"),
                                                          "path": .string("x"), "without-brook-protocol": .bool(true)])))
        XCTAssertEqual(o2.hostHeader, "h.example:8080")
        XCTAssertEqual(o2.path, "/x")
        XCTAssertEqual(o2.password, NCBrook.sha256("hello"))
        let o3 = try XCTUnwrap(NCBrookOptions(proxy: node(["udp-over-tcp": .bool(true), "without-brook-protocol": .bool(true)])))
        XCTAssertFalse(o3.withoutBrook, "withoutBrookProtocol does not apply to brook server")
        XCTAssertFalse(o3.udpUsesPackets)
        XCTAssertTrue(try XCTUnwrap(NCBrookOptions(proxy: node([:]))).udpUsesPackets)
        XCTAssertTrue(try XCTUnwrap(NCBrookOptions(proxy: node(["transport": .string("quicserver")]))).udpUsesPackets)
        XCTAssertFalse(try XCTUnwrap(NCBrookOptions(proxy: node(["transport": .string("quicserver"), "udp-over-stream": .bool(true)]))).udpUsesPackets)
    }

    // MARK: brook:// links

    func testParseServerLink() throws {
        let p = try XCTUnwrap(NCBrookLink.parse("server?name=my+server&password=hello&server=1.2.3.4%3A9999&udpovertcp=true"))
        XCTAssertEqual(p.type, "brook")
        XCTAssertEqual(p.name, "my server")
        XCTAssertEqual(p.server, "1.2.3.4")
        XCTAssertEqual(p.port, 9999)
        XCTAssertEqual(p.password, "hello")
        XCTAssertEqual(p.fields["transport"]?.string, "server")
        XCTAssertEqual(p.fields["udp-over-tcp"]?.bool, true)
        XCTAssertNil(NCSupport.unsupportedReason(p))
    }

    func testParseWSSLinkWithAddress() throws {
        let link = "wssserver?address=1.2.3.4%3A443&insecure=true&password=p%40ss&tlsfingerprint=chrome&wssserver=wss%3A%2F%2Fexample.com%3A443%2Fsecret"
        let p = try XCTUnwrap(NCBrookLink.parse(link))
        XCTAssertEqual(p.server, "1.2.3.4")
        XCTAssertEqual(p.port, 443)
        XCTAssertEqual(p.password, "p@ss")
        XCTAssertEqual(p.fields["host"]?.string, "example.com")
        XCTAssertEqual(p.fields["path"]?.string, "/secret")
        XCTAssertEqual(p.fields["skip-cert-verify"]?.bool, true)
        XCTAssertEqual(p.fields["client-fingerprint"]?.string, "chrome")
        let o = try XCTUnwrap(NCBrookOptions(proxy: p))
        XCTAssertEqual(o.hostHeader, "example.com:443")
        XCTAssertEqual(o.hostName, "example.com")
    }

    func testParseQuicAndSocks5Links() throws {
        let q = try XCTUnwrap(NCBrookLink.parse("quicserver?password=x&quicserver=quic%3A%2F%2Fq.example.com%3A8443&udpoverstream=true&withoutBrookProtocol=true"))
        XCTAssertEqual(q.server, "q.example.com")
        XCTAssertEqual(q.port, 8443)
        XCTAssertNil(q.fields["path"])
        XCTAssertEqual(q.fields["udp-over-stream"]?.bool, true)
        XCTAssertEqual(q.fields["without-brook-protocol"]?.bool, true)
        let s = try XCTUnwrap(NCBrookLink.parse("socks5?password=pw&socks5=socks5%3A%2F%2F5.6.7.8%3A1080&username=u"))
        XCTAssertEqual(s.type, "socks5")
        XCTAssertEqual(s.server, "5.6.7.8")
        XCTAssertEqual(s.fields["username"]?.string, "u")
        XCTAssertNil(NCBrookLink.parse("server?password=x"))
        XCTAssertNil(NCBrookLink.parse("kcp?kcp=1.2.3.4%3A1&password=x"))
    }

    func testSubscriptionParsesBrookLinks() {
        let text = "brook://server?password=hello&server=1.2.3.4%3A9999\nbrook://wsserver?password=hello&wsserver=ws%3A%2F%2F5.6.7.8%3A80%2Fws"
        let nodes = NCSubscriptionParser.parse(text)
        XCTAssertEqual(nodes.map(\.type), ["brook", "brook"])
        XCTAssertEqual(nodes.last?.fields["transport"]?.string, "wsserver")
    }

    func testEncodeMatchesBrookLinkAndRoundTrips() throws {
        // brook link -s 1.2.3.4:9999 -p hello --name 'my server' → url.Values.Encode (sorted, QueryEscape).
        let fields: [String: Any] = ["type": "brook", "server": "1.2.3.4", "port": 9999, "password": "hello"]
        XCTAssertEqual(NCBrookLink.encode(name: "my server", fields: fields),
                       "brook://server?name=my+server&password=hello&server=1.2.3.4%3A9999")
        let wss: [String: Any] = ["type": "brook", "server": "1.2.3.4", "port": 443, "password": "p@ss",
                                  "transport": "wssserver", "host": "example.com", "path": "/secret",
                                  "skip-cert-verify": true]
        let link = try XCTUnwrap(NCBrookLink.encode(name: "w", fields: wss))
        XCTAssertEqual(link, "brook://wssserver?address=1.2.3.4%3A443&insecure=true&name=w&password=p%40ss&wssserver=wss%3A%2F%2Fexample.com%3A443%2Fsecret")
        let back = try XCTUnwrap(NCBrookLink.parse(String(link.dropFirst("brook://".count))))
        XCTAssertEqual(back.server, "1.2.3.4")
        XCTAssertEqual(back.fields["host"]?.string, "example.com")
        XCTAssertEqual(back.fields["path"]?.string, "/secret")
        XCTAssertEqual(back.fields["skip-cert-verify"]?.bool, true)
        // Share-link entry point.
        let shared = try NCShareLink.encode(NCProxy(name: "x", type: "brook", fields: [
            "server": .string("9.9.9.9"), "port": .number(1000), "password": .string("a b"),
            "transport": .string("quicserver"), "udp-over-stream": .bool(true)]))
        XCTAssertEqual(shared, "brook://quicserver?name=x&password=a+b&quicserver=quic%3A%2F%2F9.9.9.9%3A1000&udpoverstream=true")
    }
}
