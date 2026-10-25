import XCTest
@testable import Mihomo

/// nc-sessions-flow: a protocol wrapper's send completion must not fire before the raw stream's
/// completion does (that is the uplink back-pressure), must fire exactly once when it does, and must
/// still fire when the stream is cancelled with a send outstanding.
final class NativeCoreFlowControlTests: XCTestCase {

    /// Fake raw stream that holds send completions until released. Cancel completes outstanding
    /// sends, like NWConnection does.
    private final class HeldRawStream: NCRelayStream {
        private(set) var sent: [Data] = []
        private var pending: [() -> Void] = []

        func send(_ data: Data) { sent.append(data) }

        func send(_ data: Data, completion: @escaping () -> Void) {
            sent.append(data)
            pending.append(completion)
        }

        func release() {
            let p = pending
            pending = []
            p.forEach { $0() }
        }

        func receive(_ handler: @escaping (Data?, Error?) -> Void) {}

        func cancel() { release() }
    }

    private func assertHeldThenReleased(_ make: (HeldRawStream) -> NCRelayStream, _ name: String) {
        let raw = HeldRawStream()
        let stream = make(raw)
        var count = 0
        stream.send(Data("payload".utf8)) { count += 1 }
        XCTAssertFalse(raw.sent.isEmpty, "\(name): nothing reached the raw stream")
        XCTAssertEqual(count, 0, "\(name): completion fired before the raw stream's")
        raw.release()
        XCTAssertEqual(count, 1, "\(name): completion must fire exactly once after release")
    }

    func testShadowsocksCompletionFollowsRaw() {
        assertHeldThenReleased({ raw in
            NCSSRelayStream(raw: raw,
                            encoder: NCSSEncoder(cipher: "aes-128-gcm", password: "pw", salt: Data(repeating: 7, count: 16))!,
                            decoder: NCSSDecoder(cipher: "aes-128-gcm", password: "pw")!,
                            target: NCTarget(host: "example.com", port: 443))
        }, "shadowsocks")
    }

    func testVMessCompletionFollowsRaw() {
        assertHeldThenReleased({ raw in
            NCVMessRelayStream(raw: raw, sealedHeader: Data([1, 2, 3]),
                               reqKey: Data(repeating: 1, count: 16), reqNonce: Data(repeating: 2, count: 16),
                               respV: 0, security: NCVMess.securityAESGCM)
        }, "vmess")
    }

    func testVLESSCompletionFollowsRaw() {
        assertHeldThenReleased({ raw in NCVLESSRelayStream(raw: raw) }, "vless")
    }

    func testCancelStillCompletesOutstandingSend() {
        let raw = HeldRawStream()
        let stream = NCVLESSRelayStream(raw: raw)
        var count = 0
        stream.send(Data("payload".utf8)) { count += 1 }
        XCTAssertEqual(count, 0)
        stream.cancel()
        XCTAssertEqual(count, 1, "cancel must complete an outstanding send exactly once")
    }
}
