import XCTest
@testable import Tern

/// fix/kit-snell5 regression: one raw chunk that decodes into several
/// frames must deliver ALL of them, one per receive() call. Both Snell
/// relays used to return after the first decoded piece and silently drop
/// the rest of the feed, stalling the stream after ~one frame against
/// any server that coalesces frames into a single TCP segment (the
/// sing-box / official v5 frame-size ramp does exactly that; the
/// loopback echo tests failed with 1103 of 8192 bytes delivered).
/// These tests live in UnitTests/ (not AppTests/) because the CI
/// TernUnitTests bundle only compiles this directory.
final class NativeCoreSnellRelayTests: XCTestCase {

    func testV4RelayDeliversCoalescedFrames() {
        let psk = Data("relay-psk".utf8)
        let raw = FakeRawStream()
        let relay = NCSnellV4Relay(raw: raw, psk: psk, target: NCTarget(host: "127.0.0.1", port: 18080))
        let payload = Data((0..<8192).map { UInt8(($0 * 7 + 3) & 0xff) })
        let server = NCSnellV4Writer(psk: psk)
        var wire = server.frame(Data([0x00]) + payload.prefix(1000))!
        var rest = payload.dropFirst(1000)
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(1000))
            rest = Data(rest.dropFirst(chunk.count))
            wire.append(server.frame(chunk)!)
        }
        raw.push(wire)
        var got = Data()
        for _ in 0..<32 where got.count < payload.count {
            var fired: Data??
            relay.receive { d, _ in fired = d }
            guard let data = fired ?? nil else { break }
            got.append(data)
        }
        XCTAssertEqual(got, payload)
    }

    func testStreamRelayDeliversCoalescedChunks() {
        let psk = Data("relay-psk".utf8)
        let salt = Data((0..<16).map { UInt8(0x70 + $0) })
        let raw = FakeRawStream()
        let relay = NCSnellStreamRelay(raw: raw, psk: psk, version: 3, target: NCTarget(host: "127.0.0.1", port: 18080))
        let payload = Data((0..<8192).map { UInt8(($0 * 7 + 3) & 0xff) })
        let enc = NCSnellStreamEncoder(psk: psk, version: 3, salt: salt)
        var wire = enc.encode(Data([0x00]) + payload.prefix(1000))!
        var rest = payload.dropFirst(1000)
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(1000))
            rest = Data(rest.dropFirst(chunk.count))
            wire.append(enc.encode(chunk)!)
        }
        raw.push(wire)
        var got = Data()
        for _ in 0..<32 where got.count < payload.count {
            var fired: Data??
            relay.receive { d, _ in fired = d }
            guard let data = fired ?? nil else { break }
            got.append(data)
        }
        XCTAssertEqual(got, payload)
    }
}

/// In-memory NCRelayStream: captures sends, delivers pushed chunks to the
/// pending receive handler (or queues them for the next receive call).
private final class FakeRawStream: NCRelayStream {
    private(set) var sent = Data()
    private var chunks: [Data] = []
    private var waiter: ((Data?, Error?) -> Void)?

    func send(_ data: Data) { sent.append(data) }
    func send(_ data: Data, completion: @escaping () -> Void) { sent.append(data); completion() }
    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !chunks.isEmpty { handler(chunks.removeFirst(), nil) } else { waiter = handler }
    }
    func push(_ data: Data) {
        if let w = waiter { waiter = nil; w(data, nil) } else { chunks.append(data) }
    }
    func cancel() {}
}
