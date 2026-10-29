import XCTest
@testable import Tern

/// fix/nc-vision-head-layering: the VLESS request/response heads travel UNFRAMED
/// around the vision body (a server parses the request head first, then unframes;
/// Tern used to frame the request head — Xray answered "invalid request version" —
/// and to strip the response head from the reader's output instead of its input).
/// These tests pin the stream-level half: NCVisionStream strips the response head
/// from the carrier's bytes before the vision reader sees them, even when the head
/// arrives split across chunks.
final class NativeCoreVisionHeadTests: XCTestCase {
    private let uuid: [UInt8] = (0..<16).map { UInt8($0 &+ 0xa0) }

    private final class FakeCarrier: NCVisionCarrier {
        var inbound: [Data]
        init(_ chunks: [Data]) { inbound = chunks }
        func send(_ data: Data) {}
        func send(_ data: Data, completion: @escaping () -> Void) { completion() }
        func receive(_ handler: @escaping (Data?, Error?) -> Void) {
            if inbound.isEmpty { handler(nil, nil) } else { handler(inbound.removeFirst(), nil) }
        }
        func sendDirect(_ data: Data) {}
        func sendDirect(_ data: Data, completion: @escaping () -> Void) { completion() }
        func spliceOut() -> (plaintext: [Data], rawTail: Data) { ([], Data()) }
        func receiveSpliced(_ handler: @escaping (Data?, Error?) -> Void) { handler(nil, nil) }
        func cancel() {}
    }

    private func framedBody(_ payload: [UInt8]) -> [UInt8] {
        let writer = NCVisionWriter(userUUID: uuid)
        writer.randomBelow = { _ in 0 }
        return writer.process(payload).flatMap { $0 }
    }

    private func collect(from stream: NCVisionStream, timeout: TimeInterval = 5) -> [UInt8] {
        var out: [UInt8] = []
        let done = expectation(description: "eof")
        func next() {
            stream.receive { data, _ in
                if let data {
                    out += [UInt8](data)
                    next()
                } else {
                    done.fulfill()
                }
            }
        }
        next()
        wait(for: [done], timeout: timeout)
        return out
    }

    func testResponseHeadStrippedBeforeReader() {
        let payload = [UInt8]("hello vision".utf8)
        let wire = Data([0x00, 0x00]) + Data(framedBody(payload)) // response head: version 0, no addons
        let stream = NCVisionStream(tls: FakeCarrier([wire]), uuid: uuid)
        XCTAssertEqual(collect(from: stream), payload)
    }

    func testResponseHeadSplitAcrossChunks() {
        let payload = [UInt8]("split head".utf8)
        let body = framedBody(payload)
        // Head byte 1 alone, then head byte 2 + a frame fragment, then the rest.
        let chunks = [Data([0x00]), Data([0x00]) + Data(body.prefix(3)), Data(body.dropFirst(3))]
        let stream = NCVisionStream(tls: FakeCarrier(chunks), uuid: uuid)
        XCTAssertEqual(collect(from: stream), payload)
    }

    func testResponseHeadWithAddons() {
        let payload = [UInt8]("addons".utf8)
        let wire = Data([0x00, 0x02, 0xaa, 0xbb]) + Data(framedBody(payload)) // 2 addon bytes to skip
        let stream = NCVisionStream(tls: FakeCarrier([wire]), uuid: uuid)
        XCTAssertEqual(collect(from: stream), payload)
    }
}
