import XCTest
@testable import Mihomo

/// sing-mux h2mux: preamble/stream-request bytes and the multi-stream
/// HTTP/2 core exercised with fixtures.
final class NativeCoreMuxTests: XCTestCase {
    func testPreambleAndStreamRequest() {
        XCTAssertEqual([UInt8](NCMux.preamble()), [0x00, 0x02]) // v0, protocol h2mux
        let req = NCMux.streamRequestTCP(target: NCTarget(host: "example.com", port: 443))
        XCTAssertEqual([UInt8](req.prefix(2)), [0x00, 0x00]) // flags: TCP
        XCTAssertEqual(Data(req.dropFirst(2)), NCTarget(host: "example.com", port: 443).atypEncoded)
        XCTAssertEqual(NCMux.destination.host, "sp.mux.sing-box.arpa")
        XCTAssertEqual(NCMux.destination.port, 444)
    }

    func testStreamResponseParsing() {
        XCTAssertEqual(NCMux.parseStreamResponse(Data([0x00, 0xff]))?.ok, true)
        XCTAssertEqual(NCMux.parseStreamResponse(Data([0x00, 0xff]))?.consumed, 1)
        XCTAssertNil(NCMux.parseStreamResponse(Data()))
        XCTAssertNil(NCMux.parseStreamResponse(Data([0x01, 0x00]))) // incomplete message
        let err = NCMux.parseStreamResponse(Data([0x01, 0x00, 0x03]) + Data("bad".utf8))
        XCTAssertEqual(err?.ok, false)
        XCTAssertEqual(err?.message, "bad")
        XCTAssertEqual(err?.consumed, 6)
    }

    func testUDPPacketFrames() {
        let frame = NCMux.udpPacketFrame(target: NCTarget(host: "8.8.8.8", port: 53),
                                         payload: Data("query".utf8))
        let parsed = NCMux.parseUDPPacketFrame(frame + Data([0x00]))
        XCTAssertEqual(parsed?.0, NCTarget(host: "8.8.8.8", port: 53))
        XCTAssertEqual(parsed?.1, Data("query".utf8))
        XCTAssertEqual(parsed?.2, frame.count)
    }

    func testMuxCoreStreamLifecycle() {
        let core = NCH2MuxCore()
        let start = core.start()
        XCTAssertTrue([UInt8](start).starts(with: [UInt8](NCH2ClientCore.preface)))
        let (id, headers) = core.openStream()
        XCTAssertEqual(id, 1)
        XCTAssertEqual(headers[3], 0x1) // HEADERS
        // App data within the initial window.
        let (frames, consumed) = core.makeData(streamID: id, data: Data("hello".utf8))
        XCTAssertEqual(consumed, 5)
        XCTAssertFalse(frames.isEmpty)
        // Server responds: HEADERS (:status 200) + DATA "world" + WU.
        var inbound = NCH2ClientCore.frame(type: 0x1, flags: 0x4, streamID: id,
                                           payload: NCHPACK.encodeHeaders([(":status", "200")]))
        inbound.append(NCH2ClientCore.frame(type: 0x0, flags: 0, streamID: id, payload: Data("world".utf8)))
        let result = core.feed(inbound)
        XCTAssertTrue(result.events.contains {
            if case .responseHeaders(let sid, _) = $0 { return sid == id }
            return false
        })
        XCTAssertTrue(result.events.contains {
            if case .payload(let sid, let d) = $0 { return sid == id && d == Data("world".utf8) }
            return false
        })
        // Second stream gets id 3.
        XCTAssertEqual(core.openStream().0, 3)
        // RST surfaces.
        let rst = core.feed(NCH2ClientCore.frame(type: 0x3, flags: 0, streamID: id, payload: Data(count: 4)))
        XCTAssertTrue(rst.events.contains {
            if case .reset(let sid) = $0 { return sid == id }
            return false
        })
    }
}

/// Fake base relay for session-level tests: records sends, never delivers inbound data.
private final class NCSessionStressBase: NCRelayStream {
    private let lock = NSLock()
    private(set) var sentBytes = 0
    private var handler: ((Data?, Error?) -> Void)?

    func send(_ data: Data) {
        lock.lock(); sentBytes += data.count; lock.unlock()
    }

    // NCRelayStream has no default send completion (nc-sessions-flow): the fake completes at once.
    func send(_ data: Data, completion: @escaping () -> Void) {
        send(data)
        completion()
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock(); self.handler = handler; lock.unlock()
    }

    func cancel() {}
}

extension NativeCoreMuxTests {
    /// nc-sessions: one shared session driven from 4 caller queues at once — 200 streams opened, written
    /// and (half of them) cancelled concurrently. Asserts the session-queue confinement holds: no crash,
    /// every send completion fires exactly once, and the stream table drains to the uncancelled half, then
    /// to zero. Run under Thread Sanitizer in CI (unit-tests.yml).
    func testSessionConcurrentStreamsFromManyQueues() {
        let session = NCMuxSession(key: "stress")
        let base = NCSessionStressBase()
        session.attach(base: base)
        XCTAssertEqual(session.activeStreamCount, 0) // syncs with the session queue: attach has run by now
        XCTAssertTrue(session.isAlive)

        let callerQueues = (0..<4).map { DispatchQueue(label: "test.caller.\($0)", attributes: .concurrent) }
        let total = 200
        let lock = NSLock()
        var completions = 0
        var streams: [NCMuxStream] = []
        let group = DispatchGroup()
        for i in 0..<total {
            let q = callerQueues[i % callerQueues.count]
            group.enter()
            q.async {
                let stream = session.openStream(target: NCTarget(host: "example.com", port: 443), callerQueue: q)
                lock.lock(); streams.append(stream); lock.unlock()
                stream.send(Data("hello".utf8)) {
                    lock.lock(); completions += 1; lock.unlock()
                    group.leave()
                }
                if i % 2 == 0 { stream.cancel() }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 20), .success, "every send completion must fire exactly once")
        lock.lock()
        let fired = completions
        let opened = streams
        lock.unlock()
        XCTAssertEqual(fired, total)
        XCTAssertEqual(opened.count, total)
        XCTAssertEqual(session.activeStreamCount, total / 2)

        for stream in opened { stream.cancel() }
        let deadline = Date().addingTimeInterval(10)
        while session.activeStreamCount != 0, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertEqual(session.activeStreamCount, 0)
        XCTAssertGreaterThan(base.sentBytes, 0)
    }

    /// Readiness without polling: a waiter registered while connecting is notified once on attach, and a
    /// waiter registered after readiness fires immediately on its own queue.
    func testSessionWhenReadyWaiters() {
        let session = NCMuxSession(key: "ready")
        let caller = DispatchQueue(label: "test.ready.caller")
        let lock = NSLock()
        var results: [Bool] = []
        let group = DispatchGroup()
        for _ in 0..<3 {
            group.enter()
            session.whenReady(callerQueue: caller) { err in
                lock.lock(); results.append(err == nil); lock.unlock()
                group.leave()
            }
        }
        session.attach(base: NCSessionStressBase())
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
        lock.lock(); let rs = results; lock.unlock()
        XCTAssertEqual(rs, [true, true, true])

        let late = expectation(description: "late waiter")
        session.whenReady(callerQueue: caller) { err in
            XCTAssertNil(err)
            late.fulfill()
        }
        wait(for: [late], timeout: 10)
    }
}
