import Darwin
import XCTest
@testable import Mihomo

/// fix/nc-ctrl-bsd (build 395 device report: NWListener .ready but accepted 0, self-probe /version timed out):
/// the controller's BSD loopback listener + connection (NCLoopbackListener / NCLoopbackConn), driven by a real
/// URLSession over 127.0.0.1 the way the App and the extension's self-probe talk to NCController. NCController
/// itself is tunnel-only (it needs NCDataPlane / lwIP), so this serves the same request shape — header parse,
/// Bearer check, `Connection: close` reply from the send completion, a chunked stream ended by the client — over
/// the exact socket layer NCController now runs on.
final class NCControllerSocketTests: XCTestCase {
    private let secret = "s3cr3t-test"
    private var queue: DispatchQueue!
    private var listener: NCLoopbackListener!
    private var open: [ObjectIdentifier: NCLoopbackConn] = [:]
    private var timers: [ObjectIdentifier: DispatchSourceTimer] = [:]
    private var closedStreams = 0
    private var streamClosed: XCTestExpectation?

    override func setUp() {
        super.setUp()
        queue = DispatchQueue(label: "test.nc.controller")
        listener = NCLoopbackListener(queue: queue)
        listener.onAccept = { [unowned self] conn in self.serve(conn) }
        let err = listener.start(port: 0)
        XCTAssertNil(err)
        XCTAssertGreaterThan(listener.port, 0)
    }

    override func tearDown() {
        queue.sync {
            listener.stop()
            for t in timers.values { t.cancel() }
            timers.removeAll()
            for c in open.values { c.onClose = nil; c.cancel() }
            open.removeAll()
        }
        super.tearDown()
    }

    // MARK: Minimal controller (same flow as NCController.handle / receiveRequest / respond / streamTraffic)

    private func serve(_ conn: NCLoopbackConn) {
        let id = ObjectIdentifier(conn)
        open[id] = conn
        conn.onClose = { [unowned self] in
            self.open.removeValue(forKey: id)
            if let t = self.timers.removeValue(forKey: id) {
                t.cancel()
                self.closedStreams += 1
                self.streamClosed?.fulfill()
            }
        }
        receive(conn, Data())
    }

    private func receive(_ conn: NCLoopbackConn, _ buffer: Data) {
        var buffer = buffer
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [unowned self] data, _, isComplete, error in
            if let data { buffer.append(data) }
            if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buffer[buffer.startIndex..<end.lowerBound], as: UTF8.self)
                self.route(conn, head)
                return
            }
            if error != nil || isComplete { conn.cancel(); return }
            self.receive(conn, buffer)
        }
    }

    private func route(_ conn: NCLoopbackConn, _ head: String) {
        let lines = head.components(separatedBy: "\r\n")
        let parts = lines.first?.split(separator: " ") ?? []
        let path = parts.count > 1 ? String(parts[1]) : ""
        let auth = lines.dropFirst().first { $0.lowercased().hasPrefix("authorization:") }?
            .split(separator: ":", maxSplits: 1).last.map { $0.trimmingCharacters(in: .whitespaces) }
        guard auth == "Bearer \(secret)" else { respond(conn, 401, #"{"message":"Unauthorized"}"#); return }
        switch path {
        case "/version":
            respond(conn, 200, #"{"version":"native-1.0.0","meta":true}"#)
        case "/traffic":
            conn.send(content: Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".utf8),
                      completion: .idempotent)
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 0.05, repeating: 0.05)
            timer.setEventHandler { [weak conn] in
                let line = "{\"up\":1,\"down\":2}\n"
                conn?.send(content: Data("\(String(line.utf8.count, radix: 16))\r\n\(line)\r\n".utf8), completion: .idempotent)
            }
            timers[ObjectIdentifier(conn)] = timer
            timer.resume()
        default:
            respond(conn, 404, #"{"message":"not found"}"#)
        }
    }

    private func respond(_ conn: NCLoopbackConn, _ status: Int, _ body: String) {
        let text = status == 200 ? "OK" : (status == 401 ? "Unauthorized" : "Not Found")
        var out = Data("HTTP/1.1 \(status) \(text)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(Data(body.utf8))
        conn.send(content: out, completion: .contentProcessed { _ in conn.cancel() })
    }

    // MARK: Client

    private func get(_ path: String, bearer: String?) -> (Int, Data?, Error?) {
        var req = URLRequest(url: URL(string: "http://127.0.0.1:\(listener.port)\(path)")!)
        req.timeoutInterval = 5
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let done = expectation(description: "GET \(path)")
        var result: (Int, Data?, Error?) = (-1, nil, nil)
        session.dataTask(with: req) { data, resp, err in
            result = ((resp as? HTTPURLResponse)?.statusCode ?? -1, data, err)
            done.fulfill()
        }.resume()
        wait(for: [done], timeout: 8)
        return result
    }

    // MARK: Tests

    func testVersionOverLoopbackWithBearerSecret() throws {
        let (code, data, err) = get("/version", bearer: secret)
        XCTAssertNil(err)
        XCTAssertEqual(code, 200)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data ?? Data()) as? [String: Any])
        XCTAssertEqual(obj["version"] as? String, "native-1.0.0")
    }

    func testWrongSecretIs401AndManySequentialRequestsAreServed() {
        XCTAssertEqual(get("/version", bearer: "nope").0, 401)
        for _ in 0..<20 { XCTAssertEqual(get("/version", bearer: secret).0, 200) }
        // every Connection: close reply ended its connection (no leak in the open table)
        let drained = expectation(description: "connections closed")
        func poll(_ n: Int) {
            queue.asyncAfter(deadline: .now() + 0.05) {
                if self.open.isEmpty || n == 0 { drained.fulfill() } else { poll(n - 1) }
            }
        }
        poll(60)
        wait(for: [drained], timeout: 5)
        queue.sync { XCTAssertTrue(open.isEmpty, "open connections left: \(open.count)") }
    }

    func testConcurrentRequests() {
        let group = DispatchGroup()
        let lock = NSLock()
        var codes: [Int] = []
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.httpMaximumConnectionsPerHost = 8
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        for _ in 0..<16 {
            group.enter()
            var req = URLRequest(url: URL(string: "http://127.0.0.1:\(listener.port)/version")!)
            req.timeoutInterval = 5
            req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
            session.dataTask(with: req) { _, resp, _ in
                lock.lock(); codes.append((resp as? HTTPURLResponse)?.statusCode ?? -1); lock.unlock()
                group.leave()
            }.resume()
        }
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(codes.count, 16)
        XCTAssertTrue(codes.allSatisfy { $0 == 200 }, "\(codes)")
    }

    /// A streaming endpoint (/traffic): data flows, and when the client goes away the server side notices (failed
    /// write → onClose) and its timer is cancelled — what NCController's stop()/handle() rely on.
    func testStreamStartsAndStopsWhenClientCloses() throws {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = listener.port.bigEndian
        addr.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        XCTAssertEqual(rc, 0)
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let req = "GET /traffic HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer \(secret)\r\n\r\n"
        _ = req.withCString { Darwin.write(fd, $0, strlen($0)) }
        var got = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline, !(String(decoding: got, as: UTF8.self).contains("\"down\":2")) {
            let n = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n <= 0 { break }
            got.append(contentsOf: buf[0..<n])
        }
        let text = String(decoding: got, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("HTTP/1.1 200 OK"), text)
        XCTAssertTrue(text.contains("{\"up\":1,\"down\":2}"), text)
        queue.sync { XCTAssertEqual(timers.count, 1) }

        streamClosed = expectation(description: "stream closed after the client went away")
        // RST on close so the server's next write fails at once
        var lin = linger(l_onoff: 1, l_linger: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, socklen_t(MemoryLayout<linger>.size))
        Darwin.close(fd)
        wait(for: [streamClosed!], timeout: 5)
        queue.sync {
            XCTAssertEqual(closedStreams, 1)
            XCTAssertTrue(timers.isEmpty)
        }
    }

    func testStopClosesTheListeningSocket() {
        let port = listener.port
        queue.sync { listener.stop() }
        let done = expectation(description: "refused")
        var req = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/version")!)
        req.timeoutInterval = 3
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        var failed = false
        session.dataTask(with: req) { _, _, err in failed = err != nil; done.fulfill() }.resume()
        wait(for: [done], timeout: 6)
        XCTAssertTrue(failed)
    }

    func testBindFailureReportsErrno() {
        let other = NCLoopbackListener(queue: DispatchQueue(label: "test.nc.controller.2"))
        // same port, already listening (SO_REUSEADDR does not allow two listeners on one address)
        let err = other.start(port: listener.port)
        XCTAssertNotNil(err)
        XCTAssertTrue(err?.contains("errno") ?? false, err ?? "")
        other.stop()
    }
}
