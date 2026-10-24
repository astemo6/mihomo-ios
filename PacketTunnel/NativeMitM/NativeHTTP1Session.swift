// feat/native-mitm STAGE 2 SKELETON — NOT BUILT (excluded in project.yml; see NativeTLSFront.swift).
//
// One decrypted client connection: HTTP/1.1 keep-alive loop. All rule semantics stay in Go — this file only frames
// bytes. Per request:
//   1. read the head (≤ 64 KB) and hand it to Go: LibmihomoMitmFlowBegin(headJSON) → plan (design §4.5, NOT YET IN GO):
//      local answer (reject / redirect / map local / request script mock), or forward (final method, URL, headers,
//      whether the request body goes through the lane for a request script);
//   2. forward through NativeUpstream (relay → mihomo); response head to Go: LibmihomoMitmFlowResponse(flowID, head)
//      → "stream" (no body rule: pipe as is) or "body" (stream the encoded body into NativeBodyStore, then
//      LibmihomoMitmFlowBody(flowID, handle) runs header rewrites + scripts exactly as modifyResponse does and returns
//      the final status / headers / lane handle);
//   3. write the response; free the lane handle when written.
// Until the flow API exists the session only proxies (no rules), which is why nothing builds this file yet.

import Foundation
import Network

final class NativeHTTP1Session {
    private let conn: NWConnection
    private let host: String
    private var buffer = Data()
    private static let maxHead = 64 << 10

    init(connection: NWConnection, host: String) {
        conn = connection
        self.host = host
    }

    func start() { readHead() }

    private func readHead() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 16 << 10) { [self] data, _, isComplete, error in
            if let data { buffer.append(data) }
            if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = buffer.subdata(in: buffer.startIndex..<end.upperBound)
                buffer.removeSubrange(buffer.startIndex..<end.upperBound)
                guard let req = HTTP1Head.parseRequest(head) else { return fail(400) }
                handle(req)
                return
            }
            if buffer.count > Self.maxHead { return fail(431) }
            if isComplete || error != nil { conn.cancel(); return }
            readHead()
        }
    }

    private func handle(_ req: HTTP1Head) {
        // TODO(stage 2): plan = Go flow API (design §4.5). Skeleton: forward unchanged.
        NativeUpstream.shared.forward(req, host: host, body: requestBodyReader(req)) { [self] resp in
            guard let resp else { return fail(502) }
            write(resp.head) { [self] in
                pipeBody(resp) { [self] keepAlive in
                    if keepAlive && req.keepAlive { readHead() } else { conn.cancel() }
                }
            }
        }
    }

    // TODO(stage 2): Content-Length / chunked request bodies (streamed, lane for request scripts).
    private func requestBodyReader(_ req: HTTP1Head) -> InputStream? { nil }

    private func pipeBody(_ resp: NativeUpstream.Response, done: @escaping (Bool) -> Void) {
        resp.next { [self] chunk in
            guard let chunk else { return done(resp.keepAlive) }
            write(chunk) { [self] in pipeBody(resp, done: done) }
        }
    }

    private func write(_ d: Data, then: @escaping () -> Void) {
        conn.send(content: d, completion: .contentProcessed { [self] error in
            if error != nil { conn.cancel(); return }
            then()
        })
    }

    private func fail(_ status: Int) {
        let d = Data("HTTP/1.1 \(status) \(HTTPURLResponse.localizedString(forStatusCode: status))\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)
        conn.send(content: d, completion: .contentProcessed { [self] _ in conn.cancel() })
    }
}

/// A parsed HTTP/1.1 request head (header order and case kept: Go's rules see what the client sent).
struct HTTP1Head {
    var method: String
    var target: String
    var version: String
    var headers: [(String, String)]

    var keepAlive: Bool {
        let c = headers.first { $0.0.caseInsensitiveCompare("Connection") == .orderedSame }?.1.lowercased()
        return version == "HTTP/1.1" ? c != "close" : c == "keep-alive"
    }

    static func parseRequest(_ head: Data) -> HTTP1Head? {
        guard let s = String(data: head, encoding: .isoLatin1) else { return nil }
        var lines = s.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }
        let first = lines.removeFirst().split(separator: " ", maxSplits: 2).map(String.init)
        guard first.count == 3 else { return nil }
        var hs: [(String, String)] = []
        for l in lines where !l.isEmpty {
            guard let i = l.firstIndex(of: ":") else { return nil }
            hs.append((String(l[..<i]), l[l.index(after: i)...].trimmingCharacters(in: .whitespaces)))
        }
        return HTTP1Head(method: first[0], target: first[1], version: first[2], headers: hs)
    }
}
