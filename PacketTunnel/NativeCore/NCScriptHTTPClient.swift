// NativeCore (feat/native-core-eval) — $httpClient through the tunnel's own routing (astemo6/Muse, 2026-10-25).
//
// A minimal HTTP/1.1 client on the ByteStream NCUpstreamConnector.shared.open(host:port:tls:) hands back: the
// connector applies NativeCore's rules (direct / reject / a proxy via NCConnector, origin TLS over the relayed
// stream for proxies since 6e96087), so a script's request leaves the way any app request to that host would —
// URLSession from the extension went out direct and ignored the rules.
//
// Request: `Connection: close`, Host first, the script's headers in order (its Connection / Content-Length /
// Transfer-Encoding / Host replaced), Content-Length when there is a body, Accept-Encoding gzip, br unless the
// script set one. Response: Content-Length, chunked (trailers skipped) or read-to-close; header order kept and
// every Set-Cookie kept as its own pair; gzip / deflate / br decoded with NativeBodyDecode (Content-Encoding and
// Content-Length then describe the decoded body, like the URLSession path did); redirects followed (301/302/303
// → GET without body, 307/308 keep method and body; at most 10) unless noRedirect. One deadline for the whole
// exchange: the script's timeout, else 15 s (the old core's fetchReq).
//
// `policy` (a proxy / group / DIRECT / REJECT name) replaces the rule match for this request; an unknown name fails
// the request ("unknown policy"), like Surge. `insecure` skips certificate verification on both the direct
// (NCStream allowInsecure) and the proxied (NCTLSClientStream allowInsecure) path. A connect that completes after
// the deadline is closed at once (it leaked until the peer closed).

import Foundation

enum NCScriptHTTPClient {
    struct Request {
        var url: URL
        var method: String = "GET"
        var headers: [(String, String)] = []
        var body = Data()
        var timeout: TimeInterval = 15
        var noRedirect = false
        /// explicit policy name (script option `policy`); nil / empty = the tunnel's rules
        var policy: String?
        /// script option `insecure`: do not verify the origin certificate
        var insecure = false
        /// fix/nc-script-stats: traffic ledger this request's connections count into (nil: uncounted);
        /// `trafficSource` is the connections-list chain label, "script:<name>".
        var traffic: NCScriptTrafficLedger? = nil
        var trafficSource: String = "script"
    }

    struct Response {
        var status: Int
        var headers: [(String, String)]
        var body: Data
        var url: URL
    }

    enum Failure: Error, CustomStringConvertible {
        case invalidURL(String)
        case connect(String)
        case timeout
        case io(String)
        case badResponse(String)
        case tooLarge
        case decode(String)
        case tooManyRedirects

        var description: String {
            switch self {
            case .invalidURL(let u): return "invalid url: \(u)"
            case .connect(let e): return e
            case .timeout: return "timeout"
            case .io(let e): return e
            case .badResponse(let e): return "bad response: \(e)"
            case .tooLarge: return "response body too large"
            case .decode(let e): return "decode: \(e)"
            case .tooManyRedirects: return "stopped after 10 redirects"
            }
        }
    }

    static let maxRedirects = 10
    /// raw and decoded body cap (NativeScriptBodyBudget's shared cap)
    static let bodyLimit = 8 << 20
    static let headLimit = 64 << 10
    static let readChunk = 64 << 10

    // MARK: fetch

    /// Blocks the calling thread (never a stream queue) until the response, a failure or the deadline.
    static func fetch(_ request: Request, connector: MitmUpstreamConnecting = NCUpstreamConnector.shared) -> Result<Response, Failure> {
        let deadline = DispatchTime.now() + (request.timeout > 0 ? request.timeout : 15)
        var req = request
        var hops = 0
        while true {
            let r = exchange(req, connector: connector, deadline: deadline)
            guard case .success(let resp) = r else { return r }
            guard !req.noRedirect, [301, 302, 303, 307, 308].contains(resp.status),
                  let loc = header(resp.headers, "Location"), !loc.isEmpty,
                  let next = URL(string: loc, relativeTo: req.url)?.absoluteURL,
                  let scheme = next.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
                return r
            }
            hops += 1
            if hops > maxRedirects { return .failure(.tooManyRedirects) }
            let sameOrigin = next.host?.lowercased() == req.url.host?.lowercased()
            if resp.status == 303 || ((resp.status == 301 || resp.status == 302) && req.method.uppercased() == "POST") {
                req.method = "GET"
                req.body = Data()
                req.headers.removeAll { isHeader($0.0, "Content-Type") || isHeader($0.0, "Content-Length") }
            }
            if !sameOrigin {
                // like the old core's HTTP client: credentials are not sent to another host
                req.headers.removeAll { isHeader($0.0, "Authorization") || isHeader($0.0, "Cookie") }
            }
            req.url = next
        }
    }

    /// One request / response on a fresh connection.
    private static func exchange(_ req: Request, connector: MitmUpstreamConnecting, deadline: DispatchTime) -> Result<Response, Failure> {
        guard let scheme = req.url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = req.url.host, !host.isEmpty else {
            return .failure(.invalidURL(req.url.absoluteString))
        }
        let tls = scheme == "https"
        let port = req.url.port ?? (tls ? 443 : 80)

        // connect
        let sem = DispatchSemaphore(value: 0)
        let box = LateLeaseBox()
        // fix/nc-open-6-10 #9: script traffic in /app/stats (统计 page) — the route this request used and the bytes
        // it moved are recorded once the exchange ends (NCStatsRecorder.oneShot; nothing kept per request).
        let route = NCUpstreamRoute()
        let started = Date()
        var upBytes: Int64 = 0, downBytes: Int64 = 0
        var connected = false
        defer {
            if connected {
                NCStatsRecorder.shared.oneShot(idPrefix: "script", rule: route.rule, policy: route.policy, chain: route.chain,
                                               host: host, dstPort: port, up: upBytes, down: downBytes, start: started)
            }
        }
        let start: (@escaping (Result<MitmUpstreamLease, Error>) -> Void) -> Void = { done in
            if let nc = connector as? NCUpstreamConnector {
                nc.open(host: host, port: port, tls: tls, policy: req.policy, insecure: req.insecure, alpn: ["http/1.1"],
                        route: route, completion: done)
            } else {
                connector.open(host: host, port: port, tls: tls, completion: done)
            }
        }
        start { r in if box.deliver(r) { sem.signal() } }
        let opened: Result<MitmUpstreamLease, Error>? = sem.wait(timeout: deadline) == .timedOut ? box.abandon() : box.take()
        let lease: MitmUpstreamLease
        switch opened {
        case nil: return .failure(.timeout)
        case .failure(let e)?: return .failure(.connect("\(e)"))
        case .success(let l)?: lease = l
        }
        connected = true
        defer { lease.release(reusable: false) }
        let stream = lease.stream
        // fix/nc-script-stats: one ledger entry per real connection (each redirect hop re-enters
        // exchange and counts its own); end fires exactly once via defer on every exit path.
        let trafficID = req.traffic?.begin(source: req.trafficSource, host: host, port: port)
        defer { if let trafficID { req.traffic?.end(trafficID) } }

        // request
        let head = requestHead(req, host: host, port: port, tls: tls)
        var out = Data(head.utf8)
        out.append(req.body)
        upBytes = Int64(out.count)
        let wrote: Error?? = wait(deadline) { done in stream.write(out) { done($0) } }
        switch wrote {
        case nil: stream.close(); return .failure(.timeout)
        case .some(.some(let e)): return .failure(.io("write: \(e)"))
        case .some(.none): break
        }
        if let trafficID { req.traffic?.add(trafficID, up: out.count, down: 0) }

        // response
        var parser = HTTP1ResponseParser(method: req.method, bodyLimit: bodyLimit, headLimit: headLimit)
        while !parser.complete {
            let got: (Data?, Bool, Error?)? = wait(deadline) { done in
                stream.read(min: 1, max: readChunk) { d, eof, err in done((d, eof, err)) }
            }
            guard let g = got else { stream.close(); return .failure(.timeout) }
            let (d, eof, err) = g
            if let err { return .failure(.io("read: \(err)")) }
            if let d, !d.isEmpty {
                downBytes += Int64(d.count)
                // fix/nc-script-stats: wire bytes as read (before any content decoding), the data plane's own convention
                if let trafficID { req.traffic?.add(trafficID, up: 0, down: d.count) }
                if let f = parser.feed(d) { return .failure(f) }
            }
            if eof || (d?.isEmpty ?? true) {
                if let f = parser.finishAtEOF() { return .failure(f) }
                break
            }
        }
        guard let status = parser.status else { return .failure(.badResponse("no head")) }

        // decode
        var headers = parser.headers
        var body = parser.body
        let enc = (header(headers, "Content-Encoding") ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        if !enc.isEmpty && enc != "identity" && !body.isEmpty {
            switch NativeBodyDecode.decode(enc, body, limit: bodyLimit) {
            case .decoded(let d):
                body = d
                headers.removeAll { isHeader($0.0, "Content-Encoding") || isHeader($0.0, "Content-Length") }
                headers.append(("Content-Length", String(body.count)))
            case .unsupported(let why):
                if why == "too large" { return .failure(.tooLarge) }
                // an encoding we cannot decode: hand the bytes over as received, headers unchanged
            }
        } else {
            headers.removeAll { isHeader($0.0, "Content-Length") || isHeader($0.0, "Transfer-Encoding") }
            headers.append(("Content-Length", String(body.count)))
        }
        return .success(Response(status: status, headers: headers, body: body, url: req.url))
    }

    static func requestHead(_ req: Request, host: String, port: Int, tls: Bool) -> String {
        var target = req.url.path.isEmpty ? "/" : req.url.path
        // URL.path drops a trailing ';params' and percent-decodes: rebuild from the absolute string instead
        if let comps = URLComponents(url: req.url, resolvingAgainstBaseURL: false) {
            target = comps.percentEncodedPath.isEmpty ? "/" : comps.percentEncodedPath
            if let q = comps.percentEncodedQuery { target += "?" + q }
        }
        let defaultPort = tls ? 443 : 80
        let hostHeader = (host.contains(":") ? "[\(host)]" : host) + (port == defaultPort ? "" : ":\(port)")
        var lines = ["\(req.method.isEmpty ? "GET" : req.method.uppercased()) \(target) HTTP/1.1", "Host: \(hostHeader)"]
        var hasAE = false, hasUA = false
        for (k, v) in req.headers {
            if isHeader(k, "Host") || isHeader(k, "Connection") || isHeader(k, "Content-Length")
                || isHeader(k, "Transfer-Encoding") || isHeader(k, "Keep-Alive") || isHeader(k, "Proxy-Connection") { continue }
            if k.contains("\r") || k.contains("\n") || v.contains("\r") || v.contains("\n") { continue }
            if isHeader(k, "Accept-Encoding") { hasAE = true }
            if isHeader(k, "User-Agent") { hasUA = true }
            lines.append("\(k): \(v)")
        }
        if !hasAE { lines.append("Accept-Encoding: gzip, br") }
        if !hasUA { lines.append("User-Agent: Tern") }
        if !req.body.isEmpty || ["POST", "PUT", "PATCH"].contains(req.method.uppercased()) {
            lines.append("Content-Length: \(req.body.count)")
        }
        lines.append("Connection: close")
        return lines.joined(separator: "\r\n") + "\r\n\r\n"
    }

    // MARK: helpers

    static func isHeader(_ a: String, _ b: String) -> Bool { a.caseInsensitiveCompare(b) == .orderedSame }

    static func header(_ hs: [(String, String)], _ name: String) -> String? {
        hs.first { isHeader($0.0, name) }?.1
    }

    private final class Box<T> {
        private let lock = NSLock()
        private var value: T?
        func set(_ v: T) { lock.lock(); if value == nil { value = v }; lock.unlock() }
        func get() -> T? { lock.lock(); defer { lock.unlock() }; return value }
    }

    /// Starts an async step and waits for its single callback until the deadline (nil: timed out).
    private static func wait<T>(_ deadline: DispatchTime, _ start: (@escaping (T) -> Void) -> Void) -> T? {
        let sem = DispatchSemaphore(value: 0)
        let box = Box<T>()
        start { v in box.set(v); sem.signal() }
        _ = sem.wait(timeout: deadline)
        return box.get()
    }
}

/// Hands a connect result over once; a lease that arrives after the caller gave up is released right away.
private final class LateLeaseBox {
    private let lock = NSLock()
    private var value: Result<MitmUpstreamLease, Error>?
    private var abandoned = false

    /// false: the caller already gave up (the lease was released here)
    func deliver(_ r: Result<MitmUpstreamLease, Error>) -> Bool {
        lock.lock()
        if abandoned {
            lock.unlock()
            if case .success(let l) = r { l.release(reusable: false) }
            return false
        }
        value = r
        lock.unlock()
        return true
    }

    func take() -> Result<MitmUpstreamLease, Error>? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    /// Called on timeout: a result that raced in is still used; otherwise a later one is released by deliver.
    func abandon() -> Result<MitmUpstreamLease, Error>? {
        lock.lock(); defer { lock.unlock() }
        if let v = value { return v }
        abandoned = true
        return nil
    }
}

/// Incremental HTTP/1.1 response parser (one response; interim 1xx skipped). Pure: no I/O.
struct HTTP1ResponseParser {
    enum Framing: Equatable { case none, length(Int), chunked, close }

    let method: String
    let bodyLimit: Int
    let headLimit: Int

    private(set) var status: Int?
    private(set) var headers: [(String, String)] = []
    private(set) var body = Data()
    private(set) var complete = false
    private(set) var framing: Framing?

    private var buf = Data()
    // chunked state
    private var chunkLeft = -1       // -1: expecting a size line
    private var inTrailers = false

    init(method: String, bodyLimit: Int, headLimit: Int) {
        self.method = method.uppercased()
        self.bodyLimit = bodyLimit
        self.headLimit = headLimit
    }

    /// Feeds bytes; a failure ends the parse.
    mutating func feed(_ d: Data) -> NCScriptHTTPClient.Failure? {
        if complete { return nil }
        buf.append(d)
        while !complete {
            if framing == nil {
                guard let end = find(buf, "\r\n\r\n") else {
                    return buf.count > headLimit ? .badResponse("head too large") : nil
                }
                let headData = buf.prefix(end)
                buf = Data(buf.suffix(from: buf.startIndex + end + 4))
                if let f = parseHead(Data(headData)) { return f }
                continue
            }
            switch framing! {
            case .none:
                complete = true
            case .length(let n):
                let need = n - body.count
                let take = min(need, buf.count)
                body.append(buf.prefix(take))
                buf = Data(buf.dropFirst(take))
                if body.count >= n { complete = true } else { return nil }
            case .close:
                if body.count + buf.count > bodyLimit { return .tooLarge }
                body.append(buf)
                buf = Data()
                return nil
            case .chunked:
                if let r = stepChunked() { return r.failure }
                if !complete { return nil }
            }
        }
        return nil
    }

    /// The peer closed: fine for read-to-close (and a finished message); truncation otherwise.
    mutating func finishAtEOF() -> NCScriptHTTPClient.Failure? {
        if complete { return nil }
        if framing == .close { complete = true; return nil }
        if framing == nil { return .badResponse("closed before the head") }
        return .io("connection closed before the body ended")
    }

    private struct StepFailure { let failure: NCScriptHTTPClient.Failure? }

    /// Consumes what it can of buf; nil = needs more (or completed), non-nil = failure.
    private mutating func stepChunked() -> StepFailure? {
        while true {
            if inTrailers {
                guard let e = find(buf, "\r\n") else { return nil }
                let line = buf.prefix(e)
                buf = Data(buf.suffix(from: buf.startIndex + e + 2))
                if line.isEmpty { complete = true; return nil }
                continue
            }
            if chunkLeft < 0 {
                guard let e = find(buf, "\r\n") else {
                    return buf.count > 4096 ? StepFailure(failure: .badResponse("chunk size line")) : nil
                }
                let line = String(decoding: buf.prefix(e), as: UTF8.self)
                buf = Data(buf.suffix(from: buf.startIndex + e + 2))
                let hex = line.split(separator: ";", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
                guard let n = Int(hex, radix: 16), n >= 0 else { return StepFailure(failure: .badResponse("chunk size \(line)")) }
                if n == 0 { inTrailers = true; continue }
                // n is the peer's hex (up to Int.max): compare without adding so a huge size cannot overflow
                if n > bodyLimit - body.count { return StepFailure(failure: .tooLarge) }
                chunkLeft = n
            }
            if chunkLeft > 0 {
                let take = min(chunkLeft, buf.count)
                if take == 0 { return nil }
                body.append(buf.prefix(take))
                buf = Data(buf.dropFirst(take))
                chunkLeft -= take
                if chunkLeft > 0 { return nil }
            }
            // chunk data done: its CRLF
            if buf.count < 2 { return nil }
            buf = Data(buf.dropFirst(2))
            chunkLeft = -1
        }
    }

    private mutating func parseHead(_ d: Data) -> NCScriptHTTPClient.Failure? {
        let text = String(decoding: d, as: UTF8.self)
        var lines = text.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return .badResponse("empty head") }
        let first = lines.removeFirst()
        let parts = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let st = Int(parts[1]), (100...999).contains(st) else {
            return .badResponse("status line \(first.prefix(80))")
        }
        var hs: [(String, String)] = []
        for l in lines where !l.isEmpty {
            if l.first == " " || l.first == "\t", let last = hs.popLast() {
                hs.append((last.0, last.1 + " " + l.trimmingCharacters(in: .whitespaces))) // obsolete folding
                continue
            }
            guard let c = l.firstIndex(of: ":") else { continue }
            let k = l[..<c].trimmingCharacters(in: .whitespaces)
            let v = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { hs.append((k, v)) }
        }
        if (100..<200).contains(st) && st != 101 {
            return nil // interim: framing stays nil, the next head follows
        }
        status = st
        headers = hs
        if method == "HEAD" || st == 204 || st == 304 || (100..<200).contains(st) {
            framing = .none
        } else if hs.contains(where: { NCScriptHTTPClient.isHeader($0.0, "Transfer-Encoding") && $0.1.lowercased().contains("chunked") }) {
            framing = .chunked
        } else if let cl = NCScriptHTTPClient.header(hs, "Content-Length"), let n = Int(cl.trimmingCharacters(in: .whitespaces)), n >= 0 {
            if n > bodyLimit { return .tooLarge }
            framing = n == 0 ? .none : .length(n)
            if n > 0 { body.reserveCapacity(n) }
        } else {
            framing = .close
        }
        return nil
    }

    private func find(_ d: Data, _ s: String) -> Int? {
        let needle = Data(s.utf8)
        guard let r = d.range(of: needle) else { return nil }
        return r.lowerBound - d.startIndex
    }
}
