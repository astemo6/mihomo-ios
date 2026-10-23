// feat/native-mitm STAGE 2 SKELETON — NOT BUILT (excluded in project.yml; see NativeTLSFront.swift).
//
// Origins are reached through Go's relay (LibmihomoMitmRelayPort, bridge/mitm/relay.go): a loopback CONNECT proxy
// whose dials are mihomo INNER connections, so the user's rules / policies apply exactly as on the Go path.
//
// Client choice (design §4.4): URLSession through the relay as an HTTPS proxy gives TLS, HTTP/2 to origins and
// connection reuse for free, but it decodes Content-Encoding itself, normalises headers and cannot stream request
// bodies without a bound stream pair. The first cut uses it with those limits documented; an NWConnection HTTP/1.1
// client (ProxyConfiguration(httpCONNECTProxy:) on iOS 17) is the alternative if raw bytes turn out to matter.

import Foundation

final class NativeUpstream: NSObject, URLSessionDataDelegate {
    static let shared = NativeUpstream()

    final class Response {
        var head = Data()
        var keepAlive = true
        private var pending: [Data] = []
        private var waiter: ((Data?) -> Void)?
        private var finished = false
        private let lock = NSLock()

        func next(_ f: @escaping (Data?) -> Void) {
            lock.lock()
            if !pending.isEmpty {
                let d = pending.removeFirst()
                lock.unlock()
                return f(d)
            }
            if finished { lock.unlock(); return f(nil) }
            waiter = f
            lock.unlock()
        }

        fileprivate func push(_ d: Data?) {
            lock.lock()
            if d == nil { finished = true }
            if let w = waiter {
                waiter = nil
                lock.unlock()
                return w(d)
            }
            if let d { pending.append(d) } // TODO(stage 2): back-pressure (suspend the task above ~256 KB)
            lock.unlock()
        }
    }

    private lazy var session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        let port = Int(LibmihomoMitmRelayPort())
        // iOS has no kCFNetworkProxiesHTTPS* constants; these are their string values.
        c.connectionProxyDictionary = ["HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": port,
                                       "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": port]
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpMaximumConnectionsPerHost = 4
        c.timeoutIntervalForRequest = 60
        return URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }()

    private var byTask: [Int: (Response, (Response?) -> Void)] = [:]
    private let lock = NSLock()

    func forward(_ req: HTTP1Head, host: String, body: InputStream?, completion: @escaping (Response?) -> Void) {
        guard let url = URL(string: "https://" + host + req.target) else { return completion(nil) }
        var r = URLRequest(url: url)
        r.httpMethod = req.method
        for (k, v) in req.headers where !["host", "connection", "proxy-connection", "keep-alive", "transfer-encoding"].contains(k.lowercased()) {
            r.addValue(v, forHTTPHeaderField: k)
        }
        r.httpBodyStream = body
        let task = session.dataTask(with: r)
        lock.lock()
        byTask[task.taskIdentifier] = (Response(), completion)
        lock.unlock()
        task.resume()
    }

    // MARK: URLSessionDataDelegate

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // the client follows redirects itself
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        let entry = byTask[dataTask.taskIdentifier]
        lock.unlock()
        guard let (resp, done) = entry, let http = response as? HTTPURLResponse else { return completionHandler(.cancel) }
        // URLSession already decoded the body: drop Content-Encoding / Content-Length and send chunked.
        var head = "HTTP/1.1 \(http.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: http.statusCode))\r\n"
        for (k, v) in http.allHeaderFields {
            let key = "\(k)"
            if ["content-encoding", "content-length", "transfer-encoding", "connection"].contains(key.lowercased()) { continue }
            head += "\(key): \(v)\r\n"
        }
        head += "Transfer-Encoding: chunked\r\n\r\n"
        resp.head = Data(head.utf8)
        done(resp)
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        let entry = byTask[dataTask.taskIdentifier]
        lock.unlock()
        var chunk = Data(String(data.count, radix: 16).utf8)
        chunk.append(contentsOf: [13, 10])
        chunk.append(data)
        chunk.append(contentsOf: [13, 10])
        entry?.0.push(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let entry = byTask.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
        guard let (resp, done) = entry else { return }
        if resp.head.isEmpty { return done(nil) }
        if error == nil { resp.push(Data("0\r\n\r\n".utf8)) } else { resp.keepAlive = false }
        resp.push(nil)
    }
}
