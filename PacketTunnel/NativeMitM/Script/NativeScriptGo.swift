// Native MitM stage 3, lane s3-script — what the native script dispatcher still asks Go (bridge/mitmscript.go,
// bridge/mitm/nativescript.go). None of these calls carries a response body: admission (script slots, the
// large-bundle lock and queue, the body budget incl. the small pool, the one-large-body lock, memory gates), the
// program cache index (the JavaScriptCore context of a script is loaded / dropped by Go), host APIs whose state is
// Go's ($persistentStore shared with the app, notifications, $httpAPI, geo, $httpClient through mihomo routing), and
// every log line / request-log note, formatted by the Go path's own code.
//
// ScriptGoHost is a protocol so the unit tests can count calls; production is GoScriptHost.

import Foundation
import UserNotifications

// MARK: - Switch

enum NativeScriptRuntime {
    /// App-group key; default OFF (enable after device measurement).
    static let defaultsKey = "nativeMitmScript"

    /// Tests force it; nil = read the app-group default (cached for a second).
    static var override: Bool?

    private static let lock = NSLock()
    private static var cached = false
    private static var readAt: TimeInterval = 0

    static var enabled: Bool {
        if let o = override { return o }
        lock.lock(); defer { lock.unlock() }
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = UserDefaults(suiteName: NativeMitmRuntime.appGroup)?.bool(forKey: defaultsKey) ?? false
        }
        return cached
    }
}

// MARK: - Answers (JSON from Go; field names = nativescript.go json tags)

struct ScriptReserveAnswer: Decodable {
    var slot: Int64?
    var err: String?
    var note: String?
    var gone: Bool?
}

struct ScriptPrepared: Decodable {
    var ok: Bool
    var key: String?
    var err: String?
    var name: String?
    var timeoutMs: Int64?
    var notNative: Bool?
    /// The setup base (Go's jsSetup without phase / req / resp), kept as JSON text.
    var setupJSON: String = "{}"

    enum CodingKeys: String, CodingKey { case ok, key, err, name, timeoutMs, notNative }

    static func decode(_ s: String) -> ScriptPrepared {
        let data = Data(s.utf8)
        guard var p = try? JSONDecoder().decode(ScriptPrepared.self, from: data) else {
            return ScriptPrepared(ok: false, err: "脚本运行时内部错误：prepare")
        }
        if let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let setup = obj["setup"],
           let sd = try? JSONSerialization.data(withJSONObject: setup), let ss = String(data: sd, encoding: .utf8) {
            p.setupJSON = ss
        }
        return p
    }

    init(ok: Bool, key: String? = nil, err: String? = nil) { self.ok = ok; self.key = key; self.err = err }
}

struct ScriptAdmit: Decodable {
    var ok: Bool?
    var ticket: Int64?
    var cap: Int64?
    var limit: Int64?
    var skip: String?
    var retry: Bool?
    var gone: Bool?
}

struct ScriptBodyCheck: Decodable {
    var limit: Int64
    var note: String?
}

struct ScriptFail: Decodable {
    var note: String?
    var ignored: Bool?
    var msg: String?
}

/// A finished $httpClient download (Go holds its body budget share until done()).
protocol ScriptFetch: AnyObject {
    var meta: String { get }
    var body: Data { get }
    func done()
}

protocol ScriptGoHost: AnyObject {
    func ready() -> Bool
    func token() -> Int64
    func cancel(_ token: Int64)
    func reserve(gen: Int64, rule: Int, token: Int64) -> ScriptReserveAnswer
    func release(slot: Int64, ran: Bool)
    func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared
    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit
    func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String
    func bodyRelease(ticket: Int64)
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck
    func skip(gen: Int64, rule: Int, why: String) -> String
    func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail
    func host(gen: Int64, rule: Int, op: String, arg: String) -> String
    func bytes(op: String, arg: String, input: Data) -> Data?
    func api(gen: Int64, rule: Int, arg: String) -> String
    func fetch(gen: Int64, rule: Int, token: Int64, arg: String, body: Data) -> ScriptFetch
    func memLow() -> Bool
    // native-final: the request body of an http-request script (requestPhase's loadBody, bridge/mitm/flowscripted.go)
    func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit
    func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String
    func reqLimit(gen: Int64, rule: Int) -> Int64
    /// Go-side handles still held for native script work (tests: 0 after every flow).
    func held() -> Int64
}

private func decodeJSON<T: Decodable>(_ s: String, _ fallback: T) -> T {
    (try? JSONDecoder().decode(T.self, from: Data(s.utf8))) ?? fallback
}

final class NativeScriptFetch: ScriptFetch {
    let meta: String
    let body: Data
    private let onDone: () -> Void

    init(meta: String, body: Data, onDone: @escaping () -> Void = {}) {
        self.meta = meta
        self.body = body
        self.onDone = onDone
    }

    func done() { onDone() }
}

final class NativeScriptHost: ScriptGoHost {
    static let shared = NativeScriptHost()
    static var geoLookup: ((String) -> String?)?

    private let lock = NSLock()
    private var tokenSeq: Int64 = 0
    private var slotSeq: Int64 = 0
    private var ticketSeq: Int64 = 0
    private var activeSlots: Int64 = 0

    func ready() -> Bool { true }

    func token() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        tokenSeq += 1
        return tokenSeq
    }

    func cancel(_ token: Int64) {}

    func reserve(gen: Int64, rule: Int, token: Int64) -> ScriptReserveAnswer {
        lock.lock(); defer { lock.unlock() }
        slotSeq += 1
        activeSlots += 1
        return ScriptReserveAnswer(slot: slotSeq)
    }

    func release(slot: Int64, ran: Bool) {
        lock.lock(); defer { lock.unlock() }
        if activeSlots > 0 { activeSlots -= 1 }
    }

    func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared {
        ScriptPrepared(ok: true, key: "rule_\(rule)", err: nil)
    }

    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
        let ticket: Int64 = { lock.lock(); defer { lock.unlock() }; ticketSeq += 1; return ticketSeq }()
        return ScriptAdmit(ok: true, ticket: ticket, cap: 256 << 10, limit: 256 << 10)
    }

    func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String { "" }
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String { "" }
    func bodyRelease(ticket: Int64) {}
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck {
        ScriptBodyCheck(limit: 256 << 10)
    }

    func skip(gen: Int64, rule: Int, why: String) -> String { "" }
    func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail {
        ScriptFail()
    }

    func host(gen: Int64, rule: Int, op: String, arg: String) -> String {
        switch op {
        case "sread":
            if let v = NCPersistentStore.shared.read(key: arg) {
                return "1" + v
            }
            return "0"
        case "swrite":
            guard arg.count >= 3 else { return "false" }
            let del = arg.first == "d"
            let rest = String(arg.dropFirst())
            guard let colon = rest.firstIndex(of: ":"),
                  let kl = Int(rest[..<colon]) else { return "false" }
            let after = String(rest[rest.index(after: colon)...])
            let utf16 = after.utf16
            guard utf16.count >= kl,
                  let keyEnd = String.Index(utf16Offset: kl, in: after) else { return "false" }
            let key = String(after[..<keyEnd])
            let val = String(after[keyEnd...])
            if del {
                return NCPersistentStore.shared.delete(key: key) ? "true" : "false"
            } else {
                return NCPersistentStore.shared.write(key: key, value: val) ? "true" : "false"
            }
        case "sclear":
            return NCPersistentStore.shared.clear() ? "true" : "false"
        case "btoa":
            return Data(arg.utf8).base64EncodedString()
        case "atob":
            return Data(base64Encoded: arg).flatMap { String(data: $0, encoding: .utf8) } ?? ""
        case "notify":
            if let arr = (try? JSONSerialization.jsonObject(with: Data(arg.utf8))) as? [String],
               arr.count >= 3 {
                let content = UNMutableNotificationContent()
                content.title = arr[0]
                content.subtitle = arr[1]
                content.body = arr[2]
                content.sound = .default
                if arr.count > 3 && !arr[3].isEmpty {
                    content.userInfo = ["url": arr[3]]
                }
                let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
                UNUserNotificationCenter.current().add(req) { _ in }
                return "true"
            }
            return "false"
        case "geo":
            if arg.hasPrefix("c") {
                let ip = String(arg.dropFirst())
                if let country = Self.geoLookup?(ip) {
                    return country
                }
            }
            return "{}"
        default:
            return ""
        }
    }

    func bytes(op: String, arg: String, input: Data) -> Data? {
        if op == "ungzip" {
            if case .decoded(let d) = NativeBodyDecode.gunzip([UInt8](input), limit: 16 << 20) {
                return d
            }
        }
        return nil
    }

    func api(gen: Int64, rule: Int, arg: String) -> String { "{}" }

    func fetch(gen: Int64, rule: Int, token: Int64, arg: String, body: Data) -> ScriptFetch {
        struct FetchReqArg: Decodable {
            var id: Int64
            var url: String
            var method: String?
            var headers: [[String]]?
            var timeout: Double?
            var policy: String?
            var insecure: Bool?
            var noRedirect: Bool?
        }
        guard let req = try? JSONDecoder().decode(FetchReqArg.self, from: Data(arg.utf8)),
              let targetURL = URL(string: req.url) else {
            return NativeScriptFetch(meta: #"{"id":0,"err":"invalid fetch request"}"#, body: Data())
        }
        var request = URLRequest(url: targetURL)
        request.httpMethod = req.method ?? "GET"
        if let headers = req.headers {
            for pair in headers where pair.count == 2 {
                request.addValue(pair[1], forHTTPHeaderField: pair[0])
            }
        }
        if !body.isEmpty { request.httpBody = body }
        if let timeout = req.timeout, timeout > 0 { request.timeoutInterval = timeout / 1000.0 }

        let sem = DispatchSemaphore(value: 0)
        var respData = Data()
        var respMeta = #"{"id":\#(req.id),"err":"timeout"}"#

        final class ScriptSessionDelegate: NSObject, URLSessionTaskDelegate {
            let allowInsecure: Bool
            let noRedirect: Bool
            init(allowInsecure: Bool, noRedirect: Bool) {
                self.allowInsecure = allowInsecure
                self.noRedirect = noRedirect
            }
            func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
                completionHandler(noRedirect ? nil : request)
            }
            func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
                if allowInsecure, challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                   let trust = challenge.protectionSpace.serverTrust {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                }
                completionHandler(.performDefaultHandling, nil)
            }
        }

        let delegate = ScriptSessionDelegate(allowInsecure: req.insecure ?? false, noRedirect: req.noRedirect ?? false)
        let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)

        let task = session.dataTask(with: request) { data, response, error in
            defer { sem.signal() }
            if let error {
                respMeta = #"{"id":\#(req.id),"err":"\#(error.localizedDescription)"}"#
                return
            }
            if let http = response as? HTTPURLResponse {
                respData = data ?? Data()
                var pairs: [[String]] = []
                for (k, v) in http.allHeaderFields {
                    pairs.append([String(describing: k), String(describing: v)])
                }
                let metaObj: [String: Any] = [
                    "id": req.id,
                    "status": http.statusCode,
                    "headers": pairs
                ]
                if let md = try? JSONSerialization.data(withJSONObject: metaObj),
                   let ms = String(data: md, encoding: .utf8) {
                    respMeta = ms
                }
            }
        }
        task.resume()
        _ = sem.wait(timeout: .now() + (request.timeoutInterval > 0 ? request.timeoutInterval : 15.0))
        return NativeScriptFetch(meta: respMeta, body: respData)
    }

    func memLow() -> Bool {
        NativeMemoryGovernor.active?.level == .critical
    }

    func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit {
        let ticket: Int64 = { lock.lock(); defer { lock.unlock() }; ticketSeq += 1; return ticketSeq }()
        return ScriptAdmit(ok: true, ticket: ticket, cap: 256 << 10, limit: 256 << 10)
    }

    func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String { "" }
    func reqLimit(gen: Int64, rule: Int) -> Int64 { 256 << 10 }
    func held() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return activeSlots
    }
}

/// Backwards compatibility alias for GoScriptHost
typealias GoScriptHost = NativeScriptHost
