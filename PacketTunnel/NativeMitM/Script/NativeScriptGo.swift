// Native MitM stage 3, lane s3-script — what the native script dispatcher still asks Go (bridge/mitmscript.go,
// bridge/mitm/nativescript.go). None of these calls carries a response body: admission (script slots, the
// large-bundle lock and queue, the body budget incl. the small pool, the one-large-body lock, memory gates), the
// program cache index (the JavaScriptCore context of a script is loaded / dropped by Go), host APIs whose state is
// Go's ($persistentStore shared with the app, notifications, $httpAPI, geo, $httpClient through mihomo routing), and
// every log line / request-log note, formatted by the Go path's own code.
//
// ScriptGoHost is a protocol so the unit tests can count calls; production is GoScriptHost.

import Foundation
import Libmihomo

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

final class GoScriptFetch: ScriptFetch {
    private let r: LibmihomoMitmScriptFetchResult?
    let meta: String
    let body: Data
    init(_ r: LibmihomoMitmScriptFetchResult?) {
        self.r = r
        meta = r?.meta() ?? #"{"id":0,"err":"fetch failed"}"#
        body = r?.body() ?? Data()
    }
    func done() { r?.done() }
}

final class GoScriptHost: ScriptGoHost {
    static let shared = GoScriptHost()

    func ready() -> Bool { LibmihomoMitmScriptReady() }
    func token() -> Int64 { LibmihomoMitmScriptToken() }
    func cancel(_ token: Int64) { LibmihomoMitmScriptCancel(token) }
    func reserve(gen: Int64, rule: Int, token: Int64) -> ScriptReserveAnswer {
        decodeJSON(LibmihomoMitmScriptReserve(gen, rule, token), ScriptReserveAnswer(err: "脚本运行时内部错误：reserve"))
    }
    func release(slot: Int64, ran: Bool) { LibmihomoMitmScriptRelease(slot, ran) }
    func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared {
        ScriptPrepared.decode(LibmihomoMitmScriptPrepare(gen, rule, slot, reload))
    }
    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
        let csv = respRules.map(String.init).joined(separator: ",")
        return decodeJSON(LibmihomoMitmScriptBodyAdmit(gen, rule, csv, url, contentLength, enc, token), ScriptAdmit(gone: true))
    }
    func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String { LibmihomoMitmScriptBodyLoaded(ticket, url, decoded) }
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String {
        LibmihomoMitmScriptBodyFailed(ticket, url, kind, raw, detail)
    }
    func bodyRelease(ticket: Int64) { LibmihomoMitmScriptBodyRelease(ticket) }
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck {
        decodeJSON(LibmihomoMitmScriptBodyCheck(gen, rule, blen, limit), ScriptBodyCheck(limit: 0, note: "脚本规则已更新"))
    }
    func skip(gen: Int64, rule: Int, why: String) -> String { LibmihomoMitmScriptSkip(gen, rule, why) }
    func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail {
        decodeJSON(LibmihomoMitmScriptFail(gen, rule, mode, detail, stop, timeoutMs, afterDone), ScriptFail())
    }
    func host(gen: Int64, rule: Int, op: String, arg: String) -> String { LibmihomoMitmScriptHost(gen, rule, op, arg) }
    func bytes(op: String, arg: String, input: Data) -> Data? { LibmihomoMitmScriptBytes(op, arg, input) }
    func api(gen: Int64, rule: Int, arg: String) -> String { LibmihomoMitmScriptAPI(gen, rule, arg) }
    func fetch(gen: Int64, rule: Int, token: Int64, arg: String, body: Data) -> ScriptFetch {
        GoScriptFetch(LibmihomoMitmScriptFetch(gen, rule, token, arg, body))
    }
    func memLow() -> Bool { LibmihomoMitmScriptMemLow() }
    func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit {
        decodeJSON(LibmihomoMitmScriptReqBodyAdmit(gen, rule, url, contentLength, token), ScriptAdmit(gone: true))
    }
    func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String { LibmihomoMitmScriptReqBodySkip(gen, rule, why, blen) }
    func reqLimit(gen: Int64, rule: Int) -> Int64 { LibmihomoMitmScriptReqLimit(gen, rule) }
    func held() -> Int64 { LibmihomoMitmScriptHeld() }
}
