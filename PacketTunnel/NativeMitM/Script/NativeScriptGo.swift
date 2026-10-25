// Two builds of this file (feat/native-core-eval): TERN_NO_GO = the Go-free tunnel on NativeCore (no Libmihomo);
// otherwise the app target, which still links Go and drives the Go-backed MitM benches/tests.
#if TERN_NO_GO
// Native MitM stage 3, lane s3-script — what the native script dispatcher still asks Go (bridge/mitmscript.go,
// bridge/mitm/nativescript.go). None of these calls carries a response body: admission (script slots, the
// large-bundle lock and queue, the body budget incl. the small pool, the one-large-body lock, memory gates), the
// program cache index (the JavaScriptCore context of a script is loaded / dropped by Go), host APIs whose state is
// Go's ($persistentStore shared with the app, notifications, $httpAPI, geo, $httpClient through mihomo routing), and
// every log line / request-log note, formatted by the Go path's own code.
//
// ScriptGoHost is a protocol so the unit tests can count calls; production is GoScriptHost.

import Foundation
import os
import UserNotifications

// MARK: - Switch

enum NativeScriptRuntime {
    /// App-group key; default OFF (enable after device measurement).
    static let defaultsKey = "nativeMitmScript"

    /// Tests force it; nil = read the app-group default (cached for a second).
    static var override: Bool?

    private static let lock = NSLock()
    private static var cached: Bool?
    private static var readAt: TimeInterval = 0

    /// Explicit app-group value, else ON while selective native mode is installed (feat/selective-native).
    static var enabled: Bool {
        if let o = override { return o }
        lock.lock()
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = NativeMitmRuntime.explicitSwitch(defaultsKey)
        }
        let explicit = cached
        lock.unlock()
        return NativeMitmRuntime.engineSwitch(explicit: explicit)
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
    /// NativeCore: the streaming charge bodyAdmit opened for ticket (nil: none — the Go host, fakes).
    func bodyCharge(ticket: Int64) -> NativeBodyCharge?
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
    // large-body admission (bridge/mitm largebody.go)
    private var waitingTokens: Set<Int64> = []
    private var cancelledTokens: Set<Int64> = []
    /// the streaming charge of each admitted response body (NativeScriptBodyBudget)
    private var charges: [Int64: NativeBodyCharge] = [:]
    /// ticket → rule, so bodyLoaded can remember how large a rule's bodies decode (the unknown-length estimate).
    private var ticketRules: [Int64: Int] = [:]
    private var bodyHints: [Int: Int64] = [:]
    private var lastReclaim: TimeInterval = 0
    private var jscCollectPending = false

    func ready() -> Bool { true }

    func token() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        tokenSeq += 1
        return tokenSeq
    }

    func cancel(_ token: Int64) {
        lock.lock(); defer { lock.unlock() }
        if waitingTokens.contains(token) { cancelledTokens.insert(token) }
    }

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

    // MARK: scripts (feat/native-core-eval)
    //
    // The app (bridge/nativeprep.go → mitm.ExportScriptManifest) writes nativecore-scripts.json: per script rule its
    // rule index, the code file (BOM stripped, Egern adapted), the run timeout and __tern_begin's setup base. The
    // prelude is the target's TernPrelude.js (= Go's PreludeSource, TestNativePreludeBundleCurrent). prepare() loads
    // a script into JavaScriptCore the first time it runs (and again after the engine dropped it: reload).

    struct ManifestEntry: Decodable {
        var i: Int
        var key: String?
        var name: String
        var type: String?
        var file: String?
        var timeoutMs: Int64?
        var maxSize: Int64?
        var err: String?
        /// The setup base as JSON text (decoded from the raw "setup" object).
        var setupJSON = "{}"
        enum CodingKeys: String, CodingKey { case i, key, name, type, file, timeoutMs, maxSize, err }
    }

    private var home = ""
    private var manifest: [Int: ManifestEntry] = [:]
    private var loadedKeys: Set<String> = []
    private var preludeState: String?   // nil: not tried; "": ready; else the error
    private var logLines = 0

    /// The prelude handed to JavaScriptCore (bundled resource).
    static func bundledPrelude() -> String? {
        guard let url = Bundle.main.url(forResource: "TernPrelude", withExtension: "js") else { return nil }
        return try? String(contentsOf: url, encoding: .utf8)
    }

    /// Prepares the prelude (once) and reads the app's script manifest. Returns a log line.
    @discardableResult
    func load(home: String) -> String {
        lock.lock()
        let needPrelude = preludeState == nil
        lock.unlock()
        if needPrelude {
            let state: String
            if let p = Self.bundledPrelude() {
                state = JSCScriptEngine.shared.prepare(p)
            } else {
                state = "TernPrelude.js missing from the bundle"
            }
            lock.lock(); preludeState = state; lock.unlock()
        }
        var entries: [Int: ManifestEntry] = [:]
        var note = ""
        let url = URL(fileURLWithPath: home).appendingPathComponent("nativecore-scripts.json")
        if let data = try? Data(contentsOf: url),
           let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let list = obj["scripts"] as? [[String: Any]] {
            // gap C3: task scripts (cron / event / generic / interaction) share the manifest at i = -1 - task index
            for raw in list + ((obj["tasks"] as? [[String: Any]]) ?? []) {
                guard let d = try? JSONSerialization.data(withJSONObject: raw),
                      var e = try? JSONDecoder().decode(ManifestEntry.self, from: d) else { continue }
                if let setup = raw["setup"], let sd = try? JSONSerialization.data(withJSONObject: setup),
                   let ss = String(data: sd, encoding: .utf8) {
                    e.setupJSON = ss
                }
                entries[e.i] = e
            }
        } else {
            note = " (no nativecore-scripts.json)"
        }
        lock.lock()
        self.home = home
        manifest = entries
        geoDBs = nil // ASN.mmdb may have been downloaded since
        let pState = preludeState ?? ""
        lock.unlock()
        let bad = entries.values.filter { $0.err != nil }.count
        let engine = JSCScriptEngine.shared.canInterrupt ? "interruptible" : "NOT interruptible (scripts off)"
        return "\(entries.count) script rule(s), \(bad) unloadable\(note); prelude \(pState.isEmpty ? "ok" : pState); JSC \(engine)"
    }

    func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared {
        lock.lock()
        let entry = manifest[rule]
        let home = self.home
        let pState = preludeState
        lock.unlock()
        guard let entry else { return ScriptPrepared(ok: false, err: "脚本规则已更新") }
        if let pState, !pState.isEmpty { return ScriptPrepared(ok: false, err: "脚本引擎不可用：" + pState) }
        if let err = entry.err { return ScriptPrepared(ok: false, err: err) }
        guard let key = entry.key, let file = entry.file else { return ScriptPrepared(ok: false, err: "加载脚本失败：无脚本文件") }
        lock.lock()
        let loaded = loadedKeys.contains(key)
        lock.unlock()
        if !loaded || reload {
            let url = URL(fileURLWithPath: home).appendingPathComponent(file)
            guard let code = try? String(contentsOf: url, encoding: .utf8) else {
                return ScriptPrepared(ok: false, err: "加载脚本失败：读取 \(file) 失败")
            }
            let msg = JSCScriptEngine.shared.load(key, name: entry.name, source: code)
            if !msg.isEmpty { return ScriptPrepared(ok: false, err: msg) }
            lock.lock(); loadedKeys.insert(key); lock.unlock()
        }
        var p = ScriptPrepared(ok: true, key: key)
        p.name = entry.name
        p.timeoutMs = entry.timeoutMs ?? 10_000
        p.setupJSON = entry.setupJSON
        return p
    }

    // MARK: body budget (NativeCore — NativeScriptBodyBudget: streamed, charged by actual decoded size)

    static let maxScriptBody: Int64 = 4 << 20
    static let bodyHardMax: Int64 = 8 << 20
    static let bodyBudgetMin: Int64 = 256 << 10
    /// Kept available (NativeCore 1.5 MB; Go needed 3 MB for its GC headroom) — NativeScriptBodyBudget.Config.
    static var largeBodyReserve: Int64 { NativeScriptBodyBudget.shared.config.reserve }
    /// request bodies (loaded whole before the script) and the limit note: the body + one JavaScriptCore copy
    static let bodyCopyFactor: Int64 = 2

    /// The up-front budget for bodies that are not streamed through the charge (request bodies).
    static func dynamicBodyMax() -> Int64 {
        let avail = Int64(os_proc_available_memory())
        if avail <= 0 { return maxScriptBody }
        return Swift.min(Swift.max((avail - largeBodyReserve) / bodyCopyFactor, bodyBudgetMin), bodyHardMax)
    }

    private func entry(_ rule: Int) -> ManifestEntry? { lock.lock(); defer { lock.unlock() }; return manifest[rule] }

    /// The body size handed to rule's script for a request body: its max-size within the dynamic budget.
    func scriptBodyLimit(_ rule: Int) -> Int64 {
        let dyn = Self.dynamicBodyMax()
        if let m = entry(rule)?.maxSize, m > 0, m < dyn { return m }
        return dyn
    }

    /// A response body's cap: the script's max-size, else the shared budget's — the live charge decides the rest.
    func streamLimit(_ rule: Int) -> Int64 {
        let hard = NativeScriptBodyBudget.shared.config.hardMax
        if let m = entry(rule)?.maxSize, m > 0, m < hard { return m }
        return hard
    }

    private func limitNote(_ rule: Int, _ limit: Int64) -> String {
        if let m = entry(rule)?.maxSize, m > 0, m == limit { return "脚本 max-size \(limit >> 10) KB" }
        let avail = Int64(os_proc_available_memory())
        if avail > 0 { return String(format: "上限 %lld KB，隧道可用 %.1f MB", limit >> 10, Double(avail) / 1048576) }
        return "上限 \(limit >> 10) KB"
    }

    // MARK: response body admission (NativeCore; replaces the 11347ec port of bridge/mitm/largebody.go)
    //
    // No decoded-size estimate: a body starts when its raw length + slack fits above the reserve
    // (NativeScriptBodyBudget.roomToStart); the store charges every raw / decoded byte as it appends it and stops
    // only when the bytes really produced would cross the reserve, the shared budget or the script's max-size.
    // Short of room to start: JavaScriptCore garbage + the governor's reclaim (or malloc relief), then a bounded
    // wait (largeBodyWait, token cancel, 1 s without a rise ends it). The wait holds no lock — neither this host's
    // nor any dispatcher / driver lock (the caller is the session's own serial queue) — and gives the flow's
    // script slot back meanwhile. NativeMemoryGovernor.runReclaim is safe on any thread: its reclaimer list is
    // immutable, each reclaimer takes its own lock (NativeBodyStore.trimForMemory, BoundedLRU) or hops to its own
    // queue (JSC collection, UpstreamPool.closeIdle), and it touches none of the governor's locked state.

    static let largeBodyWait: TimeInterval = 4
    static let largeBodyStall: TimeInterval = 1
    static let largeBodyPoll: TimeInterval = 0.1

    static func availableMemory() -> Int64? {
        let a = Int64(os_proc_available_memory())
        return a > 0 ? a : nil
    }

    /// Makes room: JavaScriptCore garbage (coalesced, off this thread — collection takes the VM lock a running
    /// script holds) and the governor's reclaim, or malloc relief without a governor. At most once a second.
    private func reclaimForLargeBody() {
        let now = Date().timeIntervalSince1970
        lock.lock()
        if now - lastReclaim < 1 { lock.unlock(); return }
        lastReclaim = now
        let startGC = !jscCollectPending
        if startGC { jscCollectPending = true }
        lock.unlock()
        // everything below runs with no lock held
        if startGC {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                JSCScriptEngine.shared.collect()
                guard let self else { return }
                self.lock.lock(); self.jscCollectPending = false; self.lock.unlock()
            }
        }
        if let g = NativeMemoryGovernor.active {
            _ = g.runReclaim(upTo: .high, why: "script body")
        } else {
            _ = malloc_zone_pressure_relief(nil, 0)
        }
    }

    /// Waits (no lock held; bounded by largeBodyWait, the token's cancel and a 1 s stall) until a body of rawLength
    /// can start. The flow's script slot is given back meanwhile. Returns ms waited.
    private func waitRoomToStart(rawLength: Int64, token: Int64) -> Int {
        let budget = NativeScriptBodyBudget.shared
        reclaimForLargeBody()
        if budget.roomToStart(rawLength: rawLength) { return 0 }
        let start = Date()
        lock.lock()
        waitingTokens.insert(token)
        let parked = activeSlots > 0
        if parked { activeSlots -= 1 }
        lock.unlock()
        var best = Self.availableMemory() ?? 0
        var rose = Date()
        while Date().timeIntervalSince(start) < Self.largeBodyWait {
            Thread.sleep(forTimeInterval: Self.largeBodyPoll)
            lock.lock(); let cancelled = cancelledTokens.contains(token); lock.unlock()
            if cancelled { break }
            reclaimForLargeBody()
            if budget.roomToStart(rawLength: rawLength) { break }
            let avail = Self.availableMemory() ?? 0
            if avail > best + (256 << 10) { best = avail; rose = Date() }
            if Date().timeIntervalSince(rose) >= Self.largeBodyStall { break } // nothing more is coming back
        }
        lock.lock()
        waitingTokens.remove(token)
        cancelledTokens.remove(token)
        if parked { activeSlots += 1 }
        lock.unlock()
        return Int(Date().timeIntervalSince(start) * 1000)
    }

    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
        let limit = streamLimit(rule)
        if contentLength > limit {
            return ScriptAdmit(ok: false, skip: "响应体 \(contentLength >> 10) KB 超过上限 \(limit >> 10) KB（\(limitNote(rule, limit))）")
        }
        // the store's cap: the largest any of the response's scripts takes (each script checks its own limit later)
        let cap = Swift.max(respRules.map { streamLimit($0) }.max() ?? limit, limit)
        let budget = NativeScriptBodyBudget.shared
        var charge = budget.admit(rawLength: contentLength, limit: cap)
        var waited = 0
        if charge == nil {
            waited = waitRoomToStart(rawLength: contentLength, token: token)
            charge = budget.admit(rawLength: contentLength, limit: cap)
        }
        let avail = Double(Self.availableMemory() ?? 0) / 1048576
        guard let charge else {
            let raw = contentLength < 0 ? "长度未知" : "\(contentLength >> 10) KB"
            return ScriptAdmit(ok: false, skip: String(format: "内存紧张（隧道可用 %.1f MB，保留 %lld KB），等待 %ld ms 后仍无法开始读取响应体（%@，%@）",
                                                       avail, budget.config.reserve >> 10, waited, raw, enc.isEmpty ? "identity" : enc))
        }
        if waited > 0 {
            StartupLog.write(String(format: "[MitM] 响应体（%@，压缩 %lld KB）等待内存 %ld ms 后开始流式解压，隧道可用 %.1f MB：%@",
                                    enc.isEmpty ? "identity" : enc, Swift.max(contentLength, 0) >> 10, waited, avail, String(url.prefix(100))))
        }
        lock.lock()
        ticketSeq += 1
        let ticket = ticketSeq
        ticketRules[ticket] = rule
        charges[ticket] = charge
        lock.unlock()
        return ScriptAdmit(ok: true, ticket: ticket, cap: cap, limit: limit)
    }

    func bodyCharge(ticket: Int64) -> NativeBodyCharge? {
        lock.lock(); defer { lock.unlock() }
        return charges[ticket]
    }

    /// remembers how large a rule's bodies decode (decays towards smaller answers) — diagnostics only now.
    private func noteBodyDecoded(ticket: Int64, _ n: Int64) {
        lock.lock(); defer { lock.unlock() }
        guard let rule = ticketRules[ticket] else { return }
        let prev = bodyHints[rule] ?? 0
        if bodyHints[rule] == nil && bodyHints.count >= 256, let k = bodyHints.keys.first { bodyHints.removeValue(forKey: k) }
        bodyHints[rule] = Swift.min(Swift.max(n, prev * 3 / 4), Self.bodyHardMax)
    }

    func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String {
        if decoded > 0 { noteBodyDecoded(ticket: ticket, decoded) }
        return ""
    }
    /// The load stopped: the charge says why (memory / shared budget / max-size) — the 「跳过脚本」 reason.
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String {
        let c: NativeBodyCharge? = { lock.lock(); defer { lock.unlock() }; return charges[ticket] }()
        if kind == "too-big", let c, c.stop != nil {
            let note = c.stopNote(rawReceived: raw)
            StartupLog.write("[MitM] 响应体流式解压停止：\(note)：\(String(url.prefix(100)))")
            return note
        }
        if kind == "too-big" { return "响应体超过上限" }
        if kind == "decode" { return "响应体解压失败：" + detail }
        return detail
    }
    /// The ticket ends; the charge itself is released by the store when it frees the body (or here when no store
    /// body took it: the last reference goes and NativeBodyCharge.deinit releases it).
    func bodyRelease(ticket: Int64) {
        lock.lock(); defer { lock.unlock() }
        ticketRules.removeValue(forKey: ticket)
        charges.removeValue(forKey: ticket)
    }
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck {
        let l = limit < 0 ? streamLimit(rule) : limit
        if blen <= l { return ScriptBodyCheck(limit: l) }
        let why = "响应体 \(blen >> 10) KB 超过上限 \(l >> 10) KB（\(limitNote(rule, l))）"
        return ScriptBodyCheck(limit: l, note: skip(gen: gen, rule: rule, why: why))
    }

    /// modifyResponse's 「跳过脚本：」 line (startup log here) and the request-log note.
    func skip(gen: Int64, rule: Int, why: String) -> String {
        let name = entry(rule)?.name ?? "script"
        let w = why.isEmpty ? "响应体超过上限或编码不支持" : why
        StartupLog.write("跳过脚本：\(name) — \(w)")
        return "跳过脚本：" + name + " — " + w
    }

    func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail {
        let name = entry(rule)?.name ?? "script"
        let why: String
        switch stop {
        case 1: why = "脚本超时（\(timeoutMs / 1000) 秒）"
        case 2: why = "内存紧张，脚本已停止"
        case 3: why = "连接已关闭，脚本已停止"
        default: why = detail.isEmpty ? "脚本错误" : detail
        }
        StartupLog.write("脚本失败：\(name) — \(why)\(afterDone ? "（$done 之后）" : "")")
        var f = ScriptFail()
        if afterDone && stop == 0 {
            f.ignored = true // an exception after $done: logged, the answer stands (Go: Ignored, no note)
            f.msg = why
        } else {
            f.note = "脚本错误：" + name + " — " + why
        }
        return f
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
            guard kl >= 0, utf16.count >= kl else { return "false" }
            let keyEnd = String.Index(utf16Offset: kl, in: after)
            let key = String(after[..<keyEnd])
            let val = String(after[keyEnd...])
            if del {
                return NCPersistentStore.shared.delete(key: key) ? "true" : "false"
            } else {
                return NCPersistentStore.shared.write(key: key, value: val) ? "true" : "false"
            }
        case "sclear":
            return NCPersistentStore.shared.clear() ? "true" : "false"
        case "log":
            // console.log & co (Go's log ring is gone): the startup log, bounded per line.
            // gap C4: script log page (/mitm/logs) + live /logs stream through NativeLogRing; the startup log keeps
            // the first 500 lines per process as before.
            let nl = arg.firstIndex(of: "\n")
            let level = nl.map { String(arg[..<$0]) } ?? "log"
            let msg = nl.map { String(arg[arg.index(after: $0)...]) } ?? arg
            NativeLogRing.shared.addScript(script: entry(rule)?.name ?? "script #\(rule)", level: level, msg: msg)
            lock.lock(); logLines += 1; let n = logLines; lock.unlock()
            if n <= 500 { StartupLog.write("script #\(rule): " + String(arg.prefix(300)), mirror: false) }
            return ""
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
            guard let k = arg.first else { return "" }
            return geoLookupFull(k, String(arg.dropFirst()))
        case "apisync":
            return NativeHTTPAPI.sync(arg)
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

    /// $httpAPI (gap C3): answered by NativeHTTPAPI against NativeCore's engine; {"id","v"} for __tern_deliver.
    func api(gen: Int64, rule: Int, arg: String) -> String {
        NativeHTTPAPI.async(arg, script: entry(rule)?.name ?? "script #\(rule)")
    }

    // $utils.geoip / ipasn / ipaso (gap C3): country, ASN number and AS organisation, like bridge/engine.go
    // geoLookup. The databases are mapped (not read into memory) on first use.
    private var geoDBs: (country: NCMMDB?, asn: NCMMDB?)?

    private func geoDatabases() -> (country: NCMMDB?, asn: NCMMDB?) {
        lock.lock()
        if let g = geoDBs { lock.unlock(); return g }
        let h = home
        lock.unlock()
        let base = URL(fileURLWithPath: h)
        func open(_ name: String) -> NCMMDB? {
            guard let d = try? Data(contentsOf: base.appendingPathComponent(name), options: .alwaysMapped), d.count > 1024 else { return nil }
            return NCMMDB(data: d)
        }
        let g = (country: open("geoip.metadb") ?? open("Country.mmdb"), asn: open("ASN.mmdb"))
        lock.lock(); geoDBs = g; lock.unlock()
        return g
    }

    func geoLookupFull(_ kind: Character, _ ipStr: String) -> String {
        let s = ipStr.trimmingCharacters(in: .whitespaces)
        guard let ip = NCIP(s) else { return "" }
        let dbs = geoDatabases()
        switch kind {
        case "c":
            if let c = Self.geoLookup?(s) ?? dbs.country?.countryCode(for: ip) { return c.uppercased() }
            return ""
        case "a", "o":
            guard let rec = dbs.asn?.lookup(ip), let m = rec.object else { return "" }
            if kind == "o" { return m["autonomous_system_organization"]?.string ?? m["as_name"]?.string ?? "" }
            var asn = m["autonomous_system_number"]?.int.map(String.init) ?? m["asn"]?.string ?? ""
            if asn.hasPrefix("AS") || asn.hasPrefix("as") { asn = String(asn.dropFirst(2)) }
            return asn == "0" ? "" : asn
        default:
            return ""
        }
    }

    /// $httpClient (NativeCore): NCScriptHTTPClient on NCUpstreamConnector — the request follows the tunnel's rules
    /// (direct / reject / proxy with origin TLS over the relay), not the extension's own URLSession sockets. Meta
    /// JSON as before: {"id","status","headers":[[name,value],…]} (order kept, every Set-Cookie its own pair; the
    /// body decoded, Content-Length its decoded size) or {"id","err"}.
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
        func errMeta(_ id: Int64, _ msg: String) -> String {
            let o: [String: Any] = ["id": id, "err": msg]
            if let d = try? JSONSerialization.data(withJSONObject: o), let s = String(data: d, encoding: .utf8) { return s }
            return #"{"id":\#(id),"err":"fetch failed"}"#
        }
        guard let req = try? JSONDecoder().decode(FetchReqArg.self, from: Data(arg.utf8)) else {
            return NativeScriptFetch(meta: #"{"id":0,"err":"invalid fetch request"}"#, body: Data())
        }
        guard let targetURL = URL(string: req.url) else {
            return NativeScriptFetch(meta: errMeta(req.id, "invalid url"), body: Data())
        }
        var r = NCScriptHTTPClient.Request(url: targetURL)
        r.method = (req.method ?? "GET").isEmpty ? "GET" : (req.method ?? "GET")
        r.headers = (req.headers ?? []).compactMap { $0.count == 2 ? ($0[0], $0[1]) : nil }
        r.body = body
        // Go's fetchReq: 15 s unless the script asks (ms)
        r.timeout = (req.timeout ?? 0) > 0 ? req.timeout! / 1000.0 : 15
        r.noRedirect = req.noRedirect ?? false
        r.policy = req.policy
        r.insecure = req.insecure ?? false
        switch NCScriptHTTPClient.fetch(r) {
        case .failure(let f):
            lock.lock(); logLines += 1; let n = logLines; lock.unlock()
            if n <= 500 { StartupLog.write("script #\(rule): $httpClient \(r.method) \(String(req.url.prefix(100))) failed: \(f)") }
            return NativeScriptFetch(meta: errMeta(req.id, f.description), body: Data())
        case .success(let resp):
            let metaObj: [String: Any] = [
                "id": req.id,
                "status": resp.status,
                "headers": resp.headers.map { [$0.0, $0.1] },
            ]
            guard let md = try? JSONSerialization.data(withJSONObject: metaObj), let ms = String(data: md, encoding: .utf8) else {
                return NativeScriptFetch(meta: errMeta(req.id, "meta encoding"), body: Data())
            }
            return NativeScriptFetch(meta: ms, body: resp.body)
        }
    }

    func memLow() -> Bool {
        NativeMemoryGovernor.active?.level == .critical
    }

    func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit {
        let limit = scriptBodyLimit(rule)
        if contentLength > limit {
            return ScriptAdmit(ok: false, skip: "请求体 \(contentLength >> 10) KB 超过上限 \(limit >> 10) KB（\(limitNote(rule, limit))）")
        }
        let ticket: Int64 = { lock.lock(); defer { lock.unlock() }; ticketSeq += 1; return ticketSeq }()
        return ScriptAdmit(ok: true, ticket: ticket, cap: limit, limit: limit)
    }

    func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String {
        skip(gen: gen, rule: rule, why: why.isEmpty ? "请求体 \(blen >> 10) KB 超过上限" : why)
    }
    func reqLimit(gen: Int64, rule: Int) -> Int64 { scriptBodyLimit(rule) }
    func held() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return activeSlots
    }
}

/// Backwards compatibility alias for GoScriptHost
typealias GoScriptHost = NativeScriptHost
#else
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
    private static var cached: Bool?
    private static var readAt: TimeInterval = 0

    /// Explicit app-group value, else ON while selective native mode is installed (feat/selective-native).
    static var enabled: Bool {
        if let o = override { return o }
        lock.lock()
        let now = Date().timeIntervalSince1970
        if now - readAt > 1 {
            readAt = now
            cached = NativeMitmRuntime.explicitSwitch(defaultsKey)
        }
        let explicit = cached
        lock.unlock()
        return NativeMitmRuntime.engineSwitch(explicit: explicit)
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
    /// NativeCore: the streaming charge bodyAdmit opened for ticket (nil: none — the Go host, fakes).
    func bodyCharge(ticket: Int64) -> NativeBodyCharge?
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
#endif
