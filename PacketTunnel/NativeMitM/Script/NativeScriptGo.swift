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
    /// granted large-body limits by ticket, and their sum: concurrent grants share one budget (bodyHardMax).
    private var largeGrants: [Int64: Int64] = [:]
    private var largeCharged: Int64 = 0
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
            for raw in list {
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

    // MARK: body budget (bridge/mitm handler.go dynamicBodyMax / scriptBodyLimit)

    static let maxScriptBody: Int64 = 4 << 20
    static let bodyHardMax: Int64 = 8 << 20
    static let bodyBudgetMin: Int64 = 256 << 10
    /// Kept free by the dynamic budget (bridge/mitm largebody.go: 3 MB, was 4 — the running script is interrupted
    /// below 2.5 MB and the governor sheds connections at 3 MB, so 3 MB is the line nothing crosses).
    static let largeBodyReserve: Int64 = 3 << 20
    static let bodyCopyFactor: Int64 = 3

    /// The body budget from the memory iOS still allows the extension (unknown → MaxScriptBody).
    static func dynamicBodyMax() -> Int64 {
        let avail = Int64(os_proc_available_memory())
        if avail <= 0 { return maxScriptBody }
        return Swift.min(Swift.max((avail - largeBodyReserve) / bodyCopyFactor, bodyBudgetMin), bodyHardMax)
    }

    private func entry(_ rule: Int) -> ManifestEntry? { lock.lock(); defer { lock.unlock() }; return manifest[rule] }

    /// The body size handed to rule's script: its max-size within the dynamic budget.
    func scriptBodyLimit(_ rule: Int) -> Int64 {
        let dyn = Self.dynamicBodyMax()
        if let m = entry(rule)?.maxSize, m > 0, m < dyn { return m }
        return dyn
    }

    private func limitNote(_ rule: Int, _ limit: Int64) -> String {
        if let m = entry(rule)?.maxSize, m > 0, m == limit { return "脚本 max-size \(limit >> 10) KB" }
        let avail = Int64(os_proc_available_memory())
        if avail > 0 { return String(format: "当前内存预算 %d KB，隧道可用 %.1f MB", limit >> 10, Double(avail) / 1048576) }
        return "上限 \(limit >> 10) KB"
    }

    // MARK: large-body admission (port of bridge/mitm/largebody.go, 8b29812 — astemo6/Muse)
    //
    // A body for a script on the dynamic budget is estimated before it is read (Content-Length × the encoding's
    // typical ratio, or what this rule's bodies decoded to before when the length is unknown). When the budget is
    // short of it, room is made first — JavaScriptCore garbage collected, the governor's reclaim (or malloc relief)
    // — and the admission waits up to largeBodyWait for running scripts to end, with this flow's script slot given
    // back meanwhile. A wait that ran out still admits the body at the tight budget ((avail − reserve) / 2) when the
    // body's low estimate fits it.

    static let largeBodyWait: TimeInterval = 4
    static let largeBodyStall: TimeInterval = 1
    static let largeBodyPoll: TimeInterval = 0.1
    static let smallWorkMax: Int64 = 256 << 10
    static let tightCopyFactor: Int64 = 2
    /// below this the running script is interrupted anyway (handler.go bodyAvailFloor / scriptAvailFloor)
    static let bodyAvailFloor: Int64 = 5 << 19

    /// decoded / encoded size assumed for a body with a known Content-Length.
    static func decodeRatio(_ enc: String) -> Int64 {
        switch enc.trimmingCharacters(in: .whitespaces).lowercased() {
        case "", "identity": return 1
        case "br": return 8
        default: return 6 // gzip, deflate, others
        }
    }

    static func estimateDecoded(_ cl: Int64, _ enc: String, _ hint: Int64) -> Int64 {
        let est = cl < 0 ? hint : cl &* decodeRatio(enc)
        return Swift.min(Swift.max(est, 0), bodyHardMax)
    }

    /// the least a body is likely to decode to: identity its length, encoded CL × 3, unknown length the hint.
    static func estimateLow(_ cl: Int64, _ enc: String, _ hint: Int64) -> Int64 {
        if cl < 0 { return Swift.min(Swift.max(hint, 0), bodyHardMax) }
        if decodeRatio(enc) > 1 { return Swift.min(cl &* 3, bodyHardMax) }
        return cl
    }

    /// available memory a body of est decoded bytes needs: reserve + copy factor × est.
    static func largeBodyNeed(_ est: Int64) -> Int64 { largeBodyReserve + bodyCopyFactor * est }

    static func availableMemory() -> Int64? {
        let a = Int64(os_proc_available_memory())
        return a > 0 ? a : nil
    }

    static func heapHigh() -> Bool {
        guard let l = NativeMemoryGovernor.active?.level else { return false }
        return l >= .high
    }

    /// the dynamic budget allows est now (and memory is above the floor).
    static func roomFor(_ est: Int64) -> Bool {
        guard let avail = availableMemory() else { return true }
        return avail >= bodyAvailFloor && avail >= largeBodyNeed(est)
    }

    /// dynamicBodyMax at tightCopyFactor (0 below the floor or without a reading).
    static func tightBodyMax() -> Int64 {
        guard let avail = availableMemory(), avail >= bodyAvailFloor else { return 0 }
        return Swift.max(0, Swift.min((avail - largeBodyReserve) / tightCopyFactor, bodyHardMax))
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
        if startGC {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                JSCScriptEngine.shared.collect()
                guard let self else { return }
                self.lock.lock(); self.jscCollectPending = false; self.lock.unlock()
            }
        }
        if let g = NativeMemoryGovernor.active {
            _ = g.runReclaim(upTo: .high, why: "large script body")
        } else {
            _ = malloc_zone_pressure_relief(nil, 0)
        }
    }

    /// Waits (bounded by largeBodyWait and the token's cancel) for room for est decoded bytes; low is the least the
    /// body is expected to need. The flow's script slot is given back while waiting. Returns (room found, ms waited).
    private func waitLargeHeadroom(est: Int64, low: Int64, token: Int64) -> (Bool, Int) {
        guard Self.availableMemory() != nil, est > 0 else { return (true, 0) }
        reclaimForLargeBody()
        if Self.roomFor(est) { return (true, 0) }
        let start = Date()
        lock.lock()
        waitingTokens.insert(token)
        let parked = activeSlots > 0
        if parked { activeSlots -= 1 }
        lock.unlock()
        var ok = false
        var best = Self.availableMemory() ?? 0
        var rose = Date()
        while Date().timeIntervalSince(start) < Self.largeBodyWait {
            Thread.sleep(forTimeInterval: Self.largeBodyPoll)
            lock.lock(); let cancelled = cancelledTokens.contains(token); lock.unlock()
            if cancelled { break }
            reclaimForLargeBody()
            if Self.roomFor(est) { ok = true; break }
            let avail = Self.availableMemory() ?? 0
            if avail > best + (256 << 10) { best = avail; rose = Date() }
            if low > 0, Date().timeIntervalSince(rose) >= Self.largeBodyStall {
                // nothing more is coming back: settle for the low estimate, or stop when only the tight fallback fits
                if Self.roomFor(low) { ok = true; break }
                if Self.tightBodyMax() >= low { break }
            }
        }
        if !ok { ok = Self.roomFor(est) }
        lock.lock()
        waitingTokens.remove(token)
        cancelledTokens.remove(token)
        if parked { activeSlots += 1 }
        lock.unlock()
        return (ok, Int(Date().timeIntervalSince(start) * 1000))
    }

    /// The admission step for a dynamic-budget script: (limit, granted) — granted > 0 when this step decided it.
    private func largeBodyRoom(rule: Int, limit: Int64, url: String, contentLength: Int64, enc: String, token: Int64) -> (Int64, Int64) {
        let maxSize = entry(rule)?.maxSize ?? 0
        if maxSize > 0 && maxSize == limit { return (limit, 0) } // capped by its own max-size, not the budget
        let hint: Int64 = { lock.lock(); defer { lock.unlock() }; return bodyHints[rule] ?? 0 }()
        let est = Self.estimateDecoded(contentLength, enc, hint)
        if est <= Self.smallWorkMax || (est <= limit && !Self.heapHigh()) { return (limit, 0) }
        let low = Self.estimateLow(contentLength, enc, hint)
        let (ok, waited) = waitLargeHeadroom(est: est, low: low, token: token)
        var nl = scriptBodyLimit(rule)
        var granted: Int64 = 0
        var mode = "已腾出"
        if ok {
            granted = nl
        } else {
            let t = Self.tightBodyMax()
            if t > nl && low > 0 && t >= low {
                nl = t; granted = t; mode = "按紧凑预算处理"
            } else {
                mode = "仍不足"
            }
        }
        if maxSize > 0 && nl > maxSize { nl = maxSize; if granted > 0 { granted = maxSize } }
        if waited > 0 || granted > 0 {
            let avail = Double(Self.availableMemory() ?? 0) / 1048576
            StartupLog.write(String(format: "[MitM] 大响应体（预计解压 %lld KB）等待内存 %ld ms，%@：预算 %lld → %lld KB，隧道可用 %.1f MB：%@",
                                    est >> 10, waited, mode, limit >> 10, nl >> 10, avail, String(url.prefix(100))))
        }
        return (nl, granted)
    }

    func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
        var (limit, granted) = largeBodyRoom(rule: rule, limit: scriptBodyLimit(rule), url: url, contentLength: contentLength, enc: enc, token: token)
        if contentLength > limit {
            return ScriptAdmit(ok: false, skip: "响应体 \(contentLength >> 10) KB 超过上限 \(limit >> 10) KB（\(limitNote(rule, limit))）")
        }
        lock.lock()
        ticketSeq += 1
        let ticket = ticketSeq
        ticketRules[ticket] = rule
        if granted > 0 {
            // concurrent grants share one budget: a grant past what is left of it falls back to the plain budget
            let left = Self.bodyHardMax - largeCharged
            if granted > left {
                let plain = scriptBodyLimit(rule)
                granted = Swift.max(left, 0)
                if granted <= plain { granted = 0; limit = Swift.min(limit, plain) } else { limit = Swift.min(limit, granted) }
            }
            if granted > 0 { largeGrants[ticket] = granted; largeCharged += granted }
        }
        lock.unlock()
        if contentLength > limit {
            bodyRelease(ticket: ticket)
            return ScriptAdmit(ok: false, skip: "响应体 \(contentLength >> 10) KB 超过上限 \(limit >> 10) KB（\(limitNote(rule, limit))）")
        }
        // cap: the decode limit for the store (the largest any of the response's scripts takes)
        let cap = respRules.map { $0 == rule ? limit : scriptBodyLimit($0) }.max() ?? limit
        return ScriptAdmit(ok: true, ticket: ticket, cap: Swift.max(cap, limit), limit: limit)
    }

    /// remembers how large a rule's bodies decode (decays towards smaller answers), for unknown-length estimates.
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
    func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String { "" }
    func bodyRelease(ticket: Int64) {
        lock.lock(); defer { lock.unlock() }
        ticketRules.removeValue(forKey: ticket)
        if let g = largeGrants.removeValue(forKey: ticket) { largeCharged = Swift.max(0, largeCharged - g) }
    }
    func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck {
        let l = limit < 0 ? scriptBodyLimit(rule) : limit
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
            lock.lock(); logLines += 1; let n = logLines; lock.unlock()
            if n <= 500 { StartupLog.write("script #\(rule): " + String(arg.prefix(300))) }
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
        // Go's fetchReq: 15 s unless the script asks (ms).
        request.timeoutInterval = (req.timeout ?? 0) > 0 ? req.timeout! / 1000.0 : 15

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
                let o: [String: Any] = ["id": req.id, "err": error.localizedDescription]
                if let md = try? JSONSerialization.data(withJSONObject: o), let ms = String(data: md, encoding: .utf8) {
                    respMeta = ms
                }
                return
            }
            if let http = response as? HTTPURLResponse {
                respData = data ?? Data()
                var pairs: [[String]] = []
                // URLSession hands over the decoded body: drop the encoding / length of the encoded one.
                for (k, v) in http.allHeaderFields {
                    let name = String(describing: k)
                    let lower = name.lowercased()
                    if lower == "content-encoding" || lower == "content-length" { continue }
                    pairs.append([name, String(describing: v)])
                }
                pairs.append(["Content-Length", String(respData.count)])
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
        if sem.wait(timeout: .now() + request.timeoutInterval + 1) == .timedOut { task.cancel() }
        session.finishTasksAndInvalidate() // the session retains its delegate until invalidated
        return NativeScriptFetch(meta: respMeta, body: respData)
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
