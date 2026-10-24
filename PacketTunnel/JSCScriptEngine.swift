import Foundation
import JavaScriptCore
import Libmihomo

/// feat/jsc-engine: MitM / rewrite / task scripts run in JavaScriptCore instead of goja (Go).
///
/// The Go core keeps everything except the JavaScript itself (bridge/mitm/jsengine.go, jsnative.go): the cache
/// index, the event loop, timers, `$httpClient` downloads through the proxy policy, `$persistentStore`, notifications
/// and turning `$done` into the rewrite. Both engines evaluate the same prelude (bridge/mitm/prelude.js), which
/// builds the Surge / Loon / Quantumult X / Egern API on three primitives installed here as `__tern`:
///   `host(op, arg) -> String`, `put(arrayBuffer, offset, length) -> blob id`, `take(id) -> Uint8Array`.
///
/// One `JSVirtualMachine`; one `JSContext` per loaded script (key = source hash, Go decides when to drop it), reused
/// for every run of that script — `__tern_begin` resets the globals a run created. A second concurrent run of the
/// same script gets a temporary context. A run is stopped through JavaScriptCore's execution time limit
/// (`JSContextGroupSetExecutionTimeLimit`, looked up at runtime): every 100 ms of uninterrupted JavaScript the
/// callback asks the run (`shouldStop`, timeout / client gone / memory) and terminates it; the context is then
/// discarded. Without that symbol a runaway script cannot be interrupted: Go gives up on the call after a grace
/// period and switches every later run to goja.
///
/// Note: app extensions get no JIT, so JavaScriptCore runs its bytecode interpreter (LLInt) — still several
/// times faster than goja, and its heap is not the Go heap (GOMEMLIMIT).
/// feat/native-mitm stage 1: the tunnel's native body lane (PacketTunnel/NativeBodyStore.swift). Script blob ids at
/// or above `LibmihomoNativeBlobBase()` name its handles; the engine serves them itself so the bytes never pass
/// through the Go heap. Declared here because this file is also built into the app (脚本调试), which has no lane.
///
/// Threading: every call comes from the thread running JavaScript (inside JavaScriptCore's API lock) and must not
/// call back into JavaScriptCore; the provider takes only its own locks, so a Go goroutine reading the same handle
/// for the client never waits for the VM. Text is built here from `withDecoded` (not with Foundation, whose UTF-8
/// decoding drops a leading BOM — goja keeps it as U+FEFF).
protocol JSCNativeBlobProvider: AnyObject {
    /// `__tern.put` / UTF-8 results at least this large are stored in the lane.
    var putMin: Int { get }
    /// Calls body with the decoded bytes of handle h (false: unknown / failed handle; body not called).
    func withDecoded(_ h: Int64, _ body: (UnsafeRawBufferPointer) -> Void) -> Bool
    /// Stores a copy of bytes as a new handle (0: refused).
    func store(_ bytes: UnsafeRawBufferPointer) -> Int64
    /// Keeps data as a new handle without copying it (0: refused / empty). Default: store(), one copy.
    func adopt(_ data: Data) -> Int64
    func free(_ h: Int64)
}

extension JSCNativeBlobProvider {
    func adopt(_ data: Data) -> Int64 { data.withUnsafeBytes { store($0) } }
}

final class JSCScriptEngine: NSObject, LibmihomoScriptEngineProtocol {
    static let shared = JSCScriptEngine()

    /// The native body lane (set once by the tunnel before LibmihomoStart, never cleared; nil in the app). Read on
    /// the JavaScript thread. After a wedge Go runs scripts on goja and stops opening lane bodies (`nativeUsable`),
    /// so the lane goes idle without this being touched; a late call from the wedged thread only meets handles Go
    /// already freed (withDecoded false → the Go host, which answers nothing for a dead run).
    static var nativeBlobs: JSCNativeBlobProvider?
    /// First native blob id (LibmihomoNativeBlobBase, 2^52).
    private static let nativeBase: Int64 = LibmihomoNativeBlobBase()

    private final class Entry {
        let key: String
        let name: String
        let source: String
        let wrapped: Bool
        var primary: Ctx?
        var dropped = false
        init(key: String, name: String, source: String, wrapped: Bool) {
            self.key = key
            self.name = name
            self.source = source
            self.wrapped = wrapped
        }
    }

    private final class Ctx {
        let context: JSContext
        var main: JSValue?
        var run: LibmihomoScriptRun?
        var busy = false
        var terminated = false
        var poisoned = false
        var exception: JSValue?
        init(context: JSContext) { self.context = context }
    }

    private struct Slot {
        let ctx: Ctx
        let entry: Entry
        let temp: Bool
    }

    private let vm: JSVirtualMachine
    /// Guards the engine's tables. Lock order: never wait for JavaScriptCore's API lock while holding it —
    /// JavaScript objects (JSValue / JSContext / Ctx / Entry) that go away under it are moved to `trash` and
    /// released after the unlock (`unlockAndEmpty`). Otherwise a thread holding `lock` and releasing a JSValue
    /// waits for the VM lock that a running script holds, while that script's host call or time-limit callback
    /// waits for `lock`: a deadlock.
    private let lock = NSLock()
    /// Guards `byRef` only; the time-limit callback (on the thread running JavaScript) takes nothing else.
    private let refLock = NSLock()
    private var trash: [AnyObject] = []
    /// Time-limit callback calls / terminations it asked for (under refLock; diagnostics in stats()).
    private var limitChecks = 0
    private var limitStops = 0
    private var prelude = ""
    private var entries: [String: Entry] = [:]
    private var runs: [Int64: Slot] = [:]
    private var byRef: [OpaquePointer: Ctx] = [:]
    private var gcContext: JSContext?
    private var timeLimit = false
    private var contextsMade = 0

    private override init() {
        vm = JSVirtualMachine()
        super.init()
    }

    /// Registers the engine with the core once per process (tunnel start, 脚本调试 in the app).
    @discardableResult
    static func register() -> String {
        registerLock.lock()
        defer { registerLock.unlock() }
        if let done = registered { return done }
        let msg = LibmihomoSetScriptEngine(shared)
        registered = msg
        return msg
    }
    private static let registerLock = NSLock()
    private static var registered: String?

    /// The engine the core uses now ({"engine":"native|goja",…}).
    static func status() -> String { LibmihomoScriptEngineStatus() }

    /// One engine-conformance case (UnitTests/ScriptEngineConformance.json) on goja and JavaScriptCore.
    static func conformance(home: String, caseJSON: String) -> String { LibmihomoScriptConformance(home, caseJSON) }

    /// Unit tests (lane conformance cases): registers a native body store with the core and this engine, nil
    /// unregisters (the tunnel uses NativeBodyStore.register() and never unregisters).
    static func setLaneForTests(_ lane: (NSObject & LibmihomoNativeBodyStoreProtocol & JSCNativeBlobProvider)?) {
        nativeBlobs = lane
        LibmihomoSetNativeBodyStore(lane)
    }

    /// Lane handles the Go side holds right now (0 when no body is in flight).
    static func laneLive() -> Int64 { LibmihomoNativeLaneLive() }

    /// Every goroutine's stack (the conformance test logs it when a case hangs).
    static func goroutineDump() -> String { LibmihomoGoroutineDump() }

    /// `-TernJSCSelfTest` launch argument: one conformance case, logged (device check without the test bundle).
    static func selfTestIfRequested() {
        guard ProcessInfo.processInfo.arguments.contains("-TernJSCSelfTest") else { return }
        DispatchQueue.global(qos: .utility).async {
            register()
            let c = #"{"name":"selftest","input":{"code":"var o = JSON.parse($response.body); o.ok = true; $done({body: JSON.stringify(o)});","type":"http-response","response":{"status":200,"body":"{}"}},"expect":["ok"]}"#
            let r = conformance(home: NSTemporaryDirectory(), caseJSON: c)
            NSLog("[jsc-selftest] %@ %@", r, status())
        }
    }

    // MARK: LibmihomoScriptEngineProtocol

    func prepare(_ prelude: String?) -> String {
        guard let prelude, !prelude.isEmpty else { return "empty prelude" }
        lock.lock()
        self.prelude = prelude
        lock.unlock()
        // Evaluate it once so a broken prelude keeps scripts on goja instead of failing every run.
        let probe = makeContext()
        if let e = probe.exception {
            return "prelude: " + Self.describe(e)
        }
        lock.lock()
        if let old = gcContext { trash.append(old) }
        trash.append(probe)
        gcContext = probe.context
        if !timeLimit, let group = JSContextGetGroup(probe.context.jsGlobalContextRef) {
            timeLimit = Self.installTimeLimit(group)
        }
        unlockAndEmpty()
        return ""
    }

    func load(_ key: String?, name: String?, source: String?) -> String {
        guard let key, let source else { return "missing source" }
        let name = name ?? "script"
        // Syntax check of the wrapped script (a top-level `return` is allowed, as in Surge); a script that only
        // parses unwrapped is evaluated as it is on every run.
        let wrapped = "(function(){ return function(){\n" + source + "\n}; })()"
        var wrappedOK = true
        var message = ""
        if let err = Self.syntaxError(wrapped, context: gcOrNew()) {
            wrappedOK = false
            message = err
            if Self.syntaxError(source, context: gcOrNew()) != nil { return message }
        }
        let entry = Entry(key: key, name: name, source: source, wrapped: wrappedOK)
        let c = makeContext()
        if let e = c.exception {
            return "prelude: " + Self.describe(e)
        }
        if wrappedOK {
            c.exception = nil
            let fn = c.context.evaluateScript(wrapped, withSourceURL: URL(string: "tern://" + Self.urlName(name) + ".js"))
            if let e = c.exception {
                return Self.describe(e)
            }
            c.main = fn
        }
        lock.lock()
        if let old = entries[key] {
            old.dropped = true
            if let p = old.primary, !p.busy { forget(p) }
            trash.append(old)
        }
        entries[key] = entry
        entry.primary = c
        setRef(c)
        unlockAndEmpty()
        return ""
    }

    func drop(_ key: String?) {
        guard let key else { return }
        lock.lock()
        if let e = entries.removeValue(forKey: key) {
            e.dropped = true
            if let p = e.primary, !p.busy {
                forget(p)
                trash.append(p)
                e.primary = nil
            }
            trash.append(e)
        }
        unlockAndEmpty()
    }

    func collect() {
        lock.lock()
        let g = gcContext
        lock.unlock()
        if let g { JSGarbageCollect(g.jsGlobalContextRef) }
    }

    func begin(_ run: LibmihomoScriptRun?, key: String?, setup: String?) -> String {
        guard let run, let key else { return Self.err("internal", "missing run") }
        let runID = run.id_()
        lock.lock()
        guard let entry = entries[key] else {
            lock.unlock()
            return "missing"
        }
        var ctx: Ctx?
        var temp = false
        if let p = entry.primary, !p.busy, !p.poisoned {
            ctx = p
            p.busy = true
        }
        lock.unlock()
        if ctx == nil {
            // the script's own context is busy (a concurrent run) or was discarded: a fresh one
            let c = makeContext()
            if let e = c.exception { return Self.err("internal", "prelude: " + Self.describe(e)) }
            if entry.wrapped {
                c.exception = nil
                c.main = c.context.evaluateScript("(function(){ return function(){\n" + entry.source + "\n}; })()",
                                                  withSourceURL: URL(string: "tern://" + Self.urlName(entry.name) + ".js"))
                if let e = c.exception { return Self.err("exception", Self.describe(e)) }
            }
            c.busy = true
            lock.lock()
            if entry.primary == nil && !entry.dropped {
                entry.primary = c
            } else {
                temp = true
            }
            setRef(c)
            lock.unlock()
            ctx = c
        }
        guard let c = ctx else { return Self.err("internal", "no context") }
        c.run = run
        c.terminated = false
        lock.lock()
        runs[runID] = Slot(ctx: c, entry: entry, temp: temp)
        lock.unlock()

        if let r = invoke(c, "__tern_begin", setup ?? "{}", name: entry.name) { return r }
        c.exception = nil
        if let main = c.main {
            _ = main.call(withArguments: [])
        } else {
            _ = c.context.evaluateScript(entry.source, withSourceURL: URL(string: "tern://" + Self.urlName(entry.name) + ".js"))
        }
        return outcome(c, name: entry.name, lineOffset: entry.wrapped ? 1 : 0)
    }

    func call(_ runID: Int64, fn: String?, arg: String?) -> String {
        lock.lock()
        let slot = runs[runID]
        lock.unlock()
        guard let slot, let fn else { return Self.err("internal", "unknown run") }
        return invoke(slot.ctx, fn, arg ?? "", name: slot.entry.name) ?? ""
    }

    func end(_ runID: Int64) {
        lock.lock()
        guard let slot = runs.removeValue(forKey: runID) else {
            lock.unlock()
            return
        }
        let c = slot.ctx
        c.run = nil
        c.busy = false
        if let e = c.exception { trash.append(e) }
        c.exception = nil
        if slot.temp || c.poisoned || c.terminated || slot.entry.dropped {
            if slot.entry.primary === c { slot.entry.primary = nil }
            forget(c)
        }
        trash.append(c)
        trash.append(slot.entry)
        unlockAndEmpty()
    }

    func stats() -> String {
        lock.lock()
        defer { lock.unlock() }
        let loaded = entries.values.filter { $0.primary != nil }.count
        let bytes = entries.values.reduce(0) { $0 + $1.source.utf8.count }
        refLock.lock()
        let checks = limitChecks, stops = limitStops
        refLock.unlock()
        return "jsc scripts \(entries.count) (contexts \(loaded), runs \(runs.count), sources \(String(format: "%.1f", Double(bytes) / 1_048_576)) MB, made \(contextsMade)), time limit \(timeLimit ? "on" : "off") (checks \(checks), stops \(stops))"
    }

    // MARK: contexts

    private func gcOrNew() -> JSContext {
        lock.lock()
        let g = gcContext
        lock.unlock()
        return g ?? JSContext(virtualMachine: vm)
    }

    /// A context with `__tern` and the prelude evaluated (Ctx.exception set when the prelude failed).
    private func makeContext() -> Ctx {
        let context: JSContext = JSContext(virtualMachine: vm)
        let c = Ctx(context: context)
        context.exceptionHandler = { [weak c] _, exc in c?.exception = exc }
        let tern = JSValue(newObjectIn: context)
        let host: @convention(block) (String?, String?) -> String = { [weak c] op, arg in
            guard let run = c?.run, let op else { return "" }
            if let lane = JSCScriptEngine.nativeBlobs, let r = JSCScriptEngine.laneHost(run, lane, op, arg ?? "") { return r }
            if op == "text", let id = Int64(arg ?? "") { return JSCScriptEngine.goBlobText(run, id) }
            return run.host(op, arg: arg ?? "")
        }
        let put: @convention(block) (JSValue?, Double, Double) -> Double = { [weak c] buf, off, len in
            guard let run = c?.run, let buf else { return -1 }
            return Double(JSCScriptEngine.put(run, buf, off, len))
        }
        let take: @convention(block) (Double) -> JSValue? = { [weak c] id in
            // Int64(Double) traps on NaN / ±inf / out of range: a script calling __tern.take itself must not
            // bring the tunnel down
            guard let run = c?.run, let ctx = JSContext.current(), let i = JSCScriptEngine.exactInt(id) else { return nil }
            return JSCScriptEngine.take(run, i, ctx)
        }
        tern?.setObject(unsafeBitCast(host, to: AnyObject.self), forKeyedSubscript: "host" as NSString)
        tern?.setObject(unsafeBitCast(put, to: AnyObject.self), forKeyedSubscript: "put" as NSString)
        tern?.setObject(unsafeBitCast(take, to: AnyObject.self), forKeyedSubscript: "take" as NSString)
        if let global = context.globalObject, let tern {
            let desc: [String: Any] = [
                JSPropertyDescriptorValueKey: tern,
                JSPropertyDescriptorWritableKey: false,
                JSPropertyDescriptorEnumerableKey: false,
                JSPropertyDescriptorConfigurableKey: false,
            ]
            global.defineProperty("__tern", descriptor: desc)
        }
        lock.lock()
        let src = prelude
        contextsMade += 1
        lock.unlock()
        context.evaluateScript(src, withSourceURL: URL(string: "tern://prelude.js"))
        return c
    }

    /// Caller holds `lock`.
    private func forget(_ c: Ctx) {
        refLock.lock()
        byRef.removeValue(forKey: c.context.jsGlobalContextRef)
        refLock.unlock()
        if let m = c.main { trash.append(m) }
        c.main = nil
        c.poisoned = true
    }

    private func setRef(_ c: Ctx) {
        refLock.lock()
        byRef[c.context.jsGlobalContextRef] = c
        refLock.unlock()
    }

    /// Unlocks `lock`, then releases what went away under it (may wait for JavaScriptCore's API lock).
    private func unlockAndEmpty() {
        let t = trash
        trash = []
        lock.unlock()
        withExtendedLifetime(t) {}
    }

    private func invoke(_ c: Ctx, _ fn: String, _ arg: String, name: String) -> String? {
        c.exception = nil
        guard let f = c.context.objectForKeyedSubscript(fn), !f.isUndefined else {
            return Self.err("internal", "missing " + fn)
        }
        _ = f.call(withArguments: [arg])
        let r = outcome(c, name: name, lineOffset: 0)
        return r.isEmpty ? nil : r
    }

    /// "" or the error JSON for the last call on c.
    private func outcome(_ c: Ctx, name: String, lineOffset: Int) -> String {
        if c.terminated {
            c.poisoned = true
            return Self.err("terminated", "terminated")
        }
        guard let e = c.exception else { return "" }
        c.exception = nil
        return Self.err("exception", Self.describe(e, name: name, lineOffset: lineOffset))
    }

    // MARK: execution time limit

    private typealias ShouldTerminate = @convention(c) (JSContextRef?, UnsafeMutableRawPointer?) -> Bool
    private typealias SetLimit = @convention(c) (JSContextGroupRef?, Double, ShouldTerminate?, UnsafeMutableRawPointer?) -> Void

    /// The resolved JSContextGroupSetExecutionTimeLimit (nil until installTimeLimit found it).
    private static var limitSetter: SetLimit?
    private static let limitInterval = 0.1

    /// Called by JavaScriptCore on the thread running JavaScript once `limitInterval` of uninterrupted execution
    /// has passed. Returning false does NOT start a new period on current JavaScriptCore (CI 78f8814: one check,
    /// then the busy loop ran forever and the engine wedged), so the limit is set again before returning false
    /// — setting a time limit from inside the callback is the documented way to continue.
    private static let limitCallback: ShouldTerminate = { ref, _ in
        guard let ref else { return false }
        if JSCScriptEngine.shared.shouldTerminate(JSContextGetGlobalContext(ref)) { return true }
        JSCScriptEngine.rearm(JSContextGetGroup(ref))
        return false
    }

    private static func rearm(_ group: JSContextGroupRef?) {
        guard let group, let set = limitSetter else { return }
        set(group, limitInterval, limitCallback, nil)
    }

    private static func installTimeLimit(_ group: JSContextGroupRef) -> Bool {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "JSContextGroupSetExecutionTimeLimit") else { return false }
        let set = unsafeBitCast(sym, to: SetLimit.self)
        limitSetter = set
        set(group, limitInterval, limitCallback, nil)
        return true
    }

    private func shouldTerminate(_ global: JSGlobalContextRef?) -> Bool {
        guard let global else { return false }
        refLock.lock()
        let c = byRef[global]
        limitChecks += 1
        refLock.unlock()
        guard let c, let run = c.run else { return false }
        if run.shouldStop() {
            c.terminated = true
            refLock.lock()
            limitStops += 1
            refLock.unlock()
            return true
        }
        return false
    }

    // MARK: bytes

    private static func put(_ run: LibmihomoScriptRun, _ buf: JSValue, _ off: Double, _ len: Double) -> Int64 {
        guard let ctx = buf.context else { return -1 }
        let ref = ctx.jsGlobalContextRef
        guard JSValueGetTypedArrayType(ref, buf.jsValueRef, nil) == kJSTypedArrayTypeArrayBuffer,
              let obj = JSValueToObject(ref, buf.jsValueRef, nil) else { return -1 }
        let total = JSObjectGetArrayBufferByteLength(ref, obj, nil)
        guard let o64 = exactInt(off), let n64 = exactInt(len), o64 >= 0, n64 >= 0, o64 + n64 <= Int64(total) else { return -1 }
        let o = Int(o64), n = Int(n64)
        if n == 0 { return run.put(Data()) }
        guard let p = JSObjectGetArrayBufferBytesPtr(ref, obj, nil) else { return -1 }
        if let lane = nativeBlobs, n >= lane.putMin {
            // a large result stays native: stored in the lane, owned by the run on the Go side ("" = not taken)
            let h = lane.store(UnsafeRawBufferPointer(start: p.advanced(by: o), count: n))
            if h > 0 {
                if let id = Int64(run.host("nblob", arg: String(h))), id > 0 { return id }
                lane.free(h)
            }
        }
        return run.put(Data(bytes: p.advanced(by: o), count: n))
    }

    /// Host ops the engine answers itself for lane bodies: "text" of a native blob (Go's U+FFFD rules, goText) and "utf8" of a
    /// large string (stored in the lane). nil: ask the Go host.
    private static func laneHost(_ run: LibmihomoScriptRun, _ lane: JSCNativeBlobProvider, _ op: String, _ arg: String) -> String? {
        switch op {
        case "text":
            guard let id = Int64(arg), id >= nativeBase else { return nil }
            return laneText(lane, id - nativeBase)
        case "utf8":
            // UTF-8 is at least as long as UTF-16 and at most three times: decide from the O(1) UTF-16 length
            // when possible (counting the UTF-8 of a bridged NSString walks it)
            let units = (arg as NSString).length
            if units * 3 < lane.putMin { return nil }
            if units < lane.putMin && arg.utf8.count < lane.putMin { return nil }
            // one copy: the string's UTF-8 straight into a Data the store keeps (a bridged NSString would be
            // transcoded into a native String first by withUTF8, then copied again by store)
            guard let data = arg.data(using: .utf8) else { return nil }
            let h = lane.adopt(data)
            guard h > 0 else { return nil }
            if let id = Int64(run.host("nblob", arg: String(h))), id > 0 { return String(id) }
            lane.free(h) // "" = this run does not take lane results (request phase, task, debug run): Go blob
            return nil
        default:
            return nil
        }
    }

    /// "text" of a Go blob, built here from its bytes (run.take: the same blob lookup as the host op, temp blobs
    /// go away the same way). Through the host op the text reached Swift as a Go string converted by gomobile
    /// with NSString(bytesNoCopy:…encoding: .utf8), which drops a leading BOM (CI 40052493849 bom-text-go-path:
    /// goja 37 characters, JavaScriptCore 36). CFStringCreateWithBytes with isExternalRepresentation false keeps
    /// it; peak memory is the same as before (Go's copy, then the CFString, then JavaScriptCore's copy).
    private static func goBlobText(_ run: LibmihomoScriptRun, _ id: Int64) -> String {
        guard let data = run.take(id), !data.isEmpty else { return "" }
        return data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> String in
            guard isValidUTF8(buf), let base = buf.baseAddress else { return goText(buf) }
            let bom = buf.count >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF
            if let cf = CFStringCreateWithBytes(kCFAllocatorDefault, base.assumingMemoryBound(to: UInt8.self), buf.count,
                                                CFStringBuiltInEncodings.UTF8.rawValue, false),
               !bom || (CFStringGetLength(cf) > 0 && CFStringGetCharacterAtIndex(cf, 0) == 0xFEFF) {
                return cf as String
            }
            return String(decoding: buf, as: UTF8.self)
        }
    }

    /// The text of lane handle h exactly as Go's bodyString would build it (goText), without the bytes going
    /// through Go; nil for an unknown / failed handle (then the Go host answers).
    private static func laneText(_ lane: JSCNativeBlobProvider, _ h: Int64) -> String? {
        var text: String?
        _ = lane.withDecoded(h) { bytes in text = goText(bytes) }
        return text
    }

    /// Go's bodyString: valid UTF-8 as it is (String(decoding:) keeps a leading BOM and NUL bytes, as Go strings
    /// and goja do — Foundation's UTF-8 initializers drop a leading BOM), otherwise strings.ToValidUTF8(s,
    /// "\u{FFFD}"): one U+FFFD per run of bytes that do not start a valid sequence.
    static func goText(_ buf: UnsafeRawBufferPointer) -> String {
        if isValidUTF8(buf) { return String(decoding: buf, as: UTF8.self) }
        let n = buf.count
        guard let base = buf.baseAddress else { return "" }
        let p = base.assumingMemoryBound(to: UInt8.self)
        var out = [UInt8]()
        out.reserveCapacity(n + 16)
        var i = 0
        var invalid = false
        while i < n {
            let w = utf8SeqLen(p, i, n)
            if w == 0 {
                if !invalid { out.append(contentsOf: [0xEF, 0xBF, 0xBD]) }
                invalid = true
                i += 1
                continue
            }
            invalid = false
            out.append(contentsOf: UnsafeBufferPointer(start: p + i, count: w))
            i += w
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Length of the valid UTF-8 sequence starting at p[i] (1 for ASCII), 0 when none starts there (Go's
    /// utf8.DecodeRune width-1 RuneError): shortest forms only, no surrogates, nothing above U+10FFFF.
    @inline(__always)
    private static func utf8SeqLen(_ p: UnsafePointer<UInt8>, _ i: Int, _ n: Int) -> Int {
        let c = p[i]
        if c < 0x80 { return 1 }
        var need = 0
        var lo: UInt8 = 0x80, hi: UInt8 = 0xBF
        switch c {
        case 0xC2...0xDF: need = 1
        case 0xE0: need = 2; lo = 0xA0
        case 0xE1...0xEC, 0xEE, 0xEF: need = 2
        case 0xED: need = 2; hi = 0x9F
        case 0xF0: need = 3; lo = 0x90
        case 0xF1...0xF3: need = 3
        case 0xF4: need = 3; hi = 0x8F
        default: return 0
        }
        if i + need >= n { return 0 } // truncated sequence at the end
        let c1 = p[i + 1]
        if c1 < lo || c1 > hi { return 0 }
        if need >= 2 && (p[i + 2] & 0xC0) != 0x80 { return 0 }
        if need == 3 && (p[i + 3] & 0xC0) != 0x80 { return 0 }
        return need + 1
    }

    /// Go's utf8.Valid.
    static func isValidUTF8(_ buf: UnsafeRawBufferPointer) -> Bool {
        let n = buf.count
        guard n > 0, let base = buf.baseAddress else { return true }
        let p = base.assumingMemoryBound(to: UInt8.self)
        var i = 0
        while i < n {
            // ASCII fast path, 8 bytes at a time
            while i + 8 <= n && (UnsafeRawPointer(p + i).loadUnaligned(as: UInt64.self) & 0x8080_8080_8080_8080) == 0 { i += 8 }
            if i >= n { break }
            let w = utf8SeqLen(p, i, n)
            if w == 0 { return false }
            i += w
        }
        return true
    }

    /// An integral Double in ±2^53 as Int64 (nil for NaN, infinities, fractions, larger values).
    static func exactInt(_ d: Double) -> Int64? {
        guard d.isFinite, d == d.rounded(.towardZero), abs(d) <= 9_007_199_254_740_992 else { return nil }
        return Int64(d)
    }

    private static func take(_ run: LibmihomoScriptRun, _ id: Int64, _ ctx: JSContext) -> JSValue? {
        let ref = ctx.jsGlobalContextRef
        if id >= nativeBase, let lane = nativeBlobs {
            // a lane body: copied straight from native memory into a fresh Uint8Array (never through Go)
            var made: JSObjectRef?
            let ok = lane.withDecoded(id - nativeBase) { bytes in
                guard let obj = JSObjectMakeTypedArray(ref, kJSTypedArrayTypeUint8Array, bytes.count, nil) else { return }
                if bytes.count > 0, let base = bytes.baseAddress, let p = JSObjectGetTypedArrayBytesPtr(ref, obj, nil) {
                    p.copyMemory(from: base, byteCount: bytes.count)
                }
                made = obj
            }
            if ok, let made { return JSValue(jsValueRef: made, in: ctx) }
            // unknown handle: fall through to the Go host (it materialises or returns nothing)
        }
        let data = run.take(id) ?? Data()
        guard let obj = JSObjectMakeTypedArray(ref, kJSTypedArrayTypeUint8Array, data.count, nil) else { return nil }
        if data.count > 0, let p = JSObjectGetTypedArrayBytesPtr(ref, obj, nil) {
            data.withUnsafeBytes { raw in
                if let base = raw.baseAddress { p.copyMemory(from: base, byteCount: data.count) }
            }
        }
        return JSValue(jsValueRef: obj, in: ctx)
    }

    // MARK: helpers

    private static func syntaxError(_ src: String, context: JSContext) -> String? {
        let ref = context.jsGlobalContextRef
        let s = JSStringCreateWithCFString(src as CFString)
        defer { JSStringRelease(s) }
        var exc: JSValueRef?
        if JSCheckScriptSyntax(ref, s, nil, 1, &exc) { return nil }
        if let exc, let v = JSValue(jsValueRef: exc, in: context) { return describe(v) }
        return "SyntaxError"
    }

    private static func describe(_ e: JSValue, name: String = "", lineOffset: Int = 0) -> String {
        var s = e.toString() ?? "Error"
        if let line = e.objectForKeyedSubscript("line"), line.isNumber {
            let l = Int(line.toInt32()) - lineOffset
            let col = e.objectForKeyedSubscript("column").map { $0.isNumber ? Int($0.toInt32()) : 0 } ?? 0
            s += " at \(name.isEmpty ? "script" : name).js:\(max(l, 1)):\(col)"
        }
        return s
    }

    private static func err(_ kind: String, _ message: String) -> String {
        let obj: [String: String] = ["kind": kind, "message": message]
        guard let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) else {
            return "{\"kind\":\"internal\",\"message\":\"encode\"}"
        }
        return s
    }

    private static func urlName(_ n: String) -> String {
        n.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "script"
    }
}
