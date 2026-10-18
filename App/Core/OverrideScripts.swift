import Foundation
import JavaScriptCore
import CryptoKit
import Darwin

// v0.19 覆写脚本 (override scripts), the Clash Verge / FlClash / Bettbox convention:
// `function main(config, profileName) { …; return config }` runs in JavaScriptCore in the app whenever the
// runtime config is generated (connect / reload / a script or toggle change), before our own overrides
// (group edits, node subscriptions, chains, DNS …, which the core applies afterwards). Several scripts per
// profile run in order, each one getting the previous one's result. The output is validated by the core
// exactly as a connect would parse it and only then stored (<home>/scripted/<id>.yaml); see
// bridge/overridescript.go for how the core picks it up and ignores it once the profile changed.
//
// Bettbox UI declaration: a script with `const Compatible_With_Bettbox = { ruleOptionsEnable: true,
// policyGroupOptions: [...] }` and a `ruleOptionsEnable` object gets one switch per key. The user's values are
// passed in the way Bettbox does it: after the script's top level ran, Object.assign(ruleOptionsEnable,
// custom), then main(config). Keys named in policyGroupOptions are one section, the rest are 「其他设置」.

struct OverrideScript: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String
    /// Remote source (http/https); nil = local script.
    var url: String?
    var enabled: Bool = true
    /// Remote scripts: hours between automatic updates, 0 = manual only.
    var updateIntervalHours: Int = 24
    var lastUpdated: Date?
    /// The user's switch values (Bettbox ruleOptionsEnable); only keys the script declares are passed in.
    var options: [String: Bool]?
    var lastRun: Date?
    var lastError: String?
    var lastErrorLine: Int?
    var lastMillis: Int?
    var logs: [String]?

    var isRemote: Bool { !(url ?? "").isEmpty }

    init(name: String, url: String? = nil) {
        self.name = name
        self.url = url
    }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? "script"
        url = try c.decodeIfPresent(String.self, forKey: .url)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        updateIntervalHours = try c.decodeIfPresent(Int.self, forKey: .updateIntervalHours) ?? 24
        lastUpdated = try c.decodeIfPresent(Date.self, forKey: .lastUpdated)
        options = try c.decodeIfPresent([String: Bool].self, forKey: .options)
        lastRun = try c.decodeIfPresent(Date.self, forKey: .lastRun)
        lastError = try c.decodeIfPresent(String.self, forKey: .lastError)
        lastErrorLine = try c.decodeIfPresent(Int.self, forKey: .lastErrorLine)
        lastMillis = try c.decodeIfPresent(Int.self, forKey: .lastMillis)
        logs = try c.decodeIfPresent([String].self, forKey: .logs)
    }
}

// MARK: - JavaScriptCore engine

enum JSOverrideEngine {
    static let runTimeout: TimeInterval = 10
    static let extractTimeout: TimeInterval = 3
    static let maxLogs = 200

    struct ScriptError: Error, Equatable {
        enum Kind: String { case syntax, runtime, timeout, noMain, notObject, promise, input }
        var kind: Kind
        var message: String
        var line: Int?

        var text: String {
            switch kind {
            case .timeout: return String(localized: "运行超时（超过 \(Int(JSOverrideEngine.runTimeout)) 秒），已停止")
            case .noMain: return String(localized: "没有找到 main 函数（需要 function main(config) { … return config }）")
            case .notObject: return String(localized: "main() 没有返回配置对象（需要 return config）")
            case .promise: return String(localized: "main() 返回的 Promise 没有完成")
            case .syntax:
                if let line { return String(localized: "语法错误（第 \(line) 行）：\(message)") }
                return String(localized: "语法错误：\(message)")
            case .runtime, .input:
                if let line { return String(localized: "第 \(line) 行：\(message)") }
                return message
            }
        }
    }

    /// What the script declares for the switch UI.
    struct Declared: Decodable, Equatable {
        var compatible: Bool
        var hasMain: Bool
        var keys: [String]
        var values: [String: Bool]
        var icons: [String: String]
        var policyGroupOptions: [String]

        static let empty = Declared(compatible: false, hasMain: false, keys: [], values: [:], icons: [:], policyGroupOptions: [])
        /// Switches are shown for Bettbox-compatible scripts that have a ruleOptionsEnable object.
        var hasSwitches: Bool { compatible && !keys.isEmpty }
        /// Bettbox: split into 策略组 + 其他设置 only when both sides have keys; otherwise one flat list.
        var split: (groups: [String], others: [String])? {
            let g = keys.filter { policyGroupOptions.contains($0) }
            let o = keys.filter { !policyGroupOptions.contains($0) }
            return g.isEmpty || o.isEmpty ? nil : (g, o)
        }
    }

    struct RunOutput {
        var json: String
        var logs: [String]
        var millis: Int
    }

    // Private JavaScriptCore API (JSContextRefPrivate.h), looked up at runtime: a hard execution time limit
    // for runaway scripts. When it is unavailable the thread watchdog below still returns on time.
    private typealias SetLimitFn = @convention(c) (JSContextGroupRef?, Double, UnsafeRawPointer?, UnsafeMutableRawPointer?) -> Void
    private static let setLimit: SetLimitFn? = {
        guard let h = dlopen(nil, RTLD_NOW), let sym = dlsym(h, "JSContextGroupSetExecutionTimeLimit") else { return nil }
        return unsafeBitCast(sym, to: SetLimitFn.self)
    }()

    private final class Box: @unchecked Sendable {
        var logs: [String] = []
        var exception: (String, Int?)?
        var result: Result<String, ScriptError>?
        let lock = NSLock()
        func log(_ s: String) {
            lock.lock(); defer { lock.unlock() }
            if logs.count < JSOverrideEngine.maxLogs { logs.append(s) }
        }
    }

    private static let consolePrelude = """
    var console = (function () {
      function fmt(x) { if (typeof x === 'string') return x; try { var s = JSON.stringify(x); return s === undefined ? String(x) : s; } catch (e) { return String(x); } }
      function f(l) { return function () { var a = []; for (var i = 0; i < arguments.length; i++) a.push(fmt(arguments[i])); __mihomoLog(l, a.join(' ')); }; }
      return { log: f('log'), info: f('info'), warn: f('warn'), error: f('error'), debug: f('debug') };
    })();
    """

    private static let extractTail = """

    ;var __o = (typeof ruleOptionsEnable !== 'undefined' && ruleOptionsEnable && typeof ruleOptionsEnable === 'object' && !Array.isArray(ruleOptionsEnable)) ? ruleOptionsEnable : null;
    var __keys = [], __vals = {};
    if (__o) { var __k = Object.keys(__o); for (var __i = 0; __i < __k.length; __i++) { __keys.push(__k[__i]); __vals[__k[__i]] = (typeof __o[__k[__i]] === 'boolean') ? __o[__k[__i]] : true; } }
    var __icons = {};
    if (typeof serviceConfigs !== 'undefined' && Array.isArray(serviceConfigs)) { for (var __j = 0; __j < serviceConfigs.length; __j++) { var __s = serviceConfigs[__j]; if (__s && __s.name && typeof __s.icon === 'string') __icons[String(__s.name)] = __s.icon; } }
    var __groups = [], __compat = false;
    if (typeof Compatible_With_Bettbox !== 'undefined' && Compatible_With_Bettbox) { __compat = true; if (Array.isArray(Compatible_With_Bettbox.policyGroupOptions)) { for (var __g = 0; __g < Compatible_With_Bettbox.policyGroupOptions.length; __g++) { if (typeof Compatible_With_Bettbox.policyGroupOptions[__g] === 'string') __groups.push(Compatible_With_Bettbox.policyGroupOptions[__g]); } } }
    return JSON.stringify({ compatible: __compat, hasMain: typeof main === 'function', keys: __keys, values: __vals, icons: __icons, policyGroupOptions: __groups });
    """

    private static let runTail = """

    ;if (__custom && typeof ruleOptionsEnable !== 'undefined' && ruleOptionsEnable && typeof ruleOptionsEnable === 'object') { Object.assign(ruleOptionsEnable, __custom); }
    if (typeof main !== 'function') { throw new Error('__MIHOMO_NO_MAIN__'); }
    return main(__config, __profileName);
    """

    /// Runs `body` on its own thread (big stack, recursion-heavy scripts) and waits at most `timeout` + 2 s.
    private static func onThread(timeout: TimeInterval, _ body: @escaping (Box) -> Void) -> Box {
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            body(box)
            sem.signal()
        }
        t.stackSize = 8 << 20
        t.qualityOfService = .userInitiated
        t.start()
        if sem.wait(timeout: .now() + timeout + 2) == .timedOut {
            box.lock.lock()
            if box.result == nil { box.result = .failure(ScriptError(kind: .timeout, message: "")) }
            box.lock.unlock()
        }
        return box
    }

    private static func makeContext(_ box: Box, timeout: TimeInterval) -> JSContext {
        let ctx = JSContext(virtualMachine: JSVirtualMachine())!
        if let setLimit, let ref = ctx.jsGlobalContextRef {
            setLimit(JSContextGetGroup(ref), timeout, nil, nil)
        }
        ctx.exceptionHandler = { _, exc in
            let msg = exc?.toString() ?? "error"
            let line = exc?.objectForKeyedSubscript("line").flatMap { $0.isUndefined ? nil : Int($0.toInt32()) }
            box.exception = (msg, line)
        }
        let log: @convention(block) (String, String) -> Void = { level, text in
            box.log(level == "log" ? text : "[\(level)] \(text)")
        }
        ctx.setObject(log, forKeyedSubscript: "__mihomoLog" as NSString)
        ctx.evaluateScript(consolePrelude)
        return ctx
    }

    private static func takeError(_ box: Box, _ started: Date, timeout: TimeInterval, kind: ScriptError.Kind) -> ScriptError {
        if Date().timeIntervalSince(started) >= timeout - 0.05 { return ScriptError(kind: .timeout, message: "") }
        let (msg, line) = box.exception ?? ("error", nil)
        box.exception = nil
        if msg.contains("__MIHOMO_NO_MAIN__") { return ScriptError(kind: .noMain, message: msg) }
        if msg.hasPrefix("SyntaxError") { return ScriptError(kind: .syntax, message: msg, line: line) }
        return ScriptError(kind: kind, message: msg, line: line)
    }

    /// Runs the script's top level and reads what it declares for the switch UI.
    static func declared(_ source: String) -> Result<Declared, ScriptError> {
        let res = onThread(timeout: extractTimeout) { box in
            let started = Date()
            let ctx = makeContext(box, timeout: extractTimeout)
            let v = ctx.evaluateScript("(function() { " + source + extractTail + " })()")
            box.lock.lock(); defer { box.lock.unlock() }
            if box.result != nil { return }
            if box.exception != nil || v == nil || !(v!.isString) {
                box.result = .failure(takeError(box, started, timeout: extractTimeout, kind: .runtime))
            } else {
                box.result = .success(v!.toString())
            }
        }
        res.lock.lock(); let rr = res.result; res.lock.unlock()
        switch rr {
        case .success(let json):
            guard let d = try? JSONDecoder().decode(Declared.self, from: Data(json.utf8)) else { return .success(.empty) }
            return .success(d)
        case .failure(let e): return .failure(e)
        case nil: return .failure(ScriptError(kind: .timeout, message: ""))
        }
    }

    /// main(config, profileName) with the user's switch values. Returns the new config as JSON text.
    static func run(_ source: String, configJSON: String, custom: [String: Bool]?, profileName: String) -> (Result<RunOutput, ScriptError>, [String]) {
        let started = Date()
        let customJSON: String = {
            guard let custom, !custom.isEmpty, let d = try? JSONSerialization.data(withJSONObject: custom) else { return "null" }
            return String(decoding: d, as: UTF8.self)
        }()
        let res = onThread(timeout: runTimeout) { box in
            let ctx = makeContext(box, timeout: runTimeout)
            // The script starts on line 1 of the wrapper, so error lines match the editor.
            let fnSource = "(function(__configText, __customText, __profileName) { var __config = JSON.parse(__configText); var __custom = JSON.parse(__customText); " + source + runTail + " })"
            func fail(_ k: ScriptError.Kind) {
                box.lock.lock(); defer { box.lock.unlock() }
                if box.result == nil { box.result = .failure(takeError(box, started, timeout: runTimeout, kind: k)) }
            }
            guard let fn = ctx.evaluateScript(fnSource), box.exception == nil, !fn.isUndefined else { return fail(.syntax) }
            guard var result = fn.call(withArguments: [configJSON, customJSON, profileName]), box.exception == nil else { return fail(.runtime) }
            // async main(): JavaScriptCore drains microtasks when the outermost call returns.
            if result.isObject, let then = result.objectForKeyedSubscript("then"), !then.isUndefined,
               let helper = ctx.evaluateScript("(function(p){ var b = {done:false}; p.then(function(v){ b.done = true; b.value = v; }, function(e){ b.done = true; b.error = e; }); return b; })"),
               let b = helper.call(withArguments: [result]) {
                if !(b.objectForKeyedSubscript("done")?.toBool() ?? false) {
                    box.lock.lock(); box.result = .failure(ScriptError(kind: .promise, message: "")); box.lock.unlock()
                    return
                }
                if let e = b.objectForKeyedSubscript("error"), !e.isUndefined {
                    box.lock.lock()
                    box.result = .failure(ScriptError(kind: .runtime, message: e.toString() ?? "error",
                                                      line: e.objectForKeyedSubscript("line").flatMap { $0.isUndefined ? nil : Int($0.toInt32()) }))
                    box.lock.unlock()
                    return
                }
                result = b.objectForKeyedSubscript("value") ?? result
            }
            guard let ser = ctx.evaluateScript("(function(v){ if (v === undefined || v === null || typeof v !== 'object' || Array.isArray(v)) return '__MIHOMO_NOT_OBJECT__'; return JSON.stringify(v); })"),
                  let text = ser.call(withArguments: [result]), box.exception == nil, text.isString else { return fail(.runtime) }
            let s = text.toString() ?? ""
            box.lock.lock(); defer { box.lock.unlock() }
            if box.result != nil { return }
            box.result = s == "__MIHOMO_NOT_OBJECT__" ? .failure(ScriptError(kind: .notObject, message: "")) : .success(s)
        }
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        res.lock.lock(); let logs = res.logs; let r = res.result; res.lock.unlock()
        switch r {
        case .success(let json): return (.success(RunOutput(json: json, logs: logs, millis: ms)), logs)
        case .failure(let e): return (.failure(e), logs)
        case nil: return (.failure(ScriptError(kind: .timeout, message: "")), logs)
        }
    }
}

// MARK: - Store

/// Result of running a profile's script chain.
struct OverrideChainResult: Equatable {
    var ok: Bool
    var message: String
    var failedScriptID: String?
    var proxies = 0, groups = 0, rules = 0
    var millis = 0
    var at = Date()
}

@MainActor
final class OverrideScriptStore: ObservableObject {
    static let shared = OverrideScriptStore()

    /// profile id → scripts in run order.
    @Published private(set) var byProfile: [String: [OverrideScript]] = [:]
    /// Last chain result per profile (this session).
    @Published private(set) var lastResult: [String: OverrideChainResult] = [:]
    @Published private(set) var running: Set<String> = []
    @Published var updating: Set<String> = []

    /// Fingerprint of the last successful run per profile: source + scripts + switch values.
    private var fingerprints: [String: String] = [:]

    static var dir: URL { AppShared.ensureDir(AppShared.homeURL.appendingPathComponent("override-scripts", isDirectory: true)) }
    static var indexURL: URL { dir.appendingPathComponent("index.json") }
    static func contentURL(_ id: String) -> URL { dir.appendingPathComponent("\(id).js") }

    static let template = """
    // 覆写脚本：生成运行配置时调用 main(config, profileName)，返回修改后的配置。
    // Override script: main(config, profileName) receives the profile as an object and returns it.
    // config 与配置文件结构相同（proxies、proxy-groups、rules、dns …）。
    function main(config, profileName) {
      // 例 / Example: a rule at the top
      // config.rules = ["DOMAIN-SUFFIX,example.com,DIRECT", ...(config.rules || [])];
      return config;
    }
    """

    private init() { load() }

    func load() {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        if let d = try? Data(contentsOf: Self.indexURL), let m = try? dec.decode([String: [OverrideScript]].self, from: d) {
            byProfile = m
        } else {
            byProfile = [:]
        }
    }

    private func persist() {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(byProfile.filter { !$0.value.isEmpty }) { try? d.write(to: Self.indexURL, options: .atomic) }
    }

    func scripts(_ profileID: String) -> [OverrideScript] { byProfile[profileID] ?? [] }
    func enabledCount(_ profileID: String) -> Int { scripts(profileID).filter(\.enabled).count }
    func script(_ profileID: String, _ id: String) -> OverrideScript? { scripts(profileID).first { $0.id == id } }

    nonisolated static func content(_ id: String) -> String { (try? String(contentsOf: contentURL(id), encoding: .utf8)) ?? "" }

    // MARK: editing

    @discardableResult
    func add(_ profileID: String, name: String, source: String, url: String? = nil) -> OverrideScript {
        var s = OverrideScript(name: name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "script.js" : name, url: url)
        if url != nil { s.lastUpdated = Date() }
        try? source.write(to: Self.contentURL(s.id), atomically: true, encoding: .utf8)
        byProfile[profileID, default: []].append(s)
        persist()
        return s
    }

    func update(_ profileID: String, _ s: OverrideScript) {
        guard var l = byProfile[profileID], let i = l.firstIndex(where: { $0.id == s.id }) else { return }
        l[i] = s
        byProfile[profileID] = l
        persist()
    }

    func setContent(_ profileID: String, _ id: String, _ text: String) {
        try? text.write(to: Self.contentURL(id), atomically: true, encoding: .utf8)
        objectWillChange.send()
    }

    func move(_ profileID: String, from: IndexSet, to: Int) {
        guard var l = byProfile[profileID] else { return }
        l.move(fromOffsets: from, toOffset: to)
        byProfile[profileID] = l
        persist()
    }

    func delete(_ profileID: String, _ id: String) {
        byProfile[profileID]?.removeAll { $0.id == id }
        try? FileManager.default.removeItem(at: Self.contentURL(id))
        persist()
    }

    /// Removes a deleted profile's scripts and output.
    func forget(profile p: Profile) {
        for s in scripts(p.id) { try? FileManager.default.removeItem(at: Self.contentURL(s.id)) }
        byProfile[p.id] = nil
        persist()
        LibmihomoScriptOutputClear(AppShared.homeURL.path, p.fileURL.path)
    }

    // MARK: remote

    enum DownloadError: LocalizedError {
        case badURL, http(Int), empty
        var errorDescription: String? {
            switch self {
            case .badURL: return String(localized: "脚本链接无效")
            case .http(let c): return String(localized: "下载失败：HTTP \(c)")
            case .empty: return String(localized: "脚本内容为空")
            }
        }
    }

    nonisolated static func download(_ urlString: String) async throws -> String {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)), url.scheme?.hasPrefix("http") == true else { throw DownloadError.badURL }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue("mihomo-ios", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let code = (resp as? HTTPURLResponse)?.statusCode, !(200..<300).contains(code) { throw DownloadError.http(code) }
        guard let text = String(data: data, encoding: .utf8), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw DownloadError.empty }
        return text
    }

    /// Downloads a remote script again. Returns an error message or nil.
    func refresh(_ profileID: String, _ id: String) async -> String? {
        guard var s = script(profileID, id), let u = s.url else { return nil }
        updating.insert(id)
        defer { updating.remove(id) }
        do {
            let text = try await Self.download(u)
            try? text.write(to: Self.contentURL(id), atomically: true, encoding: .utf8)
            s.lastUpdated = Date()
            update(profileID, s)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// Remote scripts whose interval elapsed (foreground / background refresh, next to subscription updates).
    func autoUpdateIfNeeded() async {
        var changed: Set<String> = []
        for (pid, list) in byProfile {
            for s in list where s.isRemote && s.updateIntervalHours > 0 {
                let due = (s.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(s.updateIntervalHours * 3600))
                if due < Date(), await refresh(pid, s.id) == nil { changed.insert(pid) }
            }
        }
        if let active = AppShared.activeProfileID, changed.contains(active), VPNManager.shared.isConnected {
            _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0)
        }
    }

    // MARK: running

    nonisolated static func fileSHA(_ url: URL) -> String {
        guard let d = try? Data(contentsOf: url) else { return "" }
        return SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
    }

    private func fingerprint(_ p: Profile, _ list: [OverrideScript]) -> String {
        var parts = [Self.fileSHA(p.fileURL), p.displayName]
        for s in list {
            let opts = (s.options ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
            parts.append(s.id + ":" + Self.fileSHA(Self.contentURL(s.id)) + ":" + opts)
        }
        return parts.joined(separator: "|")
    }

    /// Before connect / reload: runs the active profile's scripts when anything changed. Returns an error
    /// message (the connect / reload is not done then) or nil.
    func prepareActive() async -> String? {
        guard let id = AppShared.activeProfileID, let p = ProfileStore.shared.profiles.first(where: { $0.id == id }) else { return nil }
        let r = await apply(p, force: false)
        return r.ok ? nil : r.message
    }

    /// Runs the profile's enabled scripts in order, validates and stores the output (or clears it when no
    /// script is enabled). force: run even when nothing changed since the last successful run.
    @discardableResult
    func apply(_ p: Profile, force: Bool) async -> OverrideChainResult {
        let list = scripts(p.id).filter(\.enabled)
        let home = AppShared.homeURL.path, path = p.fileURL.path
        if list.isEmpty {
            LibmihomoScriptOutputClear(home, path)
            fingerprints[p.id] = nil
            let r = OverrideChainResult(ok: true, message: "")
            lastResult[p.id] = nil
            return r
        }
        let fp = fingerprint(p, list)
        if !force, fingerprints[p.id] == fp, Self.outputFresh(p), let last = lastResult[p.id], last.ok { return last }
        running.insert(p.id)
        defer { running.remove(p.id) }
        let name = p.displayName
        let inputs = list.map { ($0, Self.content($0.id)) }
        let outcome = await Task.detached(priority: .userInitiated) { () -> (OverrideChainResult, [String: (Int?, String?, Int?, [String])]) in
            Self.runChain(home: home, path: path, profileName: name, scripts: inputs)
        }.value
        // Per-script status (time, error, console output).
        var l = scripts(p.id)
        for (sid, st) in outcome.1 {
            guard let i = l.firstIndex(where: { $0.id == sid }) else { continue }
            l[i].lastRun = Date()
            l[i].lastMillis = st.0
            l[i].lastError = st.1
            l[i].lastErrorLine = st.2
            l[i].logs = st.3.isEmpty ? nil : st.3
        }
        byProfile[p.id] = l
        persist()
        lastResult[p.id] = outcome.0
        fingerprints[p.id] = outcome.0.ok ? fp : nil
        return outcome.0
    }

    nonisolated static func outputFresh(_ p: Profile) -> Bool {
        let st = LibmihomoScriptOutputStatus(AppShared.homeURL.path, p.fileURL.path)
        guard let o = try? JSONSerialization.jsonObject(with: Data(st.utf8)) as? [String: Any] else { return false }
        return (o["exists"] as? Bool ?? false) && (o["fresh"] as? Bool ?? false)
    }

    nonisolated static func status(_ p: Profile) -> (exists: Bool, fresh: Bool, at: Date?) {
        let st = LibmihomoScriptOutputStatus(AppShared.homeURL.path, p.fileURL.path)
        guard let o = try? JSONSerialization.jsonObject(with: Data(st.utf8)) as? [String: Any] else { return (false, false, nil) }
        let at = (o["at"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue) }
        return (o["exists"] as? Bool ?? false, o["fresh"] as? Bool ?? false, at)
    }

    /// The chain itself (off the main actor). Per script: millis, error, error line, console output.
    nonisolated static func runChain(home: String, path: String, profileName: String, scripts: [(OverrideScript, String)])
        -> (OverrideChainResult, [String: (Int?, String?, Int?, [String])]) {
        var stats: [String: (Int?, String?, Int?, [String])] = [:]
        let started = Date()
        var err: NSError?
        var config = LibmihomoScriptInput(path, &err)
        if let err {
            LibmihomoScriptOutputClear(home, path)
            return (OverrideChainResult(ok: false, message: String(localized: "读取配置失败：\(GoText.localize(err.localizedDescription))")), stats)
        }
        for (s, source) in scripts {
            if source.isEmpty {
                stats[s.id] = (nil, String(localized: "脚本内容为空"), nil, [])
                LibmihomoScriptOutputClear(home, path)
                return (OverrideChainResult(ok: false, message: String(localized: "覆写脚本「\(s.name)」：脚本内容为空"), failedScriptID: s.id), stats)
            }
            // Only the switch values the script declares now (a renamed key is not passed on).
            var custom: [String: Bool]? = nil
            if let o = s.options, !o.isEmpty, case .success(let d) = JSOverrideEngine.declared(source), d.hasSwitches {
                custom = o.filter { d.keys.contains($0.key) }
            }
            let (r, logs) = JSOverrideEngine.run(source, configJSON: config, custom: custom, profileName: profileName)
            switch r {
            case .success(let out):
                stats[s.id] = (out.millis, nil, nil, logs)
                config = out.json
            case .failure(let e):
                stats[s.id] = (nil, e.text, e.line, logs)
                LibmihomoScriptOutputClear(home, path)
                return (OverrideChainResult(ok: false, message: String(localized: "覆写脚本「\(s.name)」：\(e.text)"), failedScriptID: s.id), stats)
            }
        }
        let names = (try? JSONSerialization.data(withJSONObject: scripts.map { $0.0.name })).map { String(decoding: $0, as: UTF8.self) } ?? "[]"
        let msg = LibmihomoScriptOutputApply(home, path, config, names)
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        if !msg.isEmpty {
            return (OverrideChainResult(ok: false, message: String(localized: "覆写脚本的结果无法使用：\(GoText.localize(msg))"), millis: ms), stats)
        }
        var res = OverrideChainResult(ok: true, message: "", millis: ms)
        if let o = try? JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any] {
            res.proxies = (o["proxies"] as? [Any])?.count ?? 0
            res.groups = (o["proxy-groups"] as? [Any])?.count ?? 0
            res.rules = (o["rules"] as? [Any])?.count ?? 0
        }
        return (res, stats)
    }

    /// After a change to a profile's scripts: run them now (errors show at once) and reload when the profile
    /// is the one running.
    func changed(_ p: Profile) async {
        let r = await apply(p, force: true)
        if r.ok, p.id == AppShared.activeProfileID, VPNManager.shared.isConnected {
            _ = await ReloadCoalescer.shared.reload(VPNManager.shared, after: 0)
        }
    }
}
