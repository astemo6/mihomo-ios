// NativeCore (feat/native-core-eval, gap C3) — $httpAPI, cron / event / generic task scripts and panels in the native-only
// tunnel (astemo6/Muse NativeCore, 2026-10-25).
//
// - NativeHTTPAPI: the Surge $httpAPI subset the retired bridge (policies, policy groups, select get/set,
//   outbound mode get/set, current profile, reload) plus GET /v1/rules, POST /v1/dns/flush, and the two Loon
//   $config helpers (/loon/config, /loon/sub_policies) the prelude's synchronous "apisync" op uses.
// - NCCron: the retired bridge (5 or 6 fields, names, steps, Vixie dom/dow OR), local time.
// - NativeTaskRunner: the retired bridge's tasker for the tasks / panels the app exports into
//   nativecore-scripts.json ("tasks" at manifest index -1 - k, "panels"): cron schedule, network-changed event runs
//   (debounced), manual runs, panel refresh ($input / $panel, normalizePanelResult), task-prefs.json (paused /
//   enabled / deleted), task-history.json (20 runs per task), panel-cache.json, home-panels.json (visible panels
//   refresh while connected, ≥ 5 min apart when the app is not showing them; pinned generic scripts as panels).
//   One task script runs at a time (memory first); a run is the native script host's NativeScriptRun with phase
//   "task" and export on, so the script sees the same prelude, $persistentStore, $httpClient and $notification.
import Foundation

// MARK: - $httpAPI

enum NativeHTTPAPI {
    static let supported = [
        "GET /v1/policies", "GET /v1/policy_groups", "GET /v1/policy_groups/select?group_name=…",
        "POST /v1/policy_groups/select {group_name, policy}", "GET /v1/outbound", "POST /v1/outbound {mode: direct|proxy|rule}",
        "GET /v1/rules", "GET /v1/profiles/current", "POST /v1/profiles/reload", "POST /v1/dns/flush",
    ]

    private struct Arg: Decodable {
        var m: String?
        var p: String?
        var hasB: Bool?
        var bs: Bool?
        var cb: Int64?
    }

    /// The prelude's async $httpAPI: returns the __tern_deliver JSON {"id","v"} ("" when there is no callback).
    static func async(_ arg: String, script: String) -> String {
        guard let d = Data(arg.utf8) as Data?, let a = try? JSONDecoder().decode(Arg.self, from: d) else { return "" }
        let body = Self.body(d, a)
        var res: Any
        switch call(method: (a.m ?? "GET").uppercased(), path: a.p ?? "", body: body) {
        case .success(let v): res = v
        case .failure(let e):
            NativeLogRing.shared.addScript(script: script, level: "warning", msg: "$httpAPI \(a.m ?? "") \(a.p ?? "")：\(e.message)")
            res = ["error": e.message]
        }
        guard let cb = a.cb, cb >= 0 else { return "" }
        return json(["id": cb, "v": res] as [String: Any]) ?? ""
    }

    /// The prelude's synchronous "apisync" (Loon $config): the answer object as JSON.
    static func sync(_ arg: String) -> String {
        guard let d = Data(arg.utf8) as Data?, let a = try? JSONDecoder().decode(Arg.self, from: d) else { return "" }
        switch call(method: (a.m ?? "GET").uppercased(), path: a.p ?? "", body: Self.body(d, a)) {
        case .success(let v): return json(v) ?? ""
        case .failure(let e): return json(["error": e.message]) ?? ""
        }
    }

    private static func body(_ raw: Data, _ a: Arg) -> [String: Any] {
        guard a.hasB == true, let obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] else { return [:] }
        if a.bs == true, let s = obj["b"] as? String {
            return ((try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any]) ?? [:]
        }
        return obj["b"] as? [String: Any] ?? [:]
    }

    struct APIError: Error { let message: String }

    static func json(_ v: Any) -> String? {
        // never hand JSONSerialization something it would raise on (an NSException is a crash here)
        guard JSONSerialization.isValidJSONObject(v) || v is String || v is NSNumber || v is NSNull,
              let d = try? JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed]) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    private static func field(_ b: [String: Any], _ k: String) -> String {
        guard let v = b[k], !(v is NSNull) else { return "" }
        return "\(v)"
    }

    private static func surgeMode(_ m: String) -> String {
        switch m { case "global": return "proxy"; case "direct": return "direct"; default: return "rule" }
    }

    private static func typeDescription(_ t: String) -> String {
        switch t.lowercased() {
        case "ss": return "Shadowsocks"
        case "ssr": return "ShadowsocksR"
        case "vmess": return "VMess"
        case "vless": return "VLESS"
        case "trojan": return "Trojan"
        case "socks5": return "Socks5"
        case "http": return "Http"
        case "hysteria2": return "Hysteria2"
        case "anytls": return "AnyTLS"
        case "snell": return "Snell"
        case "direct": return "Direct"
        case "reject": return "Reject"
        case "select": return "Selector"
        case "url-test": return "URLTest"
        case "fallback": return "Fallback"
        case "load-balance": return "LoadBalance"
        case "relay": return "Relay"
        default: return t
        }
    }

    static func call(method: String, path rawPath: String, body: [String: Any]) -> Result<Any, APIError> {
        guard let engine = NativeCoreEngine.active else { return .failure(APIError(message: "内核未运行")) }
        let comps = URLComponents(string: rawPath)
        var path = comps?.path ?? rawPath
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        let query = comps?.queryItems ?? []
        func q(_ k: String) -> String { query.first { $0.name == k }?.value ?? "" }

        switch (method, path) {
        case ("GET", "/v1/policies"):
            let r: [String: Any]? = engine.withGroups { cfg, _ in
                ["proxies": cfg.proxies.map { $0.name }.filter { !$0.hasPrefix("__") },
                 "policy-groups": cfg.groups.map { $0.name }.filter { !$0.hasPrefix("__") }]
            }
            return .success(r ?? ["proxies": [String](), "policy-groups": [String]()])

        case ("GET", "/v1/policy_groups"):
            let r: [String: Any]? = engine.withGroups { cfg, _ in
                var out: [String: Any] = [:]
                let gm = cfg.groupMap
                let types = Dictionary(cfg.proxies.map { ($0.name, $0.type) }, uniquingKeysWith: { a, _ in a })
                for g in cfg.groups where !g.name.hasPrefix("__") {
                    out[g.name] = g.proxies.map { m -> [String: Any] in
                        let isGroup = gm[m] != nil
                        let t = isGroup ? (gm[m]?.type ?? "select") : (types[m] ?? (m.uppercased() == "DIRECT" ? "direct" : (m.uppercased() == "REJECT" ? "reject" : m)))
                        return ["name": m, "typeDescription": typeDescription(t), "isGroup": isGroup, "enabled": true]
                    }
                }
                return out
            }
            return .success(r ?? [:])

        case ("GET", "/v1/policy_groups/select"), ("GET", "/loon/sub_policies"):
            let name = q("group_name")
            let r: Result<Any, APIError>? = engine.withGroups { cfg, g in
                let gm = cfg.groupMap
                guard let grp = gm[name] else { return .failure(APIError(message: "策略组 \(name) 不存在")) }
                if path == "/loon/sub_policies" {
                    let types = Dictionary(cfg.proxies.map { ($0.name, $0.type) }, uniquingKeysWith: { a, _ in a })
                    return .success(grp.proxies.map { m -> [String: Any] in
                        ["name": m, "type": typeDescription(gm[m]?.type ?? types[m] ?? m), "isGroup": gm[m] != nil]
                    })
                }
                return .success(["policy": g.currentMember(of: grp) ?? ""])
            }
            return r ?? .failure(APIError(message: "内核未运行"))

        case ("POST", "/v1/policy_groups/select"):
            let name = field(body, "group_name"), pol = field(body, "policy")
            let check: String = engine.withGroups { (cfg: NCConfig, _: NCGroupEngine) -> String in
                guard let grp = cfg.groupMap[name] else { return "策略组 \(name) 不存在" }
                guard grp.type == "select" else { return "策略组 \(name) 不能手动选择" }
                guard grp.proxies.contains(pol) else { return "策略组 \(name) 没有 \(pol)" }
                return ""
            } ?? "内核未运行"
            if !check.isEmpty { return .failure(APIError(message: check)) }
            engine.setSelection(group: name, member: pol) // persisted like PUT /proxies/{name}
            NativeLogRing.shared.add(type: "info", payload: "[Script] $httpAPI: \(name) → \(pol)")
            return .success([String: Any]())

        case ("GET", "/v1/outbound"):
            return .success(["mode": surgeMode(engine.effectiveMode)])

        case ("POST", "/v1/outbound"):
            switch field(body, "mode").lowercased() {
            case "direct": engine.modeOverride = "direct"
            case "proxy", "global": engine.modeOverride = "global"
            case "rule": engine.modeOverride = "rule"
            default: return .failure(APIError(message: "mode 只能是 direct / proxy / rule"))
            }
            return .success([String: Any]())

        case ("GET", "/v1/rules"):
            let r: [String: Any]? = engine.withGroups { cfg, _ in
                ["rules": cfg.rules, "available-policies": ["DIRECT", "REJECT"] + cfg.groups.map { $0.name } + cfg.proxies.map { $0.name }]
            }
            return .success(r ?? ["rules": [String]()])

        case ("GET", "/v1/profiles/current"):
            return .success(["name": AppShared.activeProfileURL?.deletingPathExtension().lastPathComponent ?? "config"])

        case ("POST", "/v1/profiles/reload"):
            DispatchQueue.global(qos: .utility).async {
                if let err = NativeTunnelCore.shared.reload(hot: false) {
                    NativeLogRing.shared.add(type: "warning", payload: "[Script] $httpAPI reload: \(err)")
                }
            }
            return .success([String: Any]())

        case ("POST", "/v1/dns/flush"):
            NativeTunnelCore.shared.flushDNSCache()
            return .success([String: Any]())

        case ("GET", "/loon/config"):
            let r: [String: Any]? = engine.withGroups { cfg, g in
                var sel: [String: String] = [:]
                for grp in cfg.groups { sel[grp.name] = g.currentMember(of: grp) ?? "" }
                let m = engine.effectiveMode
                return ["running_model": m == "direct" ? 0 : (m == "global" ? 2 : 1),
                        "global_proxy": cfg.groupMap["GLOBAL"].flatMap { g.currentMember(of: $0) } ?? "",
                        "policy_select": sel,
                        "all_policy_groups": cfg.groups.map { $0.name },
                        "all_nodes": cfg.proxies.map { $0.name },
                        "ssid": UserDefaults(suiteName: AppShared.appGroup)?.string(forKey: "nativeCoreSSID") ?? ""]
            }
            return .success(r ?? [:])
        default:
            return .failure(APIError(message: "不支持的 $httpAPI：\(method) \(path)（支持：\(supported.joined(separator: "；"))）"))
        }
    }
}

// MARK: - cron

struct NCCron {
    let expr: String
    private var sec: UInt64 = 0, min: UInt64 = 0, hour: UInt64 = 0, dom: UInt64 = 0, mon: UInt64 = 0, dow: UInt64 = 0
    private var domStar = false, dowStar = false

    private static let monNames = ["jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12]
    private static let dowNames = ["sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6]
    private static let macros = ["@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
                                 "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"]

    init?(_ raw: String) {
        var e = raw.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'")).trimmingCharacters(in: .whitespaces)
        if let m = Self.macros[e.lowercased()] { e = m }
        var f = e.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        expr = f.joined(separator: " ")
        if f.count == 5 { f.insert("0", at: 0) } else if f.count != 6 { return nil }
        guard let s = Self.field(f[0], 0, 59, nil), let mi = Self.field(f[1], 0, 59, nil), let h = Self.field(f[2], 0, 23, nil),
              let d = Self.field(f[3], 1, 31, nil), let mo = Self.field(f[4], 1, 12, Self.monNames),
              let w = Self.field(f[5], 0, 6, Self.dowNames) else { return nil }
        (sec, min, hour, dom, mon, dow) = (s.0, mi.0, h.0, d.0, mo.0, w.0)
        (domStar, dowStar) = (d.1, w.1)
    }

    private static func value(_ s: String, _ names: [String: Int]?) -> Int? {
        if let names, let v = names[s.lowercased()] { return v }
        return Int(s)
    }

    private static func field(_ f: String, _ lo: Int, _ hi: Int, _ names: [String: Int]?) -> (UInt64, Bool)? {
        if f == "*" || f == "?" {
            var m: UInt64 = 0
            for i in lo...hi { m |= 1 << UInt64(i) }
            return (m, true)
        }
        var m: UInt64 = 0
        for var part in f.split(separator: ",", omittingEmptySubsequences: false).map(String.init) {
            var step = 1
            if let i = part.firstIndex(of: "/") {
                guard let s = Int(part[part.index(after: i)...]), s > 0 else { return nil }
                // a step past the field's span only ever selects the start; capping it keeps `i += step` from
                // overflowing (and trapping) on a config like "*/9223372036854775807"
                step = Swift.min(s, hi - lo + 1)
                part = String(part[..<i])
            }
            var a = lo, b = hi
            if part != "*" && part != "?" {
                let r = part.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
                guard let va = value(r[0], names) else { return nil }
                a = va; b = va
                if r.count == 2 {
                    guard let vb = value(r[1], names) else { return nil }
                    b = vb
                } else if step > 1 {
                    b = hi
                }
            }
            if names != nil && hi == 6 {
                if a == 7 && b == 7 { a = 0; b = 0 } else if b == 7 { b = 6; m |= 1 }
            }
            guard a >= lo, b <= hi, a <= b else { return nil }
            var i = a
            while i <= b { m |= 1 << UInt64(i); i += step }
        }
        return (m, false)
    }

    private func dayOK(_ c: DateComponents) -> Bool {
        let d = dom & (1 << UInt64(c.day ?? 1)) != 0
        let w = dow & (1 << UInt64((c.weekday ?? 1) - 1)) != 0
        if domStar && dowStar { return true }
        if domStar { return w }
        if dowStar { return d }
        return d || w
    }

    /// First fire time strictly after t (nil if none within 5 years), local calendar.
    func next(after t: Date) -> Date? {
        let cal = Calendar.current
        var cur = Date(timeIntervalSince1970: floor(t.timeIntervalSince1970) + 1)
        let limit = cal.date(byAdding: .year, value: 5, to: cur) ?? cur.addingTimeInterval(5 * 365 * 86400)
        var guardSteps = 0
        while cur < limit && guardSteps < 200_000 {
            guardSteps += 1
            let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second, .weekday], from: cur)
            func at(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int) -> Date {
                cal.date(from: DateComponents(year: y, month: mo, day: d, hour: h, minute: mi, second: 0)) ?? cur.addingTimeInterval(60)
            }
            let (y, mo, d, h, mi, s) = (c.year!, c.month!, c.day!, c.hour!, c.minute!, c.second!)
            if mon & (1 << UInt64(mo)) == 0 { cur = at(y, mo + 1, 1, 0, 0); continue }
            if !dayOK(c) { cur = at(y, mo, d + 1, 0, 0); continue }
            if hour & (1 << UInt64(h)) == 0 { cur = at(y, mo, d, h + 1, 0); continue }
            if min & (1 << UInt64(mi)) == 0 { cur = at(y, mo, d, h, mi + 1); continue }
            if sec & (1 << UInt64(s)) == 0 { cur = cur.addingTimeInterval(1); continue }
            return cur
        }
        return nil
    }
}

// MARK: - tasks and panels

final class NativeTaskRunner {
    static let shared = NativeTaskRunner()

    struct TaskDef: Decodable {
        var i: Int
        var taskId: String?
        var name: String
        var kind: String?
        var cron: String?
        var event: String?
        var off: Bool?
        var format: String?
        var source: String?
        var line: String?
        var path: String?
        var icon: String?
        var timeoutMs: Int64?
        var id: String { taskId ?? "task\(i)" }
    }

    struct PanelDef: Codable {
        var id: String
        var name: String
        var title: String?
        var content: String?
        var style: String?
        var icon: String?
        var iconColor: String?
        var script: String?
        var interval: Int?
        var source: String
        var format: String
        var taskId: String?
        var defaultInterval: Int?
        var intervalOverridden: Bool?
    }

    private struct TaskState {
        var nextRun: Double = 0
        var lastRun: Double = 0
        var lastOK = false
        var lastResult = ""
        var duration: Int64 = 0
        var running = false
    }

    private struct PanelState {
        var panel: PanelDef
        var updated: Double = 0
        var error = ""
        var running = false
        var bg = ""
    }

    private struct Prefs: Decodable {
        var paused: Bool?
        var enabled: [String: Bool]?
        var order: [String]?
        var deleted: [String: Bool]?
    }

    private struct HomePin: Decodable { var id: String; var interval: Int?; var params: String? }
    private struct Home: Decodable { var visible: [String]?; var tasks: [HomePin]?; var intervals: [String: Int]? }

    struct RunRecord: Codable { var time: Double; var ok: Bool; var duration: Int64; var trigger: String; var result: String?; var logs: [String]? }

    private let lock = NSLock()
    private var tasks: [TaskDef] = []
    private var states: [String: TaskState] = [:]
    private var crons: [String: NCCron] = [:]
    private var panels: [PanelState] = []
    private var prefs = Prefs()
    private var home = Home()
    private var network: [String: Any] = [:]
    private var lastNet = ""
    private var viewed = Date.distantPast
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "tern.native-tasks", qos: .utility)
    /// one task script at a time (memory first)
    private let runGate = DispatchSemaphore(value: 1)

    private var dir: URL { EnginePaths.dir }

    // MARK: load

    /// Reads the tasks / panels of the manifest the script host just loaded; restarts the schedule. Returns a log line.
    @discardableResult
    func load(home path: String) -> String {
        var defs: [TaskDef] = []
        var pdefs: [PanelDef] = []
        let url = URL(fileURLWithPath: path).appendingPathComponent("nativecore-scripts.json")
        if let data = try? Data(contentsOf: url), let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            for raw in (obj["tasks"] as? [[String: Any]]) ?? [] {
                if let d = try? JSONSerialization.data(withJSONObject: raw), let t = try? JSONDecoder().decode(TaskDef.self, from: d) { defs.append(t) }
            }
            for raw in (obj["panels"] as? [[String: Any]]) ?? [] {
                if let d = try? JSONSerialization.data(withJSONObject: raw), let p = try? JSONDecoder().decode(PanelDef.self, from: d) { pdefs.append(p) }
            }
        }
        let prefs = Self.readJSON(Prefs.self, dir.appendingPathComponent("task-prefs.json")) ?? Prefs()
        let home = Self.readJSON(Home.self, dir.appendingPathComponent("home-panels.json")) ?? Home()
        let cache = Self.readJSONArray(dir.appendingPathComponent("panel-cache.json"))
        lock.lock()
        self.prefs = prefs
        self.home = home
        tasks = Self.ordered(defs, prefs.order ?? [])
        var ns: [String: TaskState] = [:]
        crons = [:]
        let now = Date()
        for t in tasks {
            var st = states[t.id] ?? TaskState()
            st.nextRun = 0
            if let c = t.cron, !c.isEmpty, let cr = NCCron(c) {
                crons[t.id] = cr
                st.nextRun = cr.next(after: now)?.timeIntervalSince1970 ?? 0
            }
            ns[t.id] = st
        }
        states = ns
        let all = withTaskPanels(pdefs)
        var ps: [PanelState] = []
        for p in all {
            if let old = panels.first(where: { $0.panel.id == p.id }) {
                var st = old
                st.panel.interval = p.interval
                ps.append(st)
                continue
            }
            var st = PanelState(panel: p)
            if let c = cache[p.id], p.script != nil {
                st.panel.title = c["title"] as? String ?? p.title
                st.panel.content = c["content"] as? String ?? p.content
                st.panel.icon = c["icon"] as? String ?? p.icon
                st.panel.iconColor = c["iconColor"] as? String ?? p.iconColor
                st.panel.style = c["style"] as? String ?? p.style
                st.bg = c["backgroundColor"] as? String ?? ""
                st.updated = 0 // cached content shown; refreshed on first view
            }
            ps.append(st)
        }
        panels = ps
        let (nt, np) = (tasks.count, panels.count)
        lock.unlock()
        reschedule()
        return "\(nt) task(s), \(np) panel(s)"
    }

    /// fix/nc-mitm-live: what the schedule holds, for the startup log and one line in 脚本日志 at every load
    /// (a cron that does not parse used to make its task silently never run).
    func scheduleSummary() -> String {
        lock.lock(); defer { lock.unlock() }
        let cronTasks = tasks.filter { ($0.cron ?? "").isEmpty == false }
        let bad = cronTasks.filter { crons[$0.id] == nil }
        let off = tasks.filter { !enabledLocked($0) }.count
        var nextName = "", nextAt = 0.0
        for t in cronTasks where enabledLocked(t) {
            if let st = states[t.id], st.nextRun > 0, nextAt == 0 || st.nextRun < nextAt { nextAt = st.nextRun; nextName = t.name }
        }
        var out = "\(tasks.count) 个任务（定时 \(cronTasks.count)，停用 \(off)）"
        if prefs.paused == true { out += "，全部已暂停" }
        if !bad.isEmpty { out += "，cron 无法解析：" + bad.prefix(3).map { "\($0.name)（\($0.cron ?? "")）" }.joined(separator: "、") }
        if nextAt > 0 {
            let f = DateFormatter()
            f.dateFormat = "MM-dd HH:mm"
            out += "；下一次：\(nextName) \(f.string(from: Date(timeIntervalSince1970: nextAt)))"
        }
        return out
    }

    func stop() {
        lock.lock()
        timer?.cancel()
        timer = nil
        lock.unlock()
    }

    private static func ordered(_ ts: [TaskDef], _ order: [String]) -> [TaskDef] {
        guard !order.isEmpty else { return ts }
        var idx: [String: Int] = [:]
        for (i, id) in order.enumerated() where idx[id] == nil { idx[id] = i }
        return ts.enumerated().sorted { a, b in
            let ia = idx[a.element.id] ?? Int.max, ib = idx[b.element.id] ?? Int.max
            return ia != ib ? ia < ib : a.offset < b.offset
        }.map { $0.element }
    }

    /// Module panels + one panel per pinned generic / interaction script; the user's intervals win (lock held).
    private func withTaskPanels(_ base: [PanelDef]) -> [PanelDef] {
        var out = base
        var seen = Set<String>()
        for pin in home.tasks ?? [] where !seen.contains(pin.id) {
            seen.insert(pin.id)
            guard let t = tasks.first(where: { $0.id == pin.id && ($0.kind == "generic" || $0.kind == "interaction") }) else { continue }
            out.append(PanelDef(id: "task-" + t.id, name: t.name, title: t.name, icon: t.kind == "interaction" ? "hand.tap" : "play.rectangle",
                                script: t.name, interval: max(pin.interval ?? 0, 0), source: t.source ?? "", format: t.format ?? "surge", taskId: t.id))
        }
        for i in out.indices {
            if let v = home.intervals?[out[i].id], v > 0, out[i].script != nil {
                out[i].defaultInterval = out[i].interval
                out[i].interval = max(v, 60)
                out[i].intervalOverridden = true
            }
        }
        return out
    }

    private func enabledLocked(_ t: TaskDef) -> Bool {
        if prefs.paused == true || prefs.deleted?[t.id] == true { return false }
        if let v = prefs.enabled?[t.id] { return v }
        return t.off != true
    }

    // MARK: schedule

    private func reschedule() {
        lock.lock()
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        timer = t
        lock.unlock()
        t.setEventHandler { [weak self] in self?.tick() }
        t.schedule(deadline: .now() + 1)
        t.resume()
    }

    private func tick() {
        let now = Date()
        var next = now.addingTimeInterval(3600)
        var due: [TaskDef] = []
        lock.lock()
        for t in tasks {
            guard let cr = crons[t.id], var st = states[t.id], st.nextRun > 0 else { continue }
            var at = Date(timeIntervalSince1970: st.nextRun)
            if at <= now {
                if enabledLocked(t) { due.append(t) }
                guard let n = cr.next(after: now) else { st.nextRun = 0; states[t.id] = st; continue }
                st.nextRun = n.timeIntervalSince1970
                at = n
            }
            states[t.id] = st
            if at < next { next = at }
        }
        let duePanels = duePanelsLocked(now, &next)
        let t = timer
        lock.unlock()
        for task in due { DispatchQueue.global(qos: .utility).async { [weak self] in _ = self?.runAs(task, extra: [:], params: nil, trigger: "schedule") } }
        for id in duePanels { DispatchQueue.global(qos: .utility).async { [weak self] in _ = self?.refreshPanel(id) } }
        let d = max(1, next.timeIntervalSince(Date()))
        t?.schedule(deadline: .now() + d)
    }

    /// Panels with a script that are due now: visible on Home (first fill at connect, then on their interval, ≥ 5 min
    /// apart while the app is not showing panels) or shown in the app within the last window (lock held).
    private func duePanelsLocked(_ now: Date, _ next: inout Date) -> [String] {
        var due: [String] = []
        let visible = Set(home.visible ?? [])
        for st in panels where st.panel.script != nil && !st.running {
            let p = st.panel
            let onHome = visible.contains(p.id)
            let interval = p.interval ?? 0
            if interval <= 0 {
                if onHome && st.updated == 0 { due.append(p.id) }
                continue
            }
            if st.updated == 0 && !onHome { continue }
            let window = max(180, 2 * Double(interval))
            let seen = now.timeIntervalSince(viewed) <= window
            if !seen && !onHome { continue }
            var every = Double(max(interval, 60))
            if !seen { every = max(every, 300) }
            let at = Date(timeIntervalSince1970: st.updated + every)
            if at <= now { due.append(p.id) } else if at < next { next = at }
        }
        return due
    }

    // MARK: runs

    private func findLocked(_ id: String) -> TaskDef? { tasks.first { $0.id == id || $0.name == id } }

    /// Manual run (controller POST /mitm/tasks/{id}/run). Blocks the calling thread (never the controller queue).
    func run(id: String, params: String?) -> (ok: Bool, error: String?, result: Any?) {
        lock.lock(); let t = findLocked(id); lock.unlock()
        guard let t else { return (false, "任务不存在", nil) }
        var extra: [String: Any] = [:]
        if t.kind == "interaction" { extra["$input"] = ["purpose": "interaction"] }
        return runAs(t, extra: extra, params: params, trigger: t.kind == "interaction" ? "interaction" : "manual")
    }

    /// Network change (NativeTunnelCore.notifyNetworkChanged): runs every enabled event task, same network within
    /// the debounce ignored. Returns how many were started.
    func networkChanged(_ info: [String: Any]) -> Int {
        let sig = NativeHTTPAPI.json(info) ?? ""
        lock.lock()
        network = info
        let same = sig == lastNet
        lastNet = sig
        let list = tasks.filter { $0.kind == "event" && enabledLocked($0) }
        lock.unlock()
        if same { return 0 }
        for t in list {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let ev: [String: Any] = ["name": "network-changed", "data": info]
                _ = self?.runAs(t, extra: ["$event": ev], params: nil, trigger: "event")
            }
        }
        return list.count
    }

    private func runAs(_ t: TaskDef, extra: [String: Any], params: String?, trigger: String) -> (ok: Bool, error: String?, result: Any?) {
        lock.lock()
        var st = states[t.id] ?? TaskState()
        if st.running { lock.unlock(); return (false, "\(t.name) 正在运行", nil) }
        st.running = true
        states[t.id] = st
        let net = network
        lock.unlock()
        let logSeq = NativeLogRing.shared.scriptLines(since: 0).last?.id ?? 0
        let kindLabel = t.kind == "cron" ? "定时" : (t.kind == "event" ? "事件" : (t.kind == "interaction" ? "交互" : "通用"))
        NativeLogRing.shared.addScript(script: t.name, level: "info", msg: "开始运行（\(kindLabel)）")
        let start = Date()
        runGate.wait()
        let (value, err) = execute(t, extra: extra, network: net, params: params)
        runGate.signal()
        let ms = Int64(Date().timeIntervalSince(start) * 1000)
        var result = ""
        if err == nil, let value, let s = NativeHTTPAPI.json(value) { result = String(s.prefix(300)) }
        lock.lock()
        st = states[t.id] ?? TaskState()
        st.running = false
        st.lastRun = floor(start.timeIntervalSince1970)
        st.duration = ms
        st.lastOK = err == nil
        st.lastResult = err ?? result
        states[t.id] = st
        lock.unlock()
        if let err {
            NativeLogRing.shared.addScript(script: t.name, level: "error", msg: err)
        } else {
            NativeLogRing.shared.addScript(script: t.name, level: "info", msg: "运行结束，用时 \(ms) ms")
        }
        let logs = NativeLogRing.shared.scriptLines(since: logSeq).filter { $0.script == t.name }.suffix(30).map { "[\($0.level)] \($0.msg)" }
        record(t.id, RunRecord(time: floor(start.timeIntervalSince1970), ok: err == nil, duration: ms, trigger: trigger,
                               result: (err ?? result).isEmpty ? nil : (err ?? result), logs: logs.isEmpty ? nil : Array(logs)))
        return (err == nil, err, value)
    }

    /// One task script run on the native script host (phase task, export on). value: what $done exported.
    private func execute(_ t: TaskDef, extra: [String: Any], network: [String: Any], params: String?) -> (Any?, String?) {
        let host = NativeScriptHost.shared
        let p = host.prepare(gen: 0, rule: t.i, slot: 0, reload: false)
        guard p.ok, let key = p.key else { return (nil, p.err ?? "脚本运行时内部错误") }
        var setup = ((try? JSONSerialization.jsonObject(with: Data(p.setupJSON.utf8))) as? [String: Any]) ?? [:]
        setup["phase"] = "task"
        setup["export"] = true
        var globals: [String: Any] = ["$network": network]
        for (k, v) in extra { globals[k] = v }
        setup["globals"] = globals
        if let params { setup["hasParams"] = true; setup["params"] = params }
        guard let sd = try? JSONSerialization.data(withJSONObject: setup), let ss = String(data: sd, encoding: .utf8) else {
            return (nil, "脚本参数错误")
        }
        let run = NativeScriptRun(gen: 0, rule: t.i, hostAPI: host, js: JSCScriptEngine.shared, lane: nil,
                                  nativeBase: NativeBodyStore.defaultBlobBase, laneOK: false)
        let out = run.run(key: key, setup: ss, timeoutMs: p.timeoutMs ?? t.timeoutMs ?? 30_000) {
            let p2 = host.prepare(gen: 0, rule: t.i, slot: 0, reload: true)
            return p2.ok ? p2.key : nil
        }
        run.releaseNatives(keep: 0)
        switch out {
        case .failed(let note):
            return (nil, note.isEmpty ? "脚本错误" : note)
        case .ok:
            let raw = run.doneJSON
            guard !raw.isEmpty, let d = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any] else { return (nil, nil) }
            if d["undef"] as? Bool == true || d["isNull"] as? Bool == true { return (nil, nil) }
            guard let v = d["value"], !(v is NSNull) else { return (nil, nil) }
            if v is [String: Any] { return (v, nil) }
            return (["value": v], nil)
        }
    }

    // MARK: history / prefs

    private func record(_ id: String, _ r: RunRecord) {
        queue.async { [dir] in
            let url = dir.appendingPathComponent("task-history.json")
            var all = (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode([String: [RunRecord]].self, from: $0) } ?? [:]
            var l = all[id] ?? []
            l.append(r)
            if l.count > 20 { l.removeFirst(l.count - 20) }
            all[id] = l
            if let d = try? JSONEncoder().encode(all) { try? d.write(to: url, options: .atomic) }
        }
    }

    func history(id: String) -> Data {
        let url = dir.appendingPathComponent("task-history.json")
        guard let d = try? Data(contentsOf: url), let all = try? JSONDecoder().decode([String: [RunRecord]].self, from: d),
              let l = all[id], let out = try? JSONEncoder().encode(l) else { return Data("[]".utf8) }
        return out
    }

    /// PUT /mitm/tasks-prefs (the app already wrote task-prefs.json; re-read it and re-order).
    func setPrefs(_ body: Data) {
        let p = (try? JSONDecoder().decode(Prefs.self, from: body)) ?? Self.readJSON(Prefs.self, dir.appendingPathComponent("task-prefs.json")) ?? Prefs()
        lock.lock()
        prefs = p
        tasks = Self.ordered(tasks, p.order ?? [])
        lock.unlock()
    }

    /// PUT /mitm/panels-home: the Home panel configuration (also persisted, like the old core).
    func setHome(_ body: Data) -> Bool {
        guard let h = try? JSONDecoder().decode(Home.self, from: body) else { return false }
        try? body.write(to: dir.appendingPathComponent("home-panels.json"), options: .atomic)
        lock.lock()
        home = h
        let base = panels.map { $0.panel }.filter { !$0.id.hasPrefix("task-") }
        let all = withTaskPanels(base.map { var p = $0; if p.intervalOverridden == true { p.interval = p.defaultInterval; p.intervalOverridden = nil; p.defaultInterval = nil }; return p })
        var ps: [PanelState] = []
        for p in all {
            if var old = panels.first(where: { $0.panel.id == p.id }) { old.panel.interval = p.interval; old.panel.defaultInterval = p.defaultInterval; old.panel.intervalOverridden = p.intervalOverridden; ps.append(old) } else { ps.append(PanelState(panel: p)) }
        }
        panels = ps
        lock.unlock()
        reschedule()
        return true
    }

    // MARK: listings

    func listJSON() -> [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return tasks.map { t in
            let st = states[t.id] ?? TaskState()
            let script: [String: Any] = ["name": t.name, "path": t.path ?? "", "timeout": Int((t.timeoutMs ?? 30_000) / 1000)]
            var o: [String: Any] = ["id": t.id, "kind": t.kind ?? "generic", "script": script,
                                    "source": t.source ?? "", "line": t.line ?? "", "lastOK": st.lastOK, "running": st.running, "enabled": enabledLocked(t)]
            if let c = t.cron { o["cron"] = c }
            if let e = t.event { o["event"] = e }
            if let f = t.format { o["format"] = f }
            if let i = t.icon { o["icon"] = i }
            if t.off == true { o["disabledByLine"] = true }
            if st.nextRun > 0 { o["nextRun"] = st.nextRun }
            if st.lastRun > 0 { o["lastRun"] = st.lastRun }
            if !st.lastResult.isEmpty { o["lastResult"] = st.lastResult }
            if st.duration > 0 { o["duration"] = st.duration }
            return o
        }
    }

    private static func panelJSON(_ st: PanelState) -> [String: Any] {
        let p = st.panel
        var o: [String: Any] = ["id": p.id, "name": p.name, "source": p.source, "format": p.format, "running": st.running]
        if let v = p.title { o["title"] = v }
        if let v = p.content { o["content"] = v }
        if let v = p.style { o["style"] = v }
        if let v = p.icon { o["icon"] = v }
        if let v = p.iconColor { o["iconColor"] = v }
        if let v = p.script { o["script"] = v }
        if let v = p.interval { o["interval"] = v }
        if let v = p.taskId { o["taskId"] = v }
        if let v = p.defaultInterval { o["defaultInterval"] = v }
        if let v = p.intervalOverridden { o["intervalOverridden"] = v }
        if st.updated > 0 { o["updated"] = st.updated }
        if !st.error.isEmpty { o["error"] = st.error }
        if !st.bg.isEmpty { o["backgroundColor"] = st.bg }
        return o
    }

    /// GET /mitm/panels (marks the panels as being looked at; panels never filled start their first refresh).
    func panelsJSON(markViewed: Bool) -> [[String: Any]] {
        lock.lock()
        let paused = Date().timeIntervalSince(viewed) > 180
        if markViewed { viewed = Date() }
        let out = panels.map { Self.panelJSON($0) }
        let firstFill = markViewed ? panels.filter { $0.panel.script != nil && $0.updated == 0 && !$0.running }.map { $0.panel.id } : []
        lock.unlock()
        for id in firstFill { DispatchQueue.global(qos: .utility).async { [weak self] in _ = self?.refreshPanel(id) } }
        if markViewed && paused { reschedule() }
        return out
    }

    /// Runs the panel's script and stores what $done returned (the old core refreshPanel). Blocks the calling thread.
    func refreshPanel(_ id: String) -> [String: Any]? {
        lock.lock()
        guard let i = panels.firstIndex(where: { $0.panel.id == id }) else { lock.unlock(); return nil }
        let p = panels[i].panel
        if p.script == nil || panels[i].running {
            if p.script == nil { panels[i].updated = Date().timeIntervalSince1970 }
            let o = Self.panelJSON(panels[i]); lock.unlock(); return o
        }
        panels[i].running = true
        let task: TaskDef? = p.taskId != nil ? tasks.first { $0.id == p.taskId } : (tasks.first { $0.name == p.script && $0.source == p.source } ?? tasks.first { $0.name == p.script })
        let params = p.taskId.flatMap { tid in home.tasks?.first { $0.id == tid }?.params }
        lock.unlock()
        var out: [String: Any]?
        var err: String?
        if let task {
            let pin: [String: Any] = ["title": p.title ?? "", "content": p.content ?? "", "icon": p.icon ?? "", "icon-color": p.iconColor ?? "", "style": p.style ?? ""]
            let r = runAs(task, extra: ["$input": ["purpose": "panel", "position": "policy-selection"], "$panel": pin], params: params, trigger: "panel")
            if r.ok { out = Self.normalize(r.result as? [String: Any]) } else { err = r.error }
        } else {
            err = "找不到脚本 \(p.script ?? "")"
        }
        lock.lock()
        guard let j = panels.firstIndex(where: { $0.panel.id == id }) else { lock.unlock(); return nil }
        panels[j].running = false
        panels[j].updated = Date().timeIntervalSince1970
        if let err {
            panels[j].error = err
        } else {
            panels[j].error = ""
            func get(_ ks: String...) -> String? {
                for k in ks { if let v = out?[k], !(v is NSNull) { return v as? String ?? "\(v)" } }
                return nil
            }
            if let v = get("title") { panels[j].panel.title = v }
            if let v = get("content") { panels[j].panel.content = v }
            if let v = get("icon") { panels[j].panel.icon = v }
            if let v = get("icon-color", "iconColor") { panels[j].panel.iconColor = v }
            if let v = get("style") { panels[j].panel.style = v }
            if let v = get("backgroundColor", "background-color") { panels[j].bg = v }
        }
        let o = Self.panelJSON(panels[j])
        let cache = panels.filter { $0.panel.script != nil }.map { Self.panelJSON($0) }
        lock.unlock()
        queue.async { [dir] in
            if let d = try? JSONSerialization.data(withJSONObject: cache) { try? d.write(to: dir.appendingPathComponent("panel-cache.json"), options: .atomic) }
        }
        return o
    }

    /// QX UI-script results: message / htmlMessage → content (tags stripped, <br> → line break) when content is missing.
    private static func normalize(_ out: [String: Any]?) -> [String: Any]? {
        guard var m = out else { return nil }
        if let c = m["content"], !(c is NSNull) { return m }
        if let v = m["message"], !(v is NSNull) {
            m["content"] = v as? String ?? "\(v)"
        } else if let v = m["htmlMessage"], !(v is NSNull) {
            var s = v as? String ?? "\(v)"
            for br in ["<br>", "<br/>", "<br />", "</p>", "</div>", "<BR>", "<BR/>"] { s = s.replacingOccurrences(of: br, with: "\n") }
            s = s.replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
            m["content"] = s.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return m
    }

    // MARK: files

    private static func readJSON<T: Decodable>(_ t: T.Type, _ url: URL) -> T? {
        guard let d = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(T.self, from: d)
    }

    private static func readJSONArray(_ url: URL) -> [String: [String: Any]] {
        guard let d = try? Data(contentsOf: url), let l = (try? JSONSerialization.jsonObject(with: d)) as? [[String: Any]] else { return [:] }
        var out: [String: [String: Any]] = [:]
        for o in l { if let id = o["id"] as? String { out[id] = o } }
        return out
    }
}
