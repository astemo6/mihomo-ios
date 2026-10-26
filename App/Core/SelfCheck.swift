import Foundation
import Network
import Security

/// 设置 → 诊断 → 一键自检 (feat/nc-e2e, extended in feat/nc-selfcheck-2): the on-device half of the E2E replay. Runs the
/// checks that need the real extension, the real network and the user's real trust settings, one after another with
/// live status, then writes selfcheck.txt into the home directory (DiagnosticSummary puts it first in the 诊断包) and
/// builds the 诊断包.
///
/// selfcheck-2: every problem seen on recent device builds has a step that names it — config lost between import and
/// the running core (1/1/3 vs 9/29/85), rule sets / modules / scripts that never downloaded, node delay per stage for
/// plain and provider nodes (names with spaces / brackets / emoji / "/"), Home's exit-IP lookup per endpoint,
/// `tcp accepted 0`, CA type + trust, a rewrite rule actually firing, the plain-HTTP rewrite gap, and the tunnel's
/// memory against the NE limit. Each step has a hard deadline (a stuck step fails with where it stopped; the next
/// step still runs); selfcheck.txt lists the FAILs first and is redacted like the 诊断包.
/// Lean on purpose: no new dependencies, a handful of requests, nothing kept in memory after the run but the text.
@MainActor
final class SelfCheck: ObservableObject {
    enum State: Equatable { case pending, running, pass, fail, known, skip, needsDevice }

    struct Step: Identifiable, Equatable {
        let id: String
        let title: String
        var state: State = .pending
        var detail = ""
    }

    @Published private(set) var steps: [Step] = SelfCheck.makeSteps()
    @Published private(set) var running = false
    @Published private(set) var finished = false
    @Published private(set) var bundleURL: URL?
    @Published private(set) var bundleError: String?

    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    /// Step ids in run order (UITests/SelfCheckUITests lists the same ids).
    static let stepIDs = ["delay-offline", "vpn", "controller", "counts", "resources", "delay", "delay-nodes", "exitip",
                          "fetch", "dataplane", "mitm", "rewrite", "rewrite-http", "script", "restart", "memory"]

    static func makeSteps() -> [Step] {
        [
            Step(id: "delay-offline", title: String(localized: "VPN 断开时测延迟（App 内直接测）")),
            Step(id: "vpn", title: String(localized: "启动 VPN（分阶段计时）")),
            Step(id: "controller", title: String(localized: "内核控制接口 /version")),
            Step(id: "counts", title: String(localized: "配置完整性（配置 → 运行时 → 内核）")),
            Step(id: "resources", title: String(localized: "远程资源（规则集 / 重写模块 / 脚本）")),
            Step(id: "delay", title: String(localized: "策略组测延迟")),
            Step(id: "delay-nodes", title: String(localized: "逐个节点测延迟（普通节点 + 订阅节点）")),
            Step(id: "exitip", title: String(localized: "首页出口 IP 查询")),
            Step(id: "fetch", title: String(localized: "经隧道访问 3 个网址")),
            Step(id: "dataplane", title: String(localized: "数据面计数（TCP / UDP / DNS、Fake-IP、IPv6）")),
            Step(id: "mitm", title: String(localized: "MitM 自检与证书（类型 / 信任）")),
            Step(id: "rewrite", title: String(localized: "触发一条重写规则并确认日志")),
            Step(id: "rewrite-http", title: String(localized: "明文 HTTP（80 端口）重写")),
            Step(id: "script", title: String(localized: "运行一个脚本并确认有日志")),
            Step(id: "restart", title: String(localized: "断开重连与旧 Fake-IP 处理")),
            Step(id: "memory", title: String(localized: "隧道内存（各步骤后，对比系统上限）")),
        ]
    }

    // MARK: state

    /// Steps whose deadline passed: a late result from the abandoned work must not overwrite the timeout verdict.
    private var abandoned: Set<String> = []
    private var phase: [String: String] = [:]
    private var redactor: DiagnosticRedactor?
    private weak var vpn: VPNManager?

    private func set(_ id: String, _ state: State, _ detail: String = "") {
        guard !abandoned.contains(id), let i = steps.firstIndex(where: { $0.id == id }) else { return }
        steps[i].state = state
        steps[i].detail = redactor.map { $0.text(detail) } ?? detail
    }

    /// What a running step is doing now (shown live; named in the timeout verdict when it never finishes).
    private func progress(_ id: String, _ what: String) {
        phase[id] = what
        guard !abandoned.contains(id), let i = steps.firstIndex(where: { $0.id == id }), steps[i].state == .running else { return }
        steps[i].detail = what + "…"
    }

    private func progressAll(_ what: String) {
        if let i = steps.firstIndex(where: { $0.state == .pending }) { steps[i].detail = what + "…" }
    }

    var summaryLine: String {
        let p = steps.filter { $0.state == .pass }.count
        let f = steps.filter { $0.state == .fail }.count
        let k = steps.filter { $0.state == .known }.count
        let s = steps.filter { $0.state == .skip || $0.state == .needsDevice }.count
        return k > 0 ? String(localized: "通过 \(p) · 失败 \(f) · 已知 \(k) · 跳过 \(s)") : String(localized: "通过 \(p) · 失败 \(f) · 跳过 \(s)")
    }

    // MARK: run

    func run(vpn: VPNManager) async {
        guard !running else { return }
        running = true
        finished = false
        bundleURL = nil
        bundleError = nil
        abandoned = []
        phase = [:]
        memory = []
        steps = Self.makeSteps()
        self.vpn = vpn
        let started = Date()
        let home = AppShared.homeURL.path
        let profilePath = AppShared.activeProfileURL?.path ?? ""
        let r = DiagnosticRedactor()
        r.collectConfigs(home: home, profilePath: profilePath)
        redactor = r
        if Self.isSimulator {
            for s in steps { set(s.id, .needsDevice, String(localized: "需要真机")) }
        } else {
            if vpn.isConnected { await vpn.disconnectAndWait() }
            // The App's own view of the config (as the core would build it), read once: config layer + offline sample.
            progressAll(String(localized: "读取配置"))
            let view: InspectResult?? = await Self.deadline(30) { () async -> InspectResult? in
                await BlockingWork.run { () -> InspectResult? in
                    profilePath.isEmpty ? nil : NCProfileInspectorPort.inspectProfile(home: home, path: profilePath)
                }
            }
            appView = view ?? nil
            await guarded("delay-offline", 40) { await self.stepOfflineDelay() }
            await guarded("vpn", 45) { await self.stepVPN(vpn) }
            if vpn.isConnected {
                await sampleMemory("启动后")
                await guarded("controller", 10) { await self.stepController() }
                await guarded("counts", 30) { await self.stepCounts() }
                await guarded("resources", 45) { await self.stepResources() }
                await guarded("delay", 60) { await self.stepDelay() }
                await guarded("delay-nodes", 50) { await self.stepNodeDelay() }
                await guarded("exitip", 40) { await self.stepExitIP() }
                await guarded("fetch", 45) { await self.stepFetch() }
                await guarded("dataplane", 15) { await self.stepDataPlane() }
                await guarded("mitm", 20) { await self.stepMitM() }
                await guarded("rewrite", 25) { await self.stepRewrite() }
                await guarded("rewrite-http", 5) { self.stepRewriteHTTP() }
                await guarded("script", 50) { await self.stepScript() }
                await guarded("restart", 50) { await self.stepRestart(vpn) }
                await guarded("memory", 8) { await self.stepMemory() }
            } else {
                for id in Self.stepIDs.drop(while: { $0 != "controller" }) {
                    set(id, .skip, String(localized: "VPN 未连接"))
                }
            }
        }
        let text = report(started: started)
        try? text.write(toFile: (home as NSString).appendingPathComponent(Self.reportFile), atomically: true, encoding: .utf8)
        let exported: Result<URL, Error>? = await Self.deadline(60) { () async -> Result<URL, Error> in
            do { return .success(try await DiagnosticsExporter.export(vpn: vpn)) } catch { return .failure(error) }
        }
        switch exported {
        case .success(let u)?: bundleURL = u
        case .failure(let e)?: bundleError = String(localized: "导出失败：") + e.localizedDescription
        case nil: bundleError = String(localized: "导出失败：60 秒内没有完成")
        }
        appView = nil
        running = false
        finished = true
    }

    static let reportFile = "selfcheck.txt"

    private func report(started: Date) -> String {
        let f = ISO8601DateFormatter()
        let rows = steps.map { s -> SelfCheckLogic.ReportStep in
            let mark: String
            switch s.state {
            case .pass: mark = "PASS"
            case .fail: mark = "FAIL"
            case .known: mark = "KNOWN"
            case .skip: mark = "SKIP"
            case .needsDevice: mark = "SKIP(需要真机)"
            case .pending, .running: mark = "-"
            }
            return SelfCheckLogic.ReportStep(mark: mark, title: s.title, detail: s.detail)
        }
        let text = SelfCheckLogic.report(header: "Tern 一键自检 \(f.string(from: started))", summary: summaryLine, steps: rows)
        return redactor.map { $0.text(text) } ?? text
    }

    // MARK: deadlines

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func claim() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
    }

    /// `op`'s result, or nil when `seconds` pass first. Never waits for `op` past the deadline (it is cancelled and
    /// left to finish on its own), so a stuck request or blocking call cannot hang the self-check.
    static func deadline<T>(_ seconds: Double, _ op: @escaping @MainActor () async -> T) async -> T? {
        await withCheckedContinuation { (c: CheckedContinuation<T?, Never>) in
            let once = Once()
            let work = Task { @MainActor in
                let v = await op()
                if once.claim() { c.resume(returning: v) }
            }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                if once.claim() {
                    work.cancel()
                    c.resume(returning: nil)
                }
            }
        }
    }

    private func guarded(_ id: String, _ seconds: Double, _ body: @escaping @MainActor () async -> Void) async {
        let finished: Bool? = await Self.deadline(seconds) { () async -> Bool in await body(); return true }
        if finished == nil {
            let at = phase[id].map { String(localized: "，停在：\($0)") } ?? ""
            set(id, .fail, String(localized: "步骤超时：\(Int(seconds)) 秒内没有结果\(at)"))
            abandoned.insert(id)
        } else if let i = steps.firstIndex(where: { $0.id == id }), steps[i].state == .running || steps[i].state == .pending {
            set(id, .fail, String(localized: "步骤没有给出结果"))
        }
        if id != "vpn", id != "delay-offline", id != "memory", vpn?.isConnected == true {
            await sampleMemory(steps.first { $0.id == id }.map { Self.shortLabel($0.id) } ?? id)
        }
    }

    private static func shortLabel(_ id: String) -> String {
        switch id {
        case "controller": return String(localized: "接口")
        case "counts": return String(localized: "完整性")
        case "resources": return String(localized: "资源")
        case "delay": return String(localized: "组测速")
        case "delay-nodes": return String(localized: "节点测速")
        case "exitip": return String(localized: "出口")
        case "fetch": return String(localized: "访问")
        case "dataplane": return String(localized: "数据面")
        case "mitm": return "MitM"
        case "rewrite": return String(localized: "重写")
        case "rewrite-http": return "HTTP"
        case "script": return String(localized: "脚本")
        case "restart": return String(localized: "重连后")
        default: return id
        }
    }

    nonisolated private static func ms(_ t: Date) -> Int { Int(Date().timeIntervalSince(t) * 1000) }

    // MARK: shared data

    private var appView: InspectResult?
    private var groupNames: [String] = []
    private var proxiesSnapshot: [String: ProxyItem] = [:]
    private var providersSnapshot: [ProviderItem] = []

    private static func sessionLog() -> String { SelfCheckLogic.currentSession(StartupLog.read()) }

    private static func json(_ name: String) -> Any? {
        guard let d = try? Data(contentsOf: AppShared.homeURL.appendingPathComponent(name)) else { return nil }
        return try? JSONSerialization.jsonObject(with: d)
    }

    // MARK: 1 offline delay (VPN off, NCDelayTester)

    /// The 策略 page's offline path: the App tests nodes itself (bound to Wi-Fi / cellular) while the VPN is off.
    private func stepOfflineDelay() async {
        set("delay-offline", .running)
        let home = AppShared.homeURL.path
        guard let path = AppShared.activeProfileURL?.path, let view = appView else {
            set("delay-offline", .skip, String(localized: "没有可用的配置")); return
        }
        let plain = SelfCheckLogic.sample(view.proxies.map(\.name), max: 2)
        let prov = SelfCheckLogic.sample(view.proxyProviders.flatMap { ($0.proxies ?? []).map(\.name) }, max: 3)
        let names = plain + prov.filter { !plain.contains($0) }
        guard !names.isEmpty else { set("delay-offline", .skip, String(localized: "配置里没有节点")); return }
        progress("delay-offline", String(localized: "绑定物理网卡"))
        let ifaceR: String?? = await Self.deadline(3) { () async -> String? in await PhysicalInterface.current() }
        let iface: String? = ifaceR ?? nil
        NCDelayTester.setOfflineInterface(iface ?? "")
        let st = ControllerClient.testSettings
        progress("delay-offline", String(localized: "测 \(names.count) 个节点"))
        let results = await withTaskGroup(of: (String, Int, Bool).self, returning: [String: (Int, Bool)].self) { tg in
            for n in names {
                let u = NodeSettingsStore.customURL(for: n) ?? st.url
                tg.addTask {
                    await BlockingWork.run { () -> (String, Int, Bool) in
                        guard NCNodeResolver.shared.resolveByName(homeDir: home, profilePath: path, name: n) != nil else { return (n, 0, false) }
                        return (n, NCDelayTester.testDelayByName(homeDir: home, profilePath: path, name: n, url: u, timeoutMs: st.timeoutMs), true)
                    }
                }
            }
            var out: [String: (Int, Bool)] = [:]
            for await (n, ms, found) in tg { out[n] = (ms, found) }
            return out
        }
        var lines: [String] = []
        var ok = 0, missing = 0
        for n in names {
            let kind = plain.contains(n) ? String(localized: "普通") : String(localized: "订阅")
            guard let (ms, found) = results[n] else { continue }
            if !found { missing += 1; lines.append("[\(kind)] \(n)：" + String(localized: "App 侧找不到这个节点（相当于 404）")); continue }
            if ms > 0 { ok += 1; lines.append("[\(kind)] \(n)：\(ms) ms") } else { lines.append("[\(kind)] \(n)：" + String(localized: "超时或失败（\(st.timeoutMs) ms 预算）")) }
        }
        let head: String
        if ok == 0 {
            head = missing == names.count ? String(localized: "抽样的 \(names.count) 个节点在 App 侧都解析不到") : String(localized: "VPN 断开时 \(names.count) 个节点全部超时（网卡 \(iface ?? "-")）")
        } else {
            head = String(localized: "\(ok)/\(names.count) 个节点可用（网卡 \(iface?.isEmpty == false ? iface! : "-")）")
        }
        set("delay-offline", ok > 0 ? .pass : .fail, ([head] + lines).joined(separator: "\n"))
    }

    // MARK: 2 vpn

    /// Start the VPN from cold and split the time with the extension's own startup-log stamps.
    private func stepVPN(_ vpn: VPNManager) async {
        set("vpn", .running)
        if vpn.isConnected { await vpn.disconnectAndWait() }
        progress("vpn", String(localized: "连接中"))
        let t0 = Date()
        let ok = await vpn.connectAndWait(timeout: 30)
        let total = Self.ms(t0)
        guard ok else {
            let last = SelfCheckLogic.lastLine(Self.sessionLog(), containing: "FAILED") ?? ""
            set("vpn", .fail, String(localized: "未能连接（\(total) ms）：") + (vpn.lastError ?? "-") + (last.isEmpty ? "" : "\n" + last))
            return
        }
        let phases = Self.startupPhases(StartupLog.read(), since: t0)
        set("vpn", .pass, String(localized: "已连接，用时 \(total) ms") + (phases.isEmpty ? "" : "\n" + phases))
    }

    /// "HH:mm:ss.SSS [tag] msg" lines of the current startup log → per-phase durations.
    static func startupPhases(_ log: String, since t0: Date) -> String {
        let marks: [(String, String)] = [
            ("startTunnel called", String(localized: "扩展启动")),
            ("settings applied", String(localized: "隧道网络设置")),
            ("core start begin", String(localized: "内核加载开始")),
            ("core start returned OK", String(localized: "内核启动完成")),
            ("startTunnel completed OK", String(localized: "连接完成")),
        ]
        let current = SelfCheckLogic.currentSession(log)
        let cal = Calendar.current
        let day = cal.dateComponents([.year, .month, .day], from: t0)
        func stamp(_ line: String) -> Date? {
            let p = line.prefix(12).split(separator: ":")
            guard p.count == 3, let h = Int(p[0]), let m = Int(p[1]), let s = Double(p[2]) else { return nil }
            var c = day
            c.hour = h; c.minute = m; c.second = Int(s); c.nanosecond = Int((s - Double(Int(s))) * 1e9)
            return cal.date(from: c)
        }
        var prev = t0
        var out: [String] = []
        for (needle, label) in marks {
            guard let line = current.split(separator: "\n").last(where: { $0.contains(needle) }), let t = stamp(String(line)) else { continue }
            out.append("\(label) +\(max(0, Int(t.timeIntervalSince(prev) * 1000))) ms")
            prev = t
        }
        return out.joined(separator: " · ")
    }

    // MARK: 3 controller

    private func stepController() async {
        set("controller", .running)
        let t0 = Date()
        do {
            let v = try await ControllerClient.shared.version()
            set("controller", .pass, "\(v) · \(Self.ms(t0)) ms")
        } catch {
            let ctl = SelfCheckLogic.lastLine(Self.sessionLog(), containing: "controller") ?? ""
            set("controller", .fail, error.localizedDescription + (ctl.isEmpty ? "" : "\n" + String(ctl.prefix(200))))
        }
    }

    // MARK: 4 config integrity

    /// 配置 (the profile file) → App 构建 (NCProfileInspectorPort: what the App builds from it) → 运行时 (the
    /// nativecore-*.json files the App handed the tunnel) → 内核 (what the running core says it loaded). A count that
    /// drops between layers is a FAIL with the numbers.
    private func stepCounts() async {
        set("counts", .running)
        progress("counts", String(localized: "读取内核"))
        do {
            let px = try await ControllerClient.shared.proxies()
            proxiesSnapshot = px
            let groups = px.values.filter { $0.all != nil }
            let builtin: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]
            let ctlProxies = px.values.filter { $0.all == nil && !builtin.contains($0.name) }.count
            let rules = (try? await ControllerClient.shared.rules().count) ?? 0
            let providers = (try? await ControllerClient.shared.proxyProviders()) ?? []
            providersSnapshot = providers
            let empty = providers.filter { ($0.proxies ?? []).isEmpty }.map(\.name)
            let nodes = providers.reduce(0) { $0 + ($1.proxies?.count ?? 0) }
            let order = (try? Data(contentsOf: AppShared.homeURL.appendingPathComponent("runtime-groups.json")))
                .flatMap { try? JSONDecoder().decode([String].self, from: $0) } ?? []
            groupNames = (order + groups.map(\.name).sorted()).filter { n in n != "GLOBAL" && (px[n]?.all?.count ?? 0) > 1 }

            progress("counts", String(localized: "读取配置文件"))
            let path = AppShared.activeProfileURL?.path ?? ""
            let profile: ProfileCounts? = await BlockingWork.run { Self.profileCounts(path) }
            let rt = Self.runtimeCounts()
            let log = Self.sessionLog()
            let core = SelfCheckLogic.lastLine(log, containing: " proxies + ").flatMap(SelfCheckLogic.parseCoreStats)
            let rwCore = SelfCheckLogic.lastLine(log, containing: "native rewrite snapshot:").flatMap(SelfCheckLogic.parseRewriteSnapshot)
            let scCore = SelfCheckLogic.lastLine(log, containing: "native scripts: ").flatMap(SelfCheckLogic.parseScripts)
            let tkCore = SelfCheckLogic.lastLine(log, containing: "native tasks: ").flatMap(SelfCheckLogic.parseTasks)
            let app = appView
            let mods = EngineStore.shared.enabledModuleCounts
            let L = (cfg: String(localized: "配置"), app: String(localized: "App"), rt: String(localized: "运行时"), core: String(localized: "内核"), mod: String(localized: "模块"))

            let metrics: [SelfCheckLogic.Metric] = [
                .init(name: String(localized: "节点"), layers: [(L.cfg, profile?.proxies), (L.app, app?.proxies.count), (L.rt, rt?.proxies), (L.core, core?.proxies ?? ctlProxies)]),
                .init(name: String(localized: "节点集"), layers: [(L.cfg, profile?.proxyProviders), (L.app, app?.proxyProviders.count), (L.rt, rt?.providers), (L.core, core?.providers ?? providers.count)]),
                .init(name: String(localized: "节点集里的节点"), layers: [(L.app, app.map { $0.proxyProviders.reduce(0) { $0 + max(0, $1.count) } }), (L.core, nodes)], tolerance: 0.5),
                .init(name: String(localized: "策略组"), layers: [(L.cfg, profile?.groups), (L.app, app?.groups.count), (L.rt, rt?.groups), (L.core, core?.groups ?? groups.count)]),
                // The core drops rules it cannot parse (reported as ignored): those are not lost on the way.
                .init(name: String(localized: "规则"), layers: [(L.cfg, profile?.rules), (L.app, app?.rules.count), (L.rt, rt?.rules), (L.core, core.map { $0.rules + $0.ignoredRules } ?? rules)]),
                .init(name: String(localized: "规则集"), layers: [(L.cfg, profile?.ruleProviders), (L.app, app?.ruleProviders.count), (L.rt, rt?.ruleProviders)]),
                // Module numbers are references: the runtime merges the profile's own rewrites and drops duplicates.
                .init(name: String(localized: "重写规则"), layers: [(L.mod, mods.rewrites + mods.scripts), (L.rt, rt?.rewriteRules), (L.core, rwCore?.rules)], strictFrom: 1),
                .init(name: String(localized: "MitM 主机"), layers: [(L.mod, mods.hosts), (L.rt, rt?.mitmHosts), (L.core, rwCore?.hosts)], strictFrom: 1),
                .init(name: String(localized: "脚本"), layers: [(L.mod, mods.scripts), (L.rt, rt.map { $0.scripts + $0.tasks }), (L.core, scCore?.scripts)], strictFrom: 1),
                .init(name: String(localized: "定时任务"), layers: [(L.rt, rt?.tasks), (L.core, tkCore)]),
            ]
            let cmp = SelfCheckLogic.compare(metrics)
            var problems = cmp.lost
            if !empty.isEmpty { problems.append(String(localized: "没有节点的节点集：") + empty.joined(separator: ", ")) }
            if rt == nil { problems.append(String(localized: "运行时文件 nativecore-runtime.json 缺失或无法读取")) }
            if core == nil { problems.append(String(localized: "启动日志里没有内核加载行（native core …），内核可能没有加载配置")) }
            if let rw = rt, rw.rewriteRules > 0, rwCore == nil, rt?.rewriteOn == true {
                problems.append(String(localized: "运行时有 \(rw.rewriteRules) 条重写规则，但内核没有加载重写快照"))
            }
            if let sc = scCore, sc.unloadable > 0 { problems.append(String(localized: "内核里 \(sc.unloadable) 个脚本无法加载（见「远程资源」）")) }
            if ctlProxies + nodes == 0 { problems.append(String(localized: "内核里没有任何节点")) }
            if rules == 0 { problems.append(String(localized: "内核里没有规则")) }

            var lines: [String] = []
            if problems.isEmpty {
                lines.append(String(localized: "各层数量一致：节点 \(ctlProxies) · 节点集 \(providers.count)（\(nodes) 个节点）· 策略组 \(groups.count) · 规则 \(rules)"))
            } else {
                lines.append(String(localized: "数量对不上：") + problems[0])
                lines += problems.dropFirst()
            }
            lines.append(String(localized: "— 各层数量 —"))
            lines += cmp.table
            if let c = core, c.ignoredRules > 0 { lines.append(String(localized: "内核忽略的规则：\(c.ignoredRules) 条（不支持的类型）")) }
            if profile == nil { lines.append(String(localized: "配置文件不是可读的 YAML，跳过「配置」层")) }
            set("counts", problems.isEmpty ? .pass : .fail, lines.joined(separator: "\n"))
        } catch {
            set("counts", .fail, error.localizedDescription)
        }
    }

    struct ProfileCounts { var proxies = 0, proxyProviders = 0, groups = 0, rules = 0, ruleProviders = 0 }

    /// Counts straight from the profile file (the import's output), before any App processing.
    nonisolated static func profileCounts(_ path: String) -> ProfileCounts? {
        guard !path.isEmpty, let text = try? String(contentsOfFile: path, encoding: .utf8), let root = NCYAML.parse(text)?.object else { return nil }
        var c = ProfileCounts()
        c.proxies = root["proxies"]?.array?.count ?? 0
        c.proxyProviders = root["proxy-providers"]?.object?.count ?? 0
        c.groups = root["proxy-groups"]?.array?.count ?? 0
        c.rules = root["rules"]?.array?.count ?? 0
        c.ruleProviders = root["rule-providers"]?.object?.count ?? 0
        return c
    }

    struct RuntimeCounts {
        var proxies = 0, providers = 0, groups = 0, rules = 0, ruleProviders = 0
        var rewriteRules = 0, mitmHosts = 0, rewriteOn = false, scripts = 0, tasks = 0
    }

    /// The files the App wrote for the tunnel (same reading as UnitTests/NativeCoreE2EReplayTests.runtimeCounts).
    private static func runtimeCounts() -> RuntimeCounts? {
        guard let rt = json("nativecore-runtime.json") as? [String: Any] else { return nil }
        var c = RuntimeCounts()
        c.proxies = (rt["proxies"] as? [Any])?.count ?? 0
        c.providers = (rt["proxy-providers"] as? [String: Any])?.count ?? 0
        c.groups = ((rt["proxy-groups"] as? [[String: Any]]) ?? []).filter { ($0["name"] as? String) != "MIHOMO-PROBE" }.count
        c.rules = (rt["rules"] as? [Any])?.count ?? 0
        c.ruleProviders = (rt["rule-providers"] as? [String: Any])?.count ?? 0
        if let rw = json("nativecore-rewrite.json") as? [String: Any] {
            c.rewriteRules = (rw["rules"] as? [Any])?.count ?? 0
            c.mitmHosts = (rw["inc"] as? [Any])?.count ?? 0
            c.rewriteOn = (rw["on"] as? Bool) ?? false
        }
        if let sc = json("nativecore-scripts.json") as? [String: Any] {
            c.scripts = (sc["scripts"] as? [Any])?.count ?? 0
            c.tasks = (sc["tasks"] as? [Any])?.count ?? 0
        }
        return c
    }

    // MARK: 5 remote resources

    private func stepResources() async {
        set("resources", .running)
        var bad: [String] = []
        var info: [String] = []
        let log = Self.sessionLog()
        let home = AppShared.homeURL.path

        // Rule sets: the tunnel's own fetch failures this session, and local rule-set files that are not there.
        let ruleFails = SelfCheckLogic.ruleSetFailures(log)
        for f in ruleFails { bad.append(String(localized: "规则集 \(f.name)：\(f.reason)")) }
        let rps = appView?.ruleProviders ?? []
        for p in rps where p.vehicle == "file" {
            let path = p.path ?? ""
            let full = path.hasPrefix("/") ? path : (home as NSString).appendingPathComponent(path)
            if path.isEmpty || !FileManager.default.fileExists(atPath: full) {
                bad.append(String(localized: "规则集 \(p.name)：本地文件不存在（\((path as NSString).lastPathComponent)）"))
            }
        }
        info.append(String(localized: "规则集 \(rps.count) 个，下载失败 \(ruleFails.count) 个"))

        // Rewrite modules: enabled modules whose file never arrived — fetch once to name the reason.
        progress("resources", String(localized: "检查重写模块"))
        let mods = EngineStore.shared.config.modules.filter(\.enabled)
        let missing = mods.filter { m in
            let u = EnginePaths.moduleURL(m.id)
            return ((try? FileManager.default.attributesOfItem(atPath: u.path))?[.size] as? Int ?? 0) == 0
        }
        if !missing.isEmpty {
            let probes = Array(missing.prefix(10))
            let reasons = await withTaskGroup(of: (String, String).self, returning: [String: String].self) { tg in
                for m in probes {
                    let url = m.url, name = m.name
                    tg.addTask {
                        guard !url.isEmpty else { return (name, String(localized: "本地模块文件不存在")) }
                        return (name, await Self.probeDownload(url))
                    }
                }
                var out: [String: String] = [:]
                for await (n, r) in tg { out[n] = r }
                return out
            }
            for m in probes { bad.append(String(localized: "模块 \(m.name)（\(SelfCheckLogic.shortURL(m.url))）：未下载 — \(reasons[m.name] ?? "?")")) }
            if missing.count > probes.count { bad.append(String(localized: "另有 \(missing.count - probes.count) 个模块未下载")) }
        }
        info.append(String(localized: "启用的模块 \(mods.count) 个，未下载 \(missing.count) 个"))

        // Scripts: entries the App could not load (local file absent, download failed …).
        var scriptCount = 0
        if let sc = Self.json("nativecore-scripts.json") as? [String: Any] {
            let all = (sc["scripts"] as? [[String: Any]] ?? []) + (sc["tasks"] as? [[String: Any]] ?? [])
            scriptCount = all.count
            for s in all {
                guard let e = s["err"] as? String, !e.isEmpty else { continue }
                let src = (s["path"] as? String).map { " · " + SelfCheckLogic.shortURL($0) } ?? ""
                bad.append(String(localized: "脚本 \(s["name"] as? String ?? "?")\(src)：\(e)"))
            }
        }
        for l in SelfCheckLogic.lines(log, containing: "跳过脚本：").suffix(5) { bad.append(String(l.prefix(200))) }
        info.append(String(localized: "脚本 \(scriptCount) 个"))

        if bad.isEmpty {
            set("resources", .pass, info.joined(separator: " · "))
        } else {
            let head = String(localized: "\(bad.count) 项远程资源缺失：") + bad[0]
            set("resources", .fail, ([head] + SelfCheckLogic.capped(Array(bad.dropFirst()), 20) + [info.joined(separator: " · ")]).joined(separator: "\n"))
        }
    }

    /// One GET (8 s) to name why a resource is missing: "HTTP 404", "DNS 解析失败（NSURLErrorDomain -1003）" ….
    nonisolated private static func probeDownload(_ s: String) async -> String {
        guard let url = URL(string: s.trimmingCharacters(in: .whitespacesAndNewlines)), url.scheme?.hasPrefix("http") == true else {
            return String(localized: "地址无效")
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.timeoutIntervalForResource = 10
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: url)
        req.setValue("Surge iOS/3000", forHTTPHeaderField: "User-Agent")
        do {
            let (data, resp) = try await session.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if !(200..<300).contains(code) { return "HTTP \(code)" }
            return data.isEmpty ? String(localized: "HTTP \(code) 但内容为空") : String(localized: "现在可以下载（HTTP \(code)，\(data.count) 字节）— 到「模块」里更新一次")
        } catch {
            return SelfCheckLogic.describe(error)
        }
    }

    // MARK: 6 group delay

    private func stepDelay() async {
        set("delay", .running)
        guard let g = groupNames.first, let all = proxiesSnapshot[g]?.all, !all.isEmpty else {
            set("delay", .skip, String(localized: "没有可测的策略组")); return
        }
        let members = Array(all.prefix(20))
        let since = (try? await Self.logSeq()) ?? 0
        progress("delay", String(localized: "「\(g)」\(members.count) 个成员"))
        do {
            let r = try await ControllerClient.shared.membersDelay(members)
            let ok = r.values.filter { $0 > 0 }.count
            let slow = r.filter { $0.value > 0 }.max { $0.value < $1.value }
            try? await Task.sleep(nanoseconds: 300_000_000)
            let fails = SelfCheckLogic.delayFailures((try? await Self.logPayloads(since: since)) ?? [])
            var d = String(localized: "策略组「\(g)」：\(ok) 个可用 · \(members.count - ok) 个失败") + (all.count > members.count ? String(localized: "（测了前 \(members.count) 个）") : "")
            if let slow { d += " · " + String(localized: "最慢 \(slow.key) \(slow.value) ms") }
            if !fails.isEmpty {
                d += "\n" + String(localized: "失败原因（按节点数）：")
                d += "\n" + SelfCheckLogic.delayFailureLines(fails).joined(separator: "\n")
            } else if ok < members.count {
                d += "\n" + String(localized: "内核没有给出失败原因（没有 [delay] 行）")
            }
            // Everything probed since the VPN came up (策略 page, background url-test …), not just this group.
            let session = SelfCheckLogic.delayFailures((try? await Self.logPayloads(since: 0)) ?? [])
            if !session.isEmpty {
                d += "\n" + String(localized: "本次连接以来所有测速的失败原因：")
                d += "\n" + SelfCheckLogic.delayFailureLines(session, top: 8).joined(separator: "\n")
            }
            if ok == 0 { d = String(localized: "策略组「\(g)」没有一个成员可用") + (fails.first.map { "：\($0.stage) · \($0.reason)（\($0.nodes.count) 个）" } ?? "") + "\n" + d }
            set("delay", ok > 0 ? .pass : .fail, d)
        } catch {
            set("delay", .fail, error.localizedDescription)
        }
    }

    private static func logSeq() async throws -> UInt64 {
        let data = try await ControllerClient.shared.send("/hark/logs", query: [URLQueryItem(name: "since", value: "0")], timeout: 4)
        let o = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (o?["seq"] as? NSNumber)?.uint64Value ?? 0
    }

    /// Core log payloads since `since` (the log ring: [delay] / [TCP] / [MITM] / [REWRITE] lines).
    private static func logPayloads(since: UInt64) async throws -> [String] {
        let data = try await ControllerClient.shared.send("/hark/logs", query: [URLQueryItem(name: "since", value: String(since))], timeout: 4)
        let o = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (o?["logs"] as? [[String: Any]] ?? []).compactMap { $0["payload"] as? String }
    }

    // MARK: 7 per-node delay

    /// A sample of plain proxies and provider (订阅) nodes, tricky names first, each tested on its own route; the
    /// core's `[delay]` line gives the stage and timings, and 404 (not in the running config) is told apart from a
    /// timeout and from an error.
    private func stepNodeDelay() async {
        set("delay-nodes", .running)
        var providerOf: [String: String] = [:]
        for pv in providersSnapshot { for p in pv.proxies ?? [] where providerOf[p.name] == nil { providerOf[p.name] = pv.name } }
        let groupish: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]
        let plainAll = proxiesSnapshot.values.filter { $0.all == nil && !groupish.contains($0.name) && providerOf[$0.name] == nil }.map(\.name).sorted()
        let plain = SelfCheckLogic.sample(plainAll, max: 3)
        let prov = SelfCheckLogic.sample(providerOf.keys.sorted(), max: 5)
        let names = plain + prov
        guard !names.isEmpty else { set("delay-nodes", .skip, String(localized: "内核里没有节点")); return }
        let st = ControllerClient.testSettings
        let since = (try? await Self.logSeq()) ?? 0
        progress("delay-nodes", String(localized: "测 \(names.count) 个节点"))
        enum Outcome { case ok(Int), timeout, notFound, error(String) }
        let results = await withTaskGroup(of: (String, Outcome).self, returning: [String: Outcome].self) { tg in
            for n in names {
                let pv = providerOf[n]
                tg.addTask {
                    do {
                        let ms = try await ControllerClient.shared.proxyDelay(n, url: st.url, timeoutMs: st.timeoutMs, provider: pv, resolved: true)
                        return (n, ms > 0 ? .ok(ms) : .timeout)
                    } catch ControllerClient.APIError.http(404, let body) {
                        return (n, ControllerClient.APIError.isResourceNotFound(body) ? .notFound : .error("HTTP 404 \(ControllerClient.APIError.detail(body))"))
                    } catch {
                        return (n, .error(error.localizedDescription))
                    }
                }
            }
            var out: [String: Outcome] = [:]
            for await (n, o) in tg { out[n] = o }
            return out
        }
        try? await Task.sleep(nanoseconds: 300_000_000)
        let payloads = (try? await Self.logPayloads(since: since)) ?? []
        var lines: [String] = []
        var okCount = 0, timeouts = 0, notFound = 0, errors = 0
        for n in names {
            let kind = providerOf[n].map { String(localized: "订阅·\($0)") } ?? String(localized: "普通")
            let tail = SelfCheckLogic.delayLine(for: n, in: payloads)
            var l = "[\(kind)] \(n)："
            switch results[n] ?? .error("?") {
            case .ok(let ms): okCount += 1; l += "\(ms) ms"
            case .timeout: timeouts += 1; l += String(localized: "超时")
            case .notFound: notFound += 1; l += String(localized: "404 不在运行配置里（内核找不到这个名字）")
            case .error(let e): errors += 1; l += String(localized: "请求出错：") + e
            }
            if let tail {
                if case .ok = results[n] ?? .timeout {} else { l += "\n    " + String(tail.prefix(220)) }
            } else if case .ok = results[n] ?? .timeout {} else {
                l += String(localized: "（内核没有写 [delay] 行：请求可能没到探测）")
            }
            lines.append(l)
        }
        var head = String(localized: "\(okCount)/\(names.count) 可用 · 超时 \(timeouts) · 404 \(notFound) · 出错 \(errors)（预算 \(st.timeoutMs) ms）")
        let fails = SelfCheckLogic.delayFailures(payloads.filter { p in names.contains { p.hasPrefix("[delay] \($0): ") } })
        if let top = fails.first { head += " · " + String(localized: "最多：\(top.stage) · \(top.reason)（\(top.nodes.count) 个）") }
        if okCount == 0 { head = String(localized: "抽样节点没有一个可用：") + head }
        else if notFound > 0 { head = String(localized: "有节点在内核里找不到（名字编码或配置不一致）：") + head }
        set("delay-nodes", okCount > 0 && notFound == 0 && errors == 0 ? .pass : .fail, ([head] + lines).joined(separator: "\n"))
    }

    // MARK: 8 exit IP (Home)

    /// Home's 出口 line: the same endpoints in the same order, each on its own (6 s) so one dead API cannot hide the rest.
    private func stepExitIP() async {
        set("exitip", .running)
        if IPInfoFetcher.disabled { set("exitip", .skip, String(localized: "出口查询已关闭（geo_location_checker = disabled）")); return }
        let eps = IPInfoFetcher.orderedEndpoints
        progress("exitip", String(localized: "查询 \(eps.count) 个接口"))
        let results = await withTaskGroup(of: (Int, String, Bool).self, returning: [(Int, String, Bool)].self) { tg in
            for (i, ep) in eps.enumerated() {
                tg.addTask { let (l, ok) = await Self.lookup(ep); return (i, l, ok) }
            }
            var out: [(Int, String, Bool)] = []
            for await r in tg { out.append(r) }
            return out.sorted { $0.0 < $1.0 }
        }
        var lines = results.map(\.1)
        let okCount = results.filter(\.2).count
        // Home's own path (IPInfoModel.refresh): the same call under the same 15 s cap.
        progress("exitip", String(localized: "首页出口信息（15 秒）"))
        let tHome = Date()
        let useScript = GeoChecker.usesScript
        let home = await IPInfoModel.withDeadline(15) {
            await (useScript ? GeoChecker.fetchWithScript() : IPInfoFetcher.fetch())
        }
        let homeMs = Self.ms(tHome)
        let homeLine = home.map { String(localized: "首页出口信息：\($0.ip) \($0.countryCode ?? "")（\($0.source ?? "-")）· \(homeMs) ms") }
            ?? String(localized: "首页出口信息 15 秒内没有结果（首页会显示「查询失败」）· \(homeMs) ms")
        lines.insert(homeLine, at: 0)
        if GeoChecker.usesScript {
            progress("exitip", String(localized: "自定义查询脚本"))
            let t0 = Date()
            let infoR: IPInfo?? = await Self.deadline(12) { () async -> IPInfo? in await GeoChecker.fetchCustom(timeout: 8) }
            let info: IPInfo? = infoR ?? nil
            // fix/nc-diag-439 (D): say why (build 439: 13 ms = ATS refused the http:// custom URL).
            let why = GeoChecker.lastError
            lines.append(String(localized: "自定义接口 + 脚本（首页用这个）：") + (info.map { "\($0.ip) · \(Self.ms(t0)) ms" } ?? String(localized: "没有结果（\(Self.ms(t0)) ms）") + (why.isEmpty ? "" : "：" + why)))
        }
        let firstOK = results.first { $0.2 }.map { eps[$0.0].name }
        let head: String
        if okCount == 0 {
            head = String(localized: "\(eps.count) 个出口查询接口全部失败：首页会一直「查询失败」")
        } else {
            head = String(localized: "\(okCount)/\(eps.count) 个接口可用，首页会用 \(firstOK ?? "-")")
        }
        if home == nil {
            set("exitip", .fail, ([String(localized: "首页出口信息 15 秒内没有结果") + (okCount > 0 ? String(localized: "（单独查询有 \(okCount) 个接口可用：首页按顺序查询，被前面慢的接口拖住）") : String(localized: "：所有接口都失败"))] + [head] + lines).joined(separator: "\n"))
            return
        }
        set("exitip", okCount > 0 ? .pass : .fail, ([head] + lines).joined(separator: "\n"))
    }

    nonisolated private static func lookup(_ ep: IPInfoFetcher.Endpoint) async -> (String, Bool) {
        guard let url = URL(string: ep.url) else { return ("\(ep.name)：" + String(localized: "地址无效"), false) }
        let session = URLSession(configuration: IPInfoFetcher.sessionConfiguration(timeout: 6))
        defer { session.invalidateAndCancel() }
        var req = URLRequest(url: url)
        req.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let t0 = Date()
        do {
            let (data, resp) = try await session.data(for: req)
            let ms = Self.ms(t0)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            guard (200..<300).contains(code) else { return ("\(ep.name)：HTTP \(code) · \(ms) ms", false) }
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return ("\(ep.name)：HTTP \(code) " + String(localized: "但不是 JSON") + " · \(ms) ms", false) }
            guard let info = ep.parse(obj) else { return ("\(ep.name)：HTTP \(code) " + String(localized: "但没有 IP 字段") + " · \(ms) ms", false) }
            return ("\(ep.name)：\(info.ip) \(info.countryCode ?? "") · \(ms) ms", true)
        } catch {
            return ("\(ep.name)：\(SelfCheckLogic.describe(error)) · \(Self.ms(t0)) ms", false)
        }
    }

    // MARK: 9 fetch

    private static func mitmHost() -> String? {
        guard let d = try? Data(contentsOf: AppShared.homeURL.appendingPathComponent("nativecore-rewrite.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return nil }
        let hosts = (o["inc"] as? [Any] ?? []).compactMap { ($0 as? String) ?? (($0 as? [String: Any])?["pat"] as? String) ?? (($0 as? [String: Any])?["host"] as? String) }
        return hosts.first { !$0.contains("*") && !$0.hasPrefix("-") && $0.contains(".") && !$0.contains(":") }
    }

    private var planeBefore: [String: Int]?
    private var planeAfter: [String: Int]?
    private var fetchRequests = 0

    /// The data plane's counters, fresh: the extension writes them to the startup log on .dumpDiagnostics.
    private func planeCounters() async -> [String: Int]? {
        guard let vpn, vpn.isConnected else { return nil }
        _ = await vpn.send(.dumpDiagnostics, timeout: 6)
        let c = SelfCheckLogic.lastLine(Self.sessionLog(), containing: "native: packets").map(SelfCheckLogic.parsePlaneCounters) ?? [:]
        return c.isEmpty ? nil : c
    }

    private func stepFetch() async {
        set("fetch", .running)
        progress("fetch", String(localized: "读取数据面计数"))
        planeBefore = await planeCounters()
        var targets: [(String, String)] = [
            (String(localized: "国内直连"), "https://www.baidu.com/"),
            (String(localized: "代理"), "https://www.gstatic.com/generate_204"),
        ]
        if let h = Self.mitmHost() { targets.append(("MitM", "https://\(h)/")) }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 10
        cfg.timeoutIntervalForResource = 12
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        let since = (try? await Self.logSeq()) ?? 0
        var lines: [String] = []
        var failed = 0
        fetchRequests = 0
        for (label, u) in targets {
            guard let url = URL(string: u) else { continue }
            progress("fetch", "\(label) \(url.host ?? "")")
            let t0 = Date()
            fetchRequests += 1
            do {
                let (body, resp) = try await session.data(from: url)
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                lines.append("\(label) \(url.host ?? ""): HTTP \(code) · \(Self.ms(t0)) ms" + SelfCheckLogic.mitmErrorNote(status: code, body: body))
            } catch {
                // A pinned / untrusted MitM host failing is reported by the MitM step; it is not a tunnel failure.
                if label != "MitM" { failed += 1 }
                lines.append("\(label) \(url.host ?? ""): \(SelfCheckLogic.describe(error)) · \(Self.ms(t0)) ms")
            }
        }
        if let routes = try? await Self.routeLines(since: since, hosts: targets.compactMap { URL(string: $0.1)?.host }) {
            lines += routes
        }
        progress("fetch", String(localized: "读取数据面计数"))
        planeAfter = await planeCounters()
        let ov = CoreOverrides.load()
        let tun = !(ov.isMixed || ov.isProxyOnly)
        var cause: String?
        if let b = planeBefore, let a = planeAfter {
            func d(_ k: String) -> Int { (a[k] ?? 0) - (b[k] ?? 0) }
            lines.append(String(localized: "数据面计数（前后差）：packets in +\(d("packets in")) · tcp accepted +\(d("tcp accepted")) · dns queries +\(d("dns queries")) / replies +\(d("dns replies")) / failed +\(d("dns failed")) · relay ok +\(d("relay ok")) · direct +\(d("direct")) · failed +\(d("relay failed"))"))
            cause = SelfCheckLogic.fetchDiagnosis(before: b, after: a, tun: tun)
        } else {
            lines.append(String(localized: "读不到数据面计数（扩展没有回应 dumpDiagnostics）"))
        }
        if failed > 0 {
            lines.insert(cause ?? String(localized: "\(failed) 个网址经隧道访问失败（数据面计数正常：问题在出站节点或目标）"), at: 0)
        }
        set("fetch", failed == 0 ? .pass : .fail, lines.joined(separator: "\n"))
    }

    /// The data plane's `[TCP] host:443 rule … → policy` lines for these hosts (which rule / node each took).
    private static func routeLines(since: UInt64, hosts: [String]) async throws -> [String] {
        let all = try await logPayloads(since: since)
        return hosts.compactMap { h in all.last { $0.hasPrefix("[TCP] \(h):") || $0.hasPrefix("[MITM] \(h)") } }
            .map { String($0.prefix(160)) }
    }

    // MARK: 10 data plane

    /// Did the fetch step's requests reach the tunnel's TCP stack ("tcp accepted 0" on build 409), did DNS answer,
    /// which DNS mode is really in effect, IPv6.
    private func stepDataPlane() async {
        set("dataplane", .running)
        let ov = CoreOverrides.load()
        let log = Self.sessionLog()
        progress("dataplane", String(localized: "解析测试域名"))
        let ipR: String?? = await Self.deadline(5) { () async -> String? in await BlockingWork.run { Self.resolve("www.gstatic.com") } }
        let ip: String? = ipR ?? nil
        let fake = ip.map { $0.hasPrefix("198.18.") || $0.hasPrefix("198.19.") } ?? false
        var lines: [String] = []
        var problems: [String] = []
        let modeLine = SelfCheckLogic.lines(log, containing: "mode ").last { $0.hasPrefix("mode ") }
        let mixOrProxy = ov.isMixed || ov.isProxyOnly
        lines.append(String(localized: "隧道模式 \(ov.tunnelMode) · DNS 设置 \(ov.dnsMode) · 实测 www.gstatic.com → \(ip ?? "-")（\(fake ? "Fake-IP" : String(localized: "真实 IP"))）"))
        if ov.dnsMode == "fake-ip", !fake, !mixOrProxy { problems.append(String(localized: "设置是 Fake-IP，但系统解析得到真实 IP：DNS 没有被隧道接管")) }
        if let w = SelfCheckLogic.lastLine(log, containing: "WARNING: dns redir-host") { problems.append(String(w.prefix(220))) }
        let v6 = SelfCheckLogic.lastLine(log, containing: "ipv6 mode ") ?? "ipv6 mode \(ov.ipv6Mode)"
        lines.append("IPv6：" + String(v6.prefix(120)))
        if let modeLine { lines.append(String(modeLine.prefix(200))) }

        if let b = planeBefore, let a = planeAfter {
            func d(_ k: String) -> Int { (a[k] ?? 0) - (b[k] ?? 0) }
            lines.append(String(localized: "访问 \(fetchRequests) 个网址前后：packets in +\(d("packets in")) · tcp accepted +\(d("tcp accepted")) · udp opened +\(d("udp opened")) · dns queries +\(d("dns queries")) / replies +\(d("dns replies")) · relay ok +\(d("relay ok")) · direct +\(d("direct")) · failed +\(d("relay failed")) · rejected +\(d("rejected"))"))
            lines.append(String(localized: "累计：tcp accepted \(a["tcp accepted"] ?? 0) · sessions \(a["sessions"] ?? 0) · dns \(a["dns queries"] ?? 0)/\(a["dns replies"] ?? 0) · dns failed \(a["dns failed"] ?? 0) · udp dropped \(a["udp dropped"] ?? 0) · mitm decrypted \(a["mitm decrypted"] ?? 0) / fallback \(a["mitm fallback"] ?? 0)"))
            if d("tcp accepted") == 0 && fetchRequests > 0 {
                if mixOrProxy {
                    lines.append(String(localized: "tcp accepted 没有增加：\(ov.tunnelMode) 模式下 App 请求走系统代理，不经过 TUN（正常）"))
                } else {
                    problems.append(String(localized: "访问 \(fetchRequests) 个网址后 tcp accepted 仍为 +0：App 的流量没有进入隧道的 TCP 栈（packets in +\(d("packets in"))）"))
                }
            }
            if d("dns queries") > 0 && d("dns replies") == 0 { problems.append(String(localized: "隧道收到 \(d("dns queries")) 个 DNS 查询，一个都没有应答")) }
            if d("relay failed") > 0 && d("relay ok") == 0 && d("direct") == 0 { problems.append(String(localized: "这段时间的连接全部转发失败（relay failed +\(d("relay failed"))）")) }
        } else {
            problems.append(String(localized: "读不到数据面计数（扩展没有回应 dumpDiagnostics，或没有写 native: 行）"))
        }
        if problems.isEmpty {
            set("dataplane", .pass, lines.joined(separator: "\n"))
        } else {
            set("dataplane", .fail, (problems + lines).joined(separator: "\n"))
        }
    }

    // MARK: 11 MitM + CA

    /// "EC P-256" / "RSA 2048" / nil (no CA). Reads the CA certificate only (the key stays where it is).
    nonisolated private static func caType(home: String) -> String? {
        guard let der = NCCAManager.caCertDER(home: home), let cert = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(cert), let attrs = SecKeyCopyAttributes(key) as? [String: Any] else { return nil }
        let type = attrs[kSecAttrKeyType as String] as? String ?? ""
        let bits = (attrs[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue ?? 0
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) { return bits > 0 ? "EC P-\(bits)" : "EC" }
        if type == (kSecAttrKeyTypeRSA as String) { return "RSA \(bits)" }
        return type.isEmpty ? "?" : type
    }

    /// selfcheck-2 (after fix/nc-rsa-ca): the active CA's own signature (old Swift-generated EC CAs carry a bad one,
    /// which iOS rejects even when the profile is trusted) and a freshly issued leaf evaluated with SecTrust and the
    /// CA as the only anchor. nil = fine; otherwise why.
    nonisolated private static func caSignatureProblem(home: String) -> String? {
        guard let der = NCCAManager.caCertDER(home: home) else { return nil }
        let selfSig = SelfCheckLogic.verifySelfSignature(der)
        if selfSig.ok == false { return String(localized: "CA 自签名校验失败（\(selfSig.why)）") }
        guard let chain = NCCAManager.trustChain(home: home),
              let leaf = SecCertificateCreateWithData(nil, chain.leafDER as CFData),
              let ca = SecCertificateCreateWithData(nil, chain.caDER as CFData) else {
            return String(localized: "无法用这个 CA 签发证书")
        }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates([leaf] as CFArray, SecPolicyCreateSSL(true, chain.hostname as CFString), &trust) == errSecSuccess,
              let trust else { return String(localized: "无法建立证书链") }
        SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var err: CFError?
        if !SecTrustEvaluateWithError(trust, &err) {
            let why = err.map { ($0 as Error).localizedDescription } ?? "?"
            return String(localized: "新签发的证书在只信任此 CA 时验证失败（\(String(why.prefix(160))))")
        }
        return nil
    }

    private func stepMitM() async {
        set("mitm", .running)
        let home = AppShared.homeURL.path
        progress("mitm", String(localized: "检查证书"))
        let (trusted, type, loads, sigProblem) = await BlockingWork.run { () -> (Bool, String?, Bool, String?) in
            let t = Self.caType(home: home)
            let loads = t == nil ? false : NCCAManager.loadCA(home: home) != nil
            return (NCCAManager.checkTrust(home: home), t, loads, loads ? Self.caSignatureProblem(home: home) : nil)
        }
        let log = Self.sessionLog()
        let probe = log.split(separator: "\n").last { $0.contains("MITM self-probe") }.map { SelfCheckLogic.stripStamp(String($0)) }
        let state = SelfCheckLogic.lastLine(log, containing: "MITM: ")
        var lines: [String] = []
        var problems: [String] = []
        if let type {
            lines.append(String(localized: "CA：\(type)") + (loads ? "" : String(localized: "（私钥无法加载）")))
            if !loads { problems.append(String(localized: "CA 证书在，但私钥无法加载（\(type)）：MitM 不能签发证书")) }
            if let sigProblem {
                problems.insert(String(localized: "CA 证书签名无效，请重新生成 CA") + "（\(sigProblem)）", at: 0)
            } else if loads {
                lines.append(String(localized: "CA 自签名与新签发证书校验：通过"))
            }
        } else {
            problems.append(String(localized: "没有 CA 证书：在「MitM」里生成或导入"))
        }
        lines.append(String(localized: "证书受 iOS 信任：") + (trusted ? String(localized: "是") : String(localized: "否（设置 → 通用 → 关于本机 → 证书信任设置）")))
        if let state { lines.append(String(state.prefix(200))) }
        lines.append(probe ?? String(localized: "扩展还没有写 MitM 自检行（连接后约 15 秒才有）"))
        let probeFailed = probe?.contains("FAILED") == true
        if probeFailed { problems.append(String(localized: "隧道内 MitM 自检失败：") + (probe ?? "")) }
        if state?.contains("inactive") == true { problems.append(String(localized: "隧道里 MitM 没有启用")) }
        if !trusted { problems.append(String(localized: "CA 没有被 iOS 完全信任：App 会拒绝 MitM 的证书")) }
        let hasHosts = Self.mitmHost() != nil || ((Self.json("nativecore-rewrite.json") as? [String: Any])?["inc"] as? [Any])?.isEmpty == false
        if !hasHosts {
            set("mitm", .skip, (lines + [String(localized: "当前配置没有 MitM 主机")]).joined(separator: "\n"))
        } else if problems.isEmpty {
            set("mitm", .pass, lines.joined(separator: "\n"))
        } else {
            set("mitm", .fail, (problems + lines).joined(separator: "\n"))
        }
    }

    // MARK: 12 rewrite fires

    private func rewriteSnapshot() -> RWSnapshot? {
        guard let t = try? String(contentsOf: AppShared.homeURL.appendingPathComponent("nativecore-rewrite.json"), encoding: .utf8) else { return nil }
        return RWSnapshot.decode(t)
    }

    /// Fires one of the user's own reject rules on a MitM host (answered locally by the rewrite engine — nothing
    /// reaches the real server) and looks for its `[REWRITE]` line in the core log.
    private func stepRewrite() async {
        set("rewrite", .running)
        guard let snap = rewriteSnapshot() else { set("rewrite", .skip, String(localized: "没有重写快照（nativecore-rewrite.json）")); return }
        guard snap.on else { set("rewrite", .skip, String(localized: "重写与 MitM 未开启")); return }
        let hosts = (snap.inc ?? []).map(\.pat)
        let rejects: Set<String> = ["reject", "reject-200", "reject-img", "reject-dict", "reject-array"]
        var pick: (RWSnapRule, URL)?
        for r in snap.rules ?? [] where r.kind == "url" && rejects.contains(r.action ?? "") {
            guard let p = r.re?.p, let u = SelfCheckLogic.probeURL(fromPattern: p), let h = u.host,
                  hosts.contains(where: { SelfCheckLogic.hostMatches($0, h) }) else { continue }
            pick = (r, u); break
        }
        guard let (rule, url) = pick else {
            set("rewrite", .skip, String(localized: "配置里没有可安全触发的规则（需要 MitM 主机上的 reject 类 URL 重写）"))
            return
        }
        let since = (try? await Self.logSeq()) ?? 0
        progress("rewrite", SelfCheckLogic.shortURL(url.absoluteString))
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.timeoutIntervalForResource = 10
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let t0 = Date()
        var result: String
        do {
            let (body, resp) = try await session.data(from: url)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            result = "HTTP \(code) · \(Self.ms(t0)) ms" + SelfCheckLogic.mitmErrorNote(status: code, body: body)
        } catch {
            result = SelfCheckLogic.describe(error) + " · \(Self.ms(t0)) ms"
        }
        try? await Task.sleep(nanoseconds: 500_000_000)
        let payloads = (try? await Self.logPayloads(since: since)) ?? []
        let host = url.host ?? ""
        let hit = payloads.last { $0.hasPrefix("[REWRITE]") && $0.contains(host) }
        let mitmLine = payloads.last { ($0.hasPrefix("[MITM]") || $0.hasPrefix("[TCP]")) && $0.contains(host) }
        let target = String(localized: "规则 #\(rule.i) \(rule.action ?? "") → \(SelfCheckLogic.shortURL(url.absoluteString))")
        if let hit {
            set("rewrite", .pass, String(localized: "已命中：") + target + "（\(result)）\n" + String(hit.prefix(220)))
        } else {
            var d = String(localized: "规则没有命中（没有 [REWRITE] 日志）：") + target + "（\(result)）"
            if let mitmLine { d += "\n" + String(mitmLine.prefix(220)) } else { d += "\n" + String(localized: "内核日志里也没有这个主机的 [MITM] / [TCP] 行：请求没有进入 MitM") }
            set("rewrite", .fail, d)
        }
    }

    // MARK: 13 plain-HTTP rewrite

    /// fix/nc-e2e-gaps: TUN port-80 HTTP to a MitM host or to the literal host of an http:// rule now goes through the
    /// rewrite engine (MitmPlainFront in the tunnel); this step reports the configuration it applies to.
    private func stepRewriteHTTP() {
        set("rewrite-http", .running)
        guard let snap = rewriteSnapshot(), snap.on else { set("rewrite-http", .skip, String(localized: "重写与 MitM 未开启")); return }
        let httpOnly = (snap.rules ?? []).filter { r in r.re.map { SelfCheckLogic.isPlainHTTPOnly($0.p) } ?? false }
        var d = String(localized: "TUN 下 80 端口的明文 HTTP 请求：MitM 主机及 http:// 规则里写明的主机交给重写引擎处理（无需解密）")
        if !httpOnly.isEmpty { d += "\n" + String(localized: "当前配置有 \(httpOnly.count) 条只匹配 http:// 的规则") }
        set("rewrite-http", .pass, d)
    }

    // MARK: 14 script

    private func stepScript() async {
        set("script", .running)
        do {
            let data = try await ControllerClient.shared.send("/mitm/tasks")
            let tasks = (try JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
            guard let t = tasks.first(where: { ($0["enabled"] as? Bool) != false }) ?? tasks.first, let id = t["id"] as? String else {
                set("script", .skip, String(localized: "当前配置没有脚本任务")); return
            }
            let name = (t["script"] as? [String: Any])?["name"] as? String ?? id
            progress("script", String(localized: "运行「\(name)」"))
            let before = try await Self.scriptLogCount()
            let r = try await ControllerClient.shared.send("/mitm/tasks/\(ControllerClient.enc(id))/run", method: "POST", body: [String: Any](), timeout: 40)
            let obj = (try? JSONSerialization.jsonObject(with: r)) as? [String: Any] ?? [:]
            try? await Task.sleep(nanoseconds: 800_000_000)
            let after = try await Self.scriptLogCount()
            let ok = (obj["ok"] as? Bool) == true
            var d = String(localized: "任务「\(name)」：") + (ok ? String(localized: "运行成功") : String(localized: "运行失败 \(obj["error"] as? String ?? "")"))
            d += " · " + String(localized: "脚本日志 \(before) → \(after) 行")
            set("script", ok && after > before ? .pass : .fail, d)
        } catch {
            set("script", .fail, error.localizedDescription)
        }
    }

    private static func scriptLogCount() async throws -> Int {
        let data = try await ControllerClient.shared.send("/mitm/logs", timeout: 4)
        return ((try? JSONSerialization.jsonObject(with: data)) as? [Any])?.count ?? 0
    }

    // MARK: 15 restart

    /// Resolve a name while connected (fake-ip mode → 198.18.x), reconnect, then: the same fake IP must still route
    /// (persisted map), and a fake IP nobody was given must be refused at once (RST), not accepted and closed.
    private func stepRestart(_ vpn: VPNManager) async {
        set("restart", .running)
        let host = "www.gstatic.com"
        let ipR: String?? = await Self.deadline(5) { () async -> String? in await BlockingWork.run { Self.resolve(host) } }
        let ip: String? = ipR ?? nil
        guard let ip, ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") else {
            set("restart", .skip, String(localized: "当前不是 Fake-IP 模式（\(host) → \(ip ?? "-")）")); return
        }
        progress("restart", String(localized: "断开"))
        await vpn.disconnectAndWait()
        progress("restart", String(localized: "重新连接"))
        let t0 = Date()
        guard await vpn.connectAndWait(timeout: 30) else {
            set("restart", .fail, String(localized: "重连失败：") + (vpn.lastError ?? "-")); return
        }
        let reconnectMs = Self.ms(t0)
        progress("restart", String(localized: "探测旧映射"))
        let mapped = await Self.httpProbe(ip: ip, host: host)
        let stale = await Self.httpProbe(ip: "198.18.251.77", host: host)
        let mappedOK = mapped.hasPrefix("HTTP/")
        let staleOK = stale.hasPrefix("refused") || stale.hasPrefix("reset")
        var d = String(localized: "重连 \(reconnectMs) ms") + "\n"
            + String(localized: "旧映射 \(ip)：") + mapped + "\n"
            + String(localized: "无映射的 Fake-IP：") + stale
        if !mappedOK { d = String(localized: "重连后旧 Fake-IP 映射不能用（应用会连不上直到重新解析）") + "\n" + d }
        else if !staleOK { d = String(localized: "无映射的 Fake-IP 没有被立即拒绝（应用会卡住而不是重试）") + "\n" + d }
        set("restart", mappedOK && staleOK ? .pass : .fail, d)
    }

    nonisolated private static func resolve(_ host: String) -> String? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard let sa = first.pointee.ai_addr else { return nil }
        let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var a = sin.sin_addr
        inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }

    /// One HTTP HEAD to ip:80 with Host: host. Returns the status line, "refused …" / "reset …" / "closed …" / "timeout".
    nonisolated private static func httpProbe(ip: String, host: String) async -> String {
        await withCheckedContinuation { (c: CheckedContinuation<String, Never>) in
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: 80, using: .tcp)
            let q = DispatchQueue(label: "selfcheck.probe")
            let lock = NSLock()
            var done = false
            func finish(_ s: String) {
                lock.lock(); let first = !done; done = true; lock.unlock()
                guard first else { return }
                conn.cancel()
                c.resume(returning: s)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: Data("HEAD /generate_204 HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8), completion: .contentProcessed { _ in })
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, eof, err in
                        if let data, !data.isEmpty {
                            finish(String(decoding: data.prefix(40), as: UTF8.self).components(separatedBy: "\r\n").first ?? "HTTP/?")
                        } else if let err {
                            finish("reset (\(err))")
                        } else if eof {
                            finish("closed (FIN)")
                        }
                    }
                case .failed(let e), .waiting(let e):
                    if case .posix(let code) = e, code == .ECONNRESET { finish("reset (\(e))") } else { finish("refused (\(e))") }
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + 8) { finish("timeout") }
        }
    }

    // MARK: 16 memory

    private var memory: [SelfCheckLogic.MemorySample] = []

    private func sampleMemory(_ label: String) async {
        guard let vpn, vpn.isConnected else { return }
        if let s = SelfCheckLogic.memorySample(await vpn.send(.memoryStats, timeout: 4), label: label) { memory.append(s) }
    }

    private func stepMemory() async {
        set("memory", .running)
        await sampleMemory(String(localized: "结束"))
        guard !memory.isEmpty else { set("memory", .skip, String(localized: "扩展没有返回内存数据")); return }
        let v = SelfCheckLogic.memoryVerdict(memory)
        var d = v.detail
        if let p = SelfCheckLogic.lastLine(Self.sessionLog(), containing: "memory pressure") { d += "\n" + String(p.prefix(200)) }
        set("memory", v.ok ? .pass : .fail, d)
    }
}
