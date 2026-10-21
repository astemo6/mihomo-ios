import Foundation
import Combine
import UIKit
import SwiftUI

/// Live stats for the Home screen (traffic / memory websockets + connections polling).
@MainActor
final class DashboardModel: ObservableObject {
    static let shared = DashboardModel()

    @Published var up: Int64 = 0
    @Published var down: Int64 = 0
    @Published var upHistory: [Int64] = Array(repeating: 0, count: 60)
    @Published var downHistory: [Int64] = Array(repeating: 0, count: 60)
    @Published var uploadTotal: Int64 = 0
    @Published var downloadTotal: Int64 = 0
    @Published var memory: Int64 = 0
    @Published var connectionCount: Int = 0
    @Published var coreVersion: String = ""
    @Published var mode: String = CoreOverrides.load().mode
    @Published var selectedNode: String = "—"
    /// Home policy cards (v0.7): the chosen groups (feat/home-groups) with the resolved chain.
    @Published var homeGroups: [HomeGroup] = []
    /// feat/home-groups: every non-hidden top-level group in GLOBAL order (candidates for Home).
    @Published var availableGroups: [String] = []

    struct HomeGroup: Identifiable, Equatable {
        var id: String { name }
        let name: String
        let icon: String?
        let kind: String
        /// Group → … → leaf node, following `now`.
        let chain: [String]
        let delay: Int?
    }

    private var tasks: [Task<Void, Never>] = []

    /// feat/traffic-scope: 首页流量统计 (全部流量 / 仅代理流量). Changing it switches Home's numbers at once:
    /// both scopes are sampled all the time, so the chart keeps its history in either.
    @Published var scope: TrafficScope = TrafficScope.current {
        didSet {
            guard scope != oldValue else { return }
            TrafficScope.current = scope
            publishTraffic(animated: false)
        }
    }
    private var allSeries = SpeedSeries()
    private var proxySeries = SpeedSeries()
    private var lastTraffic: AppTraffic?
    /// fix/bg-chart: polling (and the /memory stream) pause while the app is not active.
    private var active = UIApplication.shared.applicationState != .background
    private var running = false
    /// fix/nav-jank: Home's speed, totals, memory and connection count are published only while Home is on
    /// screen. Sampling goes on (the series, the Live Activity and the poll interval keep their data), but other
    /// tabs no longer get several SwiftUI updates a second for numbers nobody sees; Home catches up on appear.
    private var homeVisible = true
    private var lastMemory: Int64 = 0
    private var lastConnectionCount = 0

    func setHomeVisible(_ visible: Bool) {
        HomeAnalysisModel.shared.setHomeVisible(visible) // feat/home-analysis: its 2 s snapshot runs only on Home
        guard visible != homeVisible else { return }
        homeVisible = visible
        guard visible else { return }
        publishTraffic(animated: false)
        if memory != lastMemory { memory = lastMemory }
        if connectionCount != lastConnectionCount { connectionCount = lastConnectionCount }
    }

    func start() {
        stop()
        running = true
        guard active else { return } // resumes in setActive(true)
        startTasks()
    }

    private func startTasks() {
        let c = ControllerClient.shared
        // feat/traffic-scope + fix/bg-chart: speed and totals come from one 1 s poll of GET /app/traffic
        // (both scopes) instead of the /traffic websocket. A websocket queues frames while the app is
        // suspended and replays them in a burst on return, which made the chart race forward. A poll
        // has nothing queued; SpeedSeries drops late answers and restarts after a gap.
        tasks.append(Task { [weak self] in
            while !Task.isCancelled {
                let asked = Date()
                if let t = try? await c.get(AppTraffic.self, "/app/traffic", timeout: 3) {
                    guard !Task.isCancelled, let self else { return }
                    self.ingest(t, requestedAt: asked, receivedAt: Date())
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        })
        tasks.append(Task { [weak self] in
            for await m in c.stream("/memory", as: MemorySample.self) {
                guard !Task.isCancelled, let self else { break }
                self.lastMemory = m.inuse
                if self.homeVisible && self.memory != m.inuse { self.memory = m.inuse }
            }
        })
        tasks.append(Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                tick += 1
                // v0.12: 运行模式按网络切换 can change the mode inside the extension; re-read it every ~10 s.
                if tick % 5 == 0, let cfg = try? await c.configs(), let m = (cfg["mode"] as? String)?.lowercased(), self?.mode != m {
                    self?.mode = m
                }
                if let r = try? await c.connections(), let self {
                    let n = r.connections?.count ?? 0
                    self.lastConnectionCount = n
                    if self.homeVisible && self.connectionCount != n { self.connectionCount = n }
                    ConnectionAnalytics.shared.ingest(r.connections ?? [])
                }
                if self?.coreVersion.isEmpty == true, let v = try? await c.version() { self?.coreVersion = v }
                await self?.refreshSelectedNode()
                // Adaptive interval: a full /connections pull gets heavy with many connections,
                // so back off while the count is high and return to 2 s once it drops again.
                let count = self?.lastConnectionCount ?? 0
                let pollInterval: UInt64 = count > 2000 ? 10_000_000_000 : count > 800 ? 5_000_000_000 : 2_000_000_000
                try? await Task.sleep(nanoseconds: pollInterval)
            }
        })
        Task { if let cfg = try? await c.configs(), let m = cfg["mode"] as? String { self.mode = m.lowercased() } }
    }

    /// One /app/traffic answer: both series get the sample; Home shows the chosen scope.
    private func ingest(_ t: AppTraffic, requestedAt: Date, receivedAt: Date) {
        let a = allSeries.append(up: t.up, down: t.down, requestedAt: requestedAt, receivedAt: receivedAt)
        let p = proxySeries.append(up: t.proxyUp, down: t.proxyDown, requestedAt: requestedAt, receivedAt: receivedAt)
        if a == .dropped && p == .dropped { return }
        lastTraffic = t
        if homeVisible { publishTraffic(animated: a == .appended) }
        let sp = t.speed(scope), tot = t.totals(scope)
        LiveActivityController.shared.traffic(up: sp.up, down: sp.down, totalUp: tot.up, totalDown: tot.down, node: selectedNode)
    }

    private func publishTraffic(animated: Bool) {
        let series = scope == .proxy ? proxySeries : allSeries
        let apply = {
            if let t = self.lastTraffic {
                let sp = t.speed(self.scope), tot = t.totals(self.scope)
                self.up = sp.up; self.down = sp.down
                self.uploadTotal = tot.up; self.downloadTotal = tot.down
            }
            self.upHistory = series.up; self.downHistory = series.down
        }
        if animated {
            apply()
        } else {
            // A restarted series or a scope switch is drawn in place, never animated from the old shape.
            var tr = Transaction(animation: nil)
            tr.disablesAnimations = true
            withTransaction(tr, apply)
        }
    }

    /// fix/bg-chart: RootView forwards scenePhase. Not active → every poll / stream stops (nothing queues);
    /// active again → polling resumes and the chart restarts from the current sample (SpeedSeries gap rule).
    func setActive(_ isActive: Bool) {
        HomeAnalysisModel.shared.setActive(isActive)
        guard isActive != active else { return }
        active = isActive
        if isActive {
            if running && tasks.isEmpty { startTasks() }
        } else {
            tasks.forEach { $0.cancel() }
            tasks.removeAll()
        }
    }

    func stop() {
        running = false
        tasks.forEach { $0.cancel() }
        tasks.removeAll()
        up = 0; down = 0; connectionCount = 0; memory = 0; lastMemory = 0; lastConnectionCount = 0
        // Totals stay on screen after a disconnect (as before); speeds are 0 in either scope.
        if var t = lastTraffic { t.up = 0; t.down = 0; t.proxyUp = 0; t.proxyDown = 0; lastTraffic = t }
        homeGroups = []
        availableGroups = []
        if !VPNManager.shared.isConnected { ConnectionAnalytics.shared.reset() }
    }

    /// Follows the first group from GLOBAL's order (usually the main "节点选择") down to a leaf node.
    func refreshSelectedNode() async {
        guard let all = try? await ControllerClient.shared.proxies() else { return }
        let order = LiveGroupOrder.names(all)
        let firstGroup = order.first { all[$0]?.isGroup == true }
        var name = mode == "global" ? "GLOBAL" : (firstGroup ?? "GLOBAL")
        var hops = 0
        while let p = all[name], let now = p.now, !now.isEmpty, hops < 8 {
            name = now; hops += 1
        }
        if selectedNode != name { selectedNode = name } // fix/nav-jank: was republished every 2 s
        WidgetSnapshot.update(node: name, policy: firstGroup)

        // Home policy cards (feat/home-groups): the user's chosen groups for this profile, in their order;
        // default = the first four top-level groups in GLOBAL order (hidden ones skipped).
        let available = order.filter { all[$0]?.isGroup == true && all[$0]?.hidden != true && $0 != "GLOBAL" }
        if available != availableGroups { availableGroups = available }
        var cards: [HomeGroup] = []
        // v0.19.8 (user): GLOBAL only matters in 全局 mode; it is the first card then, and never shown otherwise.
        let shown = (mode == "global" && all["GLOBAL"] != nil ? ["GLOBAL"] : []) + HomeGroupsStore.shared.resolved(available: available)
        for g in shown {
            guard let p = all[g] else { continue }
            var chain = [g]
            var cur = g
            while let n = all[cur]?.now, !n.isEmpty, chain.count < 6, !chain.contains(n) {
                chain.append(n); cur = n
            }
            cards.append(HomeGroup(name: g, icon: p.icon, kind: PolicyGroupDisplay.kind(live: p.type), chain: chain,
                                   delay: all[cur]?.lastDelay(for: NodeSettingsStore.testURL(for: cur))))
        }
        if cards != homeGroups { homeGroups = cards }
    }

    func setMode(_ m: String) async {
        mode = m
        var o = CoreOverrides.load()
        o.mode = m
        o.save()
        if VPNManager.shared.isConnected {
            try? await ControllerClient.shared.setMode(m)
            await ControllerClient.shared.afterUserSwitch() // v0.19: was always; now the 内核设置 switch (default on)
            await refreshSelectedNode() // v0.19.8: Home cards show / hide GLOBAL with the mode
        }
        NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        WidgetBridge.reload() // v0.13: widget mode row + Control Center 出站模式
    }
}

/// Exit IP (through the tunnel) + direct IP (from the extension, bypassing the tunnel).
@MainActor
final class IPInfoModel: ObservableObject {
    static let shared = IPInfoModel()

    @Published var exit: IPInfo?
    @Published var direct: IPInfo?
    @Published var loading = false
    @Published var failed = false
    @Published var updatedAt: Date?

    private var observer: NSObjectProtocol?
    private var pending: Task<Void, Never>?

    init() {
        observer = NotificationCenter.default.addObserver(forName: .egressMayHaveChanged, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.scheduleRefresh(after: 1.2) }
        }
    }

    /// Debounced refresh; the delay lets the tunnel / new node settle.
    func scheduleRefresh(after delay: Double = 0) {
        pending?.cancel()
        pending = Task { [weak self] in
            if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            if Task.isCancelled { return }
            await self?.refresh()
        }
    }

    func refresh() async {
        if UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoExitIP") {
            // v0.19 UI tests: a fixed documentation address for the 出口 IP card (no network lookups).
            exit = IPInfo(ip: "203.0.113.45", countryCode: "JP", country: "Japan", region: nil, city: "Tokyo", asn: "AS64500", org: "Example Net", source: "uitest")
            failed = false; loading = false
            return
        }
        if IPInfoFetcher.disabled {
            // QX `geo_location_checker = disabled`: no lookups; the header shows the connection state only.
            exit = nil; direct = nil; failed = false; loading = false
            return
        }
        loading = true
        failed = false
        defer { loading = false; updatedAt = Date() }
        let connected = VPNManager.shared.isConnected
        // v0.12: a custom API with a QX geo_location_checker script goes through GeoChecker; everything
        // else (auto / preferred API / custom JSON API) is IPInfoFetcher's ordered endpoints (shared with qx/rebuild).
        async let exitInfo = GeoChecker.usesScript ? GeoChecker.fetchWithScript() : IPInfoFetcher.fetch()
        async let directInfo = fetchDirectFromTunnel(enabled: connected)
        let (e, d) = await (exitInfo, directInfo)
        exit = e
        direct = connected ? d : nil
        failed = (e == nil)
    }

    private func fetchDirectFromTunnel(enabled: Bool) async -> IPInfo? {
        guard enabled else { return nil }
        guard let data = await VPNManager.shared.send(.directIP) else { return nil }
        return try? JSONDecoder().decode(IPInfo.self, from: data)
    }

    func copy() {
        var lines: [String] = []
        if let e = exit { lines.append(e.copyText) }
        if let d = direct, d.ip != exit?.ip { lines.append("直连 " + d.copyText) }
        guard !lines.isEmpty else { return }
        UIPasteboard.general.string = lines.joined(separator: "\n")
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }
}
