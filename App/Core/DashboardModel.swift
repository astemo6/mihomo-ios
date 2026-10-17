import Foundation
import Combine
import UIKit

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

    func start() {
        stop()
        let c = ControllerClient.shared
        tasks.append(Task { [weak self] in
            for await s in c.stream("/traffic", as: TrafficSample.self) {
                guard let self else { return }
                self.up = s.up; self.down = s.down
                LiveActivityController.shared.traffic(up: s.up, down: s.down, node: self.selectedNode)
                self.upHistory.append(s.up); self.downHistory.append(s.down)
                if self.upHistory.count > 60 { self.upHistory.removeFirst(self.upHistory.count - 60) }
                if self.downHistory.count > 60 { self.downHistory.removeFirst(self.downHistory.count - 60) }
            }
        })
        tasks.append(Task { [weak self] in
            for await m in c.stream("/memory", as: MemorySample.self) {
                self?.memory = m.inuse
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
                if let r = try? await c.connections() {
                    self?.uploadTotal = r.uploadTotal ?? 0
                    self?.downloadTotal = r.downloadTotal ?? 0
                    self?.connectionCount = r.connections?.count ?? 0
                    ConnectionAnalytics.shared.ingest(r.connections ?? [])
                }
                if self?.coreVersion.isEmpty == true, let v = try? await c.version() { self?.coreVersion = v }
                await self?.refreshSelectedNode()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        })
        Task { if let cfg = try? await c.configs(), let m = cfg["mode"] as? String { self.mode = m.lowercased() } }
    }

    func stop() {
        tasks.forEach { $0.cancel() }
        tasks.removeAll()
        up = 0; down = 0; connectionCount = 0; memory = 0
        homeGroups = []
        availableGroups = []
        if !VPNManager.shared.isConnected { ConnectionAnalytics.shared.reset() }
    }

    /// Follows the first group from GLOBAL's order (usually the main "节点选择") down to a leaf node.
    func refreshSelectedNode() async {
        guard let all = try? await ControllerClient.shared.proxies() else { return }
        let order = all["GLOBAL"]?.all ?? []
        let firstGroup = order.first { all[$0]?.isGroup == true }
        var name = mode == "global" ? "GLOBAL" : (firstGroup ?? "GLOBAL")
        var hops = 0
        while let p = all[name], let now = p.now, !now.isEmpty, hops < 8 {
            name = now; hops += 1
        }
        selectedNode = name
        WidgetSnapshot.update(node: name, policy: firstGroup)

        // Home policy cards (feat/home-groups): the user's chosen groups for this profile, in their order;
        // default = the first four top-level groups in GLOBAL order (hidden ones skipped).
        let testURL = ControllerClient.testSettings.url
        let available = order.filter { all[$0]?.isGroup == true && all[$0]?.hidden != true }
        if available != availableGroups { availableGroups = available }
        var cards: [HomeGroup] = []
        for g in HomeGroupsStore.shared.resolved(available: available) {
            guard let p = all[g] else { continue }
            var chain = [g]
            var cur = g
            while let n = all[cur]?.now, !n.isEmpty, chain.count < 6, !chain.contains(n) {
                chain.append(n); cur = n
            }
            cards.append(HomeGroup(name: g, icon: p.icon, kind: PolicyGroupDisplay.kind(live: p.type), chain: chain,
                                   delay: all[cur]?.lastDelay(for: testURL)))
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
            try? await ControllerClient.shared.closeAllConnections()
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
