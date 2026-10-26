import Foundation
import Network
import NetworkExtension

/// Watches the physical network (Wi-Fi ⇄ cellular, interface changes), tells the core which network it is
/// on (按网络切换策略, v0.9) and runs the engine's network-changed event scripts. The first path update
/// (tunnel start) is the baseline: it sets the network policy but is not an event for scripts.
/// The SSID comes from NEHotspotNetwork.fetchCurrent (wifi-info entitlement; an installed VPN configuration
/// or the app's location permission lets iOS answer); without it the SSID is null and only Wi-Fi /
/// cellular rules apply.
final class NetworkWatcher {
    /// v0.8: physical interface type for TrafficRecorder's Wi-Fi / cellular split ("wifi" / "cellular" / …).
    private static let typeLock = NSLock()
    private static var _currentType: String?
    static var currentType: String? {
        typeLock.lock(); defer { typeLock.unlock() }
        return _currentType
    }

    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
    private let queue = DispatchQueue(label: "tern.network-watcher")
    private var last: String?
    private var pending: DispatchWorkItem?
    /// v0.19.1: path updates are numbered (on `queue`). A Wi-Fi update waits for NEHotspotNetwork.fetchCurrent;
    /// when a newer update (e.g. cellular) arrived meanwhile, the late Wi-Fi answer is dropped, so the network
    /// policy / DNS flush never end on the network the device just left.
    private var seq = 0

    /// v0.19 网络变化时清空 DNS 缓存, read once at start and on every reload (refreshSettings) straight from
    /// overrides.json. Never CoreOverrides.load() here: it touches the Keychain and may write overrides.json
    /// from the extension.
    private let flagLock = NSLock()
    private var _flushDNS = true
    private var flushDNS: Bool {
        flagLock.lock(); defer { flagLock.unlock() }
        return _flushDNS
    }

    func refreshSettings() {
        let v = Self.readFlushDNSFlag()
        flagLock.lock(); _flushDNS = v; flagLock.unlock()
    }

    /// The flag alone, decoded from overrides.json (default on when absent / unreadable).
    static func readFlushDNSFlag() -> Bool {
        guard let d = try? Data(contentsOf: AppShared.overridesURL),
              let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return true }
        return o["flushDNSOnNetworkChange"] as? Bool ?? true
    }

    /// Review 6 R6A-2: set on `queue` by stop(); late path updates / SSID answers / debounced work do nothing.
    private var stopped = false

    func start() {
        refreshSettings()
        monitor.pathUpdateHandler = { [weak self] path in self?.update(path) }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
        // On the watcher's queue: `pending` / `stopped` are only touched there (stop runs on the NE queue).
        queue.sync {
            stopped = true
            pending?.cancel()
            pending = nil
        }
    }

    private func update(_ path: Network.NWPath) {
        guard !stopped else { return }
        seq += 1
        let mySeq = seq
        // 接管所有网络流量: the interface the core binds its sockets to (only used while includeAllNetworks is on).
        // Immediately, not debounced: new dials must leave through the network the device is on now.
        // Only a physical interface: with includeAllNetworks the extension's own path can list the tunnel (utun /
        // ipsec, type .other) first, and binding the core to it loops every socket back into the tunnel.
        let physIface = path.availableInterfaces.first { [.wifi, .cellular, .wiredEthernet].contains($0.type) }
        let physical = path.status == .satisfied ? (physIface?.name ?? "") : ""
        NativeTunnelCore.shared.setPhysicalInterface(physical)
        guard path.status == .satisfied else { return }
        let iface = path.availableInterfaces.first
        let type: String
        if path.usesInterfaceType(.wifi) { type = "wifi" }
        else if path.usesInterfaceType(.cellular) { type = "cellular" }
        else if path.usesInterfaceType(.wiredEthernet) { type = "wired" }
        else { type = "other" }
        Self.typeLock.lock(); Self._currentType = type; Self.typeLock.unlock()
        let expensive = path.isExpensive, constrained = path.isConstrained
        let name = iface?.name ?? ""
        guard type == "wifi" else {
            handle(type: type, ssid: nil, bssid: nil, iface: name, expensive: expensive, constrained: constrained)
            return
        }
        NEHotspotNetwork.fetchCurrent { [weak self] net in
            let ssid = net?.ssid, bssid = net?.bssid
            self?.queue.async {
                guard let self, !self.stopped, self.seq == mySeq else { return } // superseded / stopped
                self.handle(type: type, ssid: ssid, bssid: bssid, iface: name, expensive: expensive, constrained: constrained)
            }
        }
    }

    /// 网络变化 notification text (catalog keys, localized by iOS when shown).
    static func noticeBody(type: String, ssid: String?) -> String {
        switch type {
        case "wifi":
            if let ssid, !ssid.isEmpty { return NotifyText.loc("已切换到 Wi-Fi「%@」", [ssid]) }
            return NotifyText.loc("已切换到 Wi-Fi")
        case "cellular": return NotifyText.loc("已切换到蜂窝网络")
        case "wired": return NotifyText.loc("已切换到有线网络")
        default: return NotifyText.loc("已切换到其他网络")
        }
    }

    private func handle(type: String, ssid: String?, bssid: String?, iface: String, expensive: Bool, constrained: Bool) {
        let info: [String: Any] = [
            "type": type,
            "wifi": ["ssid": ssid.map { $0 as Any } ?? NSNull(), "bssid": bssid.map { $0 as Any } ?? NSNull()],
            "v4": ["primaryInterface": iface],
            "cellular-data": ["carrier": NSNull(), "radio": NSNull()],
            "expensive": expensive,
            "constrained": constrained,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: info, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return }
        defer { last = json }
        guard let prev = last else {
            // Baseline: the policy for the network the tunnel started on.
            let msg = NativeTunnelCore.shared.setNetworkState(type: type, ssid: ssid)
            StartupLog.write("network: \(type)\(ssid == nil ? "" : " (SSID known)")\(msg.isEmpty ? "" : ", " + msg)")
            return
        }
        guard prev != json else { return }
        // Debounce flapping (Wi-Fi handover reports several paths in a row).
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.stopped else { return }
            // fix/nc-tails: pooled DoT / DoH streams idle on the old path are dropped (always; in-flight untouched).
            NCDNSDoTPool.shared.dropIdle()
            NCDNSDoHPool.shared.dropIdle()
            // v0.19 网络变化时清空 DNS 缓存 (更多 → 内核设置, on by default).
            if self.flushDNS {
                NativeTunnelCore.shared.flushDNSCache()
                StartupLog.write("network changed (\(type)): DNS cache cleared")
            }
            let msg = NativeTunnelCore.shared.setNetworkState(type: type, ssid: ssid)
            if !msg.isEmpty { StartupLog.write(msg) }
            let n = NativeTunnelCore.shared.notifyNetworkChanged(json)
            if n > 0 { StartupLog.write("network changed (\(type), \(iface.isEmpty ? "-" : iface)): \(n) event script(s)") }
            // feat/loon-menu-notify: 更多 → 通知 → 网络变化 (default off).
            if NotifyPrefs.allows(.network) {
                TunnelNotice.post(kind: .network, title: NotifyText.loc("网络变化"), body: Self.noticeBody(type: type, ssid: ssid))
            }
        }
        pending = work
        queue.asyncAfter(deadline: .now() + 2, execute: work)
    }
}
