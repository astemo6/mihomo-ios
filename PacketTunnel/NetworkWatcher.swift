import Foundation
import Network
import NetworkExtension
import Libmihomo

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
    private let queue = DispatchQueue(label: "mihomo.network-watcher")
    private var last: String?
    private var pending: DispatchWorkItem?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in self?.update(path) }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
        pending?.cancel()
    }

    private func update(_ path: NWPath) {
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
                self?.handle(type: type, ssid: ssid, bssid: bssid, iface: name, expensive: expensive, constrained: constrained)
            }
        }
    }

    private func handle(type: String, ssid: String?, bssid: String?, iface: String, expensive: Bool, constrained: Bool) {
        let info: [String: Any] = [
            "type": type,
            "wifi": ["ssid": ssid ?? NSNull(), "bssid": bssid ?? NSNull()],
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
            let msg = LibmihomoSetNetworkState(type, ssid ?? "")
            StartupLog.write("network: \(type)\(ssid == nil ? "" : " (SSID known)")\(msg.isEmpty ? "" : ", " + msg)")
            return
        }
        guard prev != json else { return }
        // Debounce flapping (Wi-Fi handover reports several paths in a row).
        pending?.cancel()
        let work = DispatchWorkItem {
            let msg = LibmihomoSetNetworkState(type, ssid ?? "")
            if !msg.isEmpty { StartupLog.write(msg) }
            let n = LibmihomoNotifyNetworkChanged(json)
            if n > 0 { StartupLog.write("network changed (\(type), \(iface.isEmpty ? "-" : iface)): \(n) event script(s)") }
        }
        pending = work
        queue.asyncAfter(deadline: .now() + 2, execute: work)
    }
}
