import Foundation
import Network
import Libmihomo

/// Watches the physical network (Wi-Fi ⇄ cellular, interface changes) and runs the engine's
/// network-changed event scripts. The first path update (tunnel start) is the baseline, not an event.
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
        // SSID needs the Wi-Fi-info entitlement, which re-signed profiles usually lack → always null.
        let info: [String: Any] = [
            "type": type,
            "wifi": ["ssid": NSNull(), "bssid": NSNull()],
            "v4": ["primaryInterface": iface?.name ?? ""],
            "cellular-data": ["carrier": NSNull(), "radio": NSNull()],
            "expensive": path.isExpensive,
            "constrained": path.isConstrained,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: info, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return }
        defer { last = json }
        guard let prev = last, prev != json else { return }
        // Debounce flapping (Wi-Fi handover reports several paths in a row).
        pending?.cancel()
        let work = DispatchWorkItem {
            let n = LibmihomoNotifyNetworkChanged(json)
            if n > 0 { StartupLog.write("network changed (\(type), \(iface?.name ?? "-")): \(n) event script(s)") }
        }
        pending = work
        queue.asyncAfter(deadline: .now() + 2, execute: work)
    }
}
