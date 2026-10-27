import Foundation
import CoreLocation
import NetworkExtension

/// 按网络切换策略 (v0.9): per select group of the active profile, which member to use on Wi-Fi, on cellular
/// and on named Wi-Fi networks. Stored in <home>/netpolicy.json ({"<profile id>": [rules]}, our override
/// store, never the profile); the extension applies it on every network change.
struct NetworkPolicyRule: Codable, Hashable, Identifiable {
    var id: String { group }
    var group: String
    var wifi: String?
    var cellular: String?
    var ssids: [String: String]?

    var isEmpty: Bool {
        (wifi ?? "").isEmpty && (cellular ?? "").isEmpty && (ssids ?? [:]).isEmpty
    }
}

/// Last result written by the extension (<home>/netpolicy-state.json).
struct NetworkPolicyState: Decodable {
    struct Applied: Decodable, Hashable { var group: String; var node: String; var reason: String; var error: String? }
    var at: Double
    var type: String
    var ssid: String?
    var trigger: String
    var applied: [Applied]
    var mode: String?        // v0.12 运行模式按网络切换
    var modeReason: String?
}

/// 运行模式按网络切换 (v0.12, QX running_mode_trigger): rule / global / direct per cellular, Wi-Fi and named
/// Wi-Fi network. App-wide, stored in <home>/modetrigger.json and applied by the extension together with
/// 按网络切换策略. nil / "" = keep the current mode.
struct ModeTrigger: Codable, Hashable {
    var enabled: Bool = false
    var cellular: String? = nil
    var wifi: String? = nil
    var ssids: [String: String]? = nil

    static var url: URL { AppShared.homeURL.appendingPathComponent("modetrigger.json") }

    static func load() -> ModeTrigger {
        guard let d = try? Data(contentsOf: url), let m = try? JSONDecoder().decode(ModeTrigger.self, from: d) else { return ModeTrigger() }
        return m
    }

    func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(self) { try? d.write(to: Self.url, options: .atomic) }
    }

    static let modes = ["rule", "global", "direct"]

    static func title(_ m: String?) -> String {
        switch m {
        case "rule": return "规则"
        case "global": return "全局"
        case "direct": return "直连"
        default: return "不切换"
        }
    }

    var summary: String {
        var parts: [String] = []
        if let c = cellular, !c.isEmpty { parts.append(String(localized: "蜂窝 \(NSLocalizedString(Self.title(c), comment: ""))")) }
        if let w = wifi, !w.isEmpty { parts.append(String(localized: "Wi-Fi \(NSLocalizedString(Self.title(w), comment: ""))")) }
        if let n = ssids?.count, n > 0 { parts.append(String(localized: "\(n) 个指定 Wi-Fi")) }
        return parts.joined(separator: " · ")
    }
}

enum NetworkPolicyStore {
    static var url: URL { AppShared.homeURL.appendingPathComponent("netpolicy.json") }
    static var stateURL: URL { AppShared.homeURL.appendingPathComponent("netpolicy-state.json") }

    static var profileID: String? { AppShared.activeProfileURL?.deletingPathExtension().lastPathComponent }

    static func loadAll() -> [String: [NetworkPolicyRule]] {
        guard let d = try? Data(contentsOf: url),
              let m = try? JSONDecoder().decode([String: [NetworkPolicyRule]].self, from: d) else { return [:] }
        return m
    }

    static func rules() -> [NetworkPolicyRule] {
        guard let id = profileID else { return [] }
        return loadAll()[id] ?? []
    }

    static func save(_ rules: [NetworkPolicyRule]) {
        guard let id = profileID else { return }
        var all = loadAll()
        let kept = rules.filter { !$0.isEmpty }
        all[id] = kept.isEmpty ? nil : kept
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(all) { try? d.write(to: url, options: .atomic) }
    }

    static func state() -> NetworkPolicyState? {
        guard let d = try? Data(contentsOf: stateURL) else { return nil }
        return try? JSONDecoder().decode(NetworkPolicyState.self, from: d)
    }
}

/// Reads the current Wi-Fi name for the editors. NEHotspotNetwork.fetchCurrent needs the wifi-info
/// entitlement and one of: an installed VPN configuration (ours, usually enough) or precise location
/// permission. Everything degrades to manual entry when iOS returns nil.
@MainActor
final class WiFiInfo: NSObject, ObservableObject, CLLocationManagerDelegate {
    static let shared = WiFiInfo()

    @Published private(set) var ssid: String?
    @Published private(set) var checked = false
    @Published private(set) var authorization: CLAuthorizationStatus
    @Published private(set) var precise = true

    private let manager = CLLocationManager()
    private var pendingRefresh = false

    override init() {
        authorization = manager.authorizationStatus
        super.init()
        manager.delegate = self
        precise = manager.accuracyAuthorization == .fullAccuracy
    }

    /// v0.16: 定位服务 (system-wide switch); nil until read (CLLocationManager asks for it off the main thread).
    @Published private(set) var servicesEnabled: Bool?

    func refreshServices() async {
        servicesEnabled = await Task.detached(priority: .utility) { CLLocationManager.locationServicesEnabled() }.value
        authorization = manager.authorizationStatus
        precise = manager.accuracyAuthorization == .fullAccuracy
    }

    /// v0.16: whether the provisioning profile the app was (re-)signed with grants wifi-info
    /// (nil = no embedded.mobileprovision, e.g. the simulator or an unsigned build).
    static let wifiInfoEntitlement: Bool? = {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex),
              let plist = try? PropertyListSerialization.propertyList(from: data.subdata(in: start.lowerBound..<end.upperBound), format: nil) as? [String: Any],
              let ent = plist["Entitlements"] as? [String: Any] else { return nil }
        return (ent["com.apple.developer.networking.wifi-info"] as? Bool) == true
    }()

    var locationGranted: Bool { authorization == .authorizedWhenInUse || authorization == .authorizedAlways }
    var locationDenied: Bool { authorization == .denied || authorization == .restricted }

    func refresh() async {
        let net = await NEHotspotNetwork.fetchCurrent()
        ssid = net?.ssid
        checked = true
    }

    /// Asks for "when in use" location (only after the user tapped the explained button), then re-reads.
    func requestLocation() {
        guard authorization == .notDetermined else {
            if locationGranted && !precise { manager.requestTemporaryFullAccuracyAuthorization(withPurposeKey: "WiFiName") }
            return
        }
        pendingRefresh = true
        manager.requestWhenInUseAuthorization()
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        let full = manager.accuracyAuthorization == .fullAccuracy
        Task { @MainActor in
            self.authorization = status
            self.precise = full
            if self.pendingRefresh, status != .notDetermined {
                self.pendingRefresh = false
                await self.refresh()
            }
        }
    }
}
