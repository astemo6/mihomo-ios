import Foundation

/// Values shared by the app and the PacketTunnel extension.
/// Bundle IDs / App Group are injected from project.yml through Info.plist keys,
/// so project.yml is the only place they are configured.
enum AppShared {
    static let defaultAppGroup = "group.com.astemo6.mihomo"

    /// true inside the PacketTunnel extension (its bundle is a .appex).
    static let isExtension: Bool = Bundle.main.bundlePath.hasSuffix(".appex")

    /// Bundle of the containing app (for the extension: two levels up from the .appex).
    static var mainAppBundle: Bundle {
        if isExtension {
            let appURL = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent()
            return Bundle(url: appURL) ?? .main
        }
        return .main
    }

    static let mainAppBundleID: String = mainAppBundle.bundleIdentifier ?? "com.astemo6.mihomo"

    /// Tunnel extension bundle ID. Main app: the embedded packet-tunnel appex's real id when we can
    /// read it, otherwise <main bundle id>.tunnel, then the Info.plist value. Extension: its own id.
    static let tunnelBundleID: String = {
        if isExtension, let own = Bundle.main.bundleIdentifier { return own }
        if let plug = Bundle.main.builtInPlugInsURL,
           let items = try? FileManager.default.contentsOfDirectory(at: plug, includingPropertiesForKeys: nil) {
            for u in items.sorted(by: { $0.path < $1.path }) where u.pathExtension == "appex" {
                guard let b = Bundle(url: u), let id = b.bundleIdentifier else { continue }
                let ext = b.object(forInfoDictionaryKey: "NSExtension") as? [String: Any]
                let point = ext?["NSExtensionPointIdentifier"] as? String ?? ""
                let cls = ext?["NSExtensionPrincipalClass"] as? String ?? ""
                if point == "com.apple.networkextension.packet-tunnel" || cls.contains("PacketTunnelProvider") { return id }
            }
        }
        if let own = Bundle.main.bundleIdentifier, !own.isEmpty { return own + ".tunnel" }
        return Bundle.main.object(forInfoDictionaryKey: "MihomoTunnelBundleID") as? String ?? "com.astemo6.mihomo.tunnel"
    }()

    /// App groups granted by the provisioning profile the IPA was (re-)signed with.
    static func provisionedAppGroups(_ bundle: Bundle = .main) -> [String] {
        guard let url = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url) else { return [] }
        // The profile is a CMS (PKCS#7) envelope around a plain XML plist; cut the plist out.
        guard let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex) else { return [] }
        let plistData = data.subdata(in: start.lowerBound..<end.upperBound)
        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let ent = plist["Entitlements"] as? [String: Any] else { return [] }
        let groups = ent["com.apple.security.application-groups"] as? [String] ?? []
        return groups.filter { !$0.contains("*") }
    }

    /// Where each candidate came from, for 诊断.
    static private(set) var appGroupSource = ""

    /// App Group resolved at runtime so any re-signing (which replaces entitlements) still shares one
    /// container between app and extension: groups from embedded.mobileprovision in sorted order,
    /// then the Info.plist value, then the built-in default. First one the system accepts wins.
    static let appGroup: String = {
        let plist = Bundle.main.object(forInfoDictionaryKey: "MihomoAppGroup") as? String ?? defaultAppGroup
        var candidates: [(String, String)] = []
        var mine = provisionedAppGroups()
        if mine.isEmpty && isExtension { mine = provisionedAppGroups(mainAppBundle) }
        for g in mine.sorted() { candidates.append((g, "描述文件")) }
        candidates.append((plist, "Info.plist"))
        candidates.append((defaultAppGroup, "默认"))
        for (g, src) in candidates where FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: g) != nil {
            appGroupSource = src
            return g
        }
        appGroupSource = "不可用"
        return plist
    }()

    /// true when the App Group container is really shared (false => app and extension can't see each other's files).
    static var containerOK: Bool { FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) != nil }

    static var containerURL: URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            return url
        }
        // Unsigned / misconfigured builds: fall back to the app's own documents dir.
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    /// mihomo home dir (geo data, cache.db, runtime.yaml, overrides.json).
    static var homeURL: URL { ensureDir(containerURL.appendingPathComponent("mihomo", isDirectory: true)) }
    static var profilesURL: URL { ensureDir(containerURL.appendingPathComponent("profiles", isDirectory: true)) }
    static var overridesURL: URL { homeURL.appendingPathComponent("overrides.json") }
    static var profilesIndexURL: URL { containerURL.appendingPathComponent("profiles.json") }

    static var defaults: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }

    static var activeProfileID: String? {
        get { defaults.string(forKey: "activeProfileID") }
        set { defaults.set(newValue, forKey: "activeProfileID") }
    }

    static func profileURL(id: String) -> URL { profilesURL.appendingPathComponent("\(id).yaml") }

    static var activeProfileURL: URL? {
        guard let id = activeProfileID else { return nil }
        let url = profileURL(id: id)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    @discardableResult
    static func ensureDir(_ url: URL) -> URL {
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}

/// Options applied on top of the user's profile. Written as overrides.json; read by the Go bridge.
struct CoreOverrides: Codable, Equatable {
    var logLevel: String = "info"
    var ipv6: Bool = false
    var allowLan: Bool = false
    var dnsMode: String = "fake-ip"
    var sniffer: Bool = true
    var controllerPort: Int = 9090
    var secret: String = ""
    var mode: String = "rule"
    var memoryLimitMB: Int = 40

    static func load() -> CoreOverrides {
        var o = CoreOverrides()
        if let data = try? Data(contentsOf: AppShared.overridesURL),
           let decoded = try? JSONDecoder().decode(CoreOverrides.self, from: data) {
            o = decoded
        }
        if o.secret.isEmpty {
            o.secret = CoreOverrides.randomSecret()
            o.save()
        }
        return o
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            try? data.write(to: AppShared.overridesURL, options: .atomic)
        }
    }

    static func randomSecret() -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<32).map { _ in chars.randomElement()! })
    }
}

/// Messages the app sends to the tunnel through NETunnelProviderSession.sendProviderMessage.
enum TunnelMessage: String {
    case reload
    case directIP
    case freeMemory
    case version
}

/// Last start error written by the extension so the app can show why the tunnel stopped.
enum TunnelErrorLog {
    static var url: URL { AppShared.containerURL.appendingPathComponent("tunnel-last-error.txt") }
    static func write(_ msg: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date()))\t\(msg)"
        try? line.data(using: .utf8)?.write(to: url, options: .atomic)
    }
    static func clear() { try? FileManager.default.removeItem(at: url) }
    /// Returns the message if it was written within `within` seconds.
    static func recent(within: TimeInterval = 60) -> String? {
        guard let s = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let parts = s.split(separator: "\t", maxSplits: 1).map(String.init)
        guard parts.count == 2, let d = ISO8601DateFormatter().date(from: parts[0]), Date().timeIntervalSince(d) < within else { return nil }
        return parts[1]
    }
}
