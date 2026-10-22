import Foundation

/// Values shared by the app and the PacketTunnel extension.
/// Bundle IDs / App Group are injected from project.yml through Info.plist keys,
/// so project.yml is the only place they are configured.
enum AppShared {
    static let defaultAppGroup = "group.com.astemo6.mihomo"
    /// r7: Darwin notification the tunnel posts from stopTunnel (the app ends its Live Activity when it is running).
    static var tunnelStoppedNotification: String { appGroup + ".tunnelStopped" }

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

    /// Tunnel extension bundle ID. Works from the main app and from any app extension: the embedded
    /// packet-tunnel appex's real id when we can read it (re-signing may change it), otherwise our own id
    /// when we *are* the packet tunnel, then <main bundle id>.tunnel, then the Info.plist value.
    static let tunnelBundleID: String = {
        func isPacketTunnel(_ b: Bundle) -> Bool {
            let ext = b.object(forInfoDictionaryKey: "NSExtension") as? [String: Any]
            let point = ext?["NSExtensionPointIdentifier"] as? String ?? ""
            let cls = ext?["NSExtensionPrincipalClass"] as? String ?? ""
            return point == "com.apple.networkextension.packet-tunnel" || cls.contains("PacketTunnelProvider")
        }
        if isExtension, isPacketTunnel(.main), let own = Bundle.main.bundleIdentifier { return own }
        if let plug = mainAppBundle.builtInPlugInsURL,
           let items = try? FileManager.default.contentsOfDirectory(at: plug, includingPropertiesForKeys: nil) {
            for u in items.sorted(by: { $0.path < $1.path }) where u.pathExtension == "appex" {
                guard let b = Bundle(url: u), let id = b.bundleIdentifier, isPacketTunnel(b) else { continue }
                return id
            }
        }
        if let own = mainAppBundle.bundleIdentifier, !own.isEmpty { return own + ".tunnel" }
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

    /// r7 (review7 R7A-3 / backlog B05): one candidate App Group as 诊断 shows it.
    struct AppGroupCandidate: Equatable {
        var group: String
        var source: String      // 描述文件 · Info.plist · 默认
        var accepted: Bool      // the system gives us its container
        var hasData: Bool       // profiles.json there
        var ours: Bool          // the marker file names this app
    }

    /// UserDefaults.standard keys (per process: app, tunnel, widget each remember their own choice).
    static let rememberedGroupKey = "tern.appGroup.chosen"
    static let rememberedProvisionedKey = "tern.appGroup.provisioned"
    /// Written by the app into the container it uses: the main app bundle id (another app of the same team that
    /// shares a group in the profile never matches).
    static let groupMarkerName = ".tern-app-group"

    static private(set) var appGroupCandidates: [AppGroupCandidate] = []
    /// The provisioned group list changed since the choice was remembered (profile renewed / regenerated).
    static private(set) var provisionedGroupsChanged = false
    /// The remembered group is no longer granted by the profile: its data is out of reach.
    static private(set) var rememberedGroupLost: String?

    static func containerURL(forGroup g: String) -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: g)
    }

    /// App Group resolved at runtime so any re-signing (which replaces entitlements) still shares one
    /// container between app and extension.
    ///
    /// r7 R7A-3: the choice is no longer stateless ("first sorted group the system accepts" — a renewed profile with
    /// one more group sorted earlier, or without the current one, moved app, tunnel and widget to an empty
    /// container). Order, first accepted wins:
    /// 1. the group this process used last time (UserDefaults.standard);
    /// 2. a group whose marker file names this app;
    /// 3. a group that already holds profiles.json;
    /// 4. as before: profile groups in sorted order, then the Info.plist value, then the built-in default.
    /// Every process applies the same rules to the same containers, so app, tunnel and widget agree.
    static let appGroup: String = {
        let plist = Bundle.main.object(forInfoDictionaryKey: "MihomoAppGroup") as? String ?? defaultAppGroup
        var mine = provisionedAppGroups()
        if mine.isEmpty && isExtension { mine = provisionedAppGroups(mainAppBundle) }
        var ordered: [(String, String)] = mine.sorted().map { ($0, "描述文件") }
        for (g, src) in [(plist, "Info.plist"), (defaultAppGroup, "默认")] where !ordered.contains(where: { $0.0 == g }) {
            ordered.append((g, src))
        }
        let fm = FileManager.default
        var cands: [AppGroupCandidate] = []
        for (g, src) in ordered {
            let url = containerURL(forGroup: g)
            let has = url.map { fm.fileExists(atPath: $0.appendingPathComponent("profiles.json").path) } ?? false
            let marker = url.flatMap { try? String(contentsOf: $0.appendingPathComponent(groupMarkerName), encoding: .utf8) }
            let ours = marker?.trimmingCharacters(in: .whitespacesAndNewlines) == mainAppBundleID
            cands.append(AppGroupCandidate(group: g, source: src, accepted: url != nil, hasData: has, ours: ours))
        }
        appGroupCandidates = cands
        let std = UserDefaults.standard
        let remembered = std.string(forKey: rememberedGroupKey)
        let prevList = std.stringArray(forKey: rememberedProvisionedKey)
        if let prevList, !mine.isEmpty, prevList.sorted() != mine.sorted() { provisionedGroupsChanged = true }
        if !mine.isEmpty { std.set(mine.sorted(), forKey: rememberedProvisionedKey) }

        func pick() -> (String, String)? {
            if let r = remembered, cands.contains(where: { $0.group == r && $0.accepted }) { return (r, "已记住") }
            if let r = remembered { rememberedGroupLost = r }
            if let c = cands.first(where: { $0.accepted && $0.ours }) { return (c.group, "已有数据") }
            if let c = cands.first(where: { $0.accepted && $0.hasData }) { return (c.group, "已有数据") }
            if let c = cands.first(where: { $0.accepted }) { return (c.group, c.source) }
            return nil
        }
        guard let picked = pick() else {
            appGroupSource = "不可用"
            return plist
        }
        let (g, src) = picked
        appGroupSource = src
        std.set(g, forKey: rememberedGroupKey)
        if !isExtension, let url = containerURL(forGroup: g) {
            let m = url.appendingPathComponent(groupMarkerName)
            if (try? String(contentsOf: m, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) != mainAppBundleID {
                try? Data(mainAppBundleID.utf8).write(to: m, options: .atomic)
            }
        }
        return g
    }()

    /// r7 B05: a warning for 诊断 when the App Group may not be the one holding the user's data, nil when all is well.
    static var appGroupWarning: String? {
        _ = appGroup
        if !containerOK {
            return String(localized: "共享容器不可用：描述文件里没有本 App 可用的 App Group，扩展读不到配置。")
        }
        if let lost = rememberedGroupLost {
            return String(localized: "之前使用的 App Group（\(lost)）已不在描述文件里，原来的数据留在那个容器中。请用旧描述文件签名的版本导出备份，再在这里「从文件恢复」。")
        }
        let others = appGroupCandidates.filter { $0.group != appGroup && $0.accepted && ($0.hasData || $0.ours) }
        if !others.isEmpty {
            return String(localized: "另一个 App Group 里也有数据（\(others.map(\.group).joined(separator: ", "))）。如果这里的数据不对，请在原来的版本里导出备份后恢复。")
        }
        if provisionedGroupsChanged {
            return String(localized: "描述文件的 App Group 列表已变化，App 仍在使用之前的组（\(appGroup)）。")
        }
        if appGroupSource == "Info.plist" || appGroupSource == "默认" {
            return String(localized: "App Group 来自 \(appGroupSource)，不是描述文件：小组件和隧道可能看不到 App 的数据。")
        }
        return nil
    }

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

    /// Review 6 OPT-3: one instance per process (was a new UserDefaults object on every access — the tunnel's
    /// 10 s Live Activity sampler, the widget timeline and many app paths read it). UserDefaults is thread-safe
    /// and still sees writes from the other processes.
    static let defaults: UserDefaults = UserDefaults(suiteName: appGroup) ?? .standard

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

/// Options applied on top of the user's profile. Written as overrides.json; read by the Go bridge
/// (bridge/bridge.go Overrides). Decoding is tolerant: missing or mistyped keys fall back to defaults,
/// so files written by older builds keep working.
struct CoreOverrides: Codable, Equatable {
    var logLevel: String = "info"
    var ipv6: Bool = false
    var allowLan: Bool = false
    var dnsMode: String = "fake-ip"
    var sniffer: Bool = true
    var controllerPort: Int = 9090
    var secret: String = ""
    var mode: String = "rule"
    /// Go soft memory limit (GOMEMLIMIT) in MB; 20…30 (v0.6.1; older values fall back to the default).
    var memoryLimitMB: Int = 26
    /// "tun" = NEPacketTunnelFlow bridge (all traffic) · "mix" = tun + system HTTP proxy to the mixed port
    /// (Loon proxymode=mix / Surge compat) · "proxy" = NEProxySettings only.
    var tunnelMode: String = "tun"
    /// Local HTTP/SOCKS port for proxy-only mode and LAN sharing.
    var mixedPort: Int = 7890
    var tunMTU: Int = 4064
    /// jsdelivr (testingcf CDN, default) · fastly · github · custom (geoMirrorBase)
    var geoMirror: String = "jsdelivr"
    /// Base URL for geoMirror "custom"; the file name is appended (bridge GeoCustomBase validates it).
    var geoMirrorBase: String = ""
    /// Custom URL per database kind (mmdb / geosite / asn / geoip); missing = mirror default.
    var geoURLs: [String: String] = [:]
    /// Add the 手动节点 profile's nodes (and its group) to every profile.
    var mergeManual: Bool = false
    /// 安全模式: set by the app for one connection after a failed start. The core then runs the profile
    /// with these overrides only (no modules, rewrite, scripts, MitM, custom rules, smart groups).
    var safeMode: Bool = false
    /// 测速地址 for manual latency tests (live and offline); optionally also every health check.
    var testURL: String = CoreOverrides.defaultTestURL
    var testTimeoutMs: Int = 5000
    var overrideHealthCheck: Bool = false

    // v0.7 连接方式
    /// Routes sent into the tunnel / kept out of it (CIDR, IPv4 and IPv6; IPv6 entries apply only with IPv6 on).
    var includedRoutes: [String] = CoreOverrides.defaultIncludedRoutes
    var excludedRoutes: [String] = CoreOverrides.defaultExcludedRoutes
    /// Hosts / CIDRs the system HTTP proxy skips (混合 and 仅代理 modes).
    var skipProxy: [String] = CoreOverrides.defaultSkipProxy
    /// 阻止 QUIC: "off" · "nondirect" (default, v0.6.1 behaviour) · "always".
    var blockQUIC: String = "nondirect"
    /// Tunnel scope (NETunnelProviderProtocol), applied to the VPN configuration by the app.
    var includeAllNetworks: Bool = false
    var excludeLocalNetworks: Bool = true
    var excludeAPNs: Bool = true
    var excludeCellularServices: Bool = true
    var excludeDeviceCommunication: Bool = true
    /// 局域网共享: optional username / password, and only LAN source addresses.
    var lanAuth = LanAuth()
    var lanLocalOnly: Bool = true
    /// v0.8 IPv6: "off" · "auto" (only when the physical network has a global IPv6 address at start) · "always".
    /// `ipv6` stays as the value older builds read (and the extension's resolved value in memory).
    var ipv6Mode: String = "off"
    /// v0.8 IP preference for nodes without their own ip-version: "dual" (mihomo default) · "ipv4-prefer" ·
    /// "ipv6-prefer" · "ipv4" · "ipv6".
    var ipPreference: String = "dual"
    /// v0.19: the extension clears the core's DNS cache after the physical network changes (Wi-Fi ⇄ cellular,
    /// another Wi-Fi), so answers from the previous network (LAN names, CDN picks) are not reused.
    var flushDNSOnNetworkChange: Bool = true
    /// v0.19 局域网多用户: more username / password pairs accepted on the shared port (besides lanAuth).
    var lanUsers: [LanAuth] = []

    /// r7 (backlog B02): what this value looked like when it was loaded, shared by its copies. save() writes only the
    /// fields that differ from it on top of the current file (a 3-way merge under the cross-process lock), so the
    /// app, the widget (mode switch) and the extension no longer overwrite each other's changes. Not encoded;
    /// never part of ==.
    fileprivate var mergeBase = MergeBase()

    final class MergeBase: Equatable {
        var dict: [String: Any]?
        init(_ d: [String: Any]? = nil) { dict = d }
        static func == (a: MergeBase, b: MergeBase) -> Bool { true }
    }

    struct LanAuth: Codable, Equatable {
        var username: String = ""
        var password: String = ""

        init(username: String = "", password: String = "") {
            self.username = username
            self.password = password
        }

        /// v0.19.5: a missing / mistyped field is empty. The synthesized decoder threw, and CoreOverrides' tolerant
        /// get() then replaced the whole value with the default — one bad 其他用户 entry dropped every extra user,
        /// a lanAuth without "password" (the keychain holds it) lost the username.
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            username = (try? c.decodeIfPresent(String.self, forKey: .username)) ?? ""
            password = (try? c.decodeIfPresent(String.self, forKey: .password)) ?? ""
        }
    }

    static let defaultIncludedRoutes = ["0.0.0.0/0", "::/0"]
    static let defaultExcludedRoutes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"]
    static let defaultSkipProxy = ["localhost", "*.local", "127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "captive.apple.com"]

    static let defaultMemoryLimitMB = 26
    static let memoryLimitRange = 20...30
    static let defaultTestURL = "https://www.gstatic.com/generate_204"
    static let testURLPresets = [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
        "https://www.apple.com/library/test/success.html",
        "http://connectivitycheck.platform.hicloud.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "https://www.google.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
        "http://captive.apple.com",
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://wifi.vivo.com.cn/generate_204",
    ]
    /// Short label per preset for 更多 → 测速 (localised in the app).
    static let testURLLabels: [String: String] = [
        "https://www.gstatic.com/generate_204": "Google (gstatic)",
        "https://cp.cloudflare.com/generate_204": "Cloudflare",
        "https://www.apple.com/library/test/success.html": "Apple",
        "http://connectivitycheck.platform.hicloud.com/generate_204": "华为 (HTTP)",
        "http://www.gstatic.com/generate_204": "Google (HTTP)",
        "https://www.google.com/generate_204": "Google",
        "http://cp.cloudflare.com/generate_204": "Cloudflare (HTTP)",
        "http://captive.apple.com": "Apple Captive",
        "http://www.msftconnecttest.com/connecttest.txt": "Microsoft",
        "http://wifi.vivo.com.cn/generate_204": "国内 vivo",
    ]
    static func isValidTestURL(_ s: String) -> Bool {
        guard let u = URL(string: s.trimmingCharacters(in: .whitespaces)), let sc = u.scheme?.lowercased(),
              sc == "http" || sc == "https", let h = u.host, !h.isEmpty else { return false }
        return true
    }
    static let mtuChoices = [1280, 1500, 4064, 9000]

    /// v0.8 节点探测: loopback port of the probe listener (same rule as bridge/probe.go probePort): 7899, or the
    /// next lower port when the mixed or controller port already uses it.
    var probePort: Int {
        let ctrl = (1...65535).contains(controllerPort) ? controllerPort : 9090
        let mixed = mixedPort == ctrl ? 7890 : mixedPort
        var p = 7899
        while p > 7800 && (p == mixed || p == ctrl) { p -= 1 }
        return p
    }

    /// IPv6 for this start: "auto" asks the physical network (extension, before the core starts).
    func resolvedIPv6() -> Bool {
        switch ipv6Mode {
        case "always": return true
        case "auto": return NetIPv6.physicalNetworkHasGlobalIPv6()
        default: return false
        }
    }

    var isProxyOnly: Bool { tunnelMode == "proxy" }
    var isMixed: Bool { tunnelMode == "mix" }

    init() {}

    enum CodingKeys: String, CodingKey {
        case logLevel, ipv6, allowLan, dnsMode, sniffer, controllerPort, secret, mode, memoryLimitMB
        case tunnelMode, mixedPort, tunMTU, geoMirror, geoMirrorBase, geoURLs, mergeManual, safeMode
        case testURL, testTimeoutMs, overrideHealthCheck
        case includedRoutes, excludedRoutes, skipProxy, blockQUIC
        case includeAllNetworks, excludeLocalNetworks, excludeAPNs, excludeCellularServices, excludeDeviceCommunication
        case lanAuth, lanLocalOnly, ipv6Mode, ipPreference
        case flushDNSOnNetworkChange, lanUsers
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = CoreOverrides()
        func get<T: Decodable>(_ k: CodingKeys, _ fallback: T) -> T {
            (try? c.decodeIfPresent(T.self, forKey: k)) ?? fallback
        }
        logLevel = get(.logLevel, d.logLevel)
        ipv6 = get(.ipv6, d.ipv6)
        allowLan = get(.allowLan, d.allowLan)
        dnsMode = get(.dnsMode, d.dnsMode)
        sniffer = get(.sniffer, d.sniffer)
        controllerPort = get(.controllerPort, d.controllerPort)
        secret = get(.secret, d.secret)
        mode = get(.mode, d.mode)
        memoryLimitMB = get(.memoryLimitMB, d.memoryLimitMB)
        tunnelMode = get(.tunnelMode, d.tunnelMode)
        mixedPort = get(.mixedPort, d.mixedPort)
        tunMTU = get(.tunMTU, d.tunMTU)
        geoMirror = get(.geoMirror, d.geoMirror)
        geoMirrorBase = get(.geoMirrorBase, d.geoMirrorBase)
        geoURLs = get(.geoURLs, d.geoURLs)
        mergeManual = get(.mergeManual, d.mergeManual)
        safeMode = get(.safeMode, d.safeMode)
        testURL = get(.testURL, d.testURL)
        testTimeoutMs = get(.testTimeoutMs, d.testTimeoutMs)
        overrideHealthCheck = get(.overrideHealthCheck, d.overrideHealthCheck)
        includedRoutes = get(.includedRoutes, d.includedRoutes)
        excludedRoutes = get(.excludedRoutes, d.excludedRoutes)
        skipProxy = get(.skipProxy, d.skipProxy)
        blockQUIC = get(.blockQUIC, d.blockQUIC)
        includeAllNetworks = get(.includeAllNetworks, d.includeAllNetworks)
        excludeLocalNetworks = get(.excludeLocalNetworks, d.excludeLocalNetworks)
        excludeAPNs = get(.excludeAPNs, d.excludeAPNs)
        excludeCellularServices = get(.excludeCellularServices, d.excludeCellularServices)
        excludeDeviceCommunication = get(.excludeDeviceCommunication, d.excludeDeviceCommunication)
        lanAuth = get(.lanAuth, d.lanAuth)
        lanLocalOnly = get(.lanLocalOnly, d.lanLocalOnly)
        // Files from before v0.8 have only the bool.
        ipv6Mode = get(.ipv6Mode, ipv6 ? "always" : "off")
        if !["off", "auto", "always"].contains(ipv6Mode) { ipv6Mode = ipv6 ? "always" : "off" }
        ipPreference = get(.ipPreference, d.ipPreference)
        flushDNSOnNetworkChange = get(.flushDNSOnNetworkChange, d.flushDNSOnNetworkChange)
        lanUsers = get(.lanUsers, d.lanUsers)
        if !["dual", "ipv4-prefer", "ipv6-prefer", "ipv4", "ipv6"].contains(ipPreference) { ipPreference = d.ipPreference }
        if !["off", "nondirect", "always"].contains(blockQUIC) { blockQUIC = d.blockQUIC }
        if !Self.isValidTestURL(testURL) { testURL = d.testURL }
        if !(1000...30000).contains(testTimeoutMs) { testTimeoutMs = d.testTimeoutMs }
        if tunnelMode != "proxy" && tunnelMode != "mix" { tunnelMode = "tun" }
        if !(1280...9000).contains(tunMTU) { tunMTU = d.tunMTU }
        if !(1...65535).contains(mixedPort) { mixedPort = d.mixedPort }
        // v0.19.5: an out-of-range controller port (0, 70000) was kept → the core's controller could not listen
        // and the app lost the live view; the same fallback as the mixed port.
        if !(1...65535).contains(controllerPort) { controllerPort = d.controllerPort }
        if !Self.memoryLimitRange.contains(memoryLimitMB) { memoryLimitMB = d.memoryLimitMB }
    }

    /// r7 (backlog B01): where the secrets live. overrides.json carries no secret any more — it goes into backups,
    /// the sync folder and diagnostics. The controller secret, the LAN-share password and the 其他用户 passwords are
    /// in <home>/secrets.json (0600, protected until first unlock), which the extension's Go core overlays on
    /// overrides.json (bridge/secrets.go). The app also mirrors them into the Keychain, but only as a recovery copy
    /// after a reinstall: after an ipasign / zsign re-sign the Keychain access group (= App Group id) is often not
    /// readable from the extension, so the extension never depends on it (build-log item 15 / review item 14).
    /// Precedence when reading: a value still in overrides.json (older build, restored older backup) → secrets.json
    /// → Keychain (app only) → a new random controller secret.
    static var storeDir: URL { testStoreDir ?? AppShared.homeURL }
    /// Unit tests: a scratch directory instead of the App Group (and no Keychain).
    static var testStoreDir: URL?
    static var overridesFile: URL { storeDir.appendingPathComponent("overrides.json") }
    private static var useKeychain: Bool { !AppShared.isExtension && testStoreDir == nil && Bundle.main.bundleURL.pathExtension == "app" }

    static func load() -> CoreOverrides {
        OverridesLock.with(storeDir) { loadLocked() }
    }

    /// Lock held. Reads overrides.json + secrets.json, migrates secrets out of overrides.json, never loses a value.
    private static func loadLocked() -> CoreOverrides {
        var o = CoreOverrides()
        var raw: [String: Any] = [:]
        if let data = try? Data(contentsOf: overridesFile) {
            if let decoded = try? JSONDecoder().decode(CoreOverrides.self, from: data) { o = decoded }
            raw = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? [:]
        }
        let jsonCarriesSecrets = raw["secret"] != nil || (raw["lanAuth"] as? [String: Any])?["password"] != nil
            || ((raw["lanUsers"] as? [[String: Any]]) ?? []).contains { $0["password"] != nil }
        let stored = CoreSecrets.read(dir: storeDir)
        var sec = stored ?? CoreSecrets()
        // 1) legacy values in overrides.json win (an older build or a restored older backup just wrote them)
        if !o.secret.isEmpty { sec.secret = o.secret }
        if !o.lanAuth.password.isEmpty { sec.lanPassword = o.lanAuth.password }
        var legacySeen: Set<String> = []
        for u in o.lanUsers where !u.password.isEmpty {
            if legacySeen.insert(u.username).inserted { sec.lanUsers[u.username] = u.password }
        }
        // 2) the app's Keychain copy fills what is still missing (reinstall: the container is new, the Keychain is not)
        var kcSecret: String?, kcLan: String?, kcUsers: [String: String]?
        // Only when secrets.json is missing (reinstall, first start of this build) or has no secret: the Keychain is
        // not read on every load (load() runs on many UI paths).
        let readKeychain = useKeychain && (stored == nil || sec.secret.isEmpty)
        if readKeychain {
            kcSecret = Keychain.read(Keychain.controllerSecretAccount)
            kcLan = Keychain.read(Keychain.lanSharePasswordAccount)
            kcUsers = Keychain.read(Keychain.lanUsersAccount).flatMap { try? JSONDecoder().decode([String: String].self, from: Data($0.utf8)) }
            if sec.secret.isEmpty, let k = kcSecret { sec.secret = k }
            if sec.lanPassword.isEmpty, let k = kcLan { sec.lanPassword = k }
            for (u, p) in kcUsers ?? [:] where sec.lanUsers[u] == nil && o.lanUsers.contains(where: { $0.username == u }) { sec.lanUsers[u] = p }
        }
        if sec.secret.isEmpty { sec.secret = randomSecret() }
        o.apply(sec)
        // Persist: secrets first, then the stripped overrides.json, so a reader never sees a value in neither file.
        if sec != stored { sec.write(dir: storeDir) }
        if jsonCarriesSecrets { o.writePublic() }
        if useKeychain && sec != stored {
            if readKeychain { sec.mirrorToKeychain(secret: kcSecret, lan: kcLan, users: kcUsers) } else { sec.mirrorToKeychain() }
        }
        o.mergeBase = MergeBase(o.jsonObject())
        return o
    }

    /// Puts the secrets into the in-memory value (what the app, widget and tunnel use).
    fileprivate mutating func apply(_ sec: CoreSecrets) {
        secret = sec.secret
        lanAuth.password = sec.lanPassword
        lanUsers = lanUsers.map { LanAuth(username: $0.username, password: $0.password.isEmpty ? (sec.lanUsers[$0.username] ?? "") : $0.password) }
    }

    fileprivate var secrets: CoreSecrets {
        var m: [String: String] = [:]
        for u in lanUsers where !u.password.isEmpty && m[u.username] == nil { m[u.username] = u.password } // first wins, like Go
        return CoreSecrets(secret: secret, lanPassword: lanAuth.password, lanUsers: m)
    }

    /// Everything, secrets included (merge base / comparison only; never written as is).
    fileprivate func jsonObject() -> [String: Any] {
        guard let d = try? JSONEncoder().encode(self), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return [:] }
        return o
    }

    /// overrides.json without the secrets. Lock held.
    fileprivate func writePublic() {
        var obj = jsonObject()
        obj.removeValue(forKey: "secret")
        if var la = obj["lanAuth"] as? [String: Any] { la.removeValue(forKey: "password"); obj["lanAuth"] = la }
        if let users = obj["lanUsers"] as? [[String: Any]] {
            obj["lanUsers"] = users.map { u -> [String: Any] in var u = u; u.removeValue(forKey: "password"); return u }
        }
        if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) {
            try? data.write(to: Self.overridesFile, options: .atomic)
        }
    }

    /// The safe-mode flag as stored in overrides.json (no Keychain access, nothing written).
    static func storedSafeMode() -> Bool {
        struct Flag: Decodable { var safeMode: Bool? }
        guard let d = try? Data(contentsOf: overridesFile),
              let f = try? JSONDecoder().decode(Flag.self, from: d) else { return false }
        return f.safeMode ?? false
    }

    /// r7 B02: under the cross-process lock, the fields this value changed since it was loaded are written over the
    /// current file (a field another process changed meanwhile survives). A value built with CoreOverrides()
    /// (no load) replaces the whole file, as before.
    func save() {
        var me = self
        me.ipv6 = ipv6Mode != "off"
        let base = mergeBase
        OverridesLock.with(Self.storeDir) {
            var out = me
            if let b = base.dict {
                let current = Self.loadLocked()
                var merged = current.jsonObject()
                for (k, v) in me.jsonObject() where !Self.jsonEqual(v, b[k]) { merged[k] = v }
                if let d = try? JSONSerialization.data(withJSONObject: merged),
                   let m = try? JSONDecoder().decode(CoreOverrides.self, from: d) {
                    out = m
                    out.ipv6 = out.ipv6Mode != "off"
                }
            }
            let sec = out.secrets
            if sec != CoreSecrets.read(dir: Self.storeDir) {
                sec.write(dir: Self.storeDir)
                if Self.useKeychain { sec.mirrorToKeychain() }
            }
            out.writePublic()
            base.dict = out.jsonObject() // later saves of this value (and its copies) merge against what was written
        }
    }

    private static func jsonEqual(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (nil, _), (_, nil): return false
        case let (x?, y?): return NSDictionary(dictionary: ["v": x]).isEqual(to: ["v": y])
        }
    }

    static func randomSecret() -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<32).map { _ in chars.randomElement() ?? "x" })
    }
}

/// r7 (backlog B01): <home>/secrets.json — the controller secret, the LAN-share password and the 其他用户 passwords
/// (username → password). Read by the app, the widget and the extension's Go core (bridge/secrets.go); kept out of
/// unencrypted backups, the sync folder and diagnostics.
struct CoreSecrets: Codable, Equatable {
    var secret: String = ""
    var lanPassword: String = ""
    var lanUsers: [String: String] = [:]

    init(secret: String = "", lanPassword: String = "", lanUsers: [String: String] = [:]) {
        self.secret = secret
        self.lanPassword = lanPassword
        self.lanUsers = lanUsers
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        secret = (try? c.decodeIfPresent(String.self, forKey: .secret)) ?? ""
        lanPassword = (try? c.decodeIfPresent(String.self, forKey: .lanPassword)) ?? ""
        lanUsers = (try? c.decodeIfPresent([String: String].self, forKey: .lanUsers)) ?? [:]
    }

    static let fileName = "secrets.json"
    static func url(dir: URL) -> URL { dir.appendingPathComponent(fileName) }

    /// nil = no (readable) file.
    static func read(dir: URL) -> CoreSecrets? {
        guard let d = try? Data(contentsOf: url(dir: dir)) else { return nil }
        return try? JSONDecoder().decode(CoreSecrets.self, from: d)
    }

    func write(dir: URL) {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        guard let d = try? enc.encode(self) else { return }
        let u = Self.url(dir: dir)
        // Readable by the extension from first unlock on (on-demand restarts while locked), never synced.
        try? d.write(to: u, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path)
        var rv = URLResourceValues()
        rv.isExcludedFromBackup = true
        var mu = u
        try? mu.setResourceValues(rv)
    }

    /// App only: the recovery copy in the Keychain (written when it differs from what was read).
    func mirrorToKeychain(secret kcSecret: String?? = .none, lan kcLan: String?? = .none, users kcUsers: [String: String]?? = .none) {
        let curSecret = kcSecret ?? Keychain.read(Keychain.controllerSecretAccount)
        if curSecret != (secret.isEmpty ? nil : secret) { Keychain.write(Keychain.controllerSecretAccount, secret) }
        let curLan = kcLan ?? Keychain.read(Keychain.lanSharePasswordAccount)
        if curLan != (lanPassword.isEmpty ? nil : lanPassword) { Keychain.write(Keychain.lanSharePasswordAccount, lanPassword) }
        let curUsers = kcUsers ?? Keychain.read(Keychain.lanUsersAccount).flatMap { try? JSONDecoder().decode([String: String].self, from: Data($0.utf8)) }
        if (curUsers ?? [:]) != lanUsers {
            let enc = JSONEncoder()
            enc.outputFormatting = [.sortedKeys]
            let s = lanUsers.isEmpty ? "" : (try? enc.encode(lanUsers)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
            Keychain.write(Keychain.lanUsersAccount, s)
        }
    }
}

/// r7 (backlog B02 / R6A-9): one writer at a time for overrides.json + secrets.json across the app, the widget and
/// the extension: flock(2) on <home>/overrides.lock around every load-modify-save, re-entrant within a process.
/// The wait is bounded (2 s) — iOS may suspend a process at any point, and a stuck lock must not hang the others —
/// after which the caller proceeds unlocked (the previous behaviour).
enum OverridesLock {
    private static let mutex = NSRecursiveLock()
    private static var depth = 0
    private static var fd: Int32 = -1

    static func with<T>(_ dir: URL, _ body: () throws -> T) rethrows -> T {
        mutex.lock()
        defer { mutex.unlock() }
        if depth == 0 {
            AppShared.ensureDir(dir)
            let f = open(dir.appendingPathComponent("overrides.lock").path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
            if f >= 0 {
                var locked = flock(f, LOCK_EX | LOCK_NB) == 0
                var waited = 0
                while !locked && waited < 200 {
                    usleep(10_000)
                    waited += 1
                    locked = flock(f, LOCK_EX | LOCK_NB) == 0
                }
                if locked { fd = f } else { close(f) }
            }
        }
        depth += 1
        defer {
            depth -= 1
            if depth == 0 && fd >= 0 {
                flock(fd, LOCK_UN)
                close(fd)
                fd = -1
            }
        }
        return try body()
    }
}

/// Messages the app sends to the tunnel through NETunnelProviderSession.sendProviderMessage.
enum TunnelMessage: String {
    case reload
    case directIP
    case freeMemory
    case version
    /// Ask the tunnel to add the traffic since its last sample to TrafficHistory now.
    case flushStats
    /// Ask the tunnel to write its core-log / memory rings to <home>/diag/ (诊断包).
    case dumpDiagnostics
    /// 按网络切换策略 (v0.9): re-apply netpolicy.json for the current network now.
    case applyNetworkPolicy
    /// v0.18 隧道内存: current / peak / available memory + Tailscale guard status (JSON).
    case memoryStats

    /// Review 6 R6A-3: the extension's reply to `reload` when the new config is applied (anything else is the error).
    static let reloadOK = "ok"
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

/// Why the system stopped the tunnel last time (NEProviderStopReason), in words. Written by the
/// extension in stopTunnel, shown in 诊断 and the diagnostic bundle. Purely informational.
enum TunnelStopReason {
    static var url: URL { AppShared.containerURL.appendingPathComponent("tunnel-last-stop.txt") }

    static func describe(_ raw: Int) -> String {
        switch raw {
        case 0: return String(localized: "无原因")
        case 1: return String(localized: "用户手动断开")
        case 2: return String(localized: "扩展运行失败")
        case 3: return String(localized: "没有可用网络")
        case 4: return String(localized: "网络发生不可恢复的变化")
        case 5: return String(localized: "扩展被停用")
        case 6: return String(localized: "认证被取消")
        case 7: return String(localized: "VPN 配置无效")
        case 8: return String(localized: "空闲超时")
        case 9: return String(localized: "VPN 配置被关闭（在 App 或系统设置里断开）")
        case 10: return String(localized: "VPN 配置被删除")
        case 11: return String(localized: "被其他 VPN 配置取代")
        case 12: return String(localized: "用户注销")
        case 13: return String(localized: "切换了用户")
        case 14: return String(localized: "连接失败")
        case 15: return String(localized: "设备休眠")
        case 16: return String(localized: "App 更新")
        case 17: return String(localized: "内部错误")
        default: return String(localized: "未知原因（\(raw)）")
        }
    }

    static func record(_ raw: Int) {
        let line = "\(ISO8601DateFormatter().string(from: Date()))\t\(raw)"
        try? line.data(using: .utf8)?.write(to: url, options: .atomic)
    }

    /// "原因（时间）" of the last stop, or nil.
    static func last() -> String? {
        guard let s = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let p = s.split(separator: "\t").map(String.init)
        guard p.count == 2, let raw = Int(p[1].trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        let when = ISO8601DateFormatter().date(from: p[0]).map { $0.formatted(date: .abbreviated, time: .standard) } ?? p[0]
        return "\(describe(raw))（\(when)）"
    }
}


/// One CIDR entry of the 连接方式 route lists ("10.0.0.0/8", "fd00::/8", or a bare address = host route).
struct RouteSpec: Equatable {
    let address: String
    let prefix: Int
    let isV6: Bool

    init?(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return nil }
        let parts = t.split(separator: "/", maxSplits: 1).map(String.init)
        // v0.19.2: "/" alone split into [] and parts[0] crashed the app (the 连接方式 editor validates on every
        // keystroke) and the extension (routes are built at start).
        guard let addr = parts.first, !addr.isEmpty else { return nil }
        var a4 = in_addr(), a6 = in6_addr()
        if inet_pton(AF_INET, addr, &a4) == 1 {
            isV6 = false
        } else if inet_pton(AF_INET6, addr, &a6) == 1 {
            isV6 = true
        } else { return nil }
        let maxP = isV6 ? 128 : 32
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...maxP).contains(p) else { return nil }
            prefix = p
        } else {
            prefix = maxP
        }
        address = addr
    }

    /// Dotted subnet mask for IPv4 (NEIPv4Route wants a mask, not a prefix length).
    var mask: String {
        let m: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
        return "\(m >> 24 & 255).\(m >> 16 & 255).\(m >> 8 & 255).\(m & 255)"
    }

    /// Invalid lines of a list (shown by the editor, which refuses to save them).
    static func invalid(_ lines: [String]) -> [String] {
        lines.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty && RouteSpec($0) == nil }
    }
}

/// v0.8 IPv6 "自动": does a physical interface (Wi-Fi en*, cellular pdp_ip*) have a global IPv6 address?
/// Link-local (fe80::/10), ULA (fc00::/7) and loopback don't count; the tunnel's own utun is skipped.
enum NetIPv6 {
    static func physicalNetworkHasGlobalIPv6() -> Bool {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return false }
        defer { freeifaddrs(head) }
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cur {
            defer { cur = p.pointee.ifa_next }
            let name = String(cString: p.pointee.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("pdp_ip"),
                  (p.pointee.ifa_flags & UInt32(IFF_UP)) != 0,
                  let sa = p.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET6) else { continue }
            let bytes: [UInt8] = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { s6 in
                withUnsafeBytes(of: s6.pointee.sin6_addr) { Array($0) }
            }
            guard bytes.count == 16 else { continue }
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { continue }   // fe80::/10
            if (bytes[0] & 0xfe) == 0xfc { continue }                        // fc00::/7
            if bytes.allSatisfy({ $0 == 0 }) || (bytes[0..<15].allSatisfy { $0 == 0 } && bytes[15] == 1) { continue }
            return true
        }
        return false
    }
}
