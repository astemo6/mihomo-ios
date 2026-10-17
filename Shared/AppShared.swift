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
    /// jsdelivr (testingcf CDN, default) · fastly · github
    var geoMirror: String = "jsdelivr"
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

    struct LanAuth: Codable, Equatable {
        var username: String = ""
        var password: String = ""
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
        case tunnelMode, mixedPort, tunMTU, geoMirror, geoURLs, mergeManual, safeMode
        case testURL, testTimeoutMs, overrideHealthCheck
        case includedRoutes, excludedRoutes, skipProxy, blockQUIC
        case includeAllNetworks, excludeLocalNetworks, excludeAPNs, excludeCellularServices, excludeDeviceCommunication
        case lanAuth, lanLocalOnly, ipv6Mode, ipPreference
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
        if !["dual", "ipv4-prefer", "ipv6-prefer", "ipv4", "ipv6"].contains(ipPreference) { ipPreference = d.ipPreference }
        if !["off", "nondirect", "always"].contains(blockQUIC) { blockQUIC = d.blockQUIC }
        if !Self.isValidTestURL(testURL) { testURL = d.testURL }
        if !(1000...30000).contains(testTimeoutMs) { testTimeoutMs = d.testTimeoutMs }
        if tunnelMode != "proxy" && tunnelMode != "mix" { tunnelMode = "tun" }
        if !(1280...9000).contains(tunMTU) { tunMTU = d.tunMTU }
        if !(1...65535).contains(mixedPort) { mixedPort = d.mixedPort }
        if !Self.memoryLimitRange.contains(memoryLimitMB) { memoryLimitMB = d.memoryLimitMB }
    }

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
        var me = self
        me.ipv6 = ipv6Mode != "off"
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        if let data = try? enc.encode(me) {
            try? data.write(to: AppShared.overridesURL, options: .atomic)
        }
    }

    static func randomSecret() -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<32).map { _ in chars.randomElement() ?? "x" })
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
        let addr = parts[0]
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
