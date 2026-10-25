import Foundation

/// E-B1 stage 1: the override inputs of the runtime-config builder —
/// a port of the bridge's readOverrides pipeline (bridge/bridge.go
/// readOverrides + defaultOverrides sanitization, bridge/secrets.go,
/// bridge/secretguard.go, bridge/dns.go readDNSOverride,
/// bridge/localdns.go readLocalDNS) for NCRuntimeBuilder.
///
/// The overrides.json payload itself decodes through the app's own
/// CoreOverrides model (Shared/AppShared.swift), whose defaults match
/// Go's defaultOverrides; this file adds the parts only the Go side
/// did: the secrets.json overlay, controller-secret generation with
/// write-back, the extra range clamps, and the dns.json / localdns.json
/// attachments.

// MARK: - dns.json (bridge DNSOverride)

struct NCDNSOverride: Codable {
    struct FallbackRule: Codable {
        var geoip: Bool = false
        var geoipCode: String = ""
        var ipcidr: [String] = []
        var domain: [String] = []
        var geosite: [String] = []
    }
    struct Policy: Codable {
        var match: String = ""
        var servers: [String] = []
    }
    var enabled: Bool = false
    var nameserver: [String] = []
    var foreign: [String] = []
    var split: Bool = false
    var defaultNameserver: [String] = []
    var directNameserver: [String] = []
    var proxyNameserver: [String] = []
    var fallback: [String] = []
    var fallbackFilter: FallbackRule = FallbackRule()
    var fakeIPRange: String = ""
    var fakeIPFilter: [String] = []
    var fakeIPFilterMode: String = ""
    var policy: [Policy] = []
    var preferH3: Bool = false
    var respectRules: Bool = false
    var useHosts: Bool? = nil
    var useSystemHosts: Bool? = nil
    var cacheAlgorithm: String = ""
    var includeSystem: Bool = false
}

// MARK: - localdns.json (bridge LocalDNS)

struct NCLocalDNS: Codable {
    struct HostEntry: Codable {
        var domain: String = ""
        var value: String = ""
        var disabled: Bool = false
    }
    var hosts: [HostEntry] = []
    var realIP: [String] = []
}

// MARK: - secrets.json (bridge coreSecrets)

struct NCCoreSecrets: Codable {
    var secret: String = ""
    var lanPassword: String = ""
    var lanUsers: [String: String] = [:]
}

// MARK: - Resolved builder settings

struct NCRuntimeSettings {
    var core: CoreOverrides
    var dns: NCDNSOverride?
    var local: NCLocalDNS?
    var home: String
    var manualPath: String

    /// Go's IPv6 resolution for the build. Note: Go switches on
    /// ipv6Mode with "auto" reading an atomic the extension was meant
    /// to set through the bridge; nothing on the eval line sets it in
    /// the app process, so Go effectively built with false. The app
    /// has a real check (CoreOverrides.resolvedIPv6, the same one the
    /// NE settings use), and the runtime config should agree with the
    /// NE settings, so "auto" resolves through it here.
    var ipv6: Bool { core.resolvedIPv6() }

    private static var processSecret: String?

    /// bridge readOverrides: defaults -> overrides.json -> secrets
    /// overlay -> ensure secret -> sanitize -> attach dns/local.
    static func load(home: String) -> NCRuntimeSettings {
        var o = CoreOverrides()
        let overridesURL = URL(fileURLWithPath: home).appendingPathComponent("overrides.json")
        if let data = try? Data(contentsOf: overridesURL),
           let decoded = try? JSONDecoder().decode(CoreOverrides.self, from: data) {
            o = decoded
        }
        // applySecrets: values already in overrides.json win.
        let secrets = readSecrets(home: home)
        if let s = secrets {
            if o.secret.isEmpty { o.secret = s.secret }
            if o.lanAuth.password.isEmpty { o.lanAuth.password = s.lanPassword }
            for i in o.lanUsers.indices where o.lanUsers[i].password.isEmpty {
                o.lanUsers[i].password = s.lanUsers[o.lanUsers[i].username] ?? ""
            }
        }
        if o.secret.trimmingCharacters(in: .whitespaces).isEmpty {
            o.secret = ensureControllerSecret(home: home)
        }
        // Sanitize (bridge readOverrides tail).
        if o.controllerPort <= 0 || o.controllerPort > 65535 { o.controllerPort = 9090 }
        if o.dnsMode != "redir-host" { o.dnsMode = "fake-ip" }
        if o.memoryLimitMB < 20 || o.memoryLimitMB > 30 { o.memoryLimitMB = 26 }
        if !validTestURL(o.testURL) { o.testURL = "https://www.gstatic.com/generate_204" }
        if o.testTimeoutMs < 1000 || o.testTimeoutMs > 30000 { o.testTimeoutMs = 5000 }
        if o.tunnelMode != "proxy" && o.tunnelMode != "mix" { o.tunnelMode = "tun" }
        if o.blockQUIC != "off" && o.blockQUIC != "always" { o.blockQUIC = "nondirect" }
        if o.udpFallback != "reject" { o.udpFallback = "direct" }
        if !["ipv4-prefer", "ipv6-prefer", "ipv4", "ipv6"].contains(o.ipPreference) { o.ipPreference = "" }
        o.lanAuth.username = o.lanAuth.username.trimmingCharacters(in: .whitespaces)
        if o.mixedPort <= 0 || o.mixedPort > 65535 || o.mixedPort == o.controllerPort { o.mixedPort = 7890 }
        if o.tunMTU < 1280 || o.tunMTU > 9000 { o.tunMTU = 4064 }
        return NCRuntimeSettings(
            core: o,
            dns: readDNSOverride(home: home),
            local: readLocalDNS(home: home),
            home: home,
            manualPath: home.isEmpty ? "" : URL(fileURLWithPath: home)
                .appendingPathComponent("profiles/manual-nodes.yaml").path)
    }

    static func validTestURL(_ s: String) -> Bool {
        guard let u = URL(string: s.trimmingCharacters(in: .whitespaces)),
              let scheme = u.scheme, scheme == "http" || scheme == "https",
              let host = u.host, !host.isEmpty else { return false }
        return true
    }

    static func readSecrets(home: String) -> NCCoreSecrets? {
        if home.isEmpty { return nil }
        let url = URL(fileURLWithPath: home).appendingPathComponent("secrets.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(NCCoreSecrets.self, from: data)
    }

    /// bridge ensureControllerSecret: without an overrides.json nothing
    /// is persisted and a per-process secret is used; otherwise a new
    /// random secret is written back into secrets.json (other keys
    /// kept, file 0600).
    static func ensureControllerSecret(home: String) -> String {
        if home.isEmpty { return processSecretValue() }
        let homeURL = URL(fileURLWithPath: home)
        if !FileManager.default.fileExists(atPath: homeURL.appendingPathComponent("overrides.json").path) {
            return processSecretValue()
        }
        let secretsURL = homeURL.appendingPathComponent("secrets.json")
        var raw: [String: Any] = [:]
        if let data = try? Data(contentsOf: secretsURL) {
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return processSecretValue()
            }
            raw = obj
        }
        if let s = raw["secret"] as? String, !s.trimmingCharacters(in: .whitespaces).isEmpty {
            return s
        }
        let s = randomSecret()
        raw["secret"] = s
        if let data = try? JSONSerialization.data(withJSONObject: raw),
           (try? data.write(to: secretsURL, options: [.atomic])) != nil {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secretsURL.path)
            return s
        }
        return processSecretValue()
    }

    /// bridge randomSecret: 16 random bytes, hex.
    static func randomSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        if !ok {
            return String(format: "tern-%llx-%d", UInt64(Date().timeIntervalSince1970 * 1e9), ProcessInfo.processInfo.processIdentifier)
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func processSecretValue() -> String {
        if let s = processSecret { return s }
        let s = randomSecret()
        processSecret = s
        return s
    }

    /// bridge readDNSOverride: nil unless the file parses AND enabled.
    static func readDNSOverride(home: String) -> NCDNSOverride? {
        if home.isEmpty { return nil }
        let url = URL(fileURLWithPath: home).appendingPathComponent("dns.json")
        guard let data = try? Data(contentsOf: url),
              let d = try? JSONDecoder().decode(NCDNSOverride.self, from: data),
              d.enabled else { return nil }
        return d
    }

    /// bridge readLocalDNS.
    static func readLocalDNS(home: String) -> NCLocalDNS? {
        if home.isEmpty { return nil }
        let url = URL(fileURLWithPath: home).appendingPathComponent("localdns.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(NCLocalDNS.self, from: data)
    }
}
