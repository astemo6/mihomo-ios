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
            manualPath: manualNodesPath(home: home))
    }

    /// bridge runtimeinputs.go manualNodesPath:
    /// filepath.Join(filepath.Dir(home), "profiles", "manual-nodes.yaml").
    /// home is <container>/mihomo; the App writes the manual profile to
    /// AppShared.profileURL(id: "manual-nodes") = <container>/profiles/manual-nodes.yaml,
    /// so the store lives beside home, not under it (review R-1).
    static func manualNodesPath(home: String) -> String {
        if home.isEmpty { return "" }
        // Go filepath.Dir: drop everything after the last separator
        // (a trailing "/" leaves the path itself: Dir("/a/b/") == "/a/b").
        // No standardizingPath: it may strip the container's /private prefix.
        let dir: String
        if let r = home.range(of: "/", options: .backwards) {
            let head = String(home[home.startIndex..<r.lowerBound])
            dir = head.isEmpty ? "/" : head
        } else {
            dir = "."
        }
        if dir == "." { return "profiles/manual-nodes.yaml" }
        return ((dir as NSString).appendingPathComponent("profiles") as NSString)
            .appendingPathComponent("manual-nodes.yaml")
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

    /// bridge ensureControllerSecret (secretguard.go): without an overrides.json
    /// nothing is persisted and a per-process secret is used; otherwise a new
    /// random secret is written back into secrets.json (other keys kept, file
    /// 0600). Review R-5: the read-modify-write holds secrets.json's NCPathLock
    /// (Go `defer lockPath(sp)()`), and the branches follow Go exactly:
    ///   - read OK but not a JSON object      -> process secret
    ///   - read failed, file does not exist   -> start from {} and write back
    ///   - read failed for any other reason   -> process secret (never clobber
    ///     a file we could not read)
    ///   - write-back failed                  -> process secret
    static func ensureControllerSecret(home: String) -> String {
        if home.isEmpty { return processSecretValue() }
        let homeURL = URL(fileURLWithPath: home)
        if !FileManager.default.fileExists(atPath: homeURL.appendingPathComponent("overrides.json").path) {
            NSLog("[Mihomo] 控制器密钥为空且 overrides.json 不存在，本次使用随机密钥")
            return processSecretValue()
        }
        let secretsURL = homeURL.appendingPathComponent("secrets.json")
        return NCPathLock.shared.withLock(for: secretsURL.path) { () -> String in
            var raw: [String: Any] = [:]
            do {
                let data = try Data(contentsOf: secretsURL)
                guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                    NSLog("[Mihomo] 控制器密钥为空且 secrets.json 无法解析，本次使用随机密钥")
                    return processSecretValue()
                }
                raw = obj
            } catch {
                if !isNotExist(error) {
                    NSLog("[Mihomo] 控制器密钥为空且无法读取 secrets.json，本次使用随机密钥")
                    return processSecretValue()
                }
            }
            if let s = raw["secret"] as? String, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return s // another writer filled it meanwhile
            }
            let s = randomSecret()
            raw["secret"] = s
            do {
                let data = try JSONSerialization.data(withJSONObject: raw)
                try NCRuntimeFiles.writeAtomic(data, to: secretsURL.path)
            } catch {
                NSLog("[Mihomo] 控制器密钥为空，写回 secrets.json 失败（%@），本次使用随机密钥", error.localizedDescription)
                return processSecretValue()
            }
            _ = chmod(secretsURL.path, 0o600)
            NSLog("[Mihomo] 控制器密钥为空，已生成随机密钥并写回 secrets.json")
            return s
        }
    }

    /// Go os.IsNotExist for a Data(contentsOf:) failure.
    private static func isNotExist(_ error: Error) -> Bool {
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain
            && (ns.code == NSFileReadNoSuchFileError || ns.code == NSFileNoSuchFileError) { return true }
        if ns.domain == NSPOSIXErrorDomain && ns.code == Int(ENOENT) { return true }
        if let under = ns.userInfo[NSUnderlyingErrorKey] as? NSError,
           under.domain == NSPOSIXErrorDomain, under.code == Int(ENOENT) { return true }
        return false
    }

    /// bridge randomSecret: 16 random bytes, hex.
    static func randomSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        if !ok {
            return String(format: "tern-%llx-%d", UInt64(Date().timeIntervalSince1970 * 1e9), ProcessInfo.processInfo.processIdentifier)
        }
        return bytes.ncHex
    }

    private static let processSecretLock = NSLock()

    /// bridge processSecret (sync.Once).
    static func processSecretValue() -> String {
        processSecretLock.lock()
        defer { processSecretLock.unlock() }
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
