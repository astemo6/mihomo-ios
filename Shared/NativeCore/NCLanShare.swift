import Foundation

/// feat/nc-lan-share (需同步 feat/nc-kernel): 局域网共享 policy for the NativeCore local mixed port (NCLocalProxy),
/// with Clash.Meta's semantics for the top-level inbound keys the app writes into the runtime config
/// (App/Core/NCRuntimeDNS.swift NCRuntimeSteps.applyInbound, port of bridge applyInbound):
///   - `allow-lan` false → the listener binds 127.0.0.1 whatever `bind-address` says (Clash.Meta genAddr);
///   - `bind-address` "*" (Clash.Meta default) / "" / 0.0.0.0 / :: → every interface; a loopback address → loopback;
///     another IP literal → that address only;
///   - `authentication` ["user:pass", …] — split at the FIRST ':' (strings.Cut, so a password may contain ':'),
///     entries without ':' are ignored, a later duplicate user replaces the earlier one (sync.Map Store);
///     no valid entry = no authentication;
///   - `skip-auth-prefixes` — source addresses that never authenticate (the app always writes 127.0.0.0/8, ::1/128);
///   - `lan-allowed-ips` (default 0.0.0.0/0 + ::/0) / `lan-disallowed-ips` — source filter for LAN clients.
///     Divergence from Clash.Meta, on purpose: loopback is always admitted, so the system proxy NEProxySettings points
///     at 127.0.0.1 keeps working even when a profile's own lan-allowed-ips leaves loopback out.
/// Pure value type (parsing + decisions); NCLocalProxy does the I/O. Small: a few strings and CIDRs.
struct NCLanShare: Equatable {
    enum Bind: Equatable {
        case loopback
        case any
        case address(String)
    }

    var allowLan = false
    var bindAddress = "*"
    /// username → password. Empty = no authentication.
    var users: [String: String] = [:]
    var skipAuth: [NCCIDR] = []
    /// Empty = every source (Clash.Meta's default 0.0.0.0/0, ::/0).
    var allowed: [NCCIDR] = []
    var disallowed: [NCCIDR] = []

    static let loopbackPrefixes = ["127.0.0.0/8", "::1/128"]
    /// Same list as NCRuntimeSteps.lanPrivatePrefixes (仅允许局域网设备).
    static let privatePrefixes = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
    ]

    var bind: Bind { Self.bind(allowLan: allowLan, bindAddress: bindAddress) }
    var requiresAuth: Bool { !users.isEmpty }

    // MARK: parsing

    /// From the runtime config's top level (NCConfig.raw). nil when the config does not say `allow-lan` at all
    /// (a runtime.conf import path) — the caller then falls back to `from(overrides:)`.
    static func from(raw: [String: NCJSONValue]) -> NCLanShare? {
        guard let allow = raw["allow-lan"].flatMap(boolValue) else { return nil }
        var s = NCLanShare()
        s.allowLan = allow
        if let b = raw["bind-address"]?.string { s.bindAddress = b }
        s.users = parseAuthentication(strings(raw["authentication"]))
        s.skipAuth = cidrs(strings(raw["skip-auth-prefixes"]))
        s.allowed = cidrs(strings(raw["lan-allowed-ips"]))
        s.disallowed = cidrs(strings(raw["lan-disallowed-ips"]))
        return s
    }

    /// From the app's settings (更多 → 连接方式 → 局域网共享), the same translation applyInbound makes.
    static func from(overrides o: CoreOverrides) -> NCLanShare {
        var s = NCLanShare()
        s.skipAuth = cidrs(loopbackPrefixes)
        guard o.allowLan else {
            s.bindAddress = "127.0.0.1" // applyInbound writes this for 仅代理 / 混合 without sharing
            return s
        }
        s.allowLan = true
        s.bindAddress = "*"
        s.users = parseAuthentication(credentials(main: o.lanAuth, extra: o.lanUsers))
        s.allowed = o.lanLocalOnly ? cidrs(privatePrefixes) : []
        return s
    }

    /// bridge lanCredentials (NCRuntimeSteps.lanCredentials): the main user, then 其他用户 with a non-empty trimmed
    /// name without ':' and a password, first occurrence of a name wins.
    static func credentials(main: CoreOverrides.LanAuth, extra: [CoreOverrides.LanAuth]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        let mainName = main.username.trimmingCharacters(in: .whitespaces)
        if !mainName.isEmpty && !main.password.isEmpty {
            out.append(mainName + ":" + main.password)
            seen.insert(mainName)
        }
        for u in extra {
            let name = u.username.trimmingCharacters(in: .whitespaces)
            if name.isEmpty || u.password.isEmpty || name.contains(":") || seen.contains(name) { continue }
            seen.insert(name)
            out.append(name + ":" + u.password)
        }
        return out
    }

    /// Clash.Meta `authentication`: "user:pass", cut at the first ':'.
    static func parseAuthentication(_ entries: [String]) -> [String: String] {
        var users: [String: String] = [:]
        for e in entries {
            guard let cut = e.firstIndex(of: ":") else { continue }
            let user = String(e[..<cut])
            let pass = String(e[e.index(after: cut)...])
            users[user] = pass
        }
        return users
    }

    /// Clash.Meta genAddr: allow-lan off → 127.0.0.1; "*" → all interfaces; otherwise the host given.
    static func bind(allowLan: Bool, bindAddress: String) -> Bind {
        guard allowLan else { return .loopback }
        var h = bindAddress.trimmingCharacters(in: .whitespaces)
        if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        if h.isEmpty || h == "*" || h == "0.0.0.0" || h == "::" { return .any }
        if h.lowercased() == "localhost" { return .loopback }
        guard let ip = NCIP(h) else { return .any } // a host name: Clash.Meta would fail to listen; keep sharing on
        if isLoopback(ip) { return .loopback }
        return .address(ip.string)
    }

    // MARK: decisions

    /// Source address of a client as NWEndpoint prints it ("192.168.1.5", "fe80::1%en0", "::ffff:10.0.0.2").
    static func sourceIP(_ host: String) -> NCIP? {
        var h = host
        if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) }
        if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        guard let ip = NCIP(h) else { return nil }
        if case .v6(let b) = ip, b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff {
            return NCIP(bytes: Array(b[12..<16]))
        }
        return ip
    }

    static func isLoopback(_ ip: NCIP) -> Bool {
        switch ip {
        case .v4(let v): return v >> 24 == 127
        case .v6(let b): return b == [UInt8](repeating: 0, count: 15) + [1]
        }
    }

    /// May this client use the port at all (Clash.Meta IsRemoteAddrDisAllowed, plus loopback always in)?
    /// An address that does not parse is admitted (Clash.Meta: SetRemoteAddr error → not disallowed).
    func admits(_ source: NCIP?) -> Bool {
        guard let ip = source else { return allowLan }
        if Self.isLoopback(ip) { return true }
        guard allowLan else { return false }
        if !allowed.isEmpty, !allowed.contains(where: { $0.contains(ip) }) { return false }
        return !disallowed.contains(where: { $0.contains(ip) })
    }

    /// Must this client authenticate (users configured and the source not under skip-auth-prefixes)?
    func needsAuth(_ source: NCIP?) -> Bool {
        guard requiresAuth else { return false }
        guard let ip = source else { return true }
        return !skipAuth.contains(where: { $0.contains(ip) })
    }

    func verify(user: String, password: String) -> Bool {
        guard let p = users[user] else { return false }
        return p == password
    }

    /// `Proxy-Authorization` value "Basic base64(user:pass)" → (user, pass); nil when not Basic / not decodable.
    static func parseBasic(_ value: String) -> (user: String, password: String)? {
        let v = value.trimmingCharacters(in: .whitespaces)
        guard v.count > 6, v.prefix(6).lowercased() == "basic " else { return nil }
        let token = v.dropFirst(6).trimmingCharacters(in: .whitespaces)
        guard let data = Data(base64Encoded: token, options: .ignoreUnknownCharacters),
              let text = String(data: data, encoding: .utf8), let cut = text.firstIndex(of: ":") else { return nil }
        return (String(text[..<cut]), String(text[text.index(after: cut)...]))
    }

    /// HTTP head lines (after the request line) → whether they carry valid proxy credentials.
    func verifyHTTP(headerLines: [String]) -> Bool {
        for line in headerLines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            guard line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "proxy-authorization" else { continue }
            if let c = Self.parseBasic(String(line[line.index(after: colon)...])), verify(user: c.user, password: c.password) {
                return true
            }
        }
        return false
    }

    enum SocksUserPass: Equatable {
        case needMore
        case invalid
        case ok(consumed: Int, user: String, password: String)
    }

    /// RFC 1929 username/password request: VER(1)=0x01 ULEN UNAME PLEN PASSWD.
    static func parseSocksUserPass(_ b: [UInt8]) -> SocksUserPass {
        guard b.count >= 2 else { return .needMore }
        guard b[0] == 0x01 else { return .invalid }
        let ulen = Int(b[1])
        guard b.count >= 2 + ulen + 1 else { return .needMore }
        let plen = Int(b[2 + ulen])
        let total = 3 + ulen + plen
        guard b.count >= total else { return .needMore }
        let user = String(decoding: b[2..<(2 + ulen)], as: UTF8.self)
        let pass = String(decoding: b[(3 + ulen)..<total], as: UTF8.self)
        return .ok(consumed: total, user: user, password: pass)
    }

    /// Port the shared listener uses: the runtime config's `mixed-port` when valid, else the app setting.
    static func mixedPort(raw: [String: NCJSONValue], fallback: Int) -> Int {
        if let p = raw["mixed-port"]?.int, (1...65535).contains(p) { return p }
        return fallback
    }

    /// The listener the tunnel should run. `needLocal` = 仅代理 / VPN 混合 (the system proxy points at loopback).
    /// nil = no listener (TUN-only without 局域网共享).
    static func plan(needLocal: Bool, port: Int, lan: NCLanShare) -> (port: Int, bind: Bind)? {
        guard (1...65535).contains(port) else { return nil }
        if lan.allowLan { return (port, lan.bind) }
        if needLocal { return (port, .loopback) }
        return nil
    }

    // MARK: helpers

    private static func boolValue(_ v: NCJSONValue) -> Bool? {
        switch v {
        case .bool(let b): return b
        case .string(let s):
            switch s.lowercased() {
            case "true", "yes", "on": return true
            case "false", "no", "off": return false
            default: return nil
            }
        default: return nil
        }
    }

    private static func strings(_ v: NCJSONValue?) -> [String] {
        guard let v else { return [] }
        if let s = v.string { return [s] }
        return v.array?.compactMap { $0.string } ?? []
    }

    private static func cidrs(_ list: [String]) -> [NCCIDR] {
        list.compactMap { NCCIDR($0.trimmingCharacters(in: .whitespaces)) }
    }
}
