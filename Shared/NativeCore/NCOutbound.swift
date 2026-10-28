import Foundation

/// A connection target as rules and outbounds see it.
struct NCTarget: Equatable {
    var host: String // domain or IP literal
    var port: Int

    var ip: NCIP? { NCIP(host) }

    /// Whether every proxy wire format can carry this target: SOCKS/VLESS/VMess domains are u8-length-prefixed and
    /// ports are u16 (rv2-proto: oversized values used to trap in `UInt8(...)` or be silently truncated).
    var isWireEncodable: Bool {
        guard (0...65535).contains(port) else { return false }
        if ip != nil { return true }
        let n = host.utf8.count
        return n > 0 && n <= 255
    }

    /// SOCKS / Shadowsocks target encoding: ATYP + address + port (big-endian).
    /// fix/nc-socks-domain-len (#170): the one safe encoding entry — nil when
    /// the target cannot be carried (`isWireEncodable` is false). This used to
    /// `prefix(255)` the domain, silently connecting to a truncated host; every
    /// caller now fails or drops cleanly on nil instead.
    var atypEncoded: Data? {
        guard isWireEncodable else { return nil }
        var out = Data()
        if let ip = ip {
            switch ip {
            case .v4:
                out.append(0x01)
                out.append(contentsOf: ip.bytes)
            case .v6:
                out.append(0x04)
                out.append(contentsOf: ip.bytes)
            }
        } else {
            let utf8 = Array(host.utf8)
            out.append(0x03)
            out.append(UInt8(utf8.count))
            out.append(contentsOf: utf8)
        }
        out.append(UInt8((port >> 8) & 0xff))
        out.append(UInt8(port & 0xff))
        return out
    }
}

/// Stateless wire builders for the simple outbounds (SOCKS5, HTTP CONNECT).
/// Socket I/O lives in the tunnel glue; these stay pure and unit-testable.
enum NCSOCKS5 {
    static func greeting(username: String?, password: String?) -> Data {
        if username != nil {
            return Data([0x05, 0x02, 0x00, 0x02])
        }
        return Data([0x05, 0x01, 0x00])
    }

    static func authRequest(username: String, password: String) -> Data {
        var out = Data([0x01, UInt8(min(username.utf8.count, 255))])
        out.append(contentsOf: username.utf8.prefix(255))
        out.append(UInt8(min(password.utf8.count, 255)))
        out.append(contentsOf: password.utf8.prefix(255))
        return out
    }

    static func connectRequest(target: NCTarget, udp: Bool = false) -> Data? {
        guard let addr = target.atypEncoded else { return nil }
        var out = Data([0x05, udp ? 0x03 : 0x01, 0x00])
        out.append(addr)
        return out
    }

    /// Parse a SOCKS5 response header. Returns (bytesConsumed, replyCode) or nil
    /// when more bytes are needed. Throws nothing; replyCode != 0 means failure.
    /// Reads are startIndex-relative: `data` may be a slice (rv2-proto).
    static func parseResponse(_ data: Data) -> (Int, Int)? {
        guard data.count >= 4 else { return nil }
        let s = data.startIndex
        let atyp = data[s + 3]
        var need: Int
        switch atyp {
        case 0x01: need = 4 + 4 + 2
        case 0x04: need = 4 + 16 + 2
        case 0x03:
            guard data.count >= 5 else { return nil }
            need = 4 + 1 + Int(data[s + 4]) + 2
        default: return nil
        }
        guard data.count >= need else { return nil }
        return (need, Int(data[s + 1]))
    }

    /// A reply whose header can never parse (wrong version or unknown ATYP): fail instead of reading forever.
    static func isMalformedResponse(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let s = data.startIndex
        return data[s] != 0x05 || ![0x01, 0x03, 0x04].contains(data[s + 3])
    }
}

enum NCHTTPProxy {
    static func connectRequest(target: NCTarget, username: String?, password: String?) -> Data {
        let authority = target.ip?.isV4 == false && target.ip != nil ? "[\(target.host)]:\(target.port)" : "\(target.host):\(target.port)"
        var lines = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nProxy-Connection: Keep-Alive\r\n"
        if let u = username {
            let cred = Data("\(u):\(password ?? "")".utf8).base64EncodedString()
            lines += "Proxy-Authorization: Basic \(cred)\r\n"
        }
        lines += "\r\n"
        return Data(lines.utf8)
    }
}

/// Resolves a policy name through proxy groups to a concrete outbound, the way
/// Clash.Meta does: select uses the stored choice, url-test picks the lowest delay,
/// fallback picks the first alive member, load-balance rotates. DIRECT and
/// REJECT are terminal pseudo-policies. Loop-safe via a visited set.
final class NCGroupEngine {
    private let config: NCConfig
    var selections: [String: String] = [:] // group name -> chosen member
    var delays: [String: Int] = [:] // proxy name -> last measured delay ms (nil/<=0 = unknown or dead)
    var alive: [String: Bool] = [:]
    /// Nodes the connector cannot dial (NCSupport.unsupportedReason): groups pick around them (feat/native-core-eval).
    var unsupported: Set<String> = []
    /// Current Wi-Fi SSID, for SUBNET-conditioned groups (Surge SUBNET /
    /// QX ssid policies carried in group fields["subnet"]). The engine
    /// owner supplies it; nil = network unknown.
    var ssidProvider: () -> String? = { nil }
    /// 智能选择 pins (group name -> member), maintained by NCSmartSelector.
    /// For url-test / fallback groups a pin wins over the automatic pick
    /// (and over a stored manual selection, which the scorer would
    /// overwrite on its next pass anyway — the retired bridge through
    /// the group's own Set). A pin whose member is known dead is ignored,
    /// mirroring Clash.Meta dropping a fixed node on health-check failure.
    var smartPins: [String: String] {
        get { lock.lock(); defer { lock.unlock() }; return _smartPins }
        set { lock.lock(); defer { lock.unlock() }; _smartPins = newValue }
    }
    private var _smartPins: [String: String] = [:]

    private func smartPinnedMember(_ g: NCProxyGroup, members: [String]) -> String? {
        guard g.type == "url-test" || g.type == "fallback",
              let pin = smartPins[g.name], members.contains(pin),
              alive[pin] ?? true else { return nil }
        return pin
    }
    private var rrCounters: [String: Int] = [:]
    private var lastTouched: [String: Date] = [:]
    var onGroupTouched: ((String) -> Void)?
    private let lock = NSRecursiveLock()

    func lastTouch(for groupName: String) -> Date? {
        lock.lock()
        defer { lock.unlock() }
        return lastTouched[groupName]
    }

    /// Throttle bookkeeping for the touch notification; caller holds the lock.
    private func noteTouchLocked(_ groupName: String) -> Bool {
        let now = Date()
        if let last = lastTouched[groupName], now.timeIntervalSince(last) < 1.0 {
            return false
        }
        lastTouched[groupName] = now
        return true
    }

    func recordDelay(name: String, ms: Int) {
        lock.lock()
        defer { lock.unlock() }
        if ms > 0 {
            delays[name] = ms
            alive[name] = true
        } else {
            delays[name] = 0
            alive[name] = false
        }
    }

    func recordFailure(name: String) {
        lock.lock()
        defer { lock.unlock() }
        delays[name] = 0
        alive[name] = false
    }

    @discardableResult
    func setSelection(group: String, member: String?) -> [String: String] {
        lock.lock()
        defer { lock.unlock() }
        if let member {
            selections[group] = member
        } else {
            selections.removeValue(forKey: group)
        }
        return selections
    }

    /// Locked point-in-time copies for status endpoints and state handoff:
    /// the health-check scheduler writes delays/alive from its own queue, so
    /// readers must not touch the dictionaries directly.
    func statusSnapshot() -> (selections: [String: String], delays: [String: Int], alive: [String: Bool]) {
        lock.lock()
        defer { lock.unlock() }
        return (selections, delays, alive)
    }

    /// The member a SUBNET condition forces for this group right now:
    /// an exact SSID hit beats DEFAULT, which beats manual selection —
    /// auto-switching by network is the group's whole purpose.
    private func subnetForcedMember(_ g: NCProxyGroup) -> String? {
        guard let map = g.fields["subnet"]?.object, !map.isEmpty else { return nil }
        if let ssid = ssidProvider(), let hit = map[ssid]?.string, g.proxies.contains(hit) {
            return hit
        }
        if let def = map["DEFAULT"]?.string, g.proxies.contains(def) { return def }
        return nil
    }

    init(config: NCConfig) { self.config = config }

    enum Resolution: Equatable {
        case direct
        case reject
        case proxy(NCProxy)
        /// Ordered chain of ≥2 proxies: dial member 0 directly, tunnel
        /// through it to member 1's server, and so on; the last member
        /// connects to the real target. Produced by relay groups and by
        /// `dialer-proxy` expansion.
        case chain([NCProxy])
        case unknown(String)
    }

    func resolve(_ policy: String) -> Resolution {
        lock.lock()
        defer { lock.unlock() }
        return resolve(policy, visited: [])
    }

    private func resolve(_ policy: String, visited: Set<String>) -> Resolution {
        switch policy.uppercased() {
        case "DIRECT": return .direct
        case "REJECT", "REJECT-DROP": return .reject
        default: break
        }
        if let p = config.proxyMap[policy] { return expandDialer(p, visited: visited) }
        guard let g = config.groupMap[policy] else { return .unknown(policy) }
        guard !visited.contains(g.name) else { return .unknown(policy) }
        var visited = visited
        visited.insert(g.name)
        if noteTouchLocked(g.name) {
            onGroupTouched?(g.name)
        }
        if g.type == "relay" {
            // Every member must itself resolve to proxy material; the
            // concatenation is the chain, in group order.
            var chain: [NCProxy] = []
            for member in g.proxies {
                switch resolve(member, visited: visited) {
                case .proxy(let p): chain.append(p)
                case .chain(let ps): chain.append(contentsOf: ps)
                default: return .unknown(policy)
                }
            }
            if chain.count == 1 { return .proxy(chain[0]) }
            return chain.isEmpty ? .unknown(policy) : .chain(chain)
        }
        let all = g.proxies
        guard !all.isEmpty else { return .unknown(policy) }
        let usable = all.filter { !unsupported.contains($0) }
        let members = usable.isEmpty ? all : usable
        let chosen: String
        if let forced = subnetForcedMember(g) {
            chosen = forced
        } else if let pin = smartPinnedMember(g, members: members) {
            chosen = pin
        } else if let sel = selections[g.name], members.contains(sel) {
            chosen = sel // explicit choice / pin (controller PUT) wins for every type
        } else {
            switch g.type {
            case "url-test":
                chosen = members.min(by: { delayOf($0) < delayOf($1) }) ?? members[0]
            case "fallback":
                chosen = members.first(where: { alive[$0] ?? true }) ?? members[0]
            case "load-balance":
                let i = (rrCounters[g.name] ?? 0) % members.count
                rrCounters[g.name] = i + 1
                chosen = members[i]
            default: // select and anything else: first member
                chosen = members[0]
            }
        }
        return resolve(chosen, visited: visited)
    }

    /// `dialer-proxy`: this proxy's server is itself reached through the
    /// named outbound (a proxy or a group). Expands to a chain with the
    /// dialer first; loops degrade to .unknown via the visited set.
    private func expandDialer(_ proxy: NCProxy, visited: Set<String>) -> Resolution {
        guard let dialerName = proxy.fields["dialer-proxy"]?.string, !dialerName.isEmpty else {
            return .proxy(proxy)
        }
        let key = "dialer:\(proxy.name)"
        guard !visited.contains(key) else { return .unknown(proxy.name) }
        var visited = visited
        visited.insert(key)
        switch resolve(dialerName, visited: visited) {
        case .proxy(let d): return .chain([d, proxy])
        case .chain(let ds): return .chain(ds + [proxy])
        default: return .unknown(proxy.name)
        }
    }

    /// The member a group would route to right now (one level, no recursion).
    func currentMember(of group: NCProxyGroup) -> String? {
        lock.lock()
        defer { lock.unlock() }
        let all = group.proxies
        guard !all.isEmpty else { return nil }
        let usable = all.filter { !unsupported.contains($0) }
        let members = usable.isEmpty ? all : usable
        if let forced = subnetForcedMember(group) { return forced }
        if let pin = smartPinnedMember(group, members: members) { return pin }
        if let sel = selections[group.name], members.contains(sel) { return sel }
        switch group.type {
        case "url-test":
            return members.min(by: { delayOf($0) < delayOf($1) }) ?? members[0]
        case "fallback":
            return members.first(where: { alive[$0] ?? true }) ?? members[0]
        case "load-balance":
            return members[(rrCounters[group.name] ?? 0) % members.count]
        default:
            return members[0]
        }
    }

    private func delayOf(_ name: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        guard let d = delays[name], d > 0, alive[name] ?? true else { return Int.max }
        return d
    }
}
