import Foundation

/// E-B1 stage 3g: the DNS / inbound / startup / netextras steps —
/// ports of the retired bridge (applyDNSOverride,
/// defaultProxyServerNameserver), localdns (applyLocalDNS,
/// applyInbound, lanCredentials), inbounds
/// (sanitizeProfileInbounds), startup (geoxFor,
/// rewriteProviderURLs), confimport (rewriteConvertProviders),
/// memshed (capDNSCache), memtune (overrideHealthCheckURL,
/// applyQUICBlock), ipv6 (applyIPPreference), netextras
/// (applyUDPFallback) and probe (applyProbe).
///
/// nameserver-policy order: the old core threads an ordered YAML node
/// through runtime.yaml, but the artifact the tunnel consumes
/// (nativecore-runtime.json) is re-decoded into a map and sorted
/// there too — so the policy is a plain dictionary here, with the
/// same JSON-seam result.

extension NCRuntimeSteps {

    // MARK: - IP helpers (netip stand-ins)

    static func parseIP(_ s: String) -> (v4: Bool, bytes: [UInt8])? {
        var buf4 = [UInt8](repeating: 0, count: 4)
        if s.withCString({ inet_pton(AF_INET, $0, &buf4) }) == 1 { return (true, buf4) }
        var buf6 = [UInt8](repeating: 0, count: 16)
        if s.withCString({ inet_pton(AF_INET6, $0, &buf6) }) == 1 { return (false, buf6) }
        return nil
    }

    static func isLoopbackAddr(_ s: String) -> Bool {
        guard let ip = parseIP(s) else { return false }
        if ip.v4 { return ip.bytes[0] == 127 }
        return ip.bytes == [UInt8](repeating: 0, count: 15) + [1]
    }

    // MARK: - dns

    static func cleanList(_ inList: [String]) -> [NCJSONValue] {
        inList.map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .map { NCJSONValue.string($0) }
    }

    static func withSystemNameserver(_ list: [NCJSONValue]) -> [NCJSONValue] {
        if list.contains(.string("system")) { return list }
        return list + [.string("system")]
    }

    /// bridge applyDNSOverride.
    static func applyDNSOverride(
        _ dns: inout [String: NCJSONValue],
        _ d: NCDNSOverride?,
        mode: String
    ) {
        guard let d else { return }
        var domestic = cleanList(d.nameserver)
        var foreign = cleanList(d.foreign)
        if domestic.isEmpty && foreign.isEmpty { return }
        if domestic.isEmpty { domestic = foreign }
        if foreign.isEmpty { foreign = domestic }
        if d.includeSystem { domestic = withSystemNameserver(domestic) }
        var policyKeys: [String] = []
        var policy: [String: NCJSONValue] = [:]
        func policyAdd(_ k: String, _ v: [NCJSONValue]) {
            if policy[k] == nil { policyKeys.append(k) }
            policy[k] = .array(v)
        }
        if d.split {
            dns["nameserver"] = .array(foreign)
            policyAdd("geosite:cn,private", domestic)
            if dns["proxy-server-nameserver"] == nil || d.proxyNameserver.isEmpty {
                dns["proxy-server-nameserver"] = .array(domestic)
            }
        } else {
            dns["nameserver"] = .array(domestic)
        }
        for p in d.policy {
            let m = p.match.trimmingCharacters(in: .whitespaces)
            if !m.isEmpty {
                let sv = cleanList(p.servers)
                if !sv.isEmpty { policyAdd(m, sv) }
            }
        }
        _ = policyKeys // order does not survive the JSON seam (see header)
        if !policy.isEmpty {
            dns["nameserver-policy"] = .object(policy)
        } else {
            dns.removeValue(forKey: "nameserver-policy")
        }
        let defNS = cleanList(d.defaultNameserver)
        if !defNS.isEmpty { dns["default-nameserver"] = .array(defNS) }
        let proxyNS = cleanList(d.proxyNameserver)
        if !proxyNS.isEmpty { dns["proxy-server-nameserver"] = .array(proxyNS) }
        let directNS = cleanList(d.directNameserver)
        if !directNS.isEmpty {
            dns["direct-nameserver"] = .array(directNS)
        } else {
            dns.removeValue(forKey: "direct-nameserver")
        }
        let fb = cleanList(d.fallback)
        if !fb.isEmpty {
            dns["fallback"] = .array(fb)
            var ff: [String: NCJSONValue] = ["geoip": .bool(d.fallbackFilter.geoip)]
            var code = d.fallbackFilter.geoipCode.trimmingCharacters(in: .whitespaces).uppercased()
            if code.isEmpty { code = "CN" }
            ff["geoip-code"] = .string(code)
            let ipcidr = cleanList(d.fallbackFilter.ipcidr)
            if !ipcidr.isEmpty { ff["ipcidr"] = .array(ipcidr) }
            let domain = cleanList(d.fallbackFilter.domain)
            if !domain.isEmpty { ff["domain"] = .array(domain) }
            let geosite = cleanList(d.fallbackFilter.geosite)
            if !geosite.isEmpty { ff["geosite"] = .array(geosite) }
            dns["fallback-filter"] = .object(ff)
        } else {
            dns.removeValue(forKey: "fallback")
            dns.removeValue(forKey: "fallback-filter")
        }
        if mode == "fake-ip" {
            let r = d.fakeIPRange.trimmingCharacters(in: .whitespaces)
            if !r.isEmpty, let slash = r.firstIndex(of: "/") {
                let addr = String(r[..<slash])
                let bits = Int(r[r.index(after: slash)...]) ?? -1
                if let ip = parseIP(addr), ip.v4, bits >= 0, bits <= 24 {
                    dns["fake-ip-range"] = .string(r)
                }
            }
            let f = cleanList(d.fakeIPFilter)
            if !f.isEmpty { dns["fake-ip-filter"] = .array(f) }
            if d.fakeIPFilterMode == "whitelist" || d.fakeIPFilterMode == "blacklist" {
                dns["fake-ip-filter-mode"] = .string(d.fakeIPFilterMode)
            }
        }
        dns["prefer-h3"] = .bool(d.preferH3)
        let psnCount = proxyNS.count + dns.list("proxy-server-nameserver").count
        dns["respect-rules"] = .bool(d.respectRules && psnCount > 0)
        if let uh = d.useHosts { dns["use-hosts"] = .bool(uh) }
        if let ush = d.useSystemHosts { dns["use-system-hosts"] = .bool(ush) }
        if d.cacheAlgorithm == "lru" || d.cacheAlgorithm == "arc" {
            dns["cache-algorithm"] = .string(d.cacheAlgorithm)
        }
    }

    /// bridge plainNameserver.
    static func plainNameserver(_ s0: String) -> Bool {
        let s = s0
        if s == "system" { return true }
        if s.contains("#") { return false }
        var h = s
        if let range = s.range(of: "://") {
            let scheme = s[..<range.lowerBound].lowercased()
            if scheme != "udp" && scheme != "tcp" { return false }
            h = String(s[range.upperBound...])
        }
        // ParseAddrPort
        if let ap = parseAddrPort(h) { _ = ap; return true }
        let trimmed = h.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return parseIP(trimmed) != nil
    }

    /// (host, port) when h is a valid IP host:port (bracketed v6 or
    /// single-colon form) with a numeric port.
    static func parseAddrPort(_ h: String) -> (String, Int)? {
        func validPort(_ s: Substring) -> Int? {
            guard !s.isEmpty, s.allSatisfy({ $0.isNumber }), let p = Int(s), p <= 65535
            else { return nil }
            return p
        }
        if h.hasPrefix("[") {
            guard let close = h.firstIndex(of: "]"),
                  h.index(after: close) < h.endIndex,
                  h[h.index(after: close)] == ":",
                  let port = validPort(h[h.index(close, offsetBy: 2)...]),
                  parseIP(String(h[h.index(after: h.startIndex)..<close])) != nil
            else { return nil }
            return (String(h[h.index(after: h.startIndex)..<close]), port)
        }
        let parts = h.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, let port = validPort(parts[1]), parseIP(String(parts[0])) != nil
        else { return nil }
        return (String(parts[0]), port)
    }

    /// bridge defaultProxyServerNameserver.
    static func defaultProxyServerNameserver(_ dns: inout [String: NCJSONValue]) {
        if !dns.list("proxy-server-nameserver").isEmpty
            || dns["proxy-server-nameserver-policy"] != nil { return }
        func pick(_ v: NCJSONValue?) -> [NCJSONValue] {
            var out: [NCJSONValue] = []
            var seen = Set<String>()
            guard let v else { return out }
            let list: [NCJSONValue] = { if case .array(let a) = v { return a }; return [] }()
            for e in list {
                let s: String
                switch e {
                case .string(let str): s = str.trimmingCharacters(in: .whitespaces)
                case .number: s = NCValueCoercion.sprint(e) // was String(Int64(n)): traps on 1e30 / inf
                default: continue
                }
                if s.isEmpty || seen.contains(s) || !plainNameserver(s) { continue }
                seen.insert(s)
                out.append(.string(s))
            }
            return out
        }
        var ps = pick(dns["nameserver"])
        if ps.isEmpty { ps = pick(dns["default-nameserver"]) }
        if ps.isEmpty { ps = [.string("223.5.5.5"), .string("119.29.29.29")] }
        dns["proxy-server-nameserver"] = .array(ps)
    }

    /// bridge capDNSCache (memshed; iosDNSCacheMax = 1024).
    static func capDNSCache(_ dns: inout [String: NCJSONValue]) {
        let n = dns.intOf("cache-max-size")
        if n > 0 && n <= 1024 { return }
        dns["cache-max-size"] = .number(1024)
    }

    // MARK: - localdns

    static func validHostName(_ s0: String) -> Bool {
        var s = s0
        if s.hasPrefix("+.") { s = String(s.dropFirst(2)) }
        if s.hasPrefix("*.") { s = String(s.dropFirst(2)) }
        if s.isEmpty || s.utf8.count > 253 { return false }
        if s.contains(where: { " /:\\@".contains($0) }) { return false }
        return true
    }

    /// bridge hostValue: an NCJSONValue or nil.
    static func hostValue(_ v: String) -> NCJSONValue? {
        let parts = v.split(whereSeparator: { $0 == "," || $0 == " " || $0 == ";" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if parts.isEmpty { return nil }
        let allIP = parts.allSatisfy { parseIP($0) != nil }
        if !allIP {
            if parts.count == 1 && validHostName(parts[0]) { return .string(parts[0]) }
            return nil
        }
        if parts.count == 1 { return .string(parts[0]) }
        return .array(parts.map { NCJSONValue.string($0) })
    }

    /// bridge applyLocalDNS.
    static func applyLocalDNS(
        _ raw: inout [String: NCJSONValue],
        _ dns: inout [String: NCJSONValue],
        _ l: NCLocalDNS?,
        mode: String
    ) {
        guard let l else { return }
        var n = 0
        var hosts = raw.map("hosts")
        for h in l.hosts {
            let d = h.domain.trimmingCharacters(in: .whitespaces).lowercased()
            if h.disabled || !validHostName(d) { continue }
            if let v = hostValue(h.value) {
                hosts[d] = v
                n += 1
            }
        }
        if n > 0 {
            raw["hosts"] = .object(hosts)
            dns["use-hosts"] = .bool(true)
        }
        if mode != "fake-ip" || l.realIP.isEmpty { return }
        if dns.str("fake-ip-filter-mode") == "whitelist" { return }
        var existing = dns.list("fake-ip-filter")
        var seen = Set<String>()
        for e in existing {
            if case .string(let s) = e { seen.insert(s) }
        }
        for d0 in l.realIP {
            let d = d0.trimmingCharacters(in: .whitespaces)
            if d.isEmpty || seen.contains(d) { continue }
            seen.insert(d)
            existing.append(.string(d))
        }
        dns["fake-ip-filter"] = .array(existing)
    }

    /// bridge lanCredentials.
    static func lanCredentials(_ o: NCRuntimeSettings) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        let auth = o.core.lanAuth
        if !auth.username.isEmpty && !auth.password.isEmpty {
            out.append(auth.username + ":" + auth.password)
            seen.insert(auth.username)
            seen.insert(auth.username.trimmingCharacters(in: .whitespaces))
        }
        for u in o.core.lanUsers {
            let name = u.username.trimmingCharacters(in: .whitespaces)
            if name.isEmpty || u.password.isEmpty || name.contains(":") || seen.contains(name) {
                continue
            }
            seen.insert(name)
            out.append(name + ":" + u.password)
        }
        return out
    }

    static let lanPrivatePrefixes: [String] = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
    ]
    static let loopbackPrefixes: [String] = ["127.0.0.0/8", "::1/128"]

    /// bridge applyInbound.
    static func applyInbound(_ raw: inout [String: NCJSONValue], _ o: NCRuntimeSettings) {
        let needLocal = o.core.tunnelMode == "proxy" || o.core.tunnelMode == "mix"
        if o.core.allowLan {
            raw["mixed-port"] = .number(Double(o.core.mixedPort))
            raw["bind-address"] = .string("*")
            let users = lanCredentials(o)
            if !users.isEmpty {
                raw["authentication"] = .array(users.map { NCJSONValue.string($0) })
            }
            if o.core.lanLocalOnly {
                raw["lan-allowed-ips"] = .array(lanPrivatePrefixes.map { NCJSONValue.string($0) })
            } else {
                raw.removeValue(forKey: "lan-allowed-ips")
            }
            raw.removeValue(forKey: "lan-disallowed-ips")
        } else if needLocal {
            raw["mixed-port"] = .number(Double(o.core.mixedPort))
            raw["bind-address"] = .string("127.0.0.1")
        } else {
            return
        }
        raw["skip-auth-prefixes"] = .array(loopbackPrefixes.map { NCJSONValue.string($0) })
    }

    // MARK: - inbounds

    static let lanListenerTypesAuth: Set<String> = ["socks", "http", "mixed"]
    static let lanListenerTypesOwnAuth: Set<String> = [
        "shadowsocks", "vmess", "vless", "trojan", "tuic",
        "hysteria2", "anytls", "sudoku", "mieru",
    ]
    static let probeListener = "tern-probe"

    /// bridge loopbackListen.
    static func loopbackListen(_ a0: String) -> Bool {
        let a = a0.trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if a == "localhost" { return true }
        return isLoopbackAddr(a)
    }

    /// Split host:port (SplitHostPort semantics for our inputs).
    static func splitHostPort(_ p: String) -> (host: String, port: String)? {
        if p.hasPrefix("[") {
            guard let close = p.firstIndex(of: "]"),
                  p.index(after: close) < p.endIndex,
                  p[p.index(after: close)] == ":" else { return nil }
            let port = String(p[p.index(close, offsetBy: 2)...])
            return (String(p[p.index(after: p.startIndex)..<close]), port)
        }
        let parts = p.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        return (String(parts[0]), String(parts[1]))
    }

    /// bridge loopbackHostList.
    static func loopbackHostList(_ s: String) -> (out: String, changed: Bool, ok: Bool) {
        var parts = s.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        var changed = false
        for i in parts.indices {
            let p = parts[i].trimmingCharacters(in: .whitespaces)
            guard let (host, port) = splitHostPort(p), !port.isEmpty else {
                return (s, false, false)
            }
            if !host.isEmpty && loopbackListen(host) {
                parts[i] = p
                continue
            }
            parts[i] = "127.0.0.1:" + port
            changed = true
        }
        return (parts.joined(separator: ","), changed, true)
    }

    /// bridge loopbackInboundURL.
    static func loopbackInboundURL(_ s: String) -> (out: String, changed: Bool, ok: Bool) {
        guard let scheme = s.range(of: "://") else { return (s, false, false) }
        let rest = String(s[scheme.upperBound...])
        var hostStart = rest.startIndex
        if let at = rest.lastIndex(of: "@") {
            hostStart = rest.index(after: at)
        }
        var authEnd = rest.endIndex
        if let j = rest[hostStart...].firstIndex(where: { "/?#".contains($0) }) {
            authEnd = j
        }
        let (hosts, changed, ok) = loopbackHostList(String(rest[hostStart..<authEnd]))
        if !ok { return (s, false, false) }
        let rebuilt = String(s[..<scheme.upperBound]) + String(rest[..<hostStart]) + hosts + String(rest[authEnd...])
        return (rebuilt, changed, true)
    }

    /// bridge sanitizeProfileInbounds (log lines dropped; behavior kept).
    static func sanitizeProfileInbounds(
        _ raw: inout [String: NCJSONValue],
        _ o: NCRuntimeSettings
    ) {
        if raw["tunnels"] != nil { raw.removeValue(forKey: "tunnels") }
        if case .object(var m) = raw["tuic-server"] ?? .null {
            let l = m.str("listen").trimmingCharacters(in: .whitespaces)
            if !l.isEmpty {
                let (nl, changed, ok) = loopbackHostList(l)
                if !ok {
                    raw.removeValue(forKey: "tuic-server")
                } else if changed {
                    m["listen"] = .string(nl)
                    raw["tuic-server"] = .object(m)
                }
            }
        } else if raw["tuic-server"] != nil && raw["tuic-server"] != .null {
            raw.removeValue(forKey: "tuic-server")
        }
        for k in ["ss-config", "vmess-config"] {
            guard let v = raw[k], v != .null else { continue }
            guard case .string(let s) = v else {
                raw.removeValue(forKey: k)
                continue
            }
            if s.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            let (ns, changed, ok) = loopbackInboundURL(s)
            if !ok {
                raw.removeValue(forKey: k)
            } else if changed {
                raw[k] = .string(ns)
            }
        }
        var creds: [String] = []
        if o.core.allowLan { creds = lanCredentials(o) }
        var kept: [NCJSONValue] = []
        for l in raw.list("listeners") {
            guard case .object(var m) = l else { continue }
            let typ = m.str("type").trimmingCharacters(in: .whitespaces).lowercased()
            let name = m.str("name")
            switch true {
            case name == probeListener:
                kept.append(.object(m))
            case lanListenerTypesOwnAuth.contains(typ):
                if !loopbackListen(m.str("listen")) {
                    m["listen"] = .string("127.0.0.1")
                }
                kept.append(.object(m))
            case lanListenerTypesAuth.contains(typ) && !o.core.allowLan:
                if loopbackListen(m.str("listen")) {
                    kept.append(.object(m))
                }
            case lanListenerTypesAuth.contains(typ):
                if !creds.isEmpty {
                    let users: [NCJSONValue] = creds.map { c in
                        let cut = c.firstIndex(of: ":")
                        let u = cut.map { String(c[..<$0]) } ?? c
                        let p = cut.map { String(c[c.index(after: $0)...]) } ?? ""
                        return .object(["username": .string(u), "password": .string(p)])
                    }
                    m["users"] = .array(users)
                } else {
                    m.removeValue(forKey: "users")
                }
                kept.append(.object(m))
            default:
                continue
            }
        }
        if raw["listeners"] != nil || !kept.isEmpty {
            raw["listeners"] = .array(kept)
        }
    }

    // MARK: - startup geox + provider URL rewrites

    static let geoMirrorBase = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
    static let geoKinds: [(kind: String, remote: String)] = [
        ("mmdb", "geoip.metadb"), ("geosite", "geosite.dat"),
        ("asn", "GeoLite2-ASN.mmdb"), ("geoip", "geoip.dat"),
    ]

    static func geoBaseURL(_ mirror: String) -> String {
        switch mirror {
        case "fastly": return "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
        case "github": return "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
        default: return geoMirrorBase
        }
    }

    /// bridge GeoCustomBase.
    static func geoCustomBase(_ base0: String) -> String {
        var b = base0.trimmingCharacters(in: .whitespaces)
        guard let u = URL(string: b),
              (u.scheme ?? "").lowercased() == "https",
              let host = u.host, !host.isEmpty,
              u.query == nil, u.fragment == nil,
              !b.contains(" ") && !b.contains("\t") else { return "" }
        if !b.hasSuffix("/") { b += "/" }
        return b
    }

    static func geoBase(_ o: NCRuntimeSettings) -> String {
        if o.core.geoMirror == "custom" {
            let b = geoCustomBase(o.core.geoMirrorBase)
            return b.isEmpty ? geoMirrorBase : b
        }
        return geoBaseURL(o.core.geoMirror)
    }

    static func normalizeURL(_ u: String) -> String {
        if !u.contains("://") {
            return "https://" + u.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        return u
    }

    static func geoURL(_ o: NCRuntimeSettings, _ kind: String) -> String {
        if let u0 = o.core.geoURLs[kind] {
            let u = u0.trimmingCharacters(in: .whitespaces)
            if !u.isEmpty { return normalizeURL(u) }
        }
        for g in geoKinds where g.kind == kind {
            return geoBase(o) + g.remote
        }
        return ""
    }

    /// bridge geoxFor.
    static func geoxFor(_ o: NCRuntimeSettings) -> [String: NCJSONValue] {
        var out: [String: NCJSONValue] = [:]
        for g in geoKinds {
            out[g.kind] = .string(geoURL(o, g.kind))
        }
        return out
    }

    /// bridge githubToMirror.
    static func githubToMirror(_ raw: String) -> (String, Bool) {
        guard let u = URL(string: raw), u.scheme == "https",
              let host = u.host else { return (raw, false) }
        let parts = u.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var user = "", repo = "", branch = ""
        var rest: [String] = []
        switch host.lowercased() {
        case "raw.githubusercontent.com":
            if parts.count < 4 { return (raw, false) }
            user = parts[0]; repo = parts[1]; branch = parts[2]; rest = Array(parts[3...])
            if branch == "refs" && parts.count >= 6 && parts[3] == "heads" {
                branch = parts[4]; rest = Array(parts[5...])
            }
        case "github.com":
            if parts.count < 5 || (parts[2] != "raw" && parts[2] != "blob") { return (raw, false) }
            user = parts[0]; repo = parts[1]; branch = parts[3]; rest = Array(parts[4...])
            if branch == "refs" && parts.count >= 7 && parts[4] == "heads" {
                branch = parts[5]; rest = Array(parts[6...])
            }
        default:
            return (raw, false)
        }
        if rest.isEmpty || user.isEmpty || repo.isEmpty || branch.isEmpty { return (raw, false) }
        return ("https://testingcf.jsdelivr.net/gh/" + user + "/" + repo + "@" + branch + "/" + rest.joined(separator: "/"), true)
    }

    /// bridge rewriteProviderURLs.
    static func rewriteProviderURLs(_ raw: inout [String: NCJSONValue]) {
        for key in ["rule-providers", "proxy-providers"] {
            // Review R-6: the old core `pv, ok := raw[key].(map[string]any); if !ok { continue }` —
            // an absent key stays absent, a wrongly-typed one is left for the core to reject.
            guard case .object(var pv)? = raw[key] else { continue }
            for name in pv.keys {
                guard case .object(var m) = pv[name] ?? .null else { continue }
                // the old core: `p, _ := m["proxy"].(string)` — only a string proxy counts.
                if case .string(let proxy)? = m["proxy"], !proxy.isEmpty,
                   proxy.lowercased() != "direct" { continue }
                if case .string(let s) = m["url"] ?? .null {
                    let (n, ok) = githubToMirror(s)
                    if ok {
                        if m.str("x-source").isEmpty { m["x-source"] = .string(s) }
                        m["url"] = .string(n)
                        pv[name] = .object(m)
                    }
                }
            }
            raw[key] = .object(pv)
        }
    }

    /// bridge providerConvert.
    static func providerConvert(_ m: [String: NCJSONValue]) -> (kind: String, src: String) {
        let u = m.str("url")
        if u.hasPrefix("convert+") {
            let rest = String(u.dropFirst("convert+".count))
            if let colon = rest.firstIndex(of: ":") {
                return (String(rest[..<colon]), String(rest[rest.index(after: colon)...]))
            }
            return ("", u)
        }
        return (m.str("x-convert"), u)
    }

    /// bridge rewriteConvertProviders, NativeCore edition. the old bridge pointed "convert" providers at its own
    /// loopback converter (http://127.0.0.1:<port>/rules/convert | /nodes/convert + a Bearer header). NativeCore
    /// has no such endpoint (device: 27× HTTP 401, remote rule lists never loaded), and it reads every dialect
    /// itself — NCRuleProviderStore parses QX/Surge/Loon/classical/domain-set lines, NCSubscriptionParser parses
    /// raw subscription bodies — so the provider keeps its source URL. The kind still decides the behavior
    /// (domainset → domain, else classical; format text), as the converter's output did. Old runtime/profile
    /// files that still carry the loopback URL are unwrapped by the stores and by NCFinalConfigReadable.
    static func rewriteConvertProviders(
        _ raw: inout [String: NCJSONValue],
        _ o: NCRuntimeSettings
    ) {
        for key in ["proxy-providers", "rule-providers"] {
            // Review R-6: the old core type-asserts the providers map and skips anything else.
            guard case .object(var pv)? = raw[key] else { continue }
            for name in pv.keys {
                guard case .object(var m) = pv[name] ?? .null else { continue }
                let (kind, src) = providerConvert(m)
                m.removeValue(forKey: "x-convert")
                if kind.isEmpty || !src.hasPrefix("http") {
                    pv[name] = .object(m)
                    continue
                }
                if m.str("x-source").isEmpty { m["x-source"] = .string(src) }
                m["url"] = .string(src)
                // Kept (private key, stripped from the readable export; the tunnel ignores it) so the App's provider
                // download (providerPlan) still converts / splits the list as before — x-own-policy lists need it.
                m["x-convert"] = .string(kind)
                if kind != "nodes" {
                    m["behavior"] = .string(kind == "domainset" ? "domain" : "classical")
                    m["format"] = .string("text")
                }
                pv[name] = .object(m)
            }
            raw[key] = .object(pv)
        }
    }

    // MARK: - memtune / ipv6 / netextras / probe

    /// bridge overrideHealthCheckURL.
    static func overrideHealthCheckURL(
        _ raw: inout [String: NCJSONValue],
        testURL: String
    ) {
        // Review R-6: the old core mutates in place through asList / asMap, so an absent or
        // wrongly-typed proxy-groups / proxy-providers is never written back.
        if case .array(var groups)? = raw["proxy-groups"] {
            for gi in groups.indices {
                guard case .object(var m) = groups[gi] else { continue }
                switch m.str("type").lowercased() {
                case "url-test", "fallback", "load-balance", "smart":
                    m["url"] = .string(testURL)
                default:
                    if m["url"] != nil { m["url"] = .string(testURL) }
                }
                groups[gi] = .object(m)
            }
            raw["proxy-groups"] = .array(groups)
        }
        if case .object(var pp)? = raw["proxy-providers"] {
            for name in pp.keys {
                if case .object(var m) = pp[name] ?? .null,
                   case .object(var hc) = m["health-check"] ?? .null {
                    hc["url"] = .string(testURL)
                    m["health-check"] = .object(hc)
                    pp[name] = .object(m)
                }
            }
            raw["proxy-providers"] = .object(pp)
        }
    }

    /// bridge applyIPPreference.
    static func applyIPPreference(_ raw: inout [String: NCJSONValue], pref: String) {
        if pref.isEmpty { return }
        // Review R-6: only write back containers that exist with the right type
        // (the old core ranges over asList / asMap results and mutates the elements in place).
        if case .array(var proxies)? = raw["proxies"] {
            for i in proxies.indices {
                if case .object(var m) = proxies[i], m["ip-version"] == nil {
                    m["ip-version"] = .string(pref)
                    proxies[i] = .object(m)
                }
            }
            raw["proxies"] = .array(proxies)
        }
        if case .object(var pp)? = raw["proxy-providers"] {
            for name in pp.keys {
                if case .object(var pm) = pp[name] ?? .null {
                    // the old core: ov := asMap(pm["override"]); ...; pm["override"] = ov
                    var ov = pm.map("override")
                    if ov["ip-version"] == nil {
                        ov["ip-version"] = .string(pref)
                    }
                    pm["override"] = .object(ov)
                    pp[name] = .object(pm)
                }
            }
            raw["proxy-providers"] = .object(pp)
        }
    }

    static let udpFallbackRule = "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
    static let quicBlockAllRule = "AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((IN-TYPE,INNER)))),REJECT"
    static let udpFallbackRejectRule = "AND,((NETWORK,UDP),(NOT,((IN-TYPE,INNER)))),REJECT"

    static func appendUDPFallback(_ raw: inout [String: NCJSONValue]) {
        let rules = raw.list("rules")
        if rules.isEmpty { return }
        raw["rules"] = .array(rules + [.string(udpFallbackRule)])
    }

    /// fix/quic-block: the generated QUIC rule for the default ("nondirect")
    /// mode. It must sit at the FRONT of the rule list: MATCH is terminal and
    /// every deciding rule ahead of it (GEOIP,CN,DIRECT in the field config)
    /// would otherwise shadow it, which is exactly what the old append did —
    /// the rule reached the engine (and was counted in its rule total) but
    /// could never be the first match, so QUIC blocking silently did nothing.
    /// Every other generated-rule injector prepends for the same reason
    /// (applyCustomRules, applyFaceTimeRules, the "always" branch below).
    /// Idempotent: a list already carrying the rule is left alone.
    static func prependUDPFallback(_ raw: inout [String: NCJSONValue]) {
        let rules = raw.list("rules")
        if rules.isEmpty { return }
        for r in rules {
            if case .string(let s) = r, s == udpFallbackRule { return }
        }
        raw["rules"] = .array([.string(udpFallbackRule)] + rules)
    }

    /// bridge applyQUICBlock.
    static func applyQUICBlock(_ raw: inout [String: NCJSONValue], mode: String) {
        switch mode {
        case "off":
            return
        case "always":
            let rules = raw.list("rules")
            if rules.isEmpty { return }
            for r in rules {
                if case .string(let s) = r, s == quicBlockAllRule {
                    appendUDPFallback(&raw)
                    return
                }
            }
            raw["rules"] = .array([.string(quicBlockAllRule)] + rules)
            appendUDPFallback(&raw)
        default:
            prependUDPFallback(&raw)
        }
    }

    /// bridge applyUDPFallback.
    static func applyUDPFallback(_ raw: inout [String: NCJSONValue], mode: String) {
        if mode != "reject" { return }
        let rules = raw.list("rules")
        if rules.isEmpty { return }
        raw["rules"] = .array(rules + [.string(udpFallbackRejectRule)])
    }

    /// bridge probePort.
    static func probePort(_ o: NCRuntimeSettings) -> Int {
        var p = 7899
        while p > 7800 {
            if p != o.core.mixedPort && p != o.core.controllerPort { return p }
            p -= 1
        }
        return 7899
    }

    /// bridge applyProbe.
    static func applyProbe(_ raw: inout [String: NCJSONValue], _ o: NCRuntimeSettings) {
        var members: [NCJSONValue] = []
        var kept: [NCJSONValue] = []
        for g in raw.list("proxy-groups") {
            guard case .object(let m) = g else {
                kept.append(g)
                continue
            }
            let name = m.str("name")
            if name == probeGroup { continue }
            kept.append(g)
            if !name.isEmpty { members.append(.string(name)) }
        }
        members.append(.string("DIRECT"))
        var pg: [String: NCJSONValue] = [
            "name": .string(probeGroup),
            "type": .string("select"),
            "include-all": .bool(true),
            "proxies": .array(members),
            "hidden": .bool(true),
        ]
        var own: [String] = []
        var chained = false
        for n in raw.map("proxy-providers").keys {
            if n.hasPrefix(generatedProviderPrefix) {
                chained = true
            } else {
                own.append(n)
            }
        }
        if chained {
            own.sort()
            pg.removeValue(forKey: "include-all")
            pg["include-all-proxies"] = .bool(true)
            if !own.isEmpty {
                pg["use"] = .array(own.map { NCJSONValue.string($0) })
            }
        }
        kept.append(.object(pg))
        raw["proxy-groups"] = .array(kept)
        var ls: [NCJSONValue] = []
        for l in raw.list("listeners") {
            if case .object(let m) = l, m.str("name") == probeListener { continue }
            ls.append(l)
        }
        ls.append(.object([
            "name": .string(probeListener),
            "type": .string("mixed"),
            "listen": .string("127.0.0.1"),
            "port": .number(Double(probePort(o))),
            "udp": .bool(false),
            "proxy": .string(probeGroup),
        ]))
        raw["listeners"] = .array(ls)
    }
}
