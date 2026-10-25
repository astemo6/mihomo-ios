import Foundation

/// E-B1 stage 4: the runtime config builder — a port of
/// bridge/bridge.go buildRuntimeWith + marshalConfig
/// (runtimejson.go), bridge/nativeprep.go's lowerForNative, and
/// the dnsHijack helpers (netextras.go). The satellite steps live
/// in NCRuntimeSteps / NCRuntimeSubRules / NCRuntimeChains /
/// NCRuntimeCustomRules / NCRuntimeDNS.
///
/// The one deliberate seam difference: Go's builder returns bytes
/// (YAML, or JSON for large configs); the tree is returned too —
/// the native prep serializes nativecore-runtime.json from it
/// directly instead of re-reading runtime.yaml (Go's
/// NativeConfigJSON does exactly that re-encode).

enum NCRuntimeBuilder {

    /// bridge overridesFor: settings plus the profile's attachments.
    struct Request {
        var settings: NCRuntimeSettings
        var profileID: String
        var sub: NCSubRules?
        var chains: [String: String]

        static func load(home: String, profilePath: String) -> Request {
            let settings = NCRuntimeSettings.load(home: home)
            let id = NCRuntimeFiles.profileID(fromPath: profilePath)
            var sub: NCSubRules? = nil
            if let r = NCRuntimeFiles.readAllSubRules(home: home)[id], r.enabled {
                sub = r
            }
            return Request(
                settings: settings,
                profileID: id,
                sub: sub,
                chains: NCRuntimeFiles.readGroupChains(home: home, profilePath: profilePath))
        }
    }

    struct PrepReport: Codable {
        var at: Int64 = 0
        var profile: String = ""
        var rules: Int = 0
        var geosite: [String]? = nil
        var rewrite: Bool = false
        var mitmHosts: Int = 0
        var scripts: Int = 0
        var lowered: [String]? = nil
        var warnings: [String]? = nil
    }

    enum BuildError: Error {
        case yaml(String)
        var message: String {
            switch self { case .yaml(let m): return m }
        }
    }

    static let runtimeJSONThreshold = 256 << 10
    static let runtimeJSONItems = 3000

    /// bridge buildRuntimeWith (fd = the PacketFlow fd at Start; the
    /// native prep builds with 0). inject runs where Go's does —
    /// after custom rules / FaceTime, before the IP preference.
    static func build(
        profile: Data,
        req: Request,
        fd: Int32,
        inject: ((inout [String: NCJSONValue]) -> Void)? = nil
    ) throws -> (data: Data, isJSON: Bool, raw: [String: NCJSONValue]) {
        let o = req.settings
        let core = o.core
        var raw: [String: NCJSONValue] = [:]
        let text = String(decoding: profile, as: UTF8.self)
        if let parsed = NCYAML.parse(text) {
            switch parsed {
            case .object(let m): raw = m
            case .null: raw = [:]
            default:
                throw BuildError.yaml("YAML 解析失败: 配置顶层不是映射")
            }
        } else if text.split(separator: "\n").allSatisfy({
            let t = $0.trimmingCharacters(in: .whitespaces)
            return t.isEmpty || t.hasPrefix("#") || t == "---"
        }) {
            // Go: an empty / comment-only document unmarshals to a
            // nil map, which the builder replaces with an empty one.
            raw = [:]
        } else {
            throw BuildError.yaml("YAML 解析失败: 无法解析")
        }
        // Plain share-link / base64 subscription => convert.
        if raw["proxies"] == nil && raw["proxy-providers"] == nil {
            let conv = NCShareLink.convertShareLinks(text)
            if !conv.isEmpty, let reparsed = NCYAML.parse(conv), case .object(let m) = reparsed {
                raw = m
            }
        }

        var editedRules: [String: String] = [:]
        if !o.home.isEmpty && !req.profileID.isEmpty {
            let (edited, _) = NCRuntimeSteps.applyProfileRuleOverrides(
                &raw, ov: NCRuntimeFiles.readProviderOverrides(home: o.home, profileID: req.profileID))
            editedRules = edited
        }
        if let sub = req.sub {
            _ = NCRuntimeSteps.applySubRules(&raw, sub)
        }
        if core.mergeManual && !o.manualPath.isEmpty {
            NCRuntimeSteps.mergeManualNodes(&raw, manualPath: o.manualPath)
        }
        if !o.home.isEmpty && !req.profileID.isEmpty {
            let ov = NCRuntimeFiles.readProviderOverrides(home: o.home, profileID: req.profileID)
            _ = NCRuntimeSteps.applyProviderOverridesDeferred(&raw, ov: ov)
            _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        }
        if !o.home.isEmpty && !core.safeMode {
            let all = NCRuntimeFiles.readAllSubRules(home: o.home)
            NCRuntimeSteps.mergeNodeSubs(&raw, home: o.home) { all[$0] }
            _ = NCRuntimeSteps.applyGroupEdits(
                &raw, NCRuntimeFiles.readGroupEdits(home: o.home, profileID: req.profileID))
            _ = NCRuntimeSteps.pruneDanglingUse(&raw)
        }
        NCRuntimeSteps.fillEmptyProviderGroups(&raw)
        if !o.home.isEmpty {
            NCRuntimeSteps.expandOwnPolicyProviders(&raw, home: o.home)
        }
        NCRuntimeSteps.normalizeTailscale(&raw, home: o.home)
        if core.safeMode {
            _ = NCRuntimeSteps.applyChains(&raw, chains: [:])
        } else {
            _ = NCRuntimeSteps.applyChains(&raw, chains: req.chains)
        }
        if !o.home.isEmpty {
            _ = NCRuntimeSteps.applyProxyChains(
                &raw, chains: NCRuntimeFiles.readProxyChains(home: o.home), build: !core.safeMode)
        }

        if !core.logLevel.isEmpty {
            raw["log-level"] = .string(core.logLevel)
        }
        if raw.str("log-level").trimmingCharacters(in: .whitespaces).lowercased() == "debug" {
            raw["log-level"] = .string("info")
        }
        if !core.mode.isEmpty {
            raw["mode"] = .string(core.mode)
        }
        raw["ipv6"] = .bool(o.ipv6)
        raw["allow-lan"] = .bool(core.allowLan)
        raw["external-controller"] = .string("127.0.0.1:\(core.controllerPort)")
        raw["secret"] = .string(core.secret)
        raw.removeValue(forKey: "external-controller-tls")
        raw.removeValue(forKey: "external-controller-unix")
        raw.removeValue(forKey: "external-ui")
        raw["find-process-mode"] = .string("off")
        raw["unified-delay"] = .bool(true)
        raw["geo-auto-update"] = .bool(false)
        raw["geodata-loader"] = .string("memconservative")
        raw["geodata-mode"] = .bool(false)
        raw["geox-url"] = .object(NCRuntimeSteps.geoxFor(o))
        NCRuntimeSteps.rewriteProviderURLs(&raw)
        for k in ["port", "socks-port", "redir-port", "tproxy-port", "mixed-port"] {
            raw.removeValue(forKey: k)
        }
        NCRuntimeSteps.sanitizeProfileInbounds(&raw, o)
        NCRuntimeSteps.applyInbound(&raw, o)
        if raw["keep-alive-interval"] == nil { raw["keep-alive-interval"] = .number(30) }
        if raw["keep-alive-idle"] == nil { raw["keep-alive-idle"] = .number(300) }
        raw.removeValue(forKey: "iptables")
        raw.removeValue(forKey: "interface-name")
        raw.removeValue(forKey: "routing-mark")

        var profileCfg = raw.map("profile")
        profileCfg["store-selected"] = .bool(true)
        profileCfg["store-fake-ip"] = .bool(false)
        raw["profile"] = .object(profileCfg)

        // DNS
        var dns = raw.map("dns")
        dns["enable"] = .bool(true)
        dns["ipv6"] = .bool(o.ipv6)
        dns["listen"] = .string("")
        dns["enhanced-mode"] = .string(core.dnsMode)
        if core.dnsMode == "fake-ip" {
            if dns["fake-ip-range"] == nil {
                dns["fake-ip-range"] = .string("198.18.0.1/16")
            }
            if dns["fake-ip-filter"] == nil {
                dns["fake-ip-filter"] = .array([
                    "*.lan", "*.local", "localhost.ptlogin2.qq.com", "+.msftconnecttest.com",
                    "+.msftncsi.com", "time.*.com", "+.ntp.org", "+.apple.com",
                ].map { NCJSONValue.string($0) })
            }
        }
        if dns["nameserver"] == nil {
            dns["nameserver"] = .array([
                "https://223.5.5.5/dns-query", "https://doh.pub/dns-query",
            ].map { NCJSONValue.string($0) })
        }
        if dns["default-nameserver"] == nil {
            dns["default-nameserver"] = .array([
                "223.5.5.5", "119.29.29.29",
            ].map { NCJSONValue.string($0) })
        }
        // keepProfilePolicyOrder: a no-op here (see NCRuntimeDNS).
        NCRuntimeSteps.applyDNSOverride(&dns, o.dns, mode: core.dnsMode)
        NCRuntimeSteps.applyLocalDNS(&raw, &dns, o.local, mode: core.dnsMode)
        NCRuntimeSteps.defaultProxyServerNameserver(&dns)
        NCRuntimeSteps.capDNSCache(&dns)
        raw["dns"] = .object(dns)

        // Sniffer (the default table is bridge.go's, identical to
        // the one NCSnifferConfig falls back to in the tunnel).
        var sn = raw.map("sniffer")
        sn["enable"] = .bool(core.sniffer)
        if core.sniffer && sn["sniff"] == nil {
            sn["sniff"] = .object([
                "HTTP": .object([
                    "ports": .array([.number(80), .string("8080-8880")]),
                    "override-destination": .bool(true),
                ]),
                "TLS": .object(["ports": .array([.number(443), .number(8443)])]),
                "QUIC": .object(["ports": .array([.number(443), .number(8443)])]),
            ])
        }
        raw["sniffer"] = .object(sn)

        // TUN
        if fd > 0 {
            var tun: [String: NCJSONValue] = [
                "enable": .bool(true),
                "stack": .string("gvisor"),
                "file-descriptor": .number(Double(fd)),
                "auto-route": .bool(false),
                "auto-detect-interface": .bool(false),
                "dns-hijack": .array(dnsHijackList(core.dnsHijack).map { NCJSONValue.string($0) }),
                "mtu": .number(Double(core.tunMTU)),
                "recvmsgx": .bool(false),
                "sendmsgx": .bool(false),
                "udp-timeout": .number(120),
            ]
            if o.ipv6 {
                tun["inet6-address"] = .array([.string("fdfe:dcba:9876::1/126")])
            }
            raw["tun"] = .object(tun)
        } else {
            raw.removeValue(forKey: "tun")
        }

        NCRuntimeSteps.rewriteConvertProviders(&raw, o)
        if core.overrideHealthCheck {
            NCRuntimeSteps.overrideHealthCheckURL(&raw, testURL: core.testURL)
        }
        _ = NCRuntimeSteps.checkEditedRuleTargets(&raw, edited: editedRules)
        if !core.safeMode {
            NCRuntimeSteps.applyCustomRules(&raw, o)
        }
        if core.faceTimeProxy {
            NCRuntimeSteps.applyFaceTimeRules(&raw)
        }
        inject?(&raw)
        NCRuntimeSteps.applyIPPreference(&raw, pref: core.ipPreference)
        NCRuntimeSteps.applyProbe(&raw, o)
        NCRuntimeSteps.applyQUICBlock(&raw, mode: core.blockQUIC)
        NCRuntimeSteps.applyUDPFallback(&raw, mode: core.udpFallback)

        let items = raw.list("proxies").count + raw.list("proxy-groups").count + raw.list("rules").count
        let (data, isJSON) = marshalConfig(raw, big: profile.count >= runtimeJSONThreshold || items >= runtimeJSONItems)
        return (data, isJSON, raw)
    }

    /// bridge marshalConfig: JSON for large configs, YAML else.
    static func marshalConfig(
        _ raw: [String: NCJSONValue], big: Bool
    ) -> (data: Data, isJSON: Bool) {
        if big, let data = jsonData(raw) {
            return (data + Data("\n".utf8), true)
        }
        return (Data(NCYAML.emit(NCJSONValue.object(raw)).utf8), false)
    }

    /// Sorted-keys JSON of the tree (the nativecore-runtime.json
    /// shape; Go marshals the same map with encoding/json).
    static func jsonData(_ raw: [String: NCJSONValue]) -> Data? {
        let any = NCJSONValue.object(raw).anyTree
        return try? JSONSerialization.data(withJSONObject: any, options: [.sortedKeys])
    }

    // MARK: - DNS hijack (netextras.go)

    static func validDNSHijack(_ s0: String) -> Bool {
        var d = s0.trimmingCharacters(in: .whitespaces)
        if let cut = d.range(of: "://") {
            d = String(d[cut.upperBound...])
        }
        if let anyRange = d.range(of: "any") {
            d = d.replacingCharacters(in: anyRange, with: "0.0.0.0")
        }
        guard let (_, port) = NCRuntimeSteps.parseAddrPort(d) else { return false }
        return port != 0
    }

    static func dnsHijackList(_ list: [String]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        for s0 in list {
            let s = s0.trimmingCharacters(in: .whitespaces)
            if s.isEmpty || seen.contains(s) || !validDNSHijack(s) { continue }
            seen.insert(s)
            out.append(s)
        }
        return out
    }

    // MARK: - GEOSITE lowering (nativeprep.go lowerForNative)

    static func geositeProvider(_ code: String) -> String {
        "__geosite_" + code
            .replacingOccurrences(of: "@", with: "_")
            .replacingOccurrences(of: "!", with: "not_")
    }

    private static let inTypeTermRe = try? NSRegularExpression(
        pattern: #",?\(NOT,\(\(IN-TYPE,[A-Za-z-]+\)\)\)"#)
    private static let geositeRefRe = try? NSRegularExpression(
        pattern: #"\bGEOSITE,([^,()\s]+)"#, options: [.caseInsensitive])

    static func lowerForNative(
        home: String,
        _ raw: inout [String: NCJSONValue],
        _ rep: inout PrepReport
    ) {
        var rp = raw.map("rule-providers")
        var codes = Set<String>()
        var out: [NCJSONValue] = []
        for rv in raw.list("rules") {
            guard case .string(let s0) = rv else {
                out.append(rv)
                continue
            }
            var s = s0
            if let re = inTypeTermRe {
                s = re.stringByReplacingMatches(
                    in: s, range: NSRange(s.startIndex..., in: s), withTemplate: "")
            }
            if let re = geositeRefRe {
                var rebuilt = ""
                var cursor = s.startIndex
                for m in re.matches(in: s, range: NSRange(s.startIndex..., in: s)) {
                    guard let whole = Range(m.range, in: s),
                          let g1 = Range(m.range(at: 1), in: s) else { continue }
                    let code = String(s[g1]).lowercased()
                    codes.insert(code)
                    rebuilt += s[cursor..<whole.lowerBound]
                    rebuilt += "RULE-SET," + geositeProvider(code)
                    cursor = whole.upperBound
                }
                rebuilt += s[cursor...]
                s = rebuilt
            }
            if s != s0 && (rep.lowered?.count ?? 0) < 20 {
                rep.lowered = (rep.lowered ?? []) + [s0 + " → " + s]
            }
            out.append(.string(s))
        }
        raw["rules"] = .array(out)
        rep.rules = out.count
        if codes.isEmpty { return }
        let dir = URL(fileURLWithPath: home).appendingPathComponent("nativecore-geosite")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let datURL = URL(fileURLWithPath: home).appendingPathComponent("GeoSite.dat")
        let db = (try? Data(contentsOf: datURL)).flatMap { NCGeoSiteDB(data: $0) }
        if db == nil {
            rep.warnings = (rep.warnings ?? []) + ["GEOSITE: GeoSite.dat 不可用"]
        }
        for code in codes.sorted() {
            let name = geositeProvider(code)
            let file = dir.appendingPathComponent(code + ".list").path
            var list = code
            if let at = code.firstIndex(of: "@") {
                list = String(code[..<at])
                rep.warnings = (rep.warnings ?? []) + ["GEOSITE " + code + ": attributes ignored"]
            }
            let lines = db?.classicalLines(for: list)
            if db != nil && lines == nil {
                rep.warnings = (rep.warnings ?? []) + ["GEOSITE " + code + ": 分类不存在"]
            }
            let body = (lines ?? []).map { $0 + "\n" }.joined()
            try? NCRuntimeFiles.writeAtomic(Data(body.utf8), to: file)
            rp[name] = .object([
                "type": .string("file"),
                "behavior": .string("classical"),
                "path": .string(file),
            ])
            rep.geosite = (rep.geosite ?? []) + ["\(code) (\(lines?.count ?? 0))"]
        }
        raw["rule-providers"] = .object(rp)
    }
}
