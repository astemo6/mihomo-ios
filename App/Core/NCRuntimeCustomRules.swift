import Foundation

/// E-B1 stage 3f: ports of the retired bridge's build half
/// (applyCustomRules / convertCustom / addRemoteProvider /
/// addRemoteModuleRules), the mitm core-rule resolution the module
/// inject uses (ResolveCoreRules / RemoteCoreRules, config), and
/// the retired bridge. The CustomRule model, parseQXRemote,
/// providerNameFor and prettyProviderName come from the B4 graft
/// (NCRuleValidator), already verified against the same old code.

extension NCRuntimeSteps {

    // MARK: - mitm policy index / core rules

    /// mitm policyIndex (no trimming, unlike the bridge variant).
    static func mitmPolicyIndex(_ parts: [String]) -> Int {
        if parts.count < 2 { return -1 }
        if parts[0].uppercased() == "MATCH" { return 1 }
        if parts.count < 3 { return -1 }
        return 2
    }

    /// mitm ResolveCoreRules.
    static func resolveCoreRules(
        _ raw: [String: NCJSONValue],
        rules: [String],
        unresolved: inout Set<String>?
    ) -> [String] {
        let (groups, proxies, first) = profileNames(raw)
        var out: [String] = []
        for r in rules {
            var parts = NCEngineRuleset.splitTop(r)
            let idx = mitmPolicyIndex(parts)
            if idx < 0 { continue }
            let t = parts[0].uppercased()
            if (t == "RULE-SET" || t == "DOMAIN-SET") && parts[1].contains("://") {
                continue
            }
            guard let pol = resolvePolicy(parts[idx], groups: groups, proxies: proxies, firstSelect: first) else {
                unresolved?.insert(parts[idx])
                continue
            }
            parts[idx] = pol
            out.append(parts.joined(separator: ","))
        }
        return out
    }

    /// mitm RemoteCoreRules.
    static func remoteCoreRules(_ rules: [String]) -> [String] {
        var out: [String] = []
        for r in rules {
            let parts = NCEngineRuleset.splitTop(r)
            if parts.count >= 3 && parts[1].contains("://") {
                let t = parts[0].uppercased()
                if t == "RULE-SET" || t == "DOMAIN-SET" { out.append(r) }
            }
        }
        return out
    }

    // MARK: - Remote providers

    /// bridge ruleConvertURL. Legacy: NativeCore has no /rules/convert endpoint, so new runtime configs no longer
    /// emit this (providers keep the source URL); kept for recognising old configs / tests.
    static func ruleConvertURL(_ o: NCRuntimeSettings, src: String, kind: String) -> String {
        var comps = URLComponents()
        comps.scheme = "http"
        comps.host = "127.0.0.1"
        comps.port = o.core.controllerPort
        comps.path = "/rules/convert"
        comps.queryItems = [URLQueryItem(name: "url", value: src), URLQueryItem(name: "kind", value: kind)]
        return comps.string ?? ""
    }

    /// bridge addRemoteProvider: returns "RULE-SET,<name>".
    static func addRemoteProvider(
        _ raw: inout [String: NCJSONValue],
        _ o: NCRuntimeSettings,
        sp: NCRuleValidator.RemoteSpec,
        interval: Int
    ) -> String {
        var rp = raw.map("rule-providers")
        let path = "./ruleset/" + NCRuleValidator.providerNameFor(url: sp.url, kind: sp.kind) + ".txt"
        for (n, v) in rp {
            if case .object(let m) = v, m.str("path") == path {
                return "RULE-SET," + n
            }
        }
        let name = uniqueProviderName(
            NCRuleValidator.prettyProviderName(u: sp.url, tag: sp.tag)
        ) { rp[$0] != nil }
        let behavior = sp.kind == "domainset" ? "domain" : "classical"
        rp[name] = .object([
            "type": .string("http"),
            "behavior": .string(behavior),
            "format": .string("text"),
            // NativeCore fetches and parses the source list itself (no loopback /rules/convert).
            "url": .string(sp.url),
            "proxy": .string("DIRECT"),
            "path": .string(path),
            "interval": .number(Double(interval > 0 ? interval : 86400)),
            "x-source": .string(sp.url),
        ])
        raw["rule-providers"] = .object(rp)
        return "RULE-SET," + name
    }

    /// bridge convertCustom: the enabled rules in order (checks are
    /// the validator UI's concern; B4 ported those).
    static func convertCustom(
        _ raw: inout [String: NCJSONValue],
        _ o: NCRuntimeSettings,
        rules: [CustomRule]
    ) -> [String] {
        let (groups, proxies, first) = profileNames(raw)
        var out: [String] = []
        for r in rules {
            let line = r.line.trimmingCharacters(in: .whitespaces)
            var conv: NCEngineRuleset.RuleConv
            var interval = r.interval ?? 0
            if let remote = NCRuleValidator.parseQXRemote(line), remote.1 {
                let sp = remote.0
                var c = NCEngineRuleset.RuleConv()
                c.type = "RULE-SET"
                c.remoteURL = sp.url
                c.remoteKind = "list"
                c.policy = sp.policy
                conv = c
                if interval == 0 { interval = sp.interval }
            } else {
                let (c, err) = NCEngineRuleset.convertRuleLine(line)
                if err != nil { continue }
                conv = c
            }
            if conv.rule.isEmpty && conv.remoteURL.isEmpty { continue }
            guard let pol = resolvePolicy(conv.policy, groups: groups, proxies: proxies, firstSelect: first) else {
                continue
            }
            var rule: String
            if !conv.remoteURL.isEmpty {
                if !r.enabled { continue }
                var sp = NCRuleValidator.RemoteSpec(url: conv.remoteURL)
                sp.kind = conv.remoteKind
                sp.policy = pol
                rule = addRemoteProvider(&raw, o, sp: sp, interval: interval) + "," + pol + conv.options
            } else {
                rule = conv.format(pol)
            }
            if r.enabled { out.append(rule) }
        }
        return out
    }

    /// bridge readCustomRules (rules.json).
    static func readCustomRules(home: String) -> [CustomRule] {
        struct File: Decodable { var rules: [CustomRule] = [] }
        if home.isEmpty { return [] }
        return NCRuntimeFiles.readJSON(File.self, home: home, file: "rules.json")?.rules ?? []
    }

    /// bridge applyCustomRules: custom rules prepend (they win).
    static func applyCustomRules(
        _ raw: inout [String: NCJSONValue],
        _ o: NCRuntimeSettings
    ) {
        let rules = readCustomRules(home: o.home)
        if rules.isEmpty { return }
        let pre = convertCustom(&raw, o, rules: rules)
        if pre.isEmpty { return }
        raw["rules"] = .array(pre.map { NCJSONValue.string($0) } + raw.list("rules"))
    }

    /// bridge addRemoteModuleRules. the old core reads the overrides of the
    /// *current* home through a global; here the caller passes the
    /// settings of the profile being built (the same one in
    /// practice).
    static func addRemoteModuleRules(
        _ raw: inout [String: NCJSONValue],
        coreRules: [String],
        _ o: NCRuntimeSettings
    ) {
        let remote = remoteCoreRules(coreRules)
        if remote.isEmpty { return }
        let rs = remote.enumerated().map {
            CustomRule(id: String($0.offset), line: $0.element, enabled: true)
        }
        let pre = convertCustom(&raw, o, rules: rs)
        raw["rules"] = .array(pre.map { NCJSONValue.string($0) } + raw.list("rules"))
    }

    // MARK: - FaceTime

    static let faceTimeMatchers: [String] = [
        "DOMAIN-SUFFIX,push.apple.com",
        "DOMAIN-SUFFIX,push-apple.com.akadns.net",
        "DOMAIN-SUFFIX,ess.apple.com",
        "DOMAIN-SUFFIX,facetime.apple.com",
        "DOMAIN-SUFFIX,ids.apple.com",
        "AND,((NETWORK,TCP),(DST-PORT,5223))",
        "AND,((NETWORK,UDP),(DST-PORT,3478-3497))",
        "AND,((NETWORK,UDP),(DST-PORT,16384-16387))",
        "AND,((NETWORK,UDP),(DST-PORT,16393-16402))",
    ]

    /// bridge faceTimePolicy.
    static func faceTimePolicy(_ raw: [String: NCJSONValue]) -> String {
        var groups = Set<String>()
        var firstSelect = ""
        var firstGroup = ""
        for g in raw.list("proxy-groups") {
            guard case .object(let m) = g else { continue }
            let name = m.str("name")
            if name.isEmpty { continue }
            groups.insert(name)
            if firstGroup.isEmpty { firstGroup = name }
            if firstSelect.isEmpty && m.str("type") == "select" { firstSelect = name }
        }
        let rules = raw.list("rules")
        for rv in rules.reversed() {
            guard case .string(let r0) = rv else { continue }
            let r = r0.trimmingCharacters(in: .whitespaces)
            if r.hasPrefix("MATCH,") || r.hasPrefix("FINAL,") {
                let fields = r.split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
                if fields.count > 1 {
                    let t = String(fields[1]).trimmingCharacters(in: .whitespaces)
                    if groups.contains(t) { return t }
                }
                break
            }
        }
        if !firstSelect.isEmpty { return firstSelect }
        if !firstGroup.isEmpty { return firstGroup }
        for p in raw.list("proxies") {
            if case .object(let m) = p {
                let n = m.str("name")
                if !n.isEmpty { return n }
            }
        }
        return ""
    }

    /// bridge applyFaceTimeRules.
    static func applyFaceTimeRules(_ raw: inout [String: NCJSONValue]) {
        let pol = faceTimePolicy(raw)
        if pol.isEmpty { return }
        let pre = faceTimeMatchers.map { NCJSONValue.string($0 + "," + pol) }
        raw["rules"] = .array(pre + raw.list("rules"))
    }
}
