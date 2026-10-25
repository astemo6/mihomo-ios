import Foundation

/// nc-integrate B3/B4: bridge/profileruleoverrides.go ProfileRules and bridge/provideroverrides.go
/// ProfileProviders in Swift. Both read the profile as buildRuntimeWith starts from it (覆写脚本 output when
/// current = NCRuntimeFiles.readRuntimeProfile; share links converted = NCOverrideOutput.profileAsMap) and the
/// per-profile provider-overrides.json (NCRuntimeFiles.readProviderOverrides). Edited lines convert through
/// NCRuntimeSteps.convertEditedRule (#112), the same converter the runtime build uses.
///
/// Divergence: Go cached ProfileProviders for 30 s per input-file signature; the one caller
/// (ProviderOverrideStore.loadDeclared) already caches per profile path, so no second cache is kept here.
enum NCProfileRulesPort {

    // MARK: - ProfileProviders

    /// bridge ProfileProviders: the proxy-providers the profile itself declares, before the user's overrides.
    /// JSON [providerInfo] sorted by name.
    static func profileProviders(home: String, profilePath: String) -> String {
        guard let b = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false),
              let raw = try? NCOverrideOutput.profileAsMap(b) else { return "[]" }
        var out: [[String: Any]] = []
        for (name, v) in raw.map("proxy-providers") {
            guard case .object(let m) = v else { continue }
            var p: [String: Any] = ["name": name, "vehicle": ncStr(m["type"]).lowercased()]
            let interval = ncInt(m["interval"])
            if interval != 0 { p["interval"] = interval }
            let f = ncStr(m["filter"]), xf = ncStr(m["exclude-filter"])
            if !f.isEmpty { p["filter"] = f }
            if !xf.isEmpty { p["excludeFilter"] = xf }
            if (p["vehicle"] as? String) == "http" {
                let u = NCRuntimeSteps.providerSourceURL(m)
                if !u.isEmpty { p["url"] = u }
            }
            out.append(p)
        }
        out.sort { ($0["name"] as? String ?? "") < ($1["name"] as? String ?? "") }
        let s = ncJSONString(out)
        return s.isEmpty ? "[]" : s
    }

    // MARK: - ProfileRules

    private struct Ref: Hashable { var key: String; var index: Int }

    private struct Plan {
        var original = ""
        var key = ""
        var index = -1
        var out = ""
        var ov: NCProfileRuleOverride? = nil
        var err = ""
    }

    /// bridge planProfileRules.
    private static func plan(_ raw: [String: NCJSONValue], _ rules: [NCJSONValue],
                             _ ov: [String: NCProviderOverride]?) -> (plans: [Plan], matched: Int) {
        var byRef: [Ref: NCProfileRuleOverride] = [:]
        for r in ov?["#profile-rules"]?.rules ?? [] {
            let k = NCRuntimeSteps.profileRuleKey(r.rule)
            if k.isEmpty || r.index < 0 { continue }
            byRef[Ref(key: k, index: r.index)] = r
        }
        var seen: [String: Int] = [:]
        var plans: [Plan] = []
        var matched = 0
        plans.reserveCapacity(rules.count)
        for rv in rules {
            guard case .string(let r) = rv else { plans.append(Plan()); continue }
            let k = NCRuntimeSteps.profileRuleKey(r)
            let n = seen[k] ?? 0
            seen[k] = n + 1
            var p = Plan(original: r, key: k, index: n, out: r)
            if let o = byRef[Ref(key: k, index: n)] {
                p.ov = o
                matched += 1
                let line = (o.line ?? "").trimmingCharacters(in: .whitespaces)
                if o.deleted == true || o.disabled == true {
                    p.out = ""
                } else if !line.isEmpty && NCRuntimeSteps.profileRuleKey(o.line ?? "") != k {
                    let (conv, err) = NCRuntimeSteps.convertEditedRule(raw, line: o.line ?? "")
                    if let err { p.err = err } else if let conv { p.out = conv }
                }
            }
            plans.append(p)
        }
        return (plans, matched)
    }

    /// bridge ProfileRules: the profile's own rules in order with the user's overrides, and its Final.
    static func profileRules(home: String, profilePath: String) -> String {
        var items: [[String: Any]] = []
        var finalOriginal = ""
        func encode(stale: Int, finalPolicy: String, finalEdited: Bool, error: String) -> String {
            var fin: [String: Any] = ["policy": finalPolicy, "original": finalOriginal]
            if finalEdited { fin["edited"] = true }
            var res: [String: Any] = ["rules": items, "finalInfo": fin, "stale": stale]
            if !error.isEmpty { res["error"] = error }
            return ncJSONString(res)
        }
        let raw: [String: NCJSONValue]
        do {
            guard let b = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) else {
                return encode(stale: 0, finalPolicy: "", finalEdited: false,
                              error: "无法读取配置文件: " + (profilePath as NSString).lastPathComponent)
            }
            raw = try NCOverrideOutput.profileAsMap(b)
        } catch {
            return encode(stale: 0, finalPolicy: "", finalEdited: false, error: error.localizedDescription)
        }
        let ov = NCRuntimeFiles.readProviderOverrides(home: home, profileID: NCRuntimeFiles.profileID(fromPath: profilePath))
        let (plans, matched) = plan(raw, raw.list("rules"), ov)
        let stale = max(0, (ov?["#profile-rules"]?.rules?.count ?? 0) - matched)
        for (i, p) in plans.enumerated() where p.index >= 0 {
            if NCRuntimeSteps.isMatchRule(p.original) {
                finalOriginal = NCProfileInspectorPort.splitRule(p.original).proxy
            }
            var it: [String: Any] = ["position": i, "rule": p.key, "index": p.index, "original": p.original,
                                     "line": p.original]
            if !p.err.isEmpty { it["error"] = p.err }
            var shown = p.original
            if let o = p.ov {
                if o.disabled == true { it["disabled"] = true }
                if o.deleted == true { it["deleted"] = true }
                let l = (o.line ?? "").trimmingCharacters(in: .whitespaces)
                if !l.isEmpty && NCRuntimeSteps.profileRuleKey(l) != p.key {
                    it["line"] = l
                    it["edited"] = true
                    if p.err.isEmpty { shown = p.out }
                }
            }
            let sr = NCProfileInspectorPort.splitRule(shown)
            it["type"] = sr.type
            it["payload"] = sr.payload
            it["proxy"] = sr.proxy
            if let o = sr.options, !o.isEmpty { it["options"] = o }
            items.append(it)
        }
        var policy = finalOriginal
        var edited = false
        let f = (ov?["#final"]?.policy ?? "").trimmingCharacters(in: .whitespaces)
        if !f.isEmpty { policy = f; edited = f != finalOriginal }
        return encode(stale: stale, finalPolicy: policy, finalEdited: edited, error: "")
    }
}
