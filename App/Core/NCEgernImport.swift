import Foundation

/// feat/nc-egern-disabled-import (#169): an Egern *configuration* (Profile.yaml —
/// the document with `proxies:` / `policy_groups:`) converts to the same
/// ConfImportResult the Surge / QX / Loon .conf pipeline consumes, so it imports
/// through the same sheet and save path, and the source's switched-off entries
/// keep their state through the existing v0.20.2 mechanisms (no new storage):
///
///   modules: (enabled: false)   → rewriteRemotes with enabled = false
///                                 (added, never downloaded until switched on)
///   rules: rule_set (disabled)  → rule-provider + RULE-SET line, then switched
///                                 off via report.disabledRuleSets
///   rules: local (disabled)     → the rule line stays in the generated profile,
///                                 switched off via report.disabledRules
///   engine sections (scriptings / url_rewrites / header_rewrites /
///   body_rewrites / map_locals / mitm / widgets / http_captures)
///                               → attached as an Egern module (verbatim source
///                                 slices); item-level `disabled` inside them is
///                                 honoured by EngineParser.parseEgern.
///
/// Schema audit (Egern official docs, checked 2026-10-28 — see the PR for the
/// full table): `disabled` (bool) exists on every rule item, every scripting
/// entry and the url / header / body rewrite items; module references carry
/// `enabled` (bool, default true). There is NO enabled / disabled field on
/// policy groups (including external / subscription groups), on individual
/// proxies, on map_locals items or on the mitm block, and policy-group members
/// cannot be switched off individually — so for subscriptions there is nothing
/// to map (a group is imported as-is; `hidden` is UI-only in Egern too).
/// References:
///   https://egernapp.com/docs/configuration/modules/
///   https://egernapp.com/docs/configuration/rules/
///   https://egernapp.com/docs/configuration/scriptings/
///   https://egernapp.com/docs/configuration/policy_groups/
///   https://egernapp.com/docs/configuration/proxies/
///
/// Out of scope (the issue's own 不做 list): converting Egern's inline
/// `proxies:` themselves — they are listed in the report's skipped section
/// instead of being silently dropped, and references to them are filtered so
/// the generated profile still validates.
enum NCEgernImport {

    /// A document is an Egern *configuration* (not a module) when it carries
    /// top-level `proxies:` or `policy_groups:` — the two sections a module
    /// file never has (EngineParser.parseEgern reports them unsupported).
    static func isConfig(_ text: String) -> Bool {
        guard NCEngineRuleset.isEgern(text) else { return false }
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("#") { continue }
            if t == "proxies:" || t == "policy_groups:" { return true }
        }
        return false
    }

    private static let engineSections = ["scriptings", "url_rewrites", "header_rewrites",
                                         "body_rewrites", "map_locals", "mitm", "widgets", "http_captures"]
    private static let builtinPolicies: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP",
                                                       "REJECT-TINYGIF", "REJECT-IMG", "REJECT-200", "PASS", "PROXY"]

    static func convert(_ text0: String) -> ConfImportResult {
        var result = ConfImportResult()
        var rep = ConfImportResult.Report()
        rep.format = "egern"
        var notes: [String] = []
        var skipped: [String] = []
        var disabledLines: [String] = []

        // compat_arguments substitution with the declared defaults, like parseEgern.
        var text = text0
        let compatArgs = NCEngineRuleset.egernCompatArgs(text)
        if !compatArgs.isEmpty {
            var vals: [String: String] = [:]
            for a in compatArgs { vals[a.key] = a.def }
            text = NCEngineRuleset.egernSubstitute(text, vals: vals)
        }
        guard let root = NCYAML.parse(text)?.object else {
            result.error = String(localized: "Egern 配置 YAML 解析失败")
            result.report = rep
            return result
        }

        // ---- inline proxies: not converted (see the header), names remembered
        // so group members / rule policies referencing them can be filtered.
        var inlineProxyNames: Set<String> = []
        for item in root["proxies"]?.array ?? [] {
            guard let o = item.object, let (_, body) = o.first, let b = body.object else { continue }
            let n = NCEngineRuleset.egernStr(b["name"])
            if !n.isEmpty { inlineProxyNames.insert(n) }
            skipped.append("内联节点未转换：\(n.isEmpty ? "(未命名)" : n)")
        }

        // ---- policy groups (+ subscription providers)
        var proxyProviders: [String: Any] = [:]
        var groups: [[String: Any]] = []
        var groupNames: Set<String> = []
        var providerByGroup: [String: [String]] = [:]
        for item in root["policy_groups"]?.array ?? [] {
            guard let o = item.object, let (typeKey, bodyV) = o.first, let body = bodyV.object else { continue }
            let name = NCEngineRuleset.egernStr(body["name"])
            guard !name.isEmpty else { continue }
            groupNames.insert(name)
            var use: [String] = []
            for u in body["urls"]?.array ?? [] {
                guard let url = u.string, url.hasPrefix("http://") || url.hasPrefix("https://") else { continue }
                var pname = use.isEmpty ? name : name + " \(use.count + 1)"
                pname = NCRuleValidator.uniqueProviderName(base: pname, taken: { proxyProviders[$0] != nil })
                proxyProviders[pname] = [
                    "type": "http",
                    "url": url,
                    "x-convert": "nodes",
                    "path": "./proxies/" + NCRuleValidator.providerNameFor(url: url, kind: "nodes") + ".yaml",
                    "interval": body["update_interval"]?.int ?? 86400,
                    "health-check": ["enable": true, "url": "http://www.gstatic.com/generate_204", "interval": 600, "lazy": true] as [String: Any],
                ] as [String: Any]
                use.append(pname)
            }
            if !use.isEmpty { providerByGroup[name] = use }
            var members: [String] = []
            for m in body["policies"]?.array ?? [] {
                guard let s = m.string else { continue }
                if inlineProxyNames.contains(s) {
                    skipped.append("策略组「\(name)」的成员（内联节点）未转换：\(s)")
                    continue
                }
                members.append(s)
            }
            var g: [String: Any] = ["name": name]
            switch typeKey {
            case "select", "external":
                g["type"] = "select"
            case "auto_test":
                g["type"] = "url-test"
                g["url"] = "http://www.gstatic.com/generate_204"
                g["interval"] = body["interval"]?.int ?? 600
            case "fallback":
                g["type"] = "fallback"
                g["url"] = "http://www.gstatic.com/generate_204"
                g["interval"] = body["interval"]?.int ?? 600
            case "load_balance":
                g["type"] = "load-balance"
            default:
                g["type"] = "select"
                notes.append("策略组「\(name)」的类型 \(typeKey) 按手动选择导入")
            }
            if typeKey == "external", (body["type"]?.string ?? "select") == "auto_test" {
                g["type"] = "url-test"
                g["url"] = "http://www.gstatic.com/generate_204"
                g["interval"] = body["interval"]?.int ?? 600
            }
            if !members.isEmpty { g["proxies"] = members }
            if !use.isEmpty { g["use"] = use }
            if members.isEmpty && use.isEmpty {
                g["proxies"] = ["DIRECT"]
                notes.append("策略组「\(name)」没有可导入的成员，已设为 DIRECT")
            }
            groups.append(g)
        }

        // Policy resolution for rules: builtins and declared groups pass through;
        // an inline-proxy policy is unresolvable (its node is not converted).
        func resolvePolicy(_ p: String) -> String? {
            let up = p.uppercased()
            if builtinPolicies.contains(up) { return up == p ? p : up }
            if groupNames.contains(p) { return p }
            return nil
        }

        // ---- rules
        var ruleProviders: [String: Any] = [:]
        var rules: [String] = []
        var disabledRuleSets: [String] = []
        var disabledRules: [NCConfImportPort.DisabledRule] = []
        var finalRule: String? = nil
        for item in root["rules"]?.array ?? [] {
            guard let o = item.object, o.count == 1, let (k, v) = o.first, let body = v.object else {
                skipped.append("规则未转换：\(item)")
                continue
            }
            let off = body["disabled"]?.bool == true
            let policyRaw = NCEngineRuleset.egernStr(body["policy"]).trimmingCharacters(in: .whitespaces)
            if k == "rule_set" {
                let match = NCEngineRuleset.egernStr(body["match"])
                guard match.hasPrefix("http://") || match.hasPrefix("https://") else {
                    skipped.append("规则集（本地文件）未导入：\(match)")
                    continue
                }
                guard let pol = resolvePolicy(policyRaw) else {
                    skipped.append("规则集策略未转换：\(match)（\(policyRaw)）")
                    continue
                }
                var pname = NCRuleValidator.prettyProviderName(u: match, tag: "")
                pname = NCRuleValidator.uniqueProviderName(base: pname, taken: { ruleProviders[$0] != nil })
                ruleProviders[pname] = [
                    "type": "http", "behavior": "classical", "format": "text", "url": match,
                    "x-convert": "list",
                    "path": "./ruleset/" + NCRuleValidator.providerNameFor(url: match, kind: "list") + ".txt",
                    "interval": body["update_interval"]?.int ?? 86400,
                ] as [String: Any]
                rules.append("RULE-SET,\(pname),\(pol)")
                if off {
                    disabledRuleSets.append(pname)
                    disabledLines.append("[规则集] \(pname)")
                }
                continue
            }
            if k == "default" {
                if off {
                    notes.append("default 规则在源配置中停用，未导入")
                    continue
                }
                if let pol = resolvePolicy(policyRaw) { finalRule = "MATCH,\(pol)" }
                continue
            }
            let (cond, err) = NCEngineRuleset.egernCond(item)
            if let err {
                skipped.append(err)
                continue
            }
            guard let cond else { continue }
            guard !policyRaw.isEmpty, let pol = resolvePolicy(policyRaw) else {
                skipped.append("规则策略未转换：\(cond)（\(policyRaw)）")
                continue
            }
            var line = cond + "," + pol
            if cond.hasSuffix(",no-resolve"), k != "and", k != "or", k != "not" {
                line = String(cond.dropLast(",no-resolve".count)) + "," + pol + ",no-resolve"
            }
            if off {
                let occurrence = rules.filter { $0 == line }.count
                disabledRules.append(NCConfImportPort.DisabledRule(rule: line, index: occurrence))
                disabledLines.append("[规则] \(line)")
            }
            rules.append(line)
        }
        if finalRule == nil {
            let target = groups.first { ($0["type"] as? String) == "select" }?["name"] as? String ?? "DIRECT"
            finalRule = "MATCH,\(target)"
            notes.append("原配置没有 default 规则，已追加 \(finalRule!)")
        }
        if let finalRule { rules.append(finalRule) }

        // ---- remote modules (the only list with an enabled flag)
        var remotes: [ConfImportResult.RemoteModule] = []
        for item in root["modules"]?.array ?? [] {
            guard let o = item.object, let url = o["url"]?.string, !url.isEmpty else { continue }
            let enabled = o["enabled"]?.bool ?? true
            var name = NCEngineRuleset.egernStr(o["name"])
            if name.isEmpty { name = URL(string: url)?.deletingPathExtension().lastPathComponent ?? url }
            remotes.append(ConfImportResult.RemoteModule(url: url, name: name, enabled: enabled,
                                                         interval: o["update_interval"]?.int, client: nil))
            if !enabled { disabledLines.append("[模块] \(name)") }
        }

        // ---- engine sections → a module (verbatim source slices)
        var moduleText: String? = nil
        if engineSections.contains(where: { root[$0] != nil }) {
            moduleText = Self.engineModuleText(from: text, configName: NCEngineRuleset.egernStr(root["name"]))
            if let moduleText {
                let parsed = NCEngineRuleset()
                parsed.parseText(moduleText, source: "", args: [:])
                let scriptCount = parsed.rules.filter { $0.kind == "script" }.count
                rep.scripts = scriptCount
                rep.rewrites = parsed.rules.count - scriptCount
                rep.tasks = parsed.tasks.count
                rep.hostnames = parsed.hostnames.count
                rep.module = true
            }
        }

        // ---- assemble the profile
        var cfg: [String: Any] = ["mode": "rule", "rules": rules]
        if !groups.isEmpty { cfg["proxy-groups"] = groups }
        if !proxyProviders.isEmpty { cfg["proxy-providers"] = proxyProviders }
        if !ruleProviders.isEmpty { cfg["rule-providers"] = ruleProviders }
        result.yaml = NCYAML.emit(cfg)
        result.module = moduleText
        if !remotes.isEmpty { result.rewriteRemotes = remotes }

        rep.proxies = 0
        rep.groups = groups.count
        rep.rules = rules.count
        rep.providers = ruleProviders.count + proxyProviders.count
        rep.remotes = remotes.count
        if !disabledLines.isEmpty { rep.disabled = disabledLines }
        if !disabledRuleSets.isEmpty { rep.disabledRuleSets = disabledRuleSets }
        if !disabledRules.isEmpty { rep.disabledRules = disabledRules }
        if !skipped.isEmpty { rep.skipped = skipped }
        if !notes.isEmpty { rep.notes = notes }
        result.report = rep
        return result
    }

    /// The engine sections of the source document, sliced out verbatim by
    /// top-level key (with the document's `name:` line when present), so the
    /// module the import attaches is the source's own YAML — no re-serialising.
    static func engineModuleText(from text: String, configName: String) -> String {
        let wanted = Set(engineSections)
        var blocks: [String] = []
        var current: [String] = []
        var currentWanted = false
        func flush() {
            if currentWanted && !current.isEmpty { blocks.append(current.joined(separator: "\n")) }
            current = []
            currentWanted = false
        }
        for raw in text.components(separatedBy: "\n") {
            let isTop = !raw.hasPrefix(" ") && !raw.hasPrefix("\t") && !raw.hasPrefix("-") && raw.contains(":")
            if isTop {
                flush()
                let key = String(raw.split(separator: ":", maxSplits: 1).first ?? "").trimmingCharacters(in: .whitespaces)
                currentWanted = wanted.contains(key)
            }
            current.append(raw)
        }
        flush()
        guard !blocks.isEmpty else { return "" }
        var head = ""
        if !configName.isEmpty { head = "name: \(configName)\n" }
        return head + blocks.joined(separator: "\n") + "\n"
    }
}
