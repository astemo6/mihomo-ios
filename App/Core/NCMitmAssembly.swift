import Foundation

/// E-B1 stage 4: the engine config + ruleset assembly — a port of
/// bridge/mitm/config.go's Config / LoadConfig / Build (the parse
/// layer itself is the B6 port, NCEngineRuleset). The prep consumes
/// the built ruleset's core rules (mapped onto the profile by
/// NCRuntimeSteps.resolveCoreRules) and hostnames; the full rule /
/// task / panel lists are retained for the rewrite snapshot and
/// script manifest ports.
///
/// Parser-state note (nc-callsite-audit): the parser now tracks a
/// module's skip-cert-verify / h2 flags (NCEngineRuleset), and Build
/// propagates skip-cert-verify with Go's only-true semantics. The
/// panel model carries taskId, but no Swift parser assigns it yet,
/// so filterSwitches' task-bound check is in place but inert until
/// a dialect parser starts filling taskId in.

// MARK: - Config (mitm.Config / Item / Module / ScriptResource)

/// The Decodable conformances are hand-written with decodeIfPresent
/// throughout: Go's json.Unmarshal tolerates missing keys (zero
/// values), while Swift's synthesized conformance would reject a
/// sparse engine.json outright.
struct NCEngineItem: Decodable {
    var id: String = ""
    var enabled: Bool = false
    var line: String = ""
    var note: String? = nil

    enum CodingKeys: String, CodingKey { case id, enabled, line, note }

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        line = try c.decodeIfPresent(String.self, forKey: .line) ?? ""
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

struct NCEngineModule: Decodable {
    var id: String = ""
    var name: String = ""
    var url: String = ""
    var enabled: Bool = false
    var args: [String: String]? = nil
    var policies: [String: String]? = nil
    var updatedAt: Double? = nil
    var interval: Int? = nil

    enum CodingKeys: String, CodingKey { case id, name, url, enabled, args, policies, updatedAt, interval }

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        args = try c.decodeIfPresent([String: String].self, forKey: .args)
        policies = try c.decodeIfPresent([String: String].self, forKey: .policies)
        updatedAt = try c.decodeIfPresent(Double.self, forKey: .updatedAt)
        interval = try c.decodeIfPresent(Int.self, forKey: .interval)
    }
}

struct NCScriptResource: Decodable {
    var disabled: Bool = false
    var interval: Int = 0

    enum CodingKeys: String, CodingKey { case disabled, interval }

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        disabled = try c.decodeIfPresent(Bool.self, forKey: .disabled) ?? false
        interval = try c.decodeIfPresent(Int.self, forKey: .interval) ?? 0
    }
}

struct NCEngineConfig: Decodable {
    var enabled: Bool = false
    var scriptsEnabled: Bool? = nil
    var mitm: Bool = false
    var skipCertVerify: Bool = false
    var h2: Bool? = nil
    var captureBodies: Bool? = nil
    var hostnames: [String] = []
    var rules: [NCEngineItem] = []
    var scripts: [NCEngineItem] = []
    var modules: [NCEngineModule] = []
    var scriptResources: [String: NCScriptResource]? = nil
    var quic: String = ""
    var quicAllow: [String] = []
    var language: String = ""

    enum CodingKeys: String, CodingKey { case enabled, scriptsEnabled, mitm, skipCertVerify, h2, captureBodies, hostnames, rules, scripts, modules, scriptResources, quic, quicAllow, language }

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        scriptsEnabled = try c.decodeIfPresent(Bool.self, forKey: .scriptsEnabled)
        mitm = try c.decodeIfPresent(Bool.self, forKey: .mitm) ?? false
        skipCertVerify = try c.decodeIfPresent(Bool.self, forKey: .skipCertVerify) ?? false
        h2 = try c.decodeIfPresent(Bool.self, forKey: .h2)
        captureBodies = try c.decodeIfPresent(Bool.self, forKey: .captureBodies)
        hostnames = try c.decodeIfPresent([String].self, forKey: .hostnames) ?? []
        rules = try c.decodeIfPresent([NCEngineItem].self, forKey: .rules) ?? []
        scripts = try c.decodeIfPresent([NCEngineItem].self, forKey: .scripts) ?? []
        modules = try c.decodeIfPresent([NCEngineModule].self, forKey: .modules) ?? []
        scriptResources = try c.decodeIfPresent([String: NCScriptResource].self, forKey: .scriptResources)
        quic = try c.decodeIfPresent(String.self, forKey: .quic) ?? ""
        quicAllow = try c.decodeIfPresent([String].self, forKey: .quicAllow) ?? []
        language = try c.decodeIfPresent(String.self, forKey: .language) ?? ""
    }

    var rewriteOn: Bool { enabled }
    var scriptsOn: Bool { scriptsEnabled ?? enabled }
    var anyOn: Bool { rewriteOn || scriptsOn }
    var h2On: Bool { h2 ?? true }
    var captureOn: Bool { captureBodies ?? true }

    /// mitm Config.scriptLanguage ($environment.language).
    var scriptLanguage: String {
        let l = language.trimmingCharacters(in: .whitespaces)
        return l.isEmpty ? "zh-Hans" : l
    }

    /// mitm LoadConfig: engine/engine.json; a missing file is the
    /// all-off config. Go ignores the Unmarshal error and keeps
    /// whatever fields decoded — so after a strict decode failure,
    /// fall back to a per-field lossy pass (case-insensitive keys,
    /// per-element lossy arrays) instead of dropping the whole file
    /// because one field is malformed.
    static func load(home: String) -> NCEngineConfig {
        let url = URL(fileURLWithPath: home)
            .appendingPathComponent("engine/engine.json")
        guard let data = try? Data(contentsOf: url) else { return NCEngineConfig() }
        if let cfg = try? JSONDecoder().decode(NCEngineConfig.self, from: data) {
            return cfg
        }
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return NCEngineConfig()
        }
        func val(_ key: String) -> Any? {
            if let v = root[key] { return v }
            let lk = key.lowercased()
            for (k, v) in root where k.lowercased() == lk { return v }
            return nil
        }
        func boolF(_ key: String) -> Bool? { val(key) as? Bool }
        func strF(_ key: String) -> String? { val(key) as? String }
        func strArr(_ key: String) -> [String] {
            (val(key) as? [Any])?.compactMap { $0 as? String } ?? []
        }
        func lossy<T: Decodable>(_ key: String, as _: T.Type) -> [T] {
            guard let arr = val(key) as? [Any] else { return [] }
            return arr.compactMap { el in
                guard let d = try? JSONSerialization.data(withJSONObject: el) else { return nil }
                return try? JSONDecoder().decode(T.self, from: d)
            }
        }
        var cfg = NCEngineConfig()
        cfg.enabled = boolF("enabled") ?? false
        cfg.scriptsEnabled = boolF("scriptsEnabled")
        cfg.mitm = boolF("mitm") ?? false
        cfg.skipCertVerify = boolF("skipCertVerify") ?? false
        cfg.h2 = boolF("h2")
        cfg.captureBodies = boolF("captureBodies")
        cfg.hostnames = strArr("hostnames")
        cfg.rules = lossy("rules", as: NCEngineItem.self)
        cfg.scripts = lossy("scripts", as: NCEngineItem.self)
        cfg.modules = lossy("modules", as: NCEngineModule.self)
        if let dict = val("scriptResources") as? [String: Any] {
            var res: [String: NCScriptResource] = [:]
            for (k, v) in dict {
                if let d = try? JSONSerialization.data(withJSONObject: v),
                   let r = try? JSONDecoder().decode(NCScriptResource.self, from: d) {
                    res[k] = r
                }
            }
            cfg.scriptResources = res
        }
        cfg.quic = strF("quic") ?? ""
        cfg.quicAllow = strArr("quicAllow")
        cfg.language = strF("language") ?? ""
        return cfg
    }

    static func engineDir(_ home: String) -> String {
        URL(fileURLWithPath: home).appendingPathComponent("engine").path
    }

    static func modulePath(home: String, id: String) -> String {
        URL(fileURLWithPath: home)
            .appendingPathComponent("engine/modules/\(safeName(id)).txt").path
    }

    /// mitm safeName: bytes outside [A-Za-z0-9._-] become '_'
    /// (byte-wise, so a multibyte character yields several).
    static func safeName(_ s: String) -> String {
        var bytes: [UInt8] = []
        for b in s.utf8 {
            let ok = (b >= 0x61 && b <= 0x7A) || (b >= 0x41 && b <= 0x5A)
                || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F || b == 0x2E
            bytes.append(ok ? b : 0x5F)
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

// MARK: - Build (mitm.Build + filters + mapPolicy)

enum NCMitmBuild {

    /// Module file bytes -> text. UTF-8 first (every real module: 中文 / emoji policy names, script names, arguments,
    /// panel titles), Latin-1 only for a file that is not valid UTF-8 (#139 decoded Latin-1 first, which never fails,
    /// so every UTF-8 module was mojibaked). Same order as EngineStore / ModuleGallery.
    static func moduleText(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) ?? String(decoding: data, as: UTF8.self)
    }

    static func build(home: String, cfg: NCEngineConfig?) -> NCEngineRuleset {
        let rs = NCEngineRuleset()
        guard let cfg else { return rs }
        rs.addHosts(cfg.hostnames.joined(separator: ","))
        if cfg.anyOn {
            for it in cfg.rules where it.enabled {
                rs.parseLine(it.line, section: "", source: "用户")
            }
            for it in cfg.scripts where it.enabled {
                rs.parseLine(it.line, section: "script", source: "用户")
            }
            for m in cfg.modules where m.enabled {
                let path = NCEngineConfig.modulePath(home: home, id: m.id)
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                    rs.errors.append("模块 \(m.name) 未下载")
                    continue
                }
                let sub = NCEngineRuleset()
                sub.parseText(moduleText(data), source: m.name, args: m.args ?? [:])
                // mitm config.go Build: a module's skip-cert-verify=true
                // propagates to the built ruleset (false never clears).
                if sub.skipCertVerify == true { rs.skipCertVerify = true }
                rs.rules.append(contentsOf: sub.rules)
                rs.tasks.append(contentsOf: sub.tasks)
                rs.panels.append(contentsOf: sub.panels)
                rs.hostnames.append(contentsOf: sub.hostnames)
                let policies = m.policies ?? [:]
                for r in sub.coreRules {
                    rs.coreRules.append(mapPolicy(r, policies))
                }
                for e in sub.errors {
                    rs.errors.append(m.name + "：" + e)
                }
            }
        }
        filterScripts(cfg, rs)
        filterSwitches(cfg, rs)
        rs.hostnames = dedupe(rs.hostnames)
        return rs
    }

    static func dedupe(_ input: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for s in input where !s.isEmpty && !seen.contains(s) {
            seen.insert(s)
            out.append(s)
        }
        return out
    }

    /// mitm mapPolicy: rewrite a module [Rule] line's policy through
    /// the module's policy picks (splitTop / policyIndex are the
    /// mitm variants — no trimming).
    static func mapPolicy(_ rule: String, _ m: [String: String]) -> String {
        if m.isEmpty { return rule }
        var parts = NCEngineRuleset.splitTop(rule)
        let idx = NCRuntimeSteps.mitmPolicyIndex(parts)
        if idx < 0 { return rule }
        if let to = m[parts[idx]], !to.isEmpty {
            parts[idx] = to
        }
        return parts.joined(separator: ",")
    }

    /// mitm scriptAllowed: false when the resource manager disabled
    /// the script; an interval override applies to the script.
    private static func scriptAllowed(
        _ cfg: NCEngineConfig, path: String, applyInterval: (Int) -> Void
    ) -> Bool {
        guard let resources = cfg.scriptResources, let r = resources[path] else { return true }
        if r.interval > 0 { applyInterval(r.interval) }
        return !r.disabled
    }

    /// mitm filterScripts.
    private static func filterScripts(_ cfg: NCEngineConfig, _ rs: NCEngineRuleset) {
        guard let resources = cfg.scriptResources, !resources.isEmpty else { return }
        // Go applies the interval override to the script in place
        // before deciding; the Swift models are value types, so
        // mutate by index first.
        for i in rs.rules.indices where rs.rules[i].kind == "script" {
            if let path = rs.rules[i].script?.path, let r = resources[path], r.interval > 0 {
                rs.rules[i].script?.updateInterval = r.interval
            }
        }
        rs.rules = rs.rules.filter { r in
            guard r.kind == "script", let sc = r.script else { return true }
            return scriptAllowed(cfg, path: sc.path) { _ in }
        }
        // mitm config.go scriptAllowed mutates tasks too: a resource
        // interval override lands on the task's script before filtering
        // (resources.go refreshes tasks by tk.Script.UpdateInterval).
        for i in rs.tasks.indices {
            let key = rs.tasks[i].script?.path ?? rs.tasks[i].path
            if !key.isEmpty, let r = resources[key], r.interval > 0 {
                rs.tasks[i].script?.updateInterval = r.interval
            }
        }
        var off = Set<String>()
        rs.tasks = rs.tasks.filter { t in
            // The Swift task model carries the script's path/name
            // flat; Go tests t.Script (a task without one is allowed).
            if t.path.isEmpty { return true }
            let allowed = scriptAllowed(cfg, path: t.path) { _ in }
            if !allowed { off.insert(t.name) }
            return allowed
        }
        if !off.isEmpty {
            rs.panels = rs.panels.filter { p in
                guard let s = p.script, !s.isEmpty else { return true }
                return !off.contains(s)
            }
        }
    }

    /// mitm filterSwitches.
    private static func filterSwitches(_ cfg: NCEngineConfig, _ rs: NCEngineRuleset) {
        let rew = cfg.rewriteOn, scr = cfg.scriptsOn
        if rew && scr { return }
        rs.rules = rs.rules.filter { r in
            r.kind == "script" ? scr : rew
        }
        if !scr {
            rs.tasks = []
            rs.panels = rs.panels.filter { p in
                // mitm filterSwitches also drops panels bound to a task
                // (TaskID != ""); the model carries taskId even though no
                // parser assigns it yet (see header note).
                (p.script == nil || p.script!.isEmpty) && (p.taskId ?? "").isEmpty
            }
        }
    }
}
