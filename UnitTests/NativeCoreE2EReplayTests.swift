import XCTest
@testable import Mihomo

/// Tern E2E replay, stage 1 of 2 (feat/nc-e2e, .github/workflows/e2e-replay.yml): a real user config goes through
/// the App's own import path — ImportRouter.route → ConfImport.save (QX .conf: profile + 「（重写）」 module +
/// [rewrite_remote] modules + connection settings + rule-set / node-set downloads) or TernFullExport.applyInApp (a
/// Tern full export) — and then the runtime generation the connect path runs (NativeRuntimePrep: NCRuntimeBuilder +
/// lowerForNative + script manifest + rewrite / MitM snapshot), into the app container's home. Stage 2
/// (E2ETests/TernE2ETunnelTests.swift, its own test bundle because it compiles the PacketTunnel sources) starts
/// NativeCore in-process on exactly those files.
///
/// Only runs when the workflow sets TEST_RUNNER_TERN_E2E=1; every normal unit-test run skips it.
@MainActor
final class NativeCoreE2EReplayTests: XCTestCase {

    func test1_ImportAndGenerateRuntime() async throws {
        guard E2EReport.enabled else { throw XCTSkip("E2E replay: set TEST_RUNNER_TERN_E2E=1 (e2e-replay.yml)") }
        let r = E2EReport(stage: "app")
        guard let fixture = E2EReport.fixtureText() else {
            r.record("fixture", .fail, "no fixture: TERN_E2E_FIXTURE unset / unreadable and no Documents/tern-e2e/fixture.conf")
            XCTFail("no fixture")
            return
        }
        r.addSecrets(Self.fixtureSecrets(fixture.text))
        r.record("fixture", .info, "\(fixture.text.utf8.count) bytes from \(fixture.source)")

        let home = AppShared.homeURL.path
        // A clean container: the replay owns this simulator (CI only, guarded by TERN_E2E).
        Self.resetAppState()

        // 1. App import path (the same routing the import sheet / Files / clipboard use).
        let t0 = Date()
        guard let action = ImportRouter.route(text: fixture.text, name: "E2E") else {
            r.record("import", .fail, "ImportRouter.route: not recognised as a profile / Surge / QX config / full export")
            XCTFail("import route"); return
        }
        var importDetail = ""
        var confReport: ConfImportResult.Report?
        do {
            switch action {
            case .fullExport(_, let text):
                let payload = try TernFullExport.parse(text)
                importDetail = try await TernFullExport.applyInApp(payload)
            case .confText(let name, let text):
                let conv = await ConfImportResult.convert(text)
                confReport = conv.report
                if let e = conv.error, !e.isEmpty { throw ProfileStore.StoreError.invalid(e) }
                importDetail = try await ConfImport.save(text: text, name: name, result: conv, store: ProfileStore.shared)
                // A plain QX export keeps its CA in [mitm] passphrase / p12, which the conf import skips; the user
                // imports it on the CA page (NCCAManager.importP12) — do the same, so MitM uses the fixture CA.
                if let ca = Self.qxCA(text) {
                    do {
                        try NCCAManager.importP12(home: home, data: ca.p12, password: ca.pass)
                        NCCAManager.shared.reloadCA(home: home)
                        r.record("mitm-ca", .info, "fixture CA imported from [mitm] p12")
                    } catch {
                        r.record("mitm-ca", .fail, "fixture [mitm] p12 could not be imported: \(error.localizedDescription)")
                    }
                }
            case .profileText(let name, let text):
                _ = try await ProfileStore.shared.addLocal(name: name, text: text)
                importDetail = "mihomo profile"
            default:
                r.record("import", .fail, "unsupported import action \(action.id)")
                XCTFail("import action"); return
            }
        } catch {
            r.record("import", .fail, "import failed: \(error.localizedDescription)")
            XCTFail("import failed"); return
        }
        guard let profile = ProfileStore.shared.profiles.last else {
            r.record("import", .fail, "no profile after import")
            XCTFail("no profile"); return
        }
        ProfileStore.shared.activeID = profile.id
        AppShared.activeProfileID = profile.id
        let importMs = Int(Date().timeIntervalSince(t0) * 1000)
        if let rep = confReport {
            r.note("import report: format \(rep.format ?? "?"), proxies \(rep.proxies ?? 0), groups \(rep.groups ?? 0), rules \(rep.rules ?? 0), rule providers \(rep.providers ?? 0), rewrites \(rep.rewrites ?? 0), scripts \(rep.scripts ?? 0), tasks \(rep.tasks ?? 0), MitM hosts \(rep.hostnames ?? 0), remote modules \(rep.remotes ?? 0), skipped \(rep.skipped?.count ?? 0), disabled \(rep.disabled?.count ?? 0)")
            for s in (rep.skipped ?? []).prefix(40) { r.note("import skipped: \(s)") }
        }
        r.record("import", .pass, "\(importMs) ms — \(importDetail.split(separator: "\n").first.map(String.init) ?? "")")

        // The switches a user who runs this config has on (重写 / 脚本 / HTTPS 解密); the CA exists (fixture or generated).
        EngineStore.shared.config.enabled = true
        EngineStore.shared.config.scriptsEnabled = true
        EngineStore.shared.config.mitm = true
        EngineStore.shared.save(reload: false)
        if NCCAManager.shared.ensureCA(home: home) == nil {
            r.record("mitm-ca", .fail, "no MitM CA (fixture CA unreadable and none could be generated)")
        }

        // 2. Runtime generation (the connect path's NativeRuntimePrep, see E2EPrep below).
        let t1 = Date()
        let prepErr = E2EPrep.prepare(home: home, profile: profile.fileURL)
        let prepMs = Int(Date().timeIntervalSince(t1) * 1000)
        if let prepErr {
            r.record("runtime-generation", .fail, "\(prepMs) ms: \(prepErr)")
            XCTFail("prepare failed"); return
        }
        let counts = Self.runtimeCounts(home: home)
        r.addSecrets(counts.secrets)
        let unloadable = counts.badScripts
        let detail = "\(prepMs) ms — proxies \(counts.proxies), proxy-providers \(counts.providers), groups \(counts.groups), rules \(counts.rules), rule-providers \(counts.ruleProviders), modules \(counts.modules), rewrite rules \(counts.rewriteRules), MitM hosts \(counts.mitmHosts), scripts \(counts.scripts) (\(unloadable.count) unloadable), tasks \(counts.tasks), warnings \(counts.warnings.count)"
        r.record("runtime-generation", counts.proxies + counts.providers > 0 && counts.rules > 0 ? .pass : .fail, detail)
        for w in counts.warnings { r.note("prep warning: \(w)") }
        if unloadable.isEmpty {
            r.record("scripts-loadable", .pass, "\(counts.scripts) script(s), all loaded")
        } else {
            r.record("scripts-loadable", .fail, "\(unloadable.count) of \(counts.scripts) unloadable: " + unloadable.prefix(12).joined(separator: "; "))
            for u in unloadable { r.note("unloadable script: \(u)") }
        }

        E2EReport.writeHandoff([
            "home": home, "profile": profile.fileURL.path, "profileID": profile.id,
            "proxies": counts.proxies, "providers": counts.providers, "groups": counts.groups, "rules": counts.rules,
            "ruleProviders": counts.ruleProviders, "mitmHosts": counts.mitmHosts, "scripts": counts.scripts,
            "tasks": counts.tasks, "importMs": importMs, "prepMs": prepMs,
        ])
    }

    // MARK: helpers

    private static func resetAppState() {
        let fm = FileManager.default
        let root = AppShared.containerURL
        for name in ["profiles", "profiles.json", "mihomo"] {
            try? fm.removeItem(at: root.appendingPathComponent(name))
        }
        AppShared.activeProfileID = nil
        ProfileStore.shared.load()
        EngineStore.shared.config = EngineConfig()
        EngineStore.shared.save(reload: false)
        _ = AppShared.homeURL // recreate
    }

    /// QX [mitm] passphrase / p12 (base64 PKCS#12).
    static func qxCA(_ text: String) -> (p12: Data, pass: String)? {
        var inMitm = false
        var pass: String?, p12: String?
        for raw in text.components(separatedBy: .newlines) {
            let l = raw.trimmingCharacters(in: .whitespaces)
            if l.hasPrefix("[") { inMitm = l.lowercased() == "[mitm]"; continue }
            guard inMitm, let eq = l.firstIndex(of: "=") else { continue }
            let k = l[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let v = l[l.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if k == "passphrase" || k == "ca-passphrase" { pass = v }
            if k == "p12" || k == "ca-p12" { p12 = v }
        }
        guard let pass, let p12, let data = Data(base64Encoded: p12, options: .ignoreUnknownCharacters) else { return nil }
        return (p12: data, pass: pass)
    }

    /// Server addresses, passwords, uuids and URLs of the fixture — redacted from every printed line.
    static func fixtureSecrets(_ text: String) -> [String] {
        var out: [String] = []
        let keys: Set<String> = ["password", "passphrase", "p12", "ca-p12", "ca-passphrase", "obfs-host", "obfs-uri", "sni",
                                 "tls-host", "username", "psk", "public-key", "private-key", "short-id", "uuid", "token", "auth"]
        for raw in text.components(separatedBy: .newlines) {
            let l = raw.trimmingCharacters(in: .whitespaces)
            if l.isEmpty || l.hasPrefix("#") || l.hasPrefix(";") || l.hasPrefix("[") { continue }
            for part in l.components(separatedBy: ",") {
                let p = part.trimmingCharacters(in: .whitespaces)
                if p.hasPrefix("http://") || p.hasPrefix("https://") {
                    out.append(p.components(separatedBy: " ").first ?? p)
                    if let u = URL(string: p), let host = u.host { out.append(host) }
                }
                guard let eq = p.firstIndex(of: "=") else { continue }
                let k = p[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
                let v = p[p.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                if keys.contains(k) { out.append(v) }
                // QX server_local: "<type> = host:port, …"
                if ["shadowsocks", "vmess", "vless", "trojan", "http", "socks5", "hysteria2", "tuic", "anytls"].contains(k) {
                    let hp = String(v)
                    out.append(hp)
                    if let c = hp.lastIndex(of: ":") { out.append(String(hp[..<c])) }
                }
            }
        }
        return out
    }

    struct Counts {
        var proxies = 0, providers = 0, groups = 0, rules = 0, ruleProviders = 0, modules = 0
        var rewriteRules = 0, mitmHosts = 0, scripts = 0, tasks = 0
        var badScripts: [String] = []
        var warnings: [String] = []
        var secrets: [String] = []
    }

    static func runtimeCounts(home: String) -> Counts {
        var c = Counts()
        let h = URL(fileURLWithPath: home)
        func json(_ name: String) -> Any? {
            guard let d = try? Data(contentsOf: h.appendingPathComponent(name)) else { return nil }
            return try? JSONSerialization.jsonObject(with: d)
        }
        if let rt = json("nativecore-runtime.json") as? [String: Any] {
            let proxies = rt["proxies"] as? [[String: Any]] ?? []
            c.proxies = proxies.count
            for p in proxies {
                for k in ["server", "password", "uuid", "servername", "sni", "private-key", "public-key", "psk", "auth-str", "username"] {
                    if let v = p[k] as? String { c.secrets.append(v) }
                }
                if let ws = p["ws-opts"] as? [String: Any] {
                    if let path = ws["path"] as? String { c.secrets.append(path) }
                    if let hd = ws["headers"] as? [String: Any], let host = hd["Host"] as? String { c.secrets.append(host) }
                }
            }
            let pp = rt["proxy-providers"] as? [String: Any] ?? [:]
            c.providers = pp.count
            for (_, v) in pp { if let o = v as? [String: Any], let u = o["url"] as? String { c.secrets.append(u) } }
            c.groups = (rt["proxy-groups"] as? [Any])?.count ?? 0
            c.rules = (rt["rules"] as? [Any])?.count ?? 0
            let rp = rt["rule-providers"] as? [String: Any] ?? [:]
            c.ruleProviders = rp.count
            for (_, v) in rp { if let o = v as? [String: Any], let u = o["url"] as? String { c.secrets.append(u) } }
        }
        c.modules = EngineStore.shared.config.modules.count
        if let rw = json("nativecore-rewrite.json") as? [String: Any] {
            c.rewriteRules = (rw["rules"] as? [Any])?.count ?? 0
            c.mitmHosts = (rw["inc"] as? [Any])?.count ?? 0
        }
        if let sc = json("nativecore-scripts.json") as? [String: Any] {
            let scripts = sc["scripts"] as? [[String: Any]] ?? []
            c.scripts = scripts.count
            c.tasks = (sc["tasks"] as? [Any])?.count ?? 0
            for s in scripts + (sc["tasks"] as? [[String: Any]] ?? []) {
                if let e = s["err"] as? String, !e.isEmpty { c.badScripts.append("\(s["name"] as? String ?? "?"): \(e)") }
            }
        }
        if let prep = json("nativecore-prep.json") as? [String: Any] {
            c.warnings = prep["warnings"] as? [String] ?? []
        }
        return c
    }
}

/// The connect path's runtime generation (NativeRuntimePrep.prepareSyncLocked), callable without the App Group
/// guard: an unsigned simulator build has no App Group container, so `NativeRuntimePrep.prepare()` stops at
/// `AppShared.containerOK` before doing anything (AppShared falls back to Documents for every other path).
/// Same calls, same order, same files, same transaction (PrepTransaction) — keep in step with NativeRuntimePrep.swift.
/// TODO(after fix/app-toggle-hitch lands, it rewrites that file): replace with an internal seam in NativeRuntimePrep
/// (prepareSync(home:profile:…)) so this copy cannot drift.
enum E2EPrep {
    private final class State {
        var rep: NCRuntimeBuilder.PrepReport
        var groupOrder: [String] = []
        init(rep: NCRuntimeBuilder.PrepReport) { self.rep = rep }
    }

    static func prepare(home: String, profile: URL) -> String? {
        PrepTransaction.removeStale(home: home)
        let build = NCPrepMarkers.currentBuild
        let tx = PrepTransaction(home: home)
        defer { tx.discard() }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profile.path)
        let safeMode = req.settings.core.safeMode
        guard let profileData = NCRuntimeFiles.readRuntimeProfile(home: home, path: profile.path, safe: safeMode) else {
            return "读取配置失败"
        }
        var rep = NCRuntimeBuilder.PrepReport()
        rep.at = Int64(Date().timeIntervalSince1970)
        rep.profile = (profile.path as NSString).lastPathComponent
        rep.build = build
        let cfg: NCEngineConfig? = safeMode ? nil : NCEngineConfig.load(home: home)
        let rs: NCEngineRuleset? = cfg.map { NCMitmBuild.build(home: home, cfg: $0) }
        let box = State(rep: rep)
        // Optional + guard, like NativeRuntimePrep (no deferred-initialized `let`: build #359 SIL verifier crash shape).
        var builtOpt: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])? = nil
        do {
            builtOpt = try NCRuntimeBuilder.build(profile: profileData, req: req, fd: 0) { raw in
                if let cfg = cfg {
                    if cfg.anyOn, let rs = rs {
                        var unresolved: Set<String>? = nil
                        let pre = NCRuntimeSteps.resolveCoreRules(raw, rules: rs.coreRules, unresolved: &unresolved)
                        if !pre.isEmpty {
                            raw["rules"] = .array(pre.map { NCJSONValue.string($0) } + raw.list("rules"))
                        }
                        NCRuntimeSteps.addRemoteModuleRules(&raw, coreRules: rs.coreRules, req.settings)
                    }
                    if cfg.quic == "all" {
                        raw["rules"] = .array([.string("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")] + raw.list("rules"))
                    }
                }
                NCRuntimeBuilder.lowerForNative(home: home, &raw, &box.rep, stageDir: tx.stage) { box.rep.warnings = (box.rep.warnings ?? []) + [$0] }
                box.groupOrder = NCRuntimeSteps.runtimeGroupNames(raw)
            }
        } catch let err as NCRuntimeBuilder.BuildError {
            return err.message
        } catch {
            return error.localizedDescription
        }
        guard let built = builtOpt else { return "native runtime: 构建失败" }
        rep = box.rep
        do {
            tx.adoptStagedDirectory("nativecore-geosite")
            let scriptRS: NCEngineRuleset? = (cfg != nil && cfg!.anyOn) ? rs : nil
            var scriptKeep: Set<String>? = nil
            do {
                let man = try NCScriptManifest.buildManifest(home: home, cfg: cfg, rs: scriptRS)
                rep.scripts = man.scripts
                if man.bad > 0 { rep.warnings = (rep.warnings ?? []) + ["\(man.bad) 个脚本加载失败（见 nativecore-scripts.json）"] }
                try tx.put(man.data, NCScriptManifest.scriptManifestFile)
                scriptKeep = man.keep
            } catch {
                rep.scripts = 0
                rep.warnings = (rep.warnings ?? []) + ["脚本清单生成失败，本次未启用脚本：" + error.localizedDescription]
                try tx.put(try JSONEncoder().encode(NCScriptManifestRoot()), NCScriptManifest.scriptManifestFile)
            }
            rep.rewrite = false
            rep.mitmHosts = 0
            if let cfg = cfg, let rs = rs, (cfg.anyOn || (cfg.mitm && !rs.hostnames.isEmpty)) {
                do {
                    let (snap, hosts) = try NCRewriteSnapshotBuilder.exportData(home: home, cfg: cfg, rs: rs)
                    try tx.put(snap, "nativecore-rewrite.json")
                    rep.rewrite = true
                    rep.mitmHosts = hosts
                } catch let e as PrepTransaction.TxError {
                    throw e
                } catch {
                    rep.warnings = (rep.warnings ?? []) + ["重写 / MitM 快照生成失败，本次未启用：" + error.localizedDescription]
                    tx.remove("nativecore-rewrite.json")
                }
            } else {
                tx.remove("nativecore-rewrite.json")
            }
            try? tx.put(try JSONEncoder().encode(box.groupOrder), "runtime-groups.json")
            try tx.put(built.data, "runtime.yaml")
            guard let runtimeJSON = NCRuntimeBuilder.jsonData(built.raw) else { return "native runtime JSON: 序列化失败" }
            try tx.put(runtimeJSON, "nativecore-runtime.json")
            try? tx.put(try JSONEncoder().encode(rep), "nativecore-prep.json")
            try tx.commit()
            if let keep = scriptKeep { NCScriptManifest.removeObsoleteCode(home: home, keep: keep) }
        } catch {
            return error.localizedDescription
        }
        return nil
    }
}
