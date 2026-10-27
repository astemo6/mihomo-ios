import XCTest
@testable import Tern

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
                importDetail = "clash profile"
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
        // ConfImport.save lists each remote rewrite module that failed to download on its own line after the summary
        // ("<name>：<error>"). A module whose URL answers 4xx (moved / removed / behind a bot challenge) is the
        // fixture's environment → INFO; any other failure (timeout, decoding, TLS, …) is our fetcher → FAIL.
        let mods = EngineStore.shared.config.modules
        let modNames = Set(mods.map(\.name))
        let failedModules = importDetail.split(separator: "\n").dropFirst().map(String.init).filter { l in
            guard let c = l.range(of: "：") else { return false }
            return modNames.contains(String(l[..<c.lowerBound]))
        }
        if !failedModules.isEmpty {
            var gone: [String] = [], broken: [String] = []
            for line in failedModules {
                let name = String(line[..<line.range(of: "：")!.lowerBound])
                let off = mods.first(where: { $0.name == name }).map { !$0.enabled } ?? false
                let item = line + (off ? " (disabled in the fixture)" : "")
                let l = line.lowercased()
                if l.contains("http 4") { gone.append(item) } else { broken.append(item) }
            }
            for f in failedModules { r.note("remote module not downloaded: \(f)") }
            if !gone.isEmpty {
                r.record("modules-unavailable", .info, "\(gone.count) remote rewrite module URL(s) answer 4xx (gone / moved / bot challenge — not a Tern fetch bug): " + gone.prefix(8).joined(separator: "; "))
            }
            r.record("modules-download", broken.isEmpty ? .pass : .fail,
                     broken.isEmpty ? "\(rep0RemoteCount(confReport) - gone.count) of \(rep0RemoteCount(confReport)) remote module(s) downloaded; the rest are unavailable upstream"
                                    : "\(broken.count) remote module(s) failed for a reason other than HTTP 4xx: " + broken.prefix(8).joined(separator: "; "))
        }

        // The switches a user who runs this config has on (重写 / 脚本 / HTTPS 解密); the CA exists (fixture or generated).
        r.note("engine switches on (rewrite / scripts / MitM) + EngineStore.save")
        EngineStore.shared.config.enabled = true
        EngineStore.shared.config.scriptsEnabled = true
        EngineStore.shared.config.mitm = true
        EngineStore.shared.save(reload: false)

        // 2. CA + runtime generation (the connect path's NativeRuntimePrep.prepareSyncLocked via prepareSyncForReplay). Off the main actor
        // like NativeRuntimePrep.prepare() (Task.detached): run 40261727985 hung here for 10+ min when it ran on the
        // main thread. A watchdog turns a hang into a named FAIL with the last step reached instead of a silent
        // timeout of the whole job.
        let t1 = Date()
        let profileURL = profile.fileURL
        let step = E2EStep()
        let progress: @Sendable (String) -> Void = { [r] s in
            step.set(s)
            r.note(String(format: "prep +%.1fs: %@", Date().timeIntervalSince(t1), s))
        }
        let limit = Double(E2EReport.env("TERN_E2E_PREP_TIMEOUT").flatMap(Int.init) ?? 600)
        let outcome: E2EPrepOutcome = await withCheckedContinuation { (cont: CheckedContinuation<E2EPrepOutcome, Never>) in
            let once = E2EOnce()
            DispatchQueue.global(qos: .userInitiated).async {
                progress("ensureCA")
                let caOK = NCCAManager.shared.ensureCA(home: home) != nil
                progress("prepare")
                // The real connect-path generation (NativeRuntimePrep.prepareSyncLocked through its replay seam), not
                // a copy: the copy this test used to carry could drift from what a device runs.
                let err = NativeRuntimePrep.prepareSyncForReplay(home: home, profile: profileURL)
                progress("done")
                if once.take() { cont.resume(returning: .finished(caOK: caOK, error: err)) }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + limit) {
                if once.take() { cont.resume(returning: .timedOut(step: step.get())) }
            }
        }
        let prepMs = Int(Date().timeIntervalSince(t1) * 1000)
        var prepErr: String? = nil
        switch outcome {
        case .timedOut(let at):
            r.record("runtime-generation", .fail, "hung: no result after \(Int(limit)) s, last step \(at)")
            XCTFail("prepare hung at \(at)")
            return
        case .finished(let caOK, let err):
            if !caOK { r.record("mitm-ca", .fail, "no MitM CA (fixture CA unreadable and none could be generated)") }
            prepErr = err
        }
        if let prepErr {
            r.record("runtime-generation", .fail, "\(prepMs) ms: \(prepErr)")
            XCTFail("prepare failed"); return
        }
        let counts = Self.runtimeCounts(home: home)
        for l in Self.shapeNotes(home: home, profile: profileURL) { r.note(l) }
        r.addSecrets(counts.secrets)
        let unloadable = counts.badScripts
        let detail = "\(prepMs) ms — proxies \(counts.proxies), proxy-providers \(counts.providers), groups \(counts.groups), rules \(counts.rules), rule-providers \(counts.ruleProviders), modules \(counts.modules), rewrite rules \(counts.rewriteRules), MitM hosts \(counts.mitmHosts), scripts \(counts.scripts) (\(unloadable.count) unloadable), tasks \(counts.tasks), warnings \(counts.warnings.count)"
        // The runtime must carry at least what the import converted (the probe group / injected rules only add).
        // E2E 40268229079 passed with proxies 1 / groups 1 / rules 3 against an import of 9 / 29 / 85: the profile
        // YAML the converter wrote was cut after the first ws node (NCYAMLEmitter nested-mapping indentation).
        var lost: [String] = []
        if let rep = confReport {
            if counts.proxies < (rep.proxies ?? 0) { lost.append("proxies \(counts.proxies) < imported \(rep.proxies ?? 0)") }
            if counts.groups < (rep.groups ?? 0) { lost.append("groups \(counts.groups) < imported \(rep.groups ?? 0)") }
            if counts.rules < (rep.rules ?? 0) { lost.append("rules \(counts.rules) < imported \(rep.rules ?? 0)") }
            if counts.providers + counts.ruleProviders < (rep.providers ?? 0) {
                lost.append("providers \(counts.providers)+\(counts.ruleProviders) < imported \(rep.providers ?? 0)")
            }
        }
        let rtOK = counts.proxies + counts.providers > 0 && counts.rules > 0 && lost.isEmpty
        r.record("runtime-generation", rtOK ? .pass : .fail, detail + (lost.isEmpty ? "" : " — LOST vs import: " + lost.joined(separator: ", ")))
        for w in counts.warnings { r.note("prep warning: \(w)") }
        // A real export can name scripts that only exist on the exporting phone (QX local script files) or whose
        // remote URL is gone (HTTP 403/404/410): that is the fixture's environment, not a Tern bug. Those are listed
        // as INFO; anything else (parse / compile / other download errors) fails. The sample serves every script.
        let isSample = E2EReport.env("TERN_E2E_SAMPLE") == "1"
        let unavailable = isSample ? [] : unloadable.filter { u in
            let l = u.lowercased()
            return l.contains("no such file") || l.contains("http 404") || l.contains("http 410") || l.contains("http 403")
        }
        let broken = unloadable.filter { !unavailable.contains($0) }
        for u in unloadable { r.note("unloadable script: \(u)") }
        if !unavailable.isEmpty {
            r.record("scripts-unavailable", .info, "\(unavailable.count) script(s) the fixture references are not available here (local file on the exporting device / remote 4xx): " + unavailable.prefix(6).joined(separator: "; "))
        }
        if broken.isEmpty {
            r.record("scripts-loadable", .pass, "\(counts.scripts - unavailable.count) of \(counts.scripts) script(s) loaded" + (unavailable.isEmpty ? "" : " (\(unavailable.count) unavailable, see scripts-unavailable)"))
        } else {
            r.record("scripts-loadable", .fail, "\(broken.count) of \(counts.scripts) unloadable: " + broken.prefix(12).joined(separator: "; "))
        }

        // fix/nc-tls-scripts (E2E gap d): the user's device flow — delete the profile, import the same file again,
        // force-update every provider. Device build506 answered 「路径不在内核目录内」 here while the first import
        // worked; the replay never exercised a second import or a manual provider update.
        let handoffProfile = await Self.reimportAndForceUpdate(r: r, fixture: fixture.text, old: profile, home: home) ?? profile

        E2EReport.writeHandoff([
            "home": home, "profile": handoffProfile.fileURL.path, "profileID": handoffProfile.id, "container": NSHomeDirectory(),
            "proxies": counts.proxies, "providers": counts.providers, "groups": counts.groups, "rules": counts.rules,
            "ruleProviders": counts.ruleProviders, "mitmHosts": counts.mitmHosts, "scripts": counts.scripts,
            "tasks": counts.tasks, "importMs": importMs, "prepMs": prepMs,
        ])
        // Stage 2 runs after a reinstall that can hand the app a new, empty data container: keep a copy of the data
        // root on the runner (outside the artifact) for it to restore.
        let snap = E2EReport.snapshotContainer(AppShared.containerURL)
        r.note(snap < 0 ? "no TERN_E2E_STATE: data root not snapshotted for stage 2" : "data root snapshotted for stage 2: \(snap) item(s)")
        r.record("stage-done", .info, "stage 1 finished")
    }

    private func rep0RemoteCount(_ rep: ConfImportResult.Report?) -> Int { rep?.remotes ?? 0 }

    /// Delete + re-import + provider force update + runtime generation again; returns the new profile (nil: the
    /// step could not run and the first import stays in use). Provider failures that are the fixture's environment
    /// (HTTP 4xx / Cloudflare / no network to the subscription host) are INFO; a path / store error is a FAIL.
    private static func reimportAndForceUpdate(r: E2EReport, fixture: String, old: Profile, home: String) async -> Profile? {
        guard let action = ImportRouter.route(text: fixture, name: "E2E") else { return nil }
        ProfileStore.shared.delete(old)
        let gone = !FileManager.default.fileExists(atPath: old.fileURL.path) && !ProfileStore.shared.profiles.contains { $0.id == old.id }
        do {
            switch action {
            case .confText(let name, let text):
                let conv = await ConfImportResult.convert(text)
                if let e = conv.error, !e.isEmpty { throw ProfileStore.StoreError.invalid(e) }
                _ = try await ConfImport.save(text: text, name: name, result: conv, store: ProfileStore.shared)
            case .profileText(let name, let text):
                _ = try await ProfileStore.shared.addLocal(name: name, text: text)
            default:
                r.record("reimport", .skip, "re-import covers .conf / profile fixtures (this one is \(action.id))")
                return nil
            }
        } catch {
            r.record("reimport", .fail, "delete + re-import failed: \(error.localizedDescription)")
            return nil
        }
        guard let p = ProfileStore.shared.profiles.last, p.id != old.id else {
            r.record("reimport", .fail, "no new profile after the re-import")
            return nil
        }
        ProfileStore.shared.activeID = p.id
        AppShared.activeProfileID = p.id
        r.record("reimport", gone ? .pass : .fail, gone ? "deleted and imported again (new profile)" : "the deleted profile is still on disk / in the list")

        let tasks = ProviderUpdater.plan(profilePath: p.fileURL.path)
        let res = await ProviderUpdater.shared.updateAll(profile: p)
        let errs = ProviderUpdater.shared.errors.filter { e in tasks.contains { $0.id == e.key } }
        let envMarkers = ["http 4", "http 5", "timed out", "超时", "offline", "could not", "network", "网络"]
        let env: [String: String] = errs.filter { e in
            let l = e.value.lowercased()
            return envMarkers.contains { l.contains($0) }
        }
        let real: [String: String] = errs.filter { env[$0.key] == nil }
        let envLines: [String] = env.map { "\($0.key) \($0.value)" }.sorted()
        let realLines: [String] = real.map { "\($0.key) \($0.value)" }.sorted()
        var detail = "\(tasks.count) provider(s): ok \(res.ok), failed \(res.failed)"
        if !envLines.isEmpty { detail += "; environment (INFO): " + envLines.prefix(6).joined(separator: "; ") }
        if !realLines.isEmpty { detail += "; ERRORS: " + realLines.prefix(8).joined(separator: "; ") }
        r.record("reimport-provider-update", real.isEmpty && (tasks.isEmpty || res.ok > 0) ? .pass : .fail, detail)

        let err = await Task.detached(priority: .userInitiated) { NativeRuntimePrep.prepareSyncForReplay(home: home, profile: p.fileURL) }.value
        r.record("reimport-runtime", err == nil ? .pass : .fail, err.map { "runtime generation after the re-import: \($0)" } ?? "runtime regenerated for the re-imported profile")
        return err == nil ? p : nil
    }

    // MARK: helpers

    private static func resetAppState() {
        let fm = FileManager.default
        let root = AppShared.containerURL
        for name in ["profiles", "profiles.json", "tern"] {
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

    /// Non-secret shape of what runtime generation read and wrote (counts and key names only): which profile file,
    /// how big, how many proxies / groups / rules it declares, and the top-level keys of nativecore-runtime.json.
    static func shapeNotes(home: String, profile: URL) -> [String] {
        var out: [String] = []
        let all = ProfileStore.shared.profiles
        out.append("profiles in store: \(all.count) (active \(AppShared.activeProfileID ?? "nil"), using \(profile.lastPathComponent))")
        if let t = try? String(contentsOf: profile, encoding: .utf8) {
            var section = "", counts: [String: Int] = [:]
            for raw in t.components(separatedBy: .newlines) {
                if let c = raw.first, c != " ", c != "#", c != "-", let colon = raw.firstIndex(of: ":") {
                    section = String(raw[..<colon]); continue
                }
                let l = raw.trimmingCharacters(in: .whitespaces)
                if l.hasPrefix("- ") && (raw.hasPrefix("  - ") || raw.hasPrefix("- ")) { counts[section, default: 0] += 1 }
            }
            out.append("profile yaml: \(t.utf8.count) bytes, list items by key: " + counts.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ", "))
        } else {
            out.append("profile yaml: unreadable at \(profile.lastPathComponent)")
        }
        let rtURL = URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")
        if let d = try? Data(contentsOf: rtURL), let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] {
            let keys = o.keys.sorted().map { k -> String in
                let v = o[k]!
                if let a = v as? [Any] { return "\(k)[\(a.count)]" }
                if let m = v as? [String: Any] { return "\(k){\(m.count)}" }
                return k
            }
            out.append("nativecore-runtime.json: \(d.count) bytes, keys: " + keys.joined(separator: " "))
        } else {
            out.append("nativecore-runtime.json: missing or not a JSON object")
        }
        let files = (try? FileManager.default.contentsOfDirectory(atPath: home)) ?? []
        out.append("home files: " + files.sorted().prefix(60).joined(separator: " "))
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

enum E2EPrepOutcome {
    case finished(caOK: Bool, error: String?)
    case timedOut(step: String)
}

/// Resumes a continuation exactly once (prep result vs watchdog).
final class E2EOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func take() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
}

/// The last prep step reached (for the watchdog's FAIL line).
final class E2EStep: @unchecked Sendable {
    private let lock = NSLock()
    private var s = "start"
    func set(_ v: String) { lock.lock(); s = v; lock.unlock() }
    func get() -> String { lock.lock(); defer { lock.unlock() }; return s }
}
