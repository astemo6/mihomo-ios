import Foundation

/// E-B1b stage 4: prepare the runtime configuration for NativeCore purely in Swift.
///
/// Port of the retired bridge (PrepareNativeRuntime).
///
/// The tunnel kernel is NativeCore and has no the old core dependencies. The runtime config
/// files the tunnel reads (`runtime.yaml`, `nativecore-runtime.json`, `runtime-groups.json`,
/// `nativecore-rewrite.json`, `nativecore-scripts.json`, `nativecore-geosite/*.list`,
/// `nativecore-prep.json`) are generated in the app process before every tunnel start
/// and configuration reload.
///
/// DIVERGENCES from the retired bridge:
/// - `C.SetHomeDir` / `C.SetConfig`: the old core calls these global mutations on the C/old runtime.
///   In Swift, there is no corresponding global engine state; any remaining the old core callers
///   in the app maintain their own paths, so no synthetic side-effects are introduced.
/// - `nativecore-runtime.json`: the old core writes `runtime.yaml` and re-reads it through
///   `NativeConfigJSON` to produce JSON. The Swift pipeline reuses the in-memory AST
///   `raw` returned by `NCRuntimeBuilder.build`, serializing via `NCRuntimeBuilder.jsonData`
///   directly (declared seam difference from #112, semantically equivalent).
/// - File I/O errors reflect Swift `Error.localizedDescription` instead of the old core `os.PathError`.
/// - Transactional output (review rv2): the old core wrote each file in turn, so a failure part-way left e.g. a new
///   runtime.yaml next to the old nativecore-runtime.json (which the tunnel prefers) and several writes were
///   `try?` while the prepare still reported success. Here every output is first written into a staging directory
///   on the same volume (`<home>/.nativecore-stage-<uuid>/`); nothing in `<home>` changes until all of them are
///   written. The commit then rename(2)s each staged file over its live path (atomic per file, so the tunnel never
///   sees a missing or half-written file), the live file hard-linked aside first so a failed rename rolls the whole
///   set back to the previous generation. The tunnel's read side is unchanged (same paths, same formats).
enum NativeRuntimePrep {

    /// nil = prepared; else the error text (the start / reload stops with it).
    ///
    /// rv2: no App Group container / no active profile is an error, not success — the start path checks both
    /// before calling, but `VPNManager.reloadNow` did not, so a reload with the active profile gone (deleted file,
    /// cleared selection) returned nil and the UI reported the new config as applied while the tunnel kept the
    /// previous runtime files.
    static func prepare() async -> String? {
        await prepare(allowCached: false).error
    }

    /// fix/app-toggle-hitch: the outcome of one prepare for the connect path's timing log.
    struct Outcome {
        var error: String?
        /// The runtime on disk was already built from exactly the current inputs (NativeRuntimePrepCache): nothing
        /// was regenerated.
        var cached = false
        var millis = 0
        /// fix/nc-open-6-10 #8: per-stage milliseconds of this prepare ("fp 35, cfg 12, modules 140, …"), for the
        /// connect timing line in the startup log.
        var breakdown = ""
    }

    /// fix/nc-open-6-10 #8: stage stopwatch for one prepare (single thread: the prepare body is synchronous).
    final class PrepTiming {
        private var parts: [String] = []
        private var t = DispatchTime.now().uptimeNanoseconds
        func lap(_ name: String, _ extra: String = "") {
            let now = DispatchTime.now().uptimeNanoseconds
            parts.append("\(name) \((now &- t) / 1_000_000)" + (extra.isEmpty ? "" : " (\(extra))"))
            t = now
        }
        func note(_ s: String) { parts.append(s) }
        var summary: String { parts.joined(separator: ", ") }
    }

    /// allowCached (connect): skip the generation when NativeRuntimePrepCache says the outputs on disk were built
    /// from exactly the current inputs. Reloads (`prepare()`) always regenerate. Everything — the AppShared path
    /// lookups included — runs off the main actor.
    static func prepare(allowCached: Bool) async -> Outcome {
        await Task.detached(priority: .userInitiated) { () -> Outcome in
            let t0 = DispatchTime.now().uptimeNanoseconds
            func done(_ e: String?, _ cached: Bool) -> Outcome {
                Outcome(error: e, cached: cached, millis: Int((DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000))
            }
            guard AppShared.containerOK else {
                return done(String(localized: "App Group 不可用：重签名的描述文件需要包含 App Groups，且主程序和扩展使用同一个组。详见 更多 → 诊断。"), false)
            }
            guard let profile = AppShared.activeProfileURL else {
                return done(String(localized: "请先在「更多 → 配置」中添加并选择一个配置"), false)
            }
            let home = AppShared.homeURL.path
            let index = AppShared.profilesIndexURL.path
            let timing = PrepTiming()
            let r = prepareSync(home: home, profile: profile, profilesIndex: index, allowCached: allowCached, timing: timing)
            var o = done(r.error, r.cached)
            o.breakdown = timing.summary
            return o
        }.value
    }

    private final class PrepState {
        var rep: NCRuntimeBuilder.PrepReport
        var groupOrder: [String] = []
        var writeErrors: [String] = []
        init(rep: NCRuntimeBuilder.PrepReport) { self.rep = rep }
    }

    /// Review R-3: prepares are serialized. Two concurrent prepare() calls (a
    /// start racing a reload, two quick toggles) used to interleave their writes
    /// of runtime.yaml / nativecore-runtime.json / nativecore-rewrite.json, so the
    /// tunnel could load one prepare's runtime with the other's rewrite snapshot.
    /// The whole build+write runs under one per-home NCPathLock key (a sync
    /// context: the lock is never held across a suspension point).
    private static func prepareSync(home: String, profile: URL, profilesIndex: String, allowCached: Bool,
                                    timing: PrepTiming? = nil) -> (error: String?, cached: Bool) {
        let key = (home as NSString).appendingPathComponent(".nativecore-prepare.lock")
        return NCPathLock.shared.withLock(for: key) { () -> (error: String?, cached: Bool) in
            // fix/app-toggle-hitch: generation cache (see NativeRuntimePrepCache). Fingerprinted under the prepare
            // lock, so no other prepare can change the outputs between the check and the start.
            let profilesDir = profile.deletingLastPathComponent().path
            let build = NCPrepMarkers.currentBuild
            func inputs() -> String {
                NativeRuntimePrepCache.inputsFingerprint(home: home, profilesDir: profilesDir, extraFiles: [profilesIndex],
                                                         profilePath: profile.path, build: build)
            }
            timing?.lap("lock")
            if allowCached {
                let fp = inputs()
                timing?.lap("fingerprint")
                if NativeRuntimePrepCache.hit(home: home, inputs: fp) {
                    NSLog("[Tern] native runtime unchanged since the last prepare: reusing it")
                    return (nil, true)
                }
            }
            NativeRuntimePrepCache.invalidate(home: home)
            let err = prepareSyncLocked(home: home, profile: profile, timing: timing)
            if err == nil {
                // Taken after the commit: files the prepare itself wrote are part of the recorded state.
                NativeRuntimePrepCache.write(home: home, .init(inputs: inputs(), outputs: NativeRuntimePrepCache.outputsFingerprint(home: home)))
                timing?.lap("cache record")
            }
            return (err, false)
        }
    }

    /// The connect path's generation for an explicit home + profile, without the App Group / active-profile guards
    /// of `prepare()` and without the generation cache: the E2E replay (UnitTests/NativeCoreE2EReplayTests) runs it on
    /// an unsigned simulator build, which has no App Group container. Same lock, same body as a real connect.
    static func prepareSyncForReplay(home: String, profile: URL) -> String? {
        let key = (home as NSString).appendingPathComponent(".nativecore-prepare.lock")
        return NCPathLock.shared.withLock(for: key) { () -> String? in
            NativeRuntimePrepCache.invalidate(home: home)
            return prepareSyncLocked(home: home, profile: profile)
        }
    }

    /// fix/nc-open-6-10 #8: request timeout for resources the prepare downloads (it blocks the connect).
    static let prepFetchTimeout: TimeInterval = 12

    /// Every remote resource the script manifest and the rewrite snapshot will read: script code (rules + tasks)
    /// and rewrite response bodies (data-type file).
    static func remoteResources(_ rs: NCEngineRuleset) -> [String] {
        var out: [String] = []
        for r in rs.rules {
            if r.kind == "script", let sc = r.script, sc.source == nil { out.append(sc.path) }
            if !r.data.isEmpty, r.dataType.isEmpty || r.dataType == "file" { out.append(r.data) }
        }
        for t in rs.tasks { if let sc = t.script, sc.source == nil { out.append(sc.path) } }
        return out.filter { NCResources.isRemote($0) }
    }

    private static func prepareSyncLocked(home: String, profile: URL, timing: PrepTiming? = nil) -> String? {
        PrepTransaction.removeStale(home: home)
        // fix/nc-vpn-start-crash: a marker still here = the previous prepare died inside the app process (a trap
        // cannot be caught). If it died building the rewrite snapshot, quarantine that exact rule set so the next
        // connect runs without rewrite / MitM instead of crashing again.
        let build = NCPrepMarkers.currentBuild
        let crashed = NCPrepMarkers.readInflight(home: home)
        if let crashed {
            NSLog("[Tern] previous native runtime prepare did not finish (stage %@, build %@)", crashed.stage, crashed.build)
            if crashed.stage == "rewrite", let fp = crashed.fp {
                NCPrepMarkers.writeQuarantine(home: home, .init(fp: fp, build: crashed.build, at: Int64(Date().timeIntervalSince1970)))
            }
        }
        NCPrepMarkers.writeInflight(home: home, .init(stage: "build", at: Int64(Date().timeIntervalSince1970), build: build, fp: nil))
        defer { NCPrepMarkers.clearInflight(home: home) }
        // Non-throwing init: no deferred-initialized `let` in this body (build #359 SIL verifier crash shape).
        let tx = PrepTransaction(home: home)
        // Whatever happens below, the staging directory goes (after a commit it only holds the backups).
        defer { tx.discard() }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profile.path)
        let safeMode = req.settings.core.safeMode

        guard let profileData = NCRuntimeFiles.readRuntimeProfile(home: home, path: profile.path, safe: safeMode) else {
            // the old core surfaces the raw os.ReadFile error after the
            // prefix; mirror that with the real read error.
            var detail = "配置文件不可读"
            do { _ = try Data(contentsOf: profile) } catch {
                detail = error.localizedDescription
            }
            return fail("读取配置失败: " + detail)
        }

        var rep = NCRuntimeBuilder.PrepReport()
        rep.at = Int64(Date().timeIntervalSince1970)
        rep.profile = (profile.path as NSString).lastPathComponent
        rep.build = build

        // Immutable cfg / rs and a reference box for the state the (escaping) inject
        // closure mutates: Swift 6.2's SIL verifier crashed (OwnershipModelEliminator,
        // build #359) on the previous captured-var / deferred-let shape of this body.
        timing?.lap("read profile", "\(profileData.count / 1024) KB")
        let cfg: NCEngineConfig? = safeMode ? nil : NCEngineConfig.load(home: home)
        timing?.lap("engine cfg", cfg.map { "\($0.modules.filter { $0.enabled }.count) modules" } ?? "safe mode")
        let rs: NCEngineRuleset? = cfg.map { NCMitmBuild.build(home: home, cfg: $0) }
        timing?.lap("modules parse", rs.map { "\($0.rules.count) rules, \($0.hostnames.count) hosts" } ?? "-")
        // fix/nc-open-6-10 #8: one resource cache shared by the script manifest and the rewrite snapshot, with every
        // missing remote script / body downloaded in parallel up front (they used to be fetched one by one inside
        // the sequential builds, with a 30 s timeout each and no memory of a URL that had already failed).
        let res = NCResources(home: home)
        res.fetchTimeout = prepFetchTimeout
        if let cfg, let rs, cfg.anyOn || cfg.mitm {
            let remote = remoteResources(rs)
            // Start path: only a short grace is synchronous — downloads keep filling the cache
            // in the background afterwards. One hanging uncached resource must not delay the
            // tunnel by the full fetch timeout (device diag 2026-10-28: 13.4 s prefetch).
            res.prefetch(remote, maxConcurrent: 6, deadline: prepFetchTimeout + 2, blockFor: 3)
            timing?.lap("prefetch", "\(Set(remote).count) remote, fetched \(res.fetchedCount), failed \(res.failedCount), skipped \(res.skippedRecentFailure)")
        }
        let box = PrepState(rep: rep)

        var built: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])? = nil
        do {
            built = try NCRuntimeBuilder.build(
                profile: profileData,
                req: req,
                fd: 0
            ) { raw in
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
                // Geosite list writes: the old core ignores their errors
                // (`_ = writeAtomicFile` in lowerForNative) — surface
                // them as warnings, not a failed prepare.
                NCRuntimeBuilder.lowerForNative(home: home, &raw, &box.rep, stageDir: tx.stage) { box.rep.warnings = (box.rep.warnings ?? []) + [$0] }
                box.groupOrder = NCRuntimeSteps.runtimeGroupNames(raw)
            }
        } catch let err as NCRuntimeBuilder.BuildError {
            return fail(err.message)
        } catch {
            return fail(error.localizedDescription)
        }
        timing?.lap("runtime build")
        guard let buildResult = built else { return fail("native runtime: 构建失败") }
        if let e = box.writeErrors.first { return fail(e) }
        rep = box.rep
        let groupOrder = box.groupOrder

        do {
            // Geosite lists were written into the stage by lowerForNative; commit them first.
            tx.adoptStagedDirectory("nativecore-geosite")

            // Scripts manifest: content-addressed code files are additive; the manifest itself is staged and the
            // obsolete code files are only removed after the commit (see NCScriptManifest.buildManifest).
            let scriptRS: NCEngineRuleset? = (cfg != nil && cfg!.anyOn) ? rs : nil
            var scriptKeep: Set<String>? = nil
            do {
                let man = try NCScriptManifest.buildManifest(home: home, cfg: cfg, rs: scriptRS, res: res)
                rep.scripts = man.scripts
                if man.bad > 0 {
                    rep.warnings = (rep.warnings ?? []) + ["\(man.bad) 个脚本加载失败（见 nativecore-scripts.json）"]
                }
                try tx.put(man.data, NCScriptManifest.scriptManifestFile)
                scriptKeep = man.keep
                timing?.lap("scripts", "\(man.scripts) scripts, \(man.bad) bad")
            } catch {
                // Restored after #139: the manifest indexes the
                // rule set by position, so an OLD manifest next to the NEW rule set would run scripts on the wrong
                // rules. Stage an empty one: this start runs without scripts, with a warning.
                let errStr = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                rep.scripts = 0
                rep.warnings = (rep.warnings ?? []) + ["脚本清单生成失败，本次未启用脚本：" + errStr]
                try tx.put(try JSONEncoder().encode(NCScriptManifestRoot()), NCScriptManifest.scriptManifestFile)
            }

            // Rewrite / MitM snapshot. Restored after #139: a
            // snapshot failure is a warning and this start runs without rewrite / MitM (the old snapshot is removed
            // so it cannot be paired with the new rule set). Aborting the whole prepare meant one bad module blocked
            // every connect / reload. Only a staging-write failure (TxError) stays fatal.
            rep.rewrite = false
            rep.mitmHosts = 0
            if let cfg = cfg, let rs = rs, (cfg.anyOn || (cfg.mitm && !rs.hostnames.isEmpty)) {
                let fp = rewriteFingerprint(cfg: cfg, rs: rs, build: build)
                if let q = NCPrepMarkers.readQuarantine(home: home), q.fp == fp {
                    rep.warnings = (rep.warnings ?? []) + ["上次生成重写 / MitM 快照时 App 异常退出，本次未启用重写 / MitM（修改模块 / 规则或更新 App 后会重试）"]
                    tx.remove("nativecore-rewrite.json")
                } else {
                    if NCPrepMarkers.readQuarantine(home: home) != nil { NCPrepMarkers.clearQuarantine(home: home) }
                    NCPrepMarkers.writeInflight(home: home, .init(stage: "rewrite", at: Int64(Date().timeIntervalSince1970), build: build, fp: fp))
                    do {
                        let (snap, hosts) = try NCRewriteSnapshotBuilder.exportData(home: home, cfg: cfg, rs: rs, res: res)
                        try tx.put(snap, "nativecore-rewrite.json")
                        rep.rewrite = true
                        rep.mitmHosts = hosts
                    } catch let e as PrepTransaction.TxError {
                        throw e
                    } catch {
                        rep.warnings = (rep.warnings ?? []) + ["重写 / MitM 快照生成失败，本次未启用：" + error.localizedDescription]
                        tx.remove("nativecore-rewrite.json")
                    }
                    NCPrepMarkers.writeInflight(home: home, .init(stage: "commit", at: Int64(Date().timeIntervalSince1970), build: build, fp: nil))
                }
            } else {
                tx.remove("nativecore-rewrite.json")
            }
            timing?.lap("rewrite snapshot", "\(rep.mitmHosts) hosts")

            // the retired bridge ignores failures of the group-order
            // and prep-report writes (`_ = writeAtomicFile`); runtime.yaml
            // and the runtime JSON stay fatal.
            do {
                try tx.put(try JSONEncoder().encode(groupOrder), "runtime-groups.json")
            } catch {
                rep.warnings = (rep.warnings ?? []) + ["runtime-groups.json 写入失败：" + error.localizedDescription]
            }
            try tx.put(buildResult.data, "runtime.yaml")
            guard let runtimeJSON = NCRuntimeBuilder.jsonData(buildResult.raw) else {
                return fail("native runtime JSON: 序列化失败")
            }
            try tx.put(runtimeJSON, "nativecore-runtime.json")
            do {
                try tx.put(try JSONEncoder().encode(rep), "nativecore-prep.json")
            } catch {
                rep.warnings = (rep.warnings ?? []) + ["nativecore-prep.json 写入失败：" + error.localizedDescription]
            }

            try tx.commit()
            if let keep = scriptKeep {
                NCScriptManifest.removeObsoleteCode(home: home, keep: keep)
            }
            timing?.lap("write+commit")
            if res.fetchedCount + res.failedCount > 0 {
                timing?.note("downloads total \(res.fetchedCount) ok / \(res.failedCount) failed")
            }
        } catch {
            return fail(error.localizedDescription)
        }

        let summary = "runtime.yaml \(buildResult.data.count) B, \(rep.rules) rules, geosite \(rep.geosite?.count ?? 0), rewrite \(rep.rewrite ? "true" : "false"), mitm hosts \(rep.mitmHosts), scripts \(rep.scripts), warnings \(rep.warnings?.count ?? 0)"
        NSLog("[Tern] native runtime prepared: %@", summary)
        return nil
    }

    /// Identity of everything the rewrite snapshot is built from (app build + MitM switch + hostnames + every rule's
    /// patterns / templates). Stable across processes (NCPrepMarkers.fingerprint).
    static func rewriteFingerprint(cfg: NCEngineConfig, rs: NCEngineRuleset, build: String) -> String {
        var parts: [String] = [build, cfg.mitm ? "mitm" : "-", cfg.anyOn ? "on" : "-"]
        parts.append(contentsOf: rs.hostnames)
        for r in rs.rules {
            parts.append(contentsOf: [r.kind, r.phase, r.pattern, r.headerPattern, r.action, r.target, r.jq, r.line, r.data])
            for h in r.headers { parts.append(contentsOf: [h.op, h.name, h.value, h.regex]) }
            for b in r.body { parts.append(contentsOf: [b.regex, b.repl]) }
            for j in r.jsonOps { parts.append(contentsOf: [j.op, j.path, j.value]) }
        }
        return NCPrepMarkers.fingerprint(parts)
    }

    private static func fail(_ message: String) -> String {
        NSLog("[Tern] native runtime prepare failed: %@", message)
        return String(localized: "生成运行配置失败：") + message
    }
}

/// rv2: all-or-nothing write of the native runtime files (see the DIVERGENCES note on NativeRuntimePrep).
/// Runs under NativeRuntimePrep's per-home NCPathLock; not thread-safe on its own.
final class PrepTransaction {
    struct TxError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static let stagePrefix = ".nativecore-stage-"

    let home: String
    /// Staging directory, a sibling of the live files (same volume, so rename(2) is atomic).
    let stage: String
    private var entries: [(rel: String, remove: Bool)] = []

    /// The directory itself is created lazily by `put` / lowerForNative (createDirectory with intermediates).
    init(home: String) {
        self.home = home
        stage = (home as NSString).appendingPathComponent(Self.stagePrefix + UUID().uuidString)
    }

    /// Removes staging directories a crashed / killed prepare left behind.
    static func removeStale(home: String) {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: home) else { return }
        for n in items where n.hasPrefix(stagePrefix) {
            try? fm.removeItem(atPath: (home as NSString).appendingPathComponent(n))
        }
    }

    private static func posix(_ what: String, _ path: String, _ code: Int32) -> TxError {
        TxError(message: what + " " + (path as NSString).lastPathComponent + ": " + String(cString: strerror(code)))
    }

    /// Stages `data` for `<home>/<rel>`. Throws (TxError) when the staged copy cannot be written.
    func put(_ data: Data, _ rel: String) throws {
        let p = (stage as NSString).appendingPathComponent(rel)
        do {
            try FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try NCRuntimeFiles.writeAtomic(data, to: p)
        } catch {
            throw TxError(message: rel + ": " + error.localizedDescription)
        }
        entries.removeAll { $0.rel == rel }
        entries.append((rel, false))
    }

    /// Stages removal of `<home>/<rel>` (no error when it does not exist).
    func remove(_ rel: String) {
        entries.removeAll { $0.rel == rel }
        entries.append((rel, true))
    }

    /// Adopts every regular file already written into `<stage>/<dir>/` (lowerForNative's geosite lists).
    /// Live files in `<home>/<dir>/` that are not staged are left alone (as before: lists are keyed by code).
    func adoptStagedDirectory(_ dir: String) {
        let d = (stage as NSString).appendingPathComponent(dir)
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: d) else { return }
        for n in items.sorted() where !n.hasPrefix(".") {
            let rel = (dir as NSString).appendingPathComponent(n)
            entries.removeAll { $0.rel == rel }
            entries.append((rel, false))
        }
    }

    /// Moves every staged file over its live path. On any failure the files already swapped are put back
    /// (from hard links taken just before each swap) and the error is thrown: the live set is then exactly the
    /// previous generation.
    func commit() throws {
        let fm = FileManager.default
        let backup = (stage as NSString).appendingPathComponent(".old")
        do {
            try fm.createDirectory(atPath: backup, withIntermediateDirectories: true)
        } catch {
            throw TxError(message: error.localizedDescription)
        }
        var done: [(live: String, bak: String?)] = []
        func rollback() {
            for d in done.reversed() {
                if let bak = d.bak {
                    _ = rename(bak, d.live)
                } else {
                    _ = unlink(d.live)
                }
            }
        }
        for (idx, e) in entries.enumerated() {
            let live = (home as NSString).appendingPathComponent(e.rel)
            let bak = (backup as NSString).appendingPathComponent("\(idx)")
            var hadOld = false
            if link(live, bak) == 0 {
                hadOld = true
            } else if errno != ENOENT {
                // No hard links on this volume / sandbox: fall back to a copy.
                let err = errno
                if (try? fm.copyItem(atPath: live, toPath: bak)) != nil {
                    hadOld = true
                } else {
                    rollback()
                    throw Self.posix("备份", live, err)
                }
            }
            if e.remove {
                if hadOld && unlink(live) != 0 && errno != ENOENT {
                    let err = errno
                    _ = unlink(bak)
                    rollback()
                    throw Self.posix("删除", live, err)
                }
            } else {
                let staged = (stage as NSString).appendingPathComponent(e.rel)
                try? fm.createDirectory(atPath: (live as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                if rename(staged, live) != 0 {
                    let err = errno
                    if hadOld { _ = unlink(bak) }
                    rollback()
                    throw Self.posix("替换", live, err)
                }
            }
            done.append((live, hadOld ? bak : nil))
        }
        entries = []
    }

    /// Deletes the staging directory (staged files of an aborted prepare, or the backups after a commit).
    func discard() {
        try? FileManager.default.removeItem(atPath: stage)
    }
}
