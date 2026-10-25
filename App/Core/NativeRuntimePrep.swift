import Foundation

/// E-B1b stage 4: prepare the runtime configuration for NativeCore purely in Swift.
///
/// Port of `bridge/nativeprep.go` (PrepareNativeRuntime).
///
/// The tunnel kernel is NativeCore and has no Go dependencies. The runtime config
/// files the tunnel reads (`runtime.yaml`, `nativecore-runtime.json`, `runtime-groups.json`,
/// `nativecore-rewrite.json`, `nativecore-scripts.json`, `nativecore-geosite/*.list`,
/// `nativecore-prep.json`) are generated in the app process before every tunnel start
/// and configuration reload.
///
/// DIVERGENCES from bridge/nativeprep.go:
/// - `C.SetHomeDir` / `C.SetConfig`: Go calls these global mutations on the C/Go runtime.
///   In Swift, there is no corresponding global engine state; any remaining Go callers
///   in the app maintain their own paths, so no synthetic side-effects are introduced.
/// - `nativecore-runtime.json`: Go writes `runtime.yaml` and re-reads it through
///   `NativeConfigJSON` to produce JSON. The Swift pipeline reuses the in-memory AST
///   `raw` returned by `NCRuntimeBuilder.build`, serializing via `NCRuntimeBuilder.jsonData`
///   directly (declared seam difference from #112, semantically equivalent).
/// - File I/O errors reflect Swift `Error.localizedDescription` instead of Go `os.PathError`.
/// - Transactional output (review rv2): Go wrote each file in turn, so a failure part-way left e.g. a new
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
        guard AppShared.containerOK else {
            return String(localized: "App Group 不可用：重签名的描述文件需要包含 App Groups，且主程序和扩展使用同一个组。详见 更多 → 诊断。")
        }
        guard let profile = AppShared.activeProfileURL else {
            return String(localized: "请先在「更多 → 配置」中添加并选择一个配置")
        }
        let home = AppShared.homeURL.path

        return await Task.detached(priority: .userInitiated) { () -> String? in
            prepareSync(home: home, profile: profile)
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
    private static func prepareSync(home: String, profile: URL) -> String? {
        let key = (home as NSString).appendingPathComponent(".nativecore-prepare.lock")
        return NCPathLock.shared.withLock(for: key) { () -> String? in
            prepareSyncLocked(home: home, profile: profile)
        }
    }

    private static func prepareSyncLocked(home: String, profile: URL) -> String? {
        PrepTransaction.removeStale(home: home)
        // Non-throwing init: no deferred-initialized `let` in this body (build #359 SIL verifier crash shape).
        let tx = PrepTransaction(home: home)
        // Whatever happens below, the staging directory goes (after a commit it only holds the backups).
        defer { tx.discard() }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profile.path)
        let safeMode = req.settings.core.safeMode

        guard let profileData = NCRuntimeFiles.readRuntimeProfile(home: home, path: profile.path, safe: safeMode) else {
            // Go surfaces the raw os.ReadFile error after the
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

        // Immutable cfg / rs and a reference box for the state the (escaping) inject
        // closure mutates: Swift 6.2's SIL verifier crashed (OwnershipModelEliminator,
        // build #359) on the previous captured-var / deferred-let shape of this body.
        let cfg: NCEngineConfig? = safeMode ? nil : NCEngineConfig.load(home: home)
        let rs: NCEngineRuleset? = cfg.map { NCMitmBuild.build(home: home, cfg: $0) }
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
                // Geosite list writes: Go ignores their errors
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
                let man = try NCScriptManifest.buildManifest(home: home, cfg: cfg, rs: scriptRS)
                rep.scripts = man.scripts
                if man.bad > 0 {
                    rep.warnings = (rep.warnings ?? []) + ["\(man.bad) 个脚本加载失败（见 nativecore-scripts.json）"]
                }
                try tx.put(man.data, NCScriptManifest.scriptManifestFile)
                scriptKeep = man.keep
            } catch {
                // bridge nativeprep.go: a manifest failure is a warning
                // only — the OLD manifest stays in place (the code files
                // buildManifest already wrote stay too, as in Go). Do not
                // stage an empty replacement: that disabled every script.
                let errStr = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                rep.scripts = 0
                rep.warnings = (rep.warnings ?? []) + ["脚本清单写入失败：" + errStr]
            }

            // Rewrite / MitM snapshot. bridge nativeprep.go: a snapshot
            // write failure aborts the whole prepare (the runtime files
            // written before it stay, the old snapshot stays) — it is
            // NOT downgraded to a warning with the old snapshot deleted.
            rep.rewrite = false
            rep.mitmHosts = 0
            if let cfg = cfg, let rs = rs, (cfg.anyOn || (cfg.mitm && !rs.hostnames.isEmpty)) {
                let (snap, hosts) = try NCRewriteSnapshotBuilder.exportData(home: home, cfg: cfg, rs: rs)
                try tx.put(snap, "nativecore-rewrite.json")
                rep.rewrite = true
                rep.mitmHosts = hosts
            } else {
                tx.remove("nativecore-rewrite.json")
            }

            // bridge nativeprep.go ignores failures of the group-order
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
        } catch {
            return fail(error.localizedDescription)
        }

        let summary = "runtime.yaml \(buildResult.data.count) B, \(rep.rules) rules, geosite \(rep.geosite?.count ?? 0), rewrite \(rep.rewrite ? "true" : "false"), mitm hosts \(rep.mitmHosts), scripts \(rep.scripts), warnings \(rep.warnings?.count ?? 0)"
        NSLog("[Mihomo] native runtime prepared: %@", summary)
        return nil
    }

    private static func fail(_ message: String) -> String {
        NSLog("[Mihomo] native runtime prepare failed: %@", message)
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
