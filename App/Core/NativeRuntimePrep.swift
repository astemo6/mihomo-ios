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
enum NativeRuntimePrep {

    /// nil = prepared; else the error text (the start / reload stops with it).
    static func prepare() async -> String? {
        guard AppShared.containerOK else { return nil } // the start reports the App Group problem itself
        guard let profile = AppShared.activeProfileURL else { return nil }
        let home = AppShared.homeURL.path

        return await Task.detached(priority: .userInitiated) { () -> String? in
            let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profile.path)
            let safeMode = req.settings.core.safeMode

            guard let profileData = NCRuntimeFiles.readRuntimeProfile(home: home, path: profile.path, safe: safeMode) else {
                return fail("读取配置失败: 配置文件不可读")
            }

            var rep = NCRuntimeBuilder.PrepReport()
            rep.at = Int64(Date().timeIntervalSince1970)
            rep.profile = (profile.path as NSString).lastPathComponent

            var cfg: NCEngineConfig? = nil
            var rs: NCEngineRuleset? = nil
            if !safeMode {
                let loaded = NCEngineConfig.load(home: home)
                cfg = loaded
                rs = NCMitmBuild.build(home: home, cfg: loaded)
            }

            var groupOrder: [String] = []
            let buildResult: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])
            do {
                buildResult = try NCRuntimeBuilder.build(
                    profile: profileData,
                    req: req,
                    fd: 0
                ) { raw in
                    if let cfg {
                        if cfg.anyOn, let rs {
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
                    NCRuntimeBuilder.lowerForNative(home: home, &raw, &rep)
                    groupOrder = NCRuntimeSteps.runtimeGroupNames(raw)
                }
            } catch let err as NCRuntimeBuilder.BuildError {
                return fail(err.message)
            } catch {
                return fail(error.localizedDescription)
            }

            let runtimePath = URL(fileURLWithPath: home).appendingPathComponent("runtime.yaml").path
            do {
                try NCRuntimeFiles.writeAtomic(buildResult.data, to: runtimePath)
            } catch {
                return fail(error.localizedDescription)
            }

            writeRuntimeGroupOrder(home: home, names: groupOrder)

            guard let runtimeJSON = NCRuntimeBuilder.jsonData(buildResult.raw) else {
                return fail("native runtime JSON: 序列化失败")
            }
            let runtimeJSONPath = URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json").path
            do {
                try NCRuntimeFiles.writeAtomic(runtimeJSON, to: runtimeJSONPath)
            } catch {
                return fail(error.localizedDescription)
            }

            let snapPath = URL(fileURLWithPath: home).appendingPathComponent("nativecore-rewrite.json").path
            if let cfg, let rs, (cfg.anyOn || (cfg.mitm && !rs.hostnames.isEmpty)) {
                let (snap, hosts) = NCRewriteSnapshotBuilder.export(home: home, cfg: cfg, rs: rs)
                rep.rewrite = true
                rep.mitmHosts = hosts
                do {
                    try NCRuntimeFiles.writeAtomic(Data(snap.utf8), to: snapPath)
                } catch {
                    return fail(error.localizedDescription)
                }
            } else {
                try? FileManager.default.removeItem(atPath: snapPath)
            }

            let scriptRS: NCEngineRuleset? = (cfg != nil && cfg!.anyOn) ? rs : nil
            do {
                let (scripts, bad) = try NCScriptManifest.export(home: home, cfg: cfg, rs: scriptRS)
                rep.scripts = scripts
                if bad > 0 {
                    rep.warnings = (rep.warnings ?? []) + ["\(bad) 个脚本加载失败（见 nativecore-scripts.json）"]
                }
            } catch {
                let errStr = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                rep.warnings = (rep.warnings ?? []) + ["脚本清单写入失败：" + errStr]
            }

            if let prepData = try? JSONEncoder().encode(rep) {
                let prepPath = URL(fileURLWithPath: home).appendingPathComponent("nativecore-prep.json").path
                try? NCRuntimeFiles.writeAtomic(prepData, to: prepPath)
            }

            let summary = "runtime.yaml \(buildResult.data.count) B, \(rep.rules) rules, geosite \(rep.geosite?.count ?? 0), rewrite \(rep.rewrite ? "true" : "false"), mitm hosts \(rep.mitmHosts), warnings \(rep.warnings?.count ?? 0)"
            NSLog("[Mihomo] native runtime prepared: %@", summary)
            return nil
        }.value
    }

    private static func writeRuntimeGroupOrder(home: String, names: [String]?) {
        guard !home.isEmpty, let names else { return }
        guard let data = try? JSONEncoder().encode(names) else { return }
        let path = URL(fileURLWithPath: home).appendingPathComponent("runtime-groups.json").path
        try? NCRuntimeFiles.writeAtomic(data, to: path)
    }

    private static func fail(_ message: String) -> String {
        NSLog("[Mihomo] native runtime prepare failed: %@", message)
        return String(localized: "生成运行配置失败：") + message
    }
}
