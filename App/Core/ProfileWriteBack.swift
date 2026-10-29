import Foundation

/// feat/profile-write-back (user 2026-10-29 「我需要的是同步更新配置文件」): rule-page edits — the Final's
/// policy, edits / deletions of the profile's own rules, rule-set policies and the rule-set order — used to
/// live only in provider-overrides.json, re-applied to the runtime on every build; the profile file itself
/// never changed, and the pages said so. Now the edits are written into a profile file instead:
///   • a local profile takes them into its own file (overwritten in place);
///   • a remote subscription cannot (its file is replaced by the next update), so its （自定义） copy is
///     made — or the existing one reused — the edits are baked into the copy, and the copy becomes the
///     active profile, marked copyModified so subscription updates leave it alone. The subscription
///     itself is never written.
/// Baking runs the very functions the runtime builder applies (NCRuntimeSteps.applyProfileRuleOverrides /
/// applyRuleProviderOverrides, in the builder's order), so the file ends up exactly what the core was
/// already running. The baked override entries are cleared afterwards; a snapshot is captured first,
/// like every other profile write. One exception: 停用 has no representation in a profile file, so an
/// entry carrying it (a whole rule set, or single profile rules) stays an override and keeps skipping
/// at runtime — it bakes on a later save once re-enabled.
enum ProfileWriteBack {
    struct Outcome {
        /// A note worth showing (a copy was made / the write failed), nil for the silent local case.
        var note: String? = nil
        /// The active profile was switched to the copy; setActive already reloaded the core, so the
        /// caller's own reload is skipped.
        var switched = false
    }

    /// Bakes the ACTIVE profile's pending rule-family overrides into a profile file.
    /// nil = nothing to bake (no pending edits, only 停用 ones, or the manual-nodes pseudo profile) —
    /// the caller just reloads as before.
    @MainActor
    static func materializeActive() async -> Outcome? {
        let store = ProfileStore.shared
        guard let p = store.active, p.id != "manual-nodes" else { return nil }
        let ovStore = ProviderOverrideStore.shared
        let fam = ovStore.ruleFamily(p.id)
        guard !fam.isEmpty else { return nil }
        let (bake, kept) = bakeSplit(fam)
        guard !bake.isEmpty else { return nil }

        var target = p
        if p.kind == .remote {
            if let c = store.orderCopy(of: p) {
                target = c
            } else if let c = await makeCopy(of: p, store: store) {
                target = c
            } else {
                return Outcome(note: String(localized: "无法创建本地副本，修改仍保存在 Tern 里。"))
            }
        }

        SnapshotStore.shared.capture(String(localized: "规则修改写回「\(target.displayName)」前"))
        if let err = await bakeInto(target, ov: bake) {
            return Outcome(note: String(localized: "写回配置文件失败（\(err)），修改仍保存在 Tern 里。"))
        }
        ovStore.clearRuleFamily(p.id, keeping: kept)
        if target.id != p.id {
            ovStore.clearRuleFamily(target.id)
            var nc = target
            nc.copyModified = true
            store.update(nc)
            let e = await store.setActive(nc)
            var note = String(localized: "订阅配置不能直接修改：已复制为本地配置「\(nc.displayName)」并切换到它，修改已写入这份副本；原订阅保持不变。")
            if let e { note += String(localized: " 重载失败：\(e)") }
            return Outcome(note: note, switched: true)
        }
        return Outcome()
    }

    /// A fresh （自定义） copy of a subscription for the write-back: the same settings / selections /
    /// scripts migration as a 策略组 reorder copy (GroupOrder.save), except the overrides do NOT follow —
    /// they are baked into the copy's file and cleared instead.
    @MainActor
    private static func makeCopy(of p: Profile, store: ProfileStore) async -> Profile? {
        var c = Profile(name: GroupOrder.copyName(of: p), kind: .local)
        c.sourceID = p.id
        c.sourceName = p.displayName
        c.userInfo = p.userInfo
        c.lastUpdated = p.lastUpdated
        do {
            try await ProfileStore.writeProfile(store.content(of: p), to: c.fileURL)
        } catch { return nil }
        let from = p.id, to = c.id
        let err = await Task.detached(priority: .userInitiated) {
            NCProfileCopy.copySettings(homeDir: AppShared.homeURL.path, fromID: from, toID: to)
        }.value
        if !err.isEmpty { StartupLog.write("write-back copy settings: \(err)", tag: "app") }
        HomeGroupsStore.copy(from: from, to: to)
        RegionFilterStore.copy(from: from, to: to)
        let selErr = await Task.detached(priority: .userInitiated) {
            NCProfileCopy.copySelections(fromPath: p.fileURL.path, toPath: c.fileURL.path)
        }.value
        if !selErr.isEmpty { StartupLog.write("write-back copy selections: \(selErr)", tag: "app") }
        OverrideScriptStore.shared.copyScripts(from: from, to: to)
        store.insertCopy(c, after: p)
        return c
    }

    /// The profile model with the overrides applied — the builder's two rule-family steps, in its order.
    static func bakedProfile(_ raw: [String: NCJSONValue], ov: [String: NCProviderOverride]) -> [String: NCJSONValue] {
        var raw = raw
        _ = NCRuntimeSteps.applyProfileRuleOverrides(&raw, ov: ov)
        _ = NCRuntimeSteps.applyRuleProviderOverrides(&raw, ov: ov)
        return raw
    }

    /// Writes the baked model over the profile's file (YAML + its .conf sidecar, via the editor's commit).
    /// An error message, or nil on success — on failure nothing is written and the overrides stay.
    private static func bakeInto(_ t: Profile, ov: [String: NCProviderOverride]) async -> String? {
        let path = t.fileURL.path
        return await Task.detached(priority: .userInitiated) { () async -> String? in
            guard let data = FileManager.default.contents(atPath: path),
                  case .object(let model)? = NCYAML.parse(String(decoding: data, as: UTF8.self)) else {
                return String(localized: "配置文件读取失败")
            }
            let raw = bakedProfile(model, ov: ov)
            let yaml = TernConfStore.yamlFromProfile(raw)
            if let v = await ProfileStore.validate(text: yaml) { return v }
            do {
                try NCPathLock.shared.withLock(for: path) {
                    try NCRuntimeFiles.writeAtomic(Data(yaml.utf8), to: path)
                }
                try TernConfStore.commit(yamlPath: path, yaml: yaml, conf: TernConf.serializeProfile(raw))
            } catch { return error.localizedDescription }
            return nil
        }.value
    }

    /// Splits the rule family into what bakes into the file and the profile rules that stay overrides:
    /// an entry carrying 停用 is excluded whole (a disabled rule set), or per rule (the profile's rules).
    static func bakeSplit(_ fam: [String: ProviderOverride]) -> (bake: [String: NCProviderOverride], keptRules: [ProfileRuleOverride]) {
        var bake: [String: NCProviderOverride] = [:]
        var kept: [ProfileRuleOverride] = []
        for (k, v) in fam {
            if k == ProviderOverride.profileRulesKey {
                let rules = v.rules ?? []
                let go = rules.filter { $0.disabled != true }
                kept = rules.filter { $0.disabled == true }
                if !go.isEmpty { bake[k] = mirror(v, rules: go) }
                continue
            }
            if v.disabled == true { continue }
            bake[k] = mirror(v, rules: nil)
        }
        return (bake, kept)
    }

    private static func mirror(_ v: ProviderOverride, rules: [ProfileRuleOverride]?) -> NCProviderOverride {
        var m = NCProviderOverride()
        m.disabled = v.disabled
        m.deleted = v.deleted
        m.name = v.name
        m.icon = v.icon
        m.url = v.url
        m.interval = v.interval
        m.filter = v.filter
        m.excludeFilter = v.excludeFilter
        m.policy = v.policy
        m.order = v.order
        m.rules = (rules ?? v.rules)?.map {
            NCProfileRuleOverride(rule: $0.rule, index: $0.index, line: $0.line, disabled: $0.disabled, deleted: $0.deleted)
        }
        return m
    }
}
