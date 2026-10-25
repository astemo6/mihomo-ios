import SwiftUI
import Libmihomo

// Surge / Quantumult X .conf → mihomo profile (+ a module for its rewrite / MitM / script sections).
// Translation happens once, at import (bridge/confimport.go); afterwards it is an ordinary profile.

struct ConfImportResult: Decodable {
    struct Report: Decodable {
        var format: String?
        var proxies: Int?
        var groups: Int?
        var rules: Int?
        var providers: Int?
        var module: Bool?
        var rewrites: Int?
        var scripts: Int?
        var tasks: Int?
        var hostnames: Int?
        var remotes: Int?
        var skipped: [String]?
        var notes: [String]?
        /// v0.13.1: remote entries switched off in the original config (not failures).
        var disabled: [String]?
    }
    var yaml: String?
    var module: String?
    struct RemoteModule: Decodable, Hashable {
        var url: String
        var name: String
        var enabled: Bool
        var interval: Int?
    }
    var rewriteRemotes: [RemoteModule]? = nil
    /// v0.11: QX [general] connection settings (excluded_routes, ssid_suspended_list, server_check_url /
    /// timeout, udp_drop_list QUIC). Applied to the app's own settings when applySettings is not false.
    struct Settings: Decodable, Hashable {
        var excludedRoutes: [String]? = nil
        var trustedSSIDs: [String]? = nil
        var testURL: String? = nil
        var testTimeoutMs: Int? = nil
        var blockQUIC: Bool? = nil
        // v0.12
        var modeTrigger: ModeTrigger? = nil
        var geoAPI: String? = nil
        var geoScript: String? = nil
        var geoDisabled: Bool? = nil
        var parserURL: String? = nil

        var lines: [String] {
            var out: [String] = []
            if let r = excludedRoutes, !r.isEmpty { out.append(String(localized: "排除的路由：\(r.joined(separator: ", "))")) }
            if let s = trustedSSIDs, !s.isEmpty { out.append(String(localized: "受信任的 Wi-Fi：\(s.joined(separator: ", "))")) }
            if let u = testURL, !u.isEmpty { out.append(String(localized: "测速地址：\(u)")) }
            if let t = testTimeoutMs, t > 0 { out.append(String(localized: "测速超时：\(t) ms")) }
            if blockQUIC == true { out.append(String(localized: "阻止 QUIC：始终")) }
            if let m = modeTrigger { out.append(String(localized: "按网络切换运行模式：\(m.summary)")) }
            if geoDisabled == true { out.append(String(localized: "出口信息查询：关闭")) }
            else if let a = geoAPI, !a.isEmpty { out.append(String(localized: "出口信息查询：\(a)")) }
            if let p = parserURL, !p.isEmpty { out.append(String(localized: "资源解析器（仅保存）：\(p)")) }
            return out
        }

        /// Merges into CoreOverrides / on-demand / engine settings (routes and SSIDs are added, not replaced).
        @MainActor func apply() {
            var o = CoreOverrides.load()
            if let r = excludedRoutes, !r.isEmpty {
                for x in r where !o.excludedRoutes.contains(x) { o.excludedRoutes.append(x) }
            }
            if let u = testURL, CoreOverrides.isValidTestURL(u) { o.testURL = u }
            // v0.19.8: 5–10 s (bridge importedCheckTimeout); a QX 2000 made most nodes 超时 in mihomo.
            if let t = testTimeoutMs, t > 0 { o.testTimeoutMs = min(max(t, 5000), 10000) }
            o.save()
            if let s = trustedSSIDs, !s.isEmpty {
                var od = OnDemandSettings.load()
                for x in s where !od.trustedSSIDs.contains(x) { od.trustedSSIDs.append(x) }
                od.save()
            }
            if blockQUIC == true {
                EngineStore.shared.config.quic = "all"
                EngineStore.shared.save()
            }
            if var m = modeTrigger {
                m.enabled = true
                m.save()
                if VPNManager.shared.isConnected {
                    Task { _ = await VPNManager.shared.send(.applyNetworkPolicy, timeout: 4) }
                }
            }
            if geoDisabled == true || !(geoAPI ?? "").isEmpty {
                if geoDisabled == true { GeoChecker.save(checker: "disabled", url: IPInfoFetcher.checkerURL, script: GeoChecker.script) }
                else { GeoChecker.save(checker: "custom", url: geoAPI ?? "", script: geoScript ?? "") }
                IPInfoModel.shared.scheduleRefresh(after: 0.5)
            }
            if let p = parserURL, !p.isEmpty { ResourceParserSetting.url = p }
        }
    }
    var settings: Settings? = nil
    var applySettings: Bool? = nil
    var report: Report?
    var error: String?

    static func convert(_ text: String) async -> ConfImportResult {
        let json = await Task.detached(priority: .userInitiated) { NCConfImportPort.importConf(text) }.value
        return (try? JSONDecoder().decode(ConfImportResult.self, from: Data(json.utf8)))
            ?? ConfImportResult(yaml: nil, module: nil, report: nil, error: String(localized: "转换失败"))
    }
}

enum ConfImport {
    /// Saves the converted profile (validated by the real core) and, if present, the module.
    static func save(text: String, name: String, result: ConfImportResult?, store: ProfileStore,
                     progress: @MainActor (String) -> Void = { _ in }) async throws -> String {
        let r: ConfImportResult
        if let result { r = result } else { await progress(String(localized: "正在转换配置…")); r = await ConfImportResult.convert(text) }
        if let e = r.error, !e.isEmpty { throw ProfileStore.StoreError.invalid(e) }
        guard let yaml = r.yaml, !yaml.isEmpty else { throw ProfileStore.StoreError.empty }
        await progress(String(localized: "正在校验配置…"))
        let p = try await store.addLocal(name: name.isEmpty ? "导入的配置" : name, text: yaml)
        // P0-1: keep the original .conf next to the profile so rules the conversion (or a later edit) lost can be
        // restored from it (bridge RestoreConfRules); removed with the profile (ForgetProfile).
        let sourcePath = p.fileURL.path
        let saveErr = await Task.detached(priority: .utility) { NCAppFilePorts.saveConfSource(profilePath: sourcePath, text: text) }.value
        if !saveErr.isEmpty { StartupLog.write("conf import: source not saved: \(saveErr)", tag: "app") }
        var msg = String(localized: "已导入配置「\(p.name)」")
        if let m = r.module, !m.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            await MainActor.run { EngineStore.shared.addModule(text: m, name: p.name + "（重写）") }
            msg += String(localized: "，重写 / MitM / 脚本已作为模块「\(p.name)（重写）」添加")
        }
        // QX [rewrite_remote] (v0.8.1): one module per line (tag / file name, enabled= kept), downloaded now.
        let remotes = r.rewriteRemotes ?? []
        if !remotes.isEmpty {
            await progress(String(localized: "正在下载远程重写…"))
            var failed: [String] = []
            for m in remotes {
                if let e = await EngineStore.shared.addRemoteModule(url: m.url, name: m.name, enabled: m.enabled, interval: m.interval ?? 86400) {
                    failed.append("\(m.name)：\(e)")
                }
            }
            msg += String(localized: "，另添加 \(remotes.count) 个远程重写模块")
            if !failed.isEmpty {
                msg += String(localized: "（\(failed.count) 个下载失败，可在「工具 → 重写」中更新）\n") + failed.joined(separator: "\n")
            }
        }
        if let st = r.settings, r.applySettings != false, !st.lines.isEmpty {
            await MainActor.run { st.apply() }
            msg += String(localized: "，已应用 \(st.lines.count) 项连接设置")
        }
        // Rule sets / node subscriptions: download them now so they work before the first connection.
        await progress(String(localized: "正在下载规则集 / 节点集…"))
        let pr = await ProviderUpdater.shared.updateAll(profile: p)
        if pr.failed > 0 {
            msg += String(localized: "\n规则集 / 节点集：\(pr.ok) 个已下载，\(pr.failed) 个失败（规则集在「工具 → 分流规则 → 订阅」、节点集在「节点与订阅」中重试）")
        }
        return msg
    }
}

/// Conversion report shown before importing a .conf.
struct ConfReportSection: View {
    let text: String
    @Binding var result: ConfImportResult?
    @State private var showSkipped = false
    @State private var showDisabled = false

    init(text: String, result: Binding<ConfImportResult?>) {
        self.text = text
        self._result = result
    }

    var body: some View {
        Group {
            if let r = result {
                if let e = r.error, !e.isEmpty {
                    Section { Label(e, systemImage: "xmark.octagon.fill").foregroundStyle(Theme.bad).font(.footnote) }
                        .listRowBackground(Theme.card)
                } else if let rep = r.report {
                    Section {
                        HStack {
                            Label(LocalizedStringKey(rep.format == "qx" ? "Quantumult X 配置" : "Surge 配置"), systemImage: "arrow.triangle.2.circlepath.doc.on.clipboard")
                                .font(.headline)
                            Spacer()
                            Text("→ mihomo").font(.caption.weight(.bold)).foregroundStyle(Theme.accent)
                        }
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                            stat("节点", rep.proxies ?? 0)
                            stat("策略组", rep.groups ?? 0)
                            stat("规则", rep.rules ?? 0)
                            stat("规则集", rep.providers ?? 0)
                        }
                        if rep.module == true || (rep.remotes ?? 0) > 0 {
                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                                stat("重写", rep.rewrites ?? 0)
                                stat("脚本", rep.scripts ?? 0)
                                stat("MitM 主机", rep.hostnames ?? 0)
                                stat("远程重写", rep.remotes ?? 0)
                            }
                            if (rep.tasks ?? 0) > 0 {
                                Label("定时任务 \(rep.tasks ?? 0) 个", systemImage: "clock").font(.footnote)
                            }
                            Label("重写 / MitM / 脚本 → 作为模块导入，每个远程重写单独成为一个模块", systemImage: "puzzlepiece.extension").font(.footnote)
                        }
                    } header: { Text("转换结果") }
                    .listRowBackground(Theme.card)
                    if let st = r.settings, !st.lines.isEmpty {
                        Section {
                            Toggle("同时应用这些连接设置", isOn: Binding(
                                get: { result?.applySettings != false },
                                set: { result?.applySettings = $0 }))
                            ForEach(st.lines, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                        } header: { Text("连接设置") } footer: {
                            Text("来自原配置的 [general]。路由和 Wi-Fi 会追加到现有设置，下次连接时生效。")
                        }
                        .listRowBackground(Theme.card)
                    }
                    if let notes = rep.notes, !notes.isEmpty {
                        Section("说明") {
                            ForEach(notes, id: \.self) { Text($0).font(.caption) }
                        }
                        .listRowBackground(Theme.card)
                    }
                    if let off = rep.disabled, !off.isEmpty {
                        Section {
                            DisclosureGroup("已禁用（原配置中关闭）\(off.count) 项", isExpanded: $showDisabled) {
                                ForEach(off, id: \.self) { Text($0).scaledFont(10, design: .monospaced).foregroundStyle(.secondary) }
                            }
                        }
                        .listRowBackground(Theme.card)
                    }
                    if let skipped = rep.skipped, !skipped.isEmpty {
                        Section {
                            DisclosureGroup("未转换 \(skipped.count) 项", isExpanded: $showSkipped) {
                                ForEach(skipped, id: \.self) { Text($0).scaledFont(10, design: .monospaced).foregroundStyle(.secondary) }
                            }
                            .tint(Theme.warn)
                        }
                        .listRowBackground(Theme.card)
                    }
                }
            } else {
                Section { LoadingRow(text: "正在转换…") }
                    .listRowBackground(Theme.card)
            }
        }
        .task { if result == nil { result = await ConfImportResult.convert(text) } }
    }

    func stat(_ title: String, _ n: Int) -> some View {
        VStack(spacing: 2) {
            Text("\(n)").font(.title3.weight(.bold).monospacedDigit())
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
    }
}
