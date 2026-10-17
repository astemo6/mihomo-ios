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

        var lines: [String] {
            var out: [String] = []
            if let r = excludedRoutes, !r.isEmpty { out.append(String(localized: "排除的路由：\(r.joined(separator: ", "))")) }
            if let s = trustedSSIDs, !s.isEmpty { out.append(String(localized: "受信任的 Wi-Fi：\(s.joined(separator: ", "))")) }
            if let u = testURL, !u.isEmpty { out.append(String(localized: "测速地址：\(u)")) }
            if let t = testTimeoutMs, t > 0 { out.append(String(localized: "测速超时：\(t) ms")) }
            if blockQUIC == true { out.append(String(localized: "阻止 QUIC：始终")) }
            return out
        }

        /// Merges into CoreOverrides / on-demand / engine settings (routes and SSIDs are added, not replaced).
        @MainActor func apply() {
            var o = CoreOverrides.load()
            if let r = excludedRoutes, !r.isEmpty {
                for x in r where !o.excludedRoutes.contains(x) { o.excludedRoutes.append(x) }
            }
            if let u = testURL, CoreOverrides.isValidTestURL(u) { o.testURL = u }
            if let t = testTimeoutMs, t > 0 { o.testTimeoutMs = min(max(t, 1000), 5000) }
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
        }
    }
    var settings: Settings? = nil
    var applySettings: Bool? = nil
    var report: Report?
    var error: String?

    static func convert(_ text: String) async -> ConfImportResult {
        let json = await Task.detached(priority: .userInitiated) { LibmihomoImportConf(text) }.value
        return (try? JSONDecoder().decode(ConfImportResult.self, from: Data(json.utf8)))
            ?? ConfImportResult(yaml: nil, module: nil, report: nil, error: String(localized: "转换失败"))
    }
}

enum ConfImport {
    /// Saves the converted profile (validated by the real core) and, if present, the module.
    static func save(text: String, name: String, result: ConfImportResult?, store: ProfileStore) async throws -> String {
        let r: ConfImportResult
        if let result { r = result } else { r = await ConfImportResult.convert(text) }
        if let e = r.error, !e.isEmpty { throw ProfileStore.StoreError.invalid(e) }
        guard let yaml = r.yaml, !yaml.isEmpty else { throw ProfileStore.StoreError.empty }
        let p = try await store.addLocal(name: name.isEmpty ? "导入的配置" : name, text: yaml)
        var msg = "已导入配置「\(p.name)」"
        if let m = r.module, !m.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            await MainActor.run { EngineStore.shared.addModule(text: m, name: p.name + "（重写）") }
            msg += "，重写 / MitM / 脚本已作为模块「\(p.name)（重写）」添加"
        }
        // QX [rewrite_remote] (v0.8.1): one module per line (tag / file name, enabled= kept), downloaded now.
        let remotes = r.rewriteRemotes ?? []
        if !remotes.isEmpty {
            var failed: [String] = []
            for m in remotes {
                if let e = await EngineStore.shared.addRemoteModule(url: m.url, name: m.name, enabled: m.enabled, interval: m.interval ?? 86400) {
                    failed.append("\(m.name)：\(e)")
                }
            }
            msg += String(localized: "，另添加 \(remotes.count) 个远程重写模块")
            if !failed.isEmpty {
                msg += String(localized: "（\(failed.count) 个下载失败，可在「模块与资源」中更新）\n") + failed.joined(separator: "\n")
            }
        }
        // QX preview 5: [http_backend] → HTTP Backend page (QX branch only).
        let backends = await MainActor.run { QXHTTPBackendStore.importConf(text) }
        if backends > 0 { msg += String(localized: "，另添加 \(backends) 个 HTTP Backend") }
        if let st = r.settings, r.applySettings != false, !st.lines.isEmpty {
            await MainActor.run { st.apply() }
            msg += String(localized: "，已应用 \(st.lines.count) 项连接设置")
        }
        // Rule sets / node subscriptions: download them now so they work before the first connection.
        let pr = await ProviderUpdater.shared.updateAll(profile: p)
        if pr.failed > 0 {
            msg += String(localized: "\n规则集 / 节点集：\(pr.ok) 个已下载，\(pr.failed) 个失败（可在「更多 → 提供者」中重试）")
        }
        return msg
    }
}

/// Conversion report shown before importing a .conf.
struct ConfReportSection: View {
    let text: String
    @Binding var result: ConfImportResult?
    @State private var showSkipped = false

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
                            Label(rep.format == "qx" ? "Quantumult X 配置" : "Surge 配置", systemImage: "arrow.triangle.2.circlepath.doc.on.clipboard")
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
