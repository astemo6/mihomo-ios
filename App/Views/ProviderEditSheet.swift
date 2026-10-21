import SwiftUI

/// feat/subs-split: 编辑 a 节点集 (proxy-provider) of the current profile. Saved as an override
/// (provider-overrides.json): the display name, and for downloaded (http) providers the link and update
/// interval, plus mihomo's provider filter / exclude-filter. Empty = what the profile says.
struct ProviderEditSheet: View {
    let profileID: String
    let info: ProfileProviderInfo
    let onSave: () async -> Void
    @ObservedObject private var store = ProviderOverrideStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var interval = 0
    @State private var filter = ""
    @State private var exclude = ""
    @State private var error: String?
    @State private var saving = false

    static let intervals: [(Int, LocalizedStringKey)] = [(0, "跟随配置"), (3600, "每小时"), (21600, "每 6 小时"), (43200, "每 12 小时"), (86400, "每天"), (604800, "每周")]

    var isHTTP: Bool { info.vehicle == "http" }
    var hasOverride: Bool { !store.get(profileID, info.name).isEmpty }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(info.name, text: $name)
                        .accessibilityIdentifier("provider.edit.name")
                } header: { Text("名称") } footer: {
                    Text("只改本页显示的名称；策略组和规则仍按配置里的名称「\(info.name)」引用它。")
                }
                .listRowBackground(Theme.card)

                if isHTTP {
                    Section {
                        TextField(info.url ?? "https://…", text: $url, axis: .vertical)
                            .font(.footnote.monospaced())
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("provider.edit.url")
                        Picker("自动更新", selection: $interval) {
                            ForEach(Self.intervals, id: \.0) { v in
                                Text(v.1).tag(v.0)
                            }
                        }
                    } header: { Text("订阅链接") } footer: {
                        if let i = info.interval, i > 0 { Text("留空使用配置里的链接；配置里的更新间隔是 \(i) 秒。") } else { Text("留空使用配置里的链接。") }
                    }
                    .listRowBackground(Theme.card)
                }

                Section {
                    TextField(info.filter?.isEmpty == false ? info.filter! : String(localized: "保留：正则，如 (?i)港|hk"), text: $filter)
                        .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("provider.edit.filter")
                    TextField(info.excludeFilter?.isEmpty == false ? info.excludeFilter! : String(localized: "排除：正则，如 到期|剩余"), text: $exclude)
                        .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("provider.edit.exclude")
                } header: { Text("筛选节点") } footer: {
                    Text("留空使用配置里的设置。")
                }
                .listRowBackground(Theme.card)

                if let error {
                    Section { Text(error).font(.footnote).foregroundStyle(Theme.bad) }
                        .listRowBackground(Theme.card)
                }

                if hasOverride {
                    Section {
                        Button("恢复默认", role: .destructive) {
                            let icon = store.get(profileID, info.name).icon
                            store.set(profileID, info.name, ProviderOverride(disabled: store.get(profileID, info.name).disabled, icon: icon))
                            Task { await onSave(); dismiss() }
                        }
                        .accessibilityIdentifier("provider.edit.reset")
                    } footer: { Text("清除这里的修改，使用配置里的设置（图标和停用状态保留）。") }
                    .listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("编辑节点集")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if saving { ProgressView() } else {
                        Button("保存") { save() }.accessibilityIdentifier("provider.edit.save")
                    }
                }
            }
            .onAppear {
                let o = store.get(profileID, info.name)
                name = o.name ?? ""
                url = o.url ?? ""
                interval = Self.intervals.contains { $0.0 == (o.interval ?? 0) } ? (o.interval ?? 0) : 0
                filter = o.filter ?? ""
                exclude = o.excludeFilter ?? ""
            }
        }
    }

    static func validRegex(_ s: String) -> Bool {
        s.isEmpty || (try? NSRegularExpression(pattern: s)) != nil
    }

    func save() {
        let n = name.trimmingCharacters(in: .whitespaces)
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let f = filter.trimmingCharacters(in: .whitespaces)
        let x = exclude.trimmingCharacters(in: .whitespaces)
        if !u.isEmpty {
            guard let pu = URL(string: u), let sc = pu.scheme?.lowercased(), sc == "http" || sc == "https", pu.host?.isEmpty == false else {
                error = String(localized: "请输入以 http:// 或 https:// 开头的链接")
                return
            }
        }
        guard Self.validRegex(f), Self.validRegex(x) else {
            error = String(localized: "筛选表达式无效")
            return
        }
        error = nil
        saving = true
        store.update(profileID, info.name) { o in
            o.name = n.isEmpty || n == info.name ? nil : n
            o.url = u.isEmpty || u == info.url ? nil : u
            o.interval = interval > 0 ? interval : nil
            o.filter = f.isEmpty ? nil : f
            o.excludeFilter = x.isEmpty ? nil : x
        }
        Task {
            await onSave()
            saving = false
            dismiss()
        }
    }
}
