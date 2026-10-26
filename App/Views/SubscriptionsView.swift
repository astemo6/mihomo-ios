import SwiftUI

// fb-subs-global: the 订阅管理 page and its cards moved into 节点与订阅 (NodeManagerHome.swift, user 「还是分开的」).
// The editors and notification sections below are shared by it.

/// Add a node subscription: URL, name, UA, interval, groups that include it (editing one is NodeSubSheet).
struct NodeSubEditor: View {
    let sub: NodeSubscription?
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var nodes = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var url = ""
    @State private var name = ""
    @State private var ua = "clash.meta"
    @State private var interval = 24
    @State private var customGroups = false
    @State private var groups: Set<String> = []
    @State private var alert = UsageAlertRule()
    @State private var busy = false
    @State private var error: String?

    var groupNames: [String] { offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name) }
    /// Chosen groups the active profile doesn't have (they may exist in another profile). Shown and kept on
    /// save; dropping them silently on a rename was review 5 P2-9.
    var otherGroups: [String] { (sub?.groups ?? []).filter { !groupNames.contains($0) } }

    var body: some View {
        NavigationStack {
            Form {
                Section("订阅") {
                    TextField("订阅链接 https://…", text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("名称（留空自动获取）", text: $name)
                }
                .listRowBackground(Theme.card)
                Section("选项") {
                    Picker("User-Agent", selection: $ua) {
                        Text("clash.meta").tag("clash.meta")
                        Text(verbatim: "Clash.Meta (Meta core)").tag(SubscriptionUA.metaCore)
                        Text("Quantumult X").tag("Quantumult%20X/1.5.2")
                        Text("Shadowrocket").tag("Shadowrocket/2070")
                    }
                    Picker("自动更新", selection: $interval) {
                        Text("关闭").tag(0)
                        Text("每 6 小时").tag(6)
                        Text("每 12 小时").tag(12)
                        Text("每天").tag(24)
                        Text("每周").tag(168)
                    }
                }
                .listRowBackground(Theme.card)
                Section {
                    Toggle("指定策略组", isOn: $customGroups)
                    if customGroups {
                        ForEach(groupNames, id: \.self) { g in
                            Toggle(g, isOn: Binding(get: { groups.contains(g) }, set: { if $0 { groups.insert(g) } else { groups.remove(g) } }))
                        }
                        ForEach(otherGroups, id: \.self) { g in
                            Toggle(isOn: Binding(get: { groups.contains(g) }, set: { if $0 { groups.insert(g) } else { groups.remove(g) } })) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(verbatim: g)
                                    Text("不在当前配置").font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                } header: { Text("加入的策略组") } footer: {
                    Text("默认加入含节点的手动选择组和自动选择（url-test）组；这些组在别的配置中不存在时也按默认处理。")
                }
                .listRowBackground(Theme.card)
                UsageAlertSection(rule: $alert)
                if let error { Section { Text(error).foregroundStyle(Theme.bad).font(.footnote) }.listRowBackground(Theme.card) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(sub == nil ? "添加节点订阅" : "编辑节点订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button(sub == nil ? "添加" : "保存") { Task { await save() } }
                            .disabled(!url.hasPrefix("http"))
                    }
                }
            }
            .onAppear {
                if let s = sub {
                    url = s.url; name = s.name; ua = s.userAgent; interval = s.updateIntervalHours
                    alert = UsageAlerts.rule(for: s.id)
                    if let g = s.groups, !g.isEmpty { customGroups = true; groups = Set(g) }
                }
            }
        }
    }

    func save() async {
        busy = true
        defer { busy = false }
        let g: [String]? = customGroups && !groups.isEmpty ? (groupNames + otherGroups).filter { groups.contains($0) } : nil
        if var s = sub {
            let urlChanged = s.url != url || s.userAgent != ua
            s.url = url; s.name = name; s.userAgent = ua; s.updateIntervalHours = interval; s.groups = g
            UsageAlerts.setRule(alert, for: s.id)
            await nodes.save(s)
            if urlChanged, let e = await nodes.refresh(s) { error = e; return }
            dismiss()
        } else {
            do {
                let s = try await nodes.add(url: url, name: name, userAgent: ua, intervalHours: interval, groups: g)
                UsageAlerts.setRule(alert, for: s.id)
                UsageAlerts.evaluate(id: s.id, name: s.name, info: s.userInfo)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

// MARK: - v0.14 notifications

/// 用量提醒 in both subscription editors: quota threshold + days before expiry.
struct UsageAlertSection: View {
    @Binding var rule: UsageAlertRule

    var body: some View {
        Section {
            Toggle("用量提醒", isOn: $rule.enabled)
            if rule.enabled {
                Picker("流量用到", selection: $rule.quotaPercent) {
                    Text("关闭").tag(0)
                    ForEach(UsageAlertRule.quotaChoices, id: \.self) { Text("\($0)%").tag($0) }
                }
                Picker("到期前", selection: $rule.expiryDays) {
                    Text("关闭").tag(0)
                    ForEach(UsageAlertRule.expiryChoices, id: \.self) { Text("\($0) 天").tag($0) }
                }
            }
        } header: { Text("提醒") } footer: {
            Text("用订阅返回的流量与到期信息（subscription-userinfo）发本地通知：每次更新后检查流量，用完时再提醒一次；到期提醒由系统按时送达，不需要打开 App。没有这些信息的订阅不会提醒。")
        }
        .listRowBackground(Theme.card)
    }
}

/// 订阅管理 → 通知: opt-in summary after automatic updates.
struct UpdateNotifySection: View {
    @State private var on = ScheduledUpdates.notifyEnabled
    @State private var mode = ScheduledUpdates.mode
    @State private var denied = false

    var body: some View {
        Section {
            Toggle("自动更新后通知", isOn: $on)
                .onChange(of: on) { ScheduledUpdates.notifyEnabled = $0 }
            if on {
                Picker("何时通知", selection: $mode) {
                    ForEach(UpdateNotifyMode.allCases) { Text(LocalizedStringKey($0.title)).tag($0) }
                }
                .onChange(of: mode) { ScheduledUpdates.mode = $0 }
            }
            if denied && (on || hasAlerts) {
                Button {
                    if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                } label: {
                    Label("通知已在系统设置中关闭，轻点前往打开", systemImage: "bell.slash").font(.footnote).foregroundStyle(Theme.warn)
                }
            }
        } header: { Text("通知") } footer: {
            Text("按各订阅的更新间隔自动更新（打开 App 时，以及系统允许的后台刷新）。成功默认不打扰；失败或节点数减少三成以上时提醒。")
        }
        .listRowBackground(Theme.card)
        .task { denied = await NotificationAuth.allowed() == false }
    }

    var hasAlerts: Bool {
        ProfileStore.shared.profiles.contains { UsageAlerts.rule(for: $0.id).enabled }
            || NodeSubStore.shared.subs.contains { UsageAlerts.rule(for: $0.id).enabled }
    }
}
