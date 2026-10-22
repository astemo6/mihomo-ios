import SwiftUI
import UserNotifications

/// 更多 → 通知 (user 2026-10-22 「Tern没有通知管理吗」): every kind of system notification Tern sends, in one place —
/// script notifications ($notification.post / $notify, posted by the tunnel), per-subscription usage / expiry
/// reminders, and the summary after automatic updates.
struct NotificationsView: View {
    /// nil = not asked yet.
    @State private var allowed: Bool?
    @State private var scripts = NotificationPrefs.scriptsEnabled
    @State private var subs: [SubAlertItem] = []

    struct SubAlertItem: Identifiable {
        let id: String
        let name: String
        let kind: LocalizedStringKey
        var rule: UsageAlertRule
    }

    var body: some View {
        List {
            Section {
                HStack {
                    Label("系统通知权限", systemImage: "bell.badge")
                    Spacer()
                    Text(LocalizedStringKey(allowed == nil ? "未请求" : allowed == true ? "已允许" : "已关闭"))
                        .foregroundStyle(allowed == false ? Theme.warn : Color.secondary)
                }
                if allowed == nil {
                    Button("允许通知") {
                        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in
                            Task { @MainActor in allowed = await NotificationAuth.allowed() }
                        }
                    }
                } else if allowed == false {
                    Button("前往系统设置打开") {
                        if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                    }
                }
            } footer: { Text("所有通知都在本机生成，不经过任何服务器。") }
            .listRowBackground(Theme.card)

            Section {
                Toggle("脚本通知", isOn: $scripts)
                    .onChange(of: scripts) { NotificationPrefs.scriptsEnabled = $0; if $0 { NotificationAuth.request() } }
                NavigationLink { ScriptNoticesView() } label: { Text("脚本通知记录") }
            } header: { Text("脚本") } footer: {
                Text("重写 / 模块里的脚本调用 $notification.post、$notify 时（例如签到结果）发出的通知。关闭后仍会记入「脚本通知记录」。")
            }
            .listRowBackground(Theme.card)

            Section {
                if subs.isEmpty {
                    Text("没有远程订阅").foregroundStyle(.secondary)
                }
                ForEach($subs) { $s in
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle(isOn: $s.rule.enabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: s.name).lineLimit(1)
                                Text(s.kind).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        if s.rule.enabled {
                            Picker("流量用到", selection: $s.rule.quotaPercent) {
                                Text("关闭").tag(0)
                                ForEach(UsageAlertRule.quotaChoices, id: \.self) { Text("\($0)%").tag($0) }
                            }
                            Picker("到期前", selection: $s.rule.expiryDays) {
                                Text("关闭").tag(0)
                                ForEach(UsageAlertRule.expiryChoices, id: \.self) { Text("\($0) 天").tag($0) }
                            }
                        }
                    }
                    .onChange(of: s.rule) { UsageAlerts.setRule($0, for: s.id) }
                }
            } header: { Text("订阅用量与到期") } footer: {
                Text("用订阅返回的流量与到期信息提醒；没有这些信息的订阅不会提醒。")
            }
            .listRowBackground(Theme.card)

            UpdateNotifySection()
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("通知")
        .task {
            allowed = await NotificationAuth.allowed()
            var list: [SubAlertItem] = []
            for p in ProfileStore.shared.profiles where p.kind == .remote {
                list.append(SubAlertItem(id: p.id, name: p.name, kind: "配置订阅", rule: UsageAlerts.rule(for: p.id)))
            }
            for s in NodeSubStore.shared.subs {
                list.append(SubAlertItem(id: s.id, name: s.name, kind: "节点订阅", rule: UsageAlerts.rule(for: s.id)))
            }
            subs = list
        }
    }
}

/// Shared with the tunnel (app group): whether scripts may post system notifications. Default on.
enum NotificationPrefs {
    static let scriptsKey = "notify.scripts"
    static var scriptsEnabled: Bool {
        get { AppShared.defaults.object(forKey: scriptsKey) as? Bool ?? true }
        set { AppShared.defaults.set(newValue, forKey: scriptsKey) }
    }
}
