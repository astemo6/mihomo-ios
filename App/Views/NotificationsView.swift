import SwiftUI
import UserNotifications

/// 更多 → 通知 (user 2026-10-22 「Tern没有通知管理吗」): every kind of system notification Tern sends, in one place —
/// script notifications ($notification.post / $notify, posted by the tunnel), per-subscription usage / expiry
/// reminders, and the summary after automatic updates.
///
/// feat/loon-menu-notify (user 2026-10-23, Loon 录屏 「借鉴下他的通知分类，现在的太少了」): Loon's layout — a 允许通知
/// master switch, then one switch per kind (网络变化, 策略组异常, 自动策略切换, 节点异常, 脚本通知, 内存警告, plus Tern's
/// VPN 意外断开). Each kind is a real tunnel / core event (NotifyKind); the switches live in the App Group and a
/// running tunnel is told about a change at once.
struct NotificationsView: View {
    /// nil = not asked yet.
    @State private var allowed: Bool?
    @State private var master = NotifyPrefs.masterEnabled
    @State private var kinds: [String: Bool] = NotifyPrefs.currentSwitches()
    @State private var subs: [SubAlertItem] = []

    struct SubAlertItem: Identifiable {
        let id: String
        let name: String
        let kind: LocalizedStringKey
        var rule: UsageAlertRule
    }

    /// Loon's order; VPN 意外断开 (Tern only) last.
    static let order: [NotifyKind] = [.network, .policyFailure, .policyChange, .nodeFailure, .scripts, .memory, .vpn]

    static func title(_ k: NotifyKind) -> LocalizedStringKey {
        switch k {
        case .network: return "网络变化"
        case .policyFailure: return "策略组异常"
        case .policyChange: return "自动策略切换"
        case .nodeFailure: return "节点异常"
        case .scripts: return "脚本通知"
        case .memory: return "内存警告"
        case .vpn: return "VPN 意外断开"
        }
    }

    static func caption(_ k: NotifyKind) -> LocalizedStringKey {
        switch k {
        case .network: return "切换 Wi-Fi 与蜂窝网络、连上其他 Wi-Fi 时"
        case .policyFailure: return "策略组里所有节点都测速失败时"
        case .policyChange: return "自动测速或故障转移策略组换用其他节点时"
        case .nodeFailure: return "当前使用的节点测速失败时"
        case .scripts: return "重写 / 模块里的脚本发出的通知，例如签到结果"
        case .memory: return "隧道内存接近系统上限、关闭了部分连接时"
        case .vpn: return "VPN 被系统断开，或被系统结束后自动重新连接时"
        }
    }

    func binding(_ k: NotifyKind) -> Binding<Bool> {
        Binding(get: { kinds[k.rawValue] ?? k.defaultOn }, set: { on in
            kinds[k.rawValue] = on
            NotifyPrefs.set(k, on)
            if on { NotificationAuth.request() }
            Self.tellTunnel()
        })
    }

    /// The core's policy watcher starts / stops with its switches; nothing to do while disconnected (the tunnel
    /// reads the switches when it starts).
    static func tellTunnel() {
        Task { @MainActor in _ = await VPNManager.shared.send(.notifyPrefs, timeout: 3) }
    }

    var body: some View {
        List {
            Section {
                Toggle("允许通知", isOn: $master)
                    .onChange(of: master) { on in
                        NotifyPrefs.masterEnabled = on
                        if on { NotificationAuth.request() }
                        Self.tellTunnel()
                    }
                    .accessibilityIdentifier("notify.master")
                HStack {
                    Label("系统通知权限", systemImage: "bell.badge")
                    Spacer()
                    Text(LocalizedStringKey(allowed == nil ? "未请求" : allowed == true ? "已允许" : "已关闭"))
                        .foregroundStyle(allowed == false ? Theme.warn : Color.secondary)
                }
                if allowed == nil {
                    Button("请求通知权限") {
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
                ForEach(Self.order) { k in
                    Toggle(isOn: binding(k)) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(Self.title(k))
                            Text(Self.caption(k)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .accessibilityIdentifier("notify." + k.rawValue)
                    .disabled(!master)
                }
                // ui-audit: the history is still recorded with notifications off (see the footer), so it stays openable.
                NavigationLink { ScriptNoticesView() } label: { Text("脚本通知记录") }
            } footer: {
                Text("策略组异常、自动策略切换和节点异常根据策略组的测速结果判断（自动测速或手动测速），VPN 连接时每 30 秒检查一次。脚本通知关闭后仍会记入「脚本通知记录」。")
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
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
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

extension NotifyPrefs {
    /// Every kind's current switch, keyed by NotifyKind.rawValue (the page's initial state).
    static func currentSwitches() -> [String: Bool] {
        var d: [String: Bool] = [:]
        for k in NotifyKind.allCases { d[k.rawValue] = isOn(k) }
        return d
    }
}
