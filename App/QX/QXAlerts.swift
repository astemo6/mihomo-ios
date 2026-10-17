import SwiftUI
import UIKit

// QX preview 7: main v0.14's subscription notifications in QX's underline form style.
//  • QXUsageAlertField — 用量提醒 in 资源 - 节点 / 资源 - 配置 (new and edit): quota % and days before expiry,
//    with the current usage from subscription-userinfo when the resource has it.
//  • QXUpdateNotifyCard — 自动更新后通知 at the bottom of 引用资源 - 节点.
// The rules and the notifications themselves are main's (App/Core/SubscriptionAlerts.swift).

struct QXUsageAlertField: View {
    @Binding var rule: UsageAlertRule
    var info: SubscriptionUserInfo? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: $rule.enabled.animation(QXMotion.spring)) {
                Text("用量提醒").font(.system(size: 20, weight: .bold))
            }
            .tint(QXColor.switchOn)
            if let usage { Text(verbatim: usage).font(.subheadline.monospacedDigit()).foregroundStyle(.secondary) }
            if rule.enabled {
                HStack(spacing: 10) {
                    choice(String(localized: "流量用到"),
                           value: rule.quotaPercent == 0 ? String(localized: "关闭") : "\(rule.quotaPercent)%") {
                        Button { rule.quotaPercent = 0 } label: { Text("关闭") }
                        ForEach(UsageAlertRule.quotaChoices, id: \.self) { v in
                            Button { rule.quotaPercent = v } label: { Text(verbatim: "\(v)%") }
                        }
                    }
                    choice(String(localized: "到期前"),
                           value: rule.expiryDays == 0 ? String(localized: "关闭") : String(localized: "\(rule.expiryDays) 天")) {
                        Button { rule.expiryDays = 0 } label: { Text("关闭") }
                        ForEach(UsageAlertRule.expiryChoices, id: \.self) { v in
                            Button { rule.expiryDays = v } label: { Text("\(v) 天") }
                        }
                    }
                }
                .transition(.opacity)
            }
            Text("用订阅返回的流量与到期信息（subscription-userinfo）发本地通知：每次更新后检查流量，用完时再提醒一次；到期提醒由系统按时送达，不需要打开 App。没有这些信息的订阅不会提醒。")
                .font(.footnote).foregroundStyle(.secondary)
            Divider()
        }
    }

    private var usage: String? {
        guard let info, info.total > 0 || info.expire > 0 else { return nil }
        var parts: [String] = []
        if info.total > 0 {
            parts.append(String(localized: "已用 \(Fmt.bytes(info.used)) / \(Fmt.bytes(info.total))") + " · \(Int(info.fraction * 100))%")
        }
        if let d = info.expireDate { parts.append(String(localized: "\(d.formatted(date: .abbreviated, time: .omitted)) 到期")) }
        return parts.joined(separator: " · ")
    }

    /// A QX capsule menu: grey caption above, the chosen value in a cardHi capsule.
    private func choice<C: View>(_ title: String, value: String, @ViewBuilder items: () -> C) -> some View {
        Menu {
            items()
        } label: {
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: title).font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text(verbatim: value).font(.body.weight(.semibold).monospacedDigit()).foregroundStyle(.primary)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.up.chevron.down").font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(QXPalette.cardHi))
        }
    }
}

struct QXUpdateNotifyCard: View {
    @State private var on = ScheduledUpdates.notifyEnabled
    @State private var mode = ScheduledUpdates.mode
    @State private var denied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("通知").font(.headline).padding(.top, 6)
            QXCard {
                VStack(alignment: .leading, spacing: 0) {
                    Toggle(isOn: $on.animation(QXMotion.spring)) {
                        Label { Text("自动更新后通知").font(QXType.rowTitle) } icon: {
                            Image(systemName: "bell.badge").foregroundStyle(QXColor.nodes)
                        }
                    }
                    .tint(QXColor.switchOn)
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .onChange(of: on) { ScheduledUpdates.notifyEnabled = $0 }
                    if on {
                        Divider().padding(.leading, 16)
                        HStack {
                            Text("何时通知").font(QXType.rowTitle)
                            Spacer()
                            Menu {
                                ForEach(UpdateNotifyMode.allCases) { m in
                                    Button { mode = m } label: { Text(LocalizedStringKey(m.title)) }
                                }
                            } label: {
                                HStack(spacing: 4) {
                                    Text(LocalizedStringKey(mode.title)).font(QXType.rowTitle)
                                    Image(systemName: "chevron.up.chevron.down").font(.caption)
                                }
                                .foregroundStyle(QXColor.switchOn)
                            }
                        }
                        .padding(.horizontal, 16).padding(.vertical, 12)
                        .transition(.opacity)
                        .onChange(of: mode) { ScheduledUpdates.mode = $0 }
                    }
                    if denied && (on || hasAlerts) {
                        Divider().padding(.leading, 16)
                        Button {
                            if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                        } label: {
                            Label("通知已在系统设置中关闭，轻点前往打开", systemImage: "bell.slash")
                                .font(.footnote).foregroundStyle(QXColor.warning)
                        }
                        .padding(.horizontal, 16).padding(.vertical, 12)
                    }
                }
            }
            Text("按各订阅的更新间隔自动更新（打开 App 时，以及系统允许的后台刷新）。成功默认不打扰；失败或节点数减少三成以上时提醒。")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .task { denied = await NotificationAuth.allowed() == false }
    }

    private var hasAlerts: Bool {
        ProfileStore.shared.profiles.contains { UsageAlerts.rule(for: $0.id).enabled }
            || NodeSubStore.shared.subs.contains { UsageAlerts.rule(for: $0.id).enabled }
    }
}
