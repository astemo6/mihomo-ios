import SwiftUI
import UIKit

// fix/modules-only → unified subscription rows (user 2026-10-22 08:54): every remote-subscription list — 配置订阅,
// 节点订阅 / 节点集, and the 重写 page's 订阅 (modules) — uses ONE interaction model:
//   • the switch on the right = 启用 / 关闭 (for a config subscription that is its 停用 flag: the profile list already
//     has an enabled concept, so the switch is consistent with the other lists; choosing the current profile stays
//     in the sheet's 设为当前配置 and in 更多 → 配置),
//   • swipe right = 更新 (blue), swipe left = 删除 (red, asks first, no full swipe),
//   • tap = the same edit sheet (名称, 订阅地址, 自动更新间隔, 立即更新, 复制地址, status, 删除),
//   • long press = 更新 · 编辑 · 复制地址 · 启用/关闭 · 删除, always in this order,
//   • one status line: 来源 · 更新于 X · 每 N 天, the error in red underneath.
// Local-only items (a pasted module) show the same row and sheet without the address and update actions.

/// Auto-update choices in seconds. `zero` names 0 (关闭 / 跟随配置); nil = no 0 choice (modules default to 1 day).
enum SubscriptionInterval {
    static let choices: [Int] = [3600, 21600, 43200, 86400, 259200, 604800]

    static func label(_ s: Int) -> String {
        switch s {
        case 3600: return String(localized: "每小时")
        case 21600: return String(localized: "每 6 小时")
        case 43200: return String(localized: "每 12 小时")
        case 86400: return String(localized: "每天")
        case 259200: return String(localized: "每 3 天")
        case 604800: return String(localized: "每周")
        default: return String(localized: "每 \(ResourceStore.intervalText(s))")
        }
    }
}

/// What a row's status line shows.
struct SubscriptionStatus: Equatable {
    /// 来源: 「配置订阅」, 「节点集 · 来自配置」, 「Surge 模块」 …
    var source: String
    var remote: Bool = true
    var updated: Date? = nil
    /// Seconds; 0 = no automatic update.
    var interval: Int = 0
    var error: String? = nil
    var disabled = false
    /// The file has been downloaded at least once (nil = unknown, judged by `updated`).
    var downloaded: Bool? = nil
    /// Extra line under the status (expiry / used of a subscription), shown only without an error.
    var usage: String? = nil
    var usageFraction: Double? = nil

    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f
    }()

    /// 「来源 · 更新于 X · 每 N 天」.
    var line: String {
        var parts = [source]
        if disabled {
            parts.append(String(localized: "已关闭"))
        } else if !remote {
            parts.append(String(localized: "本地"))
        } else {
            if let updated {
                parts.append(String(localized: "更新于 \(Self.relative.localizedString(for: updated, relativeTo: Date()))"))
            } else if downloaded != true {
                parts.append(String(localized: "尚未下载"))
            }
            if interval > 0 { parts.append(String(localized: "每 \(ResourceStore.intervalText(interval))")) }
        }
        return parts.joined(separator: " · ")
    }
}

/// The status block of a row: one grey line, the error in red, an optional usage line.
struct SubscriptionStatusView: View {
    let status: SubscriptionStatus
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: status.line).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            if !status.disabled, let e = status.error, !e.isEmpty {
                Label { Text(verbatim: e) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                    .font(.caption).foregroundStyle(Theme.bad).lineLimit(2)
            } else if !status.disabled, let u = status.usage, !u.isEmpty {
                Text(verbatim: u).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                if let f = status.usageFraction {
                    ProgressView(value: f)
                        .tint(f > 0.9 ? Theme.bad : f > 0.75 ? Theme.warn : Theme.accent)
                        .scaleEffect(x: 1, y: 0.6, anchor: .center)
                }
            }
        }
    }
}

/// One subscription row: icon, name (+ badges), status, count, and the 启用 switch. Tapping anywhere but the switch
/// opens the edit sheet (`onTap`).
struct SubscriptionRow<Badges: View>: View {
    let id: String
    let icon: String
    let color: Color
    var customIcon: String? = nil
    let name: String
    let status: SubscriptionStatus
    var count: Int? = nil
    var updating = false
    /// nil = no switch.
    var enabled: Binding<Bool>? = nil
    var toggleDisabled = false
    let onTap: () -> Void
    @ViewBuilder var badges: () -> Badges

    var body: some View {
        HStack(spacing: 10) {
            Button(action: onTap) {
                HStack(spacing: 12) {
                    if let c = customIcon, !c.isEmpty {
                        IconGlyph(value: c, size: 22)
                            .frame(width: 32, height: 32)
                            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(color.opacity(0.15)))
                            .accessibilityHidden(true)
                    } else {
                        SourceIcon(systemName: icon, color: status.disabled ? .secondary : color)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            Text(verbatim: name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            badges()
                        }
                        SubscriptionStatusView(status: status)
                    }
                    Spacer(minLength: 4)
                    if updating {
                        ProgressView().controlSize(.small)
                    } else if let count {
                        Text(verbatim: "\(count)").font(.subheadline.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                .contentShape(Rectangle())
                .opacity(status.disabled ? 0.6 : 1)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier(id)
            if let enabled {
                Toggle("", isOn: enabled)
                    .labelsHidden()
                    .disabled(toggleDisabled)
                    .accessibilityLabel(Text(verbatim: name))
                    .accessibilityIdentifier(id + ".toggle")
            }
        }
    }
}

extension SubscriptionRow where Badges == EmptyView {
    init(id: String, icon: String, color: Color, customIcon: String? = nil, name: String, status: SubscriptionStatus,
         count: Int? = nil, updating: Bool = false, enabled: Binding<Bool>? = nil, toggleDisabled: Bool = false,
         onTap: @escaping () -> Void) {
        self.init(id: id, icon: icon, color: color, customIcon: customIcon, name: name, status: status, count: count,
                  updating: updating, enabled: enabled, toggleDisabled: toggleDisabled, onTap: onTap, badges: { EmptyView() })
    }
}

/// The actions every subscription row offers. nil = not available for this item (a local module has no 更新 / 复制地址).
struct SubscriptionActions {
    var update: (() -> Void)?
    var edit: () -> Void
    var url: String?
    /// The current 启用 state and how to flip it; nil = no switch.
    var enabled: Bool?
    var setEnabled: ((Bool) -> Void)?
    var toggleDisabled = false
    /// Asks first (the caller presents its confirmation).
    var delete: (() -> Void)?
}

extension View {
    /// Swipes and long-press menu of a subscription row: right 更新 (blue); left 删除 (red, no full swipe — the caller
    /// confirms); menu 更新 · 编辑 · 复制地址 · 启用/关闭 · 删除.
    func subscriptionActions(_ a: SubscriptionActions) -> some View {
        self
            .swipeActions(edge: .leading, allowsFullSwipe: true) {
                if let u = a.update {
                    Button { u() } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
                }
            }
            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                if let d = a.delete {
                    // Not role: .destructive — that removes the row at once, even when the confirmation is cancelled.
                    Button { d() } label: { Label("删除", systemImage: "trash") }.tint(.red)
                }
            }
            .contextMenu {
                Button { a.update?() } label: { Label("更新", systemImage: "arrow.clockwise") }
                    .disabled(a.update == nil)
                Button { a.edit() } label: { Label("编辑", systemImage: "pencil") }
                Button { if let u = a.url { UIPasteboard.general.string = u } } label: { Label("复制地址", systemImage: "doc.on.doc") }
                    .disabled(a.url == nil)
                if let on = a.enabled {
                    Button { a.setEnabled?(!on) } label: {
                        Label(LocalizedStringKey(on ? "关闭" : "启用"), systemImage: on ? "pause.circle" : "play.circle")
                    }
                    .disabled(a.toggleDisabled)
                }
                if let d = a.delete {
                    Divider()
                    Button(role: .destructive) { d() } label: { Label("删除", systemImage: "trash") }
                }
            }
    }
}

/// The one edit sheet for every subscription kind: 名称, 订阅地址, 自动更新间隔, 立即更新, 复制地址, status, extra
/// kind-specific sections, 删除 at the bottom. 保存 writes through `save` (which re-downloads when the address
/// changed) and shows its result; a failure keeps the sheet open with the error.
struct SubscriptionSheet<Extra: View>: View {
    let title: LocalizedStringKey
    @Binding var name: String
    var namePlaceholder: String = ""
    var nameFooter: Text? = nil
    /// nil = a local item (no address, no update).
    var url: Binding<String>?
    var urlPlaceholder: String = "https://…"
    @Binding var interval: Int
    /// Label of interval 0 (关闭 / 跟随配置); nil = no 0 choice.
    var zeroInterval: LocalizedStringKey? = "关闭"
    let status: SubscriptionStatus
    var updating = false
    /// Unsaved changes (enables 保存).
    var dirty: Bool
    /// Writes the edits; returns an error text (nil = done). Re-downloads when the address changed.
    let save: () async -> String?
    /// 立即更新; returns an error text.
    var update: (() async -> String?)? = nil
    var deleteTitle: Text? = nil
    var deleteMessage: Text? = nil
    var delete: (() -> Void)? = nil
    @ViewBuilder var extra: () -> Extra

    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var result: String?
    @State private var resultOK = false
    @State private var confirmDelete = false

    var urlText: String { (url?.wrappedValue ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }

    static func validURL(_ s: String) -> Bool {
        guard let u = URL(string: s), let sc = u.scheme?.lowercased(), sc == "http" || sc == "https", u.host?.isEmpty == false else { return false }
        return !s.contains(where: { $0.isWhitespace })
    }

    var urlValid: Bool { url == nil || Self.validURL(urlText) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(namePlaceholder, text: $name)
                        .accessibilityIdentifier("sub.sheet.name")
                } header: { Text("名称") } footer: { if let nameFooter { nameFooter } }
                .listRowBackground(Theme.card)

                if let url {
                    Section {
                        TextField(urlPlaceholder, text: url, axis: .vertical)
                            .font(.footnote.monospaced())
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("sub.sheet.url")
                        if !urlText.isEmpty && !urlValid {
                            Text("请输入以 http:// 或 https:// 开头的链接").font(.caption).foregroundStyle(Theme.bad)
                        }
                        Button {
                            UIPasteboard.general.string = urlText
                            result = String(localized: "已复制地址"); resultOK = true
                        } label: { Label("复制地址", systemImage: "doc.on.doc") }
                            .disabled(urlText.isEmpty)
                            .accessibilityIdentifier("sub.sheet.copy")
                    } header: { Text("订阅地址") }
                    .listRowBackground(Theme.card)
                }

                Section {
                    if url != nil {
                        Picker("自动更新", selection: $interval) {
                            if let z = zeroInterval { Text(z).tag(0) }
                            ForEach(SubscriptionInterval.choices, id: \.self) { Text(verbatim: SubscriptionInterval.label($0)).tag($0) }
                            if interval != 0 && !SubscriptionInterval.choices.contains(interval) {
                                Text(verbatim: SubscriptionInterval.label(interval)).tag(interval)
                            }
                        }
                        .accessibilityIdentifier("sub.sheet.interval")
                    }
                    SubscriptionStatusView(status: status)
                        .accessibilityIdentifier("sub.sheet.status")
                    if let update {
                        Button {
                            Task {
                                busy = true
                                let e = await update()
                                busy = false
                                result = e ?? String(localized: "已更新"); resultOK = e == nil
                            }
                        } label: {
                            HStack { Label("立即更新", systemImage: "arrow.clockwise"); Spacer(); if busy || updating { ProgressView() } }
                        }
                        .disabled(busy || updating)
                        .accessibilityIdentifier("sub.sheet.update")
                    }
                    if let result {
                        Label(result, systemImage: resultOK ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .font(.footnote).foregroundStyle(resultOK ? Theme.good : Theme.bad)
                            .accessibilityIdentifier("sub.sheet.result")
                    }
                } header: { Text("更新") }
                .listRowBackground(Theme.card)

                extra()

                if delete != nil {
                    Section {
                        Button(role: .destructive) { confirmDelete = true } label: {
                            HStack { Spacer(); Text("删除"); Spacer() }
                        }
                        .accessibilityIdentifier("sub.sheet.delete")
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button { dismiss() } label: { dirty ? Text("取消") : Text("完成") }.accessibilityIdentifier("sub.sheet.close") }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("保存") {
                            Task {
                                busy = true
                                let e = await save()
                                busy = false
                                if let e { result = e; resultOK = false } else { dismiss() }
                            }
                        }
                        .disabled(!dirty || !urlValid || (name.trimmingCharacters(in: .whitespaces).isEmpty && namePlaceholder.isEmpty))
                        .accessibilityIdentifier("sub.sheet.save")
                    }
                }
            }
            .confirmationDialog(deleteTitle ?? Text("删除？"), isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("删除", role: .destructive) {
                    let d = delete
                    dismiss()
                    d?()
                }
                .accessibilityIdentifier("sub.sheet.confirmDelete")
                Button("取消", role: .cancel) {}
            } message: { if let deleteMessage { deleteMessage } }
        }
    }
}

extension SubscriptionSheet where Extra == EmptyView {
    init(title: LocalizedStringKey, name: Binding<String>, namePlaceholder: String = "", nameFooter: Text? = nil,
         url: Binding<String>?, urlPlaceholder: String = "https://…", interval: Binding<Int>, zeroInterval: LocalizedStringKey? = "关闭",
         status: SubscriptionStatus, updating: Bool = false, dirty: Bool, save: @escaping () async -> String?,
         update: (() async -> String?)? = nil, deleteTitle: Text? = nil, deleteMessage: Text? = nil, delete: (() -> Void)? = nil) {
        self.init(title: title, name: name, namePlaceholder: namePlaceholder, nameFooter: nameFooter, url: url,
                  urlPlaceholder: urlPlaceholder, interval: interval, zeroInterval: zeroInterval, status: status, updating: updating,
                  dirty: dirty, save: save, update: update, deleteTitle: deleteTitle, deleteMessage: deleteMessage, delete: delete,
                  extra: { EmptyView() })
    }
}
