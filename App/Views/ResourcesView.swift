import SwiftUI
import UIKit
import Libmihomo

// Shared pieces of the 重写 page's subscriptions (RewriteView): the format badge, the update section of the module
// page, and the 从 URL 添加订阅 sheet. (fix/modules-only: the old 模块 page with its 全部 / 模块 / 规则集 / 脚本 filter
// is gone; 工具 → 重写 lists the subscriptions with the shared subscription rows.)

/// Source-format badge (SURGE / QX / LOON / STASH / EGERN / LIST / JS …).
struct SourceFormatBadge: View {
    let format: String
    var body: some View {
        let f = format.lowercased()
        let label: String = {
            switch f {
            case "qx": return "QX"
            case "domainset": return "DOMAIN-SET"
            case "list": return "LIST"
            case "js": return "JS"
            default: return f.uppercased()
            }
        }()
        Text(label)
            .scaledFont(8, weight: .bold)
            .padding(.horizontal, 4).padding(.vertical, 1)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(Theme.ink(0.1)))
    }
}

/// Update settings on the module detail page.
struct ResourceUpdateSection: View {
    @ObservedObject var res = ResourceStore.shared
    let key: String

    var body: some View {
        if let it = res.items.first(where: { $0.key == key }), it.isRemote {
            Section("更新") {
                Text(it.url).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                if it.readOnly == true {
                    LabeledContent("更新间隔", value: ResourceStore.intervalText(it.interval))
                } else {
                    Picker("更新间隔", selection: Binding(get: { it.interval }, set: { res.setInterval(it, $0) })) {
                        ForEach(ResourceStore.intervals, id: \.1) { Text(LocalizedStringKey($0.0)).tag($0.1) }
                        if !ResourceStore.intervals.contains(where: { $0.1 == it.interval }) {
                            Text(ResourceStore.intervalText(it.interval)).tag(it.interval)
                        }
                    }
                }
                LabeledContent("上次更新", value: it.updatedAt == 0 ? String(localized: "尚未下载") : Date(timeIntervalSince1970: it.updatedAt).formatted(date: .abbreviated, time: .shortened))
                if let c = it.checkedAt, c > 0 {
                    LabeledContent("上次检查", value: Date(timeIntervalSince1970: c).formatted(date: .abbreviated, time: .shortened))
                }
                if let e = it.error, !e.isEmpty {
                    Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.bad)
                }
                Button { Task { await res.update(it) } } label: {
                    HStack { Label("立即更新", systemImage: "arrow.clockwise"); Spacer(); if res.busy.contains(it.key) { ProgressView() } }
                }
                .disabled(res.busy.contains(it.key))
            }
            .listRowBackground(Theme.card)
        }
    }
}

/// 从 URL 添加订阅 (v0.19.8: a sheet instead of an alert, so the URL field can carry a PasteButton; nothing is read
/// from the clipboard until 粘贴 is tapped).
struct ModuleURLSheet: View {
    @Binding var url: String
    let onImport: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        TextField("https://…/xxx.sgmodule", text: $url)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityIdentifier("moduleurl.field")
                        PasteButton(payloadType: String.self) { strings in
                            let t = (strings.first ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                            DispatchQueue.main.async {
                                if case .moduleURL(let u, _)? = ImportRouter.parse(t) { url = u } else { url = t }
                            }
                        }
                        .labelStyle(.iconOnly)
                        .buttonBorderShape(.capsule)
                        .accessibilityIdentifier("moduleurl.paste")
                    }
                } footer: {
                    Text("也可以粘贴 surge:/// loon:// stash:// quantumult-x:/// egern:/// 安装链接。")
                }
            }
            .navigationTitle("添加订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
                        var u = url.trimmingCharacters(in: .whitespacesAndNewlines)
                        // Also accepts surge:/// loon:// stash:// quantumult-x:/// egern:/// install links.
                        if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { u = inner }
                        onImport(u)
                        dismiss()
                    }
                    .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .presentationDetents([.medium])
    }
}
