import SwiftUI

/// Shared delete confirmations (review 5): every place that deletes the same kind of thing asks the
/// same question with the same consequences text, so a full trailing swipe never deletes on its own.
@MainActor
enum DeleteText {
    /// Whether a delete can be undone from 配置快照 (automatic snapshots on) or not.
    static var recoverable: Text {
        SnapshotStore.shared.autoEnabled ? Text("删除后可以在「配置快照」中恢复。") : Text("删除后无法恢复。")
    }
}

extension View {
    /// Generic 「删除…？」 dialog bound to an optional pending item.
    func deleteConfirmation<T>(_ title: @escaping (T) -> Text, item: Binding<T?>,
                               message: ((T) -> Text)? = nil, id: String? = nil, actionTitle: LocalizedStringKey = "删除",
                               perform: @escaping (T) -> Void) -> some View {
        confirmationDialog(item.wrappedValue.map(title) ?? Text(verbatim: ""),
                           isPresented: Binding(get: { item.wrappedValue != nil }, set: { if !$0 { item.wrappedValue = nil } }),
                           titleVisibility: .visible, presenting: item.wrappedValue) { v in
            Button(actionTitle, role: .destructive) { item.wrappedValue = nil; perform(v) }
                .accessibilityIdentifier(id ?? "confirmDelete")
            Button("取消", role: .cancel) { item.wrappedValue = nil }
        } message: { v in
            if let message { message(v) }
        }
    }

    /// 「删除这个订阅？」 for a node subscription — 节点管理 and 订阅管理 use this one dialog.
    func nodeSubDeleteConfirmation(_ pending: Binding<NodeSubscription?>,
                                   perform: @escaping (NodeSubscription) async -> Void) -> some View {
        deleteConfirmation({ _ in Text("删除这个订阅？") }, item: pending,
                           message: { s in Text("「\(s.name)」的节点会从所有配置中移除，引用它的策略组改用其他节点。") },
                           id: "nodesub.confirmDelete") { s in Task { await perform(s) } }
    }

    /// 「删除「name」？」 for a profile. When it has 自定义 copies the message names them (review item 6);
    /// 配置 and 订阅管理 use this one dialog.
    func profileDeleteConfirmation(_ pending: Binding<Profile?>, store: ProfileStore) -> some View {
        deleteConfirmation({ p in Text("删除「\(p.displayName)」？") }, item: pending,
                           message: { p in
                               let names = store.copies(of: p).map(\.displayName).joined(separator: "、")
                               return names.isEmpty
                                   ? DeleteText.recoverable
                                   : Text("这些副本是从它复制的：\(names)。删除后它们会保留为本地配置，不再随订阅更新。")
                           }, id: "profile.confirmDelete") { p in store.delete(p) }
    }
}
