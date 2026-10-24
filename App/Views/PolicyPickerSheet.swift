import SwiftUI

/// 规则 → Final (user 2026-10-23 「Final 指向无法修改」): pick the policy a rule sends traffic to — the profile's
/// groups, the built-in policies and the profile's own nodes (PolicyTargets), searchable. 保存 hands back the
/// choice; 恢复配置原样 (on top, shown while the policy differs from the profile's) hands back nil.
struct PolicyPickerSheet: View {
    let title: Text
    /// The profile's own policy ("" = the profile has none).
    let original: String
    var footer: LocalizedStringKey? = nil
    let onSave: (String?) -> Void
    @State private var selection: String
    @State private var targets = PolicyTargets()
    @State private var search = ""
    @Environment(\.dismiss) private var dismiss

    init(title: Text, current: String, original: String, footer: LocalizedStringKey? = nil, onSave: @escaping (String?) -> Void) {
        self.title = title
        self.original = original
        self.footer = footer
        self.onSave = onSave
        _selection = State(initialValue: current)
        opened = current
    }

    /// The policy in effect when the sheet opened.
    private let opened: String
    /// Shown while the policy differs from the profile's (an edit is in effect, or one is being picked).
    var showRestore: Bool { !original.isEmpty && (opened != original || selection != original) }

    func filtered(_ names: [String]) -> [String] {
        search.isEmpty ? names : names.filter { $0.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        let groups = filtered(targets.groups)
        let builtins = filtered(targets.builtins)
        let nodes = filtered(targets.nodes)
        let unknown = !selection.isEmpty && !targets.all.contains(selection) && search.isEmpty
        NavigationStack {
            List {
                // v0.19.22 (test91): 恢复配置原样 sits on top. At the bottom it came after every node of the profile —
                // off screen (never rendered by the lazy list) for any real profile, so nobody found it.
                if search.isEmpty && (showRestore || footer != nil) {
                    Section {
                        if showRestore {
                            Button {
                                onSave(nil)
                                dismiss()
                            } label: {
                                Label("恢复配置原样", systemImage: "arrow.uturn.backward")
                            }
                            .disabled(selection == original)
                            .accessibilityIdentifier("policy.restore")
                        }
                    } footer: {
                        if let footer { Text(footer) }
                    }
                    .listRowBackground(Theme.card)
                }
                if unknown { section("当前", [selection]) }
                if !groups.isEmpty { section("策略组", groups) }
                if !builtins.isEmpty { section("内置策略", builtins) }
                if !nodes.isEmpty { section("节点", nodes) }
                if groups.isEmpty && builtins.isEmpty && nodes.isEmpty && !search.isEmpty {
                    Text("没有匹配的策略").font(.footnote).foregroundStyle(.secondary)
                        .listRowBackground(Color.clear)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索")
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        onSave(selection == original ? nil : selection)
                        dismiss()
                    }
                    .disabled(selection.isEmpty)
                    .accessibilityIdentifier("policy.save")
                }
            }
            .task { targets = await PolicyTargets.load() }
        }
    }

    func section(_ header: LocalizedStringKey, _ names: [String]) -> some View {
        Section {
            ForEach(names, id: \.self) { n in
                Button {
                    selection = n
                } label: {
                    HStack {
                        Text(verbatim: n).foregroundStyle(.primary).lineLimit(1)
                        Spacer()
                        if n == selection { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
                    }
                    .contentShape(Rectangle())
                }
                .accessibilityIdentifier("policy.pick." + n)
                .accessibilityAddTraits(n == selection ? .isSelected : [])
            }
        } header: { Text(header) }
        .listRowBackground(Theme.card)
    }
}

/// 已修改: a profile rule or the Final the user changed (the change is an override; 恢复配置原样 undoes it).
struct ModifiedTag: View {
    var body: some View {
        Text("已修改").font(.caption2.weight(.semibold))
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(Capsule().fill(Theme.accent.opacity(0.14)))
            .foregroundStyle(Theme.accent)
            .lineLimit(1).fixedSize()
            .accessibilityIdentifier("rules.modified")
    }
}
