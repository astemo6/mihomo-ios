import SwiftUI

// fix/app-policy-ui #3 (user 2026-10-26 21:23, IMG_3621): 工具 → 分流规则 → 订阅 reorders like 策略组 — ⋯ → 编辑排序
// swaps the page for a reorder list (drag handles, 置顶) with 取消 / 完成, the same ReorderRow and flow as
// GroupReorderList. The order IS the matching priority:
//   • the profile's rule sets → written into the profile file by ProfileWriteBack (feat/profile-write-back;
//     a subscription's edits land in its local copy): the RULE-SET lines of `rules:` are permuted into this
//     order (NCRuntimeSteps.applyRuleSetOrder: only the RULE-SET slots are permuted — 本地规则 / inline rules
//     and the final MATCH keep their positions; a set the profile adds later keeps its own slot);
//   • the lists the user added (rules.json) are custom rules, injected ahead of the profile's rules, so they form
//     their own section above.
// 完成 writes both and reloads the core once.

struct RuleOrderRow: Identifiable, Equatable {
    /// Rule-set name (profile) or custom rule id (user's list).
    let id: String
    let name: String
    let policy: String
    var disabled = false
}

/// What 完成 saves, from the rows as arranged (pure, unit-tested).
enum RuleSetOrderPlan {
    /// The `#rule-order` list to save: nil = unchanged (nothing to write).
    static func setOrder(_ rows: [RuleOrderRow], original: [String]) -> [String]? {
        let names = rows.map(\.id)
        return names == original ? nil : names
    }

    /// The user's lists in their new order (ids), nil = unchanged.
    static func mineOrder(_ rows: [RuleOrderRow], original: [String]) -> [String]? {
        let ids = rows.map(\.id)
        return ids == original ? nil : ids
    }

    /// `rules` with the members named in `ids` put into that order inside the slots they already hold
    /// (local custom rules between them stay where they are).
    static func reordered(_ rules: [CustomRule], ids: [String]) -> [CustomRule] {
        let rank = Dictionary(ids.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let moving = rules.filter { rank[$0.id] != nil }.sorted { rank[$0.id]! < rank[$1.id]! }
        var it = moving.makeIterator()
        return rules.map { rank[$0.id] != nil ? (it.next() ?? $0) : $0 }
    }
}

/// The reorder list shown in place of 分流规则's sections while 编辑排序 is on.
struct RuleSetReorderList: View {
    @Binding var mine: [RuleOrderRow]
    @Binding var sets: [RuleOrderRow]
    var message: String?

    var body: some View {
        List {
            if !mine.isEmpty {
                Section {
                    ForEach(mine) { r in row(r, rows: $mine, prefix: "ruleorder.mine.") }
                        .onMove { mine.move(fromOffsets: $0, toOffset: $1) }
                        .deleteDisabled(true)
                } header: {
                    Text("我添加的订阅")
                } footer: {
                    Text("自己添加的订阅排在配置里的规则集之前匹配。")
                        .modifier(UITestOrderValue(id: "ruleorder.mine.order", order: mine.map(\.name).joined(separator: " | ")))
                }
                .listRowBackground(Theme.card)
            }
            Section {
                if sets.isEmpty {
                    Text("配置里没有规则集").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(sets) { r in row(r, rows: $sets, prefix: "ruleorder.set.") }
                    .onMove { sets.move(fromOffsets: $0, toOffset: $1) }
                    .deleteDisabled(true)
            } header: {
                Text("配置里的规则集")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("顺序就是匹配优先级：越靠上越先匹配。拖动或置顶来调整顺序。")
                    Text("本地规则和 Final 的位置不变；顺序会写进配置文件（订阅配置写进它的本地副本），更新订阅后仍保持此顺序。")
                }
                .modifier(UITestOrderValue(id: "ruleorder.sets.order", order: sets.map(\.name).joined(separator: " | ")))
            }
            .listRowBackground(Theme.card)

            if let message {
                Section { Text(message).font(.footnote).foregroundStyle(Theme.bad) }
                    .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .environment(\.editMode, .constant(.active))
    }

    @ViewBuilder
    func row(_ r: RuleOrderRow, rows: Binding<[RuleOrderRow]>, prefix: String) -> some View {
        ReorderRow(name: r.name, note: r.disabled ? Text("已关闭") : nil, isFirst: rows.wrappedValue.first?.id == r.id,
                   topID: prefix + "top." + r.name,
                   onTop: { withAnimation { rows.wrappedValue = ReorderOps.toTop(rows.wrappedValue, r.id) { $0.id } } }) {
            SourceIcon(systemName: "list.bullet.rectangle", color: r.disabled ? .secondary : Theme.accent)
        } tag: {
            if !r.policy.isEmpty { PolicyChip(name: r.policy) }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(prefix + "row." + r.name)
    }
}
