import SwiftUI

// fix/nc-0.20.2 (user: every orderable list reorders the same way): one 「排序」 / 「完成」 toolbar button used by
// 分流规则, 策略, 重写 and 定时任务. Tapping it switches the list into edit mode (drag handles); it is always shown
// and only disabled when there is nothing to reorder (fewer than 2 rows), with the same look everywhere.
struct ReorderToolbarButton: View {
    let isEditing: Bool
    var count: Int = 2
    let id: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            if isEditing {
                Text("完成").fontWeight(.semibold)
            } else {
                Label("排序", systemImage: "arrow.up.arrow.down")
            }
        }
        .disabled(!isEditing && count < 2)
        .accessibilityLabel(Text(isEditing ? "完成" : "排序"))
        .accessibilityIdentifier(id)
    }
}
