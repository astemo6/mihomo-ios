import SwiftUI

// 模块库 pieces added on feat/module-browser: category / 已添加 filter chips, the 已添加 badge and the
// format helpers used by the list rows and the preview's format picker.

extension ModuleGallery {
    /// Distinct formats the item is published in (preferred URL first), from the file extensions.
    nonisolated static func formats(of item: GalleryItem) -> [String] {
        var seen = Set<String>()
        return urls(of: item).map { GalleryItem(name: "", url: $0).formatHint }.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Client name for a module URL's format (format picker in the preview).
    nonisolated static func formatLabel(_ url: String) -> String {
        switch GalleryItem(name: "", url: url).formatHint {
        case "surge": return "Surge"
        case "loon": return "Loon"
        case "stash": return "Stash"
        case "qx": return "Quantumult X"
        case "egern": return "Egern"
        default: return URL(string: url)?.lastPathComponent ?? url
        }
    }
}

/// Horizontal chips: 全部 + the categories of the visible items, and an 已添加 toggle.
struct GalleryFilterBar: View {
    let categories: [String]
    @Binding var category: String
    @Binding var onlyAdded: Bool

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                GalleryChip(title: String(localized: "已添加"), icon: "checkmark.circle", selected: onlyAdded) { onlyAdded.toggle() }
                Divider().frame(height: 16)
                GalleryChip(title: String(localized: "全部"), selected: category.isEmpty) { category = "" }
                ForEach(categories, id: \.self) { c in
                    GalleryChip(title: ModuleGallery.categoryTitle(c), selected: category == c) { category = category == c ? "" : c }
                }
            }
            .padding(.vertical, 2)
        }
        .onChange(of: categories) { cs in if !category.isEmpty && !cs.contains(category) { category = "" } }
    }
}

struct GalleryChip: View {
    let title: String
    var icon: String? = nil
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if let icon { Image(systemName: selected ? icon + ".fill" : icon).font(.caption2) }
                Text(title).font(.caption.weight(.semibold)).lineLimit(1)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Capsule().fill(selected ? Theme.accent.opacity(0.18) : Theme.cardHi))
            .foregroundStyle(selected ? Theme.accent : Color.primary)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// Small 已添加 capsule on gallery rows (same style as the subscription badges).
struct AddedBadge: View {
    var body: some View {
        Text("已添加")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(Theme.good.opacity(0.16)))
            .foregroundStyle(Theme.good)
            .fixedSize()
    }
}
