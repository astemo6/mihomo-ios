import SwiftUI
import UIKit

/// 更多 → 设置 → 外观 (v0.9). Applied to every window through UIKit's overrideUserInterfaceStyle, so sheets,
/// the import sheet ImportRouter presents and the system pickers follow it too (SwiftUI's
/// preferredColorScheme does not reliably return to "system" once it was set).
enum AppAppearance: String, CaseIterable, Identifiable {
    case system, light, dark
    static let key = "appearance"

    var id: String { rawValue }
    var title: LocalizedStringKey {
        switch self {
        case .system: return "跟随系统"
        case .light: return "浅色"
        case .dark: return "深色"
        }
    }
    var icon: String {
        switch self {
        case .system: return "circle.lefthalf.filled"
        case .light: return "sun.max"
        case .dark: return "moon"
        }
    }
    var style: UIUserInterfaceStyle {
        switch self {
        case .system: return .unspecified
        case .light: return .light
        case .dark: return .dark
        }
    }

    static var current: AppAppearance {
        AppAppearance(rawValue: UserDefaults.standard.string(forKey: key) ?? "") ?? .system
    }

    /// Sets the style on every window of every connected scene.
    @MainActor static func apply(_ a: AppAppearance = current) {
        for scene in UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }) {
            for w in scene.windows where w.overrideUserInterfaceStyle != a.style {
                w.overrideUserInterfaceStyle = a.style
            }
        }
    }
}

struct AppearanceView: View {
    @AppStorage(AppAppearance.key) private var raw = AppAppearance.system.rawValue
    @ObservedObject private var live = LiveActivityController.shared

    var body: some View {
        List {
            Section {
                ForEach(AppAppearance.allCases) { a in
                    Button {
                        raw = a.rawValue
                        AppAppearance.apply(a)
                    } label: {
                        HStack {
                            Label(a.title, systemImage: a.icon).foregroundStyle(.primary)
                            Spacer()
                            if raw == a.rawValue {
                                Image(systemName: "checkmark").font(.body.weight(.semibold)).foregroundStyle(Theme.accent)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(raw == a.rawValue ? .isSelected : [])
                }
            } footer: {
                Text("跟随系统时随 iPhone 的浅色 / 深色外观切换。小组件始终跟随系统。")
            }
            .listRowBackground(Theme.card)
            Section {
                Toggle("实时活动与灵动岛", isOn: $live.enabled).tint(Theme.accent)
                if live.enabled && !live.systemAllowed {
                    Text("系统设置中关闭了 Tern 的实时活动。").font(.caption).foregroundStyle(Theme.warn)
                }
            } footer: {
                Text("连接时在锁定屏幕和灵动岛显示连接状态、已连接时长、当前节点和速度。需要带小组件的 IPA（-widget）。时长一直走；App 关闭时，速度和节点在系统允许后台刷新时更新，也可以点实时活动上的刷新按钮（iOS 17 及以上）。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("外观")
        .navigationBarTitleDisplayMode(.inline)
    }
}
