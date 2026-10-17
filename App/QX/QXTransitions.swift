import SwiftUI
import Combine

// QX preview 7 smoothness pass.
//  • Native zoom transition (iOS 18 navigationTransition(.zoom)) from the home tiles and the windmill to their
//    pages; iOS 16/17 keep the system push. Only the phone layout zooms (on iPad the source sits in another
//    column).
//  • QXModeModel: the run mode on its own, so pages that only show the mode (其他设置, 运行模式, 小组件) no
//    longer re-render on every per-second traffic sample DashboardModel publishes.

private struct QXZoomNamespaceKey: EnvironmentKey {
    static let defaultValue: Namespace.ID? = nil
}

extension EnvironmentValues {
    /// Set by the phone shell; nil on iPad / outside the shell, which turns the zoom off.
    var qxZoomNamespace: Namespace.ID? {
        get { self[QXZoomNamespaceKey.self] }
        set { self[QXZoomNamespaceKey.self] = newValue }
    }
}

private struct QXZoomSource: ViewModifier {
    let id: QXRoute
    let radius: CGFloat
    @Environment(\.qxZoomNamespace) private var ns
    func body(content: Content) -> some View {
        if #available(iOS 18.0, *), let ns {
            content.matchedTransitionSource(id: id, in: ns) { src in
                src.clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
            }
        } else {
            content
        }
    }
}

private struct QXZoomDestination: ViewModifier {
    let id: QXRoute
    @Environment(\.qxZoomNamespace) private var ns
    func body(content: Content) -> some View {
        if #available(iOS 18.0, *), let ns {
            content.navigationTransition(.zoom(sourceID: id, in: ns))
        } else {
            content
        }
    }
}

extension View {
    /// Marks a home element as the zoom source for `route` (pushed as `.zoom(route)`).
    func qxZoomSource(_ route: QXRoute, radius: CGFloat = QXMetrics.tileRadius) -> some View {
        modifier(QXZoomSource(id: route, radius: radius))
    }
    func qxZoomDestination(_ route: QXRoute) -> some View { modifier(QXZoomDestination(id: route)) }
}

extension QXNavigator {
    /// Push with the zoom transition when the shell supports it (phone), else a plain push.
    func pushZoom(_ r: QXRoute) {
        path.append(padLayout ? r : .zoom(r))
    }
}

/// The run mode alone (mirrors DashboardModel.mode, deduplicated).
@MainActor
final class QXModeModel: ObservableObject {
    static let shared = QXModeModel()
    @Published private(set) var mode: String

    private init() {
        mode = DashboardModel.shared.mode
        DashboardModel.shared.$mode
            .removeDuplicates()
            .receive(on: DispatchQueue.main)
            .assign(to: &$mode)
    }

    func set(_ m: String) async { await DashboardModel.shared.setMode(m) }
}
