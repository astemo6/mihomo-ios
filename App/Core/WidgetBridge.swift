import Foundation
import WidgetKit

/// Keeps the widget / Control Center toggle current. Harmless in the IPA without the widget extension.
enum WidgetBridge {
    static func reload() {
        WidgetCenter.shared.reloadAllTimelines()
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadAllControls()
        }
    }
}

extension WidgetSnapshot {
    /// Called from the dashboard poll while connected.
    @MainActor
    static func update(node: String, policy: String?) {
        var s = WidgetSnapshot.load()
        s.node = node
        s.policy = policy ?? ""
        s.profile = ProfileStore.shared.active?.name ?? ""
        if let i = ProfileStore.shared.active?.userInfo, i.total > 0 {
            s.remaining = String(localized: "剩余 \(Fmt.bytes(max(i.total - i.used, 0)))")
        } else {
            s.remaining = nil
        }
        s.updated = Date()
        if s.save() { WidgetBridge.reload() }
    }
}
