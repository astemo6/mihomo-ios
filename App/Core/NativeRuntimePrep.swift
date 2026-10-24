import Foundation
import Libmihomo

/// feat/native-core-eval: the tunnel kernel is NativeCore and the extension has no Go, so the runtime config the
/// tunnel reads (runtime.yaml + nativecore-runtime.json, the rewrite / MitM snapshot, GEOSITE lists) is built here
/// in the app — by the same Go code that used to build it inside the tunnel (bridge/nativeprep.go) — before every
/// start and reload. Starts that do not go through the app (widget, Shortcuts, 按需连接) use the last prepared files.
enum NativeRuntimePrep {
    /// nil = prepared; else the error text (the start / reload stops with it).
    static func prepare() async -> String? {
        guard AppShared.containerOK else { return nil } // the start reports the App Group problem itself
        guard let profile = AppShared.activeProfileURL else { return nil }
        let home = AppShared.homeURL.path
        return await Task.detached(priority: .userInitiated) { () -> String? in
            var err: NSError?
            let summary = LibmihomoPrepareNativeRuntime(home, profile.path, &err)
            if let err {
                NSLog("[Mihomo] native runtime prepare failed: %@", err.localizedDescription)
                return String(localized: "生成运行配置失败：") + err.localizedDescription
            }
            NSLog("[Mihomo] native runtime prepared: %@", summary)
            return nil
        }.value
    }
}
