import Foundation

/// The kernel version shown in 关于 / 诊断 / 添加节点. The app no longer links the Go core (LibmihomoVersion),
/// so the kernel is NativeCore at the app's own version — a fixed string, no `#if canImport(Libmihomo)` branch.
enum CoreVersion {
    static let label: String = {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        return "NativeCore " + v
    }()
}
