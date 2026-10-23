import SwiftUI

/// v0.15.4: the settings pages under 更多 apply a change as soon as it is made (no 保存 button).
/// Toggles / pickers / steppers and text fields all go through one Debouncer per page (0.5 s), so a burst of
/// changes or typing is written once; leaving the page flushes what is still pending. Full editors (raw
/// YAML, node / rule / rewrite / script editors) keep their explicit 保存 / 完成.
@MainActor
final class Debouncer: ObservableObject {
    private var task: Task<Void, Never>?
    private var pending: (() -> Void)?

    func schedule(_ delay: Double = 0.5, _ action: @escaping () -> Void) {
        task?.cancel()
        pending = action
        task = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.flush()
        }
    }

    /// Runs the pending action now (page disappears, text field submitted).
    func flush() {
        task?.cancel()
        task = nil
        let p = pending
        pending = nil
        p?()
    }
}

/// Coalesces core reloads: every request made within the window (several pages, rapid toggles) shares one
/// `vpn.reload()` and gets its result.
/// v0.19.22: the settings pages that auto-apply (内核设置, 连接方式, DNS, 局域网, 覆写脚本, node edits …) ask for a hot
/// reload by default — the core decides from the diff whether the change can be applied in place, so a change it cannot
/// (DNS, IPv6, proxies) still gets the full reload. A window with any `hot: false` request reloads fully.
@MainActor
final class ReloadCoalescer {
    static let shared = ReloadCoalescer()
    private var waiters: [CheckedContinuation<String?, Never>] = []
    private var timer: Task<Void, Never>?
    private var hot = true

    func reload(_ vpn: VPNManager, after delay: Double = 0.4, hot: Bool = true) async -> String? {
        guard vpn.isConnected else { return nil }
        return await withCheckedContinuation { (c: CheckedContinuation<String?, Never>) in
            self.hot = waiters.isEmpty ? hot : (self.hot && hot)
            waiters.append(c)
            timer?.cancel()
            timer = Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                guard let self, !Task.isCancelled else { return }
                let w = self.waiters
                let h = self.hot
                self.waiters = []
                self.timer = nil
                self.hot = true
                let r = await vpn.reload(hot: h)
                for c in w { c.resume(returning: r) }
            }
        }
    }
}

/// Status line at the bottom of an auto-applied page ("已保存" / "已保存并重载" / errors).
struct AutoApplyFooter: View {
    let status: String?
    var body: some View {
        if let status {
            Text(verbatim: status)
                .font(.footnote).foregroundStyle(.secondary)
                .accessibilityIdentifier("autoapply.status")
        }
    }
}
