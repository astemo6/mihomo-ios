import SwiftUI
import UIKit

/// Shows a small banner when another app put something on the clipboard while we were in the
/// background. The clipboard is only read when the user taps the system PasteButton, so iOS never
/// shows the "allow paste" prompt and nothing is read silently. Replaces a share extension (which
/// would need a third bundle ID / provisioning profile and break re-signing).
@MainActor
final class ClipboardWatcher: ObservableObject {
    static let shared = ClipboardWatcher()
    @Published var visible = false
    private var seenCount: Int = UserDefaults.standard.integer(forKey: "clipboard.seenCount")
    private var hideTask: Task<Void, Never>?

    private func remember(_ c: Int) {
        seenCount = c
        UserDefaults.standard.set(c, forKey: "clipboard.seenCount")
    }

    /// App went to the background: whatever is on the clipboard now was there (or put there by us).
    func didLeave() { remember(UIPasteboard.general.changeCount) }

    /// App became active: offer the banner only for clipboard changes made elsewhere.
    func didBecomeActive() {
        let pb = UIPasteboard.general
        guard pb.changeCount != seenCount else { return }
        remember(pb.changeCount)
        guard pb.hasStrings || pb.hasURLs else { return }
        withAnimation(.spring(response: 0.35)) { visible = true }
        hideTask?.cancel()
        hideTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 15_000_000_000)
            guard !Task.isCancelled else { return }
            withAnimation { self?.visible = false }
        }
    }

    func dismiss() {
        hideTask?.cancel()
        withAnimation { visible = false }
    }
}

struct PasteBanner: View {
    @ObservedObject var watcher = ClipboardWatcher.shared
    @EnvironmentObject var router: ImportRouter

    var body: some View {
        if watcher.visible {
            HStack(spacing: 10) {
                Image(systemName: "doc.on.clipboard").foregroundStyle(Theme.accent)
                VStack(alignment: .leading, spacing: 1) {
                    Text("剪贴板有新内容").font(.subheadline.weight(.semibold))
                    Text("配置 / 模块链接、节点或模块内容都可以直接导入").font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 4)
                PasteButton(payloadType: String.self) { strings in
                    let text = strings.joined(separator: "\n")
                    Task { @MainActor in
                        watcher.dismiss()
                        router.handle(pasted: text)
                    }
                }
                .labelStyle(.titleOnly)
                .buttonBorderShape(.capsule)
                .tint(Theme.accent)
                Button { watcher.dismiss() } label: {
                    Image(systemName: "xmark").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                }
                .accessibilityLabel(Text("关闭"))
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Theme.cardHi))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(Color.white.opacity(0.08)))
            .shadow(color: .black.opacity(0.4), radius: 12, y: 4)
            .padding(.horizontal, 12)
            .frame(maxWidth: 560)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }
}
