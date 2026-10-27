import SwiftUI

/// feat/fresh-reinstall: shown by TernApp instead of the app while DataResetCoordinator is not `.normal` — the one-time
/// reinstall question, the wipe progress, and the 「已清除」 page that exits the app.
struct DataResetGateView: View {
    @ObservedObject private var reset = DataResetCoordinator.shared
    @State private var confirmWipe = false

    var body: some View {
        VStack(spacing: 18) {
            Spacer(minLength: 24)
            switch reset.phase {
            case .reinstallPrompt: prompt
            case .wiping: wiping
            case .wiped(let problems): done(problems)
            case .normal: EmptyView()
            }
            Spacer(minLength: 24)
        }
        .padding(.horizontal, 24)
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.bg.ignoresSafeArea())
        .tint(Theme.accent)
        .modifier(EgernDensity())
    }

    private var prompt: some View {
        VStack(spacing: 18) {
            Image(systemName: "externaldrive.badge.exclamationmark")
                .font(.system(size: 44, weight: .regular))
                .foregroundStyle(Theme.accent)
            Text("检测到上次安装留下的配置")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("reinstall.title")
            Text("删除 Tern 后，iOS 保留了它的共享数据：配置、订阅、模块、规则集、证书、设置，以及钥匙串中保存的密码。要继续使用这些数据，还是全部清除，从新开始？")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 10) {
                Button { reset.keep() } label: {
                    Text("保留").frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("reinstall.keep")
                Button(role: .destructive) { confirmWipe = true } label: {
                    Text("全部清除，从新开始").frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("reinstall.wipe")
            }
            .padding(.top, 6)
        }
        .confirmationDialog("清除全部数据？", isPresented: $confirmWipe, titleVisibility: .visible) {
            Button("全部清除", role: .destructive) { Task { await reset.wipe() } }
                .accessibilityIdentifier("reinstall.confirmWipe")
            Button("取消", role: .cancel) {}
        } message: {
            Text(DataResetText.consequences)
        }
    }

    private var wiping: some View {
        VStack(spacing: 14) {
            ProgressView()
            Text("正在清除…").foregroundStyle(.secondary)
        }
    }

    private func done(_ problems: Int) -> some View {
        VStack(spacing: 18) {
            Image(systemName: problems == 0 ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.system(size: 44, weight: .regular))
                .foregroundStyle(problems == 0 ? Theme.good : Theme.warn)
            Text("已清除全部数据")
                .font(.title3.weight(.semibold))
                .accessibilityIdentifier("reset.done")
            Text("Tern 将退出。重新打开后即为刚安装时的状态。")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if problems > 0 {
                Text("有 \(problems) 项未能删除，可以稍后在「更多 → 备份与恢复」中再清除一次。")
                    .font(.footnote)
                    .foregroundStyle(Theme.warn)
                    .multilineTextAlignment(.center)
            }
            Button { reset.quit() } label: {
                Text("退出 Tern").frame(maxWidth: .infinity).padding(.vertical, 4)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("reset.quit")
            .padding(.top, 6)
        }
    }
}

enum DataResetText {
    static let consequences: LocalizedStringKey = "所有配置、订阅、模块、规则集、证书、设置、统计和保存的密码都会被删除，VPN 配置也会移除。保存在「文件」、iCloud 或 WebDAV 上的备份不受影响。此操作无法撤销。"
}

/// 更多 → 备份与恢复 → 清除全部数据: two confirmations, then the same wipe as the reinstall prompt.
struct DataResetSection: View {
    @State private var step1 = false
    @State private var step2 = false

    var body: some View {
        Section {
            Button(role: .destructive) { step1 = true } label: {
                Label("清除全部数据", systemImage: "trash")
            }
            .accessibilityIdentifier("backup.resetAll")
        } footer: {
            Text("删除 Tern 的全部数据并移除 VPN 配置，恢复到刚安装时的状态。保存在「文件」、iCloud 或 WebDAV 上的备份不受影响。")
        }
        .listRowBackground(Theme.card)
        .confirmationDialog("清除全部数据？", isPresented: $step1, titleVisibility: .visible) {
            Button("继续", role: .destructive) {
                // The second question opens once the first dialog has gone.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { step2 = true }
            }
            .accessibilityIdentifier("backup.resetAll.continue")
            Button("取消", role: .cancel) {}
        } message: {
            Text(DataResetText.consequences)
        }
        .alert("确定清除全部数据？", isPresented: $step2) {
            Button("全部清除", role: .destructive) { Task { await DataResetCoordinator.shared.wipe() } }
                .accessibilityIdentifier("backup.resetAll.confirm")
            Button("取消", role: .cancel) {}
        } message: {
            Text("此操作无法撤销。需要保留数据时，请先导出完整备份。")
        }
    }
}
