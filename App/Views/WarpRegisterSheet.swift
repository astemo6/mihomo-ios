import SwiftUI

/// feat/nc-warp-register: one-tap Cloudflare WARP registration. Standalone sheet, NOT wired into 添加节点 yet
/// (integration later: present it from the node-add picker, e.g. `.sheet(isPresented:) { WarpRegisterSheet() }`, and
/// reload NodeManagerModel in onDismiss). Strings live in their own table, WarpRegister.xcstrings.
struct WarpRegisterSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = WarpRegisterModel()
    var onRegistered: (String) -> Void = { _ in }

    private static let termsURL = URL(string: "https://www.cloudflare.com/application/terms/")!
    private static let privacyURL = URL(string: "https://www.cloudflare.com/application/privacypolicy/")!

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("注册一个免费的 Cloudflare WARP 设备，并生成 MASQUE 节点。密钥只在本机生成，节点保存在手动节点里。", tableName: "WarpRegister")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Section {
                    TextField(String(localized: "节点名称", table: "WarpRegister"), text: $model.name)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("warp.name")
                } header: { Text("节点名称", tableName: "WarpRegister") }
                Section {
                    Toggle(isOn: $model.acceptedTerms) {
                        Text("我已阅读并同意 Cloudflare WARP 服务条款与隐私政策", tableName: "WarpRegister")
                    }
                    .accessibilityIdentifier("warp.terms")
                    Link(destination: Self.termsURL) { Text("服务条款", tableName: "WarpRegister") }
                    Link(destination: Self.privacyURL) { Text("隐私政策", tableName: "WarpRegister") }
                } footer: {
                    Text("这是 Cloudflare 客户端使用的非官方接口，Cloudflare 可能随时调整或限制。", tableName: "WarpRegister")
                }
                Section {
                    Button {
                        Task {
                            if let n = await model.register() { onRegistered(n.name) }
                        }
                    } label: {
                        HStack {
                            Text("注册并添加节点", tableName: "WarpRegister")
                            Spacer()
                            if model.phase == .working { ProgressView() }
                        }
                    }
                    .disabled(!model.canRegister)
                    .accessibilityIdentifier("warp.register")
                    switch model.phase {
                    case .done(let name):
                        Label { Text("已添加节点「\(name)」", tableName: "WarpRegister") } icon: {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        }
                    case .failed(let why):
                        Label { Text(verbatim: why) } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                    default:
                        EmptyView()
                    }
                }
            }
            .navigationTitle(Text(verbatim: "Cloudflare WARP"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button { dismiss() } label: {
                        if case .done = model.phase { Text("完成", tableName: "WarpRegister") } else { Text("取消", tableName: "WarpRegister") }
                    }
                }
            }
            .interactiveDismissDisabled(model.phase == .working)
        }
    }
}
