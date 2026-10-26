import SwiftUI

/// v0.18 示例配置 (Quantumult X style sample): a heavily commented Clash.Meta profile bundled with the app
/// (App/Resources/sample-profile.yaml), shown read-only with highlighting; copy it, or create a new local
/// profile from it. The bridge test TestV018SampleProfileValidates keeps it valid.
enum SampleProfile {
    static var text: String {
        guard let url = Bundle.main.url(forResource: "sample-profile", withExtension: "yaml"),
              let s = try? String(contentsOf: url, encoding: .utf8) else { return "" }
        return s
    }
}

struct SampleProfileView: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var text = SampleProfile.text
    @State private var copied = false
    @State private var busy = false
    @State private var message: String?
    @State private var isError = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "text.book.closed").foregroundStyle(Theme.accent)
                Text("每一段都有注释；服务器和密钥都是占位符，需要换成你自己的。")
                    .font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(Theme.card)
            CodeEditor(text: $text, language: .yaml, editable: false)
                .accessibilityIdentifier("sample.editor")
            if let message {
                Label(message, systemImage: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.footnote).foregroundStyle(isError ? Theme.bad : Theme.good)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.vertical, 8)
                    .background(Theme.card)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("sample.message")
            }
            HStack(spacing: 12) {
                Button {
                    UIPasteboard.general.string = text
                    copied = true
                } label: {
                    Label(copied ? "已复制" : "复制", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("sample.copy")
                Button { Task { await create() } } label: {
                    HStack {
                        if busy { ProgressView() }
                        Text("以此新建配置").bold()
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .disabled(busy || text.isEmpty)
                .accessibilityIdentifier("sample.create")
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(Theme.card)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("示例配置")
        .navigationBarTitleDisplayMode(.inline)
    }

    func create() async {
        busy = true
        defer { busy = false }
        do {
            let p = try await store.addLocal(name: String(localized: "示例配置"), text: text)
            isError = false
            message = String(localized: "已新建配置「\(p.name)」，可在 配置 页切换和编辑。")
        } catch {
            isError = true
            message = error.localizedDescription
        }
    }
}
