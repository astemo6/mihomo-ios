import SwiftUI
import CoreImage
import CoreImage.CIFilterBuiltins
import Libmihomo

// MARK: - 前置代理 picker

struct ChainCandidate: Decodable, Hashable {
    var name: String
    var type: String
    var group: Bool
}

private struct ChainCandidatesResponse: Decodable {
    var current: String
    var candidates: [ChainCandidate]
}

/// Picks the policy a node or group dials through (mihomo dialer-proxy). Candidates come from Go and
/// already exclude everything that would form a loop.
struct ChainPickerView: View {
    @Environment(\.dismiss) var dismiss
    let kind: String // "node" / "group"
    let name: String
    let profilePath: String
    let selected: String?
    let onPick: (String?) -> Void
    @State private var items: [ChainCandidate] = []
    @State private var loading = true
    @State private var search = ""

    var shown: [ChainCandidate] {
        search.isEmpty ? items : items.filter { $0.name.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        List {
            Section {
                row(nil, title: String(localized: "不使用前置代理"), subtitle: String(localized: "直接连接节点服务器"))
            } footer: {
                Text(kind == "group"
                     ? "策略组的前置代理会加到组内每个节点（以及组引用的节点集）上：连接这些节点时先经过所选的节点或策略组。会形成循环的成员自动跳过。"
                     : "连接这个节点时先经过所选的节点或策略组（mihomo dialer-proxy，相当于 Surge 的 underlying-proxy）。会形成循环的选项不会列出。")
            }
            .listRowBackground(Theme.card)
            if loading {
                LoadingRow(text: "读取配置…").listRowBackground(Theme.card)
            } else {
                let groups = shown.filter(\.group)
                let nodes = shown.filter { !$0.group }
                if !groups.isEmpty {
                    Section("策略组 \(groups.count)") {
                        ForEach(groups, id: \.self) { c in row(c.name, title: c.name, subtitle: c.type) }
                    }
                    .listRowBackground(Theme.card)
                }
                if !nodes.isEmpty {
                    Section("节点 \(nodes.count)") {
                        ForEach(nodes, id: \.self) { c in row(c.name, title: c.name, subtitle: ProxyItem.label(for: c.type)) }
                    }
                    .listRowBackground(Theme.card)
                }
                if items.isEmpty {
                    EmptyStateRow(icon: "link", title: "没有可用的前置代理", message: "配置里没有其他节点或策略组。").listRowBackground(Theme.card)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("前置代理")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always))
        .task { await load() }
    }

    func row(_ value: String?, title: String, subtitle: String) -> some View {
        Button {
            onPick(value)
            dismiss()
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(.primary).lineLimit(1)
                    Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                if selected == value { Image(systemName: "checkmark").foregroundStyle(Theme.accent) }
            }
        }
    }

    func load() async {
        let home = AppShared.homeURL.path, path = profilePath, k = kind, n = name
        let json = await Task.detached { LibmihomoChainCandidates(home, path, k, n) }.value
        if let d = json.data(using: .utf8), let r = try? JSONDecoder().decode(ChainCandidatesResponse.self, from: d) {
            items = r.candidates
        }
        loading = false
    }
}

/// Group 前置代理 as a sheet (策略 page).
struct GroupChainSheet: View {
    @Environment(\.dismiss) var dismiss
    let group: String
    @ObservedObject var smart = SmartGroups.shared
    @State private var error: String?

    var body: some View {
        NavigationStack {
            if let path = AppShared.activeProfileURL?.path {
                ChainPickerView(kind: "group", name: group, profilePath: path, selected: smart.via(group)) { via in
                    Task { if let e = await smart.setVia(group, via) { error = e } }
                }
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } } }
            } else {
                EmptyStateView(title: "没有当前配置")
            }
        }
        .alert("前置代理", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(error ?? "") }
    }
}

// MARK: - Node sharing

enum QRCode {
    static func image(_ text: String, scale: CGFloat = 10) -> UIImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: scale, y: scale)),
              let cg = CIContext().createCGImage(out, from: out.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

struct ShareWarning: View {
    var body: some View {
        Label("链接里包含服务器地址和密码，任何拿到它的人都能使用这个节点。只分享给你信任的人。", systemImage: "exclamationmark.shield")
            .font(.caption).foregroundStyle(Theme.warn)
    }
}

/// Share link + QR code for one node.
struct NodeShareSheet: View {
    @Environment(\.dismiss) var dismiss
    let name: String
    let link: String
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if link.count <= 2000, let img = QRCode.image(link) {
                        Image(uiImage: img)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 260)
                            .padding(14)
                            .background(RoundedRectangle(cornerRadius: 16).fill(Color.white))
                    } else {
                        Text("链接太长，无法生成二维码").font(.caption).foregroundStyle(.secondary)
                    }
                    Text(link)
                        .scaledFont(11, design: .monospaced)
                        .textSelection(.enabled)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 12).fill(Theme.card))
                    HStack(spacing: 12) {
                        Button { UIPasteboard.general.string = link; copied = true } label: {
                            Label(copied ? "已复制" : "复制链接", systemImage: copied ? "checkmark" : "doc.on.doc").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        ShareLink(item: link) { Label("分享", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity) }
                            .buttonStyle(.bordered)
                    }
                    ShareWarning().frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(16)
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } } }
        }
    }
}

struct ShareTarget: Identifiable {
    let id = UUID()
    let name: String
    let link: String
}

enum NodeShare {
    /// Link for a node dictionary (manual nodes); error text on failure.
    static func link(node: [String: Any]) -> Result<String, ShareError> {
        guard let d = try? JSONSerialization.data(withJSONObject: node), let json = String(data: d, encoding: .utf8) else {
            return .failure(ShareError(message: String(localized: "节点数据无效")))
        }
        let s = LibmihomoNodeShareLink(json)
        return s.isEmpty ? .failure(ShareError(message: LibmihomoLastError())) : .success(s)
    }

    /// Link for a node of the active profile, by name (策略 page).
    static func link(named name: String) async -> Result<String, ShareError> {
        guard let path = AppShared.activeProfileURL?.path else { return .failure(ShareError(message: String(localized: "没有当前配置"))) }
        let home = AppShared.homeURL.path
        let r = await Task.detached { (LibmihomoNodeShareLinkByName(home, path, name), LibmihomoLastError()) }.value
        return r.0.isEmpty ? .failure(ShareError(message: r.1)) : .success(r.0)
    }

    struct ShareError: Error { let message: String }
}

/// Manual-node list as a base64 subscription text (v2rayN style).
struct SubscriptionExportSheet: View {
    @Environment(\.dismiss) var dismiss
    @State private var text = ""
    @State private var count = 0
    @State private var skipped: [String] = []
    @State private var copied = false
    @State private var fileURL: URL?

    private struct Out: Decodable { var text: String; var count: Int; var skipped: [String] }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(text.isEmpty ? String(localized: "没有可导出的节点") : String(text.prefix(1200)) + (text.count > 1200 ? "…" : ""))
                        .scaledFont(10, design: .monospaced)
                        .textSelection(.enabled)
                } header: { Text("订阅内容（Base64，\(count) 个节点）") } footer: {
                    Text("这是通用的 Base64 订阅格式（每行一个分享链接），Shadowrocket、v2rayN、mihomo 等都能导入。把它放到任意可访问的地址，即可作为订阅链接使用。")
                }
                .listRowBackground(Theme.card)
                Section {
                    Button { UIPasteboard.general.string = text; copied = true } label: {
                        Label(copied ? "已复制" : "复制订阅内容", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(text.isEmpty)
                    if let fileURL {
                        ShareLink(item: fileURL) { Label("分享为文件", systemImage: "square.and.arrow.up") }
                    }
                    ShareWarning()
                }
                .listRowBackground(Theme.card)
                if !skipped.isEmpty {
                    Section("未导出 \(skipped.count)") {
                        ForEach(skipped, id: \.self) { Text($0).font(.caption) }
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("导出为订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } } }
            .task { await load() }
        }
    }

    func load() async {
        let path = AppShared.profileURL(id: ProfileStore.manualID).path
        let json = await Task.detached { LibmihomoManualSubscription(path) }.value
        guard let d = json.data(using: .utf8), let o = try? JSONDecoder().decode(Out.self, from: d) else { return }
        text = o.text; count = o.count; skipped = o.skipped
        if !text.isEmpty {
            let u = FileManager.default.temporaryDirectory.appendingPathComponent("manual-nodes-subscription.txt")
            try? text.write(to: u, atomically: true, encoding: .utf8)
            fileURL = u
        }
    }
}
