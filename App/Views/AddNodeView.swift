import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

/// 节点管理 → + (v0.16): the add flow of the QX preview (QXAddNode) in the main style. Paste box with format
/// detection, 剪贴板 / 扫描二维码 / 相册 / 从文件, then a protocol picker (新协议 first) that opens the
/// node editor prefilled. Everything lands in 「手动节点」.
struct AddNodeView: View {
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var model = NodeManagerModel.shared
    @State private var paste = ""
    @State private var detected: (format: String, count: Int)?
    @State private var message: String?
    @State private var isError = false
    @State private var busy = false
    @State private var target: Target?
    @State private var scanning = false
    @State private var photoItem: PhotosPickerItem?
    @State private var showPhotoPicker = false
    @State private var detectTask: Task<Void, Never>?
    @FocusState private var focused: Bool
    /// feat/home-analysis: Home's quick-add 扫描添加节点 opens this page with the scanned text (shown, not added).
    let initialText: String

    init(initialText: String = "") { self.initialText = initialText }

    struct Target: Identifiable {
        let id = UUID()
        let type: String
        let preset: [String: String]
    }

    struct Proto: Identifiable {
        var id: String { title }
        let title: String
        let subtitle: String
        let type: String
        var preset: [String: String] = [:]
    }

    /// fix/nc-0.20.2 (user): one ordered protocol list — the common ones first (「常用」), newer / niche ones after
    /// (「更多」). Only this picker uses the order; import / export are unaffected.
    static let ordered: [Proto] = [
        // 常用
        Proto(title: "Shadowsocks", subtitle: "AEAD · 2022", type: "ss"),
        Proto(title: "VMess", subtitle: "WS · gRPC · H2", type: "vmess"),
        Proto(title: "VLESS", subtitle: "Reality · XTLS-Vision", type: "vless",
              preset: ["flow": "xtls-rprx-vision", "client-fingerprint": "chrome", "tls": "true"]),
        Proto(title: "Trojan", subtitle: "TLS · WS · gRPC", type: "trojan"),
        Proto(title: "Hysteria2", subtitle: "QUIC · Brutal", type: "hysteria2"),
        Proto(title: "TUIC v5", subtitle: "QUIC · BBR", type: "tuic"),
        Proto(title: "WireGuard", subtitle: "UDP", type: "wireguard"),
        Proto(title: "HTTP(S)", subtitle: "CONNECT", type: "http"),
        Proto(title: "SOCKS5", subtitle: "TCP / UDP", type: "socks5"),
        Proto(title: "Snell", subtitle: "v4 / v5", type: "snell"),
        Proto(title: "AnyTLS", subtitle: "TLS", type: "anytls"),
        // 更多
        Proto(title: "Hysteria", subtitle: "v1", type: "hysteria"),
        Proto(title: "ShadowTLS", subtitle: "Shadowsocks + ShadowTLS v3", type: "ss",
              preset: ["plugin": "shadow-tls", "plugin-opts.version": "3", "cipher": "2022-blake3-aes-128-gcm"]),
        Proto(title: "ShadowsocksR", subtitle: "SSR", type: "ssr"),
        Proto(title: "VLESS XHTTP", subtitle: "XHTTP · Reality", type: "vless",
              preset: ["network": "xhttp", "xhttp-opts.mode": "auto", "tls": "true", "client-fingerprint": "chrome"]),
        Proto(title: "AmneziaWG", subtitle: String(localized: "WireGuard · 抗识别"), type: "wireguard", preset: ["x-awg": "true"]),
        Proto(title: "Juicity", subtitle: "QUIC · BBR", type: "juicity"),
        Proto(title: "Mieru", subtitle: "TCP / UDP", type: "mieru"),
        Proto(title: "SSH", subtitle: String(localized: "密码 / 私钥"), type: "ssh"),
        Proto(title: "Brook", subtitle: "server · ws · wss · quic", type: "brook"),
        Proto(title: "OpenVPN", subtitle: String(localized: "用户态 · PEM"), type: "openvpn"),
        Proto(title: "TrustTunnel", subtitle: "HTTP/2 · HTTP/3", type: "trusttunnel"),
        Proto(title: "MASQUE", subtitle: "HTTP/3 · WARP", type: "masque"),
        Proto(title: "Sudoku", subtitle: String(localized: "TCP · HTTP 伪装"), type: "sudoku"),
        Proto(title: "ShadowQUIC", subtitle: "QUIC · TLS 1.3", type: "shadowquic"),
        Proto(title: "GOST Relay", subtitle: "GOST v3 · TLS · WS · Mux", type: "gost-relay"),
        Proto(title: "Tailscale", subtitle: String(localized: "不支持 · 原生内核尚未接入"), type: "tailscale"),
    ]
    static let commonCount = 11
    static var common: [Proto] { Array(ordered.prefix(commonCount)) }
    static var more: [Proto] { Array(ordered.dropFirst(commonCount)) }

    var body: some View {
        List {
            Section {
                ZStack(alignment: .topLeading) {
                    TextEditor(text: $paste)
                        .scaledFont(13, design: .monospaced)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                        .frame(minHeight: 96)
                        .scrollContentBackground(.hidden)
                        .focused($focused)
                    if paste.isEmpty {
                        Text("vless:// hy2:// tuic:// anytls:// ss:// …，Base64 订阅、SIP008 / sing-box JSON、Surge / QX / Loon 节点行都可以")
                            .font(.footnote).foregroundStyle(.tertiary)
                            .padding(.top, 8).padding(.leading, 5)
                            .allowsHitTesting(false)
                    }
                }
                .onChange(of: paste) { t in detect(t) }
                HStack(spacing: 8) {
                    if let d = detected {
                        Text(verbatim: CoreText.localize(d.format))
                            .scaledFont(10, weight: .bold)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                            .background(Capsule().fill((d.count > 0 ? Theme.accent : Color.secondary).opacity(0.16)))
                            .foregroundStyle(d.count > 0 ? Theme.accent : Color.secondary)
                        (d.count > 0 ? Text("识别到 \(d.count) 个节点") : Text("未识别到节点"))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        paste = UIPasteboard.general.string ?? "" // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                        if paste.isEmpty { show(String(localized: "剪贴板为空"), error: true) }
                    } label: { Label("粘贴", systemImage: "doc.on.clipboard") }
                        .buttonStyle(.bordered)
                    Button { add() } label: {
                        if busy { ProgressView() } else { Text("添加") }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Theme.accent)
                    .disabled(busy || (detected?.count ?? 0) == 0)
                }
                .font(.subheadline.weight(.semibold))
                if let message {
                    Label(message, systemImage: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .font(.footnote).foregroundStyle(isError ? Theme.bad : Theme.good)
                }
            } header: { Text("粘贴") } footer: {
                Text("格式会自动识别：分享链接、Base64 订阅、Clash YAML、Surge / Quantumult X / Loon 节点行。")
            }
            .listRowBackground(Theme.card)

            Section {
                Button { scanning = true } label: { Label("扫描二维码", systemImage: "qrcode.viewfinder") }
                Button { showPhotoPicker = true } label: { Label("从相册识别二维码", systemImage: "photo") }
                Button { pickFile() } label: { Label("从文件", systemImage: "folder") }
            } header: { Text("其他方式") }
            .foregroundStyle(.primary)
            .listRowBackground(Theme.card)

            Section {
                ForEach(Self.common) { p in protoRow(p, new: false) }
            } header: { Text("常用") }
            .listRowBackground(Theme.card)

            Section {
                ForEach(Self.more) { p in protoRow(p, new: false) }
            } header: { Text("更多") } footer: {
                Text("协议由 Tern 内核 \(CoreVersion.label) 提供。节点保存在「本地节点」中；在 工具 → 节点与订阅 → 本地 打开「把本地节点加入每个配置」后，可在任何订阅的策略里选择。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("添加节点")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("完成") { focused = false }
            }
        }
        .sheet(item: $target, onDismiss: { Task { await model.reload() } }) { t in
            NodeEditorView(newType: t.type, preset: t.preset).environmentObject(store)
        }
        .sheet(isPresented: $scanning) {
            QRScannerSheet { code in
                scanning = false
                paste = code
            }
        }
        .photosPicker(isPresented: $showPhotoPicker, selection: $photoItem, matching: .images)
        .onAppear { if paste.isEmpty && !initialText.isEmpty { paste = initialText } }
        .onChange(of: photoItem) { item in
            guard let item else { return }
            Task {
                defer { photoItem = nil }
                guard let data = try? await item.loadTransferable(type: Data.self), let img = UIImage(data: data) else {
                    show(String(localized: "无法读取图片"), error: true); return
                }
                let codes = QRDecoder.decode(img)
                if codes.isEmpty { show(String(localized: "图片中没有识别到二维码"), error: true) } else { paste = codes.joined(separator: "\n") }
            }
        }
    }

    func protoRow(_ p: Proto, new: Bool) -> some View {
        Button { target = Target(type: p.type, preset: p.preset) } label: {
            HStack(spacing: 12) {
                Image(systemName: Self.symbol(p.type))
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.protocolColor(p.type))
                    .frame(width: 30, height: 30)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.protocolColor(p.type).opacity(0.15)))
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(verbatim: p.title).font(.subheadline.weight(.semibold))
                        if new {
                            Text(verbatim: "NEW").scaledFont(9, weight: .heavy)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                                .background(Capsule().fill(Theme.accent))
                                .foregroundStyle(Theme.onAccent)
                        }
                    }
                    Text(verbatim: p.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(verbatim: p.title))
    }

    static func symbol(_ type: String) -> String {
        switch type {
        case "vless": return "bolt.horizontal.fill"
        case "wireguard": return "lock.shield.fill"
        case "sudoku": return "square.grid.3x3.fill"
        case "masque": return "theatermasks.fill"
        case "trusttunnel": return "arrow.left.arrow.right.circle.fill"
        case "shadowquic", "hysteria", "hysteria2", "tuic", "juicity": return "hare.fill"
        case "openvpn", "ssh": return "key.fill"
        case "gost-relay": return "point.3.connected.trianglepath.dotted"
        case "socks5", "http": return "network"
        case "tailscale": return "circle.hexagongrid.fill"
        default: return "server.rack"
        }
    }

    func show(_ t: String, error: Bool) {
        withAnimation(.easeOut(duration: 0.2)) { message = t; isError = error }
    }

    /// selftest: detection ran DetectNodeFormat on the main thread on every keystroke, which parses
    /// the whole text (a pasted Base64 subscription or a file of several MB froze the editor). Now debounced
    /// and off the main thread; a newer edit cancels an older result.
    func detect(_ t: String) {
        detectTask?.cancel()
        let s = t.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { detected = nil; return }
        detectTask = Task {
            try? await Task.sleep(nanoseconds: 200_000_000)
            guard !Task.isCancelled else { return }
            let json = await Task.detached(priority: .userInitiated) { ImportTools.detectNodeFormat(s) }.value
            guard !Task.isCancelled else { return }
            if let d = json.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                detected = (o["format"] as? String ?? "", (o["count"] as? NSNumber)?.intValue ?? 0)
            } else {
                detected = ("", 0)
            }
        }
    }

    func add() {
        busy = true
        let text = paste
        Task {
            defer { busy = false }
            do {
                let n = try await store.addManualNodes(text: text)
                show(String(localized: "已添加 \(n) 个节点"), error: false)
                paste = ""
                detected = nil
                await model.reload()
            } catch {
                show(error.localizedDescription, error: true)
            }
        }
    }

    /// 从文件: the same copy-mode document picker as ImportRouter (every file selectable); the text goes
    /// into the paste box so the format and count show before adding.
    func pickFile() {
        NodeFilePicker.shared.pick { text in
            if let text, !text.isEmpty { paste = text } else { show(String(localized: "无法读取文件"), error: true) }
        }
    }
}

@MainActor
final class NodeFilePicker {
    static let shared = NodeFilePicker()
    private var delegate: ImportRouter.PickerDelegate?

    func pick(_ onText: @escaping @MainActor (String?) -> Void) {
        guard let top = ImportRouter.topViewController() else { return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: ImportRouter.pickerTypes, asCopy: true)
        picker.allowsMultipleSelection = false
        picker.shouldShowFileExtensions = true
        let d = ImportRouter.PickerDelegate { [weak self] urls in
            self?.delegate = nil
            guard let url = urls.first else { onText(nil); return }
            let data = (try? Data(contentsOf: url)).flatMap { $0.count <= 8 << 20 ? $0 : nil }
            try? FileManager.default.removeItem(at: url)
            onText(data.flatMap { String(data: $0, encoding: .utf8) ?? String(data: $0, encoding: .isoLatin1) })
        } onCancel: { [weak self] in self?.delegate = nil }
        delegate = d
        picker.delegate = d
        top.present(picker, animated: true)
    }
}
