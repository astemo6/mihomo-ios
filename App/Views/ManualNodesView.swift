import SwiftUI
import PhotosUI
import AVFoundation
import CoreImage

/// Shadowrocket-style node list: paste link, scan QR (camera / photo), or fill a per-protocol form.
struct ManualNodesView: View {
    @EnvironmentObject var store: ProfileStore
    @State private var nodes: [[String: Any]] = []
    @State private var reloadGen = 0
    @State private var editing: EditTarget?
    @State private var showScanner = false
    @State private var photoItem: PhotosPickerItem?
    @State private var showPhotoPicker = false
    @State private var message: String?
    @State private var pasteText = ""
    /// v0.19.3: text from the scanner / paste sheet, imported in the sheet's onDismiss. Setting `message`
    /// while the sheet was still animating away could drop the result alert (UIKit refuses a second
    /// presentation) and leave the binding stuck on, so later alerts never appeared either.
    @State private var pendingImport: String?
    /// Review 5: deleting a manual node asks first, as in 节点管理.
    @State private var pendingDelete: String?
    @State private var showPasteSheet = false
    @State private var share: ShareTarget?
    @State private var exportSub = false

    struct EditTarget: Identifiable {
        let id = UUID()
        let node: [String: Any]?
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 10) {
                    actionButton("粘贴", "doc.on.clipboard") { importText(UIPasteboard.general.string ?? "") } // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                    actionButton("扫码", "qrcode.viewfinder") { showScanner = true }
                    actionButton("相册", "photo") { showPhotoPicker = true }
                    actionButton("手动", "square.and.pencil") { editing = EditTarget(node: nil) }
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            } footer: {
                Text("支持 ss / ssr / vmess / vless / trojan / hysteria / hysteria2 (hy2) / tuic / wireguard (wg) / snell / anytls / mieru / socks5 / http(s) 分享链接、base64 订阅，以及 Surge / Egern / Quantumult X 的节点行。")
            }
            Section("手动节点 \(nodes.count)") {
                if nodes.isEmpty {
                    EmptyStateRow(icon: "plus.viewfinder", title: "还没有节点", message: "粘贴分享链接、扫描二维码或手动填写。")
                }
                ForEach(Array(nodes.enumerated()), id: \.offset) { _, n in
                    let name = n["name"] as? String ?? "?"
                    HStack(spacing: 10) {
                        ProtocolBadge(type: n["type"] as? String ?? "?")
                        VStack(alignment: .leading, spacing: 2) {
                            Text(name).font(.subheadline.weight(.semibold)).lineLimit(1)
                            Text("\(n["server"] as? String ?? ""):\((n["port"] as? NSNumber)?.stringValue ?? "")")
                                .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editing = EditTarget(node: n) }
                    .swipeActions {
                        Button(role: .destructive) { pendingDelete = name } label: { Label("删除", systemImage: "trash") }
                        Button { shareNode(n) } label: { Label("分享", systemImage: "qrcode") }.tint(Theme.accent)
                    }
                    .contextMenu {
                        Button { editing = EditTarget(node: n) } label: { Label("编辑", systemImage: "pencil") }
                        Button { shareNode(n) } label: { Label("分享链接与二维码", systemImage: "qrcode") }
                        Button(role: .destructive) { pendingDelete = name } label: { Label("删除", systemImage: "trash") }
                    }
                }
            }
            .listRowBackground(Theme.card)
            if let p = store.manualProfile, store.activeID != p.id, !nodes.isEmpty {
                Section {
                    Button("将「手动节点」设为当前配置") { Task { _ = await store.setActive(p) } }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("手动节点")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button { showPasteSheet = true } label: { Label("粘贴节点", systemImage: "text.badge.plus") }
                    Button { exportSub = true } label: { Label("导出为订阅文本", systemImage: "square.and.arrow.up") }
                        .disabled(nodes.isEmpty)
                } label: { Image(systemName: "ellipsis.circle") }
            }
        }
        .onAppear(perform: reload)
        .sheet(item: $share) { t in NodeShareSheet(name: t.name, link: t.link) }
        .sheet(isPresented: $exportSub) { SubscriptionExportSheet() }
        .sheet(item: $editing, onDismiss: reload) { t in NodeEditorView(node: t.node) }
        .sheet(isPresented: $showScanner, onDismiss: runPendingImport) {
            QRScannerSheet { code in
                pendingImport = code
                showScanner = false
            }
        }
        .photosPicker(isPresented: $showPhotoPicker, selection: $photoItem, matching: .images)
        .onChange(of: photoItem) { item in
            guard let item else { return }
            Task {
                defer { photoItem = nil }
                guard let data = try? await item.loadTransferable(type: Data.self), let img = UIImage(data: data) else {
                    message = String(localized: "无法读取图片"); return
                }
                let codes = QRDecoder.decode(img)
                if codes.isEmpty { message = String(localized: "图片中没有识别到二维码") } else { importText(codes.joined(separator: "\n")) }
            }
        }
        .sheet(isPresented: $showPasteSheet, onDismiss: runPendingImport) {
            NavigationStack {
                TextEditor(text: $pasteText)
                    .scaledFont(13, design: .monospaced)
                    .autocorrectionDisabled().textInputAutocapitalization(.never)
                    .padding(8)
                    .navigationTitle("粘贴节点")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { Button("取消") { showPasteSheet = false } }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("导入") { pendingImport = pasteText; pasteText = ""; showPasteSheet = false }
                        }
                    }
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .deleteConfirmation({ _ in Text("删除这个手动节点？") }, item: $pendingDelete, message: { n in Text(verbatim: n) }) { n in
            Task { await store.deleteManualNode(n); reload() }
        }
    }

    func actionButton(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: icon).font(.title3)
                Text(LocalizedStringKey(title)).font(.caption)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Theme.card))
        }
        .buttonStyle(.plain)
    }

    /// v0.19.6: read off the main actor; only the newest of overlapping reloads publishes.
    func reload() {
        let path = store.manualProfile?.fileURL.path
        reloadGen += 1
        let gen = reloadGen
        Task {
            let list = await Task.detached(priority: .userInitiated) { ProfileStore.manualNodes(path: path) }.value
            if gen == reloadGen { nodes = list }
        }
    }

    func shareNode(_ n: [String: Any]) {
        switch NodeShare.link(node: n) {
        case .success(let l): share = ShareTarget(name: n["name"] as? String ?? "", link: l)
        case .failure(let e): message = e.message
        }
    }

    func runPendingImport() {
        guard let t = pendingImport else { return }
        pendingImport = nil
        importText(t)
    }

    func importText(_ text: String) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { message = String(localized: "内容为空"); return }
        Task {
            do {
                let n = try await store.addManualNodes(text: t)
                message = String(localized: "已添加 \(n) 个节点")
                reload()
            } catch { message = error.localizedDescription }
        }
    }
}

enum QRDecoder {
    static func decode(_ image: UIImage) -> [String] {
        guard let ci = CIImage(image: image) ?? image.cgImage.map({ CIImage(cgImage: $0) }) else { return [] }
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return (detector?.features(in: ci) ?? []).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}

struct QRScannerSheet: View {
    var onCode: (String) -> Void
    @Environment(\.dismiss) var dismiss
    @State private var denied = false

    var body: some View {
        NavigationStack {
            ZStack {
                if denied {
                    VStack(spacing: 12) {
                        Image(systemName: "camera.fill").font(.largeTitle)
                        Text("没有相机权限，请在 设置 → Mihomo 中允许访问相机。").multilineTextAlignment(.center)
                    }.padding()
                } else {
                    QRScannerView(onCode: onCode).ignoresSafeArea()
                    RoundedRectangle(cornerRadius: 20).stroke(Theme.accent, lineWidth: 3).frame(width: 240, height: 240)
                }
            }
            .navigationTitle("扫描二维码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } } }
            .task {
                switch AVCaptureDevice.authorizationStatus(for: .video) {
                case .authorized: break
                case .notDetermined: denied = !(await AVCaptureDevice.requestAccess(for: .video))
                default: denied = true
                }
            }
        }
    }
}

struct QRScannerView: UIViewControllerRepresentable {
    var onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_ uiViewController: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onCode: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var preview: AVCaptureVideoPreviewLayer?
        private var done = false

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            guard let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: session)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            preview = layer
            DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            preview?.frame = view.bounds
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            if session.isRunning { session.stopRunning() }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !done, let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject, let s = obj.stringValue else { return }
            done = true
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            session.stopRunning()
            onCode?(s)
        }
    }
}
