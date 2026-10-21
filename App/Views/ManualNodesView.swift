import SwiftUI
import PhotosUI
import AVFoundation
import CoreImage

/// The node a NodeEditorView sheet opens (nil = new manual node).
/// feat/more-dedup: the old 手动节点 page (reachable from 配置 and node details) is gone; local nodes are managed
/// only on 节点与订阅 → 本地节点, which also carries its 导出为订阅文本. Adding goes through 添加节点
/// (paste, QR camera / photo, file, per-protocol form).
struct NodeEditTarget: Identifiable {
    let id = UUID()
    let node: [String: Any]?
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
                        Text("没有相机权限，请在 设置 → Tern 中允许访问相机。").multilineTextAlignment(.center)
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
