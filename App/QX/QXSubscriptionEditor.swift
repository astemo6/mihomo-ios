import SwiftUI
import Libmihomo

/// QX「资源 - 节点」for a new subscription, in QX's underline form style. Instead of a resource-parser
/// field it shows the format the native parsers detected and the node count (no parser needed).
struct QXSubscriptionEditor: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var ua = "clash.meta"
    @State private var hours = 24
    @State private var detecting = false
    @State private var detected: (format: String, count: Int)?
    @State private var detectError: String?
    @State private var saving = false
    @State private var error: String?
    @State private var detectTask: Task<Void, Never>?

    static let intervals = [6, 12, 24, 48, 72, 168]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                QXLargeTitle(title: String(localized: "资源 - 节点"),
                             caption: String(localized: "资源内容包含若干节点信息，作为远程资源来引用。"))
                field(String(localized: "资源标签"), placeholder: String(localized: "留空则使用订阅提供的名称"), text: $name)
                VStack(alignment: .leading, spacing: 8) {
                    Text("自动更新").font(.system(size: 20, weight: .bold))
                    Menu {
                        ForEach(Self.intervals, id: \.self) { h in
                            Button { hours = h } label: { Text(verbatim: Self.label(h)) }
                        }
                    } label: {
                        Text(verbatim: Self.label(hours)).foregroundStyle(.primary)
                    }
                    Divider()
                }
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 2) {
                        Text("资源路径").font(.system(size: 20, weight: .bold))
                        Text(verbatim: "*").font(.system(size: 20, weight: .bold)).foregroundStyle(QXColor.red)
                        Spacer()
                        QXPill(title: String(localized: "粘贴")) { url = UIPasteboard.general.string ?? url }
                    }
                    TextField("https://", text: $url, axis: .vertical)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .lineLimit(1...4)
                        .onChange(of: url) { _ in scheduleDetect() }
                    Divider()
                }
                field("User-Agent", placeholder: "clash.meta", text: $ua)
                    .onChange(of: ua) { _ in scheduleDetect() }

                VStack(alignment: .leading, spacing: 10) {
                    Text("格式识别").font(.system(size: 22, weight: .bold))
                    HStack(spacing: 8) {
                        if detecting {
                            ProgressView().controlSize(.small)
                            Text("正在识别…").font(.subheadline).foregroundStyle(.secondary)
                        } else if let d = detected {
                            QXChip(text: d.format, color: d.count > 0 ? QXColor.nodes : Color.secondary)
                            Text(d.count > 0 ? String(localized: "识别到 \(d.count) 个节点") : String(localized: "未识别到节点")).font(.subheadline)
                        } else if let detectError {
                            Text(verbatim: detectError).font(.subheadline).foregroundStyle(QXColor.danger)
                        } else {
                            Text("填写资源路径后自动识别").font(.subheadline).foregroundStyle(.secondary)
                        }
                    }
                    Text("无需资源解析器：Clash / mihomo YAML、Base64 或明文分享链接（含 VLESS Reality、Hysteria2、TUIC、AnyTLS、WireGuard 等）、SIP008 JSON、sing-box JSON、Surge / Quantumult X / Loon / Shadowrocket 节点行都由内置解析器直接转换。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if let error { ErrorRow(message: error) }
            }
            .padding(.horizontal, 24)
            .padding(.top, 70)
            .padding(.bottom, 40)
        }
        .background(QXPalette.bg.ignoresSafeArea())
        .overlay(alignment: .top) {
            HStack {
                QXCircleButton(systemName: "xmark") { dismiss() }.accessibilityLabel(Text("取消"))
                Spacer()
                Text("资源 - 节点").font(.headline)
                Spacer()
                if saving {
                    ProgressView().frame(width: 44, height: 44)
                } else {
                    QXCircleButton(systemName: "checkmark", tint: canSave ? QXColor.switchOn : .secondary) { save() }
                        .disabled(!canSave)
                        .accessibilityLabel(Text("保存"))
                }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 8)
            .background(LinearGradient(colors: [QXPalette.bg, QXPalette.bg.opacity(0)], startPoint: .top, endPoint: .bottom))
        }
    }

    var canSave: Bool { URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines))?.scheme?.hasPrefix("http") == true }

    static func label(_ h: Int) -> String {
        h % 24 == 0 ? String(localized: "\(h / 24) 天") : String(localized: "\(h) 小时")
    }

    private func field(_ title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: title).font(.system(size: 20, weight: .bold))
            TextField(placeholder, text: text).textInputAutocapitalization(.never).autocorrectionDisabled()
            Divider()
        }
    }

    private func scheduleDetect() {
        detectTask?.cancel()
        detected = nil
        detectError = nil
        guard canSave else { return }
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let agent = ua.isEmpty ? "clash.meta" : ua
        detectTask = Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            if Task.isCancelled { return }
            detecting = true
            defer { detecting = false }
            guard let target = URL(string: u) else { return }
            var req = URLRequest(url: target, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
            req.setValue(agent, forHTTPHeaderField: "User-Agent")
            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                if Task.isCancelled { return }
                if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) {
                    detectError = String(localized: "下载失败：HTTP \(h.statusCode)")
                    return
                }
                let text = String(data: data, encoding: .utf8) ?? ""
                let json = await Task.detached { LibmihomoDetectNodeFormat(text) }.value
                if let d = json.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                    detected = (o["format"] as? String ?? "", (o["count"] as? NSNumber)?.intValue ?? 0)
                }
                if name.isEmpty, let h = resp as? HTTPURLResponse, let t = ProfileStore.nameFromHeaders(h) { name = t }
            } catch {
                if !Task.isCancelled { detectError = error.localizedDescription }
            }
        }
    }

    private func save() {
        saving = true
        error = nil
        Task {
            defer { saving = false }
            do {
                _ = try await store.addRemote(url: url, name: name, userAgent: ua, intervalHours: hours)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
