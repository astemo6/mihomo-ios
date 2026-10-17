import SwiftUI
import Libmihomo

/// QX 添加 → 节点, with the protocol range of the mihomo core up front (QX is slow to add protocols;
/// here every protocol the core supports is one tap away, and the core follows upstream daily).
struct QXAddNodeView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @State private var target: Target?
    @State private var paste = ""
    @State private var detected: (format: String, count: Int)?
    @State private var message: String?
    @State private var busy = false

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
        var badge: String? = nil
    }

    static let protocols: [Proto] = [
        Proto(title: "VLESS", subtitle: "Reality · XTLS-Vision", type: "vless",
              preset: ["flow": "xtls-rprx-vision", "client-fingerprint": "chrome", "tls": "true"], badge: "NEW"),
        Proto(title: "Hysteria2", subtitle: "QUIC · Brutal", type: "hysteria2", badge: "NEW"),
        Proto(title: "TUIC v5", subtitle: "QUIC · BBR", type: "tuic", badge: "NEW"),
        Proto(title: "AnyTLS", subtitle: "TLS", type: "anytls", badge: "NEW"),
        Proto(title: "ShadowTLS", subtitle: "Shadowsocks + ShadowTLS v3", type: "ss",
              preset: ["plugin": "shadow-tls", "plugin-opts.version": "3", "cipher": "2022-blake3-aes-128-gcm"]),
        Proto(title: "WireGuard", subtitle: "UDP", type: "wireguard"),
        Proto(title: "Mieru", subtitle: "TCP / UDP", type: "mieru"),
        Proto(title: "Snell", subtitle: "v4 / v5", type: "snell"),
        Proto(title: "SSH", subtitle: "密码 / 私钥", type: "ssh"),
        Proto(title: "Shadowsocks", subtitle: "AEAD · 2022", type: "ss"),
        Proto(title: "ShadowsocksR", subtitle: "SSR", type: "ssr"),
        Proto(title: "VMess", subtitle: "WS · gRPC · H2", type: "vmess"),
        Proto(title: "Trojan", subtitle: "TLS · WS · gRPC", type: "trojan"),
        Proto(title: "Hysteria", subtitle: "v1", type: "hysteria"),
        Proto(title: "SOCKS5", subtitle: "TCP / UDP", type: "socks5"),
        Proto(title: "HTTP(S)", subtitle: "CONNECT", type: "http"),
    ]

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "qrcode.viewfinder") { nav.push(.dest(.manualNodes)) }
                    .accessibilityLabel(Text("扫码"))
                QXBarIcon(systemName: "list.bullet") { nav.push(.dest(.manualNodes)) }
                    .accessibilityLabel(Text("手动节点"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    QXLargeTitle(title: String(localized: "节点"),
                                 caption: String(localized: "选择协议填写，或粘贴分享链接 / 订阅内容。协议由 mihomo 内核 \(LibmihomoVersion()) 提供，内核每天自动跟进上游，新协议不用等 App 更新。"))

                    VStack(alignment: .leading, spacing: 10) {
                        Text("粘贴").font(.system(size: 20, weight: .bold))
                        TextEditor(text: $paste)
                            .font(.system(size: 14, design: .monospaced))
                            .frame(minHeight: 90)
                            .scrollContentBackground(.hidden)
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(QXPalette.card))
                            .overlay(alignment: .topLeading) {
                                if paste.isEmpty {
                                    Text("vless:// hy2:// tuic:// anytls:// ss:// …，Base64 订阅、SIP008 / sing-box JSON、Surge / QX / Loon 节点行都可以")
                                        .font(.footnote).foregroundStyle(.tertiary).padding(14).allowsHitTesting(false)
                                }
                            }
                            .onChange(of: paste) { t in detect(t) }
                        HStack(spacing: 8) {
                            if let d = detected {
                                QXChip(text: d.format, color: d.count > 0 ? QXColor.nodes : Color.secondary)
                                Text(d.count > 0 ? String(localized: "识别到 \(d.count) 个节点") : String(localized: "未识别到节点"))
                                    .font(.footnote).foregroundStyle(.secondary)
                            }
                            Spacer()
                            QXPill(title: String(localized: "剪贴板")) { paste = UIPasteboard.general.string ?? "" }
                            QXPill(title: busy ? String(localized: "添加中…") : String(localized: "添加")) { add() }
                                .disabled(busy || (detected?.count ?? 0) == 0)
                        }
                        if let message { Text(verbatim: message).font(.footnote).foregroundStyle(.secondary) }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text("协议").font(.system(size: 20, weight: .bold))
                        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                            ForEach(Self.protocols) { p in
                                Button { target = Target(type: p.type, preset: p.preset) } label: {
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack(spacing: 6) {
                                            Text(verbatim: p.title).font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary)
                                            if let b = p.badge { QXChip(text: b, color: QXColor.nodes) }
                                            Spacer(minLength: 0)
                                        }
                                        Text(verbatim: p.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                    }
                                    .padding(14)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(QXPalette.card))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    Text("节点保存在「手动节点」中；在「其他设置 → 内核设置」打开「把手动节点加入每个配置」后，可在任何订阅的策略里选择。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
        .sheet(item: $target) { t in NodeEditorView(newType: t.type, preset: t.preset) }
    }

    private func detect(_ t: String) {
        let s = t.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { detected = nil; return }
        let json = LibmihomoDetectNodeFormat(s)
        if let d = json.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
            detected = (o["format"] as? String ?? "", (o["count"] as? NSNumber)?.intValue ?? 0)
        }
    }

    private func add() {
        busy = true
        Task {
            defer { busy = false }
            do {
                let n = try await store.addManualNodes(text: paste)
                message = String(localized: "已添加 \(n) 个节点")
                paste = ""
                detected = nil
            } catch {
                message = error.localizedDescription
            }
        }
    }
}
