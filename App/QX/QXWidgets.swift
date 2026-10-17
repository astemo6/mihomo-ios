import SwiftUI

// QX preview 6: 小组件与控制中心 showcase page (其他设置 → 小组件). Quantumult X has no widgets; this page
// shows the QX widget set in light and dark with the current run mode, then how to add each one. The
// previews redraw the widget extension's layouts (Widget/MihomoWidget.swift) with the same QX palette —
// the extension's views cannot be hosted in the app, so keep the two in step when one changes.

struct QXWidgetsPage: View {
    @ObservedObject private var modeModel = QXModeModel.shared
    @EnvironmentObject var vpn: VPNManager
    @State private var scheme = 0          // 0 = 浅色, 1 = 深色
    @State private var previewMode: String?

    private var mode: String { previewMode ?? modeModel.mode }
    private var colorScheme: ColorScheme { scheme == 1 ? .dark : .light }

    var body: some View {
        QXPage(title: String(localized: "小组件")) {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    QXLargeTitle(title: String(localized: "小组件"),
                                 caption: String(localized: "主屏幕、锁定屏幕和控制中心都能看到出口位置、策略链和运行模式；风车颜色就是运行模式：三色 = 规则分流，青色 = 全局代理，黄色 = 全局直连。需要带小组件的 IPA（-widget）。"))

                    HStack(spacing: 10) {
                        Picker("", selection: $scheme) {
                            Text("浅色").tag(0)
                            Text("深色").tag(1)
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 180)
                        Spacer()
                        Button {
                            QXHaptics.select()
                            let order = ["rule", "global", "direct"]
                            let i = order.firstIndex(of: mode) ?? 0
                            withAnimation(QXMotion.spring) { previewMode = order[(i + 1) % 3] }
                        } label: {
                            HStack(spacing: 6) {
                                QXWindmill(mode: mode, size: 18)
                                Text(QXWidgetSample.modeTitle(mode)).font(.system(size: 15, weight: .semibold))
                            }
                            .padding(.horizontal, 12).frame(height: 36)
                            .background(Capsule().fill(QXPalette.cardHi))
                        }
                        .buttonStyle(QXPressStyle())
                        .foregroundStyle(.primary)
                        .accessibilityLabel(Text("切换预览的运行模式"))
                    }

                    VStack(alignment: .leading, spacing: 14) {
                        section(String(localized: "主屏幕"))
                        HStack(alignment: .top, spacing: 14) {
                            QXWidgetFrame(width: 158, height: 158) { QXSmallWidgetPreview(mode: mode) }
                            VStack(alignment: .leading, spacing: 6) {
                                Text("小号").font(.system(size: 15, weight: .semibold))
                                Text("国旗与出口位置、策略链、开关；轻点风车切换运行模式。").font(.system(size: 13)).foregroundStyle(.secondary)
                            }
                        }
                        QXWidgetFrame(width: 338, height: 158) { QXMediumWidgetPreview(mode: mode) }
                        Text("中号：出口位置与 ASN、开关；青色「节点」磁贴是当前策略链，旁边的风车卡片轻点切换运行模式；底部是今日流量与订阅剩余流量。")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }
                    .environment(\.colorScheme, colorScheme)

                    VStack(alignment: .leading, spacing: 14) {
                        section(String(localized: "锁定屏幕"))
                        QXLockScreenPreview(mode: mode)
                        Text("单行（时间上方）：国旗、出口位置与运行模式。矩形：出口位置、策略链、风车与今日流量。圆形：轻点连接 / 断开。")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 14) {
                        section(String(localized: "控制中心（iOS 18）"))
                        HStack(spacing: 14) {
                            QXControlPreview(symbol: "bolt.horizontal.circle.fill", title: "Mihomo QX", subtitle: String(localized: "已连接"), tint: QXColor.switchOn, on: true)
                            QXControlPreview(symbol: QXWidgetSample.modeSymbol(mode), title: String(localized: "运行模式"), subtitle: QXWidgetSample.modeTitle(mode), tint: QXWidgetSample.modeColor(mode), on: true)
                        }
                        Text("「Mihomo QX」开关连接 / 断开；「Mihomo QX 运行模式」按 规则分流 → 全局代理 → 全局直连 循环，图标颜色与风车一致。连接时立即生效，断开时下次连接使用。")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }
                    .environment(\.colorScheme, colorScheme)

                    VStack(alignment: .leading, spacing: 8) {
                        section(String(localized: "如何添加"))
                        step("1", String(localized: "主屏幕：长按空白处 → 左上角「编辑」→「添加小组件」→ 搜索「Mihomo QX」。"))
                        step("2", String(localized: "锁定屏幕：长按锁定屏幕 →「自定」→ 锁定屏幕 → 轻点时间上方或下方的小组件区域。"))
                        step("3", String(localized: "控制中心：从右上角下滑 → 左上角「+」→「添加控制」→ 搜索「Mihomo QX」。"))
                        step("4", String(localized: "实时活动与灵动岛在「其他设置 → 通知」中开启。"))
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
    }

    private func section(_ t: String) -> some View {
        Text(verbatim: t).font(.system(size: 20, weight: .bold))
    }

    private func step(_ n: String, _ t: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(verbatim: n).font(.system(size: 13, weight: .bold)).foregroundStyle(.white)
                .frame(width: 22, height: 22).background(Circle().fill(QXColor.nodes))
            Text(verbatim: t).font(.system(size: 15)).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Sample content + the widget palette (mirrors WidgetTheme in Widget/MihomoWidget.swift).
enum QXWidgetSample {
    static let flag = "🇭🇰"
    static let place = "Hong Kong"
    static let detail = "AS9304 HGC GLOBAL"
    static let policy = "PROXY"
    static let chain = "手动切换 ➤ 🇭🇰 香港 01"
    static let down = "1.2 GB", up = "86 MB", remaining = "128 GB"

    static func modeTitle(_ m: String) -> String {
        switch m {
        case "global": return String(localized: "全局代理")
        case "direct": return String(localized: "全局直连")
        default: return String(localized: "规则分流")
        }
    }
    static func modeSymbol(_ m: String) -> String {
        switch m {
        case "global": return "globe.asia.australia.fill"
        case "direct": return "arrow.right.circle.fill"
        default: return "arrow.triangle.branch"
        }
    }
    static func modeColor(_ m: String) -> Color {
        switch m {
        case "global": return QXColor.teal
        case "direct": return QXColor.yellow
        default: return QXColor.red
        }
    }
}

struct QXWidgetFrame<Content: View>: View {
    let width: CGFloat
    let height: CGFloat
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(16)
            .frame(width: width, height: height, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(QXPalette.bg))
            .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(QXPalette.hairline, lineWidth: 1))
            .shadow(color: QXPalette.shadow(0.10), radius: 10, y: 4)
    }
}

struct QXWidgetToggle: View {
    var on = true
    var body: some View {
        ZStack(alignment: on ? .trailing : .leading) {
            Capsule().fill(on ? QXColor.switchOn : Color.secondary.opacity(0.3)).frame(width: 50, height: 30)
            Circle().fill(Color.white).frame(width: 26, height: 26).padding(2).shadow(color: .black.opacity(0.15), radius: 1, y: 0.5)
        }
    }
}

struct QXSmallWidgetPreview: View {
    let mode: String
    var on = true
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top) {
                Text(verbatim: QXWidgetSample.flag).font(.system(size: 22))
                Spacer(minLength: 0)
                QXWindmill(mode: mode, size: 22)
                    .padding(5)
                    .background(Circle().fill(QXPalette.card))
                    .overlay(Circle().strokeBorder(QXPalette.hairline, lineWidth: 1))
            }
            Text(verbatim: QXWidgetSample.place).font(.system(size: 17, weight: .bold)).lineLimit(1)
            Text(verbatim: QXWidgetSample.chain).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 0)
            HStack {
                QXWidgetToggle(on: on)
                Spacer(minLength: 4)
                Text(verbatim: QXWidgetSample.modeTitle(mode)).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
            }
        }
        .foregroundStyle(.primary)
    }
}

struct QXMediumWidgetPreview: View {
    let mode: String
    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(verbatim: QXWidgetSample.flag).font(.system(size: 20))
                        Text(verbatim: QXWidgetSample.place).font(.system(size: 20, weight: .bold)).lineLimit(1)
                    }
                    Text(verbatim: QXWidgetSample.detail).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                QXWidgetToggle()
            }
            HStack(spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "server.rack").font(.system(size: 15, weight: .semibold))
                    VStack(alignment: .leading, spacing: 1) {
                        Text(verbatim: QXWidgetSample.policy).font(.system(size: 11, weight: .semibold)).opacity(0.85)
                        Text(verbatim: QXWidgetSample.chain).font(.system(size: 13, weight: .bold)).lineLimit(1).minimumScaleFactor(0.75)
                    }
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 11)
                .frame(maxWidth: .infinity, minHeight: 46, maxHeight: 46)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(QXColor.widgetChainTile))
                HStack(spacing: 7) {
                    QXWindmill(mode: mode, size: 22)
                    Text(verbatim: QXWidgetSample.modeTitle(mode)).font(.system(size: 13, weight: .semibold)).lineLimit(1).minimumScaleFactor(0.7)
                }
                .padding(.horizontal, 10)
                .frame(width: 112, height: 46)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(QXPalette.card))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(QXPalette.hairline, lineWidth: 1))
            }
            HStack(spacing: 10) {
                traffic("chevron.down.circle.fill", QXColor.widgetDown, QXWidgetSample.down)
                traffic("chevron.up.circle.fill", QXColor.rules, QXWidgetSample.up)
                Spacer(minLength: 4)
                Label { Text(verbatim: QXWidgetSample.remaining) } icon: { Image(systemName: "gauge.with.dots.needle.33percent") }
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
            }
        }
        .foregroundStyle(.primary)
    }

    private func traffic(_ icon: String, _ c: Color, _ v: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).font(.system(size: 11)).foregroundStyle(c)
            Text(verbatim: v).font(.system(size: 12).monospacedDigit())
        }
    }
}

/// Lock Screen accessories on a wallpaper-like gradient (they render monochrome / vibrant there).
struct QXLockScreenPreview: View {
    let mode: String
    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 4) {
                Text(verbatim: "\(QXWidgetSample.flag) \(QXWidgetSample.place) · \(QXWidgetSample.modeTitle(mode))")
            }
            .font(.system(size: 15, weight: .semibold))
            Text(verbatim: "9:41").font(.system(size: 72, weight: .semibold, design: .rounded))
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(Color.white.opacity(0.18))
                    VStack(spacing: 1) {
                        Text(verbatim: QXWidgetSample.flag).font(.title3)
                        Text("开").font(.caption2.weight(.semibold))
                    }
                }
                .frame(width: 72, height: 72)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 4) {
                        Text(verbatim: QXWidgetSample.flag)
                        Text(verbatim: QXWidgetSample.place).font(.headline).lineLimit(1)
                    }
                    Text(verbatim: QXWidgetSample.chain).font(.caption).lineLimit(1)
                    HStack(spacing: 4) {
                        QXWindmill(mode: mode, size: 11)
                        Text(verbatim: QXWidgetSample.modeTitle(mode))
                        Text(verbatim: "↓\(QXWidgetSample.down) ↑\(QXWidgetSample.up)").monospacedDigit()
                    }
                    .font(.caption2).lineLimit(1)
                }
                .padding(10)
                .frame(width: 170, height: 72, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.white.opacity(0.18)))
            }
        }
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .background(
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .fill(LinearGradient(colors: QXColor.lockWallpaper, startPoint: .topLeading, endPoint: .bottomTrailing))
        )
        .accessibilityElement(children: .combine)
    }
}

struct QXControlPreview: View {
    let symbol: String
    let title: String
    let subtitle: String
    let tint: Color
    var on = true
    var body: some View {
        HStack(spacing: 10) {
            // Control Center draws a button's symbol in its tint on a grey platter.
            Image(systemName: symbol).font(.system(size: 20, weight: .semibold))
                .foregroundStyle(on ? tint : Color.secondary)
                .frame(width: 44, height: 44)
                .background(Circle().fill(QXPalette.cardHi))
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Text(verbatim: subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 30, style: .continuous).fill(QXPalette.card))
        .overlay(RoundedRectangle(cornerRadius: 30, style: .continuous).stroke(QXPalette.hairline, lineWidth: 1))
    }
}
