import Foundation
#if canImport(ActivityKit) && !os(macOS)
import SwiftUI
import UIKit
import AppIntents

// v0.19.14 实时活动排版 (device feedback 2026-10-21 「这个排版有问题」 / 「2:46是什么意思」):
// the Lock Screen and Dynamic Island content as plain views over (state, profile, stale), so the widget draws
// them and the unit tests render them with ImageRenderer. App + widget only (the tunnel excludes this file).
//
// Lock Screen:  [icon]  已连接 2分钟46秒         ↑ 33.9K/s   (⟳)
//                       🇯🇵 东京 Green CDN      ↓ 142K/s
// Rules: the status word is one line and never wraps; the elapsed time always sits right after its label
// (never a bare number) and keeps a fixed width so nothing jumps while it counts; long node names truncate
// in the middle; speeds are stacked with tabular digits and a fixed minimum width.

/// Follows the system appearance (v0.9); same values as the app's Theme.
enum WidgetTheme {
    static func dyn(_ l: (CGFloat, CGFloat, CGFloat), _ d: (CGFloat, CGFloat, CGFloat)) -> Color {
        Color(UIColor { $0.userInterfaceStyle == .dark ? UIColor(red: d.0, green: d.1, blue: d.2, alpha: 1) : UIColor(red: l.0, green: l.1, blue: l.2, alpha: 1) })
    }
    static let bg = dyn((1, 1, 1), (0.06, 0.065, 0.09))
    static let good = dyn((0.09, 0.60, 0.29), (0.25, 0.85, 0.48))
    static let accent = dyn((0.0, 0.47, 0.78), (0.29, 0.78, 0.96))
    static let up = Color.orange
}

/// The running connected time as a duration with units: 「14分钟2秒」, 「2小时46分钟」 ("14 min, 2 sec", "2 hr, 46 min").
/// hotfix/liveact-lockscreen (device 2026-10-21 16:26): Text(timerInterval:) drew 「已连接 14:02」, which reads like a
/// clock time (connected at 14:02) although it meant 14 min 02 s. Text(date, style: .relative) is drawn and ticked by
/// the system like the timer (no ActivityKit updates needed) but always carries its units. Reserves the width of
/// "23 hr, 59 min" in the current language so the line never shifts as it counts.
@available(iOS 16.2, *)
struct LiveElapsed: View {
    let since: Date
    @Environment(\.locale) private var locale

    /// The widest value we expect to show, formatted the way the relative style formats it (short units, two fields).
    private var sample: String {
        let f = DateComponentsFormatter()
        f.unitsStyle = .short
        f.allowedUnits = [.hour, .minute]
        f.maximumUnitCount = 2
        var cal = Calendar.current
        cal.locale = locale
        f.calendar = cal
        return f.string(from: 23 * 3600 + 59 * 60) ?? "23 hr, 59 min"
    }

    /// r7: past 24 h the relative style switches to days (「1天2小时」 / "1 day, 2 hr"); reserve that width too so a long
    /// session is not squeezed. The system ticks the text without re-rendering the view, so both are reserved up front.
    private var daySample: String {
        let f = DateComponentsFormatter()
        f.unitsStyle = .short
        f.allowedUnits = [.day, .hour]
        f.maximumUnitCount = 2
        var cal = Calendar.current
        cal.locale = locale
        f.calendar = cal
        return f.string(from: 6 * 86400 + 23 * 3600) ?? "6 days, 23 hr"
    }

    var body: some View {
        ZStack(alignment: .leading) {
            Text(verbatim: sample)
            Text(verbatim: daySample)
        }
            .hidden()
            .overlay(alignment: .leading) {
                Text(since, style: .relative)
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .monospacedDigit()
            .lineLimit(1)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("已连接时长"))
            .accessibilityValue(Text(since, style: .relative))
    }
}

/// 「已连接 2:46」 — the label and its time on one line; 「未连接」 alone when disconnected. When the line does not
/// fit (long translation + large Dynamic Type) the time moves under the label with a clock glyph instead of
/// being squeezed, truncated or drawn over the speeds.
@available(iOS 16.2, *)
struct LiveStatusLine: View {
    let connected: Bool
    let since: Date
    // hotfix/liveact-lockscreen (user 16:27 「字体太大」): one step smaller than v0.19.14's headline / subheadline;
    // the status word stays semibold so it still leads the card.
    var titleFont: Font = .subheadline.weight(.semibold)
    var timeFont: Font = .footnote

    private var title: some View {
        Text(connected ? LocalizedStringKey("已连接") : LocalizedStringKey("未连接"))
            .font(titleFont)
            .lineLimit(1)
    }

    private var time: some View {
        LiveElapsed(since: since)
            .font(timeFont)
            .foregroundStyle(.secondary)
            .fixedSize()
    }

    var body: some View {
        if connected {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    title.fixedSize()
                    time
                }
                VStack(alignment: .leading, spacing: 1) {
                    title.minimumScaleFactor(0.75)
                    HStack(spacing: 3) {
                        Image(systemName: "clock").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
                        time
                    }
                }
            }
        } else {
            title.minimumScaleFactor(0.75)
        }
    }
}

/// ↑ / ↓ stacked, tabular digits, fixed minimum width ("888.8K/s").
/// Stale (no update for about twice the update interval, ActivityKit's staleDate): an old instant speed means nothing,
/// so the rows show the session totals instead (「累计」, grey) when the state carries them, otherwise no numbers at
/// all; either way with the time the numbers were taken (「更新于 下午4:22」).
@available(iOS 16.2, *)
struct LiveSpeeds: View {
    let state: TernActivityAttributes.ContentState
    var stale = false
    var font: Font = .footnote

    private var totals: (up: Int64, down: Int64)? {
        guard let u = state.totalUp, let d = state.totalDown else { return nil }
        return (u, d)
    }

    var body: some View {
        VStack(alignment: .trailing, spacing: 2) {
            if !stale {
                row(symbol: "arrow.up", text: LiveActivityFormat.speed(state.up) + "/s", color: WidgetTheme.up, label: "上传")
                row(symbol: "arrow.down", text: LiveActivityFormat.speed(state.down) + "/s", color: WidgetTheme.accent, label: "下载")
            } else if let t = totals {
                Text("累计")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1).minimumScaleFactor(0.7)
                row(symbol: "arrow.up", text: LiveActivityFormat.speed(t.up), color: .secondary, label: "上传")
                row(symbol: "arrow.down", text: LiveActivityFormat.speed(t.down), color: .secondary, label: "下载")
            }
            // feat/traffic-scope: the numbers count proxy traffic only (首页流量统计 = 仅代理流量).
            if state.proxyOnly == true {
                Text("仅代理")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1).minimumScaleFactor(0.7)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
            }
            if stale {
                Text("更新于 \(state.updated.formatted(date: .omitted, time: .shortened))")
                    .font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).minimumScaleFactor(0.7)
            }
        }
        .font(font.monospacedDigit())
        .fixedSize(horizontal: true, vertical: false)
    }

    private func row(symbol: String, text: String, color: Color, label: LocalizedStringKey) -> some View {
        HStack(spacing: 3) {
            Image(systemName: symbol).font(.caption2.weight(.bold))
            Text(verbatim: "888.8K/s").hidden()
                .overlay(alignment: .trailing) {
                    Text(verbatim: text).lineLimit(1)
                }
        }
        .foregroundStyle(color)
        .lineLimit(1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(label))
        .accessibilityValue(Text(verbatim: text))
    }
}

/// v0.11: refreshes the activity from the tunnel's latest numbers (runs in the app process).
@available(iOS 17.0, *)
struct LiveRefreshButton: View {
    var size: CGFloat = 30
    var body: some View {
        Button(intent: RefreshLiveActivityIntent()) {
            Image(systemName: "arrow.clockwise")
                .font(.footnote.weight(.semibold))
                .frame(width: size, height: size)
                .background(Circle().fill(WidgetTheme.accent.opacity(0.18)))
        }
        .buttonStyle(.plain)
        .foregroundStyle(WidgetTheme.accent)
        .accessibilityLabel(Text("刷新"))
    }
}

@available(iOS 16.2, *)
struct LiveStatusIcon: View {
    let connected: Bool
    var size: CGFloat = 38
    var body: some View {
        let tint = connected ? WidgetTheme.good : Color.secondary
        Image(systemName: "network")
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(Circle().fill(tint.opacity(0.16)))
            .accessibilityHidden(true)
    }
}

/// Node line: flag + name as the app shows it, one line, middle truncation; the profile when no node is known.
@available(iOS 16.2, *)
struct LiveNodeLine: View {
    let state: TernActivityAttributes.ContentState
    let profile: String
    var body: some View {
        Text(verbatim: state.node.isEmpty ? profile : state.node)
            .lineLimit(1)
            .truncationMode(.middle)
            .foregroundStyle(.secondary)
    }
}

/// Lock Screen / banner presentation.
@available(iOS 17.0, *)
struct LiveActivityLockContent: View {
    let state: TernActivityAttributes.ContentState
    let profile: String
    var stale = false
    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            LiveStatusIcon(connected: state.connected)
            VStack(alignment: .leading, spacing: 3) {
                LiveStatusLine(connected: state.connected, since: state.since)
                LiveNodeLine(state: state, profile: profile).font(.footnote)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .layoutPriority(1)
            LiveSpeeds(state: state, stale: stale)
            LiveRefreshButton()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        // Live Activities have ~160 pt of height; past xxLarge the two lines would be clipped.
        .dynamicTypeSize(...DynamicTypeSize.xxLarge)
    }
}

/// Dynamic Island expanded regions.
@available(iOS 17.0, *)
struct LiveIslandLeading: View {
    let state: TernActivityAttributes.ContentState
    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            LiveStatusIcon(connected: state.connected, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text(state.connected ? LocalizedStringKey("已连接") : LocalizedStringKey("未连接"))
                    .font(.caption.weight(.semibold))
                    .lineLimit(1).minimumScaleFactor(0.7)
                if state.connected {
                    // A duration with units (「14分钟2秒」), under the status word; never a bare number.
                    LiveElapsed(since: state.since)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize()
                }
            }
        }
        .padding(.leading, 4)
        .dynamicTypeSize(...DynamicTypeSize.xLarge)
    }
}

@available(iOS 17.0, *)
struct LiveIslandTrailing: View {
    let state: TernActivityAttributes.ContentState
    var stale = false
    var body: some View {
        LiveSpeeds(state: state, stale: stale, font: .caption)
            .padding(.trailing, 4)
            .dynamicTypeSize(...DynamicTypeSize.xLarge)
    }
}

@available(iOS 17.0, *)
struct LiveIslandBottom: View {
    let state: TernActivityAttributes.ContentState
    let profile: String
    var body: some View {
        HStack(spacing: 10) {
            LiveNodeLine(state: state, profile: profile)
                .font(.caption)
                .frame(maxWidth: .infinity, alignment: .leading)
            LiveRefreshButton(size: 28)
        }
        .padding(.horizontal, 4)
        .dynamicTypeSize(...DynamicTypeSize.xLarge)
    }
}

/// Compact (pill) sides: ↑ left, ↓ right (v0.19.8), always numbers; stale = grey.
@available(iOS 16.2, *)
struct LiveCompactSpeed: View {
    let up: Bool
    let state: TernActivityAttributes.ContentState
    var stale = false
    var body: some View {
        HStack(spacing: 1) {
            Image(systemName: up ? "arrow.up" : "arrow.down").font(.system(size: 9, weight: .bold))
            Text(verbatim: LiveActivityFormat.speed(up ? state.up : state.down))
        }
        .font(.caption2.monospacedDigit())
        .lineLimit(1).minimumScaleFactor(0.7)
        .foregroundStyle(stale ? Color.secondary : (up ? WidgetTheme.up : WidgetTheme.accent))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(up ? LocalizedStringKey("上传") : LocalizedStringKey("下载")))
        .accessibilityValue(Text(verbatim: LiveActivityFormat.speed(up ? state.up : state.down) + "/s"))
    }
}
#endif
