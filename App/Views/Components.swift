import SwiftUI

// Shared states for every screen (v0.6 UI audit): one empty state, one error row, one loading row,
// so lists, cards and pages look the same everywhere. All titles are LocalizedStringKey-backed.

/// Empty state inside a List section or a Card: icon, title, one or two lines of guidance.
struct EmptyStateRow<Extra: View>: View {
    let icon: String
    let title: String
    var message: String? = nil
    @ViewBuilder var extra: Extra

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.body.weight(.semibold))
                .foregroundStyle(Theme.accent)
                .frame(width: 34, height: 34)
                .background(Circle().fill(Theme.accent.opacity(0.14)))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(LocalizedStringKey(title)).font(.subheadline.weight(.semibold))
                if let message {
                    Text(LocalizedStringKey(message)).font(.footnote).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                extra
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 6)
    }
}

extension EmptyStateRow where Extra == EmptyView {
    init(icon: String, title: String, message: String? = nil) {
        self.icon = icon
        self.title = title
        self.message = message
        self.extra = EmptyView()
    }
}

/// Whole-page empty state (no list around it).
/// feat/surge-ui: an optional one-line hint plus one action button (「连接」, 「添加配置」) so an empty page
/// always says what to do next.
struct EmptyStateView: View {
    var icon = "tray"
    let title: String
    var message: String? = nil
    var actionTitle: String? = nil
    var actionID: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 40, weight: .regular)).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(LocalizedStringKey(title)).font(.headline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            if let message {
                Text(LocalizedStringKey(message)).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            if let actionTitle, let action {
                Button(action: action) {
                    Text(LocalizedStringKey(actionTitle)).font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 18).padding(.vertical, 8)
                        .background(Capsule().fill(Theme.accent.opacity(0.14)))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.accent)
                .padding(.top, 4)
                .accessibilityIdentifier(actionID ?? "empty.action")
            }
        }
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.top, 60)
    }
}

/// An error the user should read (failed load, failed start): red icon + selectable text.
struct ErrorRow: View {
    let message: String
    var retry: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.bad).accessibilityHidden(true)
            Text(message).font(.footnote).foregroundStyle(Theme.bad).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            if let retry {
                Button("重试", action: retry).font(.footnote.weight(.semibold)).buttonStyle(.borderless)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Inline progress with a short label.
struct LoadingRow: View {
    let text: String
    var body: some View {
        HStack(spacing: 10) {
            ProgressView()
            Text(LocalizedStringKey(text)).font(.footnote).foregroundStyle(.secondary)
        }
    }
}

/// A fixed point size that still follows Dynamic Type (badges, monospaced logs). Default size looks
/// exactly like `.system(size:)`; larger text settings scale it relative to the closest text style.
struct ScaledSystemFont: ViewModifier {
    @ScaledMetric private var size: CGFloat
    let weight: Font.Weight
    let design: Font.Design
    let monospacedDigit: Bool

    init(size: CGFloat, weight: Font.Weight, design: Font.Design, monospacedDigit: Bool, relativeTo: Font.TextStyle? = nil) {
        let style: Font.TextStyle = relativeTo ?? (size <= 11 ? .caption2 : (size <= 13 ? .footnote : .body))
        _size = ScaledMetric(wrappedValue: size, relativeTo: style)
        self.weight = weight
        self.design = design
        self.monospacedDigit = monospacedDigit
    }

    func body(content: Content) -> some View {
        let f = Font.system(size: size, weight: weight, design: design)
        return content.font(monospacedDigit ? f.monospacedDigit() : f)
    }
}

extension View {
    func scaledFont(_ size: CGFloat, weight: Font.Weight = .regular, design: Font.Design = .default, monospacedDigit: Bool = false,
                    relativeTo: Font.TextStyle? = nil) -> some View {
        modifier(ScaledSystemFont(size: size, weight: weight, design: design, monospacedDigit: monospacedDigit, relativeTo: relativeTo))
    }
}


// MARK: - Icon tiles (feat/surge-ui)

/// The fixed set of tile tones. Every one is an existing palette colour (Theme status colours or a hue that
/// `Theme.protocolColor` / `ruleTypeColor` already use), so tiles add no new colour to the app.
enum TileTone {
    case blue, teal, green, orange, red, purple, pink, accent, neutral

    var color: Color {
        switch self {
        case .blue: return Theme.tone(0.25, 0.6, 1.0)
        case .teal: return Theme.tone(0.2, 0.8, 0.85)
        case .green: return Theme.tone(0.35, 0.85, 0.45)
        case .orange: return Theme.tone(1.0, 0.62, 0.2)
        case .red: return Theme.tone(1.0, 0.45, 0.45)
        case .purple: return Theme.tone(0.55, 0.45, 1.0)
        case .pink: return Theme.tone(1.0, 0.4, 0.75)
        case .accent: return Theme.accent
        case .neutral: return Theme.neutral
        }
    }
    /// feat/egern-style: solid tile fill behind a white symbol — the light-mode value of the same tone in both
    /// appearances (the bright dark-mode values are too light under white). No new colour.
    var fill: Color {
        func t(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> Color { Color(Theme.rgb(r * 0.78, g * 0.78, b * 0.78)) }
        switch self {
        case .blue: return t(0.25, 0.6, 1.0)
        case .teal: return t(0.2, 0.8, 0.85)
        case .green: return t(0.35, 0.85, 0.45)
        case .orange: return t(1.0, 0.62, 0.2)
        case .red: return t(1.0, 0.45, 0.45)
        case .purple: return t(0.55, 0.45, 1.0)
        case .pink: return t(1.0, 0.4, 0.75)
        case .accent: return Theme.accentSolid
        case .neutral: return Color(UIColor(white: 0.60, alpha: 1))
        }
    }
}

/// Rounded-square icon tile for list rows. feat/egern-style: Egern's small solid tile — the tone as the fill, a white
/// symbol, 28 pt with 7 pt corners. Dimmed rows use the neutral grey.
struct IconTile: View {
    let symbol: String
    var tone: TileTone = .accent
    var dimmed = false
    var size: CGFloat = 28
    /// nil = a quarter of `size` (TernRowMetrics.iconCornerRadius for the shared list row).
    var cornerRadius: CGFloat? = nil

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: cornerRadius ?? size * 0.25, style: .continuous)
                .fill(dimmed ? TileTone.neutral.fill : tone.fill))
            .accessibilityHidden(true)
    }
}

/// fix/more-row-height (user 「更多页每行的高度与其他页行高度不一样」): the one row metric for the icon rows of the tab
/// root pages — 工具's cards, 更多 (and its sub-lists that use MoreRow) and the 更多 search results. 工具's values are
/// the reference (the more-used page): 30 pt tile with 7.5 pt corners, 12 pt between tile and text, 15 pt title
/// (`.subheadline`), 3 pt between title and detail line, 2 pt vertical padding. Rows without a detail line still get
/// the tile's height as a minimum, so a one-line 更多 row is as tall as a one-line 工具 card. The minimum scales with
/// Dynamic Type (a minimum, never a fixed height). Only these values are shared: 更多 keeps its grouped sections
/// (several rows per inset card with separators), 工具 its one-card sections.
enum TernRowMetrics {
    static let iconSize: CGFloat = 30
    static let iconCornerRadius: CGFloat = 7.5
    static let iconTextSpacing: CGFloat = 12
    static let titleDetailSpacing: CGFloat = 3
    static let verticalPadding: CGFloat = 2
    /// Minimum content height at the default text size (= the tile), scaled relative to `.subheadline`.
    static let minContentHeight: CGFloat = 30
    static let titleFont: Font = .subheadline
    static let detailFont: Font = .caption2
    /// fix/nc-0.20.2: the vertical inset SwiftUI's inset-grouped List gives a row's content (a 工具 card's cell =
    /// content + 2 × this). Rows drawn outside a List (策略's group cards) add it themselves to be as tall.
    static let listRowVerticalInset: CGFloat = 11
}

/// The shared icon row: tile · title over an optional detail line · flexible space · optional trailing content.
struct TernIconRow<Detail: View, Trailing: View>: View {
    let symbol: String
    var tone: TileTone
    var dimmed: Bool
    let title: Text
    let detail: Detail
    let trailing: Trailing
    @ScaledMetric(relativeTo: .subheadline) private var minHeight: CGFloat = TernRowMetrics.minContentHeight

    init(symbol: String, tone: TileTone = .accent, dimmed: Bool = false, title: Text,
         @ViewBuilder detail: () -> Detail, @ViewBuilder trailing: () -> Trailing) {
        self.symbol = symbol
        self.tone = tone
        self.dimmed = dimmed
        self.title = title
        self.detail = detail()
        self.trailing = trailing()
    }

    var body: some View {
        HStack(spacing: TernRowMetrics.iconTextSpacing) {
            IconTile(symbol: symbol, tone: tone, dimmed: dimmed, size: TernRowMetrics.iconSize,
                     cornerRadius: TernRowMetrics.iconCornerRadius)
            VStack(alignment: .leading, spacing: TernRowMetrics.titleDetailSpacing) {
                title.font(TernRowMetrics.titleFont).foregroundStyle(dimmed ? Color.secondary : Color.primary)
                detail
            }
            Spacer(minLength: 8)
            trailing
        }
        .frame(minHeight: minHeight)
        .padding(.vertical, TernRowMetrics.verticalPadding)
    }
}

extension TernIconRow where Trailing == EmptyView {
    init(symbol: String, tone: TileTone = .accent, dimmed: Bool = false, title: Text, @ViewBuilder detail: () -> Detail) {
        self.init(symbol: symbol, tone: tone, dimmed: dimmed, title: title, detail: detail, trailing: { EmptyView() })
    }
}

/// One settings row: tile, plain-language title, an optional small technical subtitle, an optional value.
/// `needsVPN` greys the row and shows 「需开启 VPN」 while disconnected; the row stays tappable (the page
/// explains itself and offers 连接).
struct TileRow: View {
    let title: String
    var subtitle: String? = nil
    let symbol: String
    var tone: TileTone = .accent
    var value: String? = nil
    var valueColor: Color = .secondary
    var dimmed = false
    /// r7 P3-2: user text (a profile name) is shown as typed — no Markdown, no catalog lookup.
    var valueVerbatim = false

    var body: some View {
        // feat/egern-style: 15 pt title, a small grey subtitle, the value on the right at nearly title size.
        // fix/more-row-height: tile, spacing, padding and minimum height from TernRowMetrics (same as 工具's cards).
        TernIconRow(symbol: symbol, tone: tone, dimmed: dimmed, title: Text(LocalizedStringKey(title))) {
            if let subtitle {
                Text(LocalizedStringKey(subtitle)).font(TernRowMetrics.detailFont).foregroundStyle(.secondary).lineLimit(1)
            }
        } trailing: {
            if let value {
                (valueVerbatim ? Text(verbatim: value) : Text(LocalizedStringKey(value))).font(.footnote).foregroundStyle(dimmed ? Color.secondary : valueColor).lineLimit(1)
            }
        }
    }
}

/// feat/geo-mirror-edit: the visible state of a paused live list (请求, DNS 日志, 日志). Tapping it resumes.
struct PausedChip: View {
    let id: String
    let resume: () -> Void

    var body: some View {
        Button(action: resume) {
            HStack(spacing: 6) {
                Image(systemName: "pause.circle.fill").font(.footnote.weight(.semibold))
                Text("已暂停刷新 · 点按继续").font(.caption.weight(.semibold)).lineLimit(1).minimumScaleFactor(0.8)
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
            .background(Capsule().fill(Theme.warn.opacity(0.16)))
            .foregroundStyle(Theme.warn)
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityLabel(Text("已暂停刷新 · 点按继续"))
        .accessibilityHint(Text("继续刷新"))
        .accessibilityIdentifier(id)
    }
}

/// The toolbar pause / play button shared by the same three pages.
struct PauseToggleButton: View {
    @Binding var paused: Bool
    let id: String

    var body: some View {
        Button { paused.toggle() } label: { Image(systemName: paused ? "play.fill" : "pause.fill") }
            .accessibilityLabel(Text(LocalizedStringKey(paused ? "继续刷新" : "暂停刷新")))
            .accessibilityIdentifier(id)
    }
}
