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

    init(size: CGFloat, weight: Font.Weight, design: Font.Design, monospacedDigit: Bool) {
        let style: Font.TextStyle = size <= 11 ? .caption2 : (size <= 13 ? .footnote : .body)
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
    func scaledFont(_ size: CGFloat, weight: Font.Weight = .regular, design: Font.Design = .default, monospacedDigit: Bool = false) -> some View {
        modifier(ScaledSystemFont(size: size, weight: weight, design: design, monospacedDigit: monospacedDigit))
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

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.25, style: .continuous)
                .fill(dimmed ? TileTone.neutral.fill : tone.fill))
            .accessibilityHidden(true)
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

    var body: some View {
        // feat/egern-style: 15 pt title, a small grey subtitle, the value on the right at nearly title size.
        HStack(spacing: 12) {
            IconTile(symbol: symbol, tone: tone, dimmed: dimmed)
            VStack(alignment: .leading, spacing: 1) {
                Text(LocalizedStringKey(title)).font(.subheadline).foregroundStyle(dimmed ? Color.secondary : Color.primary)
                if let subtitle {
                    Text(LocalizedStringKey(subtitle)).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if let value {
                Text(LocalizedStringKey(value)).font(.footnote).foregroundStyle(dimmed ? Color.secondary : valueColor).lineLimit(1)
            }
        }
    }
}
