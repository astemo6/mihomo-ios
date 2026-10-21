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
}

/// Rounded-square icon tile for list rows: a soft tint of the tone with the symbol in the tone itself.
/// Tinted rather than solid so the same tile reads calmly on both the light and the dark card.
struct IconTile: View {
    let symbol: String
    var tone: TileTone = .accent
    var dimmed = false

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(dimmed ? Color.secondary : tone.color)
            .frame(width: 30, height: 30)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill((dimmed ? Theme.neutral : tone.color).opacity(dimmed ? 0.14 : 0.16)))
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
        HStack(spacing: 12) {
            IconTile(symbol: symbol, tone: tone, dimmed: dimmed)
            VStack(alignment: .leading, spacing: 1) {
                Text(LocalizedStringKey(title)).foregroundStyle(dimmed ? Color.secondary : Color.primary)
                if let subtitle {
                    Text(LocalizedStringKey(subtitle)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if let value {
                Text(LocalizedStringKey(value)).font(.caption).foregroundStyle(dimmed ? Color.secondary : valueColor).lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}
