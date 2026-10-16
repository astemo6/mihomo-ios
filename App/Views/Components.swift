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
struct EmptyStateView: View {
    var icon = "tray"
    let title: String
    var message: String? = nil

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 40, weight: .regular)).foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(LocalizedStringKey(title)).font(.headline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            if let message {
                Text(LocalizedStringKey(message)).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
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
