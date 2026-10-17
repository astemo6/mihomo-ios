import SwiftUI
import UIKit

// QX preview 5: the QX dark palette, haptics and press states.
//
// Quantumult X's dark mode is pure black with #1C1C1E cards and keeps its feature colours; the recording
// is light only, so the dark values below are derived (iOS system dark greys for chrome, feature colours
// darkened until white 18 pt semibold labels reach ≥ 4:1, shadows replaced by hairlines because a shadow
// on black reads as nothing). Contrast figures are in notes/qx-release.md.

enum QXPalette {
    static func dyn(_ light: UInt32, _ dark: UInt32, darkAlpha: CGFloat = 1) -> Color {
        Color(UIColor { t in
            let dk = t.userInterfaceStyle == .dark
            let v = dk ? dark : light
            return UIColor(red: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255,
                           blue: CGFloat(v & 0xFF) / 255, alpha: dk ? darkAlpha : 1)
        })
    }

    /// Page background: light #F2F2F7 (QX grouped grey), dark pure black like QX.
    static let bg = dyn(0xF2F3F7, 0x000000)
    /// Cards, rows, sheets: white / #1C1C1E.
    static let card = dyn(0xFFFFFF, 0x1C1C1E)
    /// Pressed rows, pills, inset fields: #EAECF1 / #2C2C2E.
    static let cardHi = dyn(0xEAECF1, 0x2C2C2E)
    /// Floating chrome (circle buttons, capsules, the toolbar, bottom segments): white / #1C1C1E (raised
    /// one step above the black page so the hairline and the glyphs carry it).
    static let chrome = dyn(0xFFFFFF, 0x1C1C1E)
    /// Hairline around chrome: 7 % black in light, 14 % white in dark.
    static let hairline = Color(UIColor { t in
        t.userInterfaceStyle == .dark ? UIColor(white: 1, alpha: 0.14) : UIColor(white: 0, alpha: 0.07)
    })
    /// Separator inside cards.
    static let separator = Color(UIColor { t in
        t.userInterfaceStyle == .dark ? UIColor(white: 1, alpha: 0.10) : UIColor(white: 0, alpha: 0.06)
    })
    /// Neutral shadow: as given in light, almost none in dark.
    static func shadow(_ opacity: Double) -> Color {
        Color(UIColor { t in UIColor(white: 0, alpha: t.userInterfaceStyle == .dark ? min(opacity * 2.5, 0.45) : opacity) })
    }
    /// Coloured glow under settings buttons / selected tiles: off in dark (it turns into a halo on black).
    static func glow(_ c: Color, _ opacity: Double = 0.28) -> Color {
        Color(UIColor { t in t.userInterfaceStyle == .dark ? .clear : UIColor(c).resolvedColor(with: t).withAlphaComponent(opacity) })
    }
    /// Text on feature colours stays white in both modes (contrast checked for the dark variants).
    static let onColor = Color.white
    /// Unselected bottom-segment rings / dots.
    static let ring = Color(UIColor { t in
        t.userInterfaceStyle == .dark ? UIColor(white: 1, alpha: 0.38) : UIColor(white: 0, alpha: 0.30)
    })
}

// MARK: - Haptics

enum QXHaptics {
    static func tap() { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
    static func toggle() { UIImpactFeedbackGenerator(style: .medium).impactOccurred(intensity: 0.8) }
    static func longPress() { UIImpactFeedbackGenerator(style: .rigid).impactOccurred() }
    static func select() { UISelectionFeedbackGenerator().selectionChanged() }
    static func success() { UINotificationFeedbackGenerator().notificationOccurred(.success) }
    static func warning() { UINotificationFeedbackGenerator().notificationOccurred(.warning) }
}

/// QX buttons shrink slightly and dim while pressed (floating chrome, settings capsules, tiles).
struct QXPressStyle: ButtonStyle {
    var scale: CGFloat = 0.94
    var haptic = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? scale : 1)
            .opacity(configuration.isPressed ? 0.82 : 1)
            .animation(.spring(response: 0.22, dampingFraction: 0.7), value: configuration.isPressed)
            .onChange(of: configuration.isPressed) { p in
                if p && haptic { QXHaptics.tap() }
            }
    }
}

extension View {
    /// Haptic on every change of a toggle's value (QX ticks on each switch).
    func qxToggleHaptic<V: Equatable>(_ value: V) -> some View {
        onChange(of: value) { _ in QXHaptics.toggle() }
    }
}

/// The windmill turns while connected (QX: a steady spin, faster while traffic flows) and settles when
/// disconnected. Driven by TimelineView so it costs nothing when hidden and never jumps on re-render.
struct QXSpinningWindmill: View {
    let mode: String
    var size: CGFloat = 30
    let spinning: Bool
    /// Revolutions per second (QX ≈ 0.5 idle, faster with traffic).
    var speed: Double = 0.5
    @State private var base = Date()
    @State private var settled: Double = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if spinning && !reduceMotion {
            TimelineView(.animation) { ctx in
                let t = ctx.date.timeIntervalSince(base)
                QXWindmill(mode: mode, size: size)
                    .rotationEffect(.degrees(settled + t * 360 * speed))
            }
        } else {
            QXWindmill(mode: mode, size: size)
                .rotationEffect(.degrees(settled))
                .onAppear { base = Date() }
        }
    }
}

extension QXPalette {
    /// Home header band (exit location + tiles): a touch lighter than the page in light, black in dark.
    static let header = dyn(0xFBFBFC, 0x000000)
}
