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

// MARK: - Feature / semantic colours
//
// QX preview 6: the palette is provisional and our own (the user will retune it; QX's colours are not the
// target — only its proportions and layout). Views never use hex or RGB literals: add a token here instead.

enum QXColor {
    // Light = measured on the recording; dark = derived (QX preview 5): deepened so white 15–18 pt
    // semibold labels keep ≥ 4:1 on the colour, and lifted where the colour itself would vanish on black.
    static let nodes = QXPalette.dyn(0x3DB5E6, 0x1F86B8)      // light #3DB5E6
    static let activity = QXPalette.dyn(0xD9412B, 0xC2382A)   // #D9412B
    static let rules = QXPalette.dyn(0x5E2FD0, 0x6A3FE0)      // #5E2FD0
    static let rewrite = QXPalette.dyn(0xE0197A, 0xC8156C)    // #E0197A
    static let logs = QXPalette.dyn(0x5E5F66, 0x5A5B63)       // #5E5F66
    static let mitm = QXPalette.dyn(0x34B34A, 0x24903A)       // #34B34A
    static let tools = QXPalette.dyn(0xD9412B, 0xC2382A)      // #D9412B
    static let profile = QXPalette.dyn(0x5E5F66, 0x5A5B63)    // #5E5F66
    static let policyChip = QXPalette.dyn(0x29B88F, 0x1F9A77)
    static let teal = QXPalette.dyn(0x33C7CC, 0x2BB5BA)
    static let yellow = QXPalette.dyn(0xFFC21A, 0xF0B400)
    static let red = QXPalette.dyn(0xF2383F, 0xFF453A)
    /// Switch tint in the header (QX: system blue; iOS dark blue in dark).
    static let switchOn = QXPalette.dyn(0x007AFF, 0x0A84FF)

    // MARK: Semantic tokens added in QX preview 6 (every colour a QX screen uses lives in this file)
    /// Status colours on QX pages (mapped to the app-wide Theme so main and QX agree on meaning).
    static let success = Theme.good
    static let danger = Theme.bad
    static let warning = Theme.warn
    static func delay(_ ms: Int?) -> Color { Theme.delayColor(ms) }
    /// Traffic glyphs / chips: download and upload.
    static let trafficDown = QXPalette.dyn(0x408CFF, 0x5A9CFF)
    static let trafficUp = QXPalette.dyn(0x9E59F2, 0xAE74F5)
    /// Policy chips: DIRECT and an empty policy (REJECT uses `red`, others `policyChip`).
    static let policyDirect = QXPalette.dyn(0xFA9421, 0xFF9F2E)
    static let policyNone = Color.secondary.opacity(0.4)
    /// Policy-card background choices (策略 → 背景).
    static let cardOrange = policyDirect
    /// Rewrite type tags: reject* and the rest (scripts use `rewrite`).
    static let rewriteReject = QXPalette.dyn(0xF58CB3, 0xE07AA0)
    static let rewriteOther = QXPalette.dyn(0xCC408C, 0xD45597)
    /// 请求列表 task tile when the task is switched off.
    static let taskOff = QXPalette.dyn(0x785450, 0x6A4A46)
    /// Widget previews (mirror WidgetTheme in Widget/MihomoWidget.swift): the chain tile and download glyph.
    static let widgetChainTile = QXPalette.dyn(0x1F86B8, 0x1F86B8)
    static let widgetDown = QXPalette.dyn(0x1F86B8, 0x48B8E8)
    /// Lock Screen preview wallpaper.
    static let lockWallpaper: [Color] = [QXPalette.dyn(0x1F4D73, 0x1F4D73), QXPalette.dyn(0x5C2E8C, 0x5C2E8C)]
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
