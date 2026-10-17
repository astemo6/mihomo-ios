import SwiftUI
import UIKit

/// v0.15.4: iOS on China-mainland devices draws 🇹🇼 as a crossed-out box. Any flag (a pair of regional
/// indicator symbols) is test-drawn once; when the result has no colour it is not a real flag glyph, and the
/// two letters ("TW") are shown instead.
enum FlagSafe {
    private static let lock = NSLock()
    private static var cache: [String: Bool] = [:]

    static func isRegional(_ u: Unicode.Scalar) -> Bool { (0x1F1E6...0x1F1FF).contains(u.value) }

    /// Letters of a flag ("🇹🇼" → "TW"), nil if `s` is not exactly one flag.
    static func letters(_ s: String) -> String? {
        let sc = Array(s.unicodeScalars)
        guard sc.count == 2, sc.allSatisfy(isRegional) else { return nil }
        return String(sc.map { Character(Unicode.Scalar($0.value - 0x1F1E6 + 65)!) })
    }

    static func renders(_ flag: String) -> Bool {
        lock.lock()
        if let v = cache[flag] { lock.unlock(); return v }
        lock.unlock()
        // UI tests: -UITestMissingFlags TW simulates a China-region device (the simulator draws every flag).
        let forced = (UserDefaults.standard.string(forKey: "UITestMissingFlags") ?? "").split(separator: ",").map(String.init)
        let v = forced.contains(letters(flag) ?? "") ? false : probe(flag)
        lock.lock(); cache[flag] = v; lock.unlock()
        return v
    }

    private static func probe(_ flag: String) -> Bool {
        let size = CGSize(width: 24, height: 24)
        let fmt = UIGraphicsImageRendererFormat()
        fmt.scale = 1
        let img = UIGraphicsImageRenderer(size: size, format: fmt).image { _ in
            (flag as NSString).draw(at: .zero, withAttributes: [.font: UIFont.systemFont(ofSize: 18)])
        }
        guard let cg = img.cgImage, let data = cg.dataProvider?.data, let p = CFDataGetBytePtr(data) else { return true }
        let bpp = cg.bitsPerPixel / 8, bpr = cg.bytesPerRow
        guard bpp >= 3 else { return true }
        for y in 0..<cg.height {
            for x in 0..<cg.width {
                let o = y * bpr + x * bpp
                let r = Int(p[o]), g = Int(p[o + 1]), b = Int(p[o + 2])
                if max(r, g, b) - min(r, g, b) > 40 { return true }
            }
        }
        return false
    }

    /// `s` with every flag that does not draw replaced by its letters ("🇹🇼 Taipei" → "TW Taipei").
    static func text(_ s: String) -> String {
        guard s.unicodeScalars.contains(where: isRegional) else { return s }
        var out = ""
        var pending: Unicode.Scalar?
        for u in s.unicodeScalars {
            if isRegional(u) {
                if let a = pending {
                    var v = String.UnicodeScalarView()
                    v.append(a); v.append(u)
                    let f = String(v)
                    out += renders(f) ? f : (letters(f) ?? f)
                    pending = nil
                } else { pending = u }
            } else {
                if let a = pending { out.unicodeScalars.append(a); pending = nil }
                out.unicodeScalars.append(u)
            }
        }
        if let a = pending { out.unicodeScalars.append(a) }
        return out
    }
}

/// A flag for lists: the emoji, or a small letter badge when the system does not draw it.
struct FlagGlyph: View {
    let flag: String
    var body: some View {
        if let l = FlagSafe.letters(flag), !FlagSafe.renders(flag) {
            Text(verbatim: l)
                .font(.caption.weight(.heavy).monospaced())
                .foregroundStyle(.secondary)
                .frame(width: 30, height: 22)
                .background(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.5)))
                .accessibilityLabel(Text(verbatim: l))
        } else {
            Text(verbatim: flag).font(.title3)
        }
    }
}
