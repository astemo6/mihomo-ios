import Foundation

extension Sequence where Element == UInt8 {
    /// Lowercase hex, two digits per byte. One buffer instead of a String(format:) + array per byte
    /// (self-review r1: replaces 21 copies of `.ncHex`).
    var ncHex: String {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(underestimatedCount * 2)
        for b in self {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
