import Foundation
import Compression

/// B10 (nc-dego-rest): a minimal ZIP writer (PKWARE APPNOTE 6.3: local headers, central directory, end record;
/// no ZIP64, no encryption) for the diagnostic bundle — what Go's archive/zip did in WriteDiagnosticBundle.
/// Entries are DEFLATE-compressed with the Compression framework (COMPRESSION_ZLIB = raw DEFLATE, RFC 1951) and
/// stored instead when that does not make them smaller. Names are flagged UTF-8 (general purpose bit 11).
struct NCZipWriter {
    private var data = Data()
    private var central = Data()
    private var count = 0
    /// Entries `add` refused because they do not fit a non-ZIP64 archive (see `add`).
    private(set) var skipped: [String] = []

    /// Classic (non-ZIP64) limits: 16-bit entry count / name length, 32-bit sizes and offsets.
    static let maxEntries = Int(UInt16.max)
    static let maxNameBytes = Int(UInt16.max)
    static let max32 = Int(UInt32.max)

    /// Adds one file. `modified` becomes the entry's MS-DOS date / time (local time, 2-second resolution).
    ///
    /// rv2: every narrowing conversion used to be a trapping `UInt32(...)` / `UInt16(...)`; a > 4 GiB archive,
    /// > 65535 entries or a > 64 KiB name crashed the app while exporting diagnostics. An entry that would push
    /// the archive past those limits is now skipped (recorded in `skipped`, returns false) — ZIP64 is not
    /// implemented; diagnostic bundles are far below the limits.
    @discardableResult
    mutating func add(name: String, contents: Data, modified: Date = Date()) -> Bool {
        let nameBytes = Data(name.utf8)
        guard count < Self.maxEntries, nameBytes.count <= Self.maxNameBytes, contents.count <= Self.max32 else {
            skipped.append(name)
            return false
        }
        let crc = NCZipWriter.crc32(contents)
        var method: UInt16 = 0
        var payload = contents
        if let d = NCZipWriter.deflate(contents), d.count < contents.count {
            method = 8
            payload = d
        }
        // Local header (30) + name + payload, then central record (46) + name, then the 22-byte end record:
        // the central directory offset and every entry offset must stay representable in 32 bits.
        let projected = data.count + 30 + nameBytes.count + payload.count + central.count + 46 + nameBytes.count + 22
        guard data.count <= Self.max32, projected <= Self.max32 else {
            skipped.append(name)
            return false
        }
        let (dosTime, dosDate) = NCZipWriter.dosDateTime(modified)
        let offset = UInt32(truncatingIfNeeded: data.count)
        let flags: UInt16 = 0x0800

        var local = Data()
        local.le32(0x04034b50)
        local.le16(20)                       // version needed: 2.0 (deflate)
        local.le16(flags)
        local.le16(method)
        local.le16(dosTime)
        local.le16(dosDate)
        local.le32(crc)
        local.le32(UInt32(truncatingIfNeeded: payload.count))
        local.le32(UInt32(truncatingIfNeeded: contents.count))
        local.le16(UInt16(truncatingIfNeeded: nameBytes.count))
        local.le16(0)                        // extra field length
        local.append(nameBytes)
        data.append(local)
        data.append(payload)

        var c = Data()
        c.le32(0x02014b50)
        c.le16(0x0314)                       // made by: UNIX, 2.0
        c.le16(20)
        c.le16(flags)
        c.le16(method)
        c.le16(dosTime)
        c.le16(dosDate)
        c.le32(crc)
        c.le32(UInt32(truncatingIfNeeded: payload.count))
        c.le32(UInt32(truncatingIfNeeded: contents.count))
        c.le16(UInt16(truncatingIfNeeded: nameBytes.count))
        c.le16(0)                            // extra
        c.le16(0)                            // comment
        c.le16(0)                            // disk number start
        c.le16(0)                            // internal attributes
        c.le32(UInt32(0o100644) << 16)       // external attributes: regular file, rw-r--r--
        c.le32(offset)
        c.append(nameBytes)
        central.append(c)
        count += 1
        return true
    }

    /// The finished archive.
    func finish() -> Data {
        var out = data
        // `add` keeps count / sizes / offsets within the classic limits, so these conversions cannot truncate.
        let cdOffset = UInt32(truncatingIfNeeded: out.count)
        out.append(central)
        out.le32(0x06054b50)
        out.le16(0)                          // this disk
        out.le16(0)                          // disk with the central directory
        out.le16(UInt16(truncatingIfNeeded: count))
        out.le16(UInt16(truncatingIfNeeded: count))
        out.le32(UInt32(truncatingIfNeeded: central.count))
        out.le32(cdOffset)
        out.le16(0)                          // comment length
        return out
    }

    // MARK: helpers

    static func deflate(_ src: Data) -> Data? {
        if src.isEmpty { return nil }
        let cap = src.count + src.count / 8 + 1024
        var dst = Data(count: cap)
        let n = dst.withUnsafeMutableBytes { (d: UnsafeMutableRawBufferPointer) -> Int in
            src.withUnsafeBytes { (s: UnsafeRawBufferPointer) -> Int in
                guard let dp = d.bindMemory(to: UInt8.self).baseAddress,
                      let sp = s.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_encode_buffer(dp, cap, sp, src.count, nil, COMPRESSION_ZLIB)
            }
        }
        if n <= 0 { return nil }
        dst.count = n
        return dst
    }

    private static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
        return c
    }

    static func crc32(_ d: Data) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        d.withUnsafeBytes { (b: UnsafeRawBufferPointer) in
            for byte in b { c = crcTable[Int((c ^ UInt32(byte)) & 0xFF)] ^ (c >> 8) }
        }
        return c ^ 0xFFFFFFFF
    }

    static func dosDateTime(_ date: Date) -> (UInt16, UInt16) {
        let comps = Calendar(identifier: .gregorian).dateComponents(in: .current, from: date)
        // MS-DOS dates cover 1980...2107 (7-bit year); clamp instead of letting the bits spill into the month.
        let y = min(max((comps.year ?? 1980) - 1980, 0), 127)
        let hour: Int = comps.hour ?? 0
        let minute: Int = comps.minute ?? 0
        let second: Int = comps.second ?? 0
        let month: Int = comps.month ?? 1
        let dayOfMonth: Int = comps.day ?? 1
        let timeBits: Int = (hour << 11) | (minute << 5) | (second / 2)
        let dayBits: Int = (y << 9) | (month << 5) | dayOfMonth
        let time = UInt16(truncatingIfNeeded: timeBits)
        let day = UInt16(truncatingIfNeeded: dayBits)
        return (time, day)
    }
}

private extension Data {
    mutating func le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}
