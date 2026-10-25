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

    /// Adds one file. `modified` becomes the entry's MS-DOS date / time (local time, 2-second resolution).
    mutating func add(name: String, contents: Data, modified: Date = Date()) {
        let nameBytes = Data(name.utf8)
        let crc = NCZipWriter.crc32(contents)
        var method: UInt16 = 0
        var payload = contents
        if let d = NCZipWriter.deflate(contents), d.count < contents.count {
            method = 8
            payload = d
        }
        let (dosTime, dosDate) = NCZipWriter.dosDateTime(modified)
        let offset = UInt32(data.count)
        let flags: UInt16 = 0x0800

        var local = Data()
        local.le32(0x04034b50)
        local.le16(20)                       // version needed: 2.0 (deflate)
        local.le16(flags)
        local.le16(method)
        local.le16(dosTime)
        local.le16(dosDate)
        local.le32(crc)
        local.le32(UInt32(payload.count))
        local.le32(UInt32(contents.count))
        local.le16(UInt16(nameBytes.count))
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
        c.le32(UInt32(payload.count))
        c.le32(UInt32(contents.count))
        c.le16(UInt16(nameBytes.count))
        c.le16(0)                            // extra
        c.le16(0)                            // comment
        c.le16(0)                            // disk number start
        c.le16(0)                            // internal attributes
        c.le32(UInt32(0o100644) << 16)       // external attributes: regular file, rw-r--r--
        c.le32(offset)
        c.append(nameBytes)
        central.append(c)
        count += 1
    }

    /// The finished archive.
    func finish() -> Data {
        var out = data
        let cdOffset = UInt32(out.count)
        out.append(central)
        out.le32(0x06054b50)
        out.le16(0)                          // this disk
        out.le16(0)                          // disk with the central directory
        out.le16(UInt16(count))
        out.le16(UInt16(count))
        out.le32(UInt32(central.count))
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
        let y = max((comps.year ?? 1980) - 1980, 0)
        let time = UInt16(((comps.hour ?? 0) << 11) | ((comps.minute ?? 0) << 5) | ((comps.second ?? 0) / 2))
        let day = UInt16((y << 9) | ((comps.month ?? 1) << 5) | (comps.day ?? 1))
        return (time, day)
    }
}

private extension Data {
    mutating func le16(_ v: UInt16) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
    mutating func le32(_ v: UInt32) { var x = v.littleEndian; Swift.withUnsafeBytes(of: &x) { append(contentsOf: $0) } }
}
