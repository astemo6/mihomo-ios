import Foundation

/// VLESS flow `xtls-rprx-vision` — pure-logic port of mihomo's
/// transport/vless/vision (padding.go / conn.go / filter.go).
///
/// The stream is reframed into padding frames:
///   [16B UUID — first frame only][1B command][u16be contentLen]
///   [u16be paddingLen][content][padding]
/// Commands: 0x00 continue, 0x01 end (stop framing, pass through),
/// 0x02 direct (stop framing; caller may splice sockets). While framing is
/// active, both directions run a TLS-shape filter over the plaintext: once
/// the inner flow is recognized as TLS application data, the writer ends
/// framing (or goes direct when the ServerHello proved TLS 1.3 with an
/// XTLS-capable cipher).
///
/// These types are stream-free state machines over [UInt8]; the connector
/// layer feeds them from / drains them to a relay stream.
enum NCVision {
    static let commandContinue: UInt8 = 0x00
    static let commandEnd: UInt8 = 0x01
    static let commandDirect: UInt8 = 0x02

    static let uuidLength = 16
    static let paddingHeaderLength = uuidLength + 1 + 2 + 2 // 21 with UUID, 5 without
    static let bufferSize = 8192 // xrayBufSize

    static let tlsClientHandshakeStart: [UInt8] = [0x16, 0x03]
    static let tlsServerHandshakeStart: [UInt8] = [0x16, 0x03, 0x03]
    static let tlsApplicationDataStart: [UInt8] = [0x17, 0x03, 0x03]
    static let tls13SupportedVersions: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    /// TLS 1.3 suites from mihomo's map, minus TLS_AES_128_CCM_8_SHA256
    /// (0x1305), which the map lookup explicitly rejects.
    static let tls13CipherSuites: Set<UInt16> = [0x1301, 0x1302, 0x1303, 0x1304]

    static func u16be(_ bytes: [UInt8], _ offset: Int) -> Int {
        (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
    }

    static func firstIndex(of pattern: [UInt8], in bytes: [UInt8]) -> Int? {
        guard !pattern.isEmpty, bytes.count >= pattern.count else { return nil }
        for i in 0...(bytes.count - pattern.count) {
            if Array(bytes[i..<(i + pattern.count)]) == pattern { return i }
        }
        return nil
    }

    static func lastIndex(of pattern: [UInt8], in bytes: [UInt8]) -> Int? {
        guard !pattern.isEmpty, bytes.count >= pattern.count else { return nil }
        var i = bytes.count - pattern.count
        while i >= 0 {
            if Array(bytes[i..<(i + pattern.count)]) == pattern { return i }
            i -= 1
        }
        return nil
    }

    static func contains(_ pattern: [UInt8], in bytes: [UInt8]) -> Bool {
        firstIndex(of: pattern, in: bytes) != nil
    }
}

enum NCVisionError: Error, Equatable {
    /// First server frame carried a UUID different from the user's.
    case unknownServerUUID
    /// Server sent a padding command other than continue/end/direct.
    case unknownCommand(UInt8)
}

/// Port of filter.go's FilterTLS: watches the first few buffers of the
/// plaintext flow and classifies it (TLS? TLS 1.2+ ServerHello seen? TLS 1.3
/// with an XTLS-capable cipher?). One instance per direction; a caller that
/// wants mihomo's exact shared-state behavior may share one instance
/// between its writer and reader.
final class NCVisionFilter {
    private(set) var packetsToFilter = 8
    private(set) var isTLS = false
    private(set) var isTLS12orAbove = false
    private(set) var enableXTLS = false
    private(set) var cipher: UInt16 = 0
    private var remainingServerHello = 0

    func filter(_ bytes: [UInt8]) {
        if packetsToFilter <= 0 { return }
        let lenP = bytes.count
        packetsToFilter -= 1
        var index = -1
        if let idx = NCVision.firstIndex(of: NCVision.tlsServerHandshakeStart, in: bytes) {
            index = idx
            if lenP > index + 5 {
                // Go checks the record start at the buffer head, not at idx.
                if bytes[0] == 0x16, bytes[1] == 0x03, bytes[2] == 0x03 {
                    isTLS = true
                    if bytes[5] == 0x02 { // ServerHello handshake type
                        remainingServerHello = NCVision.u16be(bytes, index + 3) + 5
                        isTLS12orAbove = true
                        if lenP - index >= 79, remainingServerHello >= 79 {
                            let sessionIDLen = Int(bytes[index + 43])
                            let cipherOffset = index + 43 + sessionIDLen + 1
                            if cipherOffset + 2 <= lenP {
                                cipher = UInt16(NCVision.u16be(bytes, cipherOffset))
                            }
                        }
                    }
                }
            }
        } else if let idx = NCVision.firstIndex(of: NCVision.tlsClientHandshakeStart, in: bytes) {
            index = idx
            if lenP > index + 5, bytes[index + 5] == 0x01 { // ClientHello
                isTLS = true
            }
        }

        if remainingServerHello > 0 {
            var end = remainingServerHello
            var i = index
            if i < 0 { i = 0 }
            if i + end > lenP {
                end = lenP
                remainingServerHello -= (end - i)
            } else {
                remainingServerHello -= end
                end += i
            }
            let span = (i <= end && end <= lenP) ? Array(bytes[i..<end]) : []
            if NCVision.contains(NCVision.tls13SupportedVersions, in: span) {
                if NCVision.tls13CipherSuites.contains(cipher) {
                    enableXTLS = true
                }
                packetsToFilter = 0
                return
            } else if remainingServerHello <= 0 {
                // Full ServerHello seen without supported_versions: TLS 1.2.
                packetsToFilter = 0
                return
            }
        }
    }
}

/// Port of conn.go's WriteBuffer: frames outgoing plaintext (the first
/// chunk carries the VLESS request head) until the filter decides the flow
/// can continue unframed (end) or spliced (direct).
final class NCVisionWriter {
    let userUUID: [UInt8]
    let filter = NCVisionFilter()
    /// Randomness for padding lengths: returns a value in [0, n), mirroring
    /// randv2.Int32N. Tests pin this for deterministic frames.
    var randomBelow: (Int) -> Int = { Int.random(in: 0..<$0) }

    private var writeOnceUserUUID: [UInt8]?
    /// True while padding framing is applied (writeFilterApplicationData).
    private(set) var isFiltering = true
    /// True once commandDirect was emitted (writeDirect).
    private(set) var isDirect = false

    init(userUUID: [UInt8]) {
        self.userUUID = userUUID
        self.writeOnceUserUUID = userUUID
    }

    /// Frame one outgoing chunk; returns the wire pieces to write in order.
    /// After framing stops, chunks pass through untouched.
    func process(_ chunk: [UInt8]) -> [[UInt8]] {
        guard isFiltering else { return [chunk] }
        if chunk.isEmpty {
            // Long padding to hide the VLESS header (Go's empty-write path,
            // paddingTLS hardcoded true).
            return [applyPadding(content: [], command: NCVision.commandContinue, paddingTLS: true)]
        }
        filter.filter(chunk)
        var out: [[UInt8]] = []
        var usePadding = true
        for sub in Self.reshape(chunk) {
            if usePadding {
                var command = NCVision.commandContinue
                if filter.isTLS, sub.count > 6,
                   Array(sub[0..<3]) == NCVision.tlsApplicationDataStart {
                    command = NCVision.commandEnd
                    if filter.enableXTLS {
                        command = NCVision.commandDirect
                        isDirect = true
                    }
                    isFiltering = false
                    usePadding = false
                } else if !filter.isTLS12orAbove, filter.packetsToFilter <= 1 {
                    command = NCVision.commandEnd
                    isFiltering = false
                    usePadding = false
                }
                out.append(applyPadding(content: sub, command: command, paddingTLS: filter.isTLS))
            } else {
                out.append(sub)
            }
        }
        return out
    }

    /// padding.go's ApplyPadding. Padding bytes are zeros (the reader
    /// discards them unread, matching Go semantics).
    private func applyPadding(content: [UInt8], command: UInt8, paddingTLS: Bool) -> [UInt8] {
        let contentLen = content.count
        var paddingLen = 0
        if contentLen < 900 {
            if paddingTLS {
                paddingLen = randomBelow(500) + 900 - contentLen
            } else {
                paddingLen = randomBelow(256)
            }
        }
        var out: [UInt8] = []
        out.reserveCapacity(NCVision.paddingHeaderLength + contentLen + paddingLen)
        if let uuid = writeOnceUserUUID {
            out += uuid
            writeOnceUserUUID = nil
        }
        out.append(command)
        out.append(UInt8((contentLen >> 8) & 0xff))
        out.append(UInt8(contentLen & 0xff))
        out.append(UInt8((paddingLen >> 8) & 0xff))
        out.append(UInt8(paddingLen & 0xff))
        out += content
        out += [UInt8](repeating: 0, count: paddingLen)
        return out
    }

    /// padding.go's ReshapeBuffer: split chunks >= 8192-21 at the last TLS
    /// application-data record start (must land in (21, limit], else halve).
    private static func reshape(_ chunk: [UInt8]) -> [[UInt8]] {
        let limit = NCVision.bufferSize - NCVision.paddingHeaderLength
        if chunk.count < limit { return [chunk] }
        var buffers: [[UInt8]] = []
        var rest = chunk
        while rest.count >= limit {
            var cutAt = NCVision.lastIndex(of: NCVision.tlsApplicationDataStart, in: rest) ?? -1
            if cutAt < 21 || cutAt > limit {
                cutAt = NCVision.bufferSize / 2
            }
            buffers.append(Array(rest[0..<cutAt]))
            rest = Array(rest[cutAt...])
        }
        buffers.append(rest)
        return buffers
    }
}

/// Port of conn.go's ReadBuffer: parses padding frames out of the incoming
/// stream and yields plaintext. After an end/direct frame's content is
/// delivered, everything else passes through raw.
struct NCVisionReader {
    let userUUID: [UInt8]
    let filter = NCVisionFilter()

    /// True once framing ended (end or direct command): bytes pass through.
    private(set) var passthrough = false
    /// True when the server chose commandDirect — the caller may splice the
    /// underlying sockets from this point on.
    private(set) var directRequested = false

    private var buffer: [UInt8] = []
    private var readFilterUUID = true
    private var readLastCommand: UInt8 = NCVision.commandContinue
    private var remainingContent = 0
    private var remainingPadding = 0

    init(userUUID: [UInt8]) {
        self.userUUID = userUUID
    }

    /// Feed raw stream bytes; returns the plaintext pieces ready to deliver.
    mutating func feed(_ bytes: [UInt8]) throws -> [[UInt8]] {
        buffer += bytes
        var out: [[UInt8]] = []
        while true {
            if remainingContent > 0 {
                if buffer.isEmpty { break }
                let n = min(remainingContent, buffer.count)
                let chunk = Array(buffer[0..<n])
                buffer.removeFirst(n)
                remainingContent -= n
                filter.filter(chunk) // Go filters delivered content too
                out.append(chunk)
                continue
            }
            if remainingPadding > 0 {
                if buffer.isEmpty { break }
                let n = min(remainingPadding, buffer.count)
                buffer.removeFirst(n)
                remainingPadding -= n
                continue
            }
            if passthrough {
                if !buffer.isEmpty {
                    out.append(buffer)
                    buffer = []
                }
                break
            }
            switch readLastCommand {
            case NCVision.commandContinue:
                let need = readFilterUUID
                    ? NCVision.paddingHeaderLength
                    : NCVision.paddingHeaderLength - NCVision.uuidLength
                if buffer.count < need { return out }
                var header = Array(buffer[0..<need])
                buffer.removeFirst(need)
                if readFilterUUID {
                    readFilterUUID = false
                    guard Array(header[0..<NCVision.uuidLength]) == userUUID else {
                        throw NCVisionError.unknownServerUUID
                    }
                    header.removeFirst(NCVision.uuidLength)
                }
                readLastCommand = header[0]
                remainingContent = NCVision.u16be(header, 1)
                remainingPadding = NCVision.u16be(header, 3)
            case NCVision.commandEnd:
                passthrough = true
            case NCVision.commandDirect:
                // Go drains the TLS layer's decrypted leftovers, then reads
                // the raw socket; here the buffered bytes simply become the
                // passthrough payload.
                passthrough = true
                directRequested = true
            default:
                throw NCVisionError.unknownCommand(readLastCommand)
            }
        }
        return out
    }
}
