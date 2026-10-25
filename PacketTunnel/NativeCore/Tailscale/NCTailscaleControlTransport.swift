import CryptoKit
import Foundation

// MARK: - Tailscale Transport Errors

enum NCTailscaleTransportError: Error, LocalizedError {
    case invalidHTTPResponse(String)
    case unexpectedHTTPStatus(Int, String)
    case invalidHandshakeFrame(String)
    case serverError(String)
    case invalidRecordType(UInt8)
    case recordTooLarge(Int)
    case decryptionFailed
    case streamClosed

    var errorDescription: String? {
        switch self {
        case .invalidHTTPResponse(let msg):
            return "Invalid HTTP response: \(msg)"
        case .unexpectedHTTPStatus(let code, let msg):
            return "Unexpected HTTP status \(code): \(msg)"
        case .invalidHandshakeFrame(let msg):
            return "Invalid ts2021 handshake frame: \(msg)"
        case .serverError(let msg):
            return "Tailscale control server error: \(msg)"
        case .invalidRecordType(let t):
            return "Unexpected ts2021 record type \(t) (expected 0x04)"
        case .recordTooLarge(let sz):
            return "ts2021 record size \(sz) exceeds max allowed 4096"
        case .decryptionFailed:
            return "ts2021 record decryption failed"
        case .streamClosed:
            return "ts2021 transport stream closed"
        }
    }
}

// MARK: - Minimal HTTP/1.1 Response Parser
//
// Self-contained parser for HTTP/1.1 responses during control plane bootstrapping:
// 1. `GET /key?v=106` -> HTTP 200 OK with Content-Length or Chunked JSON body.
// 2. `POST /ts2021` Upgrade -> HTTP 101 Switching Protocols; immediately hands off
//    any trailing bytes after `\r\n\r\n` to the ts2021 Noise framing layer.

final class NCHTTP1ResponseParser {
    private(set) var statusCode: Int = 0
    private(set) var statusText: String = ""
    private(set) var headers: [String: String] = [:]
    private(set) var body = Data()
    private(set) var trailingData = Data()
    private(set) var isComplete: Bool = false

    private var buffer = Data()
    private var headersParsed = false
    private var isChunked = false
    private var contentLength: Int?

    init() {}

    /// Feeds incoming raw bytes into the parser. Returns true once the response is fully parsed.
    func feed(_ data: Data) throws -> Bool {
        guard !isComplete else {
            trailingData.append(data)
            return true
        }

        buffer.append(data)

        if !headersParsed {
            guard let headerEndRange = findHeaderTerminator(in: buffer) else {
                return false
            }

            let headerBytes = buffer.subdata(in: 0..<headerEndRange.lowerBound)
            let bodyStart = headerEndRange.upperBound
            try parseHeaders(headerBytes)
            headersParsed = true

            // HTTP 101 Switching Protocols: headers end the HTTP portion.
            // All remaining bytes belong to the upgraded protocol.
            if statusCode == 101 {
                isComplete = true
                if bodyStart < buffer.count {
                    trailingData = buffer.subdata(in: bodyStart..<buffer.count)
                }
                buffer.removeAll(keepingCapacity: false)
                return true
            }

            // Prepare for body reading
            if let ce = headers["transfer-encoding"], ce.lowercased().contains("chunked") {
                isChunked = true
            } else if let clStr = headers["content-length"], let cl = Int(clStr.trimmingCharacters(in: .whitespaces)) {
                // a negative length made subdata(in: 0..<cl) an inverted range (trap)
                guard cl >= 0 else { throw NCTailscaleTransportError.invalidHTTPResponse("Invalid Content-Length: \(clStr)") }
                contentLength = cl
            }

            buffer.removeSubrange(0..<bodyStart)
        }

        // Parse body
        if isChunked {
            try parseChunkedBody()
        } else if let cl = contentLength {
            if buffer.count >= cl {
                body.append(buffer.subdata(in: 0..<cl))
                if buffer.count > cl {
                    trailingData = buffer.subdata(in: cl..<buffer.count)
                }
                buffer.removeAll(keepingCapacity: false)
                isComplete = true
            }
        } else if statusCode == 204 || statusCode == 304 {
            // No body
            trailingData = buffer
            buffer.removeAll(keepingCapacity: false)
            isComplete = true
        }

        return isComplete
    }

    private func findHeaderTerminator(in data: Data) -> Range<Int>? {
        let crlf = Data([0x0d, 0x0a, 0x0d, 0x0a]) // \r\n\r\n
        if let r = data.range(of: crlf) {
            return r
        }
        let lf = Data([0x0a, 0x0a]) // \n\n fallback
        if let r = data.range(of: lf) {
            return r
        }
        return nil
    }

    private func parseHeaders(_ data: Data) throws {
        guard let text = String(data: data, encoding: .utf8) else {
            throw NCTailscaleTransportError.invalidHTTPResponse("Headers are not valid UTF-8")
        }

        let lines = text.components(separatedBy: "\n").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }

        guard let statusLine = lines.first else {
            throw NCTailscaleTransportError.invalidHTTPResponse("Empty HTTP response")
        }

        // Format: HTTP/1.1 200 OK
        let statusParts = statusLine.components(separatedBy: " ")
        guard statusParts.count >= 2, let code = Int(statusParts[1]) else {
            throw NCTailscaleTransportError.invalidHTTPResponse("Invalid status line: \(statusLine)")
        }

        self.statusCode = code
        self.statusText = statusParts.count > 2 ? statusParts[2...].joined(separator: " ") : ""

        for line in lines.dropFirst() {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            headers[key] = val
        }
    }

    private func parseChunkedBody() throws {
        while !buffer.isEmpty {
            let crlf = Data([0x0d, 0x0a])
            guard let lineRange = buffer.range(of: crlf) else { break }

            let sizeLineData = buffer.subdata(in: 0..<lineRange.lowerBound)
            guard let sizeLine = String(data: sizeLineData, encoding: .utf8)?.trimmingCharacters(in: .whitespaces) else {
                throw NCTailscaleTransportError.invalidHTTPResponse("Invalid chunk size line")
            }

            let hexStr = sizeLine.components(separatedBy: ";")[0].trimmingCharacters(in: .whitespaces)
            // Int(_:radix:) accepts a sign ("-5") and sizes up to Int.max: a negative size inverted the slice
            // range and a huge one overflowed chunkDataStart + chunkSize — both traps on server input.
            guard let chunkSize = Int(hexStr, radix: 16), chunkSize >= 0,
                  chunkSize <= Int.max - lineRange.upperBound - 2 else {
                throw NCTailscaleTransportError.invalidHTTPResponse("Malformed chunk size hex: \(hexStr)")
            }

            if chunkSize == 0 {
                // Final chunk; consume trailing \r\n\r\n if present
                let rest = buffer.subdata(in: lineRange.upperBound..<buffer.count)
                if let trailerRange = rest.range(of: crlf) {
                    let endOfChunked = lineRange.upperBound + trailerRange.upperBound
                    if endOfChunked < buffer.count {
                        trailingData = buffer.subdata(in: endOfChunked..<buffer.count)
                    }
                    buffer.removeAll(keepingCapacity: false)
                }
                isComplete = true
                return
            }

            let chunkDataStart = lineRange.upperBound
            let chunkDataEnd = chunkDataStart + chunkSize
            let chunkTotalEnd = chunkDataEnd + 2 // include trailing \r\n

            guard buffer.count >= chunkTotalEnd else {
                // Wait for full chunk
                break
            }

            body.append(buffer.subdata(in: chunkDataStart..<chunkDataEnd))
            buffer.removeSubrange(0..<chunkTotalEnd)
        }
    }
}

// MARK: - Tailscale Controlbase Framing (ts2021)
//
// Implements the exact message framing defined in official Tailscale `control/controlbase`:
//
// - Handshake Initiation (Message 1):
//   5-byte header: uint16 protocolVersion (106), uint8 msgTypeInitiation (1), uint16 length (96)
//   followed by 96-byte Noise IK Message 1. Total: 101 bytes.
// - Handshake Response (Message 2):
//   3-byte header: uint8 msgTypeResponse (2), uint16 length (48)
//   followed by 48-byte Noise IK Message 2. Total: 51 bytes.
// - Error Message:
//   3-byte header: uint8 msgTypeError (3), uint16 length, followed by error text.
// - Encrypted Record:
//   3-byte header: uint8 msgTypeRecord (4), uint16 length (ciphertext + 16-byte Poly1305 tag)
//   followed by encrypted payload. Max record size: 4096 bytes.

enum NCTailscaleControlFraming {
    static let msgTypeInitiation: UInt8 = 1
    static let msgTypeResponse: UInt8 = 2
    static let msgTypeError: UInt8 = 3
    static let msgTypeRecord: UInt8 = 4

    static let headerLen: Int = 3
    static let initiationHeaderLen: Int = 5
    static let maxMessageSize: Int = 4096
    static let maxPlaintextSize: Int = 4077 // 4096 - 3 header - 16 chacha tag

    /// Constructs the 101-byte handshake initiation frame to embed into `X-Tailscale-Handshake` (base64)
    /// or send directly on the wire.
    static func makeInitiationFrame(
        protocolVersion: UInt16 = UInt16(NCTailscaleConsts.capabilityVersion),
        noiseMsg1: Data
    ) -> Data {
        var frame = Data(capacity: initiationHeaderLen + noiseMsg1.count)
        frame.append(UInt8((protocolVersion >> 8) & 0xff))
        frame.append(UInt8(protocolVersion & 0xff))
        frame.append(msgTypeInitiation)
        let len = UInt16(noiseMsg1.count)
        frame.append(UInt8((len >> 8) & 0xff))
        frame.append(UInt8(len & 0xff))
        frame.append(noiseMsg1)
        return frame
    }

    /// Parses a handshake response frame (Message 2 or Error) from the buffer.
    /// Returns the 48-byte Noise Message 2 payload when complete, or nil if more data is needed.
    static func parseResponseMessage(from buffer: inout Data) throws -> Data? {
        guard buffer.count >= headerLen else { return nil }

        let type = buffer[0]
        let len = (Int(buffer[1]) << 8) | Int(buffer[2])
        let totalSize = headerLen + len

        guard buffer.count >= totalSize else { return nil }

        if type == msgTypeError {
            let errorBytes = buffer.subdata(in: headerLen..<totalSize)
            buffer.removeSubrange(0..<totalSize)
            let errMsg = String(data: errorBytes, encoding: .utf8) ?? "Unknown server error"
            throw NCTailscaleTransportError.serverError(errMsg)
        }

        guard type == msgTypeResponse else {
            throw NCTailscaleTransportError.invalidHandshakeFrame("Unexpected handshake frame type: \(type)")
        }

        guard len == 48 else {
            throw NCTailscaleTransportError.invalidHandshakeFrame("Expected 48-byte response payload, got \(len)")
        }

        let payload = buffer.subdata(in: headerLen..<totalSize)
        buffer.removeSubrange(0..<totalSize)
        return payload
    }

    /// Wraps plaintext into one or more ts2021 `msgTypeRecord` frames (max 4077 bytes plaintext per frame).
    static func makeRecordFrames(plaintext: Data, cipher: NCTransportCipher) throws -> Data {
        var out = Data()
        var offset = 0

        while offset < plaintext.count {
            let chunkSize = min(plaintext.count - offset, maxPlaintextSize)
            let chunk = plaintext.subdata(in: offset..<(offset + chunkSize))
            offset += chunkSize

            let encrypted = try cipher.encrypt(chunk)
            let totalLen = encrypted.count
            guard totalLen <= UInt16.max else {
                throw NCTailscaleTransportError.recordTooLarge(totalLen)
            }

            out.append(msgTypeRecord)
            out.append(UInt8((totalLen >> 8) & 0xff))
            out.append(UInt8(totalLen & 0xff))
            out.append(encrypted)
        }

        return out
    }

    /// Parses and decrypts all complete `msgTypeRecord` frames currently available in `buffer`.
    static func parseRecordFrames(from buffer: inout Data, cipher: NCTransportCipher) throws -> [Data] {
        var decryptedChunks: [Data] = []

        while buffer.count >= headerLen {
            let type = buffer[0]
            guard type == msgTypeRecord else {
                throw NCTailscaleTransportError.invalidRecordType(type)
            }

            let len = (Int(buffer[1]) << 8) | Int(buffer[2])
            guard len <= maxMessageSize - headerLen else {
                throw NCTailscaleTransportError.recordTooLarge(len)
            }

            let totalSize = headerLen + len
            guard buffer.count >= totalSize else {
                // Incomplete frame; await more bytes
                break
            }

            let encrypted = buffer.subdata(in: headerLen..<totalSize)
            buffer.removeSubrange(0..<totalSize)

            do {
                let decrypted = try cipher.decrypt(encrypted)
                decryptedChunks.append(decrypted)
            } catch {
                throw NCTailscaleTransportError.decryptionFailed
            }
        }

        return decryptedChunks
    }

    /// Strips the optional ts2021 "early payload" (`\xff\xff\xffTS` + 4-byte big-endian length) if present
    /// at the start of the decrypted stream before HTTP/2 framing begins.
    ///
    /// Reference: `tailscale.com/control/ts2021/conn.go` `EarlyPayloadMagic = "\xff\xff\xffTS"`.
    static func filterEarlyPayload(from streamData: inout Data, checked: inout Bool) -> Data? {
        if checked { return nil }

        // Needs at least 9 bytes (5 bytes magic + 4 bytes length)
        guard streamData.count >= 9 else { return nil }

        let magic = Data([0xff, 0xff, 0xff, 0x54, 0x53]) // \xff\xff\xffTS
        if streamData.prefix(5) == magic {
            let len = (Int(streamData[5]) << 24) |
                      (Int(streamData[6]) << 16) |
                      (Int(streamData[7]) << 8) |
                      Int(streamData[8])
            let total = 9 + len
            guard streamData.count >= total else {
                // Wait for the complete early payload JSON
                return nil
            }
            let earlyJSON = streamData.subdata(in: 9..<total)
            streamData.removeSubrange(0..<total)
            checked = true
            return earlyJSON
        } else {
            // No early payload present; immediate HTTP/2 stream
            checked = true
            return nil
        }
    }
}

// MARK: - Incremental MapResponse JSON Scanner
//
// Scans an incoming HTTP/2 DATA byte stream and cuts individual JSON `MapResponse` objects.
// Correctly handles:
// 1. Official 4-byte little-endian length prefixed frames (Headscale & Tailscale wire format).
// 2. Direct streaming JSON objects without length prefix.
// 3. Single JSON objects spanning multiple DATA frames.
// 4. Multiple JSON objects arriving in a single DATA frame.
// 5. Intervening whitespace / keepalive newlines.

final class NCTailscaleMapResponseScanner {
    private var buffer = Data()

    init() {}

    func append(_ data: Data) {
        buffer.append(data)
    }

    /// Extracts the next complete MapResponse JSON data if available.
    func nextResponseData() -> Data? {
        while !buffer.isEmpty {
            // Trim leading whitespace
            while let first = buffer.first, first == 0x20 || first == 0x09 || first == 0x0a || first == 0x0d {
                buffer = Data(buffer.dropFirst()) // re-base: Data.removeFirst() shifts startIndex
            }
            guard !buffer.isEmpty else { return nil }

            // Check for 4-byte little endian length prefix (Tailscale / Headscale wire format)
            if buffer.count >= 4 {
                let len = Int(buffer[0]) |
                          (Int(buffer[1]) << 8) |
                          (Int(buffer[2]) << 16) |
                          (Int(buffer[3]) << 24)

                // Sanity check: valid positive length below 16 MB
                if len > 0 && len <= 16 * 1024 * 1024 && buffer.count >= 4 + len {
                    let candidate = buffer.subdata(in: 4..<(4 + len))
                    if let firstNonWs = candidate.first(where: { $0 != 0x20 && $0 != 0x09 && $0 != 0x0a && $0 != 0x0d }),
                       firstNonWs == UInt8(ascii: "{") {
                        buffer.removeSubrange(0..<(4 + len))
                        return candidate
                    }
                }
            }

            // Fallback: incremental brace matching from the first '{'
            guard let first = buffer.first, first == UInt8(ascii: "{") else {
                // Drop non-JSON byte to realign
                buffer = Data(buffer.dropFirst()) // re-base: Data.removeFirst() shifts startIndex
                continue
            }

            var depth = 0
            var inString = false
            var escaped = false
            var foundEnd: Int? = nil

            for (idx, byte) in buffer.enumerated() {
                if inString {
                    if escaped {
                        escaped = false
                    } else if byte == UInt8(ascii: "\\") {
                        escaped = true
                    } else if byte == UInt8(ascii: "\"") {
                        inString = false
                    }
                } else {
                    if byte == UInt8(ascii: "\"") {
                        inString = true
                    } else if byte == UInt8(ascii: "{") {
                        depth += 1
                    } else if byte == UInt8(ascii: "}") {
                        depth -= 1
                        if depth == 0 {
                            foundEnd = idx + 1
                            break
                        }
                    }
                }
            }

            if let end = foundEnd {
                let objData = buffer.subdata(in: 0..<end)
                buffer.removeSubrange(0..<end)
                return objData
            } else {
                // Incomplete object, wait for more data
                return nil
            }
        }
        return nil
    }

    /// Resets the internal read buffer.
    func reset() {
        buffer.removeAll(keepingCapacity: false)
    }
}
