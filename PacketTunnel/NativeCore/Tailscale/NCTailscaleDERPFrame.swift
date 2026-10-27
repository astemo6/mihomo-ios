import Foundation

// MARK: - DERP Frame Format & Incremental Codec
//
// Encodes and decodes Tailscale DERP (Designated Encrypted Relay for Packets) frames.
// Reference: `tailscale.com/derp/derp` wire specification.
//
// Wire Frame Layout:
// - Byte 0: 1-byte FrameType (see NCTailscaleConsts.DERPFrameType)
// - Bytes 1..4: 4-byte big-endian uint32 payload length (does NOT include the 5-byte header)
// - Bytes 5..5+N: Payload (length N)
//
// Memory Protection:
// - Single frame payload upper limit: 128 KB (`maxFramePayloadSize = 128 << 10`).
//   Targets process resident memory < 8MB; rejects oversized frames to defend
//   against memory exhaustion attacks or corrupted stream framing.

enum NCDERPFrameError: Error, LocalizedError, Equatable {
    case frameTooLarge(length: Int, limit: Int)
    case payloadTooShort(frame: String, expected: Int, actual: Int)
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidPingPongLength(expected: Int, actual: Int)
    case invalidMagic(Data)

    var errorDescription: String? {
        switch self {
        case .frameTooLarge(let len, let limit):
            return "DERP frame length \(len) exceeds maximum allowed size of \(limit) bytes"
        case .payloadTooShort(let frame, let exp, let act):
            return "DERP frame \(frame) payload too short: expected at least \(exp) bytes, got \(act)"
        case .invalidKeyLength(let exp, let act):
            return "DERP key length mismatch: expected \(exp) bytes, got \(act)"
        case .invalidPingPongLength(let exp, let act):
            return "DERP ping/pong payload length mismatch: expected \(exp) bytes, got \(act)"
        case .invalidMagic(let magic):
            return "DERP server key magic mismatch: got \(magic.count) bytes"
        }
    }
}

// MARK: - DERP Parsed Frame Representation

enum NCDERPFrame: Equatable {
    /// ServerKey (0x01): 8-byte magic + 32-byte server public key (+ optional future bytes).
    case serverKey(magic: Data, serverKey: Data)
    /// ClientInfo (0x02): 32-byte client public key + 24-byte nonce + NaCl box ciphertext.
    case clientInfo(clientKey: Data, nonce: Data, boxedData: Data)
    /// ServerInfo (0x03): 24-byte nonce + NaCl box ciphertext.
    case serverInfo(nonce: Data, boxedData: Data)
    /// SendPacket (0x04): 32-byte destination public key + raw WireGuard packet bytes.
    case sendPacket(destKey: Data, data: Data)
    /// RecvPacket (0x05): 32-byte source public key + raw WireGuard packet bytes.
    case recvPacket(srcKey: Data, data: Data)
    /// KeepAlive (0x06): 0-byte frame used to maintain connection liveness.
    case keepAlive
    /// NotePreferred (0x07): 1-byte boolean (0x01 = preferred home region, 0x00 = non-home).
    case notePreferred(preferred: Bool)
    /// PeerGone (0x08): 32-byte peer public key + 1-byte reason code (0x00=disconnected, 0x01=not here).
    case peerGone(peerKey: Data, reason: UInt8)
    /// PeerPresent (0x09): 32-byte peer public key (+ optional endpoint & flags).
    case peerPresent(peerKey: Data, rawExtra: Data)
    /// ForwardPacket (0x0a): 32-byte src key + 32-byte dst key + packet bytes.
    case forwardPacket(srcKey: Data, destKey: Data, data: Data)
    /// Ping (0x12): 8-byte opaque ping challenge payload.
    case ping(data: Data)
    /// Pong (0x13): 8-byte opaque ping response payload echoing the ping payload.
    case pong(data: Data)
    /// Health (0x14): UTF-8 encoded error status message from server.
    case health(message: String)
    /// Restarting (0x15): Server is restarting (reconnect duration ms, try for ms).
    case restarting(reconnectMs: UInt32, tryForMs: UInt32)
    /// Unknown frame type received from a newer protocol extension.
    case unknown(type: UInt8, payload: Data)
}

// MARK: - DERP Frame Codec

enum NCDERPFrameCodec {
    /// Standard 5-byte DERP frame header length.
    static let headerLength: Int = 5

    /// Hard upper limit on a single DERP frame payload (128 KB).
    /// Prevents unbounded memory allocation in the Network Extension (< 8 MB resident target).
    static let maxFramePayloadSize: Int = 128 * 1024

    /// Maximum packet payload size (64 KB).
    static let maxPacketSize: Int = 64 * 1024

    /// Standard 8-byte DERP ServerKey magic (`DERP🔑` = `0x44 0x45 0x52 0x50 0xf0 0x9f 0x94 0x91`).
    static let serverKeyMagic: Data = Data([0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91])

    /// 32-byte Curve25519 key length.
    static let keyLength: Int = 32

    // MARK: - Frame Encoders

    /// Encoders wrap payload with a 5-byte header: `1 byte type + 4 bytes big-endian length`.
    static func encode(type: NCTailscaleConsts.DERPFrameType, payload: Data = Data()) -> Data {
        encode(typeByte: type.rawValue, payload: payload)
    }

    static func encode(typeByte: UInt8, payload: Data = Data()) -> Data {
        var header = Data(capacity: headerLength + payload.count)
        header.append(typeByte)
        let len = UInt32(payload.count)
        header.append(UInt8(truncatingIfNeeded: len >> 24))
        header.append(UInt8(truncatingIfNeeded: len >> 16))
        header.append(UInt8(truncatingIfNeeded: len >> 8))
        header.append(UInt8(truncatingIfNeeded: len))
        header.append(payload)
        return header
    }

    /// Encodes a ServerKey frame (8B magic + 32B public key).
    static func encodeServerKey(magic: Data = serverKeyMagic, serverKey: Data) -> Data {
        var payload = Data(capacity: magic.count + serverKey.count)
        payload.append(magic)
        payload.append(serverKey)
        return encode(type: .serverKey, payload: payload)
    }

    /// Encodes a ClientInfo frame (32B client key + 24B nonce + boxed JSON).
    static func encodeClientInfo(clientKey: Data, nonce: Data, boxedData: Data) -> Data {
        var payload = Data(capacity: clientKey.count + nonce.count + boxedData.count)
        payload.append(clientKey)
        payload.append(nonce)
        payload.append(boxedData)
        return encode(type: .clientInfo, payload: payload)
    }

    /// Encodes a ServerInfo frame (24B nonce + boxed JSON).
    static func encodeServerInfo(nonce: Data, boxedData: Data) -> Data {
        var payload = Data(capacity: nonce.count + boxedData.count)
        payload.append(nonce)
        payload.append(boxedData)
        return encode(type: .serverInfo, payload: payload)
    }

    /// Encodes a SendPacket frame (32B destination public key + raw packet).
    static func encodeSendPacket(destKey: Data, data: Data) -> Data {
        var payload = Data(capacity: keyLength + data.count)
        payload.append(destKey)
        payload.append(data)
        return encode(type: .sendPacket, payload: payload)
    }

    /// Encodes a RecvPacket frame (32B source public key + raw packet).
    static func encodeRecvPacket(srcKey: Data, data: Data) -> Data {
        var payload = Data(capacity: keyLength + data.count)
        payload.append(srcKey)
        payload.append(data)
        return encode(type: .recvPacket, payload: payload)
    }

    /// Encodes a KeepAlive frame (0-byte payload).
    static func encodeKeepAlive() -> Data {
        encode(type: .keepAlive, payload: Data())
    }

    /// Encodes a NotePreferred frame (1-byte: 0x01 for preferred home, 0x00 otherwise).
    static func encodeNotePreferred(preferred: Bool) -> Data {
        encode(type: .notePreferred, payload: Data([preferred ? 0x01 : 0x00]))
    }

    /// Encodes a PeerGone frame (32B peer key + 1-byte reason).
    static func encodePeerGone(peerKey: Data, reason: UInt8 = 0x00) -> Data {
        var payload = Data(capacity: keyLength + 1)
        payload.append(peerKey)
        payload.append(reason)
        return encode(type: .peerGone, payload: payload)
    }

    /// Encodes a Ping frame (8-byte opaque payload).
    static func encodePing(data: Data) -> Data {
        encode(type: .ping, payload: data)
    }

    /// Encodes a Pong frame (8-byte opaque payload echoing ping).
    static func encodePong(data: Data) -> Data {
        encode(type: .pong, payload: data)
    }

    // MARK: - Frame Parser

    /// Parses a raw payload given its 1-byte frame type.
    /// Supports official wire values as primary and Stage 1 sequential mapping as fallback only where
    /// the old value does not collide with an official type (0x06-0x09 fallbacks were shadowing
    /// KeepAlive/NotePreferred/PeerGone/PeerPresent and are removed).
    static func parseFrame(typeByte: UInt8, payload: Data) throws -> NCDERPFrame {
        switch typeByte {
        case NCTailscaleConsts.DERPFrameType.serverKey.rawValue: // 0x01
            guard payload.count >= 40 else {
                throw NCDERPFrameError.payloadTooShort(frame: "ServerKey", expected: 40, actual: payload.count)
            }
            let magic = payload.subdata(in: 0..<8)
            let key = payload.subdata(in: 8..<40)
            return .serverKey(magic: magic, serverKey: key)

        case NCTailscaleConsts.DERPFrameType.clientInfo.rawValue: // 0x02
            guard payload.count >= 56 else { // 32 key + 24 nonce + tag
                throw NCDERPFrameError.payloadTooShort(frame: "ClientInfo", expected: 56, actual: payload.count)
            }
            let clientKey = payload.subdata(in: 0..<32)
            let nonce = payload.subdata(in: 32..<56)
            let boxed = payload.subdata(in: 56..<payload.count)
            return .clientInfo(clientKey: clientKey, nonce: nonce, boxedData: boxed)

        case NCTailscaleConsts.DERPFrameType.serverInfo.rawValue: // 0x03
            guard payload.count >= 24 else {
                throw NCDERPFrameError.payloadTooShort(frame: "ServerInfo", expected: 24, actual: payload.count)
            }
            let nonce = payload.subdata(in: 0..<24)
            let boxed = payload.subdata(in: 24..<payload.count)
            return .serverInfo(nonce: nonce, boxedData: boxed)

        case NCTailscaleConsts.DERPFrameType.sendPacket.rawValue: // 0x04
            guard payload.count >= 32 else {
                throw NCDERPFrameError.payloadTooShort(frame: "SendPacket", expected: 32, actual: payload.count)
            }
            let destKey = payload.subdata(in: 0..<32)
            let packet = payload.subdata(in: 32..<payload.count)
            return .sendPacket(destKey: destKey, data: packet)

        case NCTailscaleConsts.DERPFrameType.recvPacket.rawValue: // 0x05
            guard payload.count >= 32 else {
                throw NCDERPFrameError.payloadTooShort(frame: "RecvPacket", expected: 32, actual: payload.count)
            }
            let srcKey = payload.subdata(in: 0..<32)
            let packet = payload.subdata(in: 32..<payload.count)
            return .recvPacket(srcKey: srcKey, data: packet)

        case NCTailscaleConsts.DERPFrameType.keepAlive.rawValue: // 0x06
            return .keepAlive

        case NCTailscaleConsts.DERPFrameType.notePreferred.rawValue: // 0x07
            let pref = (payload.first ?? 0) != 0
            return .notePreferred(preferred: pref)

        case NCTailscaleConsts.DERPFrameType.peerGone.rawValue: // 0x08
            guard payload.count >= 32 else {
                throw NCDERPFrameError.payloadTooShort(frame: "PeerGone", expected: 32, actual: payload.count)
            }
            let peerKey = payload.subdata(in: 0..<32)
            let reason = payload.count > 32 ? payload[32] : 0x00
            return .peerGone(peerKey: peerKey, reason: reason)

        case NCTailscaleConsts.DERPFrameType.peerPresent.rawValue: // 0x09
            guard payload.count >= 32 else {
                throw NCDERPFrameError.payloadTooShort(frame: "PeerPresent", expected: 32, actual: payload.count)
            }
            let peerKey = payload.subdata(in: 0..<32)
            let extra = payload.count > 32 ? payload.subdata(in: 32..<payload.count) : Data()
            return .peerPresent(peerKey: peerKey, rawExtra: extra)

        case NCTailscaleConsts.DERPFrameType.forwardPacket.rawValue: // 0x0a
            guard payload.count >= 64 else {
                throw NCDERPFrameError.payloadTooShort(frame: "ForwardPacket", expected: 64, actual: payload.count)
            }
            let srcKey = payload.subdata(in: 0..<32)
            let dstKey = payload.subdata(in: 32..<64)
            let packet = payload.subdata(in: 64..<payload.count)
            return .forwardPacket(srcKey: srcKey, destKey: dstKey, data: packet)

        case NCTailscaleConsts.DERPFrameType.ping.rawValue, 0x0c: // 0x12 (official) or 0x0c (Stage 1 fallback)
            guard payload.count == 8 else {
                throw NCDERPFrameError.invalidPingPongLength(expected: 8, actual: payload.count)
            }
            return .ping(data: payload)

        case NCTailscaleConsts.DERPFrameType.pong.rawValue, 0x0d: // 0x13 (official) or 0x0d (Stage 1 fallback)
            guard payload.count == 8 else {
                throw NCDERPFrameError.invalidPingPongLength(expected: 8, actual: payload.count)
            }
            return .pong(data: payload)

        case NCTailscaleConsts.DERPFrameType.health.rawValue, 0x0e: // 0x14 (official) or 0x0e (Stage 1 fallback)
            let msg = String(data: payload, encoding: .utf8) ?? ""
            return .health(message: msg)

        case NCTailscaleConsts.DERPFrameType.restarting.rawValue, 0x0f: // 0x15 (official) or 0x0f (Stage 1 fallback)
            guard payload.count >= 8 else {
                throw NCDERPFrameError.payloadTooShort(frame: "Restarting", expected: 8, actual: payload.count)
            }
            let recMs = UInt32(payload[0]) << 24 | UInt32(payload[1]) << 16 | UInt32(payload[2]) << 8 | UInt32(payload[3])
            let tryMs = UInt32(payload[4]) << 24 | UInt32(payload[5]) << 16 | UInt32(payload[6]) << 8 | UInt32(payload[7])
            return .restarting(reconnectMs: recMs, tryForMs: tryMs)

        default:
            return .unknown(type: typeByte, payload: payload)
        }
    }
}

// MARK: - Incremental DERP Frame Decoder

/// Stream-oriented incremental decoder for DERP frames.
/// Ingests arbitrary chunk sizes (partial headers, partial payloads, multiple frames per chunk)
/// and emits complete parsed `NCDERPFrame` instances.
final class NCDERPFrameDecoder {
    private var buffer = Data()
    private let maxFrameSize: Int

    init(maxFrameSize: Int = NCDERPFrameCodec.maxFramePayloadSize) {
        self.maxFrameSize = maxFrameSize
    }

    /// Clears any buffered state.
    func reset() {
        buffer.removeAll(keepingCapacity: false)
    }

    /// Ingests a slice of raw bytes received from the TLS stream and returns all completed frames.
    ///
    /// Throws `NCDERPFrameError.frameTooLarge` if a frame length exceeds `maxFrameSize`.
    func feed(_ chunk: Data) throws -> [NCDERPFrame] {
        guard !chunk.isEmpty else { return [] }
        buffer.append(chunk)

        var frames = [NCDERPFrame]()
        var offset = 0

        while buffer.count - offset >= NCDERPFrameCodec.headerLength {
            let typeByte = buffer[buffer.startIndex + offset]
            let lenHi = (UInt32(buffer[buffer.startIndex + offset + 1]) << 24) |
                (UInt32(buffer[buffer.startIndex + offset + 2]) << 16)
            let lenLo = (UInt32(buffer[buffer.startIndex + offset + 3]) << 8) |
                UInt32(buffer[buffer.startIndex + offset + 4])
            let frameLen = Int(lenHi | lenLo)

            if frameLen > maxFrameSize {
                // Protect against malicious frame headers or desynchronized stream
                reset()
                throw NCDERPFrameError.frameTooLarge(length: frameLen, limit: maxFrameSize)
            }

            let totalFrameLen = NCDERPFrameCodec.headerLength + frameLen
            guard buffer.count - offset >= totalFrameLen else {
                // Incomplete frame, await more chunks
                break
            }

            let payloadStart = buffer.startIndex + offset + NCDERPFrameCodec.headerLength
            let payloadEnd = payloadStart + frameLen
            let payload = buffer.subdata(in: payloadStart..<payloadEnd)

            let frame = try NCDERPFrameCodec.parseFrame(typeByte: typeByte, payload: payload)
            frames.append(frame)

            offset += totalFrameLen
        }

        // Compact consumed data and rebase indices
        if offset > 0 {
            if offset >= buffer.count {
                buffer.removeAll(keepingCapacity: false)
            } else {
                buffer = Data(buffer.dropFirst(offset))
            }
        }

        return frames
    }

    // MARK: - Debug Self-Test Verification

    /// Verifies codec round-trip and chunked incremental decoding against test vectors.
    @discardableResult
    static func selfTest() -> Bool {
        let dummyKey1 = Data(repeating: 0xaa, count: 32)
        let dummyKey2 = Data(repeating: 0xbb, count: 32)
        let dummyNonce = Data(repeating: 0xcc, count: 24)
        let dummyBox = Data(repeating: 0xdd, count: 48)
        let dummyPing = Data([1, 2, 3, 4, 5, 6, 7, 8])
        let packetData = Data("WireGuard Payload".utf8)

        let framesToTest: [NCDERPFrame] = [
            .serverKey(magic: NCDERPFrameCodec.serverKeyMagic, serverKey: dummyKey1),
            .clientInfo(clientKey: dummyKey1, nonce: dummyNonce, boxedData: dummyBox),
            .serverInfo(nonce: dummyNonce, boxedData: dummyBox),
            .sendPacket(destKey: dummyKey2, data: packetData),
            .recvPacket(srcKey: dummyKey1, data: packetData),
            .keepAlive,
            .notePreferred(preferred: true),
            .peerGone(peerKey: dummyKey1, reason: 0x01),
            .ping(data: dummyPing),
            .pong(data: dummyPing),
            .health(message: "Duplicate connection"),
        ]

        var streamData = Data()
        for f in framesToTest {
            switch f {
            case .serverKey(let magic, let key):
                streamData.append(NCDERPFrameCodec.encodeServerKey(magic: magic, serverKey: key))
            case .clientInfo(let key, let nonce, let box):
                streamData.append(NCDERPFrameCodec.encodeClientInfo(clientKey: key, nonce: nonce, boxedData: box))
            case .serverInfo(let nonce, let box):
                streamData.append(NCDERPFrameCodec.encodeServerInfo(nonce: nonce, boxedData: box))
            case .sendPacket(let dst, let d):
                streamData.append(NCDERPFrameCodec.encodeSendPacket(destKey: dst, data: d))
            case .recvPacket(let src, let d):
                streamData.append(NCDERPFrameCodec.encodeRecvPacket(srcKey: src, data: d))
            case .keepAlive:
                streamData.append(NCDERPFrameCodec.encodeKeepAlive())
            case .notePreferred(let pref):
                streamData.append(NCDERPFrameCodec.encodeNotePreferred(preferred: pref))
            case .peerGone(let key, let reason):
                streamData.append(NCDERPFrameCodec.encodePeerGone(peerKey: key, reason: reason))
            case .ping(let d):
                streamData.append(NCDERPFrameCodec.encodePing(data: d))
            case .pong(let d):
                streamData.append(NCDERPFrameCodec.encodePong(data: d))
            case .health(let msg):
                streamData.append(NCDERPFrameCodec.encode(type: .health, payload: Data(msg.utf8)))
            default:
                break
            }
        }

        // Test arbitrary chunked feeding (1 byte, 3 bytes, 7 bytes, 15 bytes)
        let decoder = NCDERPFrameDecoder()
        var decodedFrames = [NCDERPFrame]()
        let chunkSizes = [1, 3, 7, 15, 2, 4, 11]
        var streamOffset = 0
        var chunkSizeIndex = 0

        while streamOffset < streamData.count {
            let size = min(chunkSizes[chunkSizeIndex % chunkSizes.count], streamData.count - streamOffset)
            let chunk = streamData.subdata(in: streamOffset..<(streamOffset + size))
            guard let frames = try? decoder.feed(chunk) else {
                return false
            }
            decodedFrames.append(contentsOf: frames)
            streamOffset += size
            chunkSizeIndex += 1
        }

        guard decodedFrames.count == framesToTest.count else {
            return false
        }

        for i in 0..<framesToTest.count {
            if decodedFrames[i] != framesToTest[i] {
                return false
            }
        }

        // Test oversize frame rejection
        let badHeader = Data([0x04, 0x00, 0x10, 0x00, 0x01]) // 1MB + 1 length
        decoder.reset()
        do {
            _ = try decoder.feed(badHeader)
            return false // Should have thrown
        } catch {
            // Expected rejection
        }

        return true
    }
}
