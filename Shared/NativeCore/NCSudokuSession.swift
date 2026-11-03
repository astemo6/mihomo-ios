import Foundation
import CryptoKit
import Network
import Security

/// Pure-Swift clean-room data plane implementation of the Sudoku protocol (S2).
///
/// Clean-room specification references:
/// - doc/README.md § Protocol (Layers & Principle)
/// - doc/README.md § Protocol (Wire Formats) - Record layer (AEAD framing)
/// - doc/README.md § Protocol (Wire Formats) - KIP message (control plane)
/// - doc/README.md § ClientHello payload & ServerHello payload
/// - doc/README.md § Address encoding (SOCKS5 style)
/// - doc/README.md § UoT datagram frames (UDP-over-TCP)
/// - doc/README.md § How the Sudoku layer hides bytes
/// - README.md § True Arbitrary Padding & Sudoku Steganography Algorithm
/// - configs/README.md § HTTP masking / HTTP tunnel
///
/// Designed with zero third-party dependencies using standard Apple Foundation & CryptoKit.
enum NCSudokuSession {

    /// Starts a Sudoku outbound proxy session over `raw`, completing with an `NCRelayStream` ready for traffic.
    static func connect(raw: NCRelayStream, proxy: NCProxy, target: NCTarget,
                        queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let relay = NCSudokuRelay(raw: raw, proxy: proxy, target: target, queue: queue)
        relay.handshake(completion: completion)
    }
}

// MARK: - KIP Control Plane Framing

enum NCSudokuKIP {
    static let magic = Data([0x6b, 0x69, 0x70]) // "kip" in ASCII

    enum MessageType: UInt8 {
        case clientHello = 0x01
        case serverHello = 0x02
        case openTCP     = 0x10
        case startMux    = 0x11
        case startUoT    = 0x12
        case keepAlive   = 0x14
    }

    /// Wraps payload in a standard KIP frame: "kip" (3B) + type (1B) + payload_len (2B BE) + payload.
    static func buildMessage(type: MessageType, payload: Data) -> Data {
        var out = Data(capacity: 6 + payload.count)
        out.append(magic)
        out.append(type.rawValue)
        let len = UInt16(clamping: payload.count)
        out.append(UInt8(len >> 8))
        out.append(UInt8(len & 0xff))
        out.append(payload)
        return out
    }

    /// Builds a ClientHello payload:
    /// - timestamp (8 bytes uint64 BE)
    /// - user_hash (8 bytes: first 8 bytes of SHA256(privateKey) or SHA256(key))
    /// - nonce (16 bytes random)
    /// - client_pub (32 bytes X25519 ephemeral public key)
    /// - features (4 bytes uint32 BE)
    static func buildClientHello(key: String, nonce: Data, clientPub: Data) -> Data {
        var payload = Data(capacity: 68)
        let now = UInt64(Date().timeIntervalSince1970)
        for i in (0..<8).reversed() {
            payload.append(UInt8((now >> (i * 8)) & 0xff))
        }
        payload.append(NCSudoku.deriveUserHash(from: key))
        payload.append(nonce.prefix(16))
        payload.append(clientPub.prefix(32))
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // features = 0
        return buildMessage(type: .clientHello, payload: payload)
    }

    /// Parses a ServerHello message, returning server ephemeral public key and selected features.
    static func parseServerHello(payload: Data, expectedNonce: Data) throws -> (serverPub: Data, features: UInt32) {
        guard payload.count >= 52 else {
            throw NSError(domain: "NCSudoku", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "ServerHello payload too short (\(payload.count) < 52)"])
        }
        let serverNonce = payload.prefix(16)
        guard serverNonce == expectedNonce.prefix(16) else {
            throw NSError(domain: "NCSudoku", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "ServerHello nonce mismatch"])
        }
        let serverPub = payload.subdata(in: 16..<48)
        let f0 = UInt32(payload[48]) << 24
        let f1 = UInt32(payload[49]) << 16
        let f2 = UInt32(payload[50]) << 8
        let f3 = UInt32(payload[51])
        return (serverPub, f0 | f1 | f2 | f3)
    }

    /// Encodes target destination in SOCKS5 address format and wraps in OpenTCP KIP frame (type 0x10).
    static func buildOpenTCP(target: NCTarget) -> Data {
        var payload = Data()
        if let ip = target.ip {
            switch ip {
            case .v4(let a):
                payload.append(0x01) // atyp IPv4
                payload.append(contentsOf: [UInt8(a >> 24), UInt8((a >> 16) & 0xff),
                                            UInt8((a >> 8) & 0xff), UInt8(a & 0xff)])
            case .v6(let bytes):
                payload.append(0x04) // atyp IPv6
                payload.append(contentsOf: bytes)
            }
        } else {
            payload.append(0x03) // atyp Domain
            let hostBytes = Data(target.host.utf8.prefix(255))
            payload.append(UInt8(hostBytes.count))
            payload.append(hostBytes)
        }
        let p = UInt16(clamping: target.port)
        payload.append(UInt8(p >> 8))
        payload.append(UInt8(p & 0xff))
        return buildMessage(type: .openTCP, payload: payload)
    }

    /// Unwraps a KIP message from wire buffer, returning consumed bytes, message type, and payload.
    static func unwrapMessage(from buffer: Data) -> (consumed: Int, type: MessageType, payload: Data)? {
        guard buffer.count >= 6 else { return nil }
        guard buffer.prefix(3) == magic else { return nil }
        guard let type = MessageType(rawValue: buffer[buffer.startIndex + 3]) else { return nil }
        let len = (Int(buffer[buffer.startIndex + 4]) << 8) | Int(buffer[buffer.startIndex + 5])
        guard buffer.count >= 6 + len else { return nil }
        let payload = buffer.subdata(in: (buffer.startIndex + 6)..<(buffer.startIndex + 6 + len))
        return (6 + len, type, payload)
    }
}

// MARK: - AEAD Record Layer

final class NCSudokuAEAD {
    let method: NCSudoku.AEADMethod

    /// Whether this endpoint seals with the c2s base (client) or s2c (server).
    let isClient: Bool
    private let keyHash: Data
    private var sendBase: Data
    private var recvBase: Data

    private var sendEpoch: UInt32 = 0
    private var sendSeq: UInt64 = 0
    private var sendPlainBytes: UInt64 = 0
    private var recvEpoch: UInt32 = 0
    private var recvSeq: UInt64 = 0
    private var recvPlainBytes: UInt64 = 0

    /// Upstream rotates the epoch after 32 MiB of plaintext per direction
    /// (record_conn.go KeyUpdateAfterBytes).
    static let keyUpdateAfterBytes: UInt64 = 32 * 1024 * 1024

    /// Official key schedule (docs section 2.4): the PSK bases are
    /// HKDF-Expand(SHA256(key-string), "sudoku-psk-c2s"/"sudoku-psk-s2c");
    /// the record key for an epoch is HMAC-SHA256(base,
    /// "sudoku-record:" + method + epoch_be32).
    init(method: NCSudoku.AEADMethod, keyMaterial: NCSudoku.KeyMaterial, isClient: Bool = true) {
        self.method = method
        self.isClient = isClient
        self.keyHash = keyMaterial.keyHash
        let c2s = Self.hkdfExpand(prk: keyHash, info: Data("sudoku-psk-c2s".utf8))
        let s2c = Self.hkdfExpand(prk: keyHash, info: Data("sudoku-psk-s2c".utf8))
        self.sendBase = isClient ? c2s : s2c
        self.recvBase = isClient ? s2c : c2s
    }

    convenience init(method: NCSudoku.AEADMethod, key: String, isClient: Bool = true) {
        self.init(method: method, keyMaterial: NCSudoku.keyMaterial(from: key), isClient: isClient)
    }

    // MARK: HKDF / HMAC primitives (CryptoKit)

    static func hkdfExpand(prk: Data, info: Data, length: Int = 32) -> Data {
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var msg = t
            msg.append(info)
            msg.append(counter)
            t = Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: prk)))
            out.append(t)
            counter &+= 1
        }
        return Data(out.prefix(length))
    }

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt)))
    }

    /// Post-ServerHello rekey (docs section 2.4 step 2):
    /// prk = HKDF-Extract(salt=SHA256(key-string), ikm=X25519 shared ‖ nonce);
    /// session bases = HKDF-Expand(prk, "sudoku-session-c2s"/"-s2c").
    /// Record counters restart under the new bases.
    func rekey(sharedSecret: Data, nonce: Data) {
        var ikm = sharedSecret
        ikm.append(nonce)
        let prk = Self.hkdfExtract(salt: keyHash, ikm: ikm)
        let c2s = Self.hkdfExpand(prk: prk, info: Data("sudoku-session-c2s".utf8))
        let s2c = Self.hkdfExpand(prk: prk, info: Data("sudoku-session-s2c".utf8))
        sendBase = isClient ? c2s : s2c
        recvBase = isClient ? s2c : c2s
        sendEpoch = 0; sendSeq = 0; sendPlainBytes = 0
        recvEpoch = 0; recvSeq = 0; recvPlainBytes = 0
    }

    private func epochKey(base: Data, epoch: UInt32) -> Data {
        var info = Data("sudoku-record:".utf8)
        info.append(Data(method.rawValue.utf8))
        for i in (0..<4).reversed() { info.append(UInt8((epoch >> (i * 8)) & 0xff)) }
        return Data(HMAC<SHA256>.authenticationCode(for: info, using: SymmetricKey(data: base)))
    }

    // Test-visible snapshots of the schedule.
    var debugSendBase: Data { sendBase }
    var debugRecvBase: Data { recvBase }
    func debugEpochKey(send: Bool, epoch: UInt32) -> Data { epochKey(base: send ? sendBase : recvBase, epoch: epoch) }

    /// Seals plaintext into an AEAD record: [body_len u16 BE][header 12B][ciphertext].
    func seal(plaintext: Data) throws -> Data {
        if method == .none {
            var out = Data(capacity: 2 + plaintext.count)
            let len = UInt16(clamping: plaintext.count)
            out.append(UInt8(len >> 8))
            out.append(UInt8(len & 0xff))
            out.append(plaintext)
            return out
        }

        var header = Data(capacity: 12)
        let ep = sendEpoch
        let sq = sendSeq
        for i in (0..<4).reversed() { header.append(UInt8((ep >> (i * 8)) & 0xff)) }
        for i in (0..<8).reversed() { header.append(UInt8((sq >> (i * 8)) & 0xff)) }

        let key = SymmetricKey(data: epochKey(base: sendBase, epoch: ep))
        let ciphertext: Data
        switch method {
        case .chacha20Poly1305:
            let nonce = try ChaChaPoly.Nonce(data: header)
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: header)
            ciphertext = box.ciphertext + box.tag
        case .aes128GCM:
            let nonce = try AES.GCM.Nonce(data: header)
            let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: epochKey(base: sendBase, epoch: ep).prefix(16)), nonce: nonce, authenticating: header)
            ciphertext = box.ciphertext + box.tag
        case .none:
            ciphertext = plaintext
        }

        sendSeq &+= 1
        sendPlainBytes += UInt64(plaintext.count)
        if sendPlainBytes >= Self.keyUpdateAfterBytes {
            sendEpoch &+= 1
            sendSeq = 0
            sendPlainBytes = 0
        }

        var out = Data(capacity: 2 + 12 + ciphertext.count)
        let bodyLen = UInt16(clamping: 12 + ciphertext.count)
        out.append(UInt8(bodyLen >> 8))
        out.append(UInt8(bodyLen & 0xff))
        out.append(header)
        out.append(ciphertext)
        return out
    }

    /// Attempts to extract and decrypt one AEAD record from buffer.
    /// The receive path enforces the strict in-order (epoch, seq) the
    /// official record layer requires (docs section 2.4 step 4).
    func unseal(from buffer: inout Data) throws -> Data? {
        guard buffer.count >= 2 else { return nil }
        let bodyLen = (Int(buffer[buffer.startIndex]) << 8) | Int(buffer[buffer.startIndex + 1])
        if method == .none {
            guard buffer.count >= 2 + bodyLen else { return nil }
            let plaintext = buffer.subdata(in: (buffer.startIndex + 2)..<(buffer.startIndex + 2 + bodyLen))
            buffer = buffer.dropFirst(2 + bodyLen)
            return plaintext
        }

        guard bodyLen >= 12 else {
            throw NSError(domain: "NCSudoku", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid AEAD record body_len (\(bodyLen) < 12)"])
        }
        guard buffer.count >= 2 + bodyLen else { return nil }

        let header = buffer.subdata(in: (buffer.startIndex + 2)..<(buffer.startIndex + 14))
        var ep: UInt32 = 0
        var sq: UInt64 = 0
        for i in 0..<4 { ep = (ep << 8) | UInt32(header[header.startIndex + i]) }
        for i in 0..<8 { sq = (sq << 8) | UInt64(header[header.startIndex + 4 + i]) }
        guard ep == recvEpoch, sq == recvSeq else {
            throw NSError(domain: "NCSudoku", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "AEAD record out of order: got epoch \(ep) seq \(sq), expected epoch \(recvEpoch) seq \(recvSeq)"])
        }

        let cipherTotal = bodyLen - 12
        guard cipherTotal >= 16 else {
            throw NSError(domain: "NCSudoku", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Ciphertext shorter than authentication tag"])
        }
        let ct = buffer.subdata(in: (buffer.startIndex + 14)..<(buffer.startIndex + 14 + cipherTotal - 16))
        let tag = buffer.subdata(in: (buffer.startIndex + 14 + cipherTotal - 16)..<(buffer.startIndex + 2 + bodyLen))
        let recordBytes = 2 + bodyLen

        let plain: Data
        switch method {
        case .chacha20Poly1305:
            let nonce = try ChaChaPoly.Nonce(data: header)
            let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            plain = try ChaChaPoly.open(box, using: SymmetricKey(data: epochKey(base: recvBase, epoch: ep)), authenticating: header)
        case .aes128GCM:
            let nonce = try AES.GCM.Nonce(data: header)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            plain = try AES.GCM.open(box, using: SymmetricKey(data: epochKey(base: recvBase, epoch: ep).prefix(16)), authenticating: header)
        case .none:
            plain = ct
        }

        buffer = buffer.dropFirst(recordBytes)
        recvSeq &+= 1
        recvPlainBytes += UInt64(plain.count)
        if recvPlainBytes >= Self.keyUpdateAfterBytes {
            recvEpoch &+= 1
            recvSeq = 0
            recvPlainBytes = 0
        }
        return plain
    }
}

// MARK: - Sudoku 4x4 Steganography Codec

final class NCSudokuCodec {
    let tableType: NCSudoku.TableType
    let customTable: String
    let enablePureDownlink: Bool
    let paddingMin: Int
    let paddingMax: Int

    // 288 non-isomorphic valid 4x4 Sudoku completed boards
    private static let canonicalGrids: [[UInt8]] = generate288Grids()

    // Deterministic mapping table for 256 bytes derived from key
    private let byteToGrid: [[UInt8]]
    private let gridToByte: [UInt64: UInt8]

    // Precomputed unique 4-clue hint for each 4x4 grid (cell0, val0, cell1, val1, cell2, val2, cell3, val3)
    private let byteToHints: [Hint4]

    struct Hint4 {
        let c0: UInt8, v0: UInt8
        let c1: UInt8, v1: UInt8
        let c2: UInt8, v2: UInt8
        let c3: UInt8, v3: UInt8
    }

    init(key: String, tableType: NCSudoku.TableType, customTable: String?,
         enablePureDownlink: Bool, paddingMin: Int, paddingMax: Int) {
        self.tableType = tableType
        self.customTable = customTable ?? "xpxvvpvv"
        self.enablePureDownlink = enablePureDownlink
        self.paddingMin = paddingMin
        self.paddingMax = paddingMax

        // Table permutation = Go math/rand v1 shuffle of the 288 canonical
        // grids, seeded from SHA256 of the NORMALISED key string
        // (docs section 2.6 rows 2 + 12).
        var perm = Self.canonicalGrids
        Self.goShuffle(&perm, seedHash: NCSudoku.keyMaterial(from: key).keyHash)

        var bToG = [[UInt8]]()
        var gToB = [UInt64: UInt8]()
        var hints = [Hint4]()

        for b in 0..<256 {
            let grid = perm[b]
            bToG.append(grid)
            let key64 = Self.gridHash(grid)
            gToB[key64] = UInt8(b)
            hints.append(Self.findUniqueHint4(for: grid))
        }

        self.byteToGrid = bToG
        self.gridToByte = gToB
        self.byteToHints = hints
    }

    /// Encodes arbitrary data bytes into 4x4 Sudoku hint wire bytes.
    func encode(_ data: Data) -> Data {
        var out = Data(capacity: data.count * 4)
        for byte in data {
            let hint = byteToHints[Int(byte)]
            out.append(encodeClue(cell: hint.c0, val: hint.v0))
            out.append(encodeClue(cell: hint.c1, val: hint.v1))
            out.append(encodeClue(cell: hint.c2, val: hint.v2))
            out.append(encodeClue(cell: hint.c3, val: hint.v3))
        }
        return out
    }

    /// Decodes 4x4 Sudoku hint wire bytes back to original data bytes, filtering padding.
    func decode(_ wire: Data) -> Data {
        var out = Data()
        guard wire.count >= 4 else { return out }
        var offset = 0
        while offset + 4 <= wire.count {
            let b0 = wire[offset]
            let b1 = wire[offset + 1]
            let b2 = wire[offset + 2]
            let b3 = wire[offset + 3]
            offset += 4

            guard let clue0 = decodeClue(b0),
                  let clue1 = decodeClue(b1),
                  let clue2 = decodeClue(b2),
                  let clue3 = decodeClue(b3) else {
                continue // illegal clues treated as padding
            }

            // Quick contradiction check
            var board = [UInt8](repeating: 0, count: 16)
            if board[Int(clue0.cell)] != 0 { continue }
            board[Int(clue0.cell)] = clue0.val
            if board[Int(clue1.cell)] != 0 { continue }
            board[Int(clue1.cell)] = clue1.val
            if board[Int(clue2.cell)] != 0 { continue }
            board[Int(clue2.cell)] = clue2.val
            if board[Int(clue3.cell)] != 0 { continue }
            board[Int(clue3.cell)] = clue3.val

            // Solve and verify unique solvability
            if let solved = Self.solveUnique(&board) {
                let h = Self.gridHash(solved)
                if let originalByte = gridToByte[h] {
                    out.append(originalByte)
                }
            }
        }
        return out
    }

    private func encodeClue(cell: UInt8, val: UInt8) -> UInt8 {
        let r = (cell / 4) & 0x03
        let c = (cell % 4) & 0x03
        let v = (val - 1) & 0x03 // 0..3

        switch tableType {
        case .preferASCII:
            // Map (r, c, v) to printable ASCII (0x20..0x7E)
            let base: UInt8 = 0x20
            let offset = (r << 4) | (c << 2) | v
            return base + offset
        case .preferEntropy, .upASCIIToDownEntropy, .upEntropyToDownASCII:
            // Custom layout pattern (default xpxvvpvv)
            return Self.packXVP(row: r, col: c, val: val, pattern: customTable)
        }
    }

    private func decodeClue(_ byte: UInt8) -> (cell: UInt8, val: UInt8)? {
        switch tableType {
        case .preferASCII:
            guard byte >= 0x20 && byte < 0x70 else { return nil }
            let offset = byte - 0x20
            let r = (offset >> 4) & 0x03
            let c = (offset >> 2) & 0x03
            let v = (offset & 0x03) + 1
            return (r * 4 + c, v)
        case .preferEntropy, .upASCIIToDownEntropy, .upEntropyToDownASCII:
            return Self.unpackXVP(byte: byte, pattern: customTable)
        }
    }

    // MARK: - XVP Bitwise Packing / Unpacking

    static func packXVP(row: UInt8, col: UInt8, val: UInt8, pattern: String) -> UInt8 {
        // One-hot 4-bit value: 1 -> 0001, 2 -> 0010, 3 -> 0100, 4 -> 1000
        let vOneHot: UInt8 = 1 << ((val - 1) & 0x03)
        var xBits = [(row >> 1) & 1, row & 1]
        var pBits = [(col >> 1) & 1, col & 1]
        var vBits = [(vOneHot >> 3) & 1, (vOneHot >> 2) & 1, (vOneHot >> 1) & 1, vOneHot & 1]

        var out: UInt8 = 0
        var bitIdx = 7
        for ch in pattern.lowercased() {
            guard bitIdx >= 0 else { break }
            let bit: UInt8
            switch ch {
            case "x": bit = !xBits.isEmpty ? xBits.removeFirst() : 0
            case "p": bit = !pBits.isEmpty ? pBits.removeFirst() : 0
            case "v": bit = !vBits.isEmpty ? vBits.removeFirst() : 0
            default: bit = 0
            }
            if bit == 1 { out |= (1 << bitIdx) }
            bitIdx -= 1
        }
        return out
    }

    static func unpackXVP(byte: UInt8, pattern: String) -> (cell: UInt8, val: UInt8)? {
        var xBits = [UInt8]()
        var pBits = [UInt8]()
        var vBits = [UInt8]()

        var bitIdx = 7
        for ch in pattern.lowercased() {
            guard bitIdx >= 0 else { break }
            let bit = (byte >> bitIdx) & 1
            switch ch {
            case "x": xBits.append(bit)
            case "p": pBits.append(bit)
            case "v": vBits.append(bit)
            default: break
            }
            bitIdx -= 1
        }
        guard xBits.count == 2, pBits.count == 2, vBits.count == 4 else { return nil }

        let r = (xBits[0] << 1) | xBits[1]
        let c = (pBits[0] << 1) | pBits[1]
        let vVal = (vBits[0] << 3) | (vBits[1] << 2) | (vBits[2] << 1) | vBits[3]

        // Value must be strictly one-hot (1..4)
        let digit: UInt8
        switch vVal {
        case 0b0001: digit = 1
        case 0b0010: digit = 2
        case 0b0100: digit = 3
        case 0b1000: digit = 4
        default: return nil // invalid non-one-hot clue (padding)
        }
        return (r * 4 + c, digit)
    }

    // MARK: - Mathematical 4x4 Sudoku Solvers

    private static func gridHash(_ g: [UInt8]) -> UInt64 {
        var h: UInt64 = 0
        for i in 0..<16 {
            h |= (UInt64(g[i] & 0x03) << (i * 2))
        }
        return h
    }

    static func generate288Grids() -> [[UInt8]] {
        var res = [[UInt8]]()
        var current = [UInt8](repeating: 0, count: 16)
        enumerate(&current, idx: 0, out: &res)
        return res
    }

    private static func enumerate(_ grid: inout [UInt8], idx: Int, out: inout [[UInt8]]) {
        if idx == 16 {
            out.append(grid)
            return
        }
        let r = idx / 4, c = idx % 4
        let br = (r / 2) * 2, bc = (c / 2) * 2
        var used: UInt8 = 0
        for i in 0..<4 {
            let rv = grid[r * 4 + i]
            if rv > 0 { used |= (1 << rv) }
            let cv = grid[i * 4 + c]
            if cv > 0 { used |= (1 << cv) }
        }
        for dr in 0..<2 {
            for dc in 0..<2 {
                let bv = grid[(br + dr) * 4 + (bc + dc)]
                if bv > 0 { used |= (1 << bv) }
            }
        }
        for val: UInt8 in 1...4 {
            if (used & (1 << val)) == 0 {
                grid[idx] = val
                enumerate(&grid, idx: idx + 1, out: &out)
                grid[idx] = 0
            }
        }
    }

    static func solveUnique(_ board: inout [UInt8]) -> [UInt8]? {
        var solution: [UInt8]?
        var count = 0
        solveBacktracking(&board, idx: 0, count: &count, solution: &solution)
        return count == 1 ? solution : nil
    }

    private static func solveBacktracking(_ grid: inout [UInt8], idx: Int, count: inout Int, solution: inout [UInt8]?) {
        if count > 1 { return }
        if idx == 16 {
            count += 1
            if count == 1 { solution = grid }
            return
        }
        if grid[idx] != 0 {
            solveBacktracking(&grid, idx: idx + 1, count: &count, solution: &solution)
            return
        }
        let r = idx / 4, c = idx % 4
        let br = (r / 2) * 2, bc = (c / 2) * 2
        var used: UInt8 = 0
        for i in 0..<4 {
            let rv = grid[r * 4 + i]
            if rv > 0 { used |= (1 << rv) }
            let cv = grid[i * 4 + c]
            if cv > 0 { used |= (1 << cv) }
        }
        for dr in 0..<2 {
            for dc in 0..<2 {
                let bv = grid[(br + dr) * 4 + (bc + dc)]
                if bv > 0 { used |= (1 << bv) }
            }
        }
        for val: UInt8 in 1...4 {
            if (used & (1 << val)) == 0 {
                grid[idx] = val
                solveBacktracking(&grid, idx: idx + 1, count: &count, solution: &solution)
                grid[idx] = 0
                if count > 1 { return }
            }
        }
    }

    static func findUniqueHint4(for grid: [UInt8]) -> Hint4 {
        // Try symmetric 4-cell positions that yield unique solution for 4x4
        let candidates: [[Int]] = [
            [0, 5, 10, 15], // main diagonal
            [3, 6, 9, 12],  // anti diagonal
            [0, 3, 12, 15], // corners
            [1, 7, 8, 14],  // knight-hop pattern
            [2, 4, 11, 13], // dual knight-hop
            [0, 7, 10, 13],
            [1, 6, 11, 12]
        ]
        for c in candidates {
            var b = [UInt8](repeating: 0, count: 16)
            b[c[0]] = grid[c[0]]
            b[c[1]] = grid[c[1]]
            b[c[2]] = grid[c[2]]
            b[c[3]] = grid[c[3]]
            if solveUnique(&b) != nil {
                return Hint4(c0: UInt8(c[0]), v0: grid[c[0]],
                             c1: UInt8(c[1]), v1: grid[c[1]],
                             c2: UInt8(c[2]), v2: grid[c[2]],
                             c3: UInt8(c[3]), v3: grid[c[3]])
            }
        }
        // Fallback: first cell of each 2x2 box
        return Hint4(c0: 0, v0: grid[0], c1: 2, v1: grid[2], c2: 8, v2: grid[8], c3: 10, v3: grid[10])
    }

    /// Shuffles the canonical grids with Go's math/rand v1 — the wire
    /// contract for the table permutation (docs §2.6 row 12): a lagged-
    /// Fibonacci rngSource seeded with int64(BE(SHA256(key-string)[:8])),
    /// Fisher-Yates via the Lemire int31n path.
    private static func goShuffle<T>(_ list: inout [T], seedHash: Data) {
        guard list.count > 1 else { return }
        var be: UInt64 = 0
        for b in seedHash.prefix(8) { be = (be << 8) | UInt64(b) }
        var rng = NCGoRand(seed: Int64(bitPattern: be))
        rng.shuffle(&list)
    }
}

/// Port of Go's math/rand v1 generator (rngSource + Rand.Shuffle), the
/// algorithm the official Sudoku implementation seeds its grid table with.
/// The algorithm and its 607-entry seed table are from the Go standard
/// library (BSD-3-Clause, (c) The Go Authors), reimplemented here from the
/// published source — this is a wire-format contract, not Sudoku code.
struct NCGoRand {
    private var vec: [UInt64]
    private var tap: Int
    private var feed: Int

    init(seed: Int64) {
        let int32max: Int64 = 2_147_483_647
        var s = seed % int32max
        if s < 0 { s += int32max }
        if s == 0 { s = 894_823_11 }
        vec = [UInt64](repeating: 0, count: 607)
        tap = 0
        feed = 607 - 273
        var x = Int32(s)
        for i in -20..<607 {
            x = Self.seedrand(x)
            if i >= 0 {
                var u = UInt64(UInt32(bitPattern: x)) << 40
                x = Self.seedrand(x)
                u ^= UInt64(UInt32(bitPattern: x)) << 20
                x = Self.seedrand(x)
                u ^= UInt64(UInt32(bitPattern: x))
                u ^= Self.rngCooked[i]
                vec[i] = u
            }
        }
    }

    private static func seedrand(_ x0: Int32) -> Int32 {
        let a: Int64 = 48271, q: Int64 = 44488, r: Int64 = 3399
        let x = Int64(x0)
        var v = a * (x % q) - r * (x / q)
        if v < 0 { v += 2_147_483_647 }
        return Int32(v)
    }

    mutating func uint64() -> UInt64 {
        tap -= 1
        if tap < 0 { tap += 607 }
        feed -= 1
        if feed < 0 { feed += 607 }
        let x = vec[feed] &+ vec[tap]
        vec[feed] = x
        return x
    }

    mutating func int63() -> Int64 { Int64(uint64() & 0x7fff_ffff_ffff_ffff) }

    mutating func uint32() -> UInt32 { UInt32(int63() >> 31) }

    /// Go Rand.int31n (Lemire): used by Shuffle for n <= 2^31-1.
    mutating func int31n(_ n: Int32) -> Int32 {
        var v = uint32()
        var prod = UInt64(v) * UInt64(UInt32(bitPattern: n))
        var low = UInt32(prod & 0xffff_ffff)
        if low < UInt32(bitPattern: n) {
            let thresh = (0 &- UInt32(bitPattern: n)) % UInt32(bitPattern: n)
            while low < thresh {
                v = uint32()
                prod = UInt64(v) * UInt64(UInt32(bitPattern: n))
                low = UInt32(prod & 0xffff_ffff)
            }
        }
        return Int32(prod >> 32)
    }

    /// Go Rand.Shuffle (Fisher-Yates, int31n path for our sizes).
    mutating func shuffle<T>(_ a: inout [T]) {
        guard a.count > 1 else { return }
        for i in stride(from: a.count - 1, through: 1, by: -1) {
            let j = Int(int31n(Int32(i + 1)))
            if i != j { a.swapAt(i, j) }
        }
    }

    /// The shuffled index order for a seed — exposed for vector tests.
    static func permutation(count: Int, seedHash: Data) -> [Int] {
        var be: UInt64 = 0
        for b in seedHash.prefix(8) { be = (be << 8) | UInt64(b) }
        var rng = NCGoRand(seed: Int64(bitPattern: be))
        var idx = [Int](0..<count)
        rng.shuffle(&idx)
        return idx
    }

    // Go stdlib rngCooked seed table (math/rand/rng.go), as UInt64 bit patterns.
    static let rngCooked: [UInt64] = [
        0xc5f74a33eb98ffea, 0xc07b4a41ba965f5b, 0x135ec513cb81af0f, 0x4a04fb5ca74395eb, 0xa7e8831c7710cf8e, 0x7d5de4e88f37c1c3,
        0x6321cf7743ff85a9, 0x42cb06556a9ff961, 0x6e26c8d140e8d7d2, 0x49a7511f3411faa0, 0x71ed774922a65055, 0x9d5c9fc65fea2d5c,
        0x3fbdab394a014368, 0x70fa33596992340b, 0xae10fb4ecea66a02, 0xf79fbca98bbcd18a, 0x97f7ccb12ea380ac, 0x0191d794caf32b1b,
        0x3f6a323424e32caf, 0xc642cc921f01142b, 0xa122869f4ff38068, 0xa5b1a31127af3920, 0x5b07a4f9bdc29d96, 0x6a2a973c29812586,
        0x6aa433dbf77a52e1, 0x8394216e3b8ac99e, 0xdb80a9c5515b997c, 0x03c3f2eff3cbf769, 0xa6b5e431eeff210c, 0x0ec85334992953f5,
        0x2e6a1432df10d1e9, 0xbde4629959d1b149, 0x67994c3876387951, 0x0e15d461559bae63, 0xbdbf96c4e9d2a077, 0xb04f62866ada20f3,
        0x2190da1646db97bf, 0x5071873c1832957a, 0x3e3b503a19da904b, 0x33e388a5f2c78528, 0xbec70bac19d0e877, 0x00256970f81bf072,
        0xf7d18a14f64fa886, 0xa46ef978b4d4734c, 0x782ff1573127a78e, 0x00241b0ad59beba6, 0xdac549591fe95b2f, 0x6195faf2884c2d39,
        0x569c2bbdb0ef345d, 0x0b8b6039508ce21e, 0xef1576705435d2bb, 0x1d5e900af5f1d8f7, 0x1e902d187d7fd437, 0x7f227b7c8fe0eb79,
        0x38790e6201ebbb98, 0x44818eac7922e171, 0x0658d6c550dad340, 0x84bfb894cc72969a, 0xa7855141e3b329bd, 0x9cb31556b1bae746,
        0x3ca09004f9686f49, 0x0c50146d7e508769, 0xcd35d8ff935ac970, 0xde9818b4aa1554d8, 0x4df37efd6433daa0, 0xf591e9ad05b2e056,
        0x1767eb0bdbf83e29, 0xb8247292535299f2, 0xbae645975a5e4ceb, 0xecea78155c3bc32b, 0x4e295e5357ace86e, 0x8b906a9a4fadbb08,
        0xfd50086af64463c9, 0xad0385acfd19d6fc, 0xbbe6d4a5e1d13a9f, 0xfc099f33b79b039c, 0xd9782224840c5a35, 0x174e38bc45d51acf,
        0x53f82f9f54de4e3e, 0xe10dfa0a87b3ef0e, 0xea09d9ec7b439769, 0x519ec3c7cc4c5011, 0x0b47990fc413e3d5, 0x3f07e07ecfce5be2,
        0xa5d2d0b8b71922be, 0x451eea1fc87cc761, 0xc8505edef7f1d6dd, 0xfb6ed78e001ce905, 0xd7cc0a3644f468ba, 0x14c231db2e4429d0,
        0xe21ccd9a90943dd3, 0x664869f5288fc2d1, 0xddc56f604e168fb5, 0x4151e4abb0b1faf6, 0xec9647e8cea7b927, 0x76a742187dbe61de,
        0x80778d4049780e3c, 0x92714446c26ce413, 0x65475bc019e7700b, 0x0e08781d60d86d17, 0x9f0f0fe9d5f571e0, 0x476e62bf33886e57,
        0x8c710cff524eb4e6, 0x24e856a59e3899a5, 0x549f7c8b5783189a, 0x9808539c06020014, 0xb8fc59eeb2515467, 0xf38fff8b8499a614,
        0xf5a62be73a3d5222, 0x508b82832b4c4838, 0xf5109fc7682ff8de, 0xd31cadf15cc53f0c, 0xc1720509406b5826, 0xe900715210bc96fa,
        0x0704fe3536d393fb, 0xc65c9b6eccaefb4a, 0x8bafc73092be4019, 0x07f0b599d77889ea, 0x18de0a49b8fa589b, 0x2f174e71c9830ff0,
        0xb470b780a26785dd, 0x20a6b76123b162be, 0x91efbd24cdc58322, 0xfb7bb75026b32623, 0xd03d1caf9a1f04d0, 0xa5f0f909bcaee921,
        0x46aa7ced9d1c8e0b, 0xfcd8a79e7a62b6f9, 0x3ac4cf05bce83f14, 0x45c579a008a037c4, 0x4053888e527912d0, 0xf88fa0b2289f7b17,
        0x51fbaf5d2002bdda, 0x8ae403a812ca4784, 0x0d7ea237329fa450, 0xcb3f04bf02b6f208, 0xc796643e8a39ed33, 0xfd92d79ed75b6419,
        0x216821c8b258e8ac, 0xe93d3aff7b46e931, 0x36b0858cfcb72b6a, 0xae5e3c9fe7ff1167, 0x2af4c395391cc2a5, 0xe6c4fd076feb7676,
        0x50efb5fb31ede773, 0x6d7f243359dbfcae, 0x7193e740340e0fdb, 0x8ff51f73a4c6dd92, 0x94534b6efa1ca966, 0xc06a724520d70d41,
        0x30cd16bd19120592, 0x8d456b580c2cd6dc, 0x5c62bc0d6a8429ef, 0x48744ea9b8e9395e, 0x18ef14825c84aee1, 0x4a1e32b73a71e234,
        0x0fee6f27c45228c0, 0x464e2e3be0d2e4a1, 0x23bb67f482e16008, 0x0f11b541e8247327, 0xae7df90c7d2aafd7, 0x54e1f496142c391a,
        0x1d400ef625fa4274, 0x9906966610ce9e13, 0x22455934d7c1ccda, 0xe6414239b7da9220, 0xb49f9091f6275556, 0x82916b3d64288abd,
        0x9f52d0a1c7066fa0, 0x642a666cfb8cf0a1, 0x8c9d981db063ad83, 0x63dfa26158b67e4a, 0xce3cfe36ebecc2df, 0xb6e4eb2ba55364ff,
        0x6fd2179e0d7717d1, 0xb971a2b7362247db, 0xdbe5cf25d510c53b, 0x930f28ad73735261, 0x5a95dd01047feb8b, 0x30adb1407358b45a,
        0x7fb44776784c1083, 0x1b20e8f4eb075406, 0xdc275f40b6c7c0d9, 0x732df8dda67b0f27, 0xb62637afc484c885, 0x61c98649838bf631,
        0xdf061fee30277f58, 0x95d322052dac1455, 0x7ad30486e478aee9, 0x3267221f4aced145, 0x479807052c3566b8, 0xa8025350a77ea0b9,
        0x421a7ec2fc169cd3, 0x57273ab05129a700, 0xbae4f7fb719f43f2, 0x1c5bd857e8b8bf48, 0xdad594186971f359, 0x3f518aad9c427014,
        0x4c43c3b8cc8e8218, 0x981fba566f92dfb7, 0x07acaac55435c0ac, 0x5fb0881038cbbc8f, 0xf243b5556cbeba73, 0x63149f303be79fd4,
        0xf6aade431f712475, 0x4cd2a557b6cbc24b, 0x21bc6975c169de72, 0xcaf78cf40c768134, 0xf13cdd624a12159f, 0xd573d0041b390d3e,
        0x69ea8bd93bade806, 0x578baf3d78cd61f2, 0x3318a93a7f689dc9, 0x2da7501cbdbe5235, 0x5b6d448c9bb11200, 0x036566ca66f231b4,
        0xb89e51e9e2b737e4, 0x704687541c9b68cf, 0x28df28a35d2937c9, 0x8bfeb2756944b0b5, 0x29c24143c2234e9c, 0xf4fd794f8d02068f,
        0x0590f068df15e57d, 0xe4ad98adab8dc009, 0x4155b1828194a406, 0xce463027d4ff743f, 0xd306231168ec0845, 0xae01984986c0c339,
        0xcc61983656980e5a, 0xb6b4b212af3d051a, 0x70aaf14a706ce17a, 0x3547cbc995de3a40, 0x6202b8d9e9e8565f, 0x8a49ea181ddbac34,
        0x53a7bcb92853ce41, 0xa2aa132546a16f3a, 0xd6c166634bc92862, 0x92ff6acebc93a071, 0x7a403280a96cea51, 0x5a183b8f81665a24,
        0x222b4c80d2c0e464, 0x859e3d4d58ba3aa6, 0xb9a28389cb2fe563, 0x83a20cb89512fee4, 0xcbd691b061b30cbd, 0x8839baf8f3ac9f09,
        0x5ddf03b3edd1c4b8, 0xf62694c4cb82ed09, 0xd0c603b9879bd360, 0x8558daf780426657, 0xc87fdb1b629e32ab, 0xd77938d516862fe1,
        0xe33a56962759ec00, 0x051bc82f174b90d9, 0xab3b5debcad25c86, 0xa8766bd0dd9b35db, 0x425f26b683ca1487, 0x5d3c2b40a076f653,
        0x7464e98a72f8d634, 0x2f02dd3eea4e7841, 0x40977fe842527877, 0xfbf01ad4922b1d62, 0xca959c2a8b4eea29, 0x69ca7ca110533802,
        0x6b36496357247bd9, 0x7f7c07645ca7b232, 0xb8c63fa50ae3677b, 0xa0b7fd74703947d8, 0x231fb1a0dc8ce079, 0x16b63342b7c96e77,
        0xcd39a909d7e68027, 0x1427685b19caecdd, 0x9c9c6cd28e91b74d, 0x91c1fb790e0d3a54, 0x7e67d3bdb81bb611, 0xd396fc0d89f6e211,
        0x457eacfbb049eb22, 0x1de1979bf5654dd5, 0x5d436ca7585d28ca, 0xd3d7e2863218d979, 0x2fa7be3ccf9d1645, 0x1fb7a7e17b9eccb0,
        0x2b2b1fced929c282, 0xd85a90375e64310d, 0xcb336a1611227dbd, 0x636925f5baf870cd, 0x43e0d0254b84715e, 0x080ec57577219247,
        0x175ee40f58fbd971, 0x3d78cc365badbce1, 0x8495a07683903295, 0x8f89c0d3396a3b53, 0x639ba81c88d888a6, 0x3faf8d9c775ca781,
        0xeac40d3f519d2893, 0x01fe31d8c7df7dc4, 0x036d8003387dd6db, 0x8c0621f768220a97, 0x59d6a8cc7a082707, 0x2aea572af8467560,
        0x1c910136c9fdf9c3, 0xc73eddfe111385e2, 0x79edb9a2a6a387df, 0xd556d17adcc5f6fb, 0xf72709f96b28a3c7, 0x552d69f0428dce6a,
        0x9cbbb4be9a92c216, 0x4f37aef6caf41c5d, 0xd3431110cdd7a998, 0x3c7c1de5b3cc1dca, 0x048311a7625eabd9, 0x5ee41cb40ca81e2c,
        0x43385b68e51dbffc, 0xd36a1f70d4f9a2ff, 0xcaeaccb927b0cb5c, 0x3fddae4163e010e4, 0x0e7f5452a8c91ee0, 0x7e61315458970ccb,
        0x8b821c0b10054c75, 0xc444cf11f9840608, 0x2536b7a7602f6b4d, 0x331786d5a126f97f, 0xc9a9cd708372db93, 0xd7e75a07542451da,
        0xa4e5a10d28659104, 0x9024ebcbf8b8e6af, 0x08137c3380f32523, 0x32a31118a95e425f, 0xbd640b6140802b1e, 0x967e3cd0f12b1c5f,
        0x031089e87fbab9a7, 0xf11bfbb3ba3e0841, 0x3b7fc3ad0d1cd36b, 0xbfb2f4d968b759c3, 0x4c8475564905d202, 0xe0a80b2a6236fa83,
        0x86a5b8671a833ae3, 0x79608828eb8fe58d, 0x032bcb9f5721e717, 0x12d224e5dc7e16de, 0x29e68b8251e0d495, 0x2bc04a7508cb08a3,
        0x85f835a648329d25, 0x4d2799f797ec19a8, 0x443aadc076f2ed10, 0x89357de277e46717, 0xaf7907aeb63c9d6c, 0x27ce6be004db5b35,
        0x9bbf0228d95bf1d8, 0xae31e17b25e1b363, 0x23e9429e957db925, 0x950e5fab3c7e6825, 0x2aea3671bf9f5933, 0xb2d2ef433932102c,
        0x0d7ed21ec77fc8c1, 0xea5f1280f48e6247, 0x17b747cdf311ae42, 0xe001060ea9fa838e, 0xaca7508c5bccfc84, 0xa3aaa0843f04f963,
        0xf949f7a4e8ebd3a5, 0x22876bdefd41df6c, 0xc124724f07e69e7c, 0xbf470df23d5aa6b4, 0x2998352099f590b8, 0x11cc90f45895653d,
        0x03550da1ab28f8d1, 0x7842cc5c2b1b34db, 0x08b79b3694ac8400, 0xbf72d50b84f96e2c, 0x947079f8eb08f590, 0x696cb72182050872,
        0xd4885bc9ac36d5a7, 0x6cb888b579fe97e1, 0x629482105204e4fd, 0x3cef790816b93701, 0xbda77a26be136556, 0xfb8f861314dda828,
        0x08a2b7b803ae5bcf, 0xd3c8a91ed0323140, 0x870001a0b867ec3e, 0xe4f6c1f9b093dde5, 0x8e086becbc0b8378, 0x9e755197c06ffcc7,
        0x246705ee34f204f8, 0xc7927582d516264c, 0xb3e17ba47546133c, 0xa33f111b5caab4e2, 0xa23d8e161443255e, 0x48f128b344d0819c,
        0x6cd122fb39ab204d, 0x5c2910bf238f36aa, 0x90aeac10e05f9bba, 0x9d54b6b00fe42aca, 0xe88f64387a0fcdcb, 0xc45a205f01473609,
        0xc768ed8eb6b8c82d, 0xf225920d43fd23ac, 0x25bdad5a8a817964, 0x7ebc9cefb9015aab, 0x3c1ee78fa4ea733d, 0xe30e85d1757922a4,
        0x61123dc5e081fe21, 0xdc86c11079674e66, 0x8918973fb91ab9fb, 0x00d4ee55ca6d8c2a, 0xd500476d5215b5b5, 0xfc5068b3e2ea6d2a,
        0x205da910dd23cb85, 0x979b5e11369f775b, 0x2bc872747d65ead7, 0x96ba83aa2ac19de7, 0xa2258710d3a06bd5, 0x02bcfbd9169343e7,
        0x88eecd99246b6273, 0x234b301b2d3c0302, 0x3c61095d0931ecbf, 0xc1fbeae253e44498, 0x9bf8d56e39d28810, 0xef025e3275852770,
        0x3b81d83bc6a5b26d, 0x740e3af17358a76b, 0x5a0491610c217837, 0xb234c04ee9707bba, 0xe8d67481cf12c324, 0x3dc1a80712de14df,
        0x9646cd056265e405, 0xc9ed5b85fe5de223, 0xc034e6309514ca00, 0xa55cb1a9ea35e9bd, 0x83585dac1418cf4c, 0xc6bfe6b67ae71dfa,
        0xedde6a8095841598, 0x8c478074a66108d3, 0x49f4fb28492601c4, 0x6c1f1e9a65e7acb8, 0x44c3f220e0a3a35f, 0xc4422797ac160d7e,
        0xa9bed55a11ad2c15, 0x29bdbe2cde52ac8d, 0xa2486ed01638fb0c, 0x7be91fdd8fa25058, 0x6d06c94a2118cf50, 0xbe19f2b9fcb649e5,
        0x6da310d0ddefe702, 0x9db4d6197fe76870, 0xa1a8e96dd484eb63, 0xa2803dfd82f85916, 0x3a1a0a44d7644c46, 0x1a25188bb552aa62,
        0xfa3eab18c620bd11, 0x33d24f4edd10ea99, 0x386d39256536cc6c, 0x607e759efb2ba1e8, 0x921ebb3d7c6c6071, 0x96ba6b088f86692f,
        0xb2bd2aeaeafed279, 0xb70cc2def3ab10ac, 0x2b1c1284b0b6db2b, 0xd7d4c4db5bbdff92, 0x3f5b8190a0a0241e, 0x1b79f6457e60cfae,
        0xa05c318c94181e91, 0x3480a671b033e3d5, 0x7579955efbbaa755, 0x2777c9f6d0c6b0d7, 0x2a0f21c2f6662c43, 0xc286b4bc45869bbc,
        0x3de266b1c86ed249, 0x0596478ee80942c5, 0x6fd3618b2ee6ae1b, 0x3f08073a3e5dea77, 0x0e7847d01d6e71af, 0xcd1f81afc4fbaafe,
        0x24be71c60778c940, 0x1dc2b6df046a9621, 0xd0944e93950f6ccf, 0xe2c767041ea34007, 0x521bf9c9206576c6, 0x866b7a2bd7715e51,
        0x7a97753c8c793641, 0x52daac19784a65e4, 0x07d3110b7c73f7eb, 0xa66b273fbcc429b7, 0x16302dc85a75540a, 0xc840d3700a56e4de,
        0xd6875303fcd05bff, 0xabbeed06a5e32588, 0x758a6526f8636a3a, 0x01be7adae8e62038, 0xc9b4bec75bc4f40a, 0xdc7a69ce0a9fc1c3,
        0xf93f853c0adbaa64, 0xbe48b8658e39d5b6, 0x5233cc88f307cb85, 0x81f48c566746e404, 0xe6e72b2f3e111192, 0x6ee3ad5d7b4333d5,
        0x3bebf80abf44e35e, 0x324f3dfa2996372c, 0xa60900d584d3294f, 0xcfb39707d3e017c8, 0xd33cd1090a56f237, 0xfae17ac7e5605d43,
        0xc8c0106f0ead4419, 0x89bba8037b2a60be, 0x6999983c12a6557d, 0x29ecb289d4fc6351, 0xdc4e3ec308888d22, 0x2492188c7c1156a7,
        0x476502781cf85a10, 0x8e5d5db3b1c10b44, 0x15bff6623ba91eb7, 0x716a28bba3f09c65, 0xd7f47607c92f30f1, 0x9e04907834879dad,
        0xa611c59795db7099, 0x9a74c74315758aa3, 0x536d4c40116f3239, 0x52539ac587ad97d0, 0x1f1a1675f28959c3, 0x8c6d78f5619e8324,
        0x2af1cfe563eff7ad, 0x3f9d2212e5c94b1d, 0x7e023d467b37b61f, 0xfaab76adabeee96b, 0xcff95dd9926b62d1, 0x3aa278a62172db76,
        0x9982abe519c8c867, 0x34c2118df1f5857e, 0xfa7376b640136c80, 0x98a7d04ca29ade2f, 0x6d9f14b04d77e77e, 0x4b3dad048bed47a1,
        0x4c9ee5e4931d3231, 0xbaf4eba543f33d0a, 0x793aafa07373d926, 0x986ea60fe6b39a32, 0xe31f344f666361e6, 0xf21cbedc44c049cb,
        0xc4f752a0eb5e5403, 0xaf1b99e27d410520, 0x592740a0e5b8c3dd, 0x04fc4ea5fb446c97, 0xad6e587f47afe7a6, 0xde542c137b8384a4,
        0x2a0ffc0f7b301e5c, 0x820547300a5d8af4, 0xd3c639c2087dc079, 0x0a467ca8709a2bb6, 0xe242bb6bb4da36de, 0x6079b0531ec90376,
        0x058ccf98dc1843f7, 0x8417b417b011aec1, 0xecdedd4ff0dd641b, 0x8c3787282349e832, 0xd5f0bb8816e7e8fb, 0x85b650480fd8c2f4,
        0x7d45aa734f760b6d, 0x5962428553d20814, 0x400e2ba01968e7c4, 0x077e19b9a3f76000, 0x1d17558f6164030c, 0x79753148c0e6c59f,
        0x9a77d2f2ef3bd843, 0x666eb88d8701e16f, 0x5572e7ce34288668, 0xeb8d82b15491d607, 0x77c265a71aebbe54, 0x4947dddd6f3e9e07,
        0x628dfe635c795586, 0x22673e39d43ff99b, 0x637e086dc78cf522, 0xee37e3669f7e9c66, 0x92d7bb47a4afe838, 0x1f9eabdfdbe2b7bd,
        0x324fca6af2b5c1d1, 0x59e4a152525b1b29, 0x7c91d10a8d75740e, 0xcc7c533a7fca95d8, 0x1266fbf77386b1db, 0x689a66ba46d1c3bd,
        0x4bd671b124b5701a, 0x2c43fd0a9eaec04d, 0x58143117e4e16555, 0x8358c5bb1248ac23, 0xaaf677bd80e30ac5, 0xfc997227a4f07f8f,
        0xa848cc5d9cb0e150, 0x640a711eb0e49b41, 0x64fcbfa01dca3978, 0x980aab2fff6bc784, 0x395c6750aa42e65e, 0x287fea4c9695f3f4,
        0x9516361749f6428a, 0xc977d592999f2194, 0xc45166d9f6935ff8, 0xa7f503a28f431ca9, 0x51d3a3c351be10ec, 0xf579e080162896e9,
        0xe5b5e9385b202824, 0xfbba1e4a59b0c60c, 0xa8de655829aab207, 0xe1de048dc78b382e, 0x74535a96cc7adfd7, 0x7e57a19b735ef03b,
        0x39a00a3a31c025c6,
    ]
}

// MARK: - HTTP Masking Layer

enum NCSudokuHTTPMask {
    /// Generates randomized HTTP/1.1 request head for legacy direct connections.
    static func makeLegacyRequest(host: String, pathRoot: String) -> Data {
        let path: String
        if pathRoot.isEmpty {
            path = "/api/report"
        } else if pathRoot.hasPrefix("/") {
            path = pathRoot
        } else {
            path = "/" + pathRoot
        }
        let h = host.isEmpty ? "localhost" : host
        let req = "POST \(path) HTTP/1.1\r\nHost: \(h)\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: */*\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
        return Data(req.utf8)
    }
}

// MARK: - Sudoku Relay Stream (NCRelayStream)

final class NCSudokuRelay: NCRelayStream {
    private let raw: NCRelayStream
    private let proxy: NCProxy
    private let target: NCTarget
    private let queue: DispatchQueue

    private let aead: NCSudokuAEAD
    private let codec: NCSudokuCodec
    private let httpMask: NCSudoku.HTTPMaskConfig

    // Handshake state
    private let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
    private let clientNonce: Data
    private var isHandshakeDone = false

    // Receive buffering
    private var wireBuffer = Data()
    private var plainBuffer = Data()
    private var isCancelled = false

    init(raw: NCRelayStream, proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        self.raw = raw
        self.proxy = proxy
        self.target = target
        self.queue = queue

        let key = proxy.fields["key"]?.string ?? proxy.fields["password"]?.string ?? ""
        let aeadMethod = NCSudoku.AEADMethod.parse(proxy.fields["aead-method"]?.string ?? proxy.fields["aead"]?.string) ?? .chacha20Poly1305
        let tableType = NCSudoku.TableType.parse(proxy.fields["table-type"]?.string ?? proxy.fields["ascii"]?.string) ?? .preferEntropy
        let customTable = proxy.fields["custom-table"]?.string ?? proxy.fields["custom_table"]?.string
        let pureDownlink = proxy.fields["enable-pure-downlink"]?.bool ?? true
        let pmin = proxy.fields["padding-min"]?.int ?? proxy.fields["padding_min"]?.int ?? 5
        let pmax = proxy.fields["padding-max"]?.int ?? proxy.fields["padding_max"]?.int ?? 15

        self.aead = NCSudokuAEAD(method: aeadMethod, key: key)
        self.codec = NCSudokuCodec(key: key, tableType: tableType, customTable: customTable,
                                   enablePureDownlink: pureDownlink, paddingMin: pmin, paddingMax: pmax)
        self.httpMask = NCSudoku.HTTPMaskConfig.parse(from: proxy.fields["httpmask"]?.object)

        // Generate 16 bytes random nonce for handshake
        var n = Data(count: 16)
        _ = n.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        self.clientNonce = n
    }

    /// Performs the Sudoku handshake: HTTP mask -> ClientHello -> ServerHello -> OpenTCP.
    func handshake(completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let deadline = NCHandshakeDeadline(queue: queue, seconds: 15.0, raw: raw, what: "sudoku") { stream, err in
            completion(stream, err)
        }

        // 1. Send HTTP disguise head if enabled
        if !httpMask.disable && httpMask.mode == "legacy" {
            let req = NCSudokuHTTPMask.makeLegacyRequest(host: httpMask.host.isEmpty ? (proxy.server ?? "") : httpMask.host,
                                                         pathRoot: httpMask.pathRoot)
            raw.send(req)
        }

        // 2. Build ClientHello KIP frame
        let key = proxy.fields["key"]?.string ?? proxy.fields["password"]?.string ?? ""
        let clientPub = clientPrivateKey.publicKey.rawRepresentation
        let clientHello = NCSudokuKIP.buildClientHello(key: key, nonce: clientNonce, clientPub: clientPub)

        // 3. Seal ClientHello in AEAD record & Sudoku obfuscate
        guard let sealed = try? aead.seal(plaintext: clientHello) else {
            deadline.finish(nil, NSError(domain: "NCSudoku", code: 10,
                                         userInfo: [NSLocalizedDescriptionKey: "Failed to seal ClientHello"]))
            return
        }
        let wire = codec.encode(sealed)
        raw.send(wire)

        // 4. Read ServerHello response
        readServerHello(deadline: deadline)
    }

    private func readServerHello(deadline: NCHandshakeDeadline) {
        raw.receive { [weak self] data, err in
            guard let self else { return }
            if let err {
                deadline.finish(nil, err)
                return
            }
            guard let data, !data.isEmpty else {
                deadline.finish(nil, NSError(domain: "NCSudoku", code: 11,
                                             userInfo: [NSLocalizedDescriptionKey: "EOF while reading ServerHello"]))
                return
            }

            self.wireBuffer.append(data)
            let decoded = self.codec.decode(self.wireBuffer)
            self.wireBuffer = Data() // consumed decoded slice
            self.plainBuffer.append(decoded)

            // Try unsealing AEAD record
            var unsealed: Data?
            do {
                unsealed = try self.aead.unseal(from: &self.plainBuffer)
            } catch {
                deadline.finish(nil, error)
                return
            }

            guard let record = unsealed else {
                // Need more bytes
                self.readServerHello(deadline: deadline)
                return
            }

            // Parse ServerHello KIP frame
            guard let msg = NCSudokuKIP.unwrapMessage(from: record), msg.type == .serverHello else {
                deadline.finish(nil, NSError(domain: "NCSudoku", code: 12,
                                             userInfo: [NSLocalizedDescriptionKey: "Invalid ServerHello message"]))
                return
            }

            let serverPub: Data
            do {
                serverPub = try NCSudokuKIP.parseServerHello(payload: msg.payload, expectedNonce: self.clientNonce).serverPub
            } catch {
                deadline.finish(nil, error)
                return
            }

            // Rekey to the session bases: HKDF-Extract over the X25519
            // shared secret ‖ client nonce (docs section 2.4 step 2).
            // Everything after ServerHello (starting with OpenTCP) is
            // sealed under the session bases with fresh counters.
            do {
                let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub)
                let shared = try self.clientPrivateKey.sharedSecretFromKeyAgreement(with: serverKey)
                self.aead.rekey(sharedSecret: shared.withUnsafeBytes { Data($0) }, nonce: self.clientNonce)
            } catch {
                deadline.finish(nil, error)
                return
            }

            // 5. Send OpenTCP frame
            let openTCP = NCSudokuKIP.buildOpenTCP(target: self.target)
            guard let sealedOpen = try? self.aead.seal(plaintext: openTCP) else {
                deadline.finish(nil, NSError(domain: "NCSudoku", code: 13,
                                             userInfo: [NSLocalizedDescriptionKey: "Failed to seal OpenTCP"]))
                return
            }
            self.raw.send(self.codec.encode(sealedOpen))

            // Handshake complete!
            self.isHandshakeDone = true
            deadline.finish(self, nil)
        }
    }

    // MARK: - NCRelayStream Conformance

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !isCancelled, !data.isEmpty else {
            once.call()
            return
        }

        do {
            let record = try aead.seal(plaintext: data)
            let wire = codec.encode(record)
            raw.send(wire, completion: once.call)
        } catch {
            raw.cancel()
            once.call()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        guard !isCancelled else {
            handler(nil, nil)
            return
        }

        // Deliver any already buffered plaintext data first
        if !plainBuffer.isEmpty {
            let out = plainBuffer
            plainBuffer = Data()
            handler(out, nil)
            return
        }

        raw.receive { [weak self] data, err in
            guard let self else { handler(nil, err); return }
            if let err { handler(nil, err); return }
            guard let data, !data.isEmpty else {
                handler(nil, nil)
                return
            }

            self.wireBuffer.append(data)
            let decoded = self.codec.decode(self.wireBuffer)
            self.wireBuffer = Data()

            var stream = decoded
            var delivered = Data()
            while let chunk = try? self.aead.unseal(from: &stream) {
                delivered.append(chunk)
            }
            if !stream.isEmpty {
                self.plainBuffer.append(stream)
            }

            if !delivered.isEmpty {
                handler(delivered, nil)
            } else {
                self.receive(handler)
            }
        }
    }

    func cancel() {
        isCancelled = true
        raw.cancel()
    }
}
