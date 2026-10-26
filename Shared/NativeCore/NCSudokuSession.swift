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
    let keyData: Data

    private var sendEpoch: UInt32 = 0
    private var sendSeq: UInt64 = 0
    private var recvEpoch: UInt32 = 0
    private var recvSeq: UInt64 = 0

    init(method: NCSudoku.AEADMethod, key: String) {
        self.method = method
        // Key is hashed with SHA-256 to derive cipher key
        let rawKey: Data
        if key.count == 128, let d = NCSudoku.hexDecode(key) {
            rawKey = d
        } else if key.count == 64, let d = NCSudoku.hexDecode(key) {
            rawKey = d
        } else {
            rawKey = Data(key.utf8)
        }
        let hash = SHA256.hash(data: rawKey)
        keyData = Data(hash)
    }

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
        sendSeq &+= 1
        for i in (0..<4).reversed() { header.append(UInt8((ep >> (i * 8)) & 0xff)) }
        for i in (0..<8).reversed() { header.append(UInt8((sq >> (i * 8)) & 0xff)) }

        let ciphertext: Data
        switch method {
        case .chacha20Poly1305:
            let nonce = try ChaChaPoly.Nonce(data: header)
            let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: keyData), nonce: nonce, authenticating: header)
            ciphertext = box.ciphertext + box.tag
        case .aes128GCM:
            let nonce = try AES.GCM.Nonce(data: header)
            let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: keyData.prefix(16)), nonce: nonce, authenticating: header)
            ciphertext = box.ciphertext + box.tag
        case .none:
            ciphertext = plaintext
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
        let cipherTotal = bodyLen - 12
        guard cipherTotal >= 16 else {
            throw NSError(domain: "NCSudoku", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Ciphertext shorter than authentication tag"])
        }
        let ct = buffer.subdata(in: (buffer.startIndex + 14)..<(buffer.startIndex + 14 + cipherTotal - 16))
        let tag = buffer.subdata(in: (buffer.startIndex + 14 + cipherTotal - 16)..<(buffer.startIndex + 2 + bodyLen))
        buffer = buffer.dropFirst(2 + bodyLen)

        switch method {
        case .chacha20Poly1305:
            let nonce = try ChaChaPoly.Nonce(data: header)
            let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: header)
        case .aes128GCM:
            let nonce = try AES.GCM.Nonce(data: header)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: keyData.prefix(16)), authenticating: header)
        case .none:
            return ct
        }
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

        // Seeded deterministic shuffle of the 288 canonical grids
        let rawKey: Data
        if key.count == 128, let d = NCSudoku.hexDecode(key) { rawKey = d }
        else if key.count == 64, let d = NCSudoku.hexDecode(key) { rawKey = d }
        else { rawKey = Data(key.utf8) }

        var perm = Self.canonicalGrids
        Self.deterministicShuffle(&perm, seed: Data(SHA256.hash(data: rawKey)))

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

    private static func deterministicShuffle<T>(_ list: inout [T], seed: Data) {
        guard list.count > 1 else { return }
        var prng = SeededPRNG(seed: seed)
        for i in (1..<list.count).reversed() {
            let j = Int(prng.next() % UInt64(i + 1))
            if i != j { list.swapAt(i, j) }
        }
    }

    private struct SeededPRNG {
        private var state: UInt64
        init(seed: Data) {
            var s: UInt64 = 0x5a5a5a5a12345678
            for (idx, byte) in seed.enumerated() {
                s ^= (UInt64(byte) << ((idx % 8) * 8))
            }
            state = s != 0 ? s : 0x123456789abcdef0
        }
        mutating func next() -> UInt64 {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return state
        }
    }
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

            do {
                _ = try NCSudokuKIP.parseServerHello(payload: msg.payload, expectedNonce: self.clientNonce)
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
