import Foundation
import CryptoKit
import CommonCrypto

// kcptun packet crypto and Reed-Solomon FEC (kcp-go / klauspost/reedsolomon parity).
// Reference: mihomo transport/kcptun + metacubex/kcp-go (crypt.go, fec.go).

// MARK: - Options

struct NCKcptunOptions: Equatable {
    // Memory limit constants (Network Extension ~50MiB budget priority)
    static let defaultRcvWnd = 128      // mihomo default 512; capped to 128 to bound segment buffer
    static let defaultSndWnd = 128      // mihomo default 128
    static let defaultSmuxBuf = 524288  // 512 KiB; mihomo default 4 MiB
    static let defaultStreamBuf = 262144 // 256 KiB; mihomo default 2 MiB
    static let defaultMTU = 1350
    static let defaultDataShard = 10
    static let defaultParityShard = 3

    var key: String
    var crypt: String
    var mode: String
    var conn: Int
    var autoExpire: Int
    var scavengeTTL: Int
    var mtu: Int
    var sndWnd: Int
    var rcvWnd: Int
    var dataShard: Int
    var parityShard: Int
    var dscp: Int
    var noComp: Bool
    var ackNoDelay: Bool
    var noDelay: Int
    var interval: Int
    var resend: Int
    var nc: Int
    var sockBuf: Int
    var smuxVer: Int
    var smuxBuf: Int
    var frameSize: Int
    var streamBuf: Int
    var keepAlive: Int

    var fecEnabled: Bool { dataShard > 0 && parityShard > 0 }

    /// Cache key for sharing long-lived session across connections to the same node
    var cacheKey: String {
        "\(crypt):\(key):\(mode):\(mtu):\(dataShard):\(parityShard):\(noComp):\(smuxVer)"
    }

    static func parse(_ opts: [String: NCJSONValue]) -> (NCKcptunOptions?, String?) {
        func lookup(_ key: String) -> NCJSONValue? {
            let target = key.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
            for (k, v) in opts {
                let norm = k.lowercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: "_", with: "")
                if norm == target { return v }
            }
            return nil
        }

        let key = lookup("key")?.string ?? "it's a secrect"
        let crypt = (lookup("crypt")?.string ?? "aes").lowercased()
        let mode = (lookup("mode")?.string ?? "fast").lowercased()
        let conn = max(1, lookup("conn")?.int ?? 1)
        let autoExpire = lookup("autoexpire")?.int ?? 0
        let scavengeTTL = lookup("scavengettl")?.int ?? 600
        let mtu = lookup("mtu")?.int ?? defaultMTU
        let sndWnd = lookup("sndwnd")?.int ?? defaultSndWnd
        // Bound rcvWnd to memory budget
        let requestedRcvWnd = lookup("rcvwnd")?.int ?? defaultRcvWnd
        let rcvWnd = min(requestedRcvWnd, defaultRcvWnd)

        let dataShard = lookup("datashard")?.int ?? defaultDataShard
        let parityShard = lookup("parityshard")?.int ?? defaultParityShard
        let dscp = lookup("dscp")?.int ?? 0
        let noComp = lookup("nocomp")?.bool ?? false
        let ackNoDelay = lookup("acknodelay")?.bool ?? false

        var noDelay = 0
        var interval = 30
        var resend = 2
        var nc = 1
        switch mode {
        case "normal":
            noDelay = 0; interval = 40; resend = 2; nc = 1
        case "fast":
            noDelay = 0; interval = 30; resend = 2; nc = 1
        case "fast2":
            noDelay = 1; interval = 20; resend = 2; nc = 1
        case "fast3":
            noDelay = 1; interval = 10; resend = 2; nc = 1
        default:
            break
        }
        if let nd = lookup("nodelay")?.int { noDelay = nd }
        if let itv = lookup("interval")?.int { interval = itv }
        if let r = lookup("resend")?.int { resend = r }
        if let c = lookup("nc")?.int ?? lookup("nocongestion")?.int { nc = c }

        let sockBuf = lookup("sockbuf")?.int ?? 4194304
        let smuxVer = min(2, max(1, lookup("smuxver")?.int ?? 1))
        let requestedSmuxBuf = lookup("smuxbuf")?.int ?? defaultSmuxBuf
        let smuxBuf = min(requestedSmuxBuf, defaultSmuxBuf)
        let frameSize = lookup("framesize")?.int ?? 8192
        let requestedStreamBuf = lookup("streambuf")?.int ?? defaultStreamBuf
        let streamBuf = min(requestedStreamBuf, defaultStreamBuf)
        let keepAlive = lookup("keepalive")?.int ?? 10

        let options = NCKcptunOptions(
            key: key, crypt: crypt, mode: mode, conn: conn, autoExpire: autoExpire,
            scavengeTTL: scavengeTTL, mtu: mtu, sndWnd: sndWnd, rcvWnd: rcvWnd,
            dataShard: dataShard, parityShard: parityShard, dscp: dscp, noComp: noComp,
            ackNoDelay: ackNoDelay, noDelay: noDelay, interval: interval, resend: resend,
            nc: nc, sockBuf: sockBuf, smuxVer: smuxVer, smuxBuf: smuxBuf, frameSize: frameSize,
            streamBuf: streamBuf, keepAlive: keepAlive
        )
        return (options, nil)
    }
}

// MARK: - Packet Crypto

enum NCKcptunCryptMode {
    case none
    case aes256CFB(NCAES)
    case aes128CFB(NCAES)
    case aes128GCM(SymmetricKey)
    case salsa20(Data)
}

final class NCKcptunBlockCrypt {
    private let mode: NCKcptunCryptMode
    private static let initialVector: [UInt8] = [167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107]
    private static let salt = Data("kcp-go".utf8)

    init?(crypt: String, password: String) {
        let c = crypt.lowercased()
        if c == "none" || c == "null" {
            mode = .none
            return
        }

        func deriveKey(length: Int) -> Data {
            var out = [UInt8](repeating: 0, count: length)
            let passData = Data(password.utf8)
            _ = passData.withUnsafeBytes { pw in
                Self.salt.withUnsafeBytes { sw in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pw.baseAddress!.assumingMemoryBound(to: Int8.self), pw.count,
                        sw.baseAddress!.assumingMemoryBound(to: UInt8.self), sw.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 4096,
                        &out, length)
                }
            }
            return Data(out)
        }

        switch c {
        case "aes", "aes-256":
            let k = deriveKey(length: 32)
            guard let aes = NCAES(key: k) else { return nil }
            mode = .aes256CFB(aes)
        case "aes-128":
            let k = deriveKey(length: 16)
            guard let aes = NCAES(key: k) else { return nil }
            mode = .aes128CFB(aes)
        case "aes-128-gcm":
            let k = deriveKey(length: 16)
            mode = .aes128GCM(SymmetricKey(data: k))
        case "salsa20":
            let k = deriveKey(length: 32)
            mode = .salsa20(k)
        default:
            // Fallback to aes-256-cfb as mihomo default
            let k = deriveKey(length: 32)
            guard let aes = NCAES(key: k) else { return nil }
            mode = .aes256CFB(aes)
        }
    }

    /// Encrypts an outgoing datagram payload.
    func seal(_ payload: Data) -> Data {
        switch mode {
        case .none:
            return payload
        case .aes256CFB(let aes), .aes128CFB(let aes):
            // Format: Nonce(16) || CRC32(4 LE) || payload
            var buf = NCConnector.randomData(16)
            let checksum = NCCRC32.checksum(payload)
            buf.append(UInt8(checksum & 0xff))
            buf.append(UInt8((checksum >> 8) & 0xff))
            buf.append(UInt8((checksum >> 16) & 0xff))
            buf.append(UInt8((checksum >> 24) & 0xff))
            buf.append(payload)
            return Self.cfb128Encrypt(aes: aes, data: buf)
        case .aes128GCM(let key):
            let nonce = NCConnector.randomData(12)
            if let gcmNonce = try? AES.GCM.Nonce(data: nonce),
               let sealed = try? AES.GCM.seal(payload, using: key, nonce: gcmNonce) {
                return nonce + sealed.ciphertext + sealed.tag
            }
            return payload
        case .salsa20(let key):
            // salsa20BlockCrypt: first 8 bytes random nonce, then Salsa20 over rest
            let nonce = NCConnector.randomData(8)
            var body = [UInt8](payload)
            NCSalsa20.xorKeyStream(data: &body, key: key, nonce: nonce)
            return nonce + Data(body)
        }
    }

    /// Decrypts an incoming datagram packet. Returns nil if checksum or auth tag verification fails.
    func open(_ packet: Data) -> Data? {
        switch mode {
        case .none:
            return packet
        case .aes256CFB(let aes), .aes128CFB(let aes):
            guard packet.count >= 20 else { return nil }
            let plain = Self.cfb128Decrypt(aes: aes, data: packet)
            guard plain.count >= 20 else { return nil }
            let p = plain.startIndex
            let expected = UInt32(plain[p + 16]) | UInt32(plain[p + 17]) << 8 | UInt32(plain[p + 18]) << 16 | UInt32(plain[p + 19]) << 24
            let payload = plain.subdata(in: (p + 20)..<plain.endIndex)
            guard NCCRC32.checksum(payload) == expected else { return nil }
            return payload
        case .aes128GCM(let key):
            guard packet.count >= 12 + 16 else { return nil }
            let nonce = packet.prefix(12)
            let ctext = packet.subdata(in: 12..<(packet.count - 16))
            let tag = packet.suffix(16)
            guard let gcmNonce = try? AES.GCM.Nonce(data: nonce),
                  let box = try? AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ctext, tag: tag),
                  let dec = try? AES.GCM.open(box, using: key) else { return nil }
            return dec
        case .salsa20(let key):
            guard packet.count >= 8 else { return nil }
            let nonce = packet.prefix(8)
            var body = [UInt8](packet.dropFirst(8))
            NCSalsa20.xorKeyStream(data: &body, key: key, nonce: nonce)
            return Data(body)
        }
    }

    private static func cfb128Encrypt(aes: NCAES, data: Data) -> Data {
        var tbl = aes.encryptBlock(Data(initialVector))
        var dst = [UInt8](repeating: 0, count: data.count)
        let s = [UInt8](data)
        var base = 0
        while base + 16 <= s.count {
            for i in 0..<16 { dst[base + i] = s[base + i] ^ tbl[tbl.startIndex + i] }
            tbl = aes.encryptBlock(Data(dst[base..<(base + 16)]))
            base += 16
        }
        let left = s.count - base
        if left > 0 {
            for i in 0..<left { dst[base + i] = s[base + i] ^ tbl[tbl.startIndex + i] }
        }
        return Data(dst)
    }

    private static func cfb128Decrypt(aes: NCAES, data: Data) -> Data {
        var tbl = aes.encryptBlock(Data(initialVector))
        var dst = [UInt8](repeating: 0, count: data.count)
        let s = [UInt8](data)
        var base = 0
        while base + 16 <= s.count {
            for i in 0..<16 { dst[base + i] = s[base + i] ^ tbl[tbl.startIndex + i] }
            tbl = aes.encryptBlock(Data(s[base..<(base + 16)]))
            base += 16
        }
        let left = s.count - base
        if left > 0 {
            for i in 0..<left { dst[base + i] = s[base + i] ^ tbl[tbl.startIndex + i] }
        }
        return Data(dst)
    }
}

// MARK: - Reed-Solomon GF(2^8) Erasure Coding

enum NCGalois {
    static let (logTable, expTable): ([UInt8], [UInt8]) = {
        var logs = [UInt8](repeating: 0, count: 256)
        var exps = [UInt8](repeating: 0, count: 512)
        var b = 1
        for log in 0..<255 {
            logs[b] = UInt8(log)
            exps[log] = UInt8(b)
            exps[log + 255] = UInt8(b)
            b <<= 1
            if b >= 256 { b ^= 285 } // polynomial 29 = 285 = x^8 + x^4 + x^3 + x^2 + 1
        }
        return (logs, exps)
    }()

    static func multiply(_ a: UInt8, _ b: UInt8) -> UInt8 {
        if a == 0 || b == 0 { return 0 }
        let logA = Int(logTable[Int(a)])
        let logB = Int(logTable[Int(b)])
        return expTable[logA + logB]
    }

    static func inverse(_ a: UInt8) -> UInt8 {
        if a == 0 { return 0 }
        return expTable[255 - Int(logTable[Int(a)])]
    }

    static func exp(_ a: UInt8, _ n: Int) -> UInt8 {
        if n == 0 { return 1 }
        if a == 0 { return 0 }
        let logA = Int(logTable[Int(a)])
        var logResult = logA * n
        while logResult >= 255 { logResult -= 255 }
        return expTable[logResult]
    }
}

final class NCReedSolomon {
    let dataShards: Int
    let parityShards: Int
    let totalShards: Int
    private var matrix: [[UInt8]] // totalShards x dataShards

    init?(dataShards: Int, parityShards: Int) {
        guard dataShards > 0, parityShards > 0, dataShards + parityShards <= 256 else { return nil }
        self.dataShards = dataShards
        self.parityShards = parityShards
        self.totalShards = dataShards + parityShards

        // Build Vandermonde matrix (totalShards x dataShards)
        var vm = [[UInt8]](repeating: [UInt8](repeating: 0, count: dataShards), count: totalShards)
        for r in 0..<totalShards {
            for c in 0..<dataShards {
                vm[r][c] = NCGalois.exp(UInt8(r), c)
            }
        }

        // Invert top dataShards x dataShards square
        var top = [[UInt8]](repeating: [UInt8](repeating: 0, count: dataShards), count: dataShards)
        for r in 0..<dataShards {
            for c in 0..<dataShards { top[r][c] = vm[r][c] }
        }
        guard let topInv = Self.invertMatrix(top) else { return nil }

        // Multiply vm by topInv to create coding matrix with identity top square
        var m = [[UInt8]](repeating: [UInt8](repeating: 0, count: dataShards), count: totalShards)
        for r in 0..<totalShards {
            for c in 0..<dataShards {
                var val: UInt8 = 0
                for k in 0..<dataShards {
                    val ^= NCGalois.multiply(vm[r][k], topInv[k][c])
                }
                m[r][c] = val
            }
        }
        self.matrix = m
    }

    /// Generates parity shards for data shards. All data shards must have equal count.
    func encode(data: [Data]) -> [Data] {
        guard data.count == dataShards, let size = data.first?.count, size > 0 else { return [] }
        var parity = [[UInt8]](repeating: [UInt8](repeating: 0, count: size), count: parityShards)
        let dataArrays = data.map { [UInt8]($0) }

        for p in 0..<parityShards {
            let row = matrix[dataShards + p]
            for d in 0..<dataShards {
                let coeff = row[d]
                if coeff == 0 { continue }
                let shard = dataArrays[d]
                for i in 0..<size {
                    parity[p][i] ^= NCGalois.multiply(coeff, shard[i])
                }
            }
        }
        return parity.map { Data($0) }
    }

    /// Reconstructs missing data shards in-place in `shards` (length totalShards).
    /// Returns true if reconstruction succeeded.
    func reconstructData(shards: inout [Data?]) -> Bool {
        guard shards.count == totalShards else { return false }
        // Check if all data shards are already present
        var missingDataIndices: [Int] = []
        for i in 0..<dataShards {
            if shards[i] == nil { missingDataIndices.append(i) }
        }
        if missingDataIndices.isEmpty { return true }

        // Find shard length from available shards
        var shardLen = 0
        for s in shards {
            if let count = s?.count, count > 0 { shardLen = count; break }
        }
        guard shardLen > 0 else { return false }

        // Collect dataShards available shard indices
        var submatrixRows = [[UInt8]]()
        var subData = [[UInt8]]()
        for i in 0..<totalShards {
            if let d = shards[i], d.count == shardLen {
                submatrixRows.append(matrix[i])
                subData.append([UInt8](d))
                if submatrixRows.count == dataShards { break }
            }
        }
        guard submatrixRows.count == dataShards, let inv = Self.invertMatrix(submatrixRows) else { return false }

        // Reconstruct each missing data shard
        for missingIdx in missingDataIndices {
            var recovered = [UInt8](repeating: 0, count: shardLen)
            let row = inv[missingIdx]
            for k in 0..<dataShards {
                let coeff = row[k]
                if coeff == 0 { continue }
                let source = subData[k]
                for i in 0..<shardLen {
                    recovered[i] ^= NCGalois.multiply(coeff, source[i])
                }
            }
            shards[missingIdx] = Data(recovered)
        }
        return true
    }

    private static func invertMatrix(_ m: [[UInt8]]) -> [[UInt8]]? {
        let size = m.count
        var work = [[UInt8]](repeating: [UInt8](repeating: 0, count: size * 2), count: size)
        for r in 0..<size {
            for c in 0..<size { work[r][c] = m[r][c] }
            work[r][size + r] = 1
        }
        // Gaussian elimination
        for r in 0..<size {
            if work[r][r] == 0 {
                var swapped = false
                for rowBelow in (r + 1)..<size {
                    if work[rowBelow][r] != 0 {
                        work.swapAt(r, rowBelow)
                        swapped = true
                        break
                    }
                }
                if !swapped { return nil } // Singular
            }
            if work[r][r] != 1 {
                let scale = NCGalois.inverse(work[r][r])
                for c in 0..<(size * 2) {
                    work[r][c] = NCGalois.multiply(work[r][c], scale)
                }
            }
            for rowBelow in (r + 1)..<size {
                if work[rowBelow][r] != 0 {
                    let scale = work[rowBelow][r]
                    for c in 0..<(size * 2) {
                        work[rowBelow][c] ^= NCGalois.multiply(scale, work[r][c])
                    }
                }
            }
        }
        for d in 0..<size {
            for rowAbove in 0..<d {
                if work[rowAbove][d] != 0 {
                    let scale = work[rowAbove][d]
                    for c in 0..<(size * 2) {
                        work[rowAbove][c] ^= NCGalois.multiply(scale, work[d][c])
                    }
                }
            }
        }
        var result = [[UInt8]](repeating: [UInt8](repeating: 0, count: size), count: size)
        for r in 0..<size {
            for c in 0..<size { result[r][c] = work[r][size + c] }
        }
        return result
    }
}

// MARK: - FEC Encoder & Decoder

final class NCKcptunFEC {
    private let dataShards: Int
    private let parityShards: Int
    private let shardSize: Int
    private let paws: UInt32
    private let rs: NCReedSolomon?

    // Encoder state
    private var encSeq: UInt32 = 0
    private var encShardCount = 0
    private var encDataShards: [Data] = []
    private var encMaxSize = 0

    // Decoder state: shardMap[initialShardId] = [seqid: data]
    private var decShardSets: [UInt32: [UInt32: (flag: UInt16, data: Data)]] = [:]
    private var newestShardId: UInt32 = 0
    private static let maxShardSets = 3 // Bounded memory cache

    init(dataShards: Int, parityShards: Int) {
        self.dataShards = dataShards
        self.parityShards = parityShards
        self.shardSize = dataShards + parityShards
        self.paws = shardSize > 0 ? (0xffff_ffff / UInt32(shardSize)) * UInt32(shardSize) : 0
        self.rs = NCReedSolomon(dataShards: dataShards, parityShards: parityShards)
    }

    /// Encodes an outgoing packet with FEC header (seqid:4 LE, flag:2 LE, len:2 LE).
    /// Returns: (dataPacket, [parityPackets]). Parity packets are emitted only when quorum is reached.
    func encode(packet: Data) -> (data: Data, parity: [Data]) {
        guard let rs, dataShards > 0, parityShards > 0 else { return (packet, []) }

        // Data packet header: seqid (LE32) || flag=0xf1 (LE16) || len (LE16) || payload
        var dataPacket = Data(capacity: 8 + packet.count)
        let seq = encSeq
        encSeq &+= 1
        dataPacket.append(UInt8(seq & 0xff))
        dataPacket.append(UInt8((seq >> 8) & 0xff))
        dataPacket.append(UInt8((seq >> 16) & 0xff))
        dataPacket.append(UInt8((seq >> 24) & 0xff))
        dataPacket.append(contentsOf: [0xf1, 0x00]) // typeData 0xf1
        dataPacket.append(UInt8(packet.count & 0xff))
        dataPacket.append(UInt8((packet.count >> 8) & 0xff))
        dataPacket.append(packet)

        encDataShards.append(Data(dataPacket.dropFirst(6))) // includes 2-byte len + packet
        encMaxSize = max(encMaxSize, dataPacket.count - 6)
        encShardCount += 1

        if encShardCount == dataShards {
            // Equalize shard sizes by zero-padding to encMaxSize
            var equalized: [Data] = []
            for d in encDataShards {
                var copy = d
                if copy.count < encMaxSize {
                    copy.append(Data(repeating: 0, count: encMaxSize - copy.count))
                }
                equalized.append(copy)
            }
            let parityShardsData = rs.encode(data: equalized)

            var parityPackets: [Data] = []
            for pShard in parityShardsData {
                let pSeq = encSeq
                encSeq &+= 1
                var pPacket = Data(capacity: 6 + pShard.count)
                pPacket.append(UInt8(pSeq & 0xff))
                pPacket.append(UInt8((pSeq >> 8) & 0xff))
                pPacket.append(UInt8((pSeq >> 16) & 0xff))
                pPacket.append(UInt8((pSeq >> 24) & 0xff))
                pPacket.append(contentsOf: [0xf2, 0x00]) // typeParity 0xf2
                pPacket.append(pShard)
                parityPackets.append(pPacket)
            }

            encDataShards.removeAll(keepingCapacity: true)
            encShardCount = 0
            encMaxSize = 0
            return (dataPacket, parityPackets)
        }

        return (dataPacket, [])
    }

    /// Decodes an incoming packet. Returns recovered or unfragmented KCP packets.
    func decode(packet: Data) -> [Data] {
        guard let rs, dataShards > 0, parityShards > 0 else { return [packet] }
        guard packet.count >= 6 else { return [] }

        let p = packet.startIndex
        let seq = UInt32(packet[p]) | UInt32(packet[p + 1]) << 8 | UInt32(packet[p + 2]) << 16 | UInt32(packet[p + 3]) << 24
        let flag = UInt16(packet[p + 4]) | UInt16(packet[p + 5]) << 8
        guard seq < paws else { return [] }

        let payload = packet.subdata(in: (p + 6)..<packet.endIndex)
        let shardId = seq / UInt32(shardSize)

        var set = decShardSets[shardId] ?? [:]
        if set[seq] != nil { return [] } // Duplicate
        set[seq] = (flag: flag, data: payload)
        decShardSets[shardId] = set

        if Int32(bitPattern: shardId * UInt32(shardSize) &- newestShardId * UInt32(shardSize)) > 0 {
            newestShardId = shardId
        }

        // Check if we can emit or recover from this set
        var out: [Data] = []
        if flag == 0xf1 {
            // Immediate pass of intact data packet
            if payload.count >= 2 {
                let len = Int(payload[0]) | Int(payload[1]) << 8
                if payload.count >= 2 + len {
                    out.append(payload.subdata(in: 2..<(2 + len)))
                }
            }
        }

        // If shard set has at least dataShards shards and some data shards were missing, reconstruct!
        if set.count >= dataShards {
            var shards = [Data?](repeating: nil, count: shardSize)
            var maxLen = 0
            var missingCount = 0
            for i in 0..<shardSize {
                let sSeq = shardId * UInt32(shardSize) + UInt32(i)
                if let item = set[sSeq] {
                    shards[i] = item.data
                    maxLen = max(maxLen, item.data.count)
                } else if i < dataShards {
                    missingCount += 1
                }
            }

            if missingCount > 0 && maxLen > 0 {
                // Zero-pad available shards to maxLen
                for i in 0..<shardSize {
                    if var d = shards[i], d.count < maxLen {
                        d.append(Data(repeating: 0, count: maxLen - d.count))
                        shards[i] = d
                    }
                }
                if rs.reconstructData(shards: &shards) {
                    for i in 0..<dataShards {
                        let sSeq = shardId * UInt32(shardSize) + UInt32(i)
                        if set[sSeq] == nil, let rec = shards[i], rec.count >= 2 {
                            let len = Int(rec[0]) | Int(rec[1]) << 8
                            if rec.count >= 2 + len {
                                out.append(rec.subdata(in: 2..<(2 + len)))
                            }
                        }
                    }
                }
            }
        }

        // Bounded pruning of old shard sets
        let minKeep = newestShardId > UInt32(Self.maxShardSets) ? newestShardId - UInt32(Self.maxShardSets) : 0
        decShardSets = decShardSets.filter { $0.key >= minKeep }

        return out
    }
}
