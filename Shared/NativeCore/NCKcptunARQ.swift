import Foundation

// KCP ARQ protocol (Skywind3000 ikcp / metacubex/kcp-go parity) and Snappy framing (RFC / golang/snappy).
// Reference: kcp-go/kcp.go, transport/kcptun/comp.go.

// MARK: - CRC32C (Castagnoli) for Snappy

enum NCCRC32C {
    // Castagnoli polynomial 0x82f63b78
    private static let table: [UInt32] = (0...255).map { n in
        var c = UInt32(n)
        for _ in 0..<8 {
            c = (c & 1) != 0 ? 0x82f63b78 ^ (c >> 1) : c >> 1
        }
        return c
    }

    static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xffff_ffff
        for b in data {
            crc = table[Int((crc ^ UInt32(b)) & 0xff)] ^ (crc >> 8)
        }
        return crc ^ 0xffff_ffff
    }

    /// Masked CRC32C per Snappy framing format: ((crc >> 15) | (crc << 17)) + 0xa282ead8
    static func maskedChecksum(_ data: Data) -> UInt32 {
        let c = checksum(data)
        return ((c >> 15) | (c << 17)) &+ 0xa282_ead8
    }
}

// MARK: - Snappy Block & Framed Codec

enum NCSnappy {
    private static let magicHeader = Data([0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]) // sNaPpY

    // MARK: Block Decompression
    static func decompressBlock(_ src: Data) throws -> Data {
        guard !src.isEmpty else { return Data() }
        var pos = src.startIndex

        // Read varint-encoded uncompressed length
        var uncompressedLen = 0
        var shift = 0
        while pos < src.endIndex {
            let b = src[pos]
            pos += 1
            uncompressedLen |= Int(b & 0x7f) << shift
            if (b & 0x80) == 0 { break }
            shift += 7
            if shift > 35 { throw NCFramedRelay.err("snappy: malformed varint length") }
        }

        var out = Data()
        out.reserveCapacity(uncompressedLen)

        while pos < src.endIndex {
            let tag = src[pos]
            pos += 1
            let elType = tag & 0x03
            switch elType {
            case 0x00:
                // Literal
                var len = Int(tag >> 2) + 1
                if len > 60 {
                    let extraBytes = len - 60
                    guard pos + extraBytes <= src.endIndex else { throw NCFramedRelay.err("snappy: literal overrun") }
                    len = 0
                    for i in 0..<extraBytes {
                        len |= Int(src[pos + i]) << (i * 8)
                    }
                    len += 1
                    pos += extraBytes
                }
                guard pos + len <= src.endIndex else { throw NCFramedRelay.err("snappy: literal overrun") }
                out.append(src.subdata(in: pos..<(pos + len)))
                pos += len

            case 0x01:
                // Copy with 1-byte offset
                let len = Int((tag >> 2) & 0x07) + 4
                guard pos < src.endIndex else { throw NCFramedRelay.err("snappy: truncated copy") }
                let offset = (Int(tag >> 5) << 8) | Int(src[pos])
                pos += 1
                guard offset > 0, offset <= out.count else { throw NCFramedRelay.err("snappy: invalid copy offset \(offset)") }
                var srcIdx = out.count - offset
                for _ in 0..<len {
                    out.append(out[srcIdx])
                    srcIdx += 1
                }

            case 0x02:
                // Copy with 2-byte offset
                let len = Int(tag >> 2) + 1
                guard pos + 2 <= src.endIndex else { throw NCFramedRelay.err("snappy: truncated copy") }
                let offset = Int(src[pos]) | (Int(src[pos + 1]) << 8)
                pos += 2
                guard offset > 0, offset <= out.count else { throw NCFramedRelay.err("snappy: invalid copy offset \(offset)") }
                var srcIdx = out.count - offset
                for _ in 0..<len {
                    out.append(out[srcIdx])
                    srcIdx += 1
                }

            case 0x03:
                // Copy with 4-byte offset
                let len = Int(tag >> 2) + 1
                guard pos + 4 <= src.endIndex else { throw NCFramedRelay.err("snappy: truncated copy") }
                let offset = Int(src[pos]) | (Int(src[pos + 1]) << 8) | (Int(src[pos + 2]) << 16) | (Int(src[pos + 3]) << 24)
                pos += 4
                guard offset > 0, offset <= out.count else { throw NCFramedRelay.err("snappy: invalid copy offset \(offset)") }
                var srcIdx = out.count - offset
                for _ in 0..<len {
                    out.append(out[srcIdx])
                    srcIdx += 1
                }

            default:
                break
            }
        }
        return out
    }

    // MARK: Block Compression
    static func compressBlock(_ src: Data) -> Data {
        guard !src.isEmpty else { return Data([0x00]) }
        var out = Data()

        // Encode varint uncompressed length
        var lenVal = src.count
        while lenVal >= 0x80 {
            out.append(UInt8((lenVal & 0x7f) | 0x80))
            lenVal >>= 7
        }
        out.append(UInt8(lenVal & 0x7f))

        // Fast hash-table match finder (table size 4096 entries)
        let tableSize = 4096
        var table = [Int](repeating: -1, count: tableSize)

        func hash4(_ s: Data, _ idx: Int) -> Int {
            let u = UInt32(s[idx]) | UInt32(s[idx + 1]) << 8 | UInt32(s[idx + 2]) << 16 | UInt32(s[idx + 3]) << 24
            return Int((u &* 0x1e35a7bd) >> (32 - 12)) & (tableSize - 1)
        }

        func emitLiteral(_ lit: Data) {
            guard !lit.isEmpty else { return }
            var rest = lit[...]
            while !rest.isEmpty {
                let chunk = rest.prefix(65536)
                rest = rest.dropFirst(chunk.count)
                let c = chunk.count - 1
                if c < 60 {
                    out.append(UInt8(c << 2))
                } else if c < 256 {
                    out.append(contentsOf: [UInt8(60 << 2), UInt8(c)])
                } else {
                    out.append(contentsOf: [UInt8(61 << 2), UInt8(c & 0xff), UInt8((c >> 8) & 0xff)])
                }
                out.append(contentsOf: chunk)
            }
        }

        var anchor = src.startIndex
        var i = src.startIndex
        let limit = src.endIndex - 4

        while i < limit {
            let h = hash4(src, i)
            let candidate = table[h]
            table[h] = i

            let offset = i - candidate
            if candidate >= src.startIndex && offset < 65536 &&
               src[candidate] == src[i] &&
               src[candidate + 1] == src[i + 1] &&
               src[candidate + 2] == src[i + 2] &&
               src[candidate + 3] == src[i + 3] {

                // Emit preceding literals
                if i > anchor {
                    emitLiteral(src.subdata(in: anchor..<i))
                }

                // Match length
                var matchLen = 4
                while i + matchLen < src.endIndex && src[candidate + matchLen] == src[i + matchLen] && matchLen < 64 {
                    matchLen += 1
                }

                // Emit copy tag
                if offset < 2048 && matchLen <= 11 {
                    let lenCode = matchLen - 4
                    let offHi = (offset >> 8) & 0x07
                    out.append(UInt8(0x01 | (lenCode << 2) | (offHi << 5)))
                    out.append(UInt8(offset & 0xff))
                } else {
                    let lenCode = matchLen - 1
                    out.append(UInt8(0x02 | (lenCode << 2)))
                    out.append(UInt8(offset & 0xff))
                    out.append(UInt8((offset >> 8) & 0xff))
                }

                i += matchLen
                anchor = i
            } else {
                i += 1
            }
        }

        if anchor < src.endIndex {
            emitLiteral(src.subdata(in: anchor..<src.endIndex))
        }
        return out
    }
}

// MARK: - Snappy Framing Codec

final class NCSnappyFramedStream {
    private var headerWritten = false
    private var inbuf = Data()

    /// Encodes `data` into framed Snappy chunks (chunk size ≤ 65536).
    func encode(data: Data) -> Data {
        var wire = Data()
        if !headerWritten {
            headerWritten = true
            wire.append(Data([0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59])) // magic
        }
        guard !data.isEmpty else { return wire }

        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(65536))
            rest = rest.dropFirst(chunk.count)

            let crc = NCCRC32C.maskedChecksum(chunk)
            let compressed = NCSnappy.compressBlock(chunk)

            if compressed.count < chunk.count {
                // Chunk 0x00: Compressed data
                let chunkLen = 4 + compressed.count
                var head = Data([0x00, UInt8(chunkLen & 0xff), UInt8((chunkLen >> 8) & 0xff), UInt8((chunkLen >> 16) & 0xff)])
                head.append(UInt8(crc & 0xff))
                head.append(UInt8((crc >> 8) & 0xff))
                head.append(UInt8((crc >> 16) & 0xff))
                head.append(UInt8((crc >> 24) & 0xff))
                wire.append(head)
                wire.append(compressed)
            } else {
                // Chunk 0x01: Uncompressed data
                let chunkLen = 4 + chunk.count
                var head = Data([0x01, UInt8(chunkLen & 0xff), UInt8((chunkLen >> 8) & 0xff), UInt8((chunkLen >> 16) & 0xff)])
                head.append(UInt8(crc & 0xff))
                head.append(UInt8((crc >> 8) & 0xff))
                head.append(UInt8((crc >> 16) & 0xff))
                head.append(UInt8((crc >> 24) & 0xff))
                wire.append(head)
                wire.append(chunk)
            }
        }
        return wire
    }

    /// Feeds incoming wire bytes and decodes plaintext pieces.
    func decode(data: Data) throws -> [Data] {
        inbuf.append(data)
        var out: [Data] = []

        while inbuf.count >= 4 {
            let s = inbuf.startIndex
            let chunkType = inbuf[s]
            let chunkLen = Int(inbuf[s + 1]) | (Int(inbuf[s + 2]) << 8) | (Int(inbuf[s + 3]) << 16)
            guard inbuf.count >= 4 + chunkLen else { break }

            let chunkData = inbuf.subdata(in: (s + 4)..<(s + 4 + chunkLen))
            inbuf = Data(inbuf.dropFirst(4 + chunkLen))

            switch chunkType {
            case 0xff:
                // Stream identifier (must equal "sNaPpY")
                guard chunkData == Data([0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]) else {
                    throw NCFramedRelay.err("snappy: bad stream identifier")
                }
            case 0x00:
                // Compressed data
                guard chunkData.count >= 4 else { throw NCFramedRelay.err("snappy: short compressed chunk") }
                let c = chunkData.startIndex
                let expectedCRC = UInt32(chunkData[c]) | UInt32(chunkData[c + 1]) << 8 | UInt32(chunkData[c + 2]) << 16 | UInt32(chunkData[c + 3]) << 24
                let decompressed = try NCSnappy.decompressBlock(chunkData.dropFirst(4))
                guard NCCRC32C.maskedChecksum(decompressed) == expectedCRC else {
                    throw NCFramedRelay.err("snappy: CRC32C mismatch on compressed chunk")
                }
                if !decompressed.isEmpty { out.append(decompressed) }
            case 0x01:
                // Uncompressed data
                guard chunkData.count >= 4 else { throw NCFramedRelay.err("snappy: short uncompressed chunk") }
                let c = chunkData.startIndex
                let expectedCRC = UInt32(chunkData[c]) | UInt32(chunkData[c + 1]) << 8 | UInt32(chunkData[c + 2]) << 16 | UInt32(chunkData[c + 3]) << 24
                let raw = Data(chunkData.dropFirst(4))
                guard NCCRC32C.maskedChecksum(raw) == expectedCRC else {
                    throw NCFramedRelay.err("snappy: CRC32C mismatch on uncompressed chunk")
                }
                if !raw.isEmpty { out.append(raw) }
            case 0xfe:
                // Padding: skip
                break
            default:
                if chunkType <= 0x7f {
                    throw NCFramedRelay.err("snappy: unskippable chunk type \(chunkType)")
                }
                // > 0x7f: skippable unknown chunk
                break
            }
        }
        return out
    }
}

// MARK: - KCP ARQ Engine

final class NCKCPSegment {
    var conv: UInt32 = 0
    var cmd: UInt8 = 0
    var frg: UInt8 = 0
    var wnd: UInt16 = 0
    var ts: UInt32 = 0
    var sn: UInt32 = 0
    var una: UInt32 = 0
    var rto: UInt32 = 0
    var xmit: UInt32 = 0
    var resendts: UInt32 = 0
    var fastack: UInt32 = 0
    var acked: Bool = false
    var data: Data = Data()

    func encode() -> Data {
        var d = Data(capacity: 24 + data.count)
        d.append(UInt8(conv & 0xff)); d.append(UInt8((conv >> 8) & 0xff))
        d.append(UInt8((conv >> 16) & 0xff)); d.append(UInt8((conv >> 24) & 0xff))
        d.append(cmd)
        d.append(frg)
        d.append(UInt8(wnd & 0xff)); d.append(UInt8((wnd >> 8) & 0xff))
        d.append(UInt8(ts & 0xff)); d.append(UInt8((ts >> 8) & 0xff))
        d.append(UInt8((ts >> 16) & 0xff)); d.append(UInt8((ts >> 24) & 0xff))
        d.append(UInt8(sn & 0xff)); d.append(UInt8((sn >> 8) & 0xff))
        d.append(UInt8((sn >> 16) & 0xff)); d.append(UInt8((sn >> 24) & 0xff))
        d.append(UInt8(una & 0xff)); d.append(UInt8((una >> 8) & 0xff))
        d.append(UInt8((una >> 16) & 0xff)); d.append(UInt8((una >> 24) & 0xff))
        let len = UInt32(data.count)
        d.append(UInt8(len & 0xff)); d.append(UInt8((len >> 8) & 0xff))
        d.append(UInt8((len >> 16) & 0xff)); d.append(UInt8((len >> 24) & 0xff))
        d.append(data)
        return d
    }
}

final class NCKCP {
    let conv: UInt32
    var mtu: UInt32 = 1350
    var mss: UInt32 = 1350 - 24
    var state: UInt32 = 0

    var snd_una: UInt32 = 0
    var snd_nxt: UInt32 = 0
    var rcv_nxt: UInt32 = 0
    var ssthresh: UInt32 = 2
    var rx_rttvar: Int32 = 0
    var rx_srtt: Int32 = 0
    var rx_rto: UInt32 = 200
    var rx_minrto: UInt32 = 30

    var snd_wnd: UInt32 = 128
    var rcv_wnd: UInt32 = 128
    var rmt_wnd: UInt32 = 32
    var cwnd: UInt32 = 2
    var probe: UInt32 = 0

    var interval: UInt32 = 30
    var ts_flush: UInt32 = 30
    var nodelay: UInt32 = 0
    var updated: Bool = false
    var ts_probe: UInt32 = 0
    var probe_wait: UInt32 = 0
    var dead_link: UInt32 = 20
    var incr: UInt32 = 0

    var fastresend: Int32 = 2
    var nocwnd: Int32 = 1
    var stream: Bool = true

    // Queues
    var snd_queue: [NCKCPSegment] = []
    var snd_buf: [NCKCPSegment] = []
    var rcv_queue: [NCKCPSegment] = []
    var rcv_buf: [NCKCPSegment] = []
    var acklist: [(sn: UInt32, ts: UInt32)] = []

    var output: ((Data) -> Void)?

    private static let startTime = Date()
    static func currentMs() -> UInt32 {
        UInt32(truncatingIfNeeded: Int64(Date().timeIntervalSince(startTime) * 1000))
    }

    init(conv: UInt32, output: ((Data) -> Void)?) {
        self.conv = conv
        self.output = output
    }

    func setNoDelay(nodelay: Int, interval: Int, resend: Int, nc: Int) {
        self.nodelay = UInt32(nodelay)
        self.rx_minrto = nodelay > 0 ? 30 : 100
        self.interval = UInt32(interval)
        self.fastresend = Int32(resend)
        self.nocwnd = Int32(nc)
    }

    func setWindowSize(sndwnd: Int, rcvwnd: Int) {
        if sndwnd > 0 { self.snd_wnd = UInt32(sndwnd) }
        if rcvwnd > 0 { self.rcv_wnd = UInt32(rcvwnd) }
    }

    func setMTU(_ mtu: Int) {
        if mtu > 50 {
            self.mtu = UInt32(mtu)
            self.mss = self.mtu - 24
        }
    }

    // MARK: User Send
    func send(data: Data) {
        guard !data.isEmpty else { return }

        // In streaming mode, append to last segment in snd_queue if space available
        var rest = data[...]
        if stream, let last = snd_queue.last, last.data.count < Int(mss) {
            let cap = Int(mss) - last.data.count
            let take = min(cap, rest.count)
            last.data.append(contentsOf: rest.prefix(take))
            rest = rest.dropFirst(take)
        }
        guard !rest.isEmpty else { return }

        while !rest.isEmpty {
            let size = min(Int(mss), rest.count)
            let seg = NCKCPSegment()
            seg.conv = conv
            seg.cmd = 81 // IKCP_CMD_PUSH
            seg.frg = 0
            seg.data = Data(rest.prefix(size))
            rest = rest.dropFirst(size)
            snd_queue.append(seg)
        }
    }

    // MARK: User Receive
    func recv() -> Data? {
        guard !rcv_queue.isEmpty else { return nil }
        var result = Data()
        while !rcv_queue.isEmpty {
            let seg = rcv_queue.removeFirst()
            result.append(seg.data)
            if seg.frg == 0 { break }
        }

        // Move ready segments from rcv_buf to rcv_queue
        rcv_buf.sort { $0.sn < $1.sn }
        while !rcv_buf.isEmpty && rcv_buf[0].sn == rcv_nxt && rcv_queue.count < Int(rcv_wnd) {
            let seg = rcv_buf.removeFirst()
            rcv_queue.append(seg)
            rcv_nxt &+= 1
        }
        return result.isEmpty ? nil : result
    }

    // MARK: Input from Wire
    func input(data: Data) -> Int {
        guard data.count >= 24 else { return -1 }
        var p = data.startIndex

        while data.endIndex - p >= 24 {
            let c = UInt32(data[p]) | UInt32(data[p + 1]) << 8 | UInt32(data[p + 2]) << 16 | UInt32(data[p + 3]) << 24
            guard c == conv else { return -1 }
            let cmd = data[p + 4]
            let frg = data[p + 5]
            let wnd = UInt16(data[p + 6]) | UInt16(data[p + 7]) << 8
            let ts = UInt32(data[p + 8]) | UInt32(data[p + 9]) << 8 | UInt32(data[p + 10]) << 16 | UInt32(data[p + 11]) << 24
            let sn = UInt32(data[p + 12]) | UInt32(data[p + 13]) << 8 | UInt32(data[p + 14]) << 16 | UInt32(data[p + 15]) << 24
            let una = UInt32(data[p + 16]) | UInt32(data[p + 17]) << 8 | UInt32(data[p + 18]) << 16 | UInt32(data[p + 19]) << 24
            let len = UInt32(data[p + 20]) | UInt32(data[p + 21]) << 8 | UInt32(data[p + 22]) << 16 | UInt32(data[p + 23]) << 24
            p += 24

            guard data.endIndex - p >= Int(len) else { return -2 }
            let payload = data.subdata(in: p..<(p + Int(len)))
            p += Int(len)

            rmt_wnd = UInt32(wnd)
            parseUna(una)
            shrinkBuf()

            if cmd == 82 { // IKCP_CMD_ACK
                let current = Self.currentMs()
                if Int32(bitPattern: current &- ts) >= 0 {
                    updateRTT(rtt: Int32(bitPattern: current &- ts))
                }
                parseAck(sn)
                shrinkBuf()
            } else if cmd == 81 { // IKCP_CMD_PUSH
                if Int32(bitPattern: sn &- (rcv_nxt + rcv_wnd)) < 0 {
                    acklist.append((sn: sn, ts: ts))
                    if Int32(bitPattern: sn &- rcv_nxt) >= 0 {
                        let seg = NCKCPSegment()
                        seg.conv = conv
                        seg.cmd = cmd
                        seg.frg = frg
                        seg.wnd = wnd
                        seg.ts = ts
                        seg.sn = sn
                        seg.una = una
                        seg.data = payload
                        parseData(seg)
                    }
                }
            } else if cmd == 83 { // IKCP_CMD_WASK
                probe |= 2 // IKCP_ASK_TELL
            } else if cmd == 84 { // IKCP_CMD_WINS
                // Do nothing; rmt_wnd updated above
            }
        }
        return 0
    }

    private func parseUna(_ una: UInt32) {
        snd_buf.removeAll { seg in
            Int32(bitPattern: una &- seg.sn) > 0
        }
    }

    private func parseAck(_ sn: UInt32) {
        for seg in snd_buf {
            if seg.sn == sn {
                seg.acked = true
                break
            }
            if Int32(bitPattern: sn &- seg.sn) > 0 {
                seg.fastack &+= 1
            }
        }
    }

    private func shrinkBuf() {
        if let first = snd_buf.first {
            snd_una = first.sn
        } else {
            snd_una = snd_nxt
        }
    }

    private func parseData(_ newseg: NCKCPSegment) {
        let sn = newseg.sn
        if Int32(bitPattern: sn &- (rcv_nxt + rcv_wnd)) >= 0 || Int32(bitPattern: sn &- rcv_nxt) < 0 {
            return
        }
        if !rcv_buf.contains(where: { $0.sn == sn }) {
            rcv_buf.append(newseg)
            rcv_buf.sort { $0.sn < $1.sn }
        }
        while !rcv_buf.isEmpty && rcv_buf[0].sn == rcv_nxt && rcv_queue.count < Int(rcv_wnd) {
            let seg = rcv_buf.removeFirst()
            rcv_queue.append(seg)
            rcv_nxt &+= 1
        }
    }

    private func updateRTT(rtt: Int32) {
        if rx_srtt == 0 {
            rx_srtt = rtt
            rx_rttvar = rtt / 2
        } else {
            let delta = rtt - rx_srtt
            rx_srtt += delta / 8
            rx_rttvar += (abs(delta) - rx_rttvar) / 4
        }
        let rto = UInt32(rx_srtt + max(Int32(interval), 4 * rx_rttvar))
        rx_rto = min(60000, max(rx_minrto, rto))
    }

    // MARK: Flush & Update
    func update(currentMs: UInt32) {
        if !updated {
            updated = true
            ts_flush = currentMs
        }
        let slap = Int32(bitPattern: currentMs &- ts_flush)
        if slap >= 10000 || slap < -10000 {
            ts_flush = currentMs
            slap = 0
        }
        if slap >= 0 {
            ts_flush &+= interval
            if Int32(bitPattern: currentMs &- ts_flush) >= 0 {
                ts_flush = currentMs &+ interval
            }
            flush()
        }
    }

    func flush() {
        let current = Self.currentMs()
        var buffer = Data()

        func emit() {
            guard !buffer.isEmpty else { return }
            output?(buffer)
            buffer.removeAll(keepingCapacity: true)
        }

        func makeSpace(_ space: Int) {
            if buffer.count + space > Int(mtu) { emit() }
        }

        // 1. Flush ACKs
        for ack in acklist {
            makeSpace(24)
            let seg = NCKCPSegment()
            seg.conv = conv
            seg.cmd = 82 // IKCP_CMD_ACK
            seg.wnd = unusedWnd()
            seg.una = rcv_nxt
            seg.sn = ack.sn
            seg.ts = ack.ts
            buffer.append(seg.encode())
        }
        acklist.removeAll(keepingCapacity: true)

        // 2. Window probes
        if rmt_wnd == 0 {
            if probe_wait == 0 {
                probe_wait = 500
                ts_probe = current &+ probe_wait
            } else if Int32(bitPattern: current &- ts_probe) >= 0 {
                probe_wait = min(120000, probe_wait + probe_wait / 2)
                ts_probe = current &+ probe_wait
                probe |= 1 // IKCP_ASK_SEND
            }
        } else {
            ts_probe = 0
            probe_wait = 0
        }

        if (probe & 1) != 0 {
            makeSpace(24)
            let seg = NCKCPSegment()
            seg.conv = conv
            seg.cmd = 83 // IKCP_CMD_WASK
            seg.wnd = unusedWnd()
            seg.una = rcv_nxt
            buffer.append(seg.encode())
        }
        if (probe & 2) != 0 {
            makeSpace(24)
            let seg = NCKCPSegment()
            seg.conv = conv
            seg.cmd = 84 // IKCP_CMD_WINS
            seg.wnd = unusedWnd()
            seg.una = rcv_nxt
            buffer.append(seg.encode())
        }
        probe = 0

        // 3. Sliding window & sending new packets
        var cwndVal = min(snd_wnd, rmt_wnd)
        if nocwnd == 0 { cwndVal = min(cwnd, cwndVal) }

        while Int32(bitPattern: snd_nxt &- (snd_una &+ cwndVal)) < 0 && !snd_queue.isEmpty {
            let seg = snd_queue.removeFirst()
            seg.conv = conv
            seg.cmd = 81 // IKCP_CMD_PUSH
            seg.sn = snd_nxt
            snd_nxt &+= 1
            seg.una = rcv_nxt
            seg.ts = current
            seg.rto = rx_rto
            seg.fastack = 0
            seg.xmit = 0
            seg.resendts = current &+ seg.rto
            snd_buf.append(seg)
        }

        // 4. Flush snd_buf (retransmit / new transmit)
        var change = false
        var lost = false

        for seg in snd_buf {
            var needsSend = false
            if seg.xmit == 0 {
                needsSend = true
                seg.xmit &+= 1
                seg.rto = rx_rto
                seg.resendts = current &+ seg.rto
            } else if Int32(bitPattern: current &- seg.resendts) >= 0 {
                needsSend = true
                seg.xmit &+= 1
                if nodelay == 0 {
                    seg.rto &+= max(seg.rto, rx_rto)
                } else {
                    seg.rto &+= (nodelay < 2 ? seg.rto : rx_rto) / 2
                }
                seg.resendts = current &+ seg.rto
                lost = true
            } else if seg.fastack >= UInt32(fastresend) {
                needsSend = true
                seg.xmit &+= 1
                seg.fastack = 0
                seg.resendts = current &+ seg.rto
                change = true
            }

            if needsSend {
                seg.ts = current
                seg.wnd = unusedWnd()
                seg.una = rcv_nxt
                let enc = seg.encode()
                makeSpace(enc.count)
                buffer.append(enc)
                if seg.xmit >= dead_link { state = 0xffff_ffff }
            }
        }

        emit()

        // Congestion window adjustments
        if change {
            let inflight = snd_nxt &- snd_una
            ssthresh = max(2, inflight / 2)
            cwnd = ssthresh &+ UInt32(fastresend)
            incr = cwnd &* mss
        }
        if lost {
            ssthresh = max(2, cwnd / 2)
            cwnd = 1
            incr = mss
        }
        if cwnd < 1 {
            cwnd = 1
            incr = mss
        }
    }

    private func unusedWnd() -> UInt16 {
        if rcv_queue.count < Int(rcv_wnd) {
            return UInt16(min(65535, Int(rcv_wnd) - rcv_queue.count))
        }
        return 0
    }
}
