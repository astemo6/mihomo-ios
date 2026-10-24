// Native MitM stage 3 lane s3-h2: HTTP/2 frame codec (RFC 9113 §4, §6).
//
// Frames are parsed from an H2ByteQueue (the connection's receive buffer) with the per-type size and stream-id
// rules of §6 checked here; the connection (H2Connection.swift) applies the state-machine rules. Errors carry
// the RFC error code and whether they are connection errors (stream 0) or stream errors.
// PRIORITY is parsed only to be validated and ignored (RFC 9113 deprecates the priority scheme); unknown frame
// types are skipped (§4.1, §5.5).

import Foundation

enum H2FrameType: UInt8 {
    case data = 0, headers = 1, priority = 2, rstStream = 3, settings = 4, pushPromise = 5, ping = 6, goaway = 7,
         windowUpdate = 8, continuation = 9
}

enum H2Flag {
    static let endStream: UInt8 = 0x1
    static let ack: UInt8 = 0x1
    static let endHeaders: UInt8 = 0x4
    static let padded: UInt8 = 0x8
    static let priority: UInt8 = 0x20
}

enum H2ErrorCode: UInt32 {
    case noError = 0x0, protocolError = 0x1, internalError = 0x2, flowControlError = 0x3, settingsTimeout = 0x4,
         streamClosed = 0x5, frameSizeError = 0x6, refusedStream = 0x7, cancel = 0x8, compressionError = 0x9,
         connectError = 0xa, enhanceYourCalm = 0xb, inadequateSecurity = 0xc, http11Required = 0xd

    init(code: UInt32) { self = H2ErrorCode(rawValue: code) ?? .internalError }
}

enum H2Setting: UInt16 {
    case headerTableSize = 0x1, enablePush = 0x2, maxConcurrentStreams = 0x3, initialWindowSize = 0x4,
         maxFrameSize = 0x5, maxHeaderListSize = 0x6, enableConnectProtocol = 0x8
}

/// A protocol error: stream 0 = connection error (GOAWAY), else a stream error (RST_STREAM).
struct H2Error: Error, Equatable, CustomStringConvertible {
    let code: H2ErrorCode
    let stream: UInt32
    let reason: String
    init(_ code: H2ErrorCode, stream: UInt32 = 0, _ reason: String) { self.code = code; self.stream = stream; self.reason = reason }
    var isConnectionError: Bool { stream == 0 }
    var description: String { "h2 \(code) on \(stream == 0 ? "connection" : "stream \(stream)"): \(reason)" }
}

enum H2Frame: Equatable {
    /// flowSize: the whole frame payload incl. padding (what flow control counts).
    case data(stream: UInt32, payload: [UInt8], endStream: Bool, flowSize: Int)
    case headers(stream: UInt32, block: [UInt8], endStream: Bool, endHeaders: Bool)
    case priority(stream: UInt32)
    case rstStream(stream: UInt32, code: UInt32)
    case settings(ack: Bool, values: [H2SettingValue])
    case pushPromise(stream: UInt32, promised: UInt32, block: [UInt8], endHeaders: Bool)
    case ping(ack: Bool, payload: [UInt8])
    case goaway(lastStream: UInt32, code: UInt32, debug: [UInt8])
    case windowUpdate(stream: UInt32, increment: UInt32)
    case continuation(stream: UInt32, block: [UInt8], endHeaders: Bool)
    case unknown(type: UInt8, stream: UInt32)
}

struct H2SettingValue: Equatable {
    let id: UInt16
    let value: UInt32
    init(_ id: UInt16, _ value: UInt32) { self.id = id; self.value = value }
    init(_ s: H2Setting, _ value: UInt32) { id = s.rawValue; self.value = value }
}

/// Receive buffer: appended to at the tail, consumed from the head; compacts as it goes.
struct H2ByteQueue {
    private(set) var bytes: [UInt8] = []
    private(set) var head = 0
    var count: Int { bytes.count - head }

    mutating func append(_ d: Data) {
        if head > 0 && head >= bytes.count / 2 {
            bytes.removeFirst(head)
            head = 0
        }
        bytes.append(contentsOf: d)
    }
    mutating func append(_ d: [UInt8]) { append(Data(d)) }

    subscript(i: Int) -> UInt8 { bytes[head + i] }

    mutating func take(_ n: Int) -> [UInt8] {
        let s = Array(bytes[head..<(head + n)])
        head += n
        if head == bytes.count { bytes.removeAll(keepingCapacity: true); head = 0 }
        return s
    }

    mutating func skip(_ n: Int) {
        head += n
        if head == bytes.count { bytes.removeAll(keepingCapacity: true); head = 0 }
    }

    mutating func reset() { bytes = []; head = 0 }
}

enum H2Wire {
    static let preface: [UInt8] = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    static let maxWindow = Int(Int32.max)          // 2^31 - 1
    static let defaultWindow = 65_535
    static let defaultMaxFrame = 16_384

    static func u32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
    }
    static func put32(_ v: UInt32, into out: inout [UInt8]) {
        out.append(UInt8(truncatingIfNeeded: v >> 24)); out.append(UInt8(truncatingIfNeeded: v >> 16))
        out.append(UInt8(truncatingIfNeeded: v >> 8)); out.append(UInt8(truncatingIfNeeded: v))
    }
}

struct H2FrameDecoder {
    /// SETTINGS_MAX_FRAME_SIZE we advertised.
    var maxFrameSize = H2Wire.defaultMaxFrame

    /// The next complete frame, or nil when more bytes are needed. Throws H2Error.
    mutating func next(_ q: inout H2ByteQueue) throws -> H2Frame? {
        guard q.count >= 9 else { return nil }
        let length = Int(q[0]) << 16 | Int(q[1]) << 8 | Int(q[2])
        let type = q[3]
        let flags = q[4]
        let stream = (UInt32(q[5]) << 24 | UInt32(q[6]) << 16 | UInt32(q[7]) << 8 | UInt32(q[8])) & 0x7fff_ffff
        if length > maxFrameSize { throw H2Error(.frameSizeError, "frame of \(length) bytes > \(maxFrameSize)") }
        guard q.count >= 9 + length else { return nil }
        q.skip(9)
        let p = q.take(length)
        return try Self.parse(type: type, flags: flags, stream: stream, payload: p)
    }

    static func parse(type: UInt8, flags: UInt8, stream: UInt32, payload p: [UInt8]) throws -> H2Frame {
        guard let t = H2FrameType(rawValue: type) else { return .unknown(type: type, stream: stream) }
        func needStream() throws { if stream == 0 { throw H2Error(.protocolError, "\(t) on stream 0") } }
        func needConn() throws { if stream != 0 { throw H2Error(.protocolError, "\(t) on stream \(stream)") } }
        /// Strips padding (PADDED flag): returns the content range.
        func unpad(_ start: Int) throws -> Range<Int> {
            if flags & H2Flag.padded == 0 { return start..<p.count }
            guard p.count > start else { throw H2Error(.protocolError, "\(t) padding length missing") }
            let pad = Int(p[start])
            guard pad <= p.count - start - 1 else { throw H2Error(.protocolError, "\(t) padding exceeds payload") }
            return (start + 1)..<(p.count - pad)
        }
        switch t {
        case .data:
            try needStream()
            let r = try unpad(0)
            return .data(stream: stream, payload: Array(p[r]), endStream: flags & H2Flag.endStream != 0, flowSize: p.count)
        case .headers:
            try needStream()
            var r = try unpad(0)
            if flags & H2Flag.priority != 0 {
                guard r.count >= 5 else { throw H2Error(.frameSizeError, "HEADERS priority fields missing") }
                let dep = H2Wire.u32(p, r.lowerBound) & 0x7fff_ffff
                if dep == stream { throw H2Error(.protocolError, stream: stream, "stream depends on itself") }
                r = (r.lowerBound + 5)..<r.upperBound
            }
            return .headers(stream: stream, block: Array(p[r]), endStream: flags & H2Flag.endStream != 0,
                            endHeaders: flags & H2Flag.endHeaders != 0)
        case .priority:
            try needStream()
            guard p.count == 5 else { throw H2Error(.frameSizeError, stream: stream, "PRIORITY of \(p.count) bytes") }
            return .priority(stream: stream)
        case .rstStream:
            try needStream()
            guard p.count == 4 else { throw H2Error(.frameSizeError, "RST_STREAM of \(p.count) bytes") }
            return .rstStream(stream: stream, code: H2Wire.u32(p, 0))
        case .settings:
            try needConn()
            if flags & H2Flag.ack != 0 {
                guard p.isEmpty else { throw H2Error(.frameSizeError, "SETTINGS ack with payload") }
                return .settings(ack: true, values: [])
            }
            guard p.count % 6 == 0 else { throw H2Error(.frameSizeError, "SETTINGS of \(p.count) bytes") }
            var vs: [H2SettingValue] = []
            var i = 0
            while i < p.count {
                vs.append(H2SettingValue(UInt16(p[i]) << 8 | UInt16(p[i + 1]), H2Wire.u32(p, i + 2)))
                i += 6
            }
            return .settings(ack: false, values: vs)
        case .pushPromise:
            try needStream()
            let r = try unpad(0)
            guard r.count >= 4 else { throw H2Error(.frameSizeError, "PUSH_PROMISE too short") }
            return .pushPromise(stream: stream, promised: H2Wire.u32(p, r.lowerBound) & 0x7fff_ffff,
                                block: Array(p[(r.lowerBound + 4)..<r.upperBound]), endHeaders: flags & H2Flag.endHeaders != 0)
        case .ping:
            try needConn()
            guard p.count == 8 else { throw H2Error(.frameSizeError, "PING of \(p.count) bytes") }
            return .ping(ack: flags & H2Flag.ack != 0, payload: p)
        case .goaway:
            try needConn()
            guard p.count >= 8 else { throw H2Error(.frameSizeError, "GOAWAY of \(p.count) bytes") }
            return .goaway(lastStream: H2Wire.u32(p, 0) & 0x7fff_ffff, code: H2Wire.u32(p, 4), debug: Array(p[8...]))
        case .windowUpdate:
            guard p.count == 4 else { throw H2Error(.frameSizeError, "WINDOW_UPDATE of \(p.count) bytes") }
            return .windowUpdate(stream: stream, increment: H2Wire.u32(p, 0) & 0x7fff_ffff)
        case .continuation:
            try needStream()
            return .continuation(stream: stream, block: p, endHeaders: flags & H2Flag.endHeaders != 0)
        }
    }
}

enum H2FrameEncoder {
    static func header(length: Int, type: H2FrameType, flags: UInt8, stream: UInt32, into out: inout [UInt8]) {
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(type.rawValue)
        out.append(flags)
        H2Wire.put32(stream & 0x7fff_ffff, into: &out)
    }

    static func data<C: Collection>(stream: UInt32, _ payload: C, endStream: Bool, into out: inout [UInt8]) where C.Element == UInt8 {
        header(length: payload.count, type: .data, flags: endStream ? H2Flag.endStream : 0, stream: stream, into: &out)
        out.append(contentsOf: payload)
    }

    /// HEADERS (+ CONTINUATION frames when the block exceeds maxFrame).
    static func headers(stream: UInt32, block: [UInt8], endStream: Bool, maxFrame: Int, into out: inout [UInt8]) {
        var off = 0
        var first = true
        repeat {
            let n = min(maxFrame, block.count - off)
            let last = off + n == block.count
            var flags: UInt8 = last ? H2Flag.endHeaders : 0
            if first && endStream { flags |= H2Flag.endStream }
            header(length: n, type: first ? .headers : .continuation, flags: flags, stream: stream, into: &out)
            out.append(contentsOf: block[off..<(off + n)])
            off += n
            first = false
        } while off < block.count
    }

    static func settings(_ values: [H2SettingValue], into out: inout [UInt8]) {
        header(length: values.count * 6, type: .settings, flags: 0, stream: 0, into: &out)
        for v in values {
            out.append(UInt8(v.id >> 8)); out.append(UInt8(v.id & 0xff))
            H2Wire.put32(v.value, into: &out)
        }
    }

    static func settingsAck(into out: inout [UInt8]) { header(length: 0, type: .settings, flags: H2Flag.ack, stream: 0, into: &out) }

    static func ping(ack: Bool, _ payload: [UInt8], into out: inout [UInt8]) {
        header(length: 8, type: .ping, flags: ack ? H2Flag.ack : 0, stream: 0, into: &out)
        out.append(contentsOf: payload.prefix(8))
        if payload.count < 8 { out.append(contentsOf: [UInt8](repeating: 0, count: 8 - payload.count)) }
    }

    static func goaway(lastStream: UInt32, code: H2ErrorCode, debug: String = "", into out: inout [UInt8]) {
        let d = Array(debug.utf8.prefix(256))
        header(length: 8 + d.count, type: .goaway, flags: 0, stream: 0, into: &out)
        H2Wire.put32(lastStream & 0x7fff_ffff, into: &out)
        H2Wire.put32(code.rawValue, into: &out)
        out.append(contentsOf: d)
    }

    static func windowUpdate(stream: UInt32, increment: Int, into out: inout [UInt8]) {
        header(length: 4, type: .windowUpdate, flags: 0, stream: stream, into: &out)
        H2Wire.put32(UInt32(increment) & 0x7fff_ffff, into: &out)
    }

    static func rstStream(stream: UInt32, code: H2ErrorCode, into out: inout [UInt8]) {
        header(length: 4, type: .rstStream, flags: 0, stream: stream, into: &out)
        H2Wire.put32(code.rawValue, into: &out)
    }

    /// Test helpers / completeness.
    static func priority(stream: UInt32, dependsOn: UInt32, weight: UInt8, into out: inout [UInt8]) {
        header(length: 5, type: .priority, flags: 0, stream: stream, into: &out)
        H2Wire.put32(dependsOn & 0x7fff_ffff, into: &out)
        out.append(weight)
    }

    static func raw(type: UInt8, flags: UInt8, stream: UInt32, payload: [UInt8], into out: inout [UInt8]) {
        out.append(UInt8(truncatingIfNeeded: payload.count >> 16))
        out.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        out.append(UInt8(truncatingIfNeeded: payload.count))
        out.append(type)
        out.append(flags)
        H2Wire.put32(stream & 0x7fff_ffff, into: &out)
        out.append(contentsOf: payload)
    }
}
