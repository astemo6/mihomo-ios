import Compression
import Foundation
import Libmihomo
import os

/// feat/native-mitm stage 1: the native body lane (bridge/mitm/nativelane.go, work/native-mitm-design.md §3).
///
/// Response bodies that only scripts read are streamed here by the Go engine, still encoded, in ≤ 32 KB chunks
/// (`open` / `write` / `finish`) and decoded as they arrive with the Compression framework (gzip, deflate, br —
/// `COMPRESSION_BROTLI`, iOS 15+, the tunnel targets 17). The decoded bytes live in malloc'd memory, never in the
/// Go heap: the JavaScriptCore engine reads them directly for `__tern.take` of ids ≥ `LibmihomoNativeBlobBase()`
/// (JSCScriptEngine `nativeBlobs`), stores large results here (`store`), and Go streams the final body to the
/// client with `read`.
///
/// Every method is synchronous and thread-safe. The Go side owns handle lifetimes (`free`); Go counts internal
/// failures (anything but "too-big" / "decode: …") and switches the lane off for the session after three.
final class NativeBodyStore: NSObject, LibmihomoNativeBodyStoreProtocol, JSCNativeBlobProvider {
    static let shared = NativeBodyStore()

    /// Large `__tern.put` / UTF-8 results at least this big stay in the lane (smaller ones go to Go as before).
    let putMin = 64 << 10
    /// Decoder output scratch per call.
    private static let scratchSize = 64 << 10
    /// Refuse new bodies below this much available memory (Go's dynamic budget normally refuses first).
    private static let availFloor = 6 << 20

    private enum Codec { case identity, gzip, deflate, brotli }

    private final class Body {
        let codec: Codec
        let limit: Int
        let lock = NSLock()
        /// The bytes as received (identity: also the decoded bytes — `dec` stays empty and `decoded` reads `raw`).
        var raw = Data()
        var dec = Data()
        var err = ""
        var failed = false
        var finished = false
        // decoder state
        var stream: UnsafeMutablePointer<compression_stream>?
        var streamEnded = false
        /// gzip: bytes of `raw` already consumed as headers / deflate data / trailers; deflate: zlib header seen.
        var consumed = 0
        var inHeader = true
        var trailerLeft = 0

        init(codec: Codec, limit: Int, hint: Int) {
            self.codec = codec
            self.limit = limit
            if hint > 0 { raw.reserveCapacity(min(hint, limit)) }
        }

        var decoded: Data { codec == .identity ? raw : dec }

        deinit { closeStream() }

        func closeStream() {
            if let s = stream {
                compression_stream_destroy(s)
                s.deallocate()
                stream = nil
            }
        }
    }

    private let lock = NSLock()
    private var bodies: [Int64: Body] = [:]
    private var seq: Int64 = 0
    private var opened = 0
    private var refused = 0

    private override init() { super.init() }

    /// Registers the lane with the core (after JSCScriptEngine.register() succeeded) and with the JS engine.
    static func register() {
        JSCScriptEngine.nativeBlobs = shared
        LibmihomoSetNativeBodyStore(shared)
    }

    // MARK: LibmihomoNativeBodyStoreProtocol

    func open(_ enc: String?, limit: Int64, hint: Int64) -> Int64 {
        let codec: Codec
        switch (enc ?? "").trimmingCharacters(in: .whitespaces).lowercased() {
        case "", "identity": codec = .identity
        case "gzip", "x-gzip": codec = .gzip
        case "deflate": codec = .deflate
        case "br": codec = .brotli
        default: return refuse()
        }
        // 0 = not a memory-limited process (the app, the simulator): no floor
        let avail = os_proc_available_memory()
        if avail > 0 && avail < Self.availFloor { return refuse() }
        let b = Body(codec: codec, limit: Int(clamping: limit), hint: Int(clamping: hint))
        if codec == .brotli {
            // The deflate-family streams start once their header is known (`feedDeflate`); brotli has none.
            guard Self.startStream(b, COMPRESSION_BROTLI) else { return refuse() }
        }
        lock.lock()
        seq += 1
        let h = seq
        bodies[h] = b
        opened += 1
        lock.unlock()
        return h
    }

    func write(_ h: Int64, b data: Data?) -> String {
        guard let b = body(h) else { return "gone" }
        guard let data, !data.isEmpty else { return "" }
        b.lock.lock()
        defer { b.lock.unlock() }
        if b.failed { return b.err == "too-big" ? "too-big" : "decode: " + b.err }
        if b.finished { return "internal: write after finish" }
        if b.raw.count + data.count > b.limit && (b.codec == .identity || b.raw.count + data.count > Self.rawCap(b.limit)) {
            fail(b, "too-big")
            return "too-big"
        }
        b.raw.append(data)
        if b.codec == .identity { return "" }
        return decodeAvailable(b, finalize: false)
    }

    func finish(_ h: Int64) -> Int64 {
        guard let b = body(h) else { return -3 }
        b.lock.lock()
        defer { b.lock.unlock() }
        if b.failed { return b.err == "too-big" ? -2 : -1 }
        if b.codec != .identity {
            let r = decodeAvailable(b, finalize: true)
            if !r.isEmpty { return r == "too-big" ? -2 : (r.hasPrefix("decode:") ? -1 : -3) }
            if !b.streamEnded {
                fail(b, "unexpected end of compressed data")
                return -1
            }
            b.closeStream()
        }
        b.finished = true
        return Int64(b.decoded.count)
    }

    func err(_ h: Int64) -> String {
        guard let b = body(h) else { return "gone" }
        b.lock.lock()
        defer { b.lock.unlock() }
        return b.err
    }

    func len(_ h: Int64, raw: Bool) -> Int64 {
        guard let b = body(h) else { return -1 }
        b.lock.lock()
        defer { b.lock.unlock() }
        return Int64(raw ? b.raw.count : b.decoded.count)
    }

    func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data? {
        guard let b = body(h) else { return nil }
        b.lock.lock()
        defer { b.lock.unlock() }
        let src = raw ? b.raw : b.decoded
        let o = Int(clamping: off)
        guard o >= 0, n >= 0 else { return nil }
        if o >= src.count { return Data() }
        let end = min(src.count, o + Int(clamping: n))
        // Data indices are relative to startIndex (a slice may not start at 0)
        return src.subdata(in: (src.startIndex + o)..<(src.startIndex + end))
    }

    func free(_ h: Int64) {
        lock.lock()
        let b = bodies.removeValue(forKey: h)
        lock.unlock()
        if let b {
            b.lock.lock()
            b.closeStream()
            b.raw = Data()
            b.dec = Data()
            b.lock.unlock()
        }
    }

    func stats() -> String {
        lock.lock()
        let all = Array(bodies.values)
        let o = opened, r = refused
        lock.unlock()
        var bytes = 0
        for b in all {
            b.lock.lock()
            bytes += b.raw.count + b.dec.count
            b.lock.unlock()
        }
        return "native bodies \(all.count) (\(String(format: "%.1f", Double(bytes) / 1_048_576)) MB), opened \(o), refused \(r)"
    }

    // MARK: JSCNativeBlobProvider (JavaScriptCore engine, on the thread running JavaScript)

    func withDecoded(_ h: Int64, _ body: (UnsafeRawBufferPointer) -> Void) -> Bool {
        guard let b = self.body(h) else { return false }
        b.lock.lock()
        defer { b.lock.unlock() }
        guard !b.failed else { return false }
        b.decoded.withUnsafeBytes { body($0) }
        return true
    }

    func text(_ h: Int64) -> String? {
        guard let b = body(h) else { return nil }
        b.lock.lock()
        defer { b.lock.unlock() }
        // Valid UTF-8 only: invalid input goes to the Go host, whose U+FFFD replacement is the reference
        // (strings.ToValidUTF8 — one U+FFFD per run of invalid bytes).
        return String(data: b.decoded, encoding: .utf8)
    }

    func store(_ bytes: UnsafeRawBufferPointer) -> Int64 {
        let b = Body(codec: .identity, limit: bytes.count, hint: 0)
        if let base = bytes.baseAddress, bytes.count > 0 { b.raw = Data(bytes: base, count: bytes.count) }
        b.finished = true
        lock.lock()
        seq += 1
        let h = seq
        bodies[h] = b
        lock.unlock()
        return h
    }

    // MARK: decoding

    private func body(_ h: Int64) -> Body? {
        lock.lock()
        defer { lock.unlock() }
        return bodies[h]
    }

    private func refuse() -> Int64 {
        lock.lock()
        refused += 1
        lock.unlock()
        return 0
    }

    /// The encoded size accepted for a compressed body with this decoded limit (a compressed body is smaller
    /// than its decoded form except for incompressible data, where it is barely larger).
    private static func rawCap(_ limit: Int) -> Int { limit + limit / 8 + 64 << 10 }

    private func fail(_ b: Body, _ why: String) {
        b.failed = true
        b.err = why
        b.closeStream()
        b.dec = Data()
    }

    private static func startStream(_ b: Body, _ algorithm: compression_algorithm) -> Bool {
        let s = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        guard compression_stream_init(s, COMPRESSION_STREAM_DECODE, algorithm) == COMPRESSION_STATUS_OK else {
            s.deallocate()
            return false
        }
        b.stream = s
        return true
    }

    /// Decodes what `raw` holds past `consumed`. "" ok, "too-big", "decode: …", or "internal: …". Caller holds b.lock.
    private func decodeAvailable(_ b: Body, finalize: Bool) -> String {
        while true {
            if b.failed { return b.err == "too-big" ? "too-big" : "decode: " + b.err }
            switch b.codec {
            case .identity:
                return ""
            case .brotli:
                return pump(b, finalize: finalize)
            case .deflate:
                if b.inHeader {
                    // zlib wrapper (RFC 1950) as HTTP specifies; raw DEFLATE when the first two bytes are not one
                    // (some servers), like the Go path.
                    if b.raw.count < 2 { return finalize ? fail2(b, "truncated deflate header") : "" }
                    let cmf = b.raw[b.raw.startIndex], flg = b.raw[b.raw.startIndex + 1]
                    let zlib = cmf & 0x0f == 8 && (UInt16(cmf) << 8 | UInt16(flg)) % 31 == 0
                    if zlib && flg & 0x20 != 0 { return fail2(b, "zlib preset dictionary not supported") }
                    b.consumed = zlib ? 2 : 0
                    b.inHeader = false
                    guard Self.startStream(b, COMPRESSION_ZLIB) else { return "internal: stream init" }
                }
                if b.streamEnded { return "" } // adler32 trailer and anything after it are ignored
                return pump(b, finalize: finalize)
            case .gzip:
                if b.trailerLeft > 0 {
                    let take = min(b.trailerLeft, b.raw.count - b.consumed)
                    b.consumed += take
                    b.trailerLeft -= take
                    if b.trailerLeft > 0 { return finalize ? fail2(b, "truncated gzip trailer") : "" }
                    b.inHeader = true // another member may follow (multi-member gzip)
                }
                if b.inHeader {
                    if b.consumed == b.raw.count {
                        // nothing after a complete member: done; before the first member: wait
                        if b.streamEnded || !finalize { return "" }
                        return fail2(b, "empty gzip body")
                    }
                    switch Self.gzipHeaderLength(b.raw, from: b.consumed) {
                    case .some(-1):
                        if b.streamEnded { b.consumed = b.raw.count; return "" } // trailing garbage after a member
                        return fail2(b, "invalid gzip header")
                    case .some(let n):
                        b.consumed += n
                        b.inHeader = false
                        b.streamEnded = false
                        b.closeStream()
                        guard Self.startStream(b, COMPRESSION_ZLIB) else { return "internal: stream init" }
                    case .none:
                        return finalize ? fail2(b, "truncated gzip header") : ""
                    }
                }
                let r = pump(b, finalize: finalize)
                if !r.isEmpty { return r }
                if b.streamEnded {
                    b.trailerLeft = 8 // CRC32 + ISIZE
                    continue
                }
                if finalize { return fail2(b, "unexpected end of gzip data") }
                return ""
            }
        }
    }

    private func fail2(_ b: Body, _ why: String) -> String {
        fail(b, why)
        return "decode: " + why
    }

    /// Runs the stream over raw[consumed...], appending output to dec (limit enforced). Sets streamEnded when the
    /// compressed stream ended (the bytes after it stay unconsumed). Caller holds b.lock.
    private func pump(_ b: Body, finalize: Bool) -> String {
        guard let s = b.stream else { return b.streamEnded ? "" : "internal: no stream" }
        if b.streamEnded { return "" }
        let avail = b.raw.count - b.consumed
        if avail == 0 && !finalize { return "" }
        var result = ""
        let scratch = UnsafeMutablePointer<UInt8>.allocate(capacity: Self.scratchSize)
        defer { scratch.deallocate() }
        b.raw.withUnsafeBytes { (rawBuf: UnsafeRawBufferPointer) in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else {
                // empty buffer: only a finalize call gets here
                s.pointee.src_ptr = UnsafePointer(scratch)
                s.pointee.src_size = 0
                result = drain(b, s, scratch, flags: finalize ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0)
                return
            }
            s.pointee.src_ptr = base + b.consumed
            s.pointee.src_size = avail
            result = drain(b, s, scratch, flags: finalize ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0)
            // a failure inside drain destroyed the stream (fail → closeStream): s must not be read then
            if !b.failed { b.consumed = b.raw.count - s.pointee.src_size }
        }
        return result
    }

    /// compression_stream_process until the input is used up (or the stream ended) and the output drained.
    private func drain(_ b: Body, _ s: UnsafeMutablePointer<compression_stream>, _ scratch: UnsafeMutablePointer<UInt8>, flags: Int32) -> String {
        while true {
            s.pointee.dst_ptr = scratch
            s.pointee.dst_size = Self.scratchSize
            let status = compression_stream_process(s, flags)
            let produced = Self.scratchSize - s.pointee.dst_size
            if produced > 0 {
                if b.dec.count + produced > b.limit {
                    fail(b, "too-big")
                    return "too-big"
                }
                b.dec.append(scratch, count: produced)
            }
            switch status {
            case COMPRESSION_STATUS_END:
                b.streamEnded = true
                return ""
            case COMPRESSION_STATUS_OK:
                // more to do while input remains or the output buffer came back full
                if s.pointee.src_size == 0 && produced < Self.scratchSize { return "" }
            default:
                fail(b, "corrupt compressed data")
                return "decode: corrupt compressed data"
            }
        }
    }

    /// Length of the gzip member header at raw[from...]: nil = need more bytes, -1 = not a gzip header.
    private static func gzipHeaderLength(_ raw: Data, from: Int) -> Int? {
        let n = raw.count - from
        if n < 10 { return n >= 2 && !(raw[raw.startIndex + from] == 0x1f && raw[raw.startIndex + from + 1] == 0x8b) ? -1 : nil }
        let p = raw.startIndex + from
        guard raw[p] == 0x1f, raw[p + 1] == 0x8b, raw[p + 2] == 8 else { return -1 }
        let flags = raw[p + 3]
        var i = 10
        if flags & 0x04 != 0 { // FEXTRA
            guard n >= i + 2 else { return nil }
            let xlen = Int(raw[p + i]) | Int(raw[p + i + 1]) << 8
            i += 2 + xlen
            guard n >= i else { return nil }
        }
        for bit in [UInt8(0x08), 0x10] where flags & bit != 0 { // FNAME, FCOMMENT: zero-terminated
            while true {
                guard n > i else { return nil }
                let c = raw[p + i]
                i += 1
                if c == 0 { break }
            }
        }
        if flags & 0x02 != 0 { // FHCRC
            i += 2
            guard n >= i else { return nil }
        }
        return i
    }
}
