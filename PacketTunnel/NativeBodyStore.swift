// Go-zero (nc-integrate): one build of this file — the NativeCore tunnel; the app target compiles the same code
// for its unit tests (tunnel-engine calls behind TERN_TUNNEL). The Go-backed variant is gone with bridge/.
import Compression
import Foundation
import os

/// The native body lane for MitM response bodies.
/// Decodes gzip, deflate, and brotli streamingly into malloc'd memory without touching Go.
/// JSC reads them directly through JSCNativeBlobProvider.
final class NativeBodyStore: NSObject, JSCNativeBlobProvider {
    static let shared = NativeBodyStore()
    static let defaultBlobBase: Int64 = 10_000_000

    /// Large `__tern.put` / UTF-8 results at least this big stay in the lane (smaller ones go to Go as before).
    let putMin = 64 << 10
    /// Decoder output scratch per call.
    private static let scratchSize = 64 << 10
    /// Refuse new bodies below this much available memory (Go's dynamic budget normally refuses first).
    private static let availFloor = 6 << 20
    /// rv2-life: all live bodies together (raw + decoded bytes) stay under this; a new body / store / adopt that
    /// would cross it is refused (the caller falls back to its non-lane path). 12 MB ≈ a quarter of the ~50 MB
    /// extension limit — one big body plus a few small ones; the governor / floor still refuse earlier under pressure.
    static let totalCap = 12 << 20
    /// rv2-life: a finished body nobody freed for this long is dropped (a script that died between `put` and `free`
    /// leaked its bodies until the tunnel stopped). Script runs are capped far below this.
    static let ttl: TimeInterval = 180
    private static let sweepEvery: TimeInterval = 15

    fileprivate enum Codec { case identity, gzip, deflate, brotli }

    fileprivate final class Body {
        let codec: Codec
        let limit: Int
        let lock = NSLock()
        /// The bytes as received (identity: also the decoded bytes — `dec` stays empty and `decoded` reads `raw`).
        var raw = Data()
        var dec = Data()
        var err = ""
        var failed = false
        var finished = false
        /// Set by `free` (a caller still holding the object from before sees a dead handle).
        var gone = false
        // decoder state
        var stream: UnsafeMutablePointer<compression_stream>?
        var streamEnded = false
        /// gzip: bytes of `raw` already consumed as headers / deflate data / trailers; deflate: zlib header seen.
        var consumed = 0
        var inHeader = true
        /// gzip member being decoded: CRC-32 and size of its output (checked against the trailer like Go's
        /// compress/gzip, so a damaged body never reaches a script).
        var crc: UInt32 = 0
        var memberSize = 0
        /// gzip: bytes after a complete member that are not another member — ignored to the end.
        var ignoreRest = false
        /// gzip: the member's deflate stream ended; its trailer is searched in raw[trailerSearch...trailerMax+8].
        var awaitTrailer = false
        var trailerSearch = 0
        var trailerMax = 0
        /// Where the last two pumps started in `raw` and where the last one ended: the stream's end lies in
        /// there (the previous call too in case the decoder only reports END on the next call). memberStart =
        /// first deflate byte of the current gzip member.
        var callStart = 0
        var prevCallStart = 0
        var callEnd = 0
        var memberStart = 0
        /// feat/s3-mem: capacity reserved from the hint; trimForMemory copies each finished body at most once.
        var reserved = 0
        var compacted = false
        /// NativeCore: the script body budget's charge (every appended raw / decoded byte; released on free).
        var charge: NativeBodyCharge?
        /// rv2-life: for the TTL sweep, and the bytes this body counts in the store's `liveBytes`.
        let createdAt = Date()
        var finishedAt: Date?
        var counted = 0

        init(codec: Codec, limit: Int, hint: Int) {
            self.codec = codec
            self.limit = limit
            if hint > 0 {
                reserved = min(hint, limit)
                raw.reserveCapacity(reserved)
            }
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
    /// rv2-life: raw + decoded bytes of all live bodies (under `lock`; bodies report growth through `account`).
    private var liveBytes = 0
    private var lastSweep = Date.distantPast
    private var expired = 0

    private override init() { super.init() }

    /// Registers the lane with the JS engine.
    static func register() {
        JSCScriptEngine.nativeBlobs = shared
    }

    // MARK: In-process Body Store

    func open(_ enc: String?, limit: Int64, hint: Int64) -> Int64 {
        open(enc, limit: limit, hint: hint, charge: nil)
    }

    /// NativeCore: with a charge the script body budget already admitted the body (raw length above its reserve) and
    /// charges every byte as it is appended, so the store's own floor / governor admission is skipped and nothing is
    /// reserved from the hint beyond the raw length.
    func open(_ enc: String?, limit: Int64, hint: Int64, charge: NativeBodyCharge?) -> Int64 {
        let codec: Codec
        switch (enc ?? "").trimmingCharacters(in: .whitespaces).lowercased() {
        case "", "identity": codec = .identity
        case "gzip", "x-gzip": codec = .gzip
        case "deflate": codec = .deflate
        case "br": codec = .brotli
        default: return refuse()
        }
        sweepIfDue()
        if !fitsTotal(hint > 0 ? min(Int(clamping: hint), Int(clamping: limit)) : 0) { return refuse() }
        if charge != nil {
            // admitted by NativeScriptBodyBudget (live reading, actual bytes charged below)
        } else if let g = NativeMemoryGovernor.active {
            // feat/s3-mem: the native governor admits by size (small bodies down to ~4.5 MB, reclaim first)
            if !g.admit(.body, bytes: hint > 0 ? Int(clamping: hint) : -1) { return refuse() }
        } else {
            // 0 = not a memory-limited process (the app, the simulator): no floor
            let avail = os_proc_available_memory()
            if avail > 0 && avail < Self.availFloor { return refuse() }
        }
        let b = Body(codec: codec, limit: Int(clamping: limit), hint: Int(clamping: hint))
        b.charge = charge
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
        guard let b = locked(h) else { return "gone" }
        defer { b.lock.unlock() }
        guard let data, !data.isEmpty else { return "" }
        if b.failed { return b.err == "too-big" ? "too-big" : "decode: " + b.err }
        if b.finished { return "internal: write after finish" }
        if b.raw.count + data.count > b.limit && (b.codec == .identity || b.raw.count + data.count > Self.rawCap(b.limit)) {
            fail(b, "too-big")
            return "too-big"
        }
        if let c = b.charge, !c.grow(data.count) {
            fail(b, "too-big")
            return "too-big"
        }
        // rv2-life: the store-wide cap (raw growth; decoded growth is accounted after the fact below)
        if !fitsTotal(data.count) {
            fail(b, "too-big")
            return "too-big"
        }
        b.raw.append(data)
        if b.codec == .identity { account(b); return "" }
        let r = decodeAvailable(b, finalize: false)
        account(b)
        return r
    }

    func finish(_ h: Int64) -> Int64 {
        guard let b = locked(h) else { return -3 }
        defer { b.lock.unlock() }
        if b.failed { return b.err == "too-big" ? -2 : -1 }
        if b.codec != .identity {
            let r = decodeAvailable(b, finalize: true)
            account(b)
            if !r.isEmpty { return r == "too-big" ? -2 : (r.hasPrefix("decode:") ? -1 : -3) }
            if !b.streamEnded {
                fail(b, "unexpected end of compressed data")
                return -1
            }
            b.closeStream()
        }
        b.finished = true
        b.finishedAt = Date()
        return Int64(b.decoded.count)
    }

    func err(_ h: Int64) -> String {
        guard let b = locked(h) else { return "gone" }
        defer { b.lock.unlock() }
        return b.err
    }

    func len(_ h: Int64, raw: Bool) -> Int64 {
        guard let b = locked(h) else { return -1 }
        defer { b.lock.unlock() }
        return Int64(raw ? b.raw.count : b.decoded.count)
    }

    func read(_ h: Int64, raw: Bool, off: Int64, n: Int64) -> Data? {
        guard let b = locked(h) else { return nil }
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
            b.gone = true
            b.closeStream()
            b.raw = Data()
            b.dec = Data()
            b.charge?.release()
            b.charge = nil
            let counted = b.counted
            b.counted = 0
            b.lock.unlock()
            lock.lock()
            liveBytes -= counted
            lock.unlock()
        }
    }

    // MARK: rv2-life: store-wide cap + TTL

    /// Whether `extra` more bytes fit under totalCap (racy by design: a concurrent writer may cross it by one chunk).
    private func fitsTotal(_ extra: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return liveBytes + max(0, extra) <= Self.totalCap
    }

    /// Brings `liveBytes` in line with b's current size. Caller holds b.lock (never the store lock: order b → store).
    private func account(_ b: Body) {
        let now = b.raw.count + b.dec.count
        let delta = now - b.counted
        guard delta != 0 else { return }
        b.counted = now
        lock.lock()
        liveBytes += delta
        lock.unlock()
    }

    /// Admission for store / adopt (bytes known): same floor / governor as open(), plus the total cap.
    private func admitWhole(_ n: Int) -> Bool {
        sweepIfDue()
        guard fitsTotal(n) else { return false }
        if let g = NativeMemoryGovernor.active { return g.admit(.body, bytes: n) }
        let avail = os_proc_available_memory()
        return !(avail > 0 && avail < Self.availFloor + n)
    }

    /// Frees bodies finished more than `ttl` ago (and never-finished ones older than 2 × ttl), at most every
    /// `sweepEvery`. A body still being written within that window is never touched.
    private func sweepIfDue() {
        let now = Date()
        lock.lock()
        guard now.timeIntervalSince(lastSweep) >= Self.sweepEvery else { lock.unlock(); return }
        lastSweep = now
        let candidates = bodies.filter { now.timeIntervalSince($0.value.createdAt) > Self.ttl }
        lock.unlock()
        for (h, b) in candidates {
            b.lock.lock()
            let stale: Bool
            if let f = b.finishedAt {
                stale = now.timeIntervalSince(f) > Self.ttl
            } else {
                stale = (b.failed && !b.finished) ? now.timeIntervalSince(b.createdAt) > Self.ttl
                                                 : now.timeIntervalSince(b.createdAt) > 2 * Self.ttl
            }
            b.lock.unlock()
            guard stale else { continue }
            free(h)
            lock.lock(); expired += 1; lock.unlock()
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
        lock.lock(); let ex = expired; lock.unlock()
        return "native bodies \(all.count) (\(String(format: "%.1f", Double(bytes) / 1_048_576)) MB), opened \(o), refused \(r), expired \(ex)"
    }

    /// feat/s3-mem (native memory governor): gives back slack no reader needs. Bodies are never dropped (Go still
    /// reads a failed body's raw bytes to pass them through); a finished body's buffers are copied to their exact
    /// size when they can hold slack — `raw` reserved from Content-Length but shorter, `dec` grown by appending (up
    /// to ~2× its size) — each at most once and only up to `maxCopy` bytes per buffer (the copy briefly needs that
    /// much more). Returns the bytes known to be released (reserved − used; appended growth is not visible).
    func trimForMemory(maxCopy: Int = 1 << 20) -> Int {
        lock.lock()
        let all = Array(bodies.values)
        lock.unlock()
        var freed = 0
        for b in all {
            b.lock.lock()
            if !b.gone && b.finished && !b.compacted {
                b.compacted = true
                if b.reserved > b.raw.count + (64 << 10), b.raw.count <= maxCopy {
                    freed += b.reserved - b.raw.count
                    b.raw = Self.exactCopy(b.raw)
                }
                if b.codec != .identity, b.dec.count >= 64 << 10, b.dec.count <= maxCopy {
                    b.dec = Self.exactCopy(b.dec)
                }
                b.closeStream()
            }
            b.lock.unlock()
        }
        return freed
    }

    /// A copy with exactly `d.count` bytes of storage.
    static func exactCopy(_ d: Data) -> Data {
        d.withUnsafeBytes { p in p.baseAddress.map { Data(bytes: $0, count: p.count) } ?? Data() }
    }

    // MARK: JSCNativeBlobProvider (JavaScriptCore engine, on the thread running JavaScript)

    func withDecoded(_ h: Int64, _ body: (UnsafeRawBufferPointer) -> Void) -> Bool {
        guard let b = locked(h) else { return false }
        defer { b.lock.unlock() }
        guard !b.failed else { return false }
        b.decoded.withUnsafeBytes { body($0) }
        return true
    }

    func text(_ h: Int64) -> String? {
        guard let b = locked(h) else { return nil }
        defer { b.lock.unlock() }
        guard !b.failed else { return nil }
        // Valid UTF-8 only: invalid input goes to the Go host, whose U+FFFD replacement is the reference
        // (strings.ToValidUTF8 — one U+FFFD per run of invalid bytes). Not String(data:encoding:), which drops a
        // leading BOM that Go's string(b) keeps: decode leniently, then accept only an exact round trip.
        return b.decoded.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> String? in
            let s = String(decoding: buf, as: UTF8.self)
            return s.utf8.elementsEqual(buf) ? s : nil
        }
    }

    func store(_ bytes: UnsafeRawBufferPointer) -> Int64 {
        // rv2-life: through the same admission as open() (it bypassed the governor / floor and had no cap)
        guard admitWhole(bytes.count) else { return refuse() }
        let b = Body(codec: .identity, limit: bytes.count, hint: 0)
        if let base = bytes.baseAddress, bytes.count > 0 { b.raw = Data(bytes: base, count: bytes.count) }
        b.finished = true
        b.finishedAt = Date()
        b.counted = b.raw.count
        lock.lock()
        seq += 1
        let h = seq
        bodies[h] = b
        liveBytes += b.counted
        lock.unlock()
        return h
    }

    /// Keeps `data` as a new handle without copying it (Data is copy-on-write; nothing here mutates it). 0 for empty.
    func adopt(_ data: Data) -> Int64 {
        guard !data.isEmpty else { return 0 }
        guard admitWhole(data.count) else { return refuse() } // rv2-life: admission + total cap, as store()
        let b = Body(codec: .identity, limit: data.count, hint: 0)
        b.raw = data
        b.finished = true
        b.finishedAt = Date()
        b.counted = data.count
        lock.lock()
        seq += 1
        let h = seq
        bodies[h] = b
        liveBytes += b.counted
        lock.unlock()
        return h
    }

    // MARK: decoding

    private func body(_ h: Int64) -> Body? {
        lock.lock()
        defer { lock.unlock() }
        return bodies[h]
    }

    /// The body for h, locked; nil (not locked) when unknown or freed meanwhile. Pair with `b.lock.unlock()`.
    private func locked(_ h: Int64) -> Body? {
        guard let b = body(h) else { return nil }
        b.lock.lock()
        if b.gone {
            b.lock.unlock()
            return nil
        }
        return b
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
        account(b) // rv2-life: the dropped decoded bytes leave the store-wide count
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
                if b.ignoreRest {
                    b.consumed = b.raw.count
                    return ""
                }
                if b.awaitTrailer {
                    // Apple's decoder may take input past the end of the deflate stream (it reports END with the
                    // whole input used — seen in CI), so src_size cannot say where the 8-byte trailer starts. It is
                    // found by value instead: the first offset in the span of the call that ended the stream where
                    // CRC-32 and ISIZE of this member's output follow (a false match needs 64 bits to agree).
                    let crc = b.crc, size = UInt32(truncatingIfNeeded: b.memberSize), base = b.raw.startIndex
                    var e = b.trailerSearch
                    var found = false
                    while e <= b.trailerMax && e + 8 <= b.raw.count {
                        if Self.le32(b.raw, base + e) == crc && Self.le32(b.raw, base + e + 4) == size {
                            found = true
                            break
                        }
                        e += 1
                    }
                    if !found {
                        if e > b.trailerMax { return fail2(b, "gzip checksum mismatch") }
                        b.trailerSearch = e
                        return finalize ? fail2(b, "truncated gzip trailer") : ""
                    }
                    b.consumed = e + 8
                    b.awaitTrailer = false
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
                        if b.streamEnded { // trailing garbage after a member
                            b.ignoreRest = true
                            b.consumed = b.raw.count
                            return ""
                        }
                        return fail2(b, "invalid gzip header")
                    case .some(let n):
                        b.consumed += n
                        b.inHeader = false
                        b.streamEnded = false
                        b.crc = 0
                        b.memberSize = 0
                        b.memberStart = b.consumed
                        b.callStart = b.consumed
                        b.prevCallStart = b.consumed
                        b.closeStream()
                        guard Self.startStream(b, COMPRESSION_ZLIB) else { return "internal: stream init" }
                    case .none:
                        if !finalize { return "" }
                        // one stray byte after a complete member cannot start a header: ignored like longer garbage
                        if b.streamEnded && b.raw.count - b.consumed < 2 {
                            b.ignoreRest = true
                            b.consumed = b.raw.count
                            return ""
                        }
                        return fail2(b, "truncated gzip header")
                    }
                }
                let r = pump(b, finalize: finalize)
                if !r.isEmpty { return r }
                if b.streamEnded {
                    b.awaitTrailer = true
                    b.trailerSearch = max(b.memberStart, min(b.callStart, b.prevCallStart))
                    b.trailerMax = b.callEnd
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
            b.prevCallStart = b.callStart
            b.callStart = b.consumed
            b.callEnd = b.raw.count
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
            let srcBefore = s.pointee.src_size
            let status = compression_stream_process(s, flags)
            let produced = Self.scratchSize - s.pointee.dst_size
            if produced > 0 {
                if b.dec.count + produced > b.limit {
                    fail(b, "too-big")
                    return "too-big"
                }
                // NativeCore: the decoded bytes actually produced are charged (no br × 8 / gzip × 6 guess)
                if let c = b.charge, !c.grow(produced) {
                    fail(b, "too-big")
                    return "too-big"
                }
                b.dec.append(scratch, count: produced)
                if b.codec == .gzip {
                    b.crc = Self.crc32(b.crc, scratch, produced)
                    b.memberSize += produced
                }
            }
            switch status {
            case COMPRESSION_STATUS_END:
                b.streamEnded = true
                return ""
            case COMPRESSION_STATUS_OK:
                // more to do while input remains or the output buffer came back full
                if s.pointee.src_size == 0 && produced < Self.scratchSize { return "" }
                // no progress at all: wait for more input (finish reports a stream that never ended)
                if produced == 0 && s.pointee.src_size == srcBefore { return "" }
            default:
                fail(b, "corrupt compressed data")
                return "decode: corrupt compressed data"
            }
        }
    }

    private static func le32(_ d: Data, _ i: Int) -> UInt32 {
        UInt32(d[i]) | UInt32(d[i + 1]) << 8 | UInt32(d[i + 2]) << 16 | UInt32(d[i + 3]) << 24
    }

    /// CRC-32 (IEEE, reflected, as gzip uses), table built once.
    private static let crcTable: [UInt32] = (0..<256).map { (n: Int) -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    private static func crc32(_ crc: UInt32, _ p: UnsafePointer<UInt8>, _ n: Int) -> UInt32 {
        var c = ~crc
        crcTable.withUnsafeBufferPointer { t in
            for i in 0..<n { c = t[Int((c ^ UInt32(p[i])) & 0xff)] ^ (c >> 8) }
        }
        return ~c
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
