// NativeCore (feat/native-core-eval) — script body admission by ACTUAL decoded size (astemo6/Muse, 2026-10-25).
//
// The Go-era admission (bridge/mitm/largebody.go, ported in 11347ec) estimated a body before reading it
// (br × 8, gzip × 6) and refused it when reserve + 3 × estimate did not fit. On device (v0.19.26, 3–4 MB available
// under the Go core) a 147 KB br YouTube response was estimated at ~1.2 MB and skipped although it would have fit.
//
// NativeCore streams instead: a body is admitted when its raw length fits (no ratio guess), every byte the store
// appends — raw as received, decoded as the decoder produces it — is charged here, and the load stops only when the
// bytes actually produced would leave less than `reserve` available or exceed the shared budget / the script's
// max-size. Shared by all concurrent script bodies (`hardMax`).
//
// Numbers (c): NativeCore has no garbage-collected Go heap to overshoot (Go needed 3 MB free for GC headroom), and
// malloc'd decode buffers show up in os_proc_available_memory at once, so the reserve is 1.5 MB — the extension's
// own allocations between two 64 KB decoder steps plus JavaScriptCore's next block. The decode is checked live per
// chunk, so no copy factor is applied up front; the script run itself is bounded by the governor / memLow.
//
// Pure Foundation, no #if: built into the tunnel (TERN_NO_GO NativeScriptHost / NativeBodyStore) and the app target
// (UnitTests/NativeScriptBodyBudgetTests.swift).

import Foundation
import os

final class NativeScriptBodyBudget {
    struct Config {
        /// kept available while a body loads (Go: 3 MB largeBodyReserve, 4 MB before v0.19.25)
        var reserve: Int64 = 1_536 << 10
        /// all script bodies loading / held at once (raw + decoded)
        var hardMax: Int64 = 8 << 20
        /// head room asked for at admission beyond the raw length (decoder scratch, headers, the first chunks)
        var admitSlack: Int64 = 256 << 10
    }

    static let shared = NativeScriptBodyBudget()

    let config: Config
    private let available: () -> Int64?
    private let lock = NSLock()
    private var charged: Int64 = 0
    private var openCount = 0

    /// available: the memory iOS still allows the process (nil = no limit known: the app, the simulator).
    init(config: Config = Config(), available: @escaping () -> Int64? = NativeScriptBodyBudget.processAvailable) {
        self.config = config
        self.available = available
    }

    static func processAvailable() -> Int64? {
        let a = Int64(os_proc_available_memory())
        return a > 0 ? a : nil
    }

    var chargedBytes: Int64 { lock.lock(); defer { lock.unlock() }; return charged }
    var openCharges: Int { lock.lock(); defer { lock.unlock() }; return openCount }

    /// Whether a body of rawLength (-1 = unknown) can start now: the raw bytes plus the slack fit above the reserve
    /// and in what is left of the shared budget. Nothing is guessed about the decoded size.
    func roomToStart(rawLength: Int64) -> Bool {
        let need = max(rawLength, 0) + config.admitSlack
        lock.lock()
        let left = config.hardMax - charged
        lock.unlock()
        if need > left { return false }
        guard let avail = available() else { return true }
        return avail - need >= config.reserve
    }

    /// Opens a charge for one body, capped at limit (the script's max-size or hardMax). nil: no room to start.
    func admit(rawLength: Int64, limit: Int64) -> NativeBodyCharge? {
        if rawLength > limit { return nil }
        guard roomToStart(rawLength: rawLength) else { return nil }
        lock.lock(); openCount += 1; lock.unlock()
        return NativeBodyCharge(budget: self, limit: min(limit, config.hardMax))
    }

    /// n more bytes for c: within c's limit, the shared budget, and above the reserve after they are allocated.
    fileprivate func grow(_ c: NativeBodyCharge, _ n: Int64) -> NativeBodyCharge.Stop? {
        if n <= 0 { return nil }
        lock.lock()
        if c.charged + n > c.limit { lock.unlock(); return .limit }
        if charged + n > config.hardMax { lock.unlock(); return .shared }
        lock.unlock()
        if let avail = available(), avail - n < config.reserve { return .memory(avail) }
        lock.lock()
        // re-check the shared budget: another body may have grown meanwhile
        if charged + n > config.hardMax { lock.unlock(); return .shared }
        charged += n
        c.charged += n
        lock.unlock()
        return nil
    }

    fileprivate func release(_ c: NativeBodyCharge) {
        lock.lock()
        charged = max(0, charged - c.charged)
        c.charged = 0
        openCount = max(0, openCount - 1)
        lock.unlock()
    }
}

/// One body's share of NativeScriptBodyBudget. The store calls grow(n) before it appends n bytes (raw or decoded);
/// false = stop the load (too-big). release() once the body is dropped (idempotent).
final class NativeBodyCharge {
    enum Stop: Equatable {
        case limit          // the script's max-size / the budget's cap
        case shared         // all concurrent script bodies together
        case memory(Int64)  // the bytes would leave less than the reserve (available at that moment)
    }

    let limit: Int64
    /// guarded by the budget's lock
    fileprivate(set) var charged: Int64 = 0
    private weak var budget: NativeScriptBodyBudget?
    private let stateLock = NSLock()
    private var released = false
    private var _stop: Stop?

    fileprivate init(budget: NativeScriptBodyBudget, limit: Int64) {
        self.budget = budget
        self.limit = limit
    }

    /// Why the load stopped (nil while it may grow).
    var stop: Stop? { stateLock.lock(); defer { stateLock.unlock() }; return _stop }
    var chargedBytes: Int64 { stateLock.lock(); defer { stateLock.unlock() }; return released ? 0 : (budget?.chargedFor(self) ?? 0) }

    func grow(_ n: Int) -> Bool {
        stateLock.lock()
        if released || _stop != nil { stateLock.unlock(); return false }
        stateLock.unlock()
        guard let b = budget else { return true }
        if let s = b.grow(self, Int64(n)) {
            stateLock.lock(); _stop = s; stateLock.unlock()
            return false
        }
        return true
    }

    func release() {
        stateLock.lock()
        if released { stateLock.unlock(); return }
        released = true
        stateLock.unlock()
        budget?.release(self)
    }

    /// The 「跳过脚本」 reason for a stopped load (Chinese, like the other script notes).
    func stopNote(rawReceived: Int64) -> String {
        let got = chargedBytes >> 10
        switch stop {
        case .memory(let avail)?:
            return String(format: "解压到 %lld KB 时内存不足（隧道可用 %.1f MB，保留 %lld KB；已收 %lld KB）",
                          got, Double(avail) / 1048576, (budget?.config.reserve ?? 0) >> 10, rawReceived >> 10)
        case .shared?:
            return "同时处理的响应体超过共享预算 \((budget?.config.hardMax ?? 0) >> 20) MB（已解压 \(got) KB）"
        case .limit?:
            return "响应体解压后超过 \(limit >> 10) KB"
        case nil:
            return ""
        }
    }

    deinit { release() }
}

extension NativeScriptBodyBudget {
    fileprivate func chargedFor(_ c: NativeBodyCharge) -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return c.charged
    }
}

// Defaults so the Go-backed app build (GoScriptHost, the Go NativeBodyStore) and the unit-test fakes need nothing new.
extension ScriptGoHost {
    /// The streaming charge bodyAdmit opened for ticket (NativeCore only).
    func bodyCharge(ticket: Int64) -> NativeBodyCharge? { nil }
}

extension ScriptBodyStore {
    func open(_ enc: String?, limit: Int64, hint: Int64, charge: NativeBodyCharge?) -> Int64 {
        open(enc, limit: limit, hint: hint)
    }
}
