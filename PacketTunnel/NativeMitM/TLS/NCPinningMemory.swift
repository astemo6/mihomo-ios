import Foundation

/// In-memory Certificate Pinning Memory for Native MitM.
/// Replaces the old core's pinning memory.
/// If a client app fails TLS handshake because of certificate pinning,
/// the host is pinned for 30 minutes so subsequent connections bypass MitM.
public final class NCPinningMemory {
    public static let shared = NCPinningMemory()

    private let lock = NSLock()
    private var pinnedUntil: [String: Date] = [:]
    /// fix/nc-diag-439: why a host passes through (absent = the client rejected the Tern certificate).
    private var reasons: [String: String] = [:]

    public init() {}

    public static func normalize(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    public func isPinned(_ host: String) -> Bool {
        let h = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        if let expiry = pinnedUntil[h] {
            if expiry > Date() { return true }
            pinnedUntil.removeValue(forKey: h)
        }
        return false
    }

    public func markPinned(_ host: String, duration: TimeInterval = 1800) {
        markPinned(host, duration: duration, reason: nil)
    }

    /// fix/nc-diag-439: pass a host through with a stated reason (e.g. its forwarded requests keep failing upstream).
    public func markPinned(_ host: String, duration: TimeInterval, reason: String?) {
        let h = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        pinnedUntil[h] = Date().addingTimeInterval(duration)
        if let reason { reasons[h] = reason } else { reasons.removeValue(forKey: h) }
        if reasons.count > 256 { reasons = reasons.filter { pinnedUntil[$0.key] != nil } }
    }

    /// The stated reason of an active pass-through (nil: certificate rejection, or not passed through).
    public func reason(_ host: String) -> String? {
        let h = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        guard let until = pinnedUntil[h], until > Date() else { return nil }
        return reasons[h]
    }

    public func pinnedHosts() -> [String] {
        let now = Date()
        lock.lock()
        defer { lock.unlock() }
        pinnedUntil = pinnedUntil.filter { $0.value > now }
        return pinnedUntil.keys.sorted()
    }

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        pinnedUntil.removeAll()
    }
}
