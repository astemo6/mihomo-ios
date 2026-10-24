import Foundation

/// In-memory Certificate Pinning Memory for Native MitM.
/// Replaces Go's pinning memory (`bridge/mitm/engine.go pinned`).
/// If a client app fails TLS handshake because of certificate pinning,
/// the host is pinned for 30 minutes so subsequent connections bypass MitM.
public final class NCPinningMemory {
    public static let shared = NCPinningMemory()

    private let lock = NSLock()
    private var pinnedUntil: [String: Date] = [:]

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
        let h = Self.normalize(host)
        lock.lock()
        defer { lock.unlock() }
        pinnedUntil[h] = Date().addingTimeInterval(duration)
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
