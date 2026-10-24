import Foundation

/// A thread-safe, bounded LRU cache for leaf certificates / PKCS#12 data.
///
/// The cache is keyed by a normalized hostname (lowercased, trailing dot trimmed).
/// When capacity is exceeded, the least recently used entry is evicted.
///
/// This mirrors the Go side's LRU cache in `CA` (bridge/mitm/ca.go):
/// - `cache` map + `list.List` for LRU ordering
/// - `max` capacity (default 64 on Go side)
/// - Key includes hostname + extra DNS names joined by `|`
public final class CertCache<Value: Sendable>: @unchecked Sendable {
    private let capacity: Int
    private var cache: [String: Node] = [:]
    private var head: Node? // Most recently used
    private var tail: Node? // Least recently used
    private let lock = NSLock()

    /// A node in the doubly-linked LRU list.
    private final class Node: @unchecked Sendable {
        let key: String
        var value: Value
        var prev: Node?
        var next: Node?

        init(key: String, value: Value) {
            self.key = key
            self.value = value
        }
    }

    /// Creates a new certificate cache.
    ///
    /// - Parameter capacity: Maximum number of entries. Must be > 0.
    ///                       Go side defaults to 64.
    public init(capacity: Int = 64) {
        precondition(capacity > 0, "Capacity must be positive")
        self.capacity = capacity
    }

    /// Returns the cached value for `key`, marking it as recently used.
    ///
    /// - Parameter key: Normalized hostname (e.g., "example.com").
    /// - Returns: The cached value, or `nil` if not found.
    public func get(_ key: String) -> Value? {
        let normalized = Self.normalizeKey(key)
        lock.lock()
        defer { lock.unlock() }

        guard let node = cache[normalized] else { return nil }
        moveToHead(node)
        return node.value
    }

    /// Inserts or updates a value for `key`, marking it as recently used.
    ///
    /// If the cache exceeds capacity, the least recently used entry is evicted.
    ///
    /// - Parameters:
    ///   - key: Normalized hostname.
    ///   - value: The value to cache (e.g., `LeafCertResult` or PKCS#12 `Data`).
    /// - Returns: The evicted value, if any (for cleanup/observability).
    @discardableResult
    public func set(_ key: String, _ value: Value) -> Value? {
        let normalized = Self.normalizeKey(key)
        lock.lock()
        defer { lock.unlock() }

        if let existing = cache[normalized] {
            existing.value = value
            moveToHead(existing)
            return nil
        }

        let node = Node(key: normalized, value: value)
        cache[normalized] = node
        addToHead(node)

        if cache.count > capacity {
            return evictTail()
        }
        return nil
    }

    /// Removes and returns the value for `key`.
    ///
    /// - Parameter key: Normalized hostname.
    /// - Returns: The removed value, or `nil` if not found.
    @discardableResult
    public func remove(_ key: String) -> Value? {
        let normalized = Self.normalizeKey(key)
        lock.lock()
        defer { lock.unlock() }

        guard let node = cache.removeValue(forKey: normalized) else { return nil }
        unlink(node)
        return node.value
    }

    /// Removes all entries.
    public func removeAll() {
        lock.lock()
        defer { lock.unlock() }
        cache.removeAll()
        head = nil
        tail = nil
    }

    /// Returns the current number of entries.
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }

    /// Returns whether the cache is at capacity.
    public var isFull: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cache.count >= capacity
    }

    /// Returns all keys in LRU order (most recent first).
    public func keys() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        var result: [String] = []
        var node = head
        while let n = node {
            result.append(n.key)
            node = n.next
        }
        return result
    }

    /// Returns a snapshot of all entries (key, value) in LRU order.
    public func snapshot() -> [(String, Value)] {
        lock.lock()
        defer { lock.unlock() }
        var result: [(String, Value)] = []
        var node = head
        while let n = node {
            result.append((n.key, n.value))
            node = n.next
        }
        return result
    }

    // MARK: - Private LRU Operations

    private func addToHead(_ node: Node) {
        node.prev = nil
        node.next = head
        head?.prev = node
        head = node
        if tail == nil {
            tail = node
        }
    }

    private func moveToHead(_ node: Node) {
        guard node !== head else { return }
        unlink(node)
        addToHead(node)
    }

    private func unlink(_ node: Node) {
        node.prev?.next = node.next
        node.next?.prev = node.prev
        if node === head { head = node.next }
        if node === tail { tail = node.prev }
        node.prev = nil
        node.next = nil
    }

    private func evictTail() -> Value? {
        guard let node = tail else { return nil }
        cache.removeValue(forKey: node.key)
        unlink(node)
        return node.value
    }

    // MARK: - Key Normalization

    /// Normalizes a cache key to match Go side behavior:
    /// - Lowercased
    /// - Trailing dot trimmed
    /// - Extra DNS names appended with "|" separator (if provided via composite key)
    public static func normalizeKey(_ key: String) -> String {
        return key.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    /// Creates a composite key for hostname + extra DNS names (matching Go side).
    /// Go side: `key += "|" + strings.Join(extra, ",")`
    public static func compositeKey(hostname: String, extraDNSNames: [String]) -> String {
        let normalizedHost = normalizeKey(hostname)
        if extraDNSNames.isEmpty {
            return normalizedHost
        }
        let extra = extraDNSNames.map { normalizeKey($0) }.joined(separator: ",")
        return "\(normalizedHost)|\(extra)"
    }
}

/// Specialized cache for `LeafCertResult` with convenience methods.
public final class LeafCertCache: @unchecked Sendable {
    private let cache: CertCache<LeafCertResult>

    public init(capacity: Int = 64) {
        self.cache = CertCache(capacity: capacity)
    }

    public func get(hostname: String, extraDNSNames: [String] = []) -> LeafCertResult? {
        let key = CertCache<LeafCertResult>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.get(key)
    }

    @discardableResult
    public func set(hostname: String, extraDNSNames: [String] = [], value: LeafCertResult) -> LeafCertResult? {
        let key = CertCache<LeafCertResult>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.set(key, value)
    }

    @discardableResult
    public func remove(hostname: String, extraDNSNames: [String] = []) -> LeafCertResult? {
        let key = CertCache<LeafCertResult>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.remove(key)
    }

    public func removeAll() { cache.removeAll() }

    public var count: Int { cache.count }
    public var isFull: Bool { cache.isFull }
    public func keys() -> [String] { cache.keys() }
    public func snapshot() -> [(String, LeafCertResult)] { cache.snapshot() }
}

/// Cache for PKCS#12 data (raw `Data` blobs).
public final class PKCS12Cache: @unchecked Sendable {
    private let cache: CertCache<Data>

    public init(capacity: Int = 64) {
        self.cache = CertCache(capacity: capacity)
    }

    public func get(hostname: String, extraDNSNames: [String] = []) -> Data? {
        let key = CertCache<Data>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.get(key)
    }

    @discardableResult
    public func set(hostname: String, extraDNSNames: [String] = [], value: Data) -> Data? {
        let key = CertCache<Data>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.set(key, value)
    }

    @discardableResult
    public func remove(hostname: String, extraDNSNames: [String] = []) -> Data? {
        let key = CertCache<Data>.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
        return cache.remove(key)
    }

    public func removeAll() { cache.removeAll() }

    public var count: Int { cache.count }
    public var isFull: Bool { cache.isFull }
}