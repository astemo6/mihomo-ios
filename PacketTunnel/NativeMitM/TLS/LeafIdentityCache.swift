// feat/s2-tls (native MitM stage 2, B7): per-host TLS server identities for the native front.
//
// In pure native mode, leaf certificates are issued locally in Swift via NCCAManager / LeafCertIssuer,
// signed by the user's CA and packaged as PKCS#12. SecPKCS12Import keeps it in memory (no keychain).
// The bounded LRU follows astemo6's draft CertCache (origin/draft/native-mitm-b7b8 6b53dc6: normalized host key,
// most-recent-first eviction), plus a byte budget, since every entry pins a SecIdentity + its key in the NE.

import Foundation
import Security

enum NativeTLSError: Error, Equatable {
    /// No CA / no leaf for this host (leaf issuance returned nil).
    case noIdentity
    /// SecPKCS12Import failed (status) or returned no identity (errSecItemNotFound).
    case importFailed(OSStatus)
    /// The loopback listener could not start (or the per-host listener budget is used up).
    case listenerFailed
    /// The client's handshake failed; kind is what Go's pinning memory expects ("cert", "closed", "timeout", "cancelled").
    case handshakeFailed(String)
}

/// One imported identity. `cost` is what it counts against the cache's byte budget (the PKCS#12 size: leaf + CA
/// + EC/RSA key — a fair proxy for what Security keeps alive).
final class LeafIdentity {
    let identity: SecIdentity
    let cost: Int
    init(identity: SecIdentity, cost: Int) {
        self.identity = identity
        self.cost = cost
    }
}

/// Thread-safe LRU bounded by entry count AND total cost. An entry bigger than the whole byte budget is returned
/// to the caller but not kept.
final class BoundedLRU<Value> {
    let maxCount: Int
    let maxBytes: Int
    private let lock = NSLock()
    private var map: [String: (value: Value, cost: Int)] = [:]
    private var order: [String] = [] // least recent first; counts are small (tens), O(n) is fine
    private(set) var totalBytes = 0

    init(maxCount: Int, maxBytes: Int) {
        precondition(maxCount > 0 && maxBytes > 0)
        self.maxCount = maxCount
        self.maxBytes = maxBytes
    }

    static func normalize(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return map.count }
    var bytes: Int { lock.lock(); defer { lock.unlock() }; return totalBytes }
    /// Keys, least recently used first.
    var keys: [String] { lock.lock(); defer { lock.unlock() }; return order }

    func get(_ key: String) -> Value? {
        let k = Self.normalize(key)
        lock.lock(); defer { lock.unlock() }
        guard let e = map[k] else { return nil }
        touch(k)
        return e.value
    }

    /// Returns the evicted keys.
    @discardableResult
    func set(_ key: String, _ value: Value, cost: Int) -> [String] {
        let k = Self.normalize(key)
        lock.lock(); defer { lock.unlock() }
        if let old = map.removeValue(forKey: k) {
            totalBytes -= old.cost
            order.removeAll { $0 == k }
        }
        guard cost <= maxBytes else { return [] }
        map[k] = (value, cost)
        order.append(k)
        totalBytes += cost
        var evicted: [String] = []
        while map.count > maxCount || totalBytes > maxBytes, order.count > 1, let victim = order.first {
            order.removeFirst()
            if let e = map.removeValue(forKey: victim) { totalBytes -= e.cost }
            evicted.append(victim)
        }
        return evicted
    }

    func remove(_ key: String) {
        let k = Self.normalize(key)
        lock.lock(); defer { lock.unlock() }
        if let e = map.removeValue(forKey: k) {
            totalBytes -= e.cost
            order.removeAll { $0 == k }
        }
    }

    func removeAll() {
        lock.lock(); defer { lock.unlock() }
        map.removeAll()
        order.removeAll()
        totalBytes = 0
    }

    private func touch(_ k: String) {
        if order.last == k { return }
        order.removeAll { $0 == k }
        order.append(k)
    }
}

/// host → SecIdentity, imported from PKCS#12 on first use. Failures are not cached (the CA may be installed
/// later).
final class LeafIdentityCache {
    static let password = "tern"

    /// Defaults: 64 hosts and 1 MB (a P-256 leaf p12 is ~2.5 KB).
    static let shared = LeafIdentityCache()

    let cache: BoundedLRU<LeafIdentity>
    private let source: (String) -> Data?

    init(maxCount: Int = 64, maxBytes: Int = 1 << 20,
         source: @escaping (String) -> Data? = { NCCAManager.shared.leafP12(for: $0) }) {
        cache = BoundedLRU(maxCount: maxCount, maxBytes: maxBytes)
        self.source = source
    }

    func identity(for host: String) -> Result<LeafIdentity, NativeTLSError> {
        if let hit = cache.get(host) { return .success(hit) }
        guard let p12 = source(BoundedLRU<LeafIdentity>.normalize(host)), !p12.isEmpty else {
            return .failure(.noIdentity)
        }
        do {
            let id = try Self.importPKCS12(p12, password: Self.password)
            let leaf = LeafIdentity(identity: id, cost: p12.count)
            cache.set(host, leaf, cost: leaf.cost)
            return .success(leaf)
        } catch let e as NativeTLSError {
            return .failure(e)
        } catch {
            return .failure(.importFailed(errSecInternalError))
        }
    }

    /// In-memory PKCS#12 import (no keychain item is written on iOS).
    static func importPKCS12(_ data: Data, password: String) throws -> SecIdentity {
        var items: CFArray?
        let opts = [kSecImportExportPassphrase as String: password] as CFDictionary
        let status = SecPKCS12Import(data as CFData, opts, &items)
        guard status == errSecSuccess else { throw NativeTLSError.importFailed(status) }
        guard let list = items as? [[String: Any]],
              let any = list.first?[kSecImportItemIdentity as String],
              CFGetTypeID(any as CFTypeRef) == SecIdentityGetTypeID() else {
            throw NativeTLSError.importFailed(errSecItemNotFound)
        }
        return (any as! SecIdentity) // CF type, checked above
    }
}
