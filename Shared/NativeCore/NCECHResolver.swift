import Foundation

/// Result record when ECH configuration is found via DNS HTTPS (65) or SVCB (64).
struct NCECHRecord: Equatable {
    /// The effective domain name queried (honoring query-server-name).
    var queryName: String

    /// Raw ECHConfigList bytes extracted from SvcParam ech (key 5).
    /// Passed directly to E1's parser for TLS handshake consumption.
    var echConfigList: Data

    /// Record TTL in seconds (clamped).
    var ttl: UInt32

    /// Cache expiration date.
    var expires: Date

    /// The structured SVCB/HTTPS candidate record containing this ECH config.
    var candidate: NCSVCCandidate

    /// The raw DNS answer record from which this candidate was decoded.
    var sourceRecord: NCDNSRecord

    /// The chain of domain names followed if AliasMode (or CNAME) was traversed.
    var aliasChain: [String] = []
}

/// Resolution outcome distinguishing "ECH found" from "No ECH advertised".
enum NCECHResolution: Equatable {
    /// ECH configuration was found.
    case found(NCECHRecord)

    /// DNS query succeeded (NOERROR / NODATA / NXDOMAIN / no ech param),
    /// but no ECH was advertised. Conservatively cached so subsequent
    /// connections do not repeat the query.
    case noECH(queryName: String, ttl: UInt32, expires: Date)

    /// Raw ECHConfigList bytes if ECH was found, nil otherwise.
    var echConfigList: Data? {
        if case .found(let rec) = self { return rec.echConfigList }
        return nil
    }

    /// Record TTL in seconds.
    var ttl: UInt32 {
        switch self {
        case .found(let rec): return rec.ttl
        case .noECH(_, let ttl, _): return ttl
        }
    }

    /// Cache expiration date.
    var expires: Date {
        switch self {
        case .found(let rec): return rec.expires
        case .noECH(_, _, let exp): return exp
        }
    }

    /// Whether ECH is present.
    var hasECH: Bool {
        if case .found = self { return true }
        return false
    }

    /// Structured candidate record if found.
    var candidate: NCSVCCandidate? {
        if case .found(let rec) = self { return rec.candidate }
        return nil
    }
}

/// Errors occurring during ECH DNS resolution.
enum NCECHError: Error, Equatable, CustomStringConvertible {
    case invalidQueryName(String)
    case noUpstreamAvailable
    case networkError(String)
    case timeout
    case dnsError(rcode: UInt16)
    case aliasLoop(chain: [String])
    case aliasHopLimitExceeded(chain: [String])
    case malformedResponse
    case cancelled

    var description: String {
        switch self {
        case .invalidQueryName(let name): return "Invalid query name: \(name)"
        case .noUpstreamAvailable: return "No DNS upstream available"
        case .networkError(let msg): return "DNS network error: \(msg)"
        case .timeout: return "DNS query timed out"
        case .dnsError(let rcode): return "DNS query failed with rcode: \(rcode)"
        case .aliasLoop(let chain): return "HTTPS AliasMode loop detected: \(chain.joined(separator: " -> "))"
        case .aliasHopLimitExceeded(let chain): return "HTTPS AliasMode hop limit exceeded: \(chain.joined(separator: " -> "))"
        case .malformedResponse: return "Malformed DNS response"
        case .cancelled: return "DNS query was cancelled"
        }
    }
}

/// Resolves DNS HTTPS (TYPE 65) / SVCB (TYPE 64) records to retrieve ECH configuration.
///
/// Features:
/// - Reuses kernel upstreams via `NCDNSForwarder` and upstream coordinator/pools (DoH/DoT/UDP/TCP).
/// - Full RFC 9460 parsing: prioritizes ServiceMode candidates, handles AliasMode (priority 0)
///   with hop limit and loop detection.
/// - Supports `query-server-name` override for target domains / IP destinations.
/// - TTL-bound caching with negative caching for non-ECH domains.
/// - In-flight query coalescing to prevent redundant network requests.
final class NCECHResolver {
    /// Upstream routing provider type. Given queryName and RR type, returns the
    /// primary upstream, optional fallback upstream, and whether fallbackFirst applies.
    typealias UpstreamProvider = (_ queryName: String, _ type: UInt16) -> (primary: NCDNSUpstream?, fallback: NCDNSUpstream?, fallbackFirst: Bool)

    /// Cache key combining normalized query name and DNS type.
    struct CacheKey: Hashable {
        let name: String
        let type: UInt16
    }

    struct CacheEntry {
        let resolution: NCECHResolution
        let expires: Date
    }

    private struct Waiter {
        let callerQueue: DispatchQueue
        let completion: (Result<NCECHResolution, NCECHError>) -> Void
    }

    static let shared = NCECHResolver()

    private let queue: DispatchQueue
    private let forwarder: NCDNSForwarder
    private let upstreamProvider: UpstreamProvider
    private let capacity: Int

    /// Injected time provider for deterministic unit testing.
    var now: () -> Date = { Date() }

    private var cache: [CacheKey: CacheEntry] = [:]
    private var waiters: [CacheKey: [Waiter]] = [:]

    init(queue: DispatchQueue = DispatchQueue(label: "nc.dns.ech"),
         forwarder: NCDNSForwarder? = nil,
         capacity: Int = 512,
         upstreamProvider: @escaping UpstreamProvider = { _, _ in (nil, nil, false) }) {
        self.queue = queue
        self.forwarder = forwarder ?? NCDNSForwarder(queue: queue)
        self.capacity = capacity
        self.upstreamProvider = upstreamProvider
    }

    /// Query HTTPS (or SVCB) records to retrieve ECH configuration for `host`.
    ///
    /// - Parameters:
    ///   - host: The destination host or IP address.
    ///   - queryServerName: Optional override for the DNS query name (per ech-opts query-server-name).
    ///   - type: DNS RR type (defaults to TYPE 65 HTTPS; TYPE 64 SVCB also supported).
    ///   - callerQueue: Queue on which `completion` is called (defaults to main).
    ///   - completion: Callback returning `Result<NCECHResolution, NCECHError>`.
    func resolveECH(for host: String,
                    queryServerName: String? = nil,
                    type: UInt16 = NCDNSMessage.typeHTTPS,
                    callerQueue: DispatchQueue = .main,
                    completion: @escaping (Result<NCECHResolution, NCECHError>) -> Void) {
        let rawTarget: String
        if let qsn = queryServerName?.trimmingCharacters(in: .whitespaces), !qsn.isEmpty {
            rawTarget = qsn
        } else {
            rawTarget = host
        }
        let effectiveName = normalize(rawTarget)

        guard !effectiveName.isEmpty else {
            callerQueue.async { completion(.failure(.invalidQueryName(host))) }
            return
        }

        // IP literal targets without a valid query-server-name cannot have DNS HTTPS records.
        if NCIP(effectiveName) != nil {
            let res = NCECHResolution.noECH(queryName: effectiveName, ttl: 300, expires: now().addingTimeInterval(300))
            callerQueue.async { completion(.success(res)) }
            return
        }

        let key = CacheKey(name: effectiveName, type: type)

        queue.async {
            self.resolveInternal(key: key, aliasChain: [], callerQueue: callerQueue, completion: completion)
        }
    }

    private func resolveInternal(key: CacheKey,
                                  aliasChain: [String],
                                  callerQueue: DispatchQueue,
                                  completion: @escaping (Result<NCECHResolution, NCECHError>) -> Void) {
        let currentTime = now()

        // 1. Check TTL cache
        if let entry = cache[key] {
            if entry.expires > currentTime {
                callerQueue.async { completion(.success(entry.resolution)) }
                return
            } else {
                cache.removeValue(forKey: key)
            }
        }

        // 2. Coalesce in-flight requests for identical (name, type)
        if waiters[key] != nil {
            if waiters[key]!.count < 64 {
                waiters[key]!.append(Waiter(callerQueue: callerQueue, completion: completion))
            } else {
                callerQueue.async { completion(.failure(.timeout)) }
            }
            return
        }

        waiters[key] = [Waiter(callerQueue: callerQueue, completion: completion)]

        // 3. Resolve upstream route
        let (primary, fallback, fallbackFirst) = upstreamProvider(key.name, key.type)
        guard let primaryUpstream = primary ?? fallback else {
            deliver(key: key, result: .failure(.noUpstreamAvailable))
            return
        }

        // 4. Construct DNS query message
        var msg = NCDNSMessage()
        msg.id = UInt16.random(in: 1...0xffff)
        msg.recursionDesired = true
        msg.questions = [NCDNSQuestion(name: key.name, type: key.type, klass: NCDNSMessage.classIN)]
        let queryData = msg.serialized()

        // 5. Forward through kernel upstream pool
        sendQuery(queryData, primary: primaryUpstream, fallback: fallback, fallbackFirst: fallbackFirst) { [weak self] respData in
            guard let self else { return }
            self.queue.async {
                self.handleQueryResponse(key: key, aliasChain: aliasChain, respData: respData)
            }
        }
    }

    private func sendQuery(_ query: Data, primary: NCDNSUpstream, fallback: NCDNSUpstream?,
                           fallbackFirst: Bool, completion: @escaping (Data?) -> Void) {
        if fallbackFirst, let fallback {
            forwarder.forward(query, upstream: fallback) { [weak self] resp in
                if let resp { completion(resp); return }
                guard let self else { completion(nil); return }
                self.forwarder.forward(query, upstream: primary, completion: completion)
            }
            return
        }

        forwarder.forward(query, upstream: primary) { [weak self] resp in
            if let resp { completion(resp); return }
            guard let fallback, let self else { completion(resp); return }
            self.forwarder.forward(query, upstream: fallback, completion: completion)
        }
    }

    private func handleQueryResponse(key: CacheKey, aliasChain: [String], respData: Data?) {
        guard let respData else {
            deliver(key: key, result: .failure(.networkError("Upstream DNS query returned no response")))
            return
        }

        guard let msg = NCDNSMessage.parse(respData) else {
            deliver(key: key, result: .failure(.malformedResponse))
            return
        }

        let currentTime = now()

        // Handle DNS rcodes
        if msg.rcode == 3 { // NXDOMAIN: cache negative result conservatively
            let negTTL: UInt32 = 60
            let res = NCECHResolution.noECH(queryName: key.name, ttl: negTTL, expires: currentTime.addingTimeInterval(Double(negTTL)))
            storeCache(key: key, resolution: res)
            deliver(key: key, result: .success(res))
            return
        }

        if msg.rcode != 0 { // Other error (e.g. SERVFAIL, REFUSED)
            deliver(key: key, result: .failure(.dnsError(rcode: msg.rcode)))
            return
        }

        // Parse SVCB/HTTPS candidates
        let entries = msg.svcbEntries // sorted by priority ascending

        // Check if there is an AliasMode record (priority 0)
        if let aliasEntry = entries.first(where: { $0.candidate.isAliasMode }) {
            let aliasTarget = normalize(aliasEntry.candidate.targetName)
            let newChain = aliasChain + [key.name]

            // Check for alias loops
            if newChain.contains(aliasTarget) {
                deliver(key: key, result: .failure(.aliasLoop(chain: newChain + [aliasTarget])))
                return
            }

            // Check hop limit (max 5 hops)
            if newChain.count >= 5 {
                deliver(key: key, result: .failure(.aliasHopLimitExceeded(chain: newChain)))
                return
            }

            // Follow alias by resolving aliasTarget
            let aliasKey = CacheKey(name: aliasTarget, type: key.type)
            resolveInternal(key: aliasKey, aliasChain: newChain, callerQueue: queue) { [weak self] result in
                guard let self else { return }
                self.queue.async {
                    switch result {
                    case .success(let targetRes):
                        let effectiveTTL = min(aliasEntry.record.ttl, targetRes.ttl)
                        let clampedTTL = min(max(effectiveTTL, 30), 3600)
                        let exp = currentTime.addingTimeInterval(Double(clampedTTL))

                        let finalRes: NCECHResolution
                        switch targetRes {
                        case .found(var rec):
                            rec.queryName = key.name
                            rec.ttl = clampedTTL
                            rec.expires = exp
                            rec.aliasChain = newChain + [aliasTarget]
                            finalRes = .found(rec)
                        case .noECH:
                            finalRes = .noECH(queryName: key.name, ttl: clampedTTL, expires: exp)
                        }
                        self.storeCache(key: key, resolution: finalRes)
                        self.deliver(key: key, result: .success(finalRes))

                    case .failure(let err):
                        self.deliver(key: key, result: .failure(err))
                    }
                }
            }
            return
        }

        // ServiceMode: evaluate candidates in priority order.
        // Find the first candidate that contains ECH configuration.
        if let hit = entries.first(where: { $0.candidate.echConfigList != nil }) {
            let clampedTTL = min(max(hit.record.ttl, 30), 3600)
            let exp = currentTime.addingTimeInterval(Double(clampedTTL))
            let rec = NCECHRecord(
                queryName: key.name,
                echConfigList: hit.candidate.echConfigList!,
                ttl: clampedTTL,
                expires: exp,
                candidate: hit.candidate,
                sourceRecord: hit.record,
                aliasChain: aliasChain
            )
            let res = NCECHResolution.found(rec)
            storeCache(key: key, resolution: res)
            deliver(key: key, result: .success(res))
            return
        }

        // If candidates exist but none advertise ECH:
        if !entries.isEmpty {
            let minTTL = entries.map(\.record.ttl).min() ?? 60
            let clampedNegTTL = min(max(minTTL, 10), 300)
            let res = NCECHResolution.noECH(queryName: key.name, ttl: clampedNegTTL, expires: currentTime.addingTimeInterval(Double(clampedNegTTL)))
            storeCache(key: key, resolution: res)
            deliver(key: key, result: .success(res))
            return
        }

        // No SVCB/HTTPS answers: check if there is a CNAME to chase
        if let cnameTarget = msg.cnameTarget(for: key.name) {
            let target = normalize(cnameTarget)
            let newChain = aliasChain + [key.name]

            if newChain.contains(target) {
                deliver(key: key, result: .failure(.aliasLoop(chain: newChain + [target])))
                return
            }
            if newChain.count >= 5 {
                deliver(key: key, result: .failure(.aliasHopLimitExceeded(chain: newChain)))
                return
            }

            let targetKey = CacheKey(name: target, type: key.type)
            resolveInternal(key: targetKey, aliasChain: newChain, callerQueue: queue) { [weak self] result in
                guard let self else { return }
                self.queue.async {
                    switch result {
                    case .success(let targetRes):
                        let clampedTTL = min(max(targetRes.ttl, 30), 3600)
                        let exp = currentTime.addingTimeInterval(Double(clampedTTL))
                        let finalRes: NCECHResolution
                        switch targetRes {
                        case .found(var rec):
                            rec.queryName = key.name
                            rec.ttl = clampedTTL
                            rec.expires = exp
                            rec.aliasChain = newChain + [target]
                            finalRes = .found(rec)
                        case .noECH:
                            finalRes = .noECH(queryName: key.name, ttl: clampedTTL, expires: exp)
                        }
                        self.storeCache(key: key, resolution: finalRes)
                        self.deliver(key: key, result: .success(finalRes))
                    case .failure(let err):
                        self.deliver(key: key, result: .failure(err))
                    }
                }
            }
            return
        }

        // NOERROR NODATA: the domain has no HTTPS records at all.
        // Cache negative result conservatively (e.g. 60 seconds).
        let negTTL: UInt32 = 60
        let res = NCECHResolution.noECH(queryName: key.name, ttl: negTTL, expires: currentTime.addingTimeInterval(Double(negTTL)))
        storeCache(key: key, resolution: res)
        deliver(key: key, result: .success(res))
    }

    private func storeCache(key: CacheKey, resolution: NCECHResolution) {
        if cache.count >= capacity {
            let t = now()
            cache = cache.filter { $0.value.expires > t }
            if cache.count >= capacity { cache.removeAll() }
        }
        cache[key] = CacheEntry(resolution: resolution, expires: resolution.expires)
    }

    private func deliver(key: CacheKey, result: Result<NCECHResolution, NCECHError>) {
        guard let list = waiters.removeValue(forKey: key) else { return }
        for w in list {
            w.callerQueue.async { w.completion(result) }
        }
    }

    /// Synchronous cache lookup without dispatching network queries.
    func cachedECH(for host: String, queryServerName: String? = nil, type: UInt16 = NCDNSMessage.typeHTTPS) -> NCECHResolution? {
        let rawTarget: String
        if let qsn = queryServerName?.trimmingCharacters(in: .whitespaces), !qsn.isEmpty {
            rawTarget = qsn
        } else {
            rawTarget = host
        }
        let effectiveName = normalize(rawTarget)
        let key = CacheKey(name: effectiveName, type: type)
        return queue.sync {
            guard let entry = cache[key] else { return nil }
            if entry.expires > now() {
                return entry.resolution
            } else {
                cache.removeValue(forKey: key)
                return nil
            }
        }
    }

    /// Clears the resolution cache (e.g. upon engine reload).
    func clearCache() {
        queue.async {
            self.cache.removeAll()
        }
    }

    /// Cancels all pending in-flight queries with .cancelled (e.g. on tunnel stop).
    func cancelAll() {
        queue.async {
            let allWaiters = self.waiters
            self.waiters.removeAll()
            for (_, list) in allWaiters {
                for w in list {
                    w.callerQueue.async { w.completion(.failure(.cancelled)) }
                }
            }
        }
    }

    /// Total active entries in cache (for diagnostics/tests).
    var cacheCount: Int {
        queue.sync { cache.count }
    }

    private func normalize(_ name0: String) -> String {
        var n = name0.trimmingCharacters(in: .whitespaces).lowercased()
        if n.hasSuffix(".") { n.removeLast() }
        return n
    }
}

@available(iOS 13.0, macOS 10.15, *)
extension NCECHResolver {
    /// Async convenience wrapper for `resolveECH`.
    func resolveECH(for host: String,
                    queryServerName: String? = nil,
                    type: UInt16 = NCDNSMessage.typeHTTPS) async throws -> NCECHResolution {
        try await withCheckedThrowingContinuation { continuation in
            resolveECH(for: host, queryServerName: queryServerName, type: type, callerQueue: .global()) { result in
                switch result {
                case .success(let resolution):
                    continuation.resume(returning: resolution)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
