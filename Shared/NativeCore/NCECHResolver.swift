import Foundation

/// Result record when ECH configuration is found via DNS HTTPS (65) or SVCB (64).
struct NCECHRecord: Equatable {
    /// The effective domain name queried (honoring query-server-name).
    var queryName: String

    /// Raw ECHConfigList bytes extracted from SvcParam ech (key 5).
    /// Passed directly to E1's parser for TLS handshake consumption.
    /// This is the sole stored representation of ECH bytes in cache.
    var echConfigList: Data

    /// Record TTL in seconds (clamped).
    var ttl: UInt32

    /// Cache expiration date.
    var expires: Date

    /// The chain of domain names followed if AliasMode (or CNAME) was traversed.
    var aliasChain: [String] = []

    /// Derived candidate view generated on demand from echConfigList.
    /// Eliminates memory overhead of caching duplicate Data buffers and dictionary trees.
    var candidate: NCSVCCandidate {
        NCSVCCandidate(
            priority: 1,
            targetName: ".",
            alpn: nil,
            noDefaultALPN: false,
            port: nil,
            ipv4Hints: nil,
            echConfigList: echConfigList,
            ipv6Hints: nil,
            mandatoryKeys: nil,
            rawParams: [NCSvcParamKey.ech.rawValue: echConfigList]
        )
    }

    /// Derived source record view generated on demand.
    var sourceRecord: NCDNSRecord {
        NCDNSRecord(
            name: queryName,
            type: NCDNSMessage.typeHTTPS,
            klass: NCDNSMessage.classIN,
            ttl: ttl,
            rdata: candidate.serializedRData()
        )
    }

    init(queryName: String,
         echConfigList: Data,
         ttl: UInt32,
         expires: Date,
         aliasChain: [String] = []) {
        self.queryName = queryName
        self.echConfigList = echConfigList
        self.ttl = ttl
        self.expires = expires
        self.aliasChain = aliasChain
    }
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

    /// Structured candidate record if found (derived on demand).
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
    /// More than 64 callers already wait on the same in-flight query.
    case tooManyWaiters

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
        case .tooManyWaiters: return "Too many concurrent ECH lookups for the same name"
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
/// - Overall timeout covering all upstream attempts and alias hops without polluting cache.
final class NCECHResolver {
    /// Upstream routing provider type. Given queryName and RR type, returns the
    /// primary upstream, optional fallback upstream, and whether fallbackFirst applies.
    typealias UpstreamProvider = (_ queryName: String, _ type: UInt16) -> (primary: NCDNSUpstream?, fallback: NCDNSUpstream?, fallbackFirst: Bool)

    /// Upstream query forwarding function type for testing or custom forwarders.
    typealias QueryForwarder = (_ query: Data, _ upstream: NCDNSUpstream, _ completion: @escaping (Data?) -> Void) -> Void

    /// Named constant for overall ECH resolution deadline (covering all upstream attempts and alias hops).
    /// Default: 3.0 seconds (review #148 item 6; was 6). Bounded tight to avoid stalling TLS handshakes while leaving
    /// sufficient margin for sequential fallback / alias hops over mobile connections.
    static let overallTimeout: TimeInterval = 3.0
    static let defaultTimeout: TimeInterval = overallTimeout

    /// Cache key combining normalized query name and DNS type.
    struct CacheKey: Hashable {
        let name: String
        let type: UInt16
    }

    struct CacheEntry {
        let resolution: NCECHResolution
        let expires: Date
    }

    private final class Waiter {
        let id: UUID
        let callerQueue: DispatchQueue
        let completion: (Result<NCECHResolution, NCECHError>) -> Void
        var timer: DispatchWorkItem?
        var isSettled: Bool = false

        init(id: UUID = UUID(), callerQueue: DispatchQueue, completion: @escaping (Result<NCECHResolution, NCECHError>) -> Void) {
            self.id = id
            self.callerQueue = callerQueue
            self.completion = completion
        }
    }

    private let queue: DispatchQueue
    private let forwarder: NCDNSForwarder
    private let capacity: Int

    /// Injected routing provider. Can be replaced/injected at runtime or during construction.
    var upstreamProvider: UpstreamProvider

    /// Injected query forwarder. When non-nil, queries are routed through this function
    /// instead of the network NCDNSForwarder (used by UnitTests to mock upstreams).
    var queryForwarder: QueryForwarder? = nil

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
    ///   - timeout: Overall timeout for the resolution covering all upstreams and alias hops.
    ///   - callerQueue: Queue on which `completion` is called (nil = the resolver's own queue; never main by
    ///     default — this runs in the tunnel extension). Do not call the `queue.sync` helpers from that queue.
    ///   - completion: Callback returning `Result<NCECHResolution, NCECHError>`.
    func resolveECH(for host: String,
                    queryServerName: String? = nil,
                    type: UInt16 = NCDNSMessage.typeHTTPS,
                    timeout: TimeInterval = NCECHResolver.defaultTimeout,
                    callerQueue: DispatchQueue? = nil,
                    completion: @escaping (Result<NCECHResolution, NCECHError>) -> Void) {
        let callerQueue = callerQueue ?? queue
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
        let deadline = now().addingTimeInterval(timeout)

        queue.async {
            self.startResolution(key: key,
                                 timeout: timeout,
                                 deadline: deadline,
                                 callerQueue: callerQueue,
                                 completion: completion)
        }
    }

    private func startResolution(key: CacheKey,
                                 timeout: TimeInterval,
                                 deadline: Date,
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

        // 2. Check if deadline has already passed
        if deadline <= currentTime {
            callerQueue.async { completion(.failure(.timeout)) }
            return
        }

        // 3. Create waiter with timeout timer scheduled on `queue`
        let waiter = Waiter(callerQueue: callerQueue, completion: completion)
        let remaining = max(0.001, deadline.timeIntervalSince(currentTime))
        let timerItem = DispatchWorkItem { [weak self, weak waiter] in
            guard let self, let waiter, !waiter.isSettled else { return }
            self.queue.async {
                self.handleWaiterTimeout(key: key, waiter: waiter)
            }
        }
        waiter.timer = timerItem
        queue.asyncAfter(deadline: .now() + remaining, execute: timerItem)

        // 4. Coalesce in-flight requests for identical (name, type)
        if waiters[key] != nil {
            if waiters[key]!.count < 64 {
                waiters[key]!.append(waiter)
            } else {
                timerItem.cancel()
                waiter.isSettled = true
                callerQueue.async { completion(.failure(.tooManyWaiters)) }
            }
            return
        }

        waiters[key] = [waiter]

        // 5. Kick off internal resolution
        resolveInternal(key: key, aliasChain: [], deadline: deadline)
    }

    private func handleWaiterTimeout(key: CacheKey, waiter: Waiter) {
        guard !waiter.isSettled else { return }
        waiter.isSettled = true
        if var list = waiters[key] {
            list.removeAll { $0.id == waiter.id }
            if list.isEmpty {
                waiters.removeValue(forKey: key)
            } else {
                waiters[key] = list
            }
        }
        // Timeout is treated as a query failure: do NOT store negative cache!
        waiter.callerQueue.async {
            waiter.completion(.failure(.timeout))
        }
    }

    private func resolveInternal(key: CacheKey,
                                  aliasChain: [String],
                                  deadline: Date) {
        let currentTime = now()
        if deadline <= currentTime {
            deliver(key: key, result: .failure(.timeout))
            return
        }

        // 1. Resolve upstream route
        let (primary, fallback, fallbackFirst) = upstreamProvider(key.name, key.type)
        guard let primaryUpstream = primary ?? fallback else {
            deliver(key: key, result: .failure(.noUpstreamAvailable))
            return
        }

        // 2. Construct DNS query message
        var msg = NCDNSMessage()
        msg.id = UInt16.random(in: 1...0xffff)
        msg.recursionDesired = true
        msg.questions = [NCDNSQuestion(name: key.name, type: key.type, klass: NCDNSMessage.classIN)]
        let queryData = msg.serialized()

        // 3. Forward through upstream pool / mock forwarder
        sendQuery(queryData, primary: primaryUpstream, fallback: fallback, fallbackFirst: fallbackFirst) { [weak self] respData in
            guard let self else { return }
            self.queue.async {
                self.handleQueryResponse(key: key, aliasChain: aliasChain, deadline: deadline, respData: respData)
            }
        }
    }

    private func forwardQuery(_ query: Data, upstream: NCDNSUpstream, completion: @escaping (Data?) -> Void) {
        if let custom = queryForwarder {
            custom(query, upstream, completion)
        } else {
            forwarder.forward(query, upstream: upstream, completion: completion)
        }
    }

    private func sendQuery(_ query: Data, primary: NCDNSUpstream, fallback: NCDNSUpstream?,
                           fallbackFirst: Bool, completion: @escaping (Data?) -> Void) {
        if fallbackFirst, let fallback {
            forwardQuery(query, upstream: fallback) { [weak self] resp in
                if let resp { completion(resp); return }
                guard let self else { completion(nil); return }
                self.forwardQuery(query, upstream: primary, completion: completion)
            }
            return
        }

        forwardQuery(query, upstream: primary) { [weak self] resp in
            if let resp { completion(resp); return }
            guard let fallback, let self else { completion(resp); return }
            self.forwardQuery(query, upstream: fallback, completion: completion)
        }
    }

    private func handleQueryResponse(key: CacheKey, aliasChain: [String], deadline: Date, respData: Data?) {
        let currentTime = now()
        if deadline <= currentTime {
            deliver(key: key, result: .failure(.timeout))
            return
        }

        guard let respData else {
            deliver(key: key, result: .failure(.networkError("Upstream DNS query returned no response")))
            return
        }

        guard let msg = NCDNSMessage.parse(respData) else {
            deliver(key: key, result: .failure(.malformedResponse))
            return
        }

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
            resolveInternalAlias(key: aliasKey,
                                 originalKey: key,
                                 aliasChain: newChain,
                                 deadline: deadline,
                                 aliasRecordTTL: aliasEntry.record.ttl,
                                 aliasTarget: aliasTarget)
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
            resolveInternalAlias(key: targetKey,
                                 originalKey: key,
                                 aliasChain: newChain,
                                 deadline: deadline,
                                 aliasRecordTTL: 3600,
                                 aliasTarget: target)
            return
        }

        // NOERROR NODATA: the domain has no HTTPS records at all.
        // Cache negative result conservatively (e.g. 60 seconds).
        let negTTL: UInt32 = 60
        let res = NCECHResolution.noECH(queryName: key.name, ttl: negTTL, expires: currentTime.addingTimeInterval(Double(negTTL)))
        storeCache(key: key, resolution: res)
        deliver(key: key, result: .success(res))
    }

    private func resolveInternalAlias(key aliasKey: CacheKey,
                                       originalKey: CacheKey,
                                       aliasChain: [String],
                                       deadline: Date,
                                       aliasRecordTTL: UInt32,
                                       aliasTarget: String) {
        let currentTime = now()
        if deadline <= currentTime {
            deliver(key: originalKey, result: .failure(.timeout))
            return
        }

        // Check if aliasKey is already cached
        if let cached = cache[aliasKey], cached.expires > currentTime {
            let targetRes = cached.resolution
            let effectiveTTL = min(aliasRecordTTL, targetRes.ttl)
            let clampedTTL = min(max(effectiveTTL, 30), 3600)
            let exp = currentTime.addingTimeInterval(Double(clampedTTL))

            let finalRes: NCECHResolution
            switch targetRes {
            case .found(var rec):
                rec.queryName = originalKey.name
                rec.ttl = clampedTTL
                rec.expires = exp
                rec.aliasChain = aliasChain + [aliasTarget]
                finalRes = .found(rec)
            case .noECH:
                finalRes = .noECH(queryName: originalKey.name, ttl: clampedTTL, expires: exp)
            }
            storeCache(key: originalKey, resolution: finalRes)
            deliver(key: originalKey, result: .success(finalRes))
            return
        }

        let remaining = max(0.001, deadline.timeIntervalSince(currentTime))
        let aliasWaiter = Waiter(callerQueue: queue) { [weak self] result in
            guard let self else { return }
            self.queue.async {
                switch result {
                case .success(let targetRes):
                    let effectiveTTL = min(aliasRecordTTL, targetRes.ttl)
                    let clampedTTL = min(max(effectiveTTL, 30), 3600)
                    let exp = self.now().addingTimeInterval(Double(clampedTTL))

                    let finalRes: NCECHResolution
                    switch targetRes {
                    case .found(var rec):
                        rec.queryName = originalKey.name
                        rec.ttl = clampedTTL
                        rec.expires = exp
                        rec.aliasChain = aliasChain + [aliasTarget]
                        finalRes = .found(rec)
                    case .noECH:
                        finalRes = .noECH(queryName: originalKey.name, ttl: clampedTTL, expires: exp)
                    }
                    self.storeCache(key: originalKey, resolution: finalRes)
                    self.deliver(key: originalKey, result: .success(finalRes))

                case .failure(let err):
                    self.deliver(key: originalKey, result: .failure(err))
                }
            }
        }

        let timerItem = DispatchWorkItem { [weak self, weak aliasWaiter] in
            guard let self, let aliasWaiter, !aliasWaiter.isSettled else { return }
            self.queue.async {
                self.handleWaiterTimeout(key: aliasKey, waiter: aliasWaiter)
            }
        }
        aliasWaiter.timer = timerItem
        queue.asyncAfter(deadline: .now() + remaining, execute: timerItem)

        if waiters[aliasKey] != nil {
            if waiters[aliasKey]!.count < 64 {
                waiters[aliasKey]!.append(aliasWaiter)
            } else {
                timerItem.cancel()
                aliasWaiter.isSettled = true
                deliver(key: originalKey, result: .failure(.timeout))
            }
            return
        }

        waiters[aliasKey] = [aliasWaiter]
        resolveInternal(key: aliasKey, aliasChain: aliasChain, deadline: deadline)
    }

    private func storeCache(key: CacheKey, resolution: NCECHResolution) {
        if cache.count >= capacity {
            let t = now()
            cache = cache.filter { $0.value.expires > t }
            while cache.count >= capacity {
                if let oldest = cache.min(by: { $0.value.expires < $1.value.expires })?.key {
                    cache.removeValue(forKey: oldest)
                } else {
                    break
                }
            }
        }
        cache[key] = CacheEntry(resolution: resolution, expires: resolution.expires)
    }

    private func deliver(key: CacheKey, result: Result<NCECHResolution, NCECHError>) {
        guard let list = waiters.removeValue(forKey: key) else { return }
        for w in list {
            w.timer?.cancel()
            guard !w.isSettled else { continue }
            w.isSettled = true
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
                    w.timer?.cancel()
                    guard !w.isSettled else { continue }
                    w.isSettled = true
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
                    type: UInt16 = NCDNSMessage.typeHTTPS,
                    timeout: TimeInterval = NCECHResolver.defaultTimeout) async throws -> NCECHResolution {
        try await withCheckedThrowingContinuation { continuation in
            resolveECH(for: host, queryServerName: queryServerName, type: type, timeout: timeout, callerQueue: .global()) { result in
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
