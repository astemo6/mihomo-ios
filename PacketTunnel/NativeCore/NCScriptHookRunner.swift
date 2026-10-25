import Foundation

/// Tunnel-side execution of the two hook script kinds registered by
/// #120 (App/Core/NCScriptHooks.swift is the App-target contract; this
/// file is the PacketTunnel target's own implementation of the same
/// semantics — the two targets share no code, so the value types below
/// deliberately mirror the contract's).
///
///   - Surge `type=dns` scripts run AFTER an answer exists (hosts /
///     fake-IP locally, or the assigned upstream's reply) and BEFORE it
///     is written back to the client. A script answers with an address
///     list (the answer is rebuilt from it, filtered to the query's
///     qtype; an empty list is an authoritative NODATA), an rcode, or
///     nothing (pass-through). Scripts chain in declaration order:
///     each one sees the previous script's answer.
///   - Surge `type=rule` scripts run BEFORE rule matching (the
///     kernel's rule list and the manifest's rule list come from
///     different sources, so the contract's "when evaluation reaches
///     them" interleave is not representable; first verdict wins). A
///     script answers with a policy name or nothing (no match).
///
/// Fail-open everywhere: a script error, timeout or malformed result
/// is pass-through / no-match — a broken hook script never breaks DNS
/// or routing. All runs happen on one dedicated serial queue, never on
/// the DNS forwarding queue or the data-plane (lwIP) queue; each run
/// is a fresh NativeScriptRun on the shared JSC host with the script's
/// own manifest timeout (the entry always carries one — the manifest
/// builder defaults it to 10 s from the script's `timeout` setting;
/// the 1 s fallback below only fires for a hand-written manifest
/// without timeoutMs).
///
/// JS surface (set up per run by the runner + TernPrelude.js):
///   type=dns : $dns = { domain, qtype, qtypeName, answers, rcode },
///              $done([ips]) / $done({ addresses, rcode }) / $done()
///   type=rule: $rule = { domain, ip, srcIP, dstPort, srcPort,
///              network, protocol, process, url, userAgent },
///              $done("POLICY") / $done({ policy }) / $done()
///   Egern ctx-style scripts (export default, adapted at manifest
///   build) use the same $done channel; TernPrelude.js additionally
///   installs a native `ctx` global for these two phases.

// MARK: - Values (mirror App/Core/NCScriptHooks.swift)

/// One DNS query, as handed to a type=dns script.
struct NCScriptDNSQuery {
    /// Query name, lowercased, no trailing dot.
    var domain: String
    /// DNS record type code (1 = A, 28 = AAAA, 65 = HTTPS, …).
    var qtype: UInt16
}

/// Connection context for a type=rule script (field-for-field mirror
/// of NCMatchContext, IPs as literals).
struct NCScriptRuleContext {
    var domain: String? = nil
    var ip: String? = nil
    var srcIP: String? = nil
    var dstPort: Int? = nil
    var srcPort: Int? = nil
    /// "tcp" | "udp".
    var network: String? = nil
    /// Sniffed application protocol: "http" | "tls" | "quic".
    var protocolHint: String? = nil
    var processName: String? = nil
    var url: String? = nil
    var userAgent: String? = nil

    init(_ ctx: NCMatchContext) {
        self.domain = ctx.domain
        self.ip = ctx.ip?.string
        self.srcIP = ctx.srcIP?.string
        self.dstPort = ctx.dstPort
        self.srcPort = ctx.srcPort
        self.network = ctx.network
        self.protocolHint = ctx.protocolHint
        self.processName = ctx.processName
        self.url = ctx.url
        self.userAgent = ctx.userAgent
    }

    /// The JSON object handed to the script ($rule global / ctx payload).
    var jsonObject: [String: Any] {
        var o: [String: Any] = [:]
        if let domain { o["domain"] = domain }
        if let ip { o["ip"] = ip }
        if let srcIP { o["srcIP"] = srcIP }
        if let dstPort { o["dstPort"] = dstPort }
        if let srcPort { o["srcPort"] = srcPort }
        if let network { o["network"] = network }
        if let protocolHint { o["protocol"] = protocolHint }
        if let processName { o["process"] = processName }
        if let url { o["url"] = url }
        if let userAgent { o["userAgent"] = userAgent }
        return o
    }
}

final class NCScriptHookRunner {
    static let shared = NCScriptHookRunner()

    /// Every hook run serializes here: scripts never execute on the
    /// DNS forwarding queue, the data-plane queue or a routing caller.
    private let queue = DispatchQueue(label: "nc.script-hooks")
    /// fix/nc-start-empty: for the tunnel's stall watchdog (rule scripts gate routing of new flows).
    var watchQueue: DispatchQueue { queue }
    private let host = NativeScriptHost.shared

    /// Fallback when a manifest entry carries no timeout at all (the
    /// manifest builder always writes one; see the header note).
    static let fallbackTimeoutMs: Int64 = 1_000
    /// Input caps (memory budget): a DNS reply is naturally bounded;
    /// anything larger skips the hooks untouched, and a script's
    /// address list is truncated.
    static let maxReplyBytes = 65_535
    static let maxAddresses = 128

    var hasDNSScripts: Bool { !host.hookEntries(type: "dns").isEmpty }
    var hasRuleScripts: Bool { !host.hookEntries(type: "rule").isEmpty }

    // MARK: type=dns

    /// Runs the registered dns scripts over a finished reply, in
    /// declaration order. `completion` (on `completionQueue`) receives
    /// the final reply — the original bytes whenever no script changed
    /// anything or anything failed (fail-open).
    func applyDNS(query queryData: Data, reply replyData: Data,
                  on completionQueue: DispatchQueue,
                  completion: @escaping (Data) -> Void) {
        let entries = host.hookEntries(type: "dns")
        guard !entries.isEmpty, replyData.count <= Self.maxReplyBytes,
              let query = NCDNSMessage.parse(queryData),
              let question = query.questions.first else {
            completionQueue.async { completion(replyData) }
            return
        }
        let q = NCScriptDNSQuery(domain: question.name.lowercased(), qtype: question.type)
        let applicable = entries.filter { self.patternAllows($0.pattern, domain: q.domain) }
        guard !applicable.isEmpty else {
            completionQueue.async { completion(replyData) }
            return
        }
        queue.async { [weak self] in
            guard let self else {
                completionQueue.async { completion(replyData) }
                return
            }
            var current = replyData
            for entry in applicable {
                if let next = self.runOneDNSScript(entry, query: q, reply: current) {
                    current = next
                }
            }
            completionQueue.async { completion(current) }
        }
    }

    /// One dns script over the current reply. nil = pass-through (the
    /// caller keeps `reply`); non-nil = the rewritten reply.
    private func runOneDNSScript(_ entry: NativeScriptHost.ManifestEntry,
                                 query q: NCScriptDNSQuery, reply: Data) -> Data? {
        guard let msg = NCDNSMessage.parse(reply) else { return nil }
        let answers = msg.addressAnswers.map { $0.0.string }
        let payload: [String: Any] = [
            "domain": q.domain,
            "qtype": Int(q.qtype),
            "qtypeName": Self.qtypeName(q.qtype),
            "answers": answers,
            "rcode": Int(msg.rcode),
        ]
        guard let value = runOne(entry, phase: "dns", globals: ["$dns": payload], payload: payload) else {
            return nil
        }
        return Self.rewrite(reply: msg, question: q, value: value)
    }

    /// Interprets one script's $done value as a DNS decision and
    /// rebuilds the reply. nil = the value decides nothing.
    private static func rewrite(reply msg: NCDNSMessage, question q: NCScriptDNSQuery, value: Any) -> Data? {
        var addresses: [String]? = nil
        var rcode: UInt16? = nil
        func readDict(_ d: [String: Any]) {
            if let list = d["addresses"] as? [Any] { addresses = list.compactMap { $0 as? String } }
            else if let list = d["answer"] as? [Any] { addresses = list.compactMap { $0 as? String } }
            else if let list = d["ips"] as? [Any] { addresses = list.compactMap { $0 as? String } }
            else if let one = d["address"] as? String { addresses = [one] }
            if let n = d["rcode"] as? NSNumber { rcode = n.uint16Value }
        }
        switch value {
        case let list as [Any]:
            addresses = list.compactMap { $0 as? String }
        case let d as [String: Any]:
            // Egern ctx.respond(r): the adapter's finish() hands the
            // respond payload through inside the $done value.
            if let inner = d["__egernRespond"] as? [String: Any] { readDict(inner) } else { readDict(d) }
        case let s as String:
            if NCIP(s) != nil { addresses = [s] }
        default:
            break
        }
        guard addresses != nil || rcode != nil else { return nil }
        var out = msg
        out.isResponse = true
        if let rcode { out.rcode = rcode }
        if let addresses {
            let ttl = msg.answers.first?.ttl ?? 60
            var records: [NCDNSRecord] = []
            for s in addresses.prefix(maxAddresses) {
                guard let ip = NCIP(s) else { continue }
                let type: UInt16
                switch ip {
                case .v4: type = NCDNSMessage.typeA
                case .v6: type = NCDNSMessage.typeAAAA
                }
                // The answer must answer the question: A queries take
                // v4 literals, AAAA queries v6; other qtypes take what
                // the script gave (record type follows the literal).
                if q.qtype == NCDNSMessage.typeA && type != NCDNSMessage.typeA { continue }
                if q.qtype == NCDNSMessage.typeAAAA && type != NCDNSMessage.typeAAAA { continue }
                records.append(NCDNSRecord(name: msg.questions.first?.name ?? q.domain,
                                           type: type, klass: NCDNSMessage.classIN,
                                           ttl: ttl, rdata: Data(ip.bytes)))
            }
            out.answers = records
        } else if let rcode, rcode != 0 {
            // An error rcode without an explicit answer is authoritative-empty.
            out.answers = []
        }
        return out.serialized()
    }

    static func qtypeName(_ t: UInt16) -> String {
        switch t {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 65: return "HTTPS"
        default: return "TYPE\(t)"
        }
    }

    // MARK: type=rule

    /// Runs the registered rule scripts for one connection, in
    /// declaration order. `completion` (on `completionQueue`) receives
    /// the winning policy + script name, or (nil, nil) for no match.
    func applyRule(ctx: NCMatchContext, on completionQueue: DispatchQueue,
                   completion: @escaping (_ policy: String?, _ script: String?) -> Void) {
        let entries = applicableRuleEntries(for: ctx)
        guard !entries.isEmpty else {
            completionQueue.async { completion(nil, nil) }
            return
        }
        queue.async { [weak self] in
            let verdict = self?.runRuleEntries(entries, ctx: NCScriptRuleContext(ctx))
            completionQueue.async { completion(verdict?.policy, verdict?.script) }
        }
    }

    /// Synchronous form for the engine's blocking route(): waits on
    /// the hook queue for at most the sum of the scripts' own timeouts
    /// (each run self-limits at its manifest timeout) plus slack.
    /// nil = no match, or the wait expired (fail-open).
    func ruleVerdict(ctx: NCMatchContext) -> (policy: String, script: String)? {
        let entries = applicableRuleEntries(for: ctx)
        guard !entries.isEmpty else { return nil }
        let budget = entries.reduce(0.5) { $0 + Double($1.timeoutMs ?? Self.fallbackTimeoutMs) / 1000 }
        let sem = DispatchSemaphore(value: 0)
        var verdict: (policy: String, script: String)? = nil
        queue.async { [weak self] in
            verdict = self?.runRuleEntries(entries, ctx: NCScriptRuleContext(ctx))
            sem.signal()
        }
        guard sem.wait(timeout: .now() + budget) == .success else { return nil }
        return verdict
    }

    private func applicableRuleEntries(for ctx: NCMatchContext) -> [NativeScriptHost.ManifestEntry] {
        let entries = host.hookEntries(type: "rule")
        guard !entries.isEmpty else { return [] }
        return entries.filter { entry in
            guard let pattern = entry.pattern, !pattern.isEmpty else { return true }
            guard let domain = ctx.domain else { return false }
            return self.patternAllows(pattern, domain: domain)
        }
    }

    /// First decisive script wins. Runs on the hook queue.
    private func runRuleEntries(_ entries: [NativeScriptHost.ManifestEntry],
                                ctx: NCScriptRuleContext) -> (policy: String, script: String)? {
        let payload = ctx.jsonObject
        for entry in entries {
            guard let value = runOne(entry, phase: "rule", globals: ["$rule": payload], payload: payload) else {
                continue
            }
            if let policy = Self.policy(from: value), !policy.isEmpty {
                return (policy, entry.name)
            }
        }
        return nil
    }

    /// Interprets one script's $done value as a rule decision.
    /// nil = no match.
    private static func policy(from value: Any) -> String? {
        switch value {
        case let s as String:
            return s
        case let d as [String: Any]:
            if let inner = d["__egernRespond"] as? [String: Any] { return policy(from: inner) }
            if let p = d["policy"] as? String { return p }
            if let p = d["group"] as? String { return p }
            return nil
        default:
            return nil
        }
    }

    // MARK: one run on the shared JSC host

    /// A manifest `pattern` is a domain regex filter (the #120
    /// contract); an uncompilable pattern never matches.
    private func patternAllows(_ pattern: String?, domain: String) -> Bool {
        guard let pattern, !pattern.isEmpty else { return true }
        guard let re = NCRegexCache.shared.regex(pattern) else { return false }
        return re.firstMatch(in: domain, options: [], range: NSRange(domain.startIndex..., in: domain)) != nil
    }

    /// Runs one hook script and returns its exported $done value
    /// (nil: the script passed / did not answer / failed — fail-open).
    /// Mirrors NativeTaskRunner.execute's run shape: prepare, a setup
    /// with phase + export on, one NativeScriptRun, read doneJSON.
    private func runOne(_ entry: NativeScriptHost.ManifestEntry, phase: String,
                        globals: [String: Any], payload: [String: Any]) -> Any? {
        let host = self.host
        let p = host.prepare(gen: 0, rule: entry.i, slot: 0, reload: false)
        guard p.ok, let key = p.key else { return nil }
        var setup = ((try? JSONSerialization.jsonObject(with: Data(p.setupJSON.utf8))) as? [String: Any]) ?? [:]
        setup["phase"] = phase
        setup["export"] = true
        setup["globals"] = globals
        // The phase payload (same object as the $ global) — TernPrelude
        // builds the Egern `ctx` global from it for dns / rule runs.
        setup[phase] = payload
        guard let sd = try? JSONSerialization.data(withJSONObject: setup),
              let ss = String(data: sd, encoding: .utf8) else { return nil }
        let run = NativeScriptRun(gen: 0, rule: entry.i, go: host, js: JSCScriptEngine.shared,
                                  lane: nil, nativeBase: NativeBodyStore.defaultBlobBase, laneOK: false)
        let timeout = p.timeoutMs ?? entry.timeoutMs ?? Self.fallbackTimeoutMs
        let out = run.run(key: key, setup: ss, timeoutMs: timeout) {
            let p2 = host.prepare(gen: 0, rule: entry.i, slot: 0, reload: true)
            return p2.ok ? p2.key : nil
        }
        run.releaseNatives(keep: 0)
        switch out {
        case .failed:
            return nil
        case .ok:
            let raw = run.doneJSON
            guard !raw.isEmpty,
                  let d = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any] else {
                return nil
            }
            if d["undef"] as? Bool == true || d["isNull"] as? Bool == true { return nil }
            return d["value"]
        }
    }
}

// MARK: - Engine glue

// The runner itself also compiles into the app target (project.yml)
// so UnitTests/NativeCoreScriptRuntimeVerifyTests.swift can drive it
// against the real script host; NativeCoreEngine exists only in the
// tunnel, hence the guard (the same TERN_TUNNEL split NativeScriptHost
// uses for its tunnel-only calls).
#if TERN_TUNNEL
extension NativeCoreEngine {
    /// Whether any Surge type=dns script is registered (checked by
    /// the data plane once per query; with none registered the DNS
    /// path is the pre-hook one, untouched).
    var hasDNSScripts: Bool { NCScriptHookRunner.shared.hasDNSScripts }

    /// Whether any Surge type=rule script is registered.
    var hasRuleScripts: Bool { NCScriptHookRunner.shared.hasRuleScripts }

    /// Runs the registered type=dns scripts over a finished reply
    /// (local hosts / fake-IP answer or upstream response), before it
    /// is written back to the client. Fail-open: the completion
    /// receives the original reply on any script failure.
    func applyDNSScripts(query: Data, reply: Data, queue: DispatchQueue,
                         completion: @escaping (Data) -> Void) {
        NCScriptHookRunner.shared.applyDNS(query: query, reply: reply, on: queue, completion: completion)
    }
}
#endif
