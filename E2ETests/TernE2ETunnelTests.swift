import XCTest

/// Tern E2E replay, stage 2 of 2 (feat/nc-e2e): NativeCore started in-process on the runtime files stage 1
/// (UnitTests/NativeCoreE2EReplayTests.swift) generated from the fixture through the App's import path — the same
/// NativeTunnelCore.start(home:flow:…) the PacketTunnel extension calls, with a synthetic NEPacketTunnelFlow
/// (E2EFlow) in front of the real lwIP data plane, the real controller on 127.0.0.1 and the real MitM front.
///
/// This bundle compiles the PacketTunnel target's sources (project-uitests.yml, target TernE2ETunnelTests) and is
/// hosted in Tern.app so both stages share one app container. It never imports the Tern app module.
///
/// Each scenario is one E2E-RESULT line (E2EReport). Network-dependent scenarios SKIP with the reason when the runner
/// cannot reach what they need (workflow pre-checks: TERN_E2E_PUBLIC_DNS / TERN_E2E_INTERNET; per-node TCP probe).
final class TernE2ETunnelTests: XCTestCase {
    private var r: E2EReport!
    private var api: E2EController!
    private var net: E2ENet!
    private var flow: E2EFlow!
    private var home = ""
    private var sample = false
    private var port = 0
    private var secret = ""

    // Domains of the sample fixture (sample.conf [filter_local] / remote lists); in real-fixture mode the same names are
    // routed by rules this test prepends to the runtime (injectRules).
    private let dDirect = "e2e-direct.localtest.me"
    private let dProxy = "e2e-proxy.localtest.me"
    private let dFake = "e2e-fake.localtest.me"
    private let dRedir = "e2e-redir.localtest.me"
    private let dSub = "e2e-sub.localtest.me"
    private let dReject = "e2e-reject.localtest.me"
    private let dList = "e2e-list.localtest.me"
    private let dMitm = "e2e-mitm.localtest.me"
    private let origin: UInt16 = 18480

    func testReplay() throws {
        guard E2EReport.enabled else { throw XCTSkip("E2E replay: set TEST_RUNNER_TERN_E2E=1 (e2e-replay.yml)") }
        r = E2EReport(stage: "tunnel")
        guard let ho = E2EReport.readHandoff(), let h = ho["home"] as? String, !h.isEmpty else {
            r.record("handoff", .fail, "no handoff.json from stage 1 (did NativeCoreE2EReplayTests run and pass?)")
            XCTFail("no handoff"); return
        }
        home = relocate(home: h, from: ho["container"] as? String)
        sample = E2EReport.env("TERN_E2E_SAMPLE") == "1"
        r.addSecrets(runtimeSecrets())
        let mem = E2EMemory()
        mem.start()
        let stacks = E2EStackWatch() // fix/nc-mem-4 diagnostic
        stacks.start()
        defer { stacks.stop() }
        if !sample { injectRules() }

        // ---- start (what the provider does, then NativeTunnelCore.start)
        E2EHarness.prepareProcess { [weak self] in self?.r.note($0) }
        flow = E2EFlow()
        net = E2ENet(flow: flow)
        port = E2EHarness.freePort()
        secret = "e2e-" + String(UUID().uuidString.prefix(8))
        api = E2EController(port: port, secret: secret)
        let t0 = Date()
        do {
            try NativeTunnelCore.shared.start(home: home, flow: flow, mtu: 1500, controllerPort: port, secret: secret)
        } catch {
            r.record("core-start", .fail, error.localizedDescription)
            XCTFail("core start"); return
        }
        let startMs = ms(t0)
        guard let engine = NativeTunnelCore.shared.engine else {
            r.record("core-start", .fail, "started but no engine"); XCTFail("no engine"); return
        }
        r.record("core-start", .pass, "\(startMs) ms — \(engine.statsLine)")
        r.note("dns mode \(engine.config?.dns.enhancedMode ?? "?"), config source \(engine.configSource), sample fixture \(sample)")

        mem.checkpoint("started")
        controllerAndCounts(engine)
        E2EMemory.mark("controller-counts-done")
        providers(engine)
        E2EMemory.mark("providers-done")
        ruleSets(engine)
        mem.checkpoint("providers+rule-sets")
        contract(engine)
        E2EMemory.mark("contract-done")
        groupDelay(engine)
        mem.checkpoint("contract+delay")
        let mapped = trafficFakeIP(engine)
        appStatsRecorded()
        mitm()
        tasksAndScripts()
        // fix/nc-e2e-real: judged on the core phases (start, providers, rule sets, controller, delay, fake-ip traffic,
        // MitM, scripts) — what a device runs. The restart / redir-host reload phases that follow are test-only
        // (a second engine generation while the first drains, the XCTest harness's own buffers) and are reported as
        // INFO. Run 40278215218 measured them together: 54.4 MB.
        let core = mem.checkpoint("core-phases")
        let limit = 44.0 // the extension's 50 MB jetsam budget minus the ~6 MB the extension uses without the core
        // fix/nc-mem-4: judged on the kernel's lifetime peak (ledger_phys_footprint_peak, what jetsam would have seen
        // at the worst moment) — the 100 ms sampler alone passed a run whose real transient was +65.6 MB (gate 3a).
        let judged = max(core.peakMB, core.kpeakMB)
        r.record("memory-footprint", judged <= limit ? .pass : .fail,
                 String(format: "core phases: kernel peak +%.1f MB (sampled peak +%.1f) over the pre-start baseline %.1f MB, now +%.1f MB (limit %.0f MB); %@",
                        core.kpeakMB, core.peakMB, Double(mem.baseline) / 1_048_576, core.nowMB, limit, mem.checkpointLine))
        restartAndStaleFakeIP(mapped: mapped)
        mem.checkpoint("restart")
        redirHost(mappedFakeIP: mapped)
        mem.checkpoint("redir-host")

        NativeTunnelCore.shared.stop()
        let m = mem.stop()
        r.record("memory-footprint-full", .info,
                 String(format: "whole replay incl. restart + redir-host reload: baseline %.1f MB, peak %.1f MB, delta %.1f MB, kernel peak %.1f MB (delta %.1f); %@",
                        m.baselineMB, m.peakMB, m.deltaMB, m.kpeakMB, m.kpeakMB - m.baselineMB, mem.checkpointLine))
        dumpStartupLog()
        let fails = r.counts[.fail] ?? 0
        r.note("tunnel stage: \(r.counts[.pass] ?? 0) pass, \(fails) fail, \(r.counts[.skip] ?? 0) skip")
        r.record("stage-done", .info, "stage 2 finished")
        // The job decides pass / fail from the summary (known gaps), not from XCTest: always green here.
    }

    // MARK: - controller + counts

    private func controllerAndCounts(_ engine: NativeCoreEngine) {
        // fix/nc-mem-4: test-side [nc-mem] marks around each call (core-side lines: ctrl-in / ctrl-done).
        E2EMemory.mark("call /version")
        let v = api.call("GET", "/version")
        E2EMemory.mark("done /version \(v.data.count) B \(v.ms) ms")
        r.record("controller-version", v.ok && v.object?["version"] != nil ? .pass : .fail, "HTTP \(v.status) in \(v.ms) ms \(v.ok ? "" : v.message)")
        E2EMemory.mark("call /proxies")
        let pxr = api.call("GET", "/proxies")
        E2EMemory.mark("done /proxies \(pxr.data.count) B \(pxr.ms) ms")
        let px = pxr.object?["proxies"] as? [String: Any] ?? [:]
        let groups = px.values.filter { ($0 as? [String: Any])?["all"] != nil }.count
        let proxies = px.count - groups
        E2EMemory.mark("call /rules")
        let rr = api.call("GET", "/rules")
        E2EMemory.mark("done /rules \(rr.data.count) B \(rr.ms) ms")
        let rules = (rr.object?["rules"] as? [Any])?.count ?? 0
        E2EMemory.mark("call /providers/proxies")
        let pr = api.call("GET", "/providers/proxies")
        E2EMemory.mark("done /providers/proxies \(pr.data.count) B \(pr.ms) ms")
        let prov = pr.object?["providers"] as? [String: Any] ?? [:]
        let ho = E2EReport.readHandoff() ?? [:]
        let runtimeRules = ho["rules"] as? Int ?? -1
        let detail = "proxies \(proxies), groups \(groups), rules \(rules) (runtime \(runtimeRules), unparsed \(engine.unparsedRules.count)), providers \(prov.count)"
        r.record("load-counts", proxies > 0 && groups > 0 && rules > 0 ? .pass : .fail, detail)
        if engine.unparsedRules.isEmpty {
            r.record("rules-parse", .pass, "every runtime rule parsed")
        } else {
            r.record("rules-parse", .fail, "\(engine.unparsedRules.count) rule(s) not understood (silently ignored): " + engine.unparsedRules.prefix(6).joined(separator: " ; "))
        }
        for l in engine.supportReport.prefix(30) { r.note("unsupported: \(l)") }
    }

    // MARK: - proxy providers / rule sets

    private func providerNames() -> [String] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
              let pp = o["proxy-providers"] as? [String: Any] else { return [] }
        return pp.keys.sorted()
    }

    private func providerURL(_ name: String) -> String? {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
              let pp = o["proxy-providers"] as? [String: Any], let p = pp[name] as? [String: Any] else { return nil }
        return p["url"] as? String
    }

    private func providerNodes() -> [String: [String]] {
        let prov = api.call("GET", "/providers/proxies").object?["providers"] as? [String: Any] ?? [:]
        var out: [String: [String]] = [:]
        for (k, v) in prov {
            let nodes = ((v as? [String: Any])?["proxies"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
            out[k] = nodes
        }
        return out
    }

    private func providers(_ engine: NativeCoreEngine) {
        let names = providerNames()
        if names.isEmpty { r.record("proxy-providers", .info, "the config has no proxy-providers"); return }
        var nodes: [String: [String]] = [:]
        // fix/nc-mem-2: every 0.5 s (was back-to-back, ~22 GET /providers/proxies per second for the whole 25 s when a
        // provider never fills — far beyond what the App asks of the controller).
        _ = E2ENet.waitUntil(25, every: 0.5) {
            nodes = self.providerNodes()
            return names.allSatisfy { (nodes[$0]?.count ?? 0) > 0 }
        }
        for n in names {
            let c = nodes[n]?.count ?? 0
            if c > 0 { r.record("provider:\(n)", .pass, "\(c) node(s)"); continue }
            if let u = providerURL(n), let url = URL(string: u), let host = url.host, !host.hasPrefix("127."),
               !E2EHarness.tcpReachable(host: host, port: url.port ?? (url.scheme == "https" ? 443 : 80)) {
                r.record("provider:\(n)", .skip, "0 nodes — the subscription host is not reachable from this runner")
            } else if let u = providerURL(n), !u.contains("://127."), let h = E2EHarness.httpStatus(u),
                      (400..<500).contains(h.status) || h.cfBlock {
                // fix/nc-e2e-real (run 40278215218: 薯条 0 nodes): the subscription refuses the CI runner itself
                // (Cloudflare 1005 = the runner's ASN is banned) — fetched from the test process too, not through Tern.
                r.record("provider:\(n)", .skip, "0 nodes — the subscription answers HTTP \(h.status)\(h.cfBlock ? " (Cloudflare block page)" : "") to this runner directly, not a Tern fetch bug")
            } else {
                r.record("provider:\(n)", .fail, "0 nodes after 25 s (\(nodes[n] == nil ? "provider missing from /providers/proxies" : "empty"))")
            }
        }
    }

    private func ruleSets(_ engine: NativeCoreEngine) {
        guard let cfg = engine.config else { return }
        let list = NCRuleProviderStore.providers(from: cfg)
        if list.isEmpty { r.record("rule-sets", .info, "the config has no rule providers"); return }
        // fix/nc-mem-providers: judge the core's own store (cache-first load + the background refresh it started at
        // core start), as on a device. Run 40290997704 built a second NCRuleProviderStore here that downloaded and
        // indexed all 29 lists again in this process, inside the memory-footprint window.
        let remote = list.filter { $0.url != nil }
        // fix/nc-mem-2: the core fetches at most NCRuleProviderStore.maxConcurrentFetches lists at a time now.
        _ = E2ENet.waitUntil(60, every: 0.25) { remote.allSatisfy { engine.ruleProviderIsLoaded($0.name) } }
        for p in list {
            guard let u = p.url else {
                r.record("rule-set:\(p.name)", .info, "local (\(p.filePath != nil ? "file" : "inline")) — loaded with the config")
                continue
            }
            if engine.ruleProviderIsLoaded(p.name) {
                r.record("rule-set:\(p.name)", .pass, "loaded by the core (\(p.behavior)/\(p.format))")
            } else if let url = URL(string: NCRuleProviderStore.unwrapLoopbackConvert(u)), let host = url.host, !host.hasPrefix("127."),
                      !E2EHarness.tcpReachable(host: host, port: url.port ?? (url.scheme == "https" ? 443 : 80)) {
                r.record("rule-set:\(p.name)", .skip, "host not reachable from this runner")
            } else {
                r.record("rule-set:\(p.name)", .fail, "not loaded: fetch failed or no entries parsed (\(p.behavior)/\(p.format), see startup log 'rule set:')")
            }
        }
    }

    // MARK: - controller contract (every endpoint App/Core/ControllerClient + views call)

    private func contract(_ engine: NativeCoreEngine) {
        let cfg = engine.effectiveConfig
        let group = pickGroup(cfg)?.name ?? "GLOBAL"
        let node = cfg?.proxies.first?.name ?? "DIRECT"
        let pnodes = providerNodes()
        let prov = pnodes.keys.sorted().first
        let pnode = prov.flatMap { pnodes[$0]?.first }
        let test = testURL(cfg)
        let e = E2EController.enc
        var rows: [(String, String, [String: String], Any?, [String])] = [
            ("GET", "/version", [:], nil, ["version"]),
            ("GET", "/configs", [:], nil, ["mode"]),
            ("PATCH", "/configs", [:], ["mode": "rule"], []),
            ("GET", "/proxies", [:], nil, ["proxies"]),
            ("GET", "/rules", [:], nil, ["rules"]),
            ("GET", "/providers/proxies", [:], nil, ["providers"]),
            ("GET", "/providers/rules", [:], nil, ["providers"]),
            ("GET", "/connections", [:], nil, ["connections"]),
            ("GET", "/app/traffic", [:], nil, []),
            ("GET", "/smart", [:], nil, []),
            ("GET", "/hark/logs", [:], nil, ["logs"]),
            ("GET", "/mitm/logs", [:], nil, []),
            ("GET", "/mitm/requests", [:], nil, []),
            ("GET", "/mitm/hosts", [:], nil, []),
            ("GET", "/mitm/tasks", [:], nil, []),
            ("GET", "/mitm/panels", [:], nil, []),
            ("GET", "/mitm/status", [:], nil, ["running"]),
            ("GET", "/mitm/notifications", [:], nil, []),
            ("GET", "/app/stats", [:], nil, []),
            ("GET", "/app/stats/speed", [:], nil, []),
            ("GET", "/dns/query", ["name": "e2e-fake.localtest.me", "type": "A"], nil, []),
            ("POST", "/cache/dns/flush", [:], nil, []),
            ("POST", "/cache/fakeip/flush", [:], nil, []),
            ("GET", "/proxies/\(e(node))/delay", ["url": test, "timeout": "3000"], nil, ["delay"]),
            ("GET", "/group/\(e(group))/delay", ["url": test, "timeout": "3000"], nil, []),
            ("GET", "/tern/node-tcp-delay", ["name": node, "url": test, "timeout": "3000"], nil, ["delay"]),
            ("PUT", "/proxies/\(e(group))", [:], ["name": cfg?.groupMap[group]?.proxies.first ?? "DIRECT"], []),
        ]
        if let prov {
            rows.append(("PUT", "/providers/proxies/\(e(prov))", [:], nil, []))
            rows.append(("GET", "/providers/proxies/\(e(prov))/healthcheck", [:], nil, []))
            if let pnode {
                rows.append(("GET", "/providers/proxies/\(e(prov))/\(e(pnode))/healthcheck", ["url": test, "timeout": "3000"], nil, ["delay"]))
            }
        }
        for (m, path, q, body, keys) in rows {
            let rep = api.call(m, path, query: q, body: body, timeout: 25)
            let name = "contract:\(m) \(templated(path))"
            // a delay endpoint answering 503/504 with a JSON message is the contract for an unreachable node
            let delayTimeout = path.contains("delay") || path.hasSuffix("/healthcheck") ? (rep.status == 503 || rep.status == 504) : false
            if rep.status == 404 {
                r.record(name, .fail, "404 \(rep.message)")
            } else if rep.ok || delayTimeout {
                let missing = keys.filter { rep.object?[$0] == nil }
                if missing.isEmpty || delayTimeout {
                    r.record(name, .pass, "HTTP \(rep.status) in \(rep.ms) ms")
                } else {
                    r.record(name, .fail, "HTTP \(rep.status) but shape lacks \(missing.joined(separator: ", "))")
                }
            } else {
                r.record(name, .fail, "HTTP \(rep.status) \(rep.message)")
            }
        }
        for path in ["/traffic", "/memory", "/connections", "/logs"] {
            let s = api.firstStreamMessage(path, trigger: path == "/logs" ? { NativeLogRing.shared.add(type: "info", payload: "[e2e] /logs stream probe") } : nil)
            r.record("contract:WS \(path)", s.ok ? .pass : .fail, s.ok ? "first message received" : s.detail)
        }
    }

    private func templated(_ path: String) -> String {
        let c = path.split(separator: "/").map { String($0) }
        guard c.count >= 2 else { return path }
        switch c[0] {
        case "proxies" where c.count >= 2: return "/proxies/{name}" + (c.count > 2 ? "/" + c[2...].joined(separator: "/") : "")
        case "group": return "/group/{name}/delay"
        case "providers" where c.count >= 3:
            if c.count == 3 { return "/providers/\(c[1])/{name}" }
            if c.count == 4 { return "/providers/\(c[1])/{name}/\(c[3])" }
            return "/providers/\(c[1])/{provider}/{node}/\(c[4])"
        default: return path
        }
    }

    private func pickGroup(_ cfg: NCConfig?) -> NCProxyGroup? {
        guard let cfg else { return nil }
        return cfg.groups.first { $0.type == "url-test" && $0.proxies.count > 1 }
            ?? cfg.groups.first { $0.type == "select" && $0.proxies.count > 1 && $0.name != "GLOBAL" }
            ?? cfg.groups.first
    }

    private func testURL(_ cfg: NCConfig?) -> String {
        if sample { return "http://127.0.0.1:18480/generate_204" }
        return pickGroup(cfg)?.url ?? "http://www.gstatic.com/generate_204"
    }

    // MARK: - group delay test

    private func groupDelay(_ engine: NativeCoreEngine) {
        guard let cfg = engine.effectiveConfig, let g = pickGroup(cfg) else {
            r.record("group-delay", .skip, "no group with members"); return
        }
        let members = g.proxies
        let rep = api.call("GET", "/group/\(E2EController.enc(g.name))/delay", query: ["url": testURL(cfg), "timeout": "5000"], timeout: 40)
        let results = (rep.object ?? [:]).compactMapValues { ($0 as? NSNumber)?.intValue }
        let ok = results.filter { $0.value > 0 }.count
        let timeouts = members.count - ok
        let byName = Dictionary(cfg.proxies.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        var reasons: [String] = []
        var reachable = 0
        for m in members {
            if let p = byName[m], let s = p.server, let pt = p.port, E2EHarness.tcpReachable(host: s, port: pt, timeout: 2) { reachable += 1 }
        }
        for m in members where (results[m] ?? 0) <= 0 && cfg.groupMap[m] == nil && m != "DIRECT" && m != "REJECT" {
            if reasons.count >= 8 { break }
            let one = api.call("GET", "/proxies/\(E2EController.enc(m))/delay", query: ["url": testURL(cfg), "timeout": "5000"], timeout: 15)
            reasons.append("\(m): HTTP \(one.status) \(one.message)")
        }
        let slow = results.max { $0.value < $1.value }
        let detail = "group \(g.name) (\(g.type)): \(ok) ok / \(timeouts) timeout of \(members.count); HTTP \(rep.status) in \(rep.ms) ms; slowest \(slow.map { "\($0.key) \($0.value) ms" } ?? "-"); TCP-reachable from runner \(reachable)" + (reasons.isEmpty ? "" : "; failures: " + reasons.joined(separator: " ; "))
        if sample {
            // E2E-SS + E2E-VMess-WS are up, E2E-Dead is not: 2 ok, 1 timeout, each failure with a readable reason.
            r.record("group-delay", ok >= 2 && timeouts >= 1 ? .pass : .fail, detail)
            let readable = reasons.allSatisfy { !$0.contains("错误") && !$0.contains("error 2") && !$0.hasSuffix("Timeout") }
            r.record("group-delay-reasons", readable ? .pass : .fail, readable ? "every failed node says which stage failed" : "a failure has no stage / readable reason: " + reasons.joined(separator: " ; "))
        } else if reachable == 0 && ok == 0 {
            r.record("group-delay", .skip, "no member node is TCP-reachable from this runner — " + detail)
        } else {
            r.record("group-delay", ok > 0 ? .pass : .fail, detail)
        }
    }

    // MARK: - data plane, fake-ip phase

    @discardableResult
    private func expectHTTP(_ name: String, ip: String, port: UInt16, host: String, path: String, wantStatus: Int = 200,
                            needs: String? = nil, wantVia: String? = nil, avoidVia: String? = nil) -> Bool {
        let res = net.httpGet(ip: ip, port: port, host: host, path: path, timeout: 12)
        let via = connLine(host: host)
        var ok = res.established && res.status == wantStatus
        if let needs { ok = ok && res.text.contains(needs) }
        if let wantVia { ok = ok && (via?.contains("→ \(wantVia)") ?? false) }
        if let avoidVia { ok = ok && !(via?.contains("→ \(avoidVia)") ?? true) }
        let body = res.text.split(separator: "\n").first.map { String($0) } ?? ""
        let detail = "\(host):\(port)\(path) via \(ip) — \(res.established ? "established" : "no SYN-ACK")\(res.reset ? ", RST" : ""), status \(res.status.map { String($0) } ?? "-") in \(res.ms) ms; \(via ?? "no [TCP] line"); \(body)"
        r.record(name, ok ? .pass : .fail, detail)
        return ok
    }

    /// The data plane's per-connection outcome line for host (NativeLogRing, `[TCP] host:port rule … → policy …`).
    /// fix/nc-e2e-real: the routing line (`… rule … → policy`), not the later `closed after …` line of the same flow
    /// (run 40278215218 redir-host read the close line and missed `→ DIRECT`).
    private func connLine(host: String) -> String? {
        func lines() -> [String] { NativeLogRing.shared.since(0).lines.map(\.payload).filter { $0.contains("[TCP] \(host):") } }
        _ = E2ENet.waitUntil(1.5) { lines().contains { $0.contains("→") } }
        let all = lines()
        return all.last { $0.contains("→") } ?? all.last
    }

    /// fix/nc-e2e-real: tunnel DNS with one retry; a miss notes the data plane's counters and whether a Surge
    /// type=dns script hook is installed (run 40278215218: only the first fake-ip query was answered — root cause is
    /// lane fix/nc-tcp0's; this makes the next failure self-describing).
    private func resolveRetry(_ name: String) -> (rcode: Int, ips: [String])? {
        if let a = net.resolve(name), !a.ips.isEmpty { return a }
        let plane = NativeTunnelCore.shared.plane?.statsLine ?? "no data plane"
        let hooks = NativeTunnelCore.shared.engine?.hasDNSScripts ?? false
        r.note("dns miss for \(name) (retrying once in 1 s): dns scripts \(hooks); \(plane)")
        Thread.sleep(forTimeInterval: 1)
        let again = net.resolve(name)
        if again == nil || again!.ips.isEmpty {
            r.note("dns miss again for \(name): \(NativeTunnelCore.shared.plane?.statsLine ?? "no data plane")")
        } else {
            r.note("dns retry answered \(name)")
        }
        return again
    }

    private var dnsNeeded: Bool { !E2EReport.publicDNSOK }

    private func trafficFakeIP(_ engine: NativeCoreEngine) -> (domain: String, ip: String)? {
        let mode = engine.config?.dns.enhancedMode.lowercased() ?? "fake-ip"
        guard mode == "fake-ip" else {
            r.record("dns-fakeip", .info, "config runs \(mode): fake-ip scenarios run after a switch is not attempted in this phase")
            return nil
        }
        guard let a = resolveRetry(dFake), let ip = a.ips.first else {
            r.record("dns-fakeip", .fail, "no answer from the tunnel DNS 198.18.0.2 for \(dFake)")
            return nil
        }
        let fake = ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.")
        r.record("dns-fakeip", fake ? .pass : .fail, "\(dFake) → \(ip) (rcode \(a.rcode))")
        let mapped: (domain: String, ip: String)? = fake ? (domain: dFake, ip: ip) : nil
        guard !dnsNeeded else {
            for n in ["traffic-direct", "traffic-fakeip", "traffic-proxied", "traffic-provider-node", "traffic-rule-set-direct"] {
                r.record(n, .skip, "public DNS (localtest.me → 127.0.0.1) not available on this runner")
            }
            return mapped
        }
        if let d = resolveRetry(dDirect)?.ips.first {
            expectHTTP("traffic-direct", ip: d, port: origin, host: dDirect, path: "/e2e/direct", needs: "e2e-ok", wantVia: "DIRECT")
        } else { r.record("traffic-direct", .fail, "no DNS answer for \(dDirect)") }
        if fake { expectHTTP("traffic-fakeip", ip: ip, port: origin, host: dFake, path: "/e2e/fake", needs: "e2e-ok") }
        if sample {
            if let p = resolveRetry(dProxy)?.ips.first {
                expectHTTP("traffic-proxied", ip: p, port: origin, host: dProxy, path: "/e2e/proxied", needs: "e2e-ok", avoidVia: "DIRECT")
            } else { r.record("traffic-proxied", .fail, "no DNS answer for \(dProxy)") }
            if let s = resolveRetry(dSub)?.ips.first {
                expectHTTP("traffic-provider-node", ip: s, port: origin, host: dSub, path: "/e2e/sub", needs: "e2e-ok", avoidVia: "DIRECT")
            } else { r.record("traffic-provider-node", .fail, "no DNS answer for \(dSub)") }
            if let l = resolveRetry(dList)?.ips.first {
                expectHTTP("traffic-rule-set-direct", ip: l, port: origin, host: dList, path: "/e2e/list", needs: "e2e-ok", wantVia: "DIRECT")
            } else { r.record("traffic-rule-set-direct", .fail, "no DNS answer for \(dList)") }
            if let x = resolveRetry(dReject)?.ips.first {
                let res = net.httpGet(ip: x, port: origin, host: dReject, path: "/e2e/reject", timeout: 6)
                let line = connLine(host: dReject) ?? "no [TCP] line"
                let rejected = !res.text.contains("e2e-ok") && (line.contains("REJECT") || line.contains("rejected"))
                r.record("traffic-rule-set-reject", rejected ? .pass : .fail, "\(line); got \(res.text.isEmpty ? "no data" : String(res.text.prefix(60)))")
            } else { r.record("traffic-rule-set-reject", .fail, "no DNS answer for \(dReject)") }
        } else if E2EReport.internetOK {
            trafficProxiedReal(engine)
        } else {
            r.record("traffic-proxied", .skip, "no internet on this runner")
        }
        return mapped
    }

    /// fix/nc-e2e-gaps: the traffic scenarios above must show up in GET /app/stats (统计) and /app/stats/speed.
    private func appStatsRecorded() {
        _ = E2ENet.waitUntil(2.5) { (self.api.call("GET", "/app/stats/speed").object?["seconds"] as? [Any])?.isEmpty == false }
        let st = api.call("GET", "/app/stats", query: ["hosts": "600", "rules": "300", "session": "0", "closedAfter": "0"])
        let sp = api.call("GET", "/app/stats/speed")
        guard st.ok, let o = st.object, sp.ok, let so = sp.object else {
            r.record("app-stats-recorded", .fail, "GET /app/stats HTTP \(st.status), /app/stats/speed HTTP \(sp.status)")
            return
        }
        let total = o["totalConnections"] as? Int ?? 0
        let hosts = (o["hosts"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
        let closed = (o["closed"] as? [Any])?.count ?? 0
        let secs = (so["seconds"] as? [Any])?.count ?? 0
        let sawLocal = hosts.contains { $0.hasSuffix("localtest.me") }
        let ok = total > 0 && sawLocal && secs > 0 && (o["full"] as? Bool) == true
        r.record("app-stats-recorded", ok ? .pass : .fail,
                 "connections \(total), hosts \(hosts.count) (localtest.me \(sawLocal)), rules \(o["ruleCount"] ?? "-"), closed \(closed), speed points \(secs)")
    }

    // MARK: - proxied traffic on the real fixture (fix/nc-e2e-gaps)

    /// Run 40290997704 sent connectivitycheck.gstatic.com through the config's final policy — DIRECT on the user's
    /// profile — so the proxied path was never exercised. Now the target is chosen by the engine's own routing: a
    /// DOMAIN / DOMAIN-SUFFIX rule of the profile whose policy resolves to a proxy node (Google-family first: an HTTP
    /// generate_204 there is stable), then the injected connectivitycheck.gstatic.com rule (→ the url-test group,
    /// see injectRules). PASS needs: the request answered over the tunnel, the [TCP] line not DIRECT / REJECT, and the
    /// rule's resolution a node (or chain). A dead node the user selected is tried past, not counted as a Tern bug.
    private func proxiedCandidates(_ engine: NativeCoreEngine) -> [(host: String, path: String, rule: String, node: String)] {
        var out: [(host: String, path: String, rule: String, node: String)] = []
        var seen = Set<String>()
        func node(for host: String) -> (String, String)? {
            let ctx = engine.matchContext(domain: host, ip: nil, dstPort: 80, network: "tcp")
            let (policy, rule, res) = engine.route(ctx)
            switch res {
            case .proxy(let p): return ("\(rule ?? "?") → \(policy)", p.name)
            case .chain(let ps): return ("\(rule ?? "?") → \(policy)", ps.map(\.name).joined(separator: " -> "))
            default: return nil
            }
        }
        func add(_ host: String, _ path: String) {
            guard seen.insert(host).inserted, let found = node(for: host) else { return }
            out.append((host, path, found.0, found.1))
        }
        let rules = engine.effectiveConfig?.rules ?? []
        var google: [String] = [], other: [String] = []
        for l in rules {
            let p = l.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            guard p.count >= 3 else { continue }
            let t = p[0].uppercased(), v = p[1].lowercased()
            guard t == "DOMAIN" || t == "DOMAIN-SUFFIX", !v.hasSuffix("localtest.me"), v.contains("."),
                  !v.hasPrefix("connectivitycheck.") else { continue }
            let host = t == "DOMAIN-SUFFIX" && v.split(separator: ".").count == 2 ? "www." + v : v
            if v == "google.com" || v.hasSuffix(".google.com") || v == "gstatic.com" || v.hasSuffix(".gstatic.com") {
                google.append(host)
            } else { other.append(host) }
        }
        for h in google.prefix(3) { add(h, "/generate_204") }
        for h in other where out.count < 3 { add(h, "/") }
        add("connectivitycheck.gstatic.com", "/generate_204")
        return out
    }

    private func trafficProxiedReal(_ engine: NativeCoreEngine) {
        let cands = proxiedCandidates(engine)
        guard !cands.isEmpty else {
            r.record("traffic-proxied", .fail, "no profile domain (nor the injected connectivitycheck rule) resolves to a proxy node")
            return
        }
        var tried: [String] = []
        for c in cands.prefix(4) {
            guard let ip = resolveRetry(c.host)?.ips.first else { tried.append("\(c.host): no DNS answer"); continue }
            let res = net.httpGet(ip: ip, port: 80, host: c.host, path: c.path, timeout: 12)
            let via = connLine(host: c.host) ?? "no [TCP] line"
            let proxied = via.contains("→") && !via.contains("→ DIRECT") && !via.contains("→ REJECT")
            let answered = res.established && res.status != nil
            let detail = "\(c.host):80\(c.path) via \(ip) — rule \(c.rule) (node \(c.node)); \(res.established ? "established" : "no SYN-ACK"), status \(res.status.map { String($0) } ?? "-") in \(res.ms) ms; \(via)"
            if answered && proxied {
                r.record("traffic-proxied", .pass, detail + (tried.isEmpty ? "" : " — earlier candidates: " + tried.joined(separator: "; ")))
                return
            }
            tried.append(detail)
            // routed DIRECT despite the engine saying proxy = product bug: stop and fail on it
            if via.contains("→ DIRECT") { break }
        }
        r.record("traffic-proxied", .fail, tried.joined(separator: " | "))
    }

    // MARK: - MitM

    private func mitmHosts() -> [String] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("nativecore-rewrite.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return [] }
        // fix/nc-e2e-real: RWSnapshot host entries are {"pat": …, "port": …} (run 40278215218 read "host" → 0 hosts);
        // a .conf profile's [MITM] hostnames live in the loaded canonical config instead.
        var out = (o["inc"] as? [Any] ?? []).compactMap { e -> String? in
            if let s = e as? String { return s }
            let d = e as? [String: Any]
            return (d?["pat"] as? String) ?? (d?["host"] as? String)
        }
        for h in NativeTunnelCore.shared.engine?.loadedCanonicalConfig?.mitm.hostnames ?? [] where !out.contains(h) { out.append(h) }
        return out
    }

    private func mitm() {
        let ca = NCCAManager.caCertDER(home: home)
        let hosts = mitmHosts()
        let host: String? = sample ? dMitm : hosts.first { !$0.contains("*") && !$0.hasPrefix("-") && $0.contains(".") }
        guard let host else { r.record("mitm-decrypt", .skip, "no concrete MitM hostname in the config (\(hosts.count) pattern(s))"); return }
        guard ca != nil else { r.record("mitm-decrypt", .fail, "no MitM CA in the app container"); return }
        guard !dnsNeeded || !sample else {
            r.record("mitm-decrypt", .skip, "public DNS not available"); return
        }
        guard let ip = resolveRetry(host)?.ips.first else { r.record("mitm-decrypt", .fail, "no DNS answer for the MitM host"); return }
        let first = E2ETLSProbe.get(net: net, ip: ip, sni: host, path: sample ? "/reject" : "/", caDER: ca)
        let mitmLine = connLine(host: host) ?? ""
        let decrypted = first.handshake && first.trustedByCA
        r.record("mitm-decrypt", decrypted ? .pass : .fail,
                 "\(host) via \(ip): relay \(first.relayEstablished ? "up" : "down"), TLS \(first.handshake ? "ok" : "failed"), leaf chains to the MitM CA \(first.trustedByCA ? "yes" : "no")\(first.trustError.map { " (\($0))" } ?? "")\(first.error.map { "; \($0)" } ?? ""); \(mitmLine.isEmpty ? "no [TCP] line" : mitmLine)")
        guard sample else {
            let reqs = api.call("GET", "/mitm/requests").json as? [[String: Any]] ?? []
            r.record("mitm-request-log", decrypted ? (reqs.isEmpty ? .fail : .pass) : .skip, "\(reqs.count) request(s) in /mitm/requests")
            return
        }
        if decrypted {
            r.record("mitm-rewrite", first.status == 200 ? .pass : .fail, "/reject (reject-200): status \(first.status.map { String($0) } ?? "-"), \(first.text.count) bytes")
            let rem = E2ETLSProbe.get(net: net, ip: ip, sni: host, path: "/remote", caDER: ca)
            r.record("mitm-rewrite-remote-module", rem.status == 200 && rem.text.contains("{}") ? .pass : .fail, "/remote (reject-dict from [rewrite_remote]): status \(rem.status.map { String($0) } ?? "-"), body \(String(rem.text.suffix(40)))")
            NativeLogRing.shared.clearScripts()
            let echo = E2ETLSProbe.get(net: net, ip: ip, sni: host, path: "/echo", caDER: ca)
            r.record("mitm-echo-script", echo.text.contains("e2e-echo-ok") ? .pass : .fail, "/echo (script-echo-response): status \(echo.status.map { String($0) } ?? "-"), body \(String(echo.text.suffix(40)))")
            scriptEvidence(marker: "e2e-echo script ran", scriptHint: "e2e-echo")
        } else {
            for n in ["mitm-rewrite", "mitm-rewrite-remote-module", "mitm-echo-script", "script-console-log", "script-diag-line", "script-log-api"] {
                r.record(n, .fail, "MitM did not decrypt the flow, so the rewrite / script never ran")
            }
        }
        if !E2EReport.internetOK {
            r.record("mitm-response-script", .skip, "no internet on this runner (origin httpbin.org)")
        } else if let hip = net.resolve("httpbin.org")?.ips.first {
            let resp = E2ETLSProbe.get(net: net, ip: hip, sni: "httpbin.org", path: "/get", caDER: ca, timeout: 25)
            if !resp.handshake {
                r.record("mitm-response-script", .fail, "httpbin.org not decrypted: \(resp.error ?? "-")")
            } else if resp.status == nil {
                r.record("mitm-response-script", .skip, "decrypted, but no answer from the origin through the loopback node (\(resp.error ?? "timeout"))")
            } else {
                r.record("mitm-response-script", resp.text.contains("<!--e2e-resp-->") ? .pass : .fail, "status \(resp.status!), marker \(resp.text.contains("<!--e2e-resp-->") ? "present" : "missing")")
            }
        } else { r.record("mitm-response-script", .fail, "no DNS answer for httpbin.org") }
        let reqs = api.call("GET", "/mitm/requests").json as? [[String: Any]] ?? []
        r.record("mitm-request-log", reqs.isEmpty ? .fail : .pass, "\(reqs.count) request(s) in /mitm/requests")
    }

    /// A script ran: its console.log line reached the script log ring (脚本日志 page reads /mitm/logs), and the
    /// core log has a `[SCRIPT]` line.
    private func scriptEvidence(marker: String, scriptHint: String) {
        _ = E2ENet.waitUntil(3) { NativeLogRing.shared.scriptLines(since: 0).contains { $0.msg.contains(marker) } }
        let lines = NativeLogRing.shared.scriptLines(since: 0)
        r.record("script-console-log", lines.contains { $0.msg.contains(marker) } ? .pass : .fail, "\(lines.count) script log line(s)")
        let diag = NativeLogRing.shared.since(0).lines.contains { $0.payload.hasPrefix("[SCRIPT]") && $0.payload.contains(scriptHint) }
        r.record("script-diag-line", diag ? .pass : .fail, diag ? "[SCRIPT] line in the core log" : "no [SCRIPT] line in the core log (诊断包 core-log.txt shows nothing about scripts)")
        let api = self.api.call("GET", "/mitm/logs").json as? [[String: Any]] ?? []
        r.record("script-log-api", api.contains { ($0["msg"] as? String ?? "").contains(marker) } ? .pass : .fail, "GET /mitm/logs: \(api.count) line(s)")
    }

    // MARK: - tasks / cron

    private func tasksAndScripts() {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("nativecore-scripts.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else {
            r.record("cron-parse", .skip, "no script manifest"); return
        }
        let tasks = o["tasks"] as? [[String: Any]] ?? []
        let crons = tasks.compactMap { t -> (String, String)? in
            guard let c = t["cron"] as? String, !c.isEmpty else { return nil }
            return (t["name"] as? String ?? "?", c)
        }
        let bad = crons.filter { NCCron($0.1) == nil }
        if crons.isEmpty {
            r.record("cron-parse", .info, "\(tasks.count) task(s), none scheduled by cron")
        } else {
            r.record("cron-parse", bad.isEmpty ? .pass : .fail, "\(crons.count) cron task(s)" + (bad.isEmpty ? ", all parse" : "; unparseable (never run): " + bad.map { "\($0.0) '\($0.1)'" }.joined(separator: ", ")))
        }
        let listed = api.call("GET", "/mitm/tasks").json as? [[String: Any]] ?? []
        guard let t = listed.first(where: { ($0["kind"] as? String) == "cron" }) ?? listed.first, let id = t["id"] as? String else {
            r.record("task-run", tasks.isEmpty ? .info : .fail, "GET /mitm/tasks listed \(listed.count) of \(tasks.count) task(s)"); return
        }
        let before = NativeLogRing.shared.scriptLines(since: 0).count
        let run = api.call("POST", "/mitm/tasks/\(E2EController.enc(id))/run", body: [String: Any](), timeout: 40)
        _ = E2ENet.waitUntil(3) { NativeLogRing.shared.scriptLines(since: 0).count > before }
        let after = NativeLogRing.shared.scriptLines(since: 0)
        let ranOK = (run.object?["ok"] as? Bool) == true
        let logged = sample ? after.contains { $0.msg.contains("e2e-task ran") } : after.count > before
        r.record("task-run", ranOK && logged ? .pass : .fail, "POST run: HTTP \(run.status) ok=\(ranOK)\(run.object?["error"].map { " error=\($0)" } ?? ""); script log lines \(before) → \(after.count)")
    }

    // MARK: - restart: persisted fake-ip map + stale fake-ip

    private func restartAndStaleFakeIP(mapped: (domain: String, ip: String)?) {
        NativeTunnelCore.shared.stop()
        let t0 = Date()
        do {
            try NativeTunnelCore.shared.start(home: home, flow: flow, mtu: 1500, controllerPort: port, secret: secret)
        } catch {
            r.record("core-restart", .fail, error.localizedDescription); return
        }
        r.record("core-restart", .pass, "\(ms(t0)) ms")
        if let mapped, !dnsNeeded {
            expectHTTP("fakeip-persist-restore", ip: mapped.ip, port: origin, host: mapped.domain, path: "/e2e/restored", needs: "e2e-ok")
        } else {
            r.record("fakeip-persist-restore", .skip, mapped == nil ? "no fake-ip mapping from the first phase" : "public DNS not available")
        }
        // An address in the fake-ip range nobody was given (an app's DNS cache from an older session / a lost map).
        let stale = "198.18.251.77"
        guard let c = net.connect(stale, 443) else { return }
        _ = E2ENet.waitUntil(6) { c.reset || c.finReceived }
        let how = c.reset ? "RST" : (c.finReceived ? "FIN (the app takes it as a normal close and retries the dead address)" : "nothing within 6 s")
        let line = NativeLogRing.shared.since(0).lines.last { $0.payload.contains(stale) }?.payload ?? "no [TCP] line"
        r.record("stale-fakeip-reset", c.reset ? .pass : .fail, "SYN to unmapped \(stale):443 → \(c.established ? "handshake, then " : "")\(how); \(line)")
        if !c.reset { c.abort() }
        net.forget(c)
    }

    // MARK: - redir-host

    private func redirHost(mappedFakeIP: (domain: String, ip: String)?) {
        let url = URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")
        guard let d = try? Data(contentsOf: url), var o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else {
            r.record("redir-host", .skip, "runtime JSON unreadable"); return
        }
        var dns = o["dns"] as? [String: Any] ?? [:]
        let was = dns["enhanced-mode"] as? String ?? "fake-ip"
        dns["enhanced-mode"] = "redir-host"
        dns["enable"] = true
        o["dns"] = dns
        guard let nd = try? JSONSerialization.data(withJSONObject: o) else { return }
        try? nd.write(to: url, options: .atomic)
        defer {
            dns["enhanced-mode"] = was
            o["dns"] = dns
            if let back = try? JSONSerialization.data(withJSONObject: o) { try? back.write(to: url, options: .atomic) }
        }
        if let err = NativeTunnelCore.shared.reload(hot: false) {
            r.record("redir-host", .fail, "reload into redir-host failed: \(err)"); return
        }
        guard E2EReport.internetOK, !dnsNeeded else {
            r.record("redir-host", .skip, "needs the config's upstream DNS (internet) on this runner"); return
        }
        guard let a = net.resolve(dRedir, timeout: 8) else {
            r.record("redir-host", .fail, "no DNS answer (forwarded to the config's upstream) for \(dRedir)"); return
        }
        let real = a.ips.first ?? "-"
        guard real == "127.0.0.1" else {
            r.record("redir-host", .fail, "\(dRedir) answered \(a.ips) rcode \(a.rcode) — expected the real address 127.0.0.1, not a fake IP"); return
        }
        expectHTTP("redir-host", ip: real, port: origin, host: dRedir, path: "/e2e/redir", needs: "e2e-ok", wantVia: "DIRECT")
        if let m = mappedFakeIP {
            expectHTTP("redir-host-stale-fakeip", ip: m.ip, port: origin, host: m.domain, path: "/e2e/stale", needs: "e2e-ok")
        }
    }

    // MARK: - helpers

    private func ms(_ t: Date) -> Int { Int(Date().timeIntervalSince(t) * 1000) }

    /// Each `xcodebuild test-without-building` reinstalls the host app and the simulator gives it a NEW data container
    /// (run 40268231519: stage 1 …/D31662A7…, stage 2 …/8CA29A7C…); the files move along but every absolute path stage 1
    /// wrote (handoff home, provider / script / geo paths inside the runtime files) still names the old one. On a device
    /// the App Group container is stable, so rewrite the old container prefix to the current one before starting.
    private func relocate(home h: String, from old: String?) -> String {
        let now = NSHomeDirectory()
        let fm = FileManager.default
        let moved = old.map { !$0.isEmpty && $0 != now && h.hasPrefix($0) } ?? false
        let newHome = moved ? now + h.dropFirst(old!.count) : h
        // The new container may not have the old one's files (the reinstall gave a fresh data container): restore stage
        // 1's snapshot ($TERN_E2E_STATE, a runner path outside the artifact) into the home's parent (= the data root).
        let rt = (newHome as NSString).appendingPathComponent("nativecore-runtime.json")
        if !fm.fileExists(atPath: rt) {
            let root = URL(fileURLWithPath: (newHome as NSString).deletingLastPathComponent, isDirectory: true)
            let n = E2EReport.restoreContainer(into: root)
            r.note(n < 0 ? "runtime files missing under the stage 2 home and no stage 1 snapshot (TERN_E2E_STATE unset)"
                         : "runtime files missing under the stage 2 home: restored \(n) item(s) of stage 1's data root from the snapshot")
        }
        guard moved, let old else { return newHome }
        let oldEsc = old.replacingOccurrences(of: "/", with: "\\/"), nowEsc = now.replacingOccurrences(of: "/", with: "\\/")
        var n = 0
        if let en = fm.enumerator(atPath: newHome) {
            for case let rel as String in en {
                let p = (newHome as NSString).appendingPathComponent(rel)
                guard let a = try? fm.attributesOfItem(atPath: p), (a[.type] as? FileAttributeType) == .typeRegular,
                      ((a[.size] as? NSNumber)?.intValue ?? 0) < 32 << 20,
                      let t = try? String(contentsOfFile: p, encoding: .utf8), t.contains(old) || t.contains(oldEsc) else { continue }
                let u = t.replacingOccurrences(of: old, with: now).replacingOccurrences(of: oldEsc, with: nowEsc)
                if (try? u.write(toFile: p, atomically: true, encoding: .utf8)) != nil { n += 1 }
            }
        }
        r.note("app container moved between stages (reinstall): \(n) file(s) under home rewritten to the new container path")
        return newHome
    }

    private func runtimeSecrets() -> [String] {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return [] }
        var out: [String] = []
        for p in o["proxies"] as? [[String: Any]] ?? [] {
            for k in ["server", "password", "uuid", "servername", "sni", "private-key", "public-key", "psk", "auth-str", "username"] {
                if let v = p[k] as? String { out.append(v) }
            }
        }
        for key in ["proxy-providers", "rule-providers"] {
            for (_, v) in o[key] as? [String: Any] ?? [:] { if let u = (v as? [String: Any])?["url"] as? String { out.append(u) } }
        }
        return out
    }

    /// Real fixture only: the data-plane scenarios aim at *.localtest.me (→ 127.0.0.1, the local origin), so route those
    /// names DIRECT ahead of the user's rules, and the public connectivity check to the policy of the config's final rule.
    private func injectRules() {
        let url = URL(fileURLWithPath: home).appendingPathComponent("nativecore-runtime.json")
        guard let d = try? Data(contentsOf: url), var o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return }
        var rules = o["rules"] as? [String] ?? []
        // fix/nc-e2e-gaps: the connectivity check goes to a group of proxy nodes (url-test first), not the final
        // policy (DIRECT on the user's profile — run 40290997704 never tested a proxied path).
        let groups = o["proxy-groups"] as? [[String: Any]] ?? []
        func members(_ g: [String: Any]) -> [String] {
            (g["proxies"] as? [String] ?? []).filter { !["DIRECT", "REJECT", "REJECT-DROP", "PASS"].contains($0.uppercased()) }
        }
        let proxyGroup = (groups.first { ($0["type"] as? String) == "url-test" && members($0).count > 1 }
            ?? groups.first { ($0["type"] as? String) == "fallback" && members($0).count > 1 }
            ?? groups.first { ($0["type"] as? String) == "select" && members($0).count > 1 && ($0["name"] as? String) != "GLOBAL" })?["name"] as? String
        let finalPolicy = proxyGroup ?? rules.last.flatMap { l -> String? in
            let p = l.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            return p.first?.uppercased() == "MATCH" || p.first?.uppercased() == "FINAL" ? p.last : nil
        } ?? "DIRECT"
        rules.insert(contentsOf: ["DOMAIN-SUFFIX,localtest.me,DIRECT", "DOMAIN,connectivitycheck.gstatic.com,\(finalPolicy)"], at: 0)
        o["rules"] = rules
        if let nd = try? JSONSerialization.data(withJSONObject: o) { try? nd.write(to: url, options: .atomic) }
        r.note("real fixture: prepended 2 test rules (localtest.me → DIRECT, connectivitycheck.gstatic.com → \(proxyGroup != nil ? "proxy group" : "final policy"))")
    }

    private func dumpStartupLog() {
        guard let text = try? String(contentsOf: StartupLog.url, encoding: .utf8) else { return }
        let lines = text.split(separator: "\n").suffix(300).map { r.redact(String($0)) }
        try? lines.joined(separator: "\n").write(to: E2EReport.outDir.appendingPathComponent("startup-log.redacted.txt"), atomically: true, encoding: .utf8)
        let core = NativeLogRing.shared.since(0).lines.suffix(300).map { r.redact($0.payload) }
        try? core.joined(separator: "\n").write(to: E2EReport.outDir.appendingPathComponent("core-log.redacted.txt"), atomically: true, encoding: .utf8)
    }
}
