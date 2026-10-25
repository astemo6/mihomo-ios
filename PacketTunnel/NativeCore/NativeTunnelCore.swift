import Foundation
import NetworkExtension

/// feat/native-core-eval: everything the tunnel used to ask the Go core for (Libmihomo*), served by NativeCore.
/// The PacketTunnel target does not link Libmihomo any more; the app writes the runtime config
/// (bridge/nativeprep.go PrepareNativeRuntime) and the tunnel only reads it.
final class NativeTunnelCore {
    static let shared = NativeTunnelCore()

    static let version = "native-core 0.1 (Swift/lwIP)"

    private let lock = NSLock()
    // Gap D3: read from the provider, the message handler, the stats samplers and the controller — under `lock`.
    private var _engine: NativeCoreEngine?
    private var _plane: NCDataPlane?
    private var _controller: NCController?
    private var _localProxy: NCLocalProxy?
    var engine: NativeCoreEngine? { lock.lock(); defer { lock.unlock() }; return _engine }
    var plane: NCDataPlane? { lock.lock(); defer { lock.unlock() }; return _plane }
    var controller: NCController? { lock.lock(); defer { lock.unlock() }; return _controller }
    var localProxy: NCLocalProxy? { lock.lock(); defer { lock.unlock() }; return _localProxy }
    private var home = ""

    // reload status (bridge/reloadstatus.go shape: running, seq, done, kind, lastError, lastMs, lastDoneAgoMs, runningMs)
    private var reloadRunning = 0
    private var reloadSeq: Int64 = 0
    private var reloadDone: Int64 = 0
    private var reloadKind = ""
    private var reloadLastError = ""
    private var reloadLastMs: Int64 = 0
    private var reloadStarted = Date.distantPast
    private var reloadLastDone: Date?

    // live status (rate from the previous sample)
    private var lastSample: (at: Date, up: Int64, down: Int64, pUp: Int64, pDown: Int64)?

    private(set) var physicalInterface = ""
    private(set) var networkType = ""

    // MARK: lifecycle

    // rv2-life (#8 / #9): start / stop / reload are serialized by `lifecycle` (held for the whole step, never while
    // `lock` is held). `generation` is bumped by every start and stop under its own tiny lock, so a reload that
    // began before a stop (or a newer start) sees it changed and aborts instead of reviving a stopped core
    // (engine.isRunning, health check, NativeTaskRunner). `genLock` is never held while taking another lock: the
    // engine checks the token while holding its state lock, and stop() bumps it before waiting for `lifecycle`.
    private let lifecycle = NSLock()
    private let genLock = NSLock()
    private var generation: UInt64 = 0
    private func bumpGeneration() -> UInt64 { genLock.lock(); defer { genLock.unlock() }; generation &+= 1; return generation }
    private func isCurrent(_ g: UInt64) -> Bool { genLock.lock(); defer { genLock.unlock() }; return generation == g }

    /// Loads the config and brings the data plane (and controller) up. Throws a user-facing error.
    /// `mixedPort` > 0 also starts the local mixed proxy (gap D1: 仅代理 / VPN 混合) on 127.0.0.1:mixedPort;
    /// `requireMixedPort` (仅代理, where it is the only way in) turns a listener failure into a start failure.
    /// rv2-life #9: idempotent — a core that is already up is stopped completely first (lwIP timers, listeners,
    /// health check, task runner), so two data planes / controllers never coexist.
    func start(home: String, flow: NEPacketTunnelFlow, mtu: Int, controllerPort: Int, secret: String,
               mixedPort: Int = 0, requireMixedPort: Bool = false) throws {
        _ = bumpGeneration() // an in-flight reload of the old core aborts
        lifecycle.lock()
        defer { lifecycle.unlock() }
        lock.lock()
        let alreadyUp = _plane != nil || _engine != nil
        lock.unlock()
        if alreadyUp {
            StartupLog.write("native core start: a previous core is still up, stopping it first")
            stopLocked()
        }
        let gen = bumpGeneration()
        let engine = NativeCoreEngine()
        if let msg = engine.load(home: home) {
            engine.stop()
            throw PacketTunnelProvider.error("内核配置加载失败：\(msg)")
        }
        let plane = NCDataPlane(engine: engine, flow: flow, mtu: UInt16(clamping: mtu))
        do {
            try plane.start()
        } catch {
            engine.stop()
            throw PacketTunnelProvider.error("内核数据面启动失败：\(error.localizedDescription)")
        }
        var localProxy: NCLocalProxy?
        if mixedPort > 0 {
            let lp = NCLocalProxy(engine: engine, port: mixedPort, stats: plane.stats)
            if let why = lp.start() {
                StartupLog.write("local proxy: 127.0.0.1:\(mixedPort) not listening: \(why)")
                if requireMixedPort {
                    plane.stop()
                    engine.stop()
                    throw PacketTunnelProvider.error("本地代理端口 \(mixedPort) 无法监听：\(why)。请在 更多 → 连接方式 换一个端口")
                }
            } else {
                StartupLog.write("local proxy: HTTP / HTTPS CONNECT / SOCKS5 on 127.0.0.1:\(mixedPort)")
                plane.localProxy = lp
                localProxy = lp
            }
        }
        var controller: NCController?
        if controllerPort > 0 {
            let c = NCController(engine: engine, plane: plane, port: controllerPort, secret: secret)
            // rv2-life: a listen failure is logged + written to nativecore-controller.json (NCController.start);
            // the tunnel keeps running (the data plane does not need it) but no longer pretends the API is up.
            if c.start(home: home) {
                controller = c
            } else {
                c.stop()
            }
        }
        lock.lock()
        self.home = home
        _engine = engine
        _plane = plane
        _controller = controller
        _localProxy = localProxy
        lock.unlock()
        NativeCoreEngine.active = engine
        loadRewriteSnapshot(home: home, engine: engine)
        StartupLog.write("native core up (gen \(gen)): \(engine.statsLine)")
        NCMemorySampler.sample("start")
        logSupport(engine)
    }

    func stop() {
        _ = bumpGeneration() // cancels an in-flight reload (it re-checks before committing anything)
        lifecycle.lock()
        defer { lifecycle.unlock() }
        stopLocked()
    }

    /// Caller holds `lifecycle`.
    private func stopLocked() {
        lock.lock()
        let (c, lp, p, e) = (_controller, _localProxy, _plane, _engine)
        _controller = nil; _localProxy = nil; _plane = nil; _engine = nil
        lastSample = nil
        lock.unlock()
        c?.stop()
        lp?.stop()
        p?.stop()
        e?.stop()
        NativeCoreEngine.active = nil
        NativeTaskRunner.shared.stop()
        logRewriteSkips()
        NCPersistentStore.shared.flush() // $persistentStore writes still waiting for their coalesced flush
    }

    /// Re-reads the config the app just prepared (TunnelMessage.reload / .reloadHot). nil = applied.
    /// rv2-life #8 / M: the slow part (config parse, rule-set cache, geo databases) runs off the lwIP queue and off
    /// the engine lock (NativeCoreEngine.load prepares first, then swaps the parsed state in one short locked step),
    /// so established flows keep moving and new flows wait only for the swap. A stop() or a newer start() during
    /// the reload bumps the generation: the engine refuses to commit, and the rewrite / task reload is skipped.
    func reload(hot: Bool) -> String? {
        genLock.lock(); let gen = generation; genLock.unlock()
        lock.lock()
        reloadRunning += 1
        reloadSeq += 1
        reloadKind = hot ? "hot" : "full"
        reloadStarted = Date()
        let (engine, plane, home) = (_engine, _plane, self.home)
        lock.unlock()
        if engine != nil { NCMemorySampler.sample("reload-pre") }
        var err: String?
        if let engine, plane != nil {
            err = engine.load(home: home, isCurrent: { [weak self] in self?.isCurrent(gen) ?? false })
            if err == nil {
                // Commit the side effects (scripts, tasks, rewrite) only while this core is still the live one;
                // `lifecycle` keeps a concurrent stop() from interleaving with them.
                lifecycle.lock()
                lock.lock(); let live = _engine === engine; lock.unlock()
                if live && isCurrent(gen) {
                    loadRewriteSnapshot(home: home, engine: engine)
                    StartupLog.write("native core reloaded (\(hot ? "hot" : "full")): \(engine.statsLine)")
                    logSupport(engine)
                    NCMemorySampler.sample("reload-post")
                } else {
                    err = "内核已停止或已重启，本次重载已取消"
                }
                lifecycle.unlock()
            }
        } else {
            err = "内核未运行"
        }
        lock.lock()
        reloadRunning -= 1
        reloadDone += 1
        reloadLastError = err ?? ""
        reloadLastMs = Int64(Date().timeIntervalSince(reloadStarted) * 1000)
        reloadLastDone = Date()
        lock.unlock()
        return err
    }

    /// The app's rewrite / MitM snapshot (bridge/mitm ExportRewriteSnapshot); .conf profiles carry their own.
    /// gap C5: rules the native rewrite engine skipped (Go-free: they used to make the whole request pass through)
    private func logRewriteSkips() {
        let sk = NativeRewriteEngine.skipStats()
        guard !sk.isEmpty else { return }
        StartupLog.write("rewrite rules skipped natively: " + sk.sorted { $0.value > $1.value }.prefix(12).map { "\($0.key) ×\($0.value)" }.joined(separator: ", "))
    }

    private func loadRewriteSnapshot(home: String, engine: NativeCoreEngine) {
        logRewriteSkips()
        // Scripts: the prelude once per process, the app's script manifest (code files + run setup) every load.
        StartupLog.write("native scripts: " + NativeScriptHost.shared.load(home: home))
        // gap C3: cron / event / generic tasks and panels from the same manifest
        StartupLog.write("native tasks: " + NativeTaskRunner.shared.load(home: home))
        let url = URL(fileURLWithPath: home).appendingPathComponent("nativecore-rewrite.json")
        if let text = try? String(contentsOf: url, encoding: .utf8), let snap = RWSnapshot.decode(text) {
            NativeRewriteSnapshotSource.shared.setSnapshot(snap, json: text)
            NativeRewriteEngine.load(snap)
            StartupLog.write("native rewrite snapshot: \(snap.rules?.count ?? 0) rules, \(snap.inc?.count ?? 0) MitM hosts, on \(snap.on)")
        } else if let canonical = engine.loadedCanonicalConfig {
            let snap = canonical.buildRewriteSnapshot()
            NativeRewriteSnapshotSource.shared.setSnapshot(snap)
            NativeRewriteEngine.load(snap)
        } else {
            let empty = RWSnapshot(version: RWSnapshot.supportedVersion, gen: 0, on: false, capture: false)
            NativeRewriteEngine.load(empty)
        }
    }

    private func logSupport(_ engine: NativeCoreEngine) {
        let lines = engine.supportReport
        guard !lines.isEmpty else { return }
        StartupLog.write("native core: \(lines.count) item(s) not supported yet:")
        for l in lines.prefix(30) { StartupLog.write("  " + l) }
        if lines.count > 30 { StartupLog.write("  … \(lines.count - 30) more") }
        let url = URL(fileURLWithPath: home).appendingPathComponent("nativecore-unsupported.json")
        if let data = try? JSONSerialization.data(withJSONObject: lines) { try? data.write(to: url, options: .atomic) }
    }

    // MARK: Libmihomo replacements

    func reloadStatus() -> String {
        lock.lock(); defer { lock.unlock() }
        var out: [String: Any] = [
            "running": reloadRunning > 0, "seq": reloadSeq, "done": reloadDone, "kind": reloadKind,
            "lastError": reloadLastError, "lastMs": reloadLastMs, "lastDoneAgoMs": -1, "runningMs": 0,
        ]
        if reloadRunning > 0 { out["runningMs"] = Int64(Date().timeIntervalSince(reloadStarted) * 1000) }
        if let d = reloadLastDone { out["lastDoneAgoMs"] = Int64(Date().timeIntervalSince(d) * 1000) }
        return Self.json(out)
    }

    /// "up,down" totals since start (LibmihomoTrafficTotals).
    func trafficTotals() -> String {
        guard let s = plane?.stats.snapshot() else { return "0,0" }
        return "\(s.up),\(s.down)"
    }

    /// LibmihomoLiveStatus: "up\tdown\ttotalUp\ttotalDown\tnode\tproxyUp\tproxyDown\tproxyUpTotal\tproxyDownTotal".
    func liveStatus() -> String {
        guard let s = plane?.stats.snapshot() else { return "" }
        let now = Date()
        lock.lock()
        let prev = lastSample
        lastSample = (now, s.up, s.down, s.proxyUp, s.proxyDown)
        lock.unlock()
        var up: Int64 = 0, down: Int64 = 0, pUp: Int64 = 0, pDown: Int64 = 0
        if let p = prev {
            let dt = max(now.timeIntervalSince(p.at), 0.5)
            up = Int64(Double(max(0, s.up - p.up)) / dt)
            down = Int64(Double(max(0, s.down - p.down)) / dt)
            pUp = Int64(Double(max(0, s.proxyUp - p.pUp)) / dt)
            pDown = Int64(Double(max(0, s.proxyDown - p.pDown)) / dt)
        }
        return [String(up), String(down), String(s.up), String(s.down), mainNode(),
                String(pUp), String(pDown), String(s.proxyUp), String(s.proxyDown)].joined(separator: "\t")
    }

    /// The node the first group routes to now (the Live Activity's "main node").
    private func mainNode() -> String {
        guard let engine else { return "" }
        return engine.withGroups { cfg, g in Self.mainNode(cfg: cfg, g: g) } ?? ""
    }

    private static func mainNode(cfg: NCConfig, g: NCGroupEngine) -> String {
        let group = cfg.groupMap["GLOBAL"].flatMap { _ in cfg.groups.first { $0.name != "GLOBAL" } } ?? cfg.groups.first
        guard var cur = group else { return "" }
        for _ in 0..<8 {
            guard let m = g.currentMember(of: cur) else { return "" }
            guard let next = cfg.groupMap[m] else { return m }
            cur = next
        }
        return ""
    }

    /// LibmihomoMemorySnapshot's shape (TunnelMemorySnapshot in the app); Go fields are absent.
    func memorySnapshot(footprint: UInt64, peak: UInt64, available: Int) -> [String: Any] {
        let conns = plane?.stats.snapshot().connections.count ?? 0
        return [
            "footprint": footprint, "peak": peak, "available": available, "connections": conns,
            "at": Int64(Date().timeIntervalSince1970),
            "native": ["on": true, "sessions": NativeMitmRuntime.liveSessions],
        ]
    }

    /// LibmihomoSetPhysicalInterface: remembered for 诊断. Native sockets are NWConnections, which iOS keeps off the
    /// tunnel for the provider's own process; with includeAllNetworks this is still unverified on device.
    func setPhysicalInterface(_ name: String) {
        lock.lock(); physicalInterface = name; lock.unlock()
    }

    /// LibmihomoSetNetworkState: the SSID feeds SUBNET groups (NCGroupEngine.ssidProvider reads the app group).
    func setNetworkState(type: String, ssid: String?) -> String {
        lock.lock(); networkType = type; lock.unlock()
        let d = UserDefaults(suiteName: AppShared.appGroup)
        if let ssid, !ssid.isEmpty { d?.set(ssid, forKey: "nativeCoreSSID") } else { d?.removeObject(forKey: "nativeCoreSSID") }
        return ""
    }

    /// LibmihomoFlushDNSCache: NativeCore keeps no resolver cache beyond the fake-IP pool (which must survive).
    func flushDNSCache() {}

    /// LibmihomoNotifyNetworkChanged: infoJSON becomes $network; every enabled network-changed event script runs
    /// (gap C3, NativeTaskRunner). Returns how many were started.
    func notifyNetworkChanged(_ json: String) -> Int {
        let info = ((try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]) ?? [:]
        return NativeTaskRunner.shared.networkChanged(info)
    }

    /// LibmihomoShedConnections: close the oldest `percent` % of connections.
    func shedConnections(percent: Int) -> Int {
        guard let plane else { return 0 }
        let conns = plane.stats.snapshot().connections
        let n = conns.count * max(0, min(100, percent)) / 100
        guard n > 0 else { return 0 }
        let oldest = conns.sorted { ($0["start"] as? String ?? "") < ($1["start"] as? String ?? "") }.prefix(n)
        for c in oldest { if let id = c["id"] as? String { plane.requestCloseConnection(id: id) } }
        return n
    }

    static func json(_ o: Any) -> String {
        (try? JSONSerialization.data(withJSONObject: o)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }
}
