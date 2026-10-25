import Foundation
import NetworkExtension

/// feat/native-core-eval: everything the tunnel used to ask the Go core for (Libmihomo*), served by NativeCore.
/// The PacketTunnel target does not link Libmihomo any more (TERN_NO_GO); the app writes the runtime config
/// (bridge/nativeprep.go PrepareNativeRuntime) and the tunnel only reads it.
final class NativeTunnelCore {
    static let shared = NativeTunnelCore()

    static let version = "native-core 0.1 (Swift/lwIP)"

    private let lock = NSLock()
    // Gap D3: read from the provider, the message handler, the stats samplers and the controller — under `lock`.
    private var _engine: NativeCoreEngine?
    private var _plane: NCDataPlane?
    private var _controller: NCController?
    var engine: NativeCoreEngine? { lock.lock(); defer { lock.unlock() }; return _engine }
    var plane: NCDataPlane? { lock.lock(); defer { lock.unlock() }; return _plane }
    var controller: NCController? { lock.lock(); defer { lock.unlock() }; return _controller }
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

    /// Loads the config and brings the data plane (and controller) up. Throws a user-facing error.
    func start(home: String, flow: NEPacketTunnelFlow, mtu: Int, controllerPort: Int, secret: String) throws {
        let engine = NativeCoreEngine()
        if let msg = engine.load(home: home) {
            throw PacketTunnelProvider.error("内核配置加载失败：\(msg)")
        }
        let plane = NCDataPlane(engine: engine, flow: flow, mtu: UInt16(clamping: mtu))
        do {
            try plane.start()
        } catch {
            engine.stop()
            throw PacketTunnelProvider.error("内核数据面启动失败：\(error.localizedDescription)")
        }
        var controller: NCController?
        if controllerPort > 0 {
            let c = NCController(engine: engine, plane: plane, port: controllerPort, secret: secret)
            c.start()
            controller = c
        }
        lock.lock()
        self.home = home
        _engine = engine
        _plane = plane
        _controller = controller
        lock.unlock()
        NativeCoreEngine.active = engine
        loadRewriteSnapshot(home: home, engine: engine)
        StartupLog.write("native core up: \(engine.statsLine)")
        logSupport(engine)
    }

    func stop() {
        lock.lock()
        let (c, p, e) = (_controller, _plane, _engine)
        _controller = nil; _plane = nil; _engine = nil
        lock.unlock()
        c?.stop()
        p?.stop()
        e?.stop()
        NativeCoreEngine.active = nil
        NCPersistentStore.shared.flush() // $persistentStore writes still waiting for their coalesced flush
    }

    /// Re-reads the config the app just prepared (TunnelMessage.reload / .reloadHot). nil = applied.
    func reload(hot: Bool) -> String? {
        lock.lock()
        reloadRunning += 1
        reloadSeq += 1
        reloadKind = hot ? "hot" : "full"
        reloadStarted = Date()
        let (engine, plane, home) = (_engine, _plane, self.home)
        lock.unlock()
        var err: String?
        if let engine, let plane {
            // On the data plane's queue: the plane reads the engine's rules / groups there.
            err = plane.queue.sync { engine.load(home: home) }
            if err == nil {
                loadRewriteSnapshot(home: home, engine: engine)
                StartupLog.write("native core reloaded (\(hot ? "hot" : "full")): \(engine.statsLine)")
                logSupport(engine)
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
    private func loadRewriteSnapshot(home: String, engine: NativeCoreEngine) {
        // Scripts: the prelude once per process, the app's script manifest (code files + run setup) every load.
        StartupLog.write("native scripts: " + NativeScriptHost.shared.load(home: home))
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

    /// LibmihomoNotifyNetworkChanged: network-changed event scripts are not run by the native core yet.
    func notifyNetworkChanged(_ json: String) -> Int { 0 }

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
