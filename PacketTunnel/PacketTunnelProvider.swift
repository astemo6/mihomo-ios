import Foundation
import NetworkExtension
import Libmihomo
import UserNotifications

/// Posts local notifications for scripts ($notification.post / $notify).
final class ScriptNotifier: NSObject, LibmihomoNotifierProtocol {
    func notify(_ payload: String?) {
        guard let data = payload?.data(using: .utf8),
              let n = try? JSONDecoder().decode(ScriptNotification.self, from: data) else { return }
        let content = UNMutableNotificationContent()
        content.title = n.title ?? ""
        content.subtitle = n.subtitle ?? ""
        content.body = n.body ?? ""
        content.sound = .default
        if let u = n.url, !u.isEmpty { content.userInfo = ["url": u] }
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let notifier = ScriptNotifier()
    private let memoryProbe = ExtensionMemoryProbe()
    private var bridge: PacketFlowBridge?
    private var memoryGuard: MemoryGuard?
    private var traffic: TrafficRecorder?
    private var liveStats: LiveStatsSampler?
    private var network: NetworkWatcher?
    /// v0.19.1: set by stopTunnel. A stop that arrives while the core is still starting (user taps 断开 during
    /// 连接中…) must not be followed by the start path launching MemoryGuard / TrafficRecorder / NetworkWatcher
    /// timers in an extension that is going away; the late start stops the core it brought up instead.
    private let stopLock = NSLock()
    private var _stopped = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        TunnelErrorLog.clear()
        StartupLog.begin("startTunnel")
        LibmihomoSetStageLog(StartupLog.url.path, TimeZone.current.secondsFromGMT())
        LibmihomoSetTimeZone(TimeZone.current.identifier, TimeZone.current.secondsFromGMT())
        StartupLog.write("startTunnel called, \(ProcessMemory.summary())")
        // Exactly one completion, whichever comes first: core result, error, or the watchdog.
        let lock = NSLock()
        var finished = false
        let completionHandler: (Error?) -> Void = { err in
            lock.lock()
            if finished { lock.unlock(); return }
            finished = true
            lock.unlock()
            if let err {
                TunnelErrorLog.write(err.localizedDescription)
                StartupLog.write("FAILED: \(err.localizedDescription)")
            } else {
                StartupLog.write("startTunnel completed OK, \(ProcessMemory.summary())")
            }
            completionHandler(err)
        }
        // Review 6 R6A-1: true once the start was completed (only the watchdog can have done that by the time the
        // core start returns OK), so a late core start stops the core instead of leaving it running.
        let startTimedOut: () -> Bool = {
            lock.lock(); defer { lock.unlock() }
            return finished
        }
        guard AppShared.containerOK else {
            completionHandler(Self.error("App Group 不可用（\(AppShared.appGroup)）：重签名的描述文件需要包含 App Groups，且主程序和扩展使用同一个组"))
            return
        }
        guard let profile = AppShared.activeProfileURL else {
            completionHandler(Self.error("没有可用的配置，请先在「配置」中添加并选择一个配置"))
            return
        }
        StartupLog.write("app group \(AppShared.appGroup) (\(AppShared.appGroupSource)), profile \(profile.lastPathComponent)")
        GeoBootstrap.install { StartupLog.write($0) }
        var overrides = CoreOverrides.load()
        // v0.8 IPv6 自动: decided once per start from the physical network; Go gets the same answer.
        overrides.ipv6 = overrides.resolvedIPv6()
        LibmihomoSetNetworkIPv6(overrides.ipv6)
        StartupLog.write("ipv6 mode \(overrides.ipv6Mode) → \(overrides.ipv6 ? "on" : "off"), ip preference \(overrides.ipPreference)")
        LibmihomoSetNotifier(notifier)
        LibmihomoSetMemoryLimit(Int32(overrides.memoryLimitMB))
        LibmihomoSetMemoryProbe(memoryProbe)
        let proxyOnly = overrides.isProxyOnly
        // 接管所有网络流量: with includeAllNetworks iOS scopes this extension's own unbound sockets into the tunnel
        // too, so the core's proxy / DIRECT / DNS sockets must be bound to the physical interface (Go side,
        // physiface.go). The VPN configuration's value is the one iOS enforces (overrides.json is logged next to it).
        let includeAll = protocolConfiguration.includeAllNetworks
        LibmihomoSetBindPhysicalInterface(includeAll)
        StartupLog.write("tunnel scope: includeAllNetworks \(includeAll ? "on" : "off") (setting \(overrides.includeAllNetworks ? "on" : "off")), excludeLocalNetworks \(protocolConfiguration.excludeLocalNetworks)\(includeAll ? ", " + LibmihomoPhysicalInterfaceStatus() : "")")
        StartupLog.write("mode \(proxyOnly ? "proxy-only (NEProxySettings)" : overrides.isMixed ? "mix (tun + system proxy)" : "tun (NEPacketTunnelFlow bridge)"), quic \(overrides.blockQUIC), routes +\(overrides.includedRoutes.count)/-\(overrides.excludedRoutes.count), mtu \(overrides.tunMTU), GOMEMLIMIT \(overrides.memoryLimitMB) MB\(overrides.safeMode ? ", SAFE MODE" : "")")
        if let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
            StartupLog.write("tunnel \(v) (\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?")), \(LibmihomoVersion())")
        }

        // Watchdog: never leave the system at "连接中…" (Go has its own 20 s bound; this covers anything else).
        DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
            completionHandler(Self.error("启动超时（30 秒）。请到 更多 → 诊断 查看启动日志"))
        }

        StartupLog.write("applying tunnel network settings")
        setTunnelNetworkSettings(Self.networkSettings(overrides)) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(Self.error("设置隧道网络失败：\(error.localizedDescription)"))
                return
            }
            StartupLog.write("settings applied")
            var fd: Int32 = 0
            if !proxyOnly {
                let b = PacketFlowBridge(flow: self.packetFlow)
                b.onFailure = { [weak self] why in
                    self?.cancelTunnelWithError(Self.error("数据包桥接失败：\(why)"))
                }
                do {
                    fd = try b.start()
                } catch {
                    completionHandler(Self.error("无法创建数据包桥接：\(error.localizedDescription)"))
                    return
                }
                self.stopLock.lock(); self.bridge = b; self.stopLock.unlock()
                StartupLog.write("packet-flow bridge up, core fd \(fd)")
            }
            // Off the NetworkExtension callback queue: LibmihomoStart returns within 20 s at most.
            DispatchQueue.global(qos: .userInitiated).async {
                StartupLog.write("core start begin")
                var err: NSError?
                LibmihomoStart(AppShared.homeURL.path, profile.path, fd, &err)
                StartupLog.write("core start returned\(err.map { ": " + $0.localizedDescription } ?? " OK"), \(ProcessMemory.summary()), \(LibmihomoMemoryStats())")
                if let err {
                    self.takeBridge()?.stop()
                    LibmihomoDumpDiagnostics()
                    completionHandler(Self.error("内核启动失败：\(err.localizedDescription)"))
                    return
                }
                // Review 6 R6A-1: publish the helpers under stopLock, so a stopTunnel either sees them (and stops
                // them) or has already set `stopped` (and nothing is started). The watchdog may also have failed
                // the start meanwhile: then the core must not keep running in an extension iOS has written off.
                let timedOut = startTimedOut()
                let started: Bool = {
                    self.stopLock.lock(); defer { self.stopLock.unlock() }
                    guard !self._stopped, !timedOut else { return false }
                    let guardian = MemoryGuard()
                    guardian.start()
                    self.memoryGuard = guardian
                    let rec = TrafficRecorder()
                    rec.start()
                    self.traffic = rec
                    let ls = LiveStatsSampler()
                    ls.start()
                    self.liveStats = ls
                    let nw = NetworkWatcher()
                    nw.start()
                    self.network = nw
                    return true
                }()
                guard started else {
                    StartupLog.write(timedOut ? "core start returned after the start watchdog: stopping the core again"
                                              : "stopTunnel arrived during core start: stopping the core again")
                    LibmihomoStop()
                    self.takeBridge()?.stop()
                    completionHandler(Self.error("已断开"))
                    return
                }
                completionHandler(nil)
                DispatchQueue.global().asyncAfter(deadline: .now() + 15) { [weak self] in
                    StartupLog.write("+15 s: \(ProcessMemory.summary()), \(LibmihomoMemoryStats()), bridge \(self?.currentBridge?.stats ?? "-"), \(LibmihomoPhysicalInterfaceStatus())")
                }
            }
        }
    }

    /// 连接方式 (v0.7): tun = routes through the packet flow, DNS to the core; mix = the same plus a
    /// system HTTP/HTTPS proxy pointing at the core's local mixed port; proxy = only that system proxy, no
    /// routes and no DNS. Routes and the proxy skip list come from 更多 → 连接方式 (defaults = v0.6.1 values).
    static func networkSettings(_ o: CoreOverrides) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        if o.isProxyOnly {
            ipv4.includedRoutes = []
            settings.ipv4Settings = ipv4
            settings.proxySettings = systemProxy(o)
            return settings
        }
        settings.mtu = NSNumber(value: o.tunMTU)
        let inc = o.includedRoutes.compactMap(RouteSpec.init)
        let exc = o.excludedRoutes.compactMap(RouteSpec.init)
        let inc4 = inc.filter { !$0.isV6 }.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
        ipv4.includedRoutes = inc4.isEmpty ? [NEIPv4Route.default()] : inc4
        ipv4.excludedRoutes = exc.filter { !$0.isV6 }.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
        settings.ipv4Settings = ipv4
        if o.ipv6 {
            let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
            let inc6 = inc.filter(\.isV6).map { NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix)) }
            ipv6.includedRoutes = inc6.isEmpty ? [NEIPv6Route.default()] : inc6
            ipv6.excludedRoutes = exc.filter(\.isV6).map { NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix)) }
            settings.ipv6Settings = ipv6
        }
        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        if o.isMixed { settings.proxySettings = systemProxy(o) }
        return settings
    }

    private static func systemProxy(_ o: CoreOverrides) -> NEProxySettings {
        let proxy = NEProxySettings()
        proxy.httpEnabled = true
        proxy.httpsEnabled = true
        proxy.httpServer = NEProxyServer(address: "127.0.0.1", port: o.mixedPort)
        proxy.httpsServer = NEProxyServer(address: "127.0.0.1", port: o.mixedPort)
        proxy.excludeSimpleHostnames = true
        let skip = o.skipProxy.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        proxy.exceptionList = skip.isEmpty ? CoreOverrides.defaultSkipProxy : skip
        return proxy
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let why = TunnelStopReason.describe(reason.rawValue)
        StartupLog.write("stopTunnel reason=\(reason.rawValue)（\(why)）, \(ProcessMemory.summary()), bridge \(currentBridge?.stats ?? "-")")
        TunnelStopReason.record(reason.rawValue)
        // Review 6 R6A-1: take the helpers under the same lock the start path publishes them with.
        stopLock.lock()
        _stopped = true
        let (traffic, liveStats, network, memoryGuard) = (self.traffic, self.liveStats, self.network, self.memoryGuard)
        self.liveStats = nil
        self.network = nil
        self.memoryGuard = nil
        stopLock.unlock()
        traffic?.stop() // flushes the last delta
        liveStats?.stop()
        network?.stop()
        memoryGuard?.stop()
        LibmihomoStop()
        LibmihomoDumpDiagnostics()
        takeBridge()?.stop()
        completionHandler()
    }

    /// The bridge, read under stopLock (written by the start path on another queue).
    private var currentBridge: PacketFlowBridge? {
        stopLock.lock(); defer { stopLock.unlock() }
        return bridge
    }

    /// Removes and returns the bridge exactly once (start-failure path and stopTunnel can both get here).
    private func takeBridge() -> PacketFlowBridge? {
        stopLock.lock(); defer { stopLock.unlock() }
        let b = bridge
        bridge = nil
        return b
    }

    /// The traffic recorder, read under stopLock (handleAppMessage / sleep run on the NE queue).
    private var currentTraffic: TrafficRecorder? {
        stopLock.lock(); defer { stopLock.unlock() }
        return traffic
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        switch TunnelMessage(rawValue: cmd) {
        case .reload:
            guard let profile = AppShared.activeProfileURL else {
                completionHandler?("没有可用的配置".data(using: .utf8))
                return
            }
            // LibmihomoReload re-parses the profile (YAML + provider downloads, seconds).
            // Never block the NE callback thread on it: handleAppMessage must stay responsive,
            // otherwise an in-flight reload delays stopTunnel's completion and iOS may kill
            // the extension. The completionHandler may be called asynchronously.
            // Read `network` here, on the provider's queue: stopTunnel clears it there too (v0.19.1, was read
            // from the background queue while stopTunnel could be writing it).
            stopLock.lock(); let nw = network; stopLock.unlock()
            DispatchQueue.global(qos: .userInitiated).async {
                var err: NSError?
                LibmihomoReload(profile.path, &err)
                nw?.refreshSettings() // settings saved by the app before it asked for the reload
                // Review 6 R6A-3: success is a non-empty "ok" (an empty reply can reach the app as nil, which the app
                // now reads as a timeout).
                completionHandler?(Data((err?.localizedDescription ?? TunnelMessage.reloadOK).utf8))
            }
        case .directIP:
            // Sockets opened by the provider itself are not routed through its own tunnel,
            // so this request reveals the real (direct) egress IP.
            Task {
                let info = await IPInfoFetcher.fetch(timeout: 5)
                completionHandler?(info.flatMap { try? JSONEncoder().encode($0) })
            }
        case .freeMemory:
            LibmihomoFreeMemory()
            completionHandler?(nil)
        case .version:
            completionHandler?(LibmihomoVersion().data(using: .utf8))
        case .flushStats:
            currentTraffic?.sampleNow()
            LibmihomoFlushRuleHits()
            completionHandler?(nil)
        case .dumpDiagnostics:
            LibmihomoRecordMemorySample(Int64(ProcessMemory.footprintBytes()), Int64(ProcessMemory.availableBytes()))
            LibmihomoDumpDiagnostics()
            completionHandler?("\(ProcessMemory.summary()), \(LibmihomoMemoryStats())".data(using: .utf8))
        case .memoryStats:
            completionHandler?(Data(MemorySnapshotWriter.snapshot().utf8))
        case .applyNetworkPolicy:
            let n = LibmihomoApplyNetworkPolicy()
            completionHandler?("\(n)".data(using: .utf8))
        case .none:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        currentTraffic?.sample()
        LibmihomoFlushRuleHits()
        LibmihomoFreeMemory()
        completionHandler()
    }

    override func wake() {}

    static func error(_ msg: String) -> NSError {
        NSError(domain: "Mihomo.PacketTunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: msg])
    }
}

/// v0.18: footprint / headroom for the Go side (Tailscale start guard).
final class ExtensionMemoryProbe: NSObject, LibmihomoMemoryProbeProtocol {
    func footprint() -> Int64 { Int64(ProcessMemory.footprintBytes()) }
    func available() -> Int64 { Int64(ProcessMemory.availableBytes()) }
}

/// v0.18 隧道内存: one snapshot = Swift-measured footprint / peak / available + Go numbers + Tailscale status.
enum MemorySnapshotWriter {
    private static var trackedPeak: UInt64 = 0
    private static let lock = NSLock()

    static func snapshot(fp: UInt64 = ProcessMemory.footprintBytes(), avail: Int = ProcessMemory.availableBytes()) -> String {
        lock.lock()
        trackedPeak = max(trackedPeak, fp)
        let peak = max(trackedPeak, ProcessMemory.peakBytes())
        lock.unlock()
        let json = LibmihomoMemorySnapshot(Int64(fp), Int64(peak), Int64(avail))
        TunnelMemoryFile.write(json)
        return json
    }

    static func save(fp: UInt64, avail: Int) { _ = snapshot(fp: fp, avail: avail) }
}

/// Keeps the extension under the ~50 MB jetsam limit. v0.6.1, after the first device test: iOS sends
/// "critical" pressure events constantly once the footprint is near 40 MB, and closing every connection
/// on each event broke browsing. Now the footprint decides, with hysteresis:
///   < 44 MB            pressure events are only logged (rate limited)
///   ≥ 40 MB (timer) / ≥ 44 MB (event)   return memory to the OS first (FreeOSMemory)
///   ≥ 47 MB or < 3 MB available         close the oldest 25 % of connections (50 % below 2 MB available),
///                                       then not again until the footprint fell below 42 MB or 30 s passed.
final class MemoryGuard {
    private let queue = DispatchQueue(label: "mihomo.memoryguard", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var pressure: DispatchSourceMemoryPressure?
    private var interval = 10
    private var lastShed = Date.distantPast
    private var lastFree = Date.distantPast
    private var lastPressureLog = Date.distantPast
    private var armed = true
    /// Review 6 R6A-2: set on `queue` by stop(); a tick already running must not schedule a new timer.
    private var stopped = false

    private let freeAtBytes: UInt64 = 40 << 20
    private let pressureFreeAtBytes: UInt64 = 44 << 20
    private let shedAtBytes: UInt64 = 47 << 20
    private let rearmBelowBytes: UInt64 = 42 << 20
    private let shedAvailableBelow = 3 << 20

    func start() {
        queue.async { [self] in
            guard !stopped else { return }
            let p = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
            p.setEventHandler { [weak self] in
                guard let self, !self.stopped, let ev = self.pressure?.data else { return }
                self.onPressure(critical: ev.contains(.critical))
            }
            p.resume()
            pressure = p
            schedule(10)
        }
    }

    /// Review 6 R6A-2: runs on the guard's own queue (timer / pressure source are only touched there), so a tick
    /// in flight can no longer re-create the timer after the tunnel stopped.
    func stop() {
        queue.sync {
            stopped = true
            timer?.cancel()
            timer = nil
            pressure?.cancel()
            pressure = nil
        }
    }

    private func onPressure(critical: Bool) {
        let fp = ProcessMemory.footprintBytes()
        if Date().timeIntervalSince(lastPressureLog) > 60 {
            lastPressureLog = Date()
            StartupLog.write("memory pressure \(critical ? "critical" : "warning") (logged at most once a minute): \(ProcessMemory.summary())")
        }
        evaluate(fp: fp, avail: ProcessMemory.availableBytes(), freeAt: pressureFreeAtBytes, why: "memory pressure")
    }

    private func schedule(_ seconds: Int) {
        guard !stopped else { return }
        interval = seconds
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(seconds), repeating: .seconds(seconds), leeway: .seconds(max(1, seconds / 4)))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func tick() {
        guard !stopped else { return }
        let fp = ProcessMemory.footprintBytes()
        let avail = ProcessMemory.availableBytes()
        LibmihomoRecordMemorySample(Int64(fp), Int64(avail))
        MemorySnapshotWriter.save(fp: fp, avail: avail)
        evaluate(fp: fp, avail: avail, freeAt: freeAtBytes, why: "timer")
        // Sample faster while close to the limit, slowly otherwise (battery).
        let want = fp >= freeAtBytes ? 2 : 10
        if want != interval { schedule(want) }
    }

    private func evaluate(fp: UInt64, avail: Int, freeAt: UInt64, why: String) {
        if fp < rearmBelowBytes || Date().timeIntervalSince(lastShed) > 30 { armed = true }
        let lowAvail = avail >= 0 && avail < shedAvailableBelow
        if fp >= freeAt || fp >= shedAtBytes || lowAvail {
            if Date().timeIntervalSince(lastFree) > 3 {
                lastFree = Date()
                LibmihomoFreeMemory()
            }
        }
        guard (fp >= shedAtBytes || lowAvail) && armed else { return }
        // Re-check after returning memory: often that alone is enough.
        let fp2 = ProcessMemory.footprintBytes()
        let avail2 = ProcessMemory.availableBytes()
        let low2 = avail2 >= 0 && avail2 < shedAvailableBelow
        guard fp2 >= shedAtBytes || low2 else { return }
        armed = false
        lastShed = Date()
        let percent = (avail2 >= 0 && avail2 < 2 << 20) ? 50 : 25
        let n = LibmihomoShedConnections(percent)
        LibmihomoFreeMemory()
        StartupLog.write("memory guard (\(why)): closed \(n) oldest connections (\(percent) %) at footprint \(fp2 >> 20) MB → \(ProcessMemory.summary())")
    }
}

/// v0.11: speed / totals / main node for the Live Activity, every 10 s and only while the app's
/// 实时活动 switch is on (one Go call + one small App Group write; nothing allocated otherwise).
final class LiveStatsSampler {
    private let queue = DispatchQueue(label: "mihomo.livestats", qos: .utility)
    private var timer: DispatchSourceTimer?

    func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(5), repeating: .seconds(10), leeway: .seconds(3))
        t.setEventHandler {
            guard LiveStats.wanted else { return }
            LiveStats(status: LibmihomoLiveStatus()).save()
        }
        t.resume()
        timer = t
    }

    func stop() {
        timer?.cancel()
        timer = nil
        if LiveStats.wanted { LiveStats().save() } // disconnected: no stale speed
    }
}

/// Adds the core's traffic counters to today's bucket in TrafficHistory every two minutes.
final class TrafficRecorder {
    private let queue = DispatchQueue(label: "mihomo.traffic", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var lastUp: Int64 = 0
    private var lastDown: Int64 = 0

    func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(120), repeating: .seconds(120), leeway: .seconds(30))
        t.setEventHandler { [weak self] in self?.sampleOnQueue() }
        t.resume()
        timer = t
    }

    func stop() {
        timer?.cancel()
        timer = nil
        queue.sync { sampleOnQueue() }
    }

    func sample() { queue.async { [weak self] in self?.sampleOnQueue() } }

    func sampleNow() { queue.sync { sampleOnQueue() } }

    private func sampleOnQueue() {
        let parts = LibmihomoTrafficTotals().split(separator: ",").compactMap { Int64($0) }
        guard parts.count == 2 else { return }
        let up = parts[0], down = parts[1]
        // Counters restart with the core; a smaller value means a restart, count from zero.
        let du = up >= lastUp ? up - lastUp : up
        let dd = down >= lastDown ? down - lastDown : down
        lastUp = up
        lastDown = down
        TrafficHistory.add(up: du, down: dd, iface: NetworkWatcher.currentType)
    }
}
