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
    private var bridge: PacketFlowBridge?
    private var memoryGuard: MemoryGuard?
    private var traffic: TrafficRecorder?
    private var network: NetworkWatcher?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        TunnelErrorLog.clear()
        StartupLog.begin("startTunnel")
        LibmihomoSetStageLog(StartupLog.url.path, TimeZone.current.secondsFromGMT())
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
        let overrides = CoreOverrides.load()
        LibmihomoSetNotifier(notifier)
        LibmihomoSetMemoryLimit(Int32(overrides.memoryLimitMB))
        let proxyOnly = overrides.isProxyOnly
        StartupLog.write("mode \(proxyOnly ? "proxy-only (NEProxySettings)" : "tun (NEPacketTunnelFlow bridge)"), mtu \(overrides.tunMTU), GOMEMLIMIT \(overrides.memoryLimitMB) MB")

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
                self.bridge = b
                StartupLog.write("packet-flow bridge up, core fd \(fd)")
            }
            // Off the NetworkExtension callback queue: LibmihomoStart returns within 20 s at most.
            DispatchQueue.global(qos: .userInitiated).async {
                StartupLog.write("core start begin")
                var err: NSError?
                LibmihomoStart(AppShared.homeURL.path, profile.path, fd, &err)
                StartupLog.write("core start returned\(err.map { ": " + $0.localizedDescription } ?? " OK"), \(ProcessMemory.summary()), \(LibmihomoMemoryStats())")
                if let err {
                    self.bridge?.stop()
                    self.bridge = nil
                    completionHandler(Self.error("内核启动失败：\(err.localizedDescription)"))
                    return
                }
                let guardian = MemoryGuard()
                guardian.start()
                self.memoryGuard = guardian
                let rec = TrafficRecorder()
                rec.start()
                self.traffic = rec
                let nw = NetworkWatcher()
                nw.start()
                self.network = nw
                completionHandler(nil)
                DispatchQueue.global().asyncAfter(deadline: .now() + 15) { [weak self] in
                    StartupLog.write("+15 s: \(ProcessMemory.summary()), \(LibmihomoMemoryStats()), bridge \(self?.bridge?.stats ?? "-")")
                }
            }
        }
    }

    /// Tun mode: default route through the packet flow, DNS to the core. Proxy-only mode: no routes,
    /// only an HTTP/HTTPS system proxy pointing at the core's local mixed port.
    static func networkSettings(_ o: CoreOverrides) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        if o.isProxyOnly {
            ipv4.includedRoutes = []
            settings.ipv4Settings = ipv4
            let proxy = NEProxySettings()
            proxy.httpEnabled = true
            proxy.httpsEnabled = true
            proxy.httpServer = NEProxyServer(address: "127.0.0.1", port: o.mixedPort)
            proxy.httpsServer = NEProxyServer(address: "127.0.0.1", port: o.mixedPort)
            proxy.excludeSimpleHostnames = true
            proxy.exceptionList = ["localhost", "*.local", "127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "captive.apple.com"]
            settings.proxySettings = proxy
            return settings
        }
        settings.mtu = NSNumber(value: o.tunMTU)
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
        ]
        settings.ipv4Settings = ipv4
        if o.ipv6 {
            let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }
        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        return settings
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        StartupLog.write("stopTunnel reason=\(reason.rawValue), \(ProcessMemory.summary()), bridge \(bridge?.stats ?? "-")")
        traffic?.stop() // flushes the last delta
        network?.stop()
        network = nil
        memoryGuard?.stop()
        LibmihomoStop()
        bridge?.stop()
        bridge = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        switch TunnelMessage(rawValue: cmd) {
        case .reload:
            guard let profile = AppShared.activeProfileURL else {
                completionHandler?("没有可用的配置".data(using: .utf8))
                return
            }
            var err: NSError?
            LibmihomoReload(profile.path, &err)
            completionHandler?((err?.localizedDescription ?? "").data(using: .utf8))
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
            traffic?.sampleNow()
            completionHandler?(nil)
        case .none:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        traffic?.sample()
        LibmihomoFreeMemory()
        completionHandler()
    }

    override func wake() {}

    static func error(_ msg: String) -> NSError {
        NSError(domain: "Mihomo.PacketTunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: msg])
    }
}

/// Keeps the extension under the ~50 MB jetsam limit (Hako-style): GOMEMLIMIT does the pacing in Go;
/// this watches phys_footprint / os_proc_available_memory and memory-pressure events, returns memory to
/// the OS when it climbs, and closes connections as a last resort before iOS would kill the tunnel.
final class MemoryGuard {
    private let queue = DispatchQueue(label: "mihomo.memoryguard", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var pressure: DispatchSourceMemoryPressure?
    private var interval = 10
    private var lastShed = Date.distantPast

    private let freeAtBytes: UInt64 = 38 << 20
    private let shedAtBytes: UInt64 = 45 << 20
    private let shedAvailableBelow = 5 << 20

    func start() {
        let p = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
        p.setEventHandler { [weak self] in
            guard let self, let ev = self.pressure?.data else { return }
            LibmihomoFreeMemory()
            if ev.contains(.critical) { self.shed(reason: "memory pressure critical") }
            StartupLog.write("memory pressure \(ev.contains(.critical) ? "critical" : "warning"): \(ProcessMemory.summary())")
        }
        p.resume()
        pressure = p
        schedule(10)
    }

    func stop() {
        timer?.cancel()
        timer = nil
        pressure?.cancel()
        pressure = nil
    }

    private func schedule(_ seconds: Int) {
        interval = seconds
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(seconds), repeating: .seconds(seconds), leeway: .seconds(max(1, seconds / 4)))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func tick() {
        let fp = ProcessMemory.footprintBytes()
        let avail = ProcessMemory.availableBytes()
        if fp >= shedAtBytes || (avail >= 0 && avail < shedAvailableBelow) {
            LibmihomoFreeMemory()
            shed(reason: "footprint \(fp >> 20) MB, available \(avail >> 20) MB")
        } else if fp >= freeAtBytes {
            LibmihomoFreeMemory()
        }
        // Sample faster while close to the limit, slowly otherwise (battery).
        let want = fp >= freeAtBytes ? 2 : 10
        if want != interval { schedule(want) }
    }

    private func shed(reason: String) {
        guard Date().timeIntervalSince(lastShed) > 15 else { return }
        lastShed = Date()
        let n = LibmihomoShedConnections()
        LibmihomoFreeMemory()
        StartupLog.write("memory guard: closed \(n) connections (\(reason)) → \(ProcessMemory.summary())")
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
        TrafficHistory.add(up: du, down: dd)
    }
}
