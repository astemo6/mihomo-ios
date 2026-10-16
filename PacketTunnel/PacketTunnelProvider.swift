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
    private var tunFd: Int32 = 0
    private let notifier = ScriptNotifier()

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

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = 1500
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
        ]
        settings.ipv4Settings = ipv4
        if overrides.ipv6 {
            let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }
        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        // Watchdog: never leave the system at "连接中…" (Go has its own 20 s bound; this covers anything else).
        DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
            completionHandler(Self.error("启动超时（30 秒）。请到 更多 → 内核覆写设置 → 诊断 查看启动日志"))
        }

        StartupLog.write("applying tunnel network settings")
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(Self.error("设置隧道网络失败：\(error.localizedDescription)"))
                return
            }
            StartupLog.write("settings applied")
            guard let fd = Self.findTunnelFileDescriptor(packetFlow: self.packetFlow) else {
                completionHandler(Self.error("无法获取 utun 文件描述符"))
                return
            }
            StartupLog.write("fd found: \(fd)")
            self.tunFd = fd
            // Off the NetworkExtension callback queue: LibmihomoStart returns within 20 s at most.
            DispatchQueue.global(qos: .userInitiated).async {
                StartupLog.write("core start begin")
                var err: NSError?
                LibmihomoStart(AppShared.homeURL.path, profile.path, fd, &err)
                StartupLog.write("core start returned\(err.map { ": " + $0.localizedDescription } ?? " OK"), \(ProcessMemory.summary()), \(LibmihomoMemoryStats())")
                if let err {
                    completionHandler(Self.error("内核启动失败：\(err.localizedDescription)"))
                    return
                }
                completionHandler(nil)
                // Memory again once providers have had a moment to load.
                DispatchQueue.global().asyncAfter(deadline: .now() + 15) {
                    StartupLog.write("+15 s: \(ProcessMemory.summary()), \(LibmihomoMemoryStats())")
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        StartupLog.write("stopTunnel reason=\(reason.rawValue), \(ProcessMemory.summary())")
        LibmihomoStop()
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
        case .none:
            completionHandler?(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        LibmihomoFreeMemory()
        completionHandler()
    }

    override func wake() {}

    // MARK: - utun fd

    /// Finds the utun control socket created by NetworkExtension.
    /// Scans fds and asks each for UTUN_OPT_IFNAME (SYSPROTO_CONTROL=2, UTUN_OPT_IFNAME=2),
    /// the same approach sing-box / Hiddify use.
    static func findTunnelFileDescriptor(packetFlow: NEPacketTunnelFlow) -> Int32? {
        var buf = [CChar](repeating: 0, count: 64)
        for fd: Int32 in 0...1024 {
            var len = socklen_t(buf.count)
            if getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buf, &len) == 0 {
                let name = String(cString: buf)
                if name.hasPrefix("utun") {
                    return fd
                }
            }
        }
        return nil
    }

    static func error(_ msg: String) -> NSError {
        NSError(domain: "Mihomo.PacketTunnel", code: 1, userInfo: [NSLocalizedDescriptionKey: msg])
    }
}
