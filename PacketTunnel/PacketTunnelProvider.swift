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
        let completionHandler: (Error?) -> Void = { err in
            if let err { TunnelErrorLog.write(err.localizedDescription) }
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

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }
            guard let fd = Self.findTunnelFileDescriptor(packetFlow: self.packetFlow) else {
                completionHandler(Self.error("无法获取 utun 文件描述符"))
                return
            }
            self.tunFd = fd
            var err: NSError?
            LibmihomoStart(AppShared.homeURL.path, profile.path, fd, &err)
            if let err {
                completionHandler(Self.error("内核启动失败：\(err.localizedDescription)"))
                return
            }
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
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
