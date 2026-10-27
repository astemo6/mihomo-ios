import Foundation
import Network

/// Gap D2 (feat/nc-modes, on astemo6/Muse's NativeCore): keeps the native core's own outbound sockets off the
/// tunnel while 接管所有网络流量 (includeAllNetworks) is on.
///
/// Without includeAllNetworks iOS routes a packet-tunnel provider's own sockets around its tunnel, so nothing is
/// needed. With it, the system also scopes the provider's unbound sockets into the tunnel: a DIRECT dial, a proxy
/// server dial or a DNS forward would enter NEPacketTunnelFlow, come back to NCDataPlane, be dialled again, and
/// loop. NEIPv4Settings.excludedRoutes is no fix: the proxy servers' addresses (often behind host names, behind
/// CDNs) are not known when the routes are set, DIRECT targets are arbitrary, and with includeAllNetworks iOS does
/// not treat excluded routes as a way out for the provider itself. the old core solved this by
/// binding every socket to the physical interface; this is the Network.framework
/// equivalent: `requiredInterface` = the current physical interface (Wi-Fi / cellular / wired, from a path monitor
/// that never lists the tunnel), and the tunnel's interface type (.other: utun / ipsec) prohibited, so a dial made
/// before the first path update still cannot pick the tunnel. Loopback destinations (the MitM front, the local
/// proxy) are never bound.
///
/// Name resolution: a bound NWConnection resolves through the bound interface's resolver, not the tunnel DNS
/// (198.18.0.2), so proxy server host names do not come back as fake IPs.
enum NCOutboundBinding {
    private static let lock = NSLock()
    private static var enabled = false
    private static var physical: NWInterface?
    private static var monitor: NWPathMonitor?
    private static let monitorQueue = DispatchQueue(label: "nc.outbound-binding")

    /// Called at tunnel start with the VPN configuration's includeAllNetworks (the value iOS enforces).
    static func start(includeAllNetworks: Bool) {
        stop()
        lock.lock()
        enabled = includeAllNetworks
        lock.unlock()
        guard includeAllNetworks else { return }
        let m = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
        m.pathUpdateHandler = { path in
            let iface = path.status == .satisfied
                ? path.availableInterfaces.first { [.wifi, .cellular, .wiredEthernet].contains($0.type) }
                : nil
            lock.lock()
            let changed = physical?.name != iface?.name
            physical = iface
            lock.unlock()
            if changed { StartupLog.write("outbound binding: physical interface \(iface?.name ?? "none")") }
        }
        m.start(queue: monitorQueue)
        lock.lock()
        monitor = m
        lock.unlock()
    }

    static func stop() {
        lock.lock()
        let m = monitor
        monitor = nil
        physical = nil
        enabled = false
        lock.unlock()
        m?.cancel()
    }

    static var isEnabled: Bool { lock.lock(); defer { lock.unlock() }; return enabled }

    /// For 诊断 / the startup log.
    static var describe: String {
        lock.lock(); defer { lock.unlock() }
        guard enabled else { return "off (includeAllNetworks off: provider sockets bypass the tunnel)" }
        return "on, bound to \(physical?.name ?? "(no physical interface yet: tunnel type prohibited)")"
    }

    /// Applies the binding to parameters of a connection to `host` (no-op unless includeAllNetworks is on).
    static func apply(_ params: NWParameters, host: String) {
        guard !isLoopback(host) else { return }
        lock.lock()
        let (on, iface) = (enabled, physical)
        lock.unlock()
        guard on else { return }
        params.prohibitedInterfaceTypes = [.other]
        if let iface { params.requiredInterface = iface }
    }

    /// `base` copied and bound — for the `.tcp` / `.udp` / `.tls` presets (shared instances must not be mutated).
    static func params(_ base: NWParameters, host: String) -> NWParameters {
        guard isEnabled, !isLoopback(host) else { return base }
        let p = base.copy()
        apply(p, host: host)
        return p
    }

    static func isLoopback(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "localhost" || h == "::1" || h.hasPrefix("127.")
    }
}
