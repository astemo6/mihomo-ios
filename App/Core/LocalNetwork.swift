import Foundation
import Network
import Darwin

// v0.19 内网 IP 详情: the device's LAN side, read without any entitlement:
// - interfaces from getifaddrs (Wi-Fi en0, personal hotspot bridge*, cellular pdp_ip*, wired en1…),
// - the Wi-Fi router from NWPathMonitor(requiredInterfaceType: .wifi).currentPath.gateways (the
//   physical Wi-Fi path, not the VPN's), falling back to <subnet>.1 marked as a guess,
// - the system DNS servers from libresolv (res_9_ninit / res_9_getservers, looked up with dlsym; the
//   app links -lresolv). While our VPN is connected these are the tunnel's DNS, which the page says.
// - network type from NWPathMonitor; the SSID through WiFiInfo (wifi-info + VPN config or location).

struct LocalInterface: Hashable, Identifiable {
    var name: String
    var ipv4: [String] = []
    var ipv6: [String] = []
    var subnet: String?
    var id: String { name }

    var kind: String {
        if name == "en0" { return "Wi-Fi" }
        if name.hasPrefix("bridge") { return "个人热点" }
        if name.hasPrefix("pdp_ip") { return "蜂窝网络" }
        if name.hasPrefix("en") { return "有线 / 其他" }
        return name
    }
    var sortKey: Int {
        if name == "en0" { return 0 }
        if name.hasPrefix("bridge") { return 1 }
        if name.hasPrefix("en") { return 2 }
        if name.hasPrefix("pdp_ip") { return 3 }
        return 4
    }
}

struct LocalNetworkInfo: Equatable {
    var interfaces: [LocalInterface] = []
    var gateway: String?
    var gatewayGuessed = false
    var dns: [String] = []
    /// wifi / cellular / wired / other / none
    var pathType = "none"
    var expensive = false
    var constrained = false
}

enum LocalNetwork {
    static func interfaces() -> [LocalInterface] {
        var map: [String: LocalInterface] = [:]
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let ifa = cur.pointee
            p = ifa.ifa_next
            guard let sa = ifa.ifa_addr else { continue }
            let fam = sa.pointee.sa_family
            guard fam == UInt8(AF_INET) || fam == UInt8(AF_INET6) else { continue }
            let flags = Int32(ifa.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            let name = String(cString: ifa.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("bridge") || name.hasPrefix("pdp_ip") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            var ip = String(cString: host)
            var entry = map[name] ?? LocalInterface(name: name)
            if fam == UInt8(AF_INET) {
                guard !ip.hasPrefix("169.254.") else { continue }
                entry.ipv4.append(ip)
                if entry.subnet == nil, let nm = ifa.ifa_netmask {
                    let mask = nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                    let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
                    entry.subnet = "\(dotted(addr & mask))/\(mask.nonzeroBitCount)"
                }
            } else {
                if let pct = ip.firstIndex(of: "%") { ip = String(ip[..<pct]) }
                entry.ipv6.append(ip)
            }
            map[name] = entry
        }
        return map.values.filter { !$0.ipv4.isEmpty || !$0.ipv6.isEmpty }.sorted { ($0.sortKey, $0.name) < ($1.sortKey, $1.name) }
    }

    static func dotted(_ v: UInt32) -> String { "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)" }

    /// One NWPathMonitor answer (the first path update), or nil after `timeout`.
    static func path(_ type: NWInterface.InterfaceType?, timeout: TimeInterval = 1.5) async -> NWPath? {
        await withCheckedContinuation { (c: CheckedContinuation<NWPath?, Never>) in
            let m = type.map { NWPathMonitor(requiredInterfaceType: $0) } ?? NWPathMonitor()
            let q = DispatchQueue(label: "lan.path")
            let lock = NSLock()
            var done = false
            func finish(_ p: NWPath?) {
                lock.lock(); defer { lock.unlock() }
                guard !done else { return }
                done = true
                m.cancel()
                c.resume(returning: p)
            }
            m.pathUpdateHandler = { finish($0) }
            m.start(queue: q)
            q.asyncAfter(deadline: .now() + timeout) { finish(nil) }
        }
    }

    static func endpointHost(_ e: NWEndpoint) -> String? {
        if case let .hostPort(host, _) = e {
            switch host {
            case .ipv4(let a): return "\(a)"
            case .ipv6(let a): return "\(a)".components(separatedBy: "%").first
            case .name(let n, _): return n
            @unknown default: return nil
            }
        }
        return nil
    }

    // libresolv without a bridging header: res_9_ninit fills an opaque __res_9_state (well under 8 KB),
    // res_9_getservers copies the servers as 128-byte sockaddr unions.
    private typealias NInit = @convention(c) (UnsafeMutableRawPointer) -> Int32
    private typealias GetServers = @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer, Int32) -> Int32
    private typealias NDestroy = @convention(c) (UnsafeMutableRawPointer) -> Void

    static func dnsServers() -> [String] {
        guard let h = dlopen(nil, RTLD_NOW),
              let i = dlsym(h, "res_9_ninit"), let g = dlsym(h, "res_9_getservers"), let d = dlsym(h, "res_9_ndestroy") else { return [] }
        let ninit = unsafeBitCast(i, to: NInit.self)
        let getservers = unsafeBitCast(g, to: GetServers.self)
        let ndestroy = unsafeBitCast(d, to: NDestroy.self)
        let state = UnsafeMutableRawPointer.allocate(byteCount: 8192, alignment: 16)
        state.initializeMemory(as: UInt8.self, repeating: 0, count: 8192)
        defer { state.deallocate() }
        guard ninit(state) == 0 else { return [] }
        defer { ndestroy(state) }
        let unionSize = 128, maxServers: Int32 = 8
        let buf = UnsafeMutableRawPointer.allocate(byteCount: unionSize * Int(maxServers), alignment: 16)
        buf.initializeMemory(as: UInt8.self, repeating: 0, count: unionSize * Int(maxServers))
        defer { buf.deallocate() }
        let n = Int(getservers(state, buf, maxServers))
        var out: [String] = []
        for k in 0..<max(0, min(n, Int(maxServers))) {
            let sa = (buf + k * unionSize).assumingMemoryBound(to: sockaddr.self)
            guard sa.pointee.sa_family == UInt8(AF_INET) || sa.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = sa.pointee.sa_len > 0 ? socklen_t(sa.pointee.sa_len)
                : socklen_t(sa.pointee.sa_family == UInt8(AF_INET) ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            if getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: host).components(separatedBy: "%").first ?? ""
                if !s.isEmpty && !out.contains(s) { out.append(s) }
            }
        }
        return out
    }

    static func read() async -> LocalNetworkInfo {
        var info = LocalNetworkInfo()
        info.interfaces = interfaces()
        info.dns = await Task.detached(priority: .utility) { dnsServers() }.value
        if let p = await path(nil) {
            if p.status != .satisfied { info.pathType = "none" }
            else if p.usesInterfaceType(.wifi) { info.pathType = "wifi" }
            else if p.usesInterfaceType(.cellular) { info.pathType = "cellular" }
            else if p.usesInterfaceType(.wiredEthernet) { info.pathType = "wired" }
            else { info.pathType = "other" }
            info.expensive = p.isExpensive
            info.constrained = p.isConstrained
        }
        // The Wi-Fi path itself (under a VPN the default path is the tunnel's).
        if let wifi = await path(.wifi), wifi.status == .satisfied {
            if info.pathType == "other" || info.pathType == "none" { info.pathType = "wifi" }
            info.gateway = wifi.gateways.compactMap(endpointHost).first { !$0.contains(":") } ?? wifi.gateways.compactMap(endpointHost).first
        }
        if info.gateway == nil, let en0 = info.interfaces.first(where: { $0.name == "en0" }), let sub = en0.subnet,
           let base = sub.split(separator: "/").first {
            var parts = base.split(separator: ".").map(String.init)
            if parts.count == 4, let last = Int(parts[3]) {
                parts[3] = String(last + 1)
                info.gateway = parts.joined(separator: ".")
                info.gatewayGuessed = true
            }
        }
        return info
    }
}
