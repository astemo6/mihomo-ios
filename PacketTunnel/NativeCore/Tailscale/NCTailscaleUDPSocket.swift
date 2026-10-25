import Foundation

// MARK: - Single multi-endpoint UDP socket (phase 2)
//
// One POSIX UDP socket shared by STUN probes, disco messages and direct
// WireGuard packets — the magicsock model. Bound to the Tailscale port
// (41641) when free, else an ephemeral port. Receives via a dispatch read
// source; the owner demultiplexes by content.

final class NCTailscaleUDPSocket {
    private(set) var localPort: UInt16 = 0
    private var fd: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var recvBuffer = [UInt8](repeating: 0, count: 65535)

    /// (packet, sourceEndpoint "ip:port") — delivered on the socket queue.
    var onPacket: ((Data, String) -> Void)?

    var isOpen: Bool { fd >= 0 }

    @discardableResult
    func start(preferredPort: UInt16 = 41641, queue: DispatchQueue) -> Bool {
        stop()
        let s = socket(AF_INET6, SOCK_DGRAM, 0)
        guard s >= 0 else { return false }
        var one: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        // Dual-stack: also receive IPv4 (mapped) where the platform allows.
        var zero: Int32 = 0
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in6()
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_addr = in6addr_any
        addr.sin6_port = preferredPort.bigEndian
        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(s, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        if bound != 0 {
            // Preferred port busy: retry on an ephemeral port.
            addr.sin6_port = 0
            let retry = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(s, sa, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            guard retry == 0 else { close(s); return false }
        }

        var actual = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        withUnsafeMutablePointer(to: &actual) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(s, sa, &len)
            }
        }
        localPort = UInt16(bigEndian: actual.sin6_port)
        fd = s

        let source = DispatchSource.makeReadSource(fileDescriptor: s, queue: queue)
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { close(s) }
        source.resume()
        readSource = source
        return true
    }

    func stop() {
        readSource?.cancel()
        readSource = nil
        fd = -1
        localPort = 0
    }

    private func drain() {
        guard fd >= 0 else { return }
        // Drain all pending datagrams per activation.
        for _ in 0..<64 {
            var src = sockaddr_storage()
            var srcLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = recvBuffer.withUnsafeMutableBufferPointer { buf in
                withUnsafeMutablePointer(to: &src) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        recvfrom(fd, buf.baseAddress, buf.count, 0, sa, &srcLen)
                    }
                }
            }
            if n <= 0 { return }
            let data = Data(recvBuffer[0..<n])
            if let endpoint = Self.endpointString(from: src) {
                onPacket?(data, endpoint)
            }
        }
    }

    func send(_ data: Data, to endpoint: String) {
        guard fd >= 0, let (sa, saLen) = Self.makeSockaddr(for: endpoint) else { return }
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var addr = sa
            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { dest in
                    _ = sendto(fd, base, data.count, 0, dest, saLen)
                }
            }
        }
    }

    /// Non-loopback interface addresses with our port, as endpoint strings.
    func localEndpoints() -> [String] {
        guard localPort > 0 else { return [] }
        var out: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let node = cur {
            let flags = Int32(node.pointee.ifa_flags)
            if flags & IFF_LOOPBACK == 0, let sa = node.pointee.ifa_addr {
                switch sa.pointee.sa_family {
                case sa_family_t(AF_INET):
                    var addr = sockaddr_in()
                    memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
                    var bytes = [UInt8](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    var ip = addr.sin_addr
                    if inet_ntop(AF_INET, &ip, &bytes, socklen_t(INET_ADDRSTRLEN)) != nil {
                        let s = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                        out.append("\(s):\(localPort)")
                    }
                case sa_family_t(AF_INET6):
                    var addr = sockaddr_in6()
                    memcpy(&addr, sa, MemoryLayout<sockaddr_in6>.size)
                    if addr.sin6_scope_id == 0 || true {
                        var bytes = [UInt8](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                        var ip = addr.sin6_addr
                        if inet_ntop(AF_INET6, &ip, &bytes, socklen_t(INET6_ADDRSTRLEN)) != nil {
                            let s = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                            if !s.hasPrefix("fe80") {
                                out.append("[\(s)]:\(localPort)")
                            }
                        }
                    }
                default:
                    break
                }
            }
            cur = node.pointee.ifa_next
        }
        return out
    }

    // MARK: sockaddr helpers

    static func endpointString(from storage: sockaddr_storage) -> String? {
        var copy = storage
        return withUnsafePointer(to: &copy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                switch sa.pointee.sa_family {
                case sa_family_t(AF_INET):
                    var addr = sockaddr_in()
                    memcpy(&addr, sa, MemoryLayout<sockaddr_in>.size)
                    var bytes = [UInt8](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    var ip = addr.sin_addr
                    guard inet_ntop(AF_INET, &ip, &bytes, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
                    let s = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                    return "\(s):\(UInt16(bigEndian: addr.sin_port))"
                case sa_family_t(AF_INET6):
                    var addr = sockaddr_in6()
                    memcpy(&addr, sa, MemoryLayout<sockaddr_in6>.size)
                    var bytes = [UInt8](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    var ip = addr.sin6_addr
                    guard inet_ntop(AF_INET6, &ip, &bytes, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
                    let s = bytes.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                    // Unmap v4-mapped v6 sources so they match netmap endpoint strings.
                    if s.hasPrefix("::ffff:"), let v4 = NCIP(String(s.dropFirst(7))) {
                        return "\(v4.string):\(UInt16(bigEndian: addr.sin6_port))"
                    }
                    return "[\(s)]:\(UInt16(bigEndian: addr.sin6_port))"
                default:
                    return nil
                }
            }
        }
    }

    static func makeSockaddr(for endpoint: String) -> (sockaddr_storage, socklen_t)? {
        guard let (ip, port) = NCTailscaleDisco.parseEndpoint(endpoint) else { return nil }
        var storage = sockaddr_storage()
        switch ip {
        case .v4:
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            guard inet_pton(AF_INET, ip.string, &addr.sin_addr) == 1 else { return nil }
            memcpy(&storage, &addr, MemoryLayout<sockaddr_in>.size)
            return (storage, socklen_t(MemoryLayout<sockaddr_in>.size))
        case .v6:
            var addr = sockaddr_in6()
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            guard inet_pton(AF_INET6, ip.string, &addr.sin6_addr) == 1 else { return nil }
            memcpy(&storage, &addr, MemoryLayout<sockaddr_in6>.size)
            return (storage, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }
}
