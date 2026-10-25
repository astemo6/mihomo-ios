import Foundation

/// Swift side of the lwIP bridge (lwip/nc_stack.h). One instance per tunnel;
/// every entry point must be called on the engine's serial queue, matching the
/// C side's single-threaded contract. Callback payloads are copied to Data
/// synchronously, as the C contract requires.
final class NCTunStack {
    final class TCPConn {
        let handle: UnsafeMutableRawPointer
        let dst: NCTarget
        let srcPort: Int
        var closed = false
        init(handle: UnsafeMutableRawPointer, dst: NCTarget, srcPort: Int) {
            self.handle = handle
            self.dst = dst
            self.srcPort = srcPort
        }
    }

    struct UDPSessionInfo {
        let id: UInt32
        let src: NCTarget
        let dst: NCTarget
    }

    var onOutput: (Data) -> Void = { _ in }
    /// Return false to refuse the connection.
    var onTCPAccept: (TCPConn) -> Bool = { _ in false }
    /// data == nil means the peer sent FIN.
    var onTCPData: (TCPConn, Data?) -> Void = { _, _ in }
    var onTCPError: (TCPConn) -> Void = { _ in }
    var onUDP: (UDPSessionInfo, Data) -> Void = { _, _ in }
    /// rv2-life: the app ACKed bytes we wrote (lwIP send window opened): drain the outbox, resume the relay read.
    var onTCPSent: (TCPConn) -> Void = { _ in }
    /// rv2-life: the C side ended a UDP session (idle expiry or eviction for a new flow).
    var onUDPClosed: (UInt32) -> Void = { _ in }

    private(set) var running = false

    @discardableResult
    func start(ip4: String, ip6: String?, mtu: UInt16) -> Bool {
        var cbs = nc_callbacks()
        cbs.output = ncOnOutput
        cbs.tcp_accept = ncOnAccept
        cbs.tcp_recv = ncOnRecv
        cbs.tcp_err = ncOnErr
        cbs.udp_recv = ncOnUDP
        cbs.tcp_sent = ncOnSent
        cbs.udp_closed = ncOnUDPClosed
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        let ok = ip4.withCString { p4 in
            ip6?.withCString { p6 in
                nc_init(&cbs, ctx, p4, p6, mtu)
            } ?? nc_init(&cbs, ctx, p4, nil, mtu)
        }
        running = ok == 0
        return running
    }

    func stop() {
        guard running else { return }
        nc_shutdown()
        running = false
    }

    func input(_ packet: Data) {
        packet.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            nc_input(base.assumingMemoryBound(to: UInt8.self), UInt32(packet.count))
        }
    }

    func poll() { nc_poll() }

    /// Returns the number of bytes the stack queued; the caller keeps any
    /// remainder and retries on a later poll tick.
    @discardableResult
    func tcpWrite(_ conn: TCPConn, _ data: Data) -> Int {
        // rv2-life: a closed TCPConn's slot may already belong to a new connection.
        guard !conn.closed else { return -1 }
        return data.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return 0 }
            return Int(nc_tcp_write(conn.handle, base.assumingMemoryBound(to: UInt8.self), UInt32(data.count)))
        }
    }

    /// rv2-life: acknowledge `n` received bytes (reopens the app's send window; see nc_tcp_recved). A no-op once the
    /// connection is gone (its C slot may already serve another connection).
    func tcpRecved(_ conn: TCPConn, _ n: Int) {
        guard n > 0, !conn.closed, connForHandle(conn.handle) === conn else { return }
        nc_tcp_recved(conn.handle, UInt32(clamping: n))
    }

    func tcpClose(_ conn: TCPConn) {
        guard !conn.closed else { return }
        conn.closed = true
        unregister(conn)
        nc_tcp_close(conn.handle)
    }

    func tcpAbort(_ conn: TCPConn) {
        guard !conn.closed else { return }
        conn.closed = true
        unregister(conn)
        nc_tcp_abort(conn.handle)
    }

    @discardableResult
    func udpSend(session: UInt32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return false }
            return nc_udp_send(session, base.assumingMemoryBound(to: UInt8.self), UInt32(data.count)) == 0
        }
    }

    func udpClose(session: UInt32) { nc_udp_close(session) }

    // MARK: Callback targets (invoked from the @_cdecl shims below)

    fileprivate func handleAccept(handle: UnsafeMutableRawPointer, dstBytes: UnsafePointer<UInt8>, dstPort: UInt16,
                                  srcBytes: UnsafePointer<UInt8>, srcPort: UInt16, is6: Int32) -> Int32 {
        let dstIP = NCTunStack.ipString(bytes: dstBytes, is6: is6 == 1)
        let conn = TCPConn(handle: handle, dst: NCTarget(host: dstIP, port: Int(dstPort)), srcPort: Int(srcPort))
        _ = srcBytes
        guard onTCPAccept(conn) else { return 0 }
        register(conn)
        return 1
    }

    fileprivate static func ipString(bytes: UnsafePointer<UInt8>, is6: Bool) -> String {
        if is6 {
            return NCIP.v6((0..<16).map { bytes[$0] }).string
        }
        return "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"
    }
}

/* C callback shims: nc_stack calls these synchronously on the engine queue. */

private func ncSelf(_ ctx: UnsafeMutableRawPointer?) -> NCTunStack? {
    guard let ctx else { return nil }
    return Unmanaged<NCTunStack>.fromOpaque(ctx).takeUnretainedValue()
}

@_cdecl("ncOnOutput")
func ncOnOutput(_ ctx: UnsafeMutableRawPointer?, _ pkt: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let stack = ncSelf(ctx), let pkt else { return }
    stack.onOutput(Data(bytes: pkt, count: Int(len)))
}

@_cdecl("ncOnAccept")
func ncOnAccept(_ ctx: UnsafeMutableRawPointer?, _ conn: UnsafeMutableRawPointer?,
                _ dst: UnsafePointer<UInt8>?, _ dstPort: UInt16,
                _ src: UnsafePointer<UInt8>?, _ srcPort: UInt16, _ is6: Int32) -> Int32 {
    guard let stack = ncSelf(ctx), let conn, let dst, let src else { return 0 }
    return stack.handleAccept(handle: conn, dstBytes: dst, dstPort: dstPort, srcBytes: src, srcPort: srcPort, is6: is6)
}

@_cdecl("ncOnRecv")
func ncOnRecv(_ ctx: UnsafeMutableRawPointer?, _ conn: UnsafeMutableRawPointer?,
              _ data: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let stack = ncSelf(ctx), let conn else { return }
    // The C side hands us the conn slot pointer as identity; the engine maps it
    // back to its TCPConn through the registry below.
    if let c = stack.connForHandle(conn) {
        stack.onTCPData(c, data.map { Data(bytes: $0, count: Int(len)) })
    }
}

@_cdecl("ncOnErr")
func ncOnErr(_ ctx: UnsafeMutableRawPointer?, _ conn: UnsafeMutableRawPointer?, _ err: Int32) {
    guard let stack = ncSelf(ctx), let conn else { return }
    if let c = stack.connForHandle(conn) {
        c.closed = true // rv2-life: the C slot is freed right after this call; nothing may write / close it again
        stack.unregister(c)
        stack.onTCPError(c)
    }
    _ = err
}

@_cdecl("ncOnUDP")
func ncOnUDP(_ ctx: UnsafeMutableRawPointer?, _ session: UInt32,
             _ src: UnsafePointer<UInt8>?, _ srcPort: UInt16,
             _ dst: UnsafePointer<UInt8>?, _ dstPort: UInt16, _ is6: Int32,
             _ data: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let stack = ncSelf(ctx), let src, let dst, let data else { return }
    let info = NCTunStack.UDPSessionInfo(
        id: session,
        src: NCTarget(host: NCTunStack.ipString(bytes: src, is6: is6 == 1), port: Int(srcPort)),
        dst: NCTarget(host: NCTunStack.ipString(bytes: dst, is6: is6 == 1), port: Int(dstPort)))
    stack.onUDP(info, Data(bytes: data, count: Int(len)))
}

@_cdecl("ncOnSent")
func ncOnSent(_ ctx: UnsafeMutableRawPointer?, _ conn: UnsafeMutableRawPointer?, _ len: UInt32) {
    guard let stack = ncSelf(ctx), let conn, let c = stack.connForHandle(conn) else { return }
    _ = len
    stack.onTCPSent(c)
}

@_cdecl("ncOnUDPClosed")
func ncOnUDPClosed(_ ctx: UnsafeMutableRawPointer?, _ session: UInt32) {
    guard let stack = ncSelf(ctx) else { return }
    stack.onUDPClosed(session)
}

/* The C accept callback receives a slot pointer; TCPConn objects are created
   there, and later callbacks (recv/err) only carry that same pointer. The
   stack keeps a small registry so all callbacks agree on one object. */
extension NCTunStack {
    private static var registry: [UInt: TCPConn] = [:]

    func register(_ conn: TCPConn) {
        NCTunStack.registry[UInt(bitPattern: conn.handle)] = conn
    }

    func unregister(_ conn: TCPConn) {
        NCTunStack.registry.removeValue(forKey: UInt(bitPattern: conn.handle))
    }

    fileprivate func connForHandle(_ handle: UnsafeMutableRawPointer) -> TCPConn? {
        NCTunStack.registry[UInt(bitPattern: handle)]
    }
}
