// fix/nc-e2e-gaps: the plain-HTTP twin of MitmTLSFront. On TUN, port-80 HTTP flows whose host has rewrite work
// (a MitM host, or the literal host of a rule that matches http://) used to go straight to the origin, so
// `^http://…` rewrite / reject / script rules never ran (self-check 「明文 HTTP（80 端口）重写」 known gap). The data plane
// now relays such a flow to this loopback listener, and the accepted connection runs the same NativeMitmSession
// (HTTP/1.1, rewrite engine, scripts) with tls = false: the forward URL is http://<Host>/…, the upstream plain TCP.
//
// Lean: one BSD loopback listener (NCLoopbackListener; NWListener on the loopback did not deliver connections inside
// the tunnel on iOS 18.7), opened on first use on an ephemeral port, shared by every flow (the session routes on
// the request's Host header, not on the listener). Admission is the TLS front's: a session slot is reserved before
// the data plane hands a flow over (NativeMitmRuntime.reserve), so a full front declines and the flow is relayed
// as before instead of being cut.

import Foundation

final class MitmPlainFront {
    static let shared = MitmPlainFront()

    private let lock = NSLock()
    private var _onAccept: ((MitmAcceptedConnection) -> Void)?
    /// Set by NativeMitmRuntime.install (nil: no native MitM session runtime — every flow declines).
    var onAccept: ((MitmAcceptedConnection) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _onAccept }
        set { lock.lock(); _onAccept = newValue; lock.unlock() }
    }

    private let queue = DispatchQueue(label: "tern.native-mitm.plain", qos: .userInitiated)
    private var listener: NCLoopbackListener?
    private var port: UInt16 = 0
    private var failedAt: Date?
    private(set) var accepted = 0

    /// Loopback port to relay one plain-HTTP flow to, with a session slot reserved for it; 0 = declined (no runtime,
    /// MitM off, session cap / memory governor, listener failed).
    func admit() -> UInt16 {
        guard onAccept != nil, NativeMitmRuntime.forced || NativeMitmRuntime.active else { return 0 }
        guard NativeMitmRuntime.reserve() else { return 0 }
        let p = queue.sync { () -> UInt16 in
            if listener != nil { return port }
            if let f = failedAt, Date().timeIntervalSince(f) < 30 { return 0 } // do not retry a failing bind per flow
            let l = NCLoopbackListener(queue: queue)
            l.onAccept = { [weak self] c in self?.accept(c) }
            l.onAcceptError = { why in StartupLog.write("MITM plain front: \(why)") }
            if let why = l.start(port: 0) {
                failedAt = Date()
                StartupLog.write("MITM plain front: listener failed: \(why)")
                return 0
            }
            listener = l
            port = l.port
            return port
        }
        if p == 0 { NativeMitmRuntime.unreserve() }
        return p
    }

    /// The data plane could not reach the listener after admit(): give the reserved slot back.
    func unadmit() { NativeMitmRuntime.unreserve() }

    func stop() {
        queue.sync {
            listener?.stop()
            listener = nil
            port = 0
            failedAt = nil
        }
    }

    private func accept(_ c: NCLoopbackConn) {
        guard let h = onAccept else { c.cancel(); return }
        accepted += 1
        h(MitmAcceptedConnection(stream: LoopbackByteStream(c), host: "", port: 80, alpn: nil,
                                 connID: NativeMitmRuntime.nextID(), tls: false))
    }
}

/// An accepted loopback connection as the session contract's ByteStream (plaintext both ways).
final class LoopbackByteStream: ByteStream {
    private let conn: NCLoopbackConn
    init(_ c: NCLoopbackConn) { conn = c }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: Swift.max(1, min), maximumLength: Swift.max(1, max)) { data, _, eof, error in
            completion(data, eof, error)
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else { return completion(nil) }
        conn.send(content: data, completion: .contentProcessed { completion($0) })
    }

    func closeWrite() { conn.shutdownWrite() }

    func close() {
        // Let queued bytes (a response written right before close) go out first: cancel after a zero-length send.
        let c = conn
        c.send(content: Data(), completion: .contentProcessed { _ in c.cancel() })
    }
}
