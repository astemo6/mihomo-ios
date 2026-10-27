import Foundation

/// Hysteria2 UDP (protocol v2) for the tunnel's UDP stack: one NCUDPSession per stack UDP session,
/// carried as UDPMessages over the QUIC datagram flow of the SHARED hysteria2 connection
/// (NCConnector.sharedHysteria2 — the same connection TCP flows use). The wire codec lives in
/// Shared/NativeCore/NCHysteria2UDPCodec.swift; the datagram flow and session-ID demux in
/// NCHysteria2Connection (Shared/NativeCore/NCHysteria2.swift).
///
/// nc-memory: each session used to build and authenticate its own QUIC connection (a full QUIC +
/// TLS + HTTP/3 stack per DNS query / UDP flow). Sessions now share the per-proxy connection and
/// differ only by their hysteria session ID, as the protocol intends.
final class NCUDPHysteria2Session: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }

    /// The caller's queue: session state lives here; datagram deliveries hop back to it from the
    /// connection's session queue.
    private let queue: DispatchQueue
    private let proxy: NCProxy?
    private var connection: NCHysteria2Connection?
    private var sessionID: UInt32?
    private var reassembler = NCHy2UDP.Reassembler()
    private var acquiring = false
    private var cancelled = false
    private var queued: [(Data, NCTarget)] = []
    /// Cap on packets held while the shared connection authenticates (as NCUDPTUICSession).
    private static let maxQueued = 32

    /// Session over an already-started shared connection.
    init(connection: NCHysteria2Connection, queue: DispatchQueue) {
        self.queue = queue
        self.proxy = nil
        attach(connection)
    }

    /// Session for a proxy config: acquires the shared connection (dialing it if needed).
    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard proxy.server != nil, proxy.port != nil, proxy.password != nil else { return nil }
        self.queue = queue
        self.proxy = proxy
        acquire()
    }

    private func acquire() {
        guard !acquiring, !cancelled, let proxy, let server = proxy.server, let port = proxy.port else { return }
        acquiring = true
        NCConnector.sharedHysteria2(proxy: proxy, server: server, port: port, queue: queue) { [weak self] conn, _ in
            self?.queue.async {
                guard let self else { return }
                self.acquiring = false
                guard let conn, !self.cancelled else { self.queued = []; return }
                self.attach(conn)
            }
        }
    }

    /// Session queue: register on `conn` and flush what queued meanwhile.
    private func attach(_ conn: NCHysteria2Connection) {
        guard !cancelled else { return }
        let id = conn.registerUDP { [weak self] raw in
            // Connection queue → session queue.
            self?.queue.async { self?.handleDatagram(raw) }
        }
        guard let id else {
            // Not ready, or the server answered Hysteria-UDP: false — nothing will ever drain.
            queued = []
            return
        }
        connection = conn
        sessionID = id
        let pending = queued
        queued = []
        for (data, target) in pending { send(data, to: target) }
    }

    private func handleDatagram(_ raw: Data) {
        guard !cancelled, let frame = NCHy2UDP.decodeFrame(raw), frame.sessionID == sessionID,
              let payload = reassembler.feed(frame) else { return }
        onReply(payload)
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if let conn = connection, !conn.isAlive {
            // Shared connection died: drop the stale registration, re-acquire a fresh one.
            connection = nil
            sessionID = nil
            reassembler.reset()
        }
        guard let conn = connection, let id = sessionID else {
            if queued.count < Self.maxQueued { queued.append((data, target)) }
            acquire()
            return
        }
        conn.sendUDP(sessionID: id, target: target, payload: data)
    }

    func cancel() {
        cancelled = true
        queued = []
        reassembler.reset()
        if let conn = connection, let id = sessionID { conn.unregisterUDP(id) }
        connection = nil
        sessionID = nil
    }
}
