// feat/s2-tls: a client connection after the native front's TLS handshake, as the contract's ByteStream.
// Plaintext in / out; the TLS record layer is Network.framework's.

import Foundation
import Network
import Security

final class TLSByteStream: ByteStream {
    let connection: NWConnection
    /// The host Go handed over (listener key); always set.
    let host: String
    /// SNI the client sent, nil when it sent none (an IP CONNECT). Route on `routingHost`.
    let sni: String?
    /// Negotiated ALPN ("http/1.1" or nil when the client offered none).
    let alpn: String?
    var routingHost: String { sni ?? host }

    private let lock = NSLock()
    private var closed = false
    /// closeWrite() queued a FIN that has not been processed yet: close() then lets it go out first.
    private var finPending = false

    init(connection: NWConnection, host: String, sni: String?, alpn: String?) {
        self.connection = connection
        self.host = host
        self.sni = sni
        self.alpn = alpn
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: Swift.max(1, min), maximumLength: Swift.max(1, max)) { data, _, isComplete, error in
            completion(data, isComplete, error)
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed { completion($0) })
    }

    /// Half-close: sends close_notify / FIN after queued data, keeps reading.
    func closeWrite() {
        lock.lock()
        if closed || finPending { lock.unlock(); return }
        finPending = true
        lock.unlock()
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] _ in
            guard let self else { return }
            self.lock.lock(); self.finPending = false; let cancel = self.closed; self.lock.unlock()
            if cancel { self.connection.cancel() }
        })
    }

    func close() {
        lock.lock()
        let first = !closed
        closed = true
        let pending = finPending
        lock.unlock()
        guard first else { return }
        // A queued FIN (the session's closeWrite() right before close()) carries the last bytes and close_notify:
        // cancelling now dropped them (2026-10-24 bench: clients got a 502 head without its body, then a reset).
        // The FIN's completion cancels; the backstop covers a peer that never reads.
        if pending {
            let c = connection
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { c.cancel() }
        } else {
            connection.cancel()
        }
    }

    /// SNI + ALPN of a ready TLS connection.
    static func handshakeInfo(_ conn: NWConnection) -> (sni: String?, alpn: String?) {
        guard let meta = conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return (nil, nil)
        }
        let sec = meta.securityProtocolMetadata
        var sni: String?
        if let p = sec_protocol_metadata_get_server_name(sec) {
            let s = String(cString: p)
            if !s.isEmpty { sni = s }
        }
        var alpn: String?
        if let p = sec_protocol_metadata_get_negotiated_protocol(sec) {
            alpn = String(cString: p)
        }
        return (sni, alpn)
    }
}
