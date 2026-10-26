// native-only (nc-integrate): one build of this file — the NativeCore tunnel; the app target compiles the same code
// for its unit tests (tunnel-engine calls behind TERN_TUNNEL). The old-core variant is gone with the retired bridge
// feat/s2-tls (native MitM stage 2, B7): the TLS server side of the native front.
//
// Handoff: the old core keeps
// the CONNECT front (loop check, SNI peek, MitM host list, pinning memory), then asks listen(host, alpn) for the
// port of a loopback TLS listener presenting the old core's leaf for host. the old core writes the client's ClientHello there and pipes
// once our ServerHello arrives. Every failure here is a FALLBACK SIGNAL, never a client-visible error:
//   - listen returns 0 (no handler, no identity, import failed, listener budget full, listener won't start)
//     → the old core terminates TLS itself;
//   - the handshake fails before ready → no ServerHello reaches caller, and the failure kind goes to NCPinningMemory.
// One listener per host: Network.framework fixes a listener's TLS identity at creation and has no public per-SNI
// certificate callback. TLS: server identity = the old core leaf, ALPN http/1.1, min TLS 1.2.
// s3-h2: when native h2 is on (NativeH2Runtime, switch nativeMitmH2) and the client's offer (the old core passes it to
// listen) contains "h2", the connection goes to a second listener for the host offering "h2, http/1.1"; the
// accepted stream reports the negotiated ALPN and the session layer picks NativeH2Session or NativeMitmSession.
// Not registered here — the `wire` lane calls register() behind the runtime switch (NativeMitmRuntime.defaultOn, iOS 17+).

import Foundation
import Network
import Security

final class MitmTLSFront: NSObject {
    static let shared = MitmTLSFront()

    /// Set by the session layer (`wire`). Called on `queue` once per handshaken client connection. While nil,
    /// listen() declines.
    var onAccept: ((TLSByteStream) -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _onAccept }
        set { lock.lock(); _onAccept = newValue; lock.unlock() }
    }
    /// Reported handshake failures (stored in Swift NCPinningMemory). Injectable for tests.
    var reportHandshakeFailure: (String, String) -> Void = { host, kind in
        if kind == "cert" || kind == "closed" {
            NCPinningMemory.shared.markPinned(host)
        }
    }

    let identities: LeafIdentityCache
    let queue: DispatchQueue
    let maxListeners: Int
    let idleClose: TimeInterval
    let handshakeTimeout: TimeInterval

    private let lock = NSLock()
    private var _onAccept: ((TLSByteStream) -> Void)?
    private var listeners: [String: Entry] = [:]

    private final class Entry {
        let listener: NWListener
        var port: UInt16 = 0
        var lastUse = Date()
        init(listener: NWListener) { self.listener = listener }
    }

    init(identities: LeafIdentityCache = .shared,
         queue: DispatchQueue = DispatchQueue(label: "tern.native-mitm.tls"),
         maxListeners: Int = 64, idleClose: TimeInterval = 60, handshakeTimeout: TimeInterval = 10) {
        self.identities = identities
        self.queue = queue
        self.maxListeners = maxListeners
        self.idleClose = idleClose
        self.handshakeTimeout = handshakeTimeout
    }

    func register() {
        // Pure native: registered in NativeCore data plane
    }


    func listen(_ host: String?, alpn: String?) -> Int64 {
        guard let host, !host.isEmpty else { return 0 }
        if NCPinningMemory.shared.isPinned(host) { return 0 }
        // Admission (session cap + runtime switch, set by NativeMitmRuntime.install): decided here
        if let admit, !admit() { return 0 }
        let h2 = NativeH2Runtime.enabled && (alpn ?? "").split(separator: ",").contains { $0.trimmingCharacters(in: .whitespaces) == "h2" }
        switch port(for: host, h2: h2) {
        case .success(let p): return Int64(p)
        case .failure:
            unadmit?()
            return 0
        }
    }

    /// Admission hooks (nil: admit everything). admit() true holds a slot that the accepted session claims;
    /// unadmit() gives it back when no port could be offered.
    var admit: (() -> Bool)? {
        get { lock.lock(); defer { lock.unlock() }; return _admit }
        set { lock.lock(); _admit = newValue; lock.unlock() }
    }
    var unadmit: (() -> Void)? {
        get { lock.lock(); defer { lock.unlock() }; return _unadmit }
        set { lock.lock(); _unadmit = newValue; lock.unlock() }
    }
    private var _admit: (() -> Bool)?
    private var _unadmit: (() -> Void)?

    /// Port of the loopback TLS listener for host, created on first use.
    /// h2: the listener offering "h2, http/1.1" (a separate listener per host and ALPN set — Network.framework
    /// fixes both at creation).
    func port(for rawHost: String, h2: Bool = false) -> Result<UInt16, NativeTLSError> {
        let host = BoundedLRU<LeafIdentity>.normalize(rawHost)
        let key = h2 ? host + "#h2" : host
        guard onAccept != nil else { return .failure(.listenerFailed) }
        lock.lock()
        if let e = listeners[key], e.port != 0 {
            e.lastUse = Date()
            lock.unlock()
            return .success(e.port)
        }
        let full = listeners.count >= maxListeners
        lock.unlock()
        if full {
            sweepIdle()
            lock.lock(); let still = listeners.count >= maxListeners; lock.unlock()
            if still { return .failure(.listenerFailed) }
        }
        let leaf: LeafIdentity
        switch identities.identity(for: host) {
        case .success(let l): leaf = l
        case .failure(let e): return .failure(e)
        }
        guard let entry = makeListener(host: host, key: key, identity: leaf.identity, h2: h2) else { return .failure(.listenerFailed) }
        lock.lock()
        if let raced = listeners[key], raced.port != 0 { // another thread won
            lock.unlock()
            entry.listener.cancel()
            return .success(raced.port)
        }
        listeners[key] = entry
        lock.unlock()
        return .success(entry.port)
    }

    static func tlsOptions(identity: SecIdentity, h2: Bool = false) -> NWProtocolTLS.Options? {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        guard let sid = sec_identity_create(identity) else { return nil }
        sec_protocol_options_set_local_identity(sec, sid)
        if h2 { sec_protocol_options_add_tls_application_protocol(sec, "h2") }
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        return tls
    }

    private func makeListener(host: String, key: String, identity: SecIdentity, h2: Bool) -> Entry? {
        guard let tls = Self.tlsOptions(identity: identity, h2: h2) else { return nil }
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        params.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: params) else { return nil }
        let entry = Entry(listener: listener)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self, weak entry] state in
            switch state {
            case .ready:
                entry?.port = listener.port?.rawValue ?? 0
                ready.signal()
            case .failed, .cancelled:
                ready.signal()
                self?.forget(key, listener: listener)
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { conn.cancel(); return }
            self.accept(conn, host: host)
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 1) == .success, entry.port != 0 else {
            listener.cancel()
            return nil
        }
        return entry
    }

    private func forget(_ host: String, listener: NWListener) {
        lock.lock()
        if listeners[host]?.listener === listener { listeners.removeValue(forKey: host) }
        lock.unlock()
    }

    private func accept(_ conn: NWConnection, host: String) {
        var done = false // queue-confined
        let timeout = DispatchWorkItem { [weak self] in
            guard !done else { return }
            done = true
            self?.reportHandshakeFailure(host, "timeout")
            conn.cancel()
        }
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { conn.cancel(); return }
            switch state {
            case .ready:
                guard !done else { return }
                done = true
                timeout.cancel()
                let info = TLSByteStream.handshakeInfo(conn)
                let stream = TLSByteStream(connection: conn, host: host, sni: info.sni, alpn: info.alpn)
                if let h = self.onAccept { h(stream) } else { stream.close() }
            case .failed(let error), .waiting(let error):
                if !done {
                    done = true
                    timeout.cancel()
                    self.reportHandshakeFailure(host, Self.classify(error))
                }
                conn.cancel()
            case .cancelled:
                if !done {
                    done = true
                    timeout.cancel()
                    self.reportHandshakeFailure(host, "cancelled")
                }
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + handshakeTimeout, execute: timeout)
    }

    /// "cert" (the client rejected our certificate), "closed" (it hung up after seeing it), else "timeout" —
    /// the kinds the retired bridge NativeHandshakeFailed understands.
    static func classify(_ error: NWError) -> String {
        switch error {
        case .tls(let status):
            switch status {
            case errSSLPeerBadCert, errSSLPeerUnsupportedCert, errSSLPeerCertRevoked, errSSLPeerCertExpired,
                 errSSLPeerCertUnknown, errSSLPeerUnknownCA, errSSLPeerAccessDenied, errSSLPeerDecryptError,
                 errSSLBadCert, errSSLUnknownRootCert, errSSLNoRootCert, errSSLXCertChainInvalid:
                return "cert"
            case errSSLClosedAbort, errSSLClosedGraceful, errSSLClosedNoNotify:
                return "closed"
            default:
                return "timeout"
            }
        case .posix(let code) where code == .ECONNRESET || code == .EPIPE || code == .ENOTCONN:
            return "closed"
        default:
            return "timeout"
        }
    }

    // MARK: lifecycle

    var listenerCount: Int { lock.lock(); defer { lock.unlock() }; return listeners.count }

    /// Closes listeners idle > idleClose (call from the tunnel's periodic timer). Open connections are unaffected.
    func sweepIdle(now: Date = Date()) {
        lock.lock()
        let idle = listeners.filter { now.timeIntervalSince($0.value.lastUse) > idleClose }
        for k in idle.keys { listeners.removeValue(forKey: k) }
        lock.unlock()
        for (_, e) in idle { e.listener.cancel() }
    }

    /// Closes every listener and drops cached identities (CA changed / tunnel stopping).
    func reset() {
        lock.lock()
        let all = listeners
        listeners.removeAll()
        lock.unlock()
        for (_, e) in all { e.listener.cancel() }
        identities.cache.removeAll()
    }
}
