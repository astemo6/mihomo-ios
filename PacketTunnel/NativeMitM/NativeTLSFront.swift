// feat/native-mitm STAGE 2 SKELETON — NOT BUILT. project.yml excludes PacketTunnel/NativeMitM/** from every target
// until the Go flow API (work/native-mitm-design.md §4.5) exists and this compiles on CI. Written against the iOS 17
// SDK from documentation; no local Swift compiler was available, so expect small API fixes on first build.
//
// The Go engine keeps the CONNECT front (loop check, SNI peek, MitM host list, pinning memory) and hands a TLS
// connection here only when this front says yes (bridge/mitm/nativeterm.go): Listen(host, alpn) returns the port of a
// per-host loopback NWListener whose TLS identity is the leaf Go signed with the user's CA (LibmihomoMitmLeafIdentity,
// PKCS#12). Go then writes the peeked ClientHello and pipes; if this side never answers, Go falls back to its own TLS.
//
// Why one listener per host: Network.framework fixes a listener's TLS identity at creation and has no public
// per-connection SNI callback. Hosts in use at once are few (tens); idle listeners are closed after 60 s.

import Foundation
import Network
import Security

final class NativeTLSFront: NSObject {
    static let shared = NativeTLSFront()

    private let queue = DispatchQueue(label: "tern.native-mitm.front")
    private let lock = NSLock()
    private var listeners: [String: Entry] = [:]
    private static let idleClose: TimeInterval = 60
    private static let maxListeners = 64

    private final class Entry {
        let listener: NWListener
        var port: UInt16 = 0
        var lastUse = Date()
        init(listener: NWListener) { self.listener = listener }
    }

    static func register() {}

    func listen(_ host: String?, alpn: String?) -> Int64 {
        guard let host, !host.isEmpty else { return 0 }
        // Stage 2 serves HTTP/1.1 only; Go already keeps h2-only (gRPC) clients on its own path.
        lock.lock()
        if let e = listeners[host], e.port != 0 {
            e.lastUse = Date()
            lock.unlock()
            return Int64(e.port)
        }
        let full = listeners.count >= Self.maxListeners
        lock.unlock()
        if full { return 0 }
        guard let identity = Self.identity(for: host) else { return 0 }
        guard let entry = makeListener(host: host, identity: identity) else { return 0 }
        lock.lock()
        listeners[host] = entry
        lock.unlock()
        return Int64(entry.port)
    }

    // MARK: listener

    private func makeListener(host: String, identity: SecIdentity) -> Entry? {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        guard let sid = sec_identity_create(identity) else { return nil }
        sec_protocol_options_set_local_identity(sec, sid)
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
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
                self?.forget(host)
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in
            self?.accept(conn, host: host)
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 1) == .success, entry.port != 0 else {
            listener.cancel()
            return nil
        }
        return entry
    }

    private func forget(_ host: String) {
        lock.lock()
        listeners.removeValue(forKey: host)
        lock.unlock()
    }

    private func accept(_ conn: NWConnection, host: String) {
        var handshook = false
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                handshook = true
                NativeHTTP1Session(connection: conn, host: host).start()
            case .failed(let error):
                if !handshook {
                    NCPinningMemory.shared.pin(host)
                }
                conn.cancel()
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    /// "cert" (the client rejected our certificate), "closed" (hung up after it), else "timeout".
    private static func classify(_ error: NWError) -> String {
        switch error {
        case .tls(let status):
            switch status {
            case errSSLPeerBadCert, errSSLPeerUnsupportedCert, errSSLPeerCertRevoked, errSSLPeerCertExpired,
                 errSSLPeerCertUnknown, errSSLPeerUnknownCA, errSSLPeerAccessDenied, errSSLPeerDecryptError:
                return "cert"
            case errSSLClosedAbort, errSSLClosedGraceful, errSSLClosedNoNotify:
                return "closed"
            default:
                return "timeout"
            }
        case .posix(let code) where code == .ECONNRESET || code == .EPIPE:
            return "closed"
        default:
            return "timeout"
        }
    }

    // MARK: identities

    private static let identityCache = NSCache<NSString, SecIdentityBox>()

    private final class SecIdentityBox {
        let identity: SecIdentity
        init(_ i: SecIdentity) { identity = i }
    }

    /// The leaf identity Go signed for host (PKCS#12, password "tern"; SecPKCS12Import keeps it in memory).
    private static func identity(for host: String) -> SecIdentity? {
        if let box = identityCache.object(forKey: host as NSString) { return box.identity }
        guard let ident = LeafCertIssuer.shared.identity(for: host) else { return nil }
        identityCache.setObject(SecIdentityBox(ident.secIdentity), forKey: host as NSString)
        return ident.secIdentity
    }

    // MARK: idle sweep (call from the tunnel's existing 30 s timer)

    func sweepIdle() {
        let now = Date()
        lock.lock()
        let idle = listeners.filter { now.timeIntervalSince($0.value.lastUse) > Self.idleClose }
        for k in idle.keys { listeners.removeValue(forKey: k) }
        lock.unlock()
        for (_, e) in idle { e.listener.cancel() }
    }
}
