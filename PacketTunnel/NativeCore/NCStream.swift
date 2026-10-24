import Foundation
import Network
import Security

/// A single TCP byte stream over NWConnection, with one-shot receives: the
/// caller (handshake code, then the relay pump) chains receive calls, which
/// keeps handshake buffering explicit and avoids competing receive loops.
/// All callbacks arrive on `queue`.
final class NCStream {
    let conn: NWConnection
    let queue: DispatchQueue
    private var cancelled = false

    init(to host: String, port: Int, tls: Bool = false, queue: DispatchQueue) {
        self.queue = queue
        conn = NWConnection(to: Self.endpoint(host, port: port), using: tls ? .tls : .tcp)
    }

    /// TLS with proxy-protocol options: explicit SNI (servername) and optional
    /// skip-cert-verify, as Trojan/VLESS/VMess configs carry them.
    init(to host: String, port: Int, tlsServerName: String?, allowInsecure: Bool, queue: DispatchQueue) {
        self.queue = queue
        let tlsOptions = NWProtocolTLS.Options()
        if let sni = tlsServerName, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, sni)
        }
        if allowInsecure {
            sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, queue)
        }
        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        conn = NWConnection(to: Self.endpoint(host, port: port), using: params)
    }

    private static func endpoint(_ host: String, port: Int) -> NWEndpoint {
        let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any
        if let v4 = IPv4Address(host) {
            return .hostPort(host: .ipv4(v4), port: p)
        }
        if let v6 = IPv6Address(host) {
            return .hostPort(host: .ipv6(v6), port: p)
        }
        return .hostPort(host: NWEndpoint.Host(host), port: p)
    }

    /// Starts the connection; `ready` fires exactly once (nil error on success).
    func start(ready: @escaping (Error?) -> Void) {
        var fired = false
        conn.stateUpdateHandler = { [weak self] state in
            guard !fired else { return }
            switch state {
            case .ready:
                fired = true
                ready(nil)
            case .failed(let e):
                fired = true
                ready(e)
            case .cancelled:
                fired = true
                ready(NSError(domain: "NativeCore", code: 2, userInfo: [NSLocalizedDescriptionKey: "connection cancelled"]))
            default:
                break
            }
            _ = self
        }
        conn.start(queue: queue)
    }

    func send(_ data: Data) {
        guard !cancelled, !data.isEmpty else { return }
        conn.send(content: data, completion: .idempotent)
    }

    /// One-shot receive of the next chunk. The handler gets nil data on EOF/error.
    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                handler(data, nil)
            } else if isComplete {
                handler(nil, nil)
            } else {
                handler(nil, error)
            }
        }
    }

    func cancel() {
        cancelled = true
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}

/// Growable byte buffer for handshake parsing.
final class NCByteBuffer {
    private(set) var data = Data()
    func append(_ d: Data) { data.append(d) }
    func take(_ n: Int) -> Data {
        let out = Data(data.prefix(n))
        data = data.dropFirst(n)
        return out
    }
    var count: Int { data.count }
    var isEmpty: Bool { data.isEmpty }
}
