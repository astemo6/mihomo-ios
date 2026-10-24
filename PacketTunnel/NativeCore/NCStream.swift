import Foundation
import Network

/// A single TCP byte stream over NWConnection, with one-shot receives: the
/// caller (handshake code, then the relay pump) chains receive calls, which
/// keeps handshake buffering explicit and avoids competing receive loops.
/// All callbacks arrive on `queue`.
final class NCStream {
    let conn: NWConnection
    let queue: DispatchQueue
    private var cancelled = false

    init(to host: String, port: Int, tls: Bool = false, queue: DispatchQueue) {
        let endpoint: NWEndpoint
        if let v4 = IPv4Address(host) {
            endpoint = .hostPort(host: .ipv4(v4), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        } else if let v6 = IPv6Address(host) {
            endpoint = .hostPort(host: .ipv6(v6), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        } else {
            endpoint = .hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        }
        let params: NWParameters = tls ? .tls : .tcp
        conn = NWConnection(to: endpoint, using: params)
        self.queue = queue
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
