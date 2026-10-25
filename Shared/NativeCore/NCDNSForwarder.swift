import Foundation
import Network

// nc-lifecycle (evidence rework): NCDNSForwarder moved verbatim from
// PacketTunnel/NativeCore/NCUDPSessions.swift to Shared — the #131 pattern.
// NativeCoreEngine owns a forwarder instance for rule resolution, and the
// engine is compiled into the app target for unit tests (see project.yml),
// which requires every engine dependency to live in Shared. The class only
// ever depended on Shared types (NCDNSUpstreamCoordinator, NCOutboundBinding,
// Data helpers) plus Network.framework. Behavior unchanged; the data plane
// and the engine see the exact same type through the same name/signatures.

/// One-shot upstream DNS forwarding over UDP, with TCP retry on truncation.
/// Used for queries the fake-IP responder declines (filter hosts, non-A types).
final class NCDNSForwarder {
    private let queue: DispatchQueue

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    func forward(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        // nc-dns: identical in-flight queries coalesce and the global upstream cap applies
        // (see NCDNSUpstreamCoordinator); the one-shot UDP exchange is forwardUDPOnce.
        NCDNSUpstreamCoordinator.shared.submit(
            key: "udp://\(server):\(port)|" + Self.mergeKeySuffix(query),
            id: Self.transactionID(query), callerQueue: queue,
            execute: { [weak self] done in
                guard let self else { done(nil); return }
                self.forwardUDPOnce(query, server: server, port: port, completion: done)
            }, completion: completion)
    }

    static func transactionID(_ query: Data) -> UInt16? {
        guard query.count >= 2 else { return nil }
        return UInt16(query[0]) << 8 | UInt16(query[1])
    }

    /// Coalescing key material: the whole wire query minus its transaction ID — two queries
    /// merge only when flags, question and additional (EDNS) bytes are all identical.
    static func mergeKeySuffix(_ query: Data) -> String {
        Data(query.dropFirst(min(2, query.count))).base64EncodedString()
    }

    private func forwardUDPOnce(_ query: Data, server: String, port: Int = 53, completion: @escaping (Data?) -> Void) {
        let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any
        let conn = NWConnection(host: NWEndpoint.Host(server), port: nwPort, using: NCOutboundBinding.params(.udp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: query, completion: .contentProcessed { _ in
                    conn.receiveMessage { data, _, _, _ in
                        guard let data else {
                            finish(nil)
                            return
                        }
                        // Truncated bit (TC) set: retry over TCP like resolvers do.
                        if data.count > 2, data[2] & 0x02 != 0 {
                            Self.forwardTCP(query, server: server, port: port, queue: self.queue) { finish($0 ?? data) }
                        } else {
                            finish(data)
                        }
                    }
                })
            case .failed:
                finish(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }

    static func forwardTCP(_ query: Data, server: String, port: Int = 53, queue: DispatchQueue, completion: @escaping (Data?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any, using: NCOutboundBinding.params(.tcp, host: server))
        var done = false
        func finish(_ data: Data?) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(data)
        }
        conn.stateUpdateHandler = { state in
            if case .ready = state {
                var framed = Data()
                framed.appendBE16(UInt16(query.count))
                framed.append(query)
                conn.send(content: framed, completion: .contentProcessed { _ in
                    conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { lenData, _, _, _ in
                        guard let lenData, lenData.count == 2 else { finish(nil); return }
                        let len = Int(lenData[0]) << 8 | Int(lenData[1])
                        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, _ in
                            finish(data)
                        }
                    }
                })
            } else if case .failed = state {
                finish(nil)
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 5) { finish(nil) }
    }
}
