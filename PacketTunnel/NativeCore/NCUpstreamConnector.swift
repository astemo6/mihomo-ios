import Foundation
import Network

/// Pure Swift upstream connector using NCConnector and NCStream.
/// Replaces the Go HTTP CONNECT loopback relay (bridge/mitm/relay.go).
final class NCUpstreamConnector: MitmUpstreamConnecting {
    static let shared: NCUpstreamConnector = {
        let c = NCUpstreamConnector()
        UpstreamPoolConnector.nativeConnector = c
        return c
    }()

    func open(host: String, port: Int, tls: Bool, completion: @escaping (Result<MitmUpstreamLease, Error>) -> Void) {
        let queue = DispatchQueue(label: "nc.upstream.dial", qos: .userInitiated)
        let target = NCTarget(host: host, port: port)

        let resolution: NCGroupEngine.Resolution = {
            if let engine = NativeCoreEngine.active {
                let ctx = engine.matchContext(domain: host, ip: NCIP(host), dstPort: port, network: "tcp")
                return engine.resolve(ctx)
            }
            return .direct
        }()

        if case .reject = resolution {
            completion(.failure(UpstreamError.proxyRefused(status: 403, reason: "rejected by rule")))
            return
        }

        // Direct connection path:
        if case .direct = resolution {
            let stream = tls
                ? NCStream(to: host, port: port, tlsServerName: host, allowInsecure: false, queue: queue)
                : NCStream(to: host, port: port, queue: queue)
            stream.start { err in
                if let err {
                    completion(.failure(UpstreamError.connectFailed(err.localizedDescription)))
                } else {
                    let lease = NCRelayUpstreamLease(stream: stream, queue: queue)
                    completion(.success(lease))
                }
            }
            return
        }

        // Proxy connection path via NCConnector:
        NCConnector.connect(target: target, resolution: resolution, queue: queue) { relayStream, err in
            guard let relayStream else {
                completion(.failure(UpstreamError.connectFailed(err?.localizedDescription ?? "connector failed")))
                return
            }
            guard tls else {
                completion(.success(NCRelayUpstreamLease(relay: relayStream, queue: queue)))
                return
            }
            // The proxy relays raw bytes: the origin TLS session runs on top of it
            // (the direct path gets TLS from NCStream/Network.framework).
            let tlsStream = NCTLSClientStream(raw: relayStream,
                                              config: .init(serverName: host, alpn: ["http/1.1"]),
                                              queue: queue)
            tlsStream.startHandshake { err in
                if let err {
                    tlsStream.cancel()
                    completion(.failure(UpstreamError.connectFailed("upstream TLS: \(err)")))
                } else {
                    completion(.success(NCRelayUpstreamLease(relay: tlsStream, queue: queue)))
                }
            }
        }
    }
}

final class NCRelayUpstreamLease: MitmUpstreamLease {
    let stream: ByteStream

    init(stream: NCStream, queue: DispatchQueue) {
        self.stream = NCStreamByteStream(stream: stream, queue: queue)
    }

    init(relay: NCRelayStream, queue: DispatchQueue) {
        self.stream = NCRelayByteStream(relay: relay, queue: queue)
    }

    func release(reusable: Bool) {
        if !reusable {
            stream.close()
        }
    }
}

final class NCStreamByteStream: ByteStream {
    private let stream: NCStream
    private let queue: DispatchQueue
    private var closed = false
    private var buffer = Data()

    init(stream: NCStream, queue: DispatchQueue) {
        self.stream = stream
        self.queue = queue
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            if !self.buffer.isEmpty {
                let n = Swift.min(self.buffer.count, max)
                let chunk = self.buffer.prefix(n)
                self.buffer.removeFirst(n)
                completion(Data(chunk), false, nil)
                return
            }
            if self.closed {
                completion(nil, true, nil)
                return
            }
            self.stream.receive { [weak self] data, error in
                guard let self else { completion(nil, true, nil); return }
                if let error {
                    completion(nil, false, error)
                } else if let data, !data.isEmpty {
                    if data.count > max {
                        self.buffer.append(data.dropFirst(max))
                        completion(Data(data.prefix(max)), false, nil)
                    } else {
                        completion(data, false, nil)
                    }
                } else {
                    self.closed = true
                    completion(nil, true, nil)
                }
            }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        stream.send(data)
        queue.async { completion(nil) }
    }

    func closeWrite() {}

    func close() {
        closed = true
        stream.cancel()
    }
}

final class NCRelayByteStream: ByteStream {
    private let relay: NCRelayStream
    private let queue: DispatchQueue
    private var closed = false
    private var buffer = Data()

    init(relay: NCRelayStream, queue: DispatchQueue) {
        self.relay = relay
        self.queue = queue
    }

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async {
            if !self.buffer.isEmpty {
                let n = Swift.min(self.buffer.count, max)
                let chunk = self.buffer.prefix(n)
                self.buffer.removeFirst(n)
                completion(Data(chunk), false, nil)
                return
            }
            if self.closed {
                completion(nil, true, nil)
                return
            }
            self.relay.receive { [weak self] data, error in
                guard let self else { completion(nil, true, nil); return }
                if let error {
                    completion(nil, false, error)
                } else if let data, !data.isEmpty {
                    if data.count > max {
                        self.buffer.append(data.dropFirst(max))
                        completion(Data(data.prefix(max)), false, nil)
                    } else {
                        completion(data, false, nil)
                    }
                } else {
                    self.closed = true
                    completion(nil, true, nil)
                }
            }
        }
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        relay.send(data)
        queue.async { completion(nil) }
    }

    func closeWrite() {}

    func close() {
        closed = true
        relay.cancel()
    }
}
