import Foundation
import Network

/// B8 draft (native MitM lane): the upstream side of one intercepted
/// connection.
///
/// Topology (TODO B8): the Swift layer terminates the client's TLS (B7),
/// parses HTTP/1.1 (HTTPMessage.swift), and forwards the exchange to the Go
/// core through its relay listener (`bridge/mitm/relay.go` — a plain-HTTP
/// loopback/App-Group-local endpoint the core already exposes to the
/// extension). Policy, DNS, proxy selection and the TUN stay in the core;
/// this layer never dials the origin itself.
///
/// The protocol is the seam B6 must confirm: today the draft assumes
///   1. one NWConnection to the relay per intercepted connection (no pooling
///      until the relay's keep-alive semantics are pinned down), and
///   2. the relay speaks HTTP/1.1 absolute-form, i.e. the Swift layer sends
///      the request head with the full URL as target and the core routes it.
/// Both are marked `OPEN` in the README.

enum UpstreamError: Error {
    case connectionFailed(Error)
    case connectionClosed
    case cancelled
}

/// A byte pipe to the Go relay. Bodies stream: the body channel (B1–B3)
/// decides how much is buffered for scripts; this layer just moves bytes in
/// order and reports EOF / errors exactly once.
protocol UpstreamConnection: AnyObject {
    /// Queue all sends run on.
    var queue: DispatchQueue { get }
    func start()
    func send(_ data: Data, completion: @escaping (Error?) -> Void)
    /// Deliver received bytes in order; `isComplete` fires once at EOF.
    func receive(onChunk: @escaping (Data) -> Void,
                 onComplete: @escaping (UpstreamError?) -> Void)
    func cancel()
}

final class NWUpstreamConnection: UpstreamConnection {
    let queue = DispatchQueue(label: "tern.nativemitm.upstream")
    private let connection: NWConnection
    private var receiveHandler: ((Data) -> Void)?
    private var completeHandler: ((UpstreamError?) -> Void)?
    private var completed = false

    /// `endpoint` is injected: relay host/port come from the tunnel
    /// configuration at runtime (B6 alignment point), never hard-coded.
    init(endpoint: NWEndpoint) {
        self.connection = NWConnection(to: endpoint, using: .tcp)
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .failed(let err):
                self.finish(.connectionFailed(err))
            case .cancelled:
                self.finish(.cancelled)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed { err in
            completion(err)
        })
    }

    func receive(onChunk: @escaping (Data) -> Void,
                 onComplete: @escaping (UpstreamError?) -> Void) {
        receiveHandler = onChunk
        completeHandler = onComplete
        pump()
    }

    private func pump() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.receiveHandler?(data) }
            if let error {
                self.finish(.connectionFailed(error))
                return
            }
            if isComplete {
                self.finish(nil)
                return
            }
            self.pump()
        }
    }

    func cancel() {
        connection.cancel()
    }

    private func finish(_ error: UpstreamError?) {
        guard !completed else { return }
        completed = true
        completeHandler?(error)
    }
}
