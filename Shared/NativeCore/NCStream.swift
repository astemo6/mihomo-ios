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
        // Gap D2: bound to the physical interface while includeAllNetworks is on (NCOutboundBinding).
        conn = NWConnection(to: Self.endpoint(host, port: port), using: NCOutboundBinding.params(tls ? .tls : .tcp, host: host))
    }

    /// TLS with proxy-protocol options: explicit SNI (servername) and optional
    /// skip-cert-verify, as Trojan/VLESS/VMess configs carry them.
    /// `alpn` (feat/nc-xhttp): ALPN protocols to offer — XHTTP needs "h2"; empty keeps the system default.
    init(to host: String, port: Int, tlsServerName: String?, allowInsecure: Bool, alpn: [String] = [],
         queue: DispatchQueue) {
        self.queue = queue
        let tlsOptions = NWProtocolTLS.Options()
        for p in alpn { sec_protocol_options_add_tls_application_protocol(tlsOptions.securityProtocolOptions, p) }
        if let sni = tlsServerName, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, sni)
        }
        if allowInsecure {
            sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, queue)
        }
        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        NCOutboundBinding.apply(params, host: host)
        conn = NWConnection(to: Self.endpoint(host, port: port), using: params)
    }

    /// Caller-built parameters (feat/nc-brook: wss with ALPN http/1.1 + a custom CA anchor). The physical-interface
    /// binding is applied here like every other init.
    init(to host: String, port: Int, parameters: NWParameters, queue: DispatchQueue) {
        self.queue = queue
        NCOutboundBinding.apply(parameters, host: host)
        conn = NWConnection(to: Self.endpoint(host, port: port), using: parameters)
    }

    static func endpoint(_ host: String, port: Int) -> NWEndpoint {
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
    ///
    /// fix/nc-delay-test: when the queue carries an NCDialTrace (a delay probe), the connect is traced (DNS / TCP /
    /// TLS split from NWConnection's establishment report) and `.waiting` fails at once with its reason, the way a Go
    /// dial returns its error — before, a probe whose DNS or route failed sat in `.waiting` until the probe timeout and
    /// was reported as a bare 超时. Real flows keep NWConnection's waiting behaviour; a slow one (≥ slowDialMs) gets
    /// one rate-limited `[dial]` line with the same split.
    func start(ready: @escaping (Error?) -> Void) {
        var fired = false
        let trace = NCDialTrace.on(queue)
        let t0 = DispatchTime.now()
        let connectStartMs = trace?.elapsedMs ?? 0
        trace?.begin("connect")
        let label = Self.label(conn.endpoint)
        conn.stateUpdateHandler = { [weak self] state in
            guard !fired else { return }
            switch state {
            case .ready:
                fired = true
                let total = NCDialTrace.ms(from: t0, to: .now())
                if let trace {
                    trace.end("connect")
                    self?.conn.requestEstablishmentReport(queue: self?.queue ?? .global()) { report in
                        if let report { trace.absorb(report, connectStartMs: connectStartMs) }
                    }
                } else if total >= Self.slowDialMs, NCDialTrace.logSink != nil, let conn = self?.conn {
                    Self.logSlowDial(conn: conn, label: label, totalMs: total)
                }
                ready(nil)
            case .waiting(let e) where trace != nil:
                fired = true
                trace?.end("connect", error: e)
                trace?.connectFailed(e)
                trace?.fail("connect \(label): \(NCDialTrace.describe(e)) (waiting: no route / DNS failure)")
                ready(e)
            case .failed(let e):
                fired = true
                trace?.end("connect", error: e)
                trace?.connectFailed(e)
                trace?.fail("connect \(label): \(NCDialTrace.describe(e))")
                ready(e)
            case .cancelled:
                fired = true
                trace?.end("connect")
                ready(NSError(domain: "NativeCore", code: 2, userInfo: [NSLocalizedDescriptionKey: "connection cancelled"]))
            default:
                break
            }
            _ = self
        }
        conn.start(queue: queue)
    }

    /// Real dials slower than this get a `[dial]` diagnostic line (rate-limited).
    static let slowDialMs = 500
    private static let slowDialLimiter = NCLineLimiter(perWindow: 5, window: 1)

    private static func label(_ e: NWEndpoint) -> String {
        if case .hostPort(let host, let port) = e {
            switch host {
            case .name(let n, _): return "\(n):\(port)"
            case .ipv4(let a): return "\(a):\(port)"
            case .ipv6(let a): return "[\(a)]:\(port)"
            @unknown default: return "\(e)"
            }
        }
        return "\(e)"
    }

    private static func logSlowDial(conn: NWConnection, label: String, totalMs: Int) {
        let (ok, dropped) = slowDialLimiter.admit()
        guard ok else { return }
        conn.requestEstablishmentReport(queue: .global(qos: .utility)) { report in
            guard let sink = NCDialTrace.logSink else { return }
            if dropped > 0 { sink("[dial] \(dropped) slow-dial line(s) suppressed", false) }
            let t = NCDialTrace()
            if let report { t.absorb(report, connectStartMs: 0) }
            let split = t.summary
            sink("[dial] \(label) ready in \(totalMs) ms" + (split.isEmpty ? "" : ": " + split), false)
        }
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
/// `data` is always a rebased Data (startIndex 0): callers index it absolutely (`data[3]`), and a `dropFirst`
/// slice would keep the old indices and trap / misread (rv2-proto). Handshake buffers are tiny, so the copy is free.
final class NCByteBuffer {
    private(set) var data = Data()
    func append(_ d: Data) { data.append(d) }
    func take(_ n: Int) -> Data {
        let n = max(0, min(n, data.count))
        let out = Data(data.prefix(n))
        data = n >= data.count ? Data() : Data(data.dropFirst(n))
        return out
    }
    var count: Int { data.count }
    var isEmpty: Bool { data.isEmpty }
}

/// Fires a completion at most once and arms a deadline that cancels `raw` when the handshake stalls
/// (slowloris guard for SOCKS5 / HTTP CONNECT handshakes, rv2-proto). Use on the stream's queue.
final class NCHandshakeDeadline {
    private var completion: ((NCRelayStream?, Error?) -> Void)?
    private var timer: DispatchWorkItem?

    init(queue: DispatchQueue, seconds: TimeInterval, raw: NCRelayStream, what: String,
         completion: @escaping (NCRelayStream?, Error?) -> Void) {
        self.completion = completion
        // Strong self: the work item keeps the deadline alive until it fires or finish() cancels it.
        let t = DispatchWorkItem { [weak raw] in
            guard self.completion != nil else { return }
            raw?.cancel()
            self.finish(nil, NSError(domain: "NativeCore", code: 4,
                                     userInfo: [NSLocalizedDescriptionKey: "\(what) handshake timeout"]))
        }
        timer = t
        queue.asyncAfter(deadline: .now() + seconds, execute: t)
    }

    var isDone: Bool { completion == nil }

    func finish(_ stream: NCRelayStream?, _ error: Error?) {
        guard let c = completion else { return }
        completion = nil
        timer?.cancel()
        timer = nil
        c(stream, error)
    }
}

/// Send-side flow control (see NCRelayStream.send(_:completion:)): completes once NWConnection processed the bytes.
extension NCStream {
    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !data.isEmpty else { queue.async(execute: completion); return }
        // After cancel() NWConnection completes the send with an error at once: the caller still gets its callback.
        conn.send(content: data, completion: .contentProcessed { _ in completion() })
    }
}
