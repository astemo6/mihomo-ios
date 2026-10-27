// native-only (nc-integrate): one build of this file — the NativeCore tunnel; the app target compiles the same code
// for its unit tests (tunnel-engine calls behind TERN_TUNNEL). The old-core variant is gone with the retired bridge
// Native MitM stage 2, lane `upstream` (B8b): byte pipe from the native front to the origin.
//
// Raw bytes only: no URLSession, no automatic decompression, no header normalisation. The HTTP lane frames
// requests / responses on top of this stream (design §12.8 items 1–2).
//
// Two ways through the relay:
// - plain (origin without TLS, or a caller that runs its own protocol): a TCP NWConnection to the relay; this
//   type writes the CONNECT head itself (so the relay's optional X-Tern-Policy header can be set) and parses the
//   reply; bytes after the reply's blank line are kept and delivered first.
// - tls (the MitM upstream, iOS 17+): NWConnection to host:port with NWParameters(tls:) and a privacy context
//   whose only proxy is ProxyConfiguration(httpCONNECTProxy: 127.0.0.1:<relay>). Network.framework sends the
//   CONNECT; TLS to the origin uses the system trust store (none when the engine's skip-cert-verify is on), SNI = host
//   (not for IP literals), ALPN "http/1.1" (the native h2 session also offers "h2", s3-h2).
//   iOS 16 has no per-connection CONNECT proxy in Network.framework: `.unsupported` → the caller keeps the old core
//   path for that connection (the same fallback the native front already has).
//
// Credit: built from astemo6's B8 draft (origin/draft/native-mitm-b7b8 6b53dc6, drafts/native-mitm/Upstream.swift):
// its NWConnection receive pump, injected relay endpoint and exactly-once completion are kept. Corrected here:
// the relay only accepts CONNECT, not absolute-form requests, so the draft's "send the head with the
// full URL" seam is replaced by CONNECT + TLS-to-origin; the draft's .waiting state was ignored (an open could
// hang on a dead relay) — now an open fails on .waiting and has a connect timeout; the receive handler
// re-pumped without back-pressure — now reads are pull-based (read(min,max)); a cancel after a send could
// leave sends un-errored — writes after close report .closed; one-connection-per-flow → bounded keep-alive pool.
//
// Threading: every method may be called from any queue; all state lives on `queue` (shared with the pool) and
// every completion is delivered on `queue`, never synchronously from the call.

import Foundation
import Network
import Security

/// The byte-stream half of the stage-2 contract (work/native-s2-lanes.md: `ByteStream { read(min,max); write;
/// close }`). Declared here under a lane-local name so this lane builds before S2Contract.swift exists; at
/// integration `extension UpstreamConnection: ByteStream {}` (or a typealias) maps it — the signatures are the
/// contract's.
protocol UpstreamByteStream: AnyObject {
    /// Delivers at least `min` bytes (fewer only right before EOF), at most `max`. `(nil, true, nil)` = EOF.
    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func write(_ data: Data, completion: @escaping (Error?) -> Void)
    /// Half-close: sends FIN (TLS: close_notify + FIN); reads keep working until the peer's EOF.
    func shutdownWrite(completion: @escaping (Error?) -> Void)
    /// Tears the connection down; a pending read completes with `UpstreamError.closed`.
    func close()
}

enum UpstreamError: Error, Equatable, CustomStringConvertible {
    case relayUnavailable                    // relay not running
    case invalidTarget(String)               // CR/LF/space in host or policy, port 0
    case unsupported(String)                 // tls through the relay needs iOS 17
    case connectFailed(String)               // NWConnection failed / waiting while opening (incl. TLS errors)
    case proxyRefused(status: Int, reason: String) // relay answered non-2xx (502 + X-Tern-Error = dial failed)
    case malformedProxyReply
    case timeout
    case cancelled
    case closed
    case io(String)

    var description: String {
        switch self {
        case .relayUnavailable: return "relay not running"
        case .invalidTarget(let s): return "invalid target: \(s)"
        case .unsupported(let s): return "unsupported: \(s)"
        case .connectFailed(let s): return "connect failed: \(s)"
        case .proxyRefused(let st, let r): return "relay refused \(st)" + (r.isEmpty ? "" : ": \(r)")
        case .malformedProxyReply: return "malformed relay reply"
        case .timeout: return "connect timeout"
        case .cancelled: return "cancelled"
        case .closed: return "closed"
        case .io(let s): return "io: \(s)"
        }
    }
}

/// Where one upstream connection goes. `policy` becomes the relay's X-Tern-Policy header (plain mode only;
/// Network.framework's CONNECT cannot carry extra headers, so tls mode always goes through the user's rules).
struct UpstreamTarget: Hashable, CustomStringConvertible {
    let host: String
    let port: UInt16
    let tls: Bool
    let policy: String?
    /// MitM skip-cert-verify: origin certificates are not verified.
    let skipVerify: Bool

    init(host: String, port: UInt16, tls: Bool = true, policy: String? = nil, skipVerify: Bool = false) {
        // "[::1]" → "::1": the authority form adds the brackets back.
        if host.hasPrefix("["), host.hasSuffix("]") { self.host = String(host.dropFirst().dropLast()) } else { self.host = host }
        self.port = port
        self.tls = tls
        self.policy = policy
        self.skipVerify = skipVerify
    }

    var isIPLiteral: Bool { IPv4Address(host) != nil || IPv6Address(host) != nil }
    var authority: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    var description: String { (tls ? "tls://" : "tcp://") + authority + (policy.map { " via \($0)" } ?? "") }

    func validate() -> UpstreamError? {
        func bad(_ s: String) -> Bool { s.unicodeScalars.contains { $0.value < 0x21 || $0.value == 0x7f } }
        if host.isEmpty || bad(host) || host.contains("/") { return .invalidTarget("host") }
        if port == 0 { return .invalidTarget("port") }
        if let p = policy, p.isEmpty || p.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) {
            return .invalidTarget("policy")
        }
        return nil
    }
}

final class UpstreamConnection: UpstreamByteStream, CustomStringConvertible {
    let target: UpstreamTarget
    let id: UInt64
    let queue: DispatchQueue
    /// Set by the pool: true when this connection already served a request (a failure before the first response
    /// byte on a reused connection is the caller's cue to retry an idempotent request on a fresh one, as the old core does).
    var reused = false
    var requestsServed = 0
    /// ALPN the origin picked (tls mode; nil when the server sent none).
    private(set) var negotiatedALPN: String?
    /// ALPN offered to the origin (tls mode): "http/1.1" for the stage-2 session; "h2", "http/1.1" for the native
    /// h2 session (H2/H2Upstream.swift), which then speaks whichever the origin picked.
    private(set) var offeredALPN: [String] = ["http/1.1"]

    private let conn: NWConnection
    private let relayPort: UInt16
    private var opened = false
    private var closed = false
    private var writeShut = false
    private var eof = false
    private var readError: Error?
    private var buffer = Data()
    private var receiving = false
    private var waiter: (min: Int, max: Int, completion: (Data?, Bool, Error?) -> Void)?
    private var openCompletion: ((Result<UpstreamConnection, UpstreamError>) -> Void)?
    private var timeoutItem: DispatchWorkItem?
    private var replyHead = Data()

    // Pool hooks (queue-confined).
    internal var isIdle = false
    internal var onIdleEvent: ((UpstreamConnection) -> Void)?

    static let maxReplyHead = 16 * 1024
    static let defaultReadMax = 64 * 1024

    var description: String { "upstream#\(id) \(target)" }

    /// True while the connection can carry another request: open, both directions up, nothing unread.
    var isReusable: Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        return opened && !closed && !writeShut && !eof && readError == nil && buffer.isEmpty && waiter == nil
    }

    private init(target: UpstreamTarget, relayPort: UInt16, queue: DispatchQueue, id: UInt64, conn: NWConnection) {
        self.target = target
        self.relayPort = relayPort
        self.queue = queue
        self.id = id
        self.conn = conn
    }

    deinit { conn.cancel() }

    /// The relay's CONNECT proxy context. feat/native-slim: one per relay port (was one per connection; a context
    /// carries its own proxy / resolver / TLS session state, and 100 of them stayed around after a burst).
    @available(iOS 17.0, macOS 14.0, *)
    static func privacyContext(relay: NWEndpoint.Port) -> NWParameters.PrivacyContext {
        func make() -> NWParameters.PrivacyContext {
            let ctx = NWParameters.PrivacyContext(description: "tern.nativemitm.upstream")
            ctx.proxyConfigurations = [ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: relay), tlsOptions: nil)]
            return ctx
        }
        guard NativeMitmRuntime.slim.sharedPrivacyContext else { return make() }
        ctxLock.lock(); defer { ctxLock.unlock() }
        if let c = sharedContext, c.port == relay.rawValue, let ctx = c.ctx as? NWParameters.PrivacyContext { return ctx }
        let ctx = make()
        sharedContext = (relay.rawValue, ctx)
        return ctx
    }
    private static let ctxLock = NSLock()
    private static var sharedContext: (port: UInt16, ctx: AnyObject)?

    /// Opens a connection to `target` through the relay on 127.0.0.1:`relayPort`. The returned object can be
    /// `close()`d to abort the open (completion then reports `.cancelled`). Completion runs once, on `queue`.
    @discardableResult
    static func open(target: UpstreamTarget, relayPort: Int, queue: DispatchQueue, id: UInt64,
                     connectTimeout: TimeInterval, alpn: [String] = ["http/1.1"],
                     completion: @escaping (Result<UpstreamConnection, UpstreamError>) -> Void) -> UpstreamConnection? {
        if let err = target.validate() {
            queue.async { completion(.failure(err)) }
            return nil
        }
        guard relayPort != 0 else {
            queue.async { completion(.failure(.relayUnavailable)) }
            return nil
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let nw: NWConnection
        guard let oport = NWEndpoint.Port(rawValue: target.port) else {
            queue.async { completion(.failure(.invalidTarget("port"))) }
            return nil
        }
        if relayPort > 0 {
            guard relayPort <= 65535, let rport = NWEndpoint.Port(rawValue: UInt16(relayPort)) else {
                queue.async { completion(.failure(.relayUnavailable)) }
                return nil
            }
            if target.tls {
                guard #available(iOS 17.0, macOS 14.0, *) else {
                    queue.async { completion(.failure(.unsupported("TLS through the relay needs iOS 17"))) }
                    return nil
                }
                let tls = NWProtocolTLS.Options()
                let sec = tls.securityProtocolOptions
                if !target.isIPLiteral { sec_protocol_options_set_tls_server_name(sec, target.host) }
                for p in alpn { sec_protocol_options_add_tls_application_protocol(sec, p) }
                if target.skipVerify {
                    sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, queue)
                }
                let params = NWParameters(tls: tls, tcp: tcp)
                params.setPrivacyContext(Self.privacyContext(relay: rport))
                nw = NWConnection(host: NWEndpoint.Host(target.host), port: oport, using: params)
            } else {
                nw = NWConnection(host: "127.0.0.1", port: rport, using: NWParameters(tls: nil, tcp: tcp))
            }
        } else {
            // Direct native connection
            if target.tls {
                let tls = NWProtocolTLS.Options()
                let sec = tls.securityProtocolOptions
                if !target.isIPLiteral { sec_protocol_options_set_tls_server_name(sec, target.host) }
                for p in alpn { sec_protocol_options_add_tls_application_protocol(sec, p) }
                if target.skipVerify {
                    sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, queue)
                }
                nw = NWConnection(host: NWEndpoint.Host(target.host), port: oport, using: NWParameters(tls: tls, tcp: tcp))
            } else {
                nw = NWConnection(host: NWEndpoint.Host(target.host), port: oport, using: NWParameters(tls: nil, tcp: tcp))
            }
        }
        let c = UpstreamConnection(target: target, relayPort: relayPort > 0 ? UInt16(relayPort) : 0, queue: queue, id: id, conn: nw)
        c.offeredALPN = alpn
        c.openCompletion = completion
        nw.stateUpdateHandler = { [weak c] st in c?.handleState(st) }
        let t = DispatchWorkItem { [weak c] in c?.finishOpen(.failure(.timeout)) }
        c.timeoutItem = t
        queue.asyncAfter(deadline: .now() + connectTimeout, execute: t)
        nw.start(queue: queue)
        return c
    }

    // MARK: open

    private func handleState(_ st: NWConnection.State) {
        switch st {
        case .ready:
            if openCompletion == nil { return }
            if target.tls {
                if let meta = conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata,
                   let p = sec_protocol_metadata_get_negotiated_protocol(meta.securityProtocolMetadata) {
                    negotiatedALPN = String(cString: p)
                }
                if let a = negotiatedALPN, !offeredALPN.contains(a) {
                    finishOpen(.failure(.connectFailed("origin chose ALPN \(a)")))
                    return
                }
                finishOpen(.success(self))
            } else {
                if relayPort > 0 {
                    sendConnect()
                } else {
                    finishOpen(.success(self))
                }
            }
        case .waiting(let err):
            // Loopback relay: waiting means refused / unreachable; don't sit in Network's retry loop.
            if openCompletion != nil { finishOpen(.failure(.connectFailed(String(describing: err)))) }
        case .failed(let err):
            if openCompletion != nil {
                finishOpen(.failure(.connectFailed(String(describing: err))))
            } else {
                if readError == nil { readError = UpstreamError.io(String(describing: err)) }
                closed = true
                ioEvent()
            }
        case .cancelled:
            if openCompletion != nil { finishOpen(.failure(.cancelled)) }
            closed = true
            ioEvent()
        default:
            break
        }
    }

    private func sendConnect() {
        var head = "CONNECT \(target.authority) HTTP/1.1\r\nHost: \(target.authority)\r\n"
        if let p = target.policy { head += "X-Tern-Policy: \(p)\r\n" }
        head += "\r\n"
        conn.send(content: Data(head.utf8), completion: .contentProcessed { [weak self] err in
            guard let self, let err else { return }
            self.finishOpen(.failure(.connectFailed(String(describing: err))))
        })
        readReply()
    }

    private func readReply() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, done, err in
            guard let self, self.openCompletion != nil else { return }
            if let data { self.replyHead.append(data) }
            if let r = self.replyHead.range(of: Data([13, 10, 13, 10])) {
                let head = self.replyHead.subdata(in: self.replyHead.startIndex..<r.upperBound)
                self.buffer = self.replyHead.subdata(in: r.upperBound..<self.replyHead.endIndex)
                self.replyHead = Data()
                self.finishOpen(Self.parseReply(head).map { _ in self })
                return
            }
            if let err {
                self.finishOpen(.failure(.connectFailed(String(describing: err))))
            } else if done {
                self.finishOpen(.failure(.malformedProxyReply))
            } else if self.replyHead.count > Self.maxReplyHead {
                self.finishOpen(.failure(.malformedProxyReply))
            } else {
                self.readReply()
            }
        }
    }

    /// Parses the relay's reply head ("HTTP/1.1 200 Connection established\r\n\r\n"); any 2xx is success.
    static func parseReply(_ head: Data) -> Result<Void, UpstreamError> {
        let text = String(decoding: head, as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        let parts = (lines.first ?? "").split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/1."), let status = Int(parts[1]), (100...999).contains(status) else {
            return .failure(.malformedProxyReply)
        }
        if (200...299).contains(status) { return .success(()) }
        var reason = parts.count > 2 ? String(parts[2]) : ""
        for l in lines.dropFirst() {
            guard let colon = l.firstIndex(of: ":") else { continue }
            if l[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "x-tern-error" {
                reason = l[l.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        return .failure(.proxyRefused(status: status, reason: reason))
    }

    private func finishOpen(_ r: Result<UpstreamConnection, UpstreamError>) {
        guard let cb = openCompletion else { return }
        openCompletion = nil
        timeoutItem?.cancel()
        timeoutItem = nil
        switch r {
        case .success:
            opened = true
        case .failure:
            closed = true
            conn.cancel()
        }
        cb(r)
    }

    // MARK: ByteStream

    func read(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async { self.readOnQueue(min: min, max: max, completion: completion) }
    }

    private func readOnQueue(min: Int, max: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        if waiter != nil { return completion(nil, false, UpstreamError.io("concurrent read")) }
        if !opened, buffer.isEmpty { return completion(nil, false, closed ? UpstreamError.closed : UpstreamError.io("not open")) }
        let lo = Swift.max(1, min)
        waiter = (lo, Swift.max(lo, max), completion)
        serviceWaiter()
    }

    private func serviceWaiter() {
        guard let w = waiter else { return }
        let finished = eof || readError != nil || closed
        if buffer.count >= w.min || (finished && !buffer.isEmpty) {
            let n = Swift.min(buffer.count, w.max)
            let out = buffer.prefix(n)
            buffer = Data(buffer.dropFirst(n))
            waiter = nil
            w.completion(Data(out), eof && buffer.isEmpty, nil)
            return
        }
        if finished {
            waiter = nil
            if eof { w.completion(nil, true, nil) } else { w.completion(nil, false, readError ?? UpstreamError.closed) }
            return
        }
        pump(min: w.min - buffer.count, max: w.max - buffer.count)
    }

    private func pump(min: Int, max: Int) {
        guard !receiving, !closed, !eof, readError == nil else { return }
        receiving = true
        conn.receive(minimumIncompleteLength: Swift.max(1, min), maximumLength: Swift.max(1, min, max)) {
            [weak self] data, _, done, err in
            guard let self else { return }
            self.receiving = false
            if let data, !data.isEmpty { self.buffer.append(data) }
            if done { self.eof = true }
            if let err, !self.eof, !self.closed { self.readError = UpstreamError.io(String(describing: err)) }
            self.ioEvent()
        }
    }

    /// Something changed on the read side (data, EOF, error, cancel).
    private func ioEvent() {
        if isIdle, waiter == nil {
            // Idle in the pool: any byte, EOF or error means the connection is no longer reusable.
            if !buffer.isEmpty || eof || readError != nil || closed { onIdleEvent?(self) }
            return
        }
        serviceWaiter()
    }

    /// Pool: keep one receive outstanding while idle so a server-side close (or stray bytes) is noticed and the
    /// connection leaves the pool instead of failing the next request.
    func startIdleProbe() {
        dispatchPrecondition(condition: .onQueue(queue))
        pump(min: 1, max: Self.defaultReadMax)
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async {
            guard self.opened, !self.closed else { return completion(UpstreamError.closed) }
            guard !self.writeShut else { return completion(UpstreamError.io("write after shutdown")) }
            if data.isEmpty { return completion(nil) }
            self.conn.send(content: data, completion: .contentProcessed { err in
                completion(err.map { UpstreamError.io(String(describing: $0)) })
            })
        }
    }

    func shutdownWrite(completion: @escaping (Error?) -> Void) {
        queue.async {
            guard self.opened, !self.closed else { return completion(UpstreamError.closed) }
            if self.writeShut { return completion(nil) }
            self.writeShut = true
            self.conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { err in
                completion(err.map { UpstreamError.io(String(describing: $0)) })
            })
        }
    }

    func close() {
        queue.async { self.closeOnQueue() }
    }

    func closeOnQueue() {
        if openCompletion != nil { finishOpen(.failure(.cancelled)); return }
        if !closed && opened { NativeMitmRuntime.noteChurn() }
        closed = true
        isIdle = false
        onIdleEvent = nil
        conn.cancel() // idempotent; also releases a connection that already failed
        if let w = waiter {
            waiter = nil
            w.completion(nil, false, UpstreamError.closed)
        }
    }
}
