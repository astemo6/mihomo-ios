import Foundation
import Network
import Security

/// fix/nc-mitm-live: proves, from inside the packet tunnel, that the native MitM front works end to end — the
/// loopback TLS listener accepts (build 395 showed an NWListener that was `.ready` but never delivered a connection
/// in this process), a leaf can be issued from the CA, the TLS handshake completes — and whether iOS trusts the CA
/// (the system trust store the apps use, user-installed profiles included). One line in the startup log at +15 s:
///   `MITM self-probe: front TLS handshake ok in 38 ms; CA trusted by iOS: yes`
///   `MITM self-probe: FAILED — no TLS answer from the front in 5 s (loopback listener not accepting)`
enum NCMitmSelfProbe {
    static let host = "tern-selfprobe.invalid"

    static func run(timeout: TimeInterval = 5, completion: @escaping (String) -> Void) {
        guard MitmTLSFront.shared.onAccept != nil else {
            completion("native front not installed (iOS 17+ required) — MitM off")
            return
        }
        let port = MitmTLSFront.shared.listen(host: host, alpn: "http/1.1")
        guard port > 0, let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            completion("FAILED — the front declined (no CA / leaf could not be issued / listener did not start)")
            return
        }
        let queue = DispatchQueue(label: "nc.mitm-selfprobe")
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(sec, host)
        sec_protocol_options_add_tls_application_protocol(sec, "http/1.1")
        var trusted: Bool?
        var trustError = ""
        sec_protocol_options_set_verify_block(sec, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            // The leaf names `host`; the policy is for that name, so this answers "does iOS trust the Tern CA".
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
            var err: CFError?
            trusted = SecTrustEvaluateWithError(trust, &err)
            if let err { trustError = (err as Error).localizedDescription }
            complete(true) // the probe checks the handshake either way
        }, queue)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let conn = NWConnection(host: "127.0.0.1", port: nwPort, using: params)
        let start = DispatchTime.now()
        var done = false
        func finish(_ line: String) {
            guard !done else { return }
            done = true
            conn.cancel()
            completion(line)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ms = (DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds) / 1_000_000
                let t: String
                switch trusted {
                case .some(true): t = "yes"
                case .some(false): t = "NO (\(trustError.prefix(120))) — install the Tern certificate and enable full trust in 设置 → 通用 → 关于本机 → 证书信任设置"
                case .none: t = "unknown"
                }
                finish("front TLS handshake ok in \(ms) ms; CA trusted by iOS: \(t)")
            case .failed(let e):
                finish("FAILED — handshake with the front: \(e)")
            case .waiting(let e):
                finish("FAILED — front not reachable on 127.0.0.1:\(port): \(e)")
            default:
                break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            finish("FAILED — no TLS answer from the front in \(Int(timeout)) s (loopback listener not accepting?)")
        }
    }
}
