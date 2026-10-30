import XCTest
import Network
import Security
@testable import Tern

/// THROWAWAY probe-branch diagnostics (verify/kit-juicity only, never merged):
/// dials the real kit juicity-server (zhiheng 45.92.159.155:24033) three ways and
/// NSLog-logs every state transition so the xcresult stdout localizes the hang:
///  A) raw NWConnectionGroup QUIC + uni auth stream + bidi TCP stream, by hand;
///  B) NCConnector.connect through the production NCJuicityConnection;
///  C) TUIC control through the production NCTUICConnection (same exporter pattern).
final class JuicityDiagTests: XCTestCase {
    private let q = DispatchQueue(label: "juicity.diag")
    private let server = "45.92.159.155"
    private let uuidStr = "6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71"
    private let passStr = "yeCsUwsFbAhUYMUgdeiC"

    private func juicityProxy() -> NCProxy {
        NCProxy(name: "Tern-Juicity", type: "juicity", fields: [
            "server": .string(server), "port": .number(24033),
            "uuid": .string(uuidStr), "password": .string(passStr),
            "udp": .bool(true), "congestion-controller": .string("bbr"),
            "sni": .string("tern.test"), "skip-cert-verify": .bool(true),
        ])
    }

    private func tuicProxy() -> NCProxy {
        NCProxy(name: "Tern-TUIC", type: "tuic", fields: [
            "server": .string(server), "port": .number(24015),
            "uuid": .string(uuidStr), "password": .string(passStr),
            "alpn": .array([.string("h3")]),
            "udp": .bool(true), "congestion-controller": .string("bbr"),
            "sni": .string("tern.test"), "skip-cert-verify": .bool(true),
        ])
    }

    private func httpExchange(_ s: NCRelayStream, tag: String) {
        let exp = expectation(description: "\(tag) http")
        var got = Data()
        func read() {
            s.receive { d, e in
                if let d, !d.isEmpty {
                    got.append(d)
                    NSLog("[jdiag] %@ recv %d bytes: %@", tag, d.count, String(decoding: d.prefix(80), as: UTF8.self))
                    exp.fulfill()
                } else {
                    NSLog("[jdiag] %@ recv end err=%@", tag, String(describing: e))
                    exp.fulfill()
                }
            }
        }
        s.send(Data("HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n".utf8))
        read()
        wait(for: [exp], timeout: 30)
        NSLog("[jdiag] %@ total %d bytes", tag, got.count)
    }

    func testDiagC_TUICControl() {
        let exp = expectation(description: "tuic dial")
        var stream: NCRelayStream?
        var err: Error?
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: "www.gstatic.com", port: 80), proxy: tuicProxy(), queue: q) { s, e in
            stream = s; err = e
            NSLog("[jdiag] C tuic connect cb after %.2fs stream=%@ err=%@", Date().timeIntervalSince(t0), s != nil, String(describing: e))
            exp.fulfill()
        }
        wait(for: [exp], timeout: 40)
        guard let s = stream else { NSLog("[jdiag] C tuic FAILED err=%@", String(describing: err)); return }
        httpExchange(s, tag: "C tuic")
        s.cancel()
    }

    func testDiagB_JuicityViaConnector() {
        let exp = expectation(description: "juicity dial")
        var stream: NCRelayStream?
        var err: Error?
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: "www.gstatic.com", port: 80), proxy: juicityProxy(), queue: q) { s, e in
            stream = s; err = e
            NSLog("[jdiag] B juicity connect cb after %.2fs stream=%@ err=%@", Date().timeIntervalSince(t0), s != nil, String(describing: e))
            exp.fulfill()
        }
        wait(for: [exp], timeout: 40)
        guard let s = stream else { NSLog("[jdiag] B juicity FAILED err=%@", String(describing: err)); return }
        httpExchange(s, tag: "B juicity")
        s.cancel()
    }

    func testDiagA_RawQUIC() {
        let opts = NWProtocolQUIC.Options(alpn: ["h3"])
        let tls = opts.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        sec_protocol_options_set_tls_server_name(tls, "tern.test")
        sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, q)
        opts.idleTimeout = 30_000
        let params = NWParameters(quic: opts)
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: 24033)!)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: params)
        let t0 = Date()
        func ts() -> String { String(format: "%.2f", Date().timeIntervalSince(t0)) }
        let groupReady = expectation(description: "group ready")
        var groupFired = false
        group.stateUpdateHandler = { st in
            NSLog("[jdiag] A group state %@ at %@", String(describing: st), ts())
            if case .ready = st, !groupFired { groupFired = true; groupReady.fulfill() }
            if case .failed(let e) = st { NSLog("[jdiag] A group FAILED %@", String(describing: e)) }
        }
        group.start(queue: q)
        wait(for: [groupReady], timeout: 20)
        guard groupFired else { NSLog("[jdiag] A group never ready"); group.cancel(); return }

        // Auth uni stream with derived options, like NCQUICStreamOptions.
        let uniOpts = NCQUICStreamOptions.unidirectional(from: group, fallback: { opts })
        guard let auth = group.extract(connectionTo: nil, using: uniOpts) else {
            NSLog("[jdiag] A extract auth returned nil"); group.cancel(); return
        }
        let authReady = expectation(description: "auth ready")
        var authFired = false
        auth.stateUpdateHandler = { st in
            NSLog("[jdiag] A auth state %@ at %@", String(describing: st), ts())
            if case .ready = st, !authFired { authFired = true; authReady.fulfill() }
        }
        auth.start(queue: q)
        wait(for: [authReady], timeout: 20)
        guard authFired else { NSLog("[jdiag] A auth never ready"); group.cancel(); return }

        if let md = auth.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata {
            let sec = md.securityProtocolMetadata
            let proto = sec_protocol_metadata_get_negotiated_protocol(sec).map { String(cString: $0) } ?? "?"
            let ver = sec_protocol_metadata_get_negotiated_tls_protocol_version(sec)
            NSLog("[jdiag] A negotiated alpn=%@ tlsver=%d", proto, ver.rawValue)
            let uuid = NCJuicityWire.uuidBytes(uuidStr)!
            let label = [CChar](uuid.map { CChar(bitPattern: $0) })
            let ctx = [UInt8](Data(passStr.utf8))
            let secret = label.withUnsafeBufferPointer { lp in
                ctx.withUnsafeBufferPointer { cp in
                    sec_protocol_metadata_create_secret_with_context(sec, lp.count, lp.baseAddress!, cp.count, cp.baseAddress!, 32)
                }
            }
            if let secret {
                let out = Data(referencing: (secret as AnyObject) as! NSData)
                NSLog("[jdiag] A exporter token %d bytes sha256=%@", out.count, NCSHA256.hash(out).map { String(format: "%02x", $0) }.joined())
                let msg = NCJuicityWire.authMessage(uuid: uuid, token: out)
                let sent = expectation(description: "auth sent")
                auth.send(content: msg, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { e in
                    NSLog("[jdiag] A auth send done err=%@ at %@", String(describing: e), ts())
                    sent.fulfill()
                })
                wait(for: [sent], timeout: 15)
            } else {
                NSLog("[jdiag] A exporter returned nil")
            }
        } else {
            NSLog("[jdiag] A no QUIC metadata on auth stream")
        }

        // Bidi TCP stream with using:nil, like openTCP.
        guard let conn = group.extract(connectionTo: nil, using: nil) else {
            NSLog("[jdiag] A extract tcp returned nil"); group.cancel(); return
        }
        let tcpReady = expectation(description: "tcp ready")
        var tcpFired = false
        conn.stateUpdateHandler = { st in
            NSLog("[jdiag] A tcp state %@ at %@", String(describing: st), ts())
            if case .ready = st, !tcpFired { tcpFired = true; tcpReady.fulfill() }
        }
        conn.start(queue: q)
        wait(for: [tcpReady], timeout: 20)
        guard tcpFired else { NSLog("[jdiag] A tcp stream never ready"); group.cancel(); return }
        var head = NCJuicityWire.tcpRequestHeader(target: NCTarget(host: "www.gstatic.com", port: 80))!
        head.append(Data("HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n".utf8))
        conn.send(content: head, completion: .contentProcessed { e in
            NSLog("[jdiag] A tcp send err=%@", String(describing: e))
        })
        let gotExp = expectation(description: "tcp recv")
        func recv() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { d, _, _, e in
                NSLog("[jdiag] A tcp recv %d bytes err=%@ data=%@", d?.count ?? -1, String(describing: e),
                      d.map { String(decoding: $0.prefix(80), as: UTF8.self) } ?? "-")
                gotExp.fulfill()
            }
        }
        recv()
        wait(for: [gotExp], timeout: 20)
        group.cancel()
    }
}
