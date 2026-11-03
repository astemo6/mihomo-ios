import XCTest

/// fix/kit-ss-obfs DIAGNOSIS: Shadowsocks + simple-obfs (http mode) against the REAL kit
/// server on zhiheng (shadowsocks-rust 1.25.0 + obfs-server 0.0.5, TCP 24021;
/// plugin-opts: obfs=http, host=www.bing.com — the exact kit seed entry).
///
/// Server health is proven with the official sslocal + obfs-local using the same
/// credentials (generate_204 = 204, egress = 45.92.159.155), and a byte-level replay
/// of the client's obfs HTTP header against the real server is accepted (101 +
/// response bytes). Yet the kit probe (test99, full extension path) reports
/// Tern-SS-Obfs = timeout while Tern-SS-V2ray — same plugin layer, same server —
/// measures 112 ms. These stages split the dial at the plugin seam with a wire
/// tap so the failing stage names itself:
///   stage 1: manual stack — NCStream → tap → NCSSPluginStream(obfs http) →
///            NCSSRelayStream → HTTP fetch (egress must be 45.92.159.155)
///   stage 2: production path — NCConnector.connect with the seed-exact NCProxy
///   control A: SS-V2ray (kit 24022) via NCConnector — same plugin layer
///   control B: plain SS-AEAD (kit 24004) via NCConnector — same SS codec
///
/// Runs in proto-loopback.yml job `ss-obfs-zh` with TEST_RUNNER_NC_SSOBFS_ZH=1 and
/// TEST_RUNNER_NC_SSOBFS_{SERVER,PORT,PASSWORD} in the environment; there it FAILS
/// (never skips) when the server is unreachable; elsewhere it skips.
final class NCSSObfsZhihengInteropTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "ssobfs.zh.interop.test")

    private var server: String { env["NC_SSOBFS_SERVER"] ?? "45.92.159.155" }
    private var password: String { env["NC_SSOBFS_PASSWORD"] ?? "" }

    override func setUpWithError() throws {
        guard env["NC_SSOBFS_ZH"] == "1" else {
            throw XCTSkip("SS-Obfs zhiheng interop: set TEST_RUNNER_NC_SSOBFS_ZH=1 with the kit node env (proto-loopback.yml ss-obfs-zh)")
        }
        XCTAssertFalse(password.isEmpty, "NC_SSOBFS_PASSWORD missing")
    }

    private func obfsNode() -> NCProxy {
        NCProxy(name: "Tern-SS-Obfs", type: "ss", fields: [
            "server": .string(server),
            "port": .number(Double(env["NC_SSOBFS_PORT"] ?? "") ?? 24021),
            "cipher": .string("aes-256-gcm"),
            "password": .string(password),
            "udp": .bool(false),
            "plugin": .string("obfs"),
            "plugin-opts": .object(["mode": .string("http"), "host": .string("www.bing.com")]),
        ])
    }

    private func v2rayNode() -> NCProxy {
        NCProxy(name: "Tern-SS-V2ray", type: "ss", fields: [
            "server": .string(server),
            "port": .number(24022),
            "cipher": .string("aes-256-gcm"),
            "password": .string(password),
            "udp": .bool(false),
            "plugin": .string("v2ray-plugin"),
            "plugin-opts": .object(["mode": .string("websocket"), "host": .string("tern.test"), "path": .string("/y566yq2t")]),
        ])
    }

    private func plainNode() -> NCProxy {
        NCProxy(name: "Tern-SS-AEAD", type: "ss", fields: [
            "server": .string(server),
            "port": .number(24004),
            "cipher": .string("aes-256-gcm"),
            "password": .string(password),
            "udp": .bool(true),
        ])
    }

    // MARK: helpers (mirrors NCJuicityZhihengInteropTests)

    private func get(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 60) -> (String, Data) {
        let done = expectation(description: "GET \(path)")
        var raw = Data()
        var finished = false
        func finish() { if !finished { finished = true; done.fulfill() } }
        func read() {
            s.receive { d, _ in
                guard let d, !d.isEmpty else { finish(); return }
                raw.append(d)
                read()
            }
        }
        q.async {
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-ssobfs-zh-probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else {
            return (String(decoding: all.prefix(200), as: UTF8.self), Data())
        }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        var body = Data(all[r.upperBound...])
        if head.lowercased().contains("transfer-encoding: chunked") { body = dechunk(body) }
        return (head.components(separatedBy: "\r\n").first ?? "", body)
    }

    private func dechunk(_ d: Data) -> Data {
        var out = Data()
        var i = d.startIndex
        while let crlf = d[i...].range(of: Data([13, 10])) {
            let sizeLine = String(decoding: d[i..<crlf.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let n = Int(sizeLine.trimmingCharacters(in: .whitespaces), radix: 16), n > 0 else { break }
            let start = crlf.upperBound
            guard start + n <= d.endIndex else { out.append(d[start...]); break }
            out.append(d[start..<(start + n)])
            i = min(start + n + 2, d.endIndex)
        }
        return out
    }

    private func assertTraceEgress(_ s: NCRelayStream, _ label: String) {
        let (status, body) = get(s, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[ssobfs-zh] %@ GET /cdn-cgi/trace -> %@", label, status)
        XCTAssertTrue(status.contains(" 200"), "\(label): \(status)")
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[ssobfs-zh] %@ trace: %@", label, text.split(separator: "\n").filter { $0.hasPrefix("ip=") || $0.hasPrefix("colo=") }.joined(separator: " "))
        XCTAssertTrue(text.contains("ip=\(server)"), "\(label): egress is not the kit server: \(text)")
    }

    private func viaConnector(_ p: NCProxy, _ label: String) {
        let exp = expectation(description: "connector dial \(label)")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: "www.cloudflare.com", port: 80), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 30)
        NSLog("[ssobfs-zh] %@ connect -> %@ in %.2f s",
              label, out.0 != nil ? "ok" : "error \(String(describing: out.1))", Date().timeIntervalSince(t0))
        let s = try? XCTUnwrap(out.0, "\(label) connect failed: \(String(describing: out.1))")
        guard let s else { XCTFail("\(label) connect failed: \(String(describing: out.1))"); return }
        defer { s.cancel() }
        assertTraceEgress(s, label)
    }

    // MARK: stage 1 — manual stack with a wire tap at the plugin seam

    func testWireTapManualStack() throws {
        let raw = NCStream(to: server, port: 24021, queue: q)
        let started = expectation(description: "tcp connect")
        var startErr: Error?
        raw.start { e in startErr = e; started.fulfill() }
        wait(for: [started], timeout: 15)
        NSLog("[ssobfs-zh] stage1 tcp -> %@", startErr == nil ? "ready" : "error \(String(describing: startErr))")
        XCTAssertNil(startErr)
        guard startErr == nil else { return }

        let tap = TapStream(raw)
        let opts = try XCTUnwrap(NCSSPluginOptions(pluginName: "obfs", opts: [
            "mode": .string("http"), "host": .string("www.bing.com"),
        ]), "seed plugin-opts must parse")
        let plugin = NCSSPluginStream(raw: tap, options: opts, serverPort: "24021")
        let pstarted = expectation(description: "plugin start")
        var perr: Error?
        plugin.start { e in perr = e; pstarted.fulfill() }
        wait(for: [pstarted], timeout: 10)
        NSLog("[ssobfs-zh] stage1 plugin start -> %@", perr == nil ? "ok" : "error \(String(describing: perr))")
        XCTAssertNil(perr)
        guard perr == nil else { return }

        let enc = try XCTUnwrap(NCSSEncoder(cipher: "aes-256-gcm", password: password))
        let dec = try XCTUnwrap(NCSSDecoder(cipher: "aes-256-gcm", password: password))
        let relay = NCSSRelayStream(raw: plugin, encoder: enc, decoder: dec,
                                    target: NCTarget(host: "www.cloudflare.com", port: 80))
        defer { relay.cancel() }
        // NCSSRelayStream.init has already sent the SS head through the plugin (tap logged it).
        assertTraceEgress(relay, "stage1")
        NSLog("[ssobfs-zh] stage1 tap totals: out=%d chunks, in=%d chunks", tap.outChunks, tap.inChunks)
    }

    // MARK: stage 2 — production path

    func testProductionPathViaConnector() throws {
        viaConnector(obfsNode(), "stage2")
    }

    // MARK: controls

    func testV2RayControlViaConnector() throws {
        viaConnector(v2rayNode(), "control-v2ray")
    }

    func testPlainSSControlViaConnector() throws {
        viaConnector(plainNode(), "control-plain")
    }
}

/// Wire tap: logs every chunk crossing the plugin seam (sizes + printable
/// prefix of the first outbound chunk — the obfs HTTP header is ASCII).
private final class TapStream: NCRelayStream {
    private let raw: NCRelayStream
    private(set) var outChunks = 0
    private(set) var inChunks = 0

    init(_ raw: NCRelayStream) { self.raw = raw }

    func send(_ data: Data, completion: @escaping () -> Void) {
        outChunks += 1
        if outChunks == 1 {
            let head = String(decoding: data.prefix(400), as: UTF8.self)
            NSLog("[ssobfs-zh] tap-out #1 (%d bytes): %@", data.count, head)
        } else {
            NSLog("[ssobfs-zh] tap-out #%d (%d bytes)", outChunks, data.count)
        }
        raw.send(data, completion: completion)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] d, e in
            if let d {
                self?.inChunks += 1
                NSLog("[ssobfs-zh] tap-in (%d bytes): %@", d.count,
                      String(decoding: d.prefix(120), as: UTF8.self))
            } else {
                NSLog("[ssobfs-zh] tap-in end (error=%@)", String(describing: e))
            }
            handler(d, e)
        }
    }

    func cancel() { raw.cancel() }
}
