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
                // Mux-backed streams (v2ray-plugin) never deliver EOF at response
                // end — the trace body is complete once its ip=/colo= lines are in.
                let text = String(decoding: raw, as: UTF8.self)
                if text.contains("ip=") && text.contains("colo=") { finish(); return }
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

    // MARK: stage 3 — the probe's own path: seed YAML → NCConfig → NCGroupEngine → delay tester
    //
    // Stages 1–2 hand-build the NCProxy. test99 instead imports the seed YAML in the
    // App, the tunnel loads the resulting config, and NCController's delay tester
    // measures through NCGroupEngine. These two variants replicate that chain
    // in-process (YAML decode, and the App's JSON re-encode the tunnel prefers)
    // and print the delay tester's full Outcome — stage + error text the UI hides.

    private var seedYAML: String {
        """
        proxies:
        - name: Tern-SS-Obfs
          type: ss
          server: \(server)
          port: 24021
          cipher: aes-256-gcm
          password: \(password)
          udp: false
          plugin: obfs
          plugin-opts:
            mode: http
            host: www.bing.com
        """
    }

    private func anyValue(_ v: NCJSONValue) -> Any {
        switch v {
        case .null: return NSNull()
        case .bool(let b): return b
        case .number(let n): return n
        case .string(let s): return s
        case .array(let a): return a.map(anyValue)
        case .object(let o): return o.mapValues(anyValue)
        }
    }

    private func delayViaEngine(_ cfg: NCConfig, _ label: String) {
        if let p = cfg.proxyMap["Tern-SS-Obfs"] {
            NSLog("[ssobfs-zh] %@ imported fields: plugin=%@ plugin-opts=%@", label,
                  p.fields["plugin"]?.string ?? "<nil>", String(describing: p.fields["plugin-opts"]))
        } else {
            NSLog("[ssobfs-zh] %@ imported fields: node MISSING from proxyMap (proxies=%d)", label, cfg.proxies.count)
        }
        let engine = NCGroupEngine(config: cfg)
        let exp = expectation(description: "delay \(label)")
        var outcome: NCTunnelDelayTester.Outcome?
        NCTunnelDelayTester.measure(groupEngine: engine, name: "Tern-SS-Obfs",
                                    url: "http://www.gstatic.com/generate_204", timeoutMs: 8000,
                                    unified: false, logSuccess: true) { o in
            outcome = o
            exp.fulfill()
        }
        wait(for: [exp], timeout: 40)
        NSLog("[ssobfs-zh] %@ delay outcome: ms=%@ failure=%@ stage=%@ error=%@ | %@",
              label, outcome?.ms.map(String.init) ?? "nil", outcome?.failure ?? "-",
              outcome?.stage ?? "-", outcome?.error ?? "-", outcome?.stages ?? "")
        XCTAssertNotNil(outcome?.ms, "\(label): delay probe failed (see outcome line)")
    }

    func testImportedViaYAMLDelay() throws {
        let root = try XCTUnwrap(NCYAML.parse(seedYAML)?.object, "seed YAML must parse")
        delayViaEngine(NCConfig.decode(root: root), "stage3-yaml")
    }

    func testImportedViaJSONDelay() throws {
        let root = try XCTUnwrap(NCYAML.parse(seedYAML)?.object, "seed YAML must parse")
        let data = try JSONSerialization.data(withJSONObject: anyValue(.object(root)))
        delayViaEngine(try NCConfig.decode(jsonData: data), "stage3-json")
    }

    // MARK: stage 5 — the full sweep: real kit seed file + measureGroupDelay over all 40
    //
    // Stages 1-4 pass in isolation, yet test99 (App UI, full sweep) times SS-Obfs out.
    // This stage replicates the sweep itself: the EXACT kit seed as the profile file,
    // every member measured through the App-side tester with batching (limit 8, the
    // NCDelayTester.measureGroupDelay default). If SS-Obfs alone fails here, the
    // preceding probes poison it (bisect by order); if all pass, the delta is the
    // UI-test environment itself, not the code path.

    func testFullSweepAppSide() throws {
        let dir = NSTemporaryDirectory() + "ssobfs-sweep-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let profile = dir + "/kit.yaml"
        let seed = try XCTUnwrap(String(data: Data(base64Encoded: Self.kitSeedB64) ?? Data(), encoding: .utf8),
                                 "kit seed must decode")
        try seed.write(toFile: profile, atomically: true, encoding: .utf8)
        let names = ["Tern-SOCKS5", "Tern-HTTP", "Tern-HTTPS", "Tern-SS-AEAD", "Tern-SS2022",
                     "Tern-SS-ShadowTLS", "Tern-VMess", "Tern-VMess-WS", "Tern-VLESS",
                     "Tern-VLESS-Reality", "Tern-VLESS-Vision", "Tern-VLESS-MLKEM", "Tern-Trojan",
                     "Tern-Hysteria", "Tern-Hysteria2", "Tern-TUIC", "Tern-AnyTLS",
                     "Tern-Naive-H2", "Tern-Naive-H3", "Tern-SS-Obfs", "Tern-SS-V2ray",
                     "Tern-SS-KCPTun", "Tern-SS-Cloak", "Tern-SS-Restls", "Tern-SSR",
                     "Tern-Snell4", "Tern-Snell5", "Tern-Mieru", "Tern-SSH", "Tern-Brook",
                     "Tern-GOST-Relay", "Tern-Juicity", "Tern-WireGuard", "Tern-AmneziaWG",
                     "Tern-OpenConnect", "Tern-TrustTunnel-H2", "Tern-TrustTunnel-H3",
                     "Tern-Sudoku", "Tern-MASQUE-IP", "Tern-MASQUE-UDP"]
        let exp = expectation(description: "sweep")
        Task {
            let results = await NCDelayTester.measureGroupDelay(
                members: names, homeDir: dir, profilePath: profile,
                url: "https://www.gstatic.com/generate_204", timeoutMs: 5000, tcp: false, limit: 8)
            for n in names { NSLog("[ssobfs-sweep] %@ = %d", n, results[n] ?? -999) }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 600)
    }

    /// The kit seed profile verbatim (same base64 as App/Core/UITestSeed.kitProbeB64 —
    /// the profile test99 imports; kept in sync by construction, it IS the probe input).
    static let kitSeedB64 =
        "cHJveGllczoKLSBuYW1lOiBUZXJuLVNPQ0tTNQogIHR5cGU6IHNvY2tzNQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6" +
        "IDI0MDAxCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCi0g" +
        "bmFtZTogVGVybi1IVFRQCiAgdHlwZTogaHR0cAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAyCiAgdXNlcm5h" +
        "bWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCi0gbmFtZTogVGVybi1IVFRQUwogIHR5cGU6IGh0" +
        "dHAKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwMwogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5" +
        "ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHRsczogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQot" +
        "IG5hbWU6IFRlcm4tU1MtQUVBRAogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMDQKICBjaXBo" +
        "ZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDogdHJ1ZQotIG5hbWU6IFRl" +
        "cm4tU1MyMDIyCiAgdHlwZTogc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNQogIGNpcGhlcjogMjAyMi1i" +
        "bGFrZTMtYWVzLTEyOC1nY20KICBwYXNzd29yZDogYTIrSWdUTG1udHJrNmNJZUY2VUFGdz09CiAgdWRwOiB0cnVlCi0gbmFtZTog" +
        "VGVybi1TUy1TaGFkb3dUTFMKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDA2CiAgY2lwaGVy" +
        "OiBhZXMtMTI4LWdjbQogIHBhc3N3b3JkOiBTQUkxRzFIaTlJTVd4VDhqMWRZc3QwUnEKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBz" +
        "aGFkb3ctdGxzCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAgIGhvc3Q6IHd3dy5taWNyb3Nv" +
        "ZnQuY29tCiAgICBwYXNzd29yZDogbzEyRDNZRjdZbWx4RExMTmxURFcKICAgIHZlcnNpb246IDMKLSBuYW1lOiBUZXJuLVZNZXNz" +
        "CiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNwogIHV1aWQ6IDZjZWI1MjE1LTE1Yjkt" +
        "NGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB0Y3AKICB1ZHA6IHRy" +
        "dWUKLSBuYW1lOiBUZXJuLVZNZXNzLVdTCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAw" +
        "OAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8K" +
        "ICBuZXR3b3JrOiB3cwogIHVkcDogdHJ1ZQogIHdzLW9wdHM6CiAgICBwYXRoOiAveTlkZ2xtNXUKICAgIGhlYWRlcnM6CiAgICAg" +
        "IEhvc3Q6IHRlcm4udGVzdAotIG5hbWU6IFRlcm4tVkxFU1MKICB0eXBlOiB2bGVzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQog" +
        "IHBvcnQ6IDI0MDA5CiAgdXVpZDogNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxCiAgbmV0d29yazogdGNwCiAg" +
        "dWRwOiB0cnVlCi0gbmFtZTogVGVybi1WTEVTUy1SZWFsaXR5CiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
        "ICBwb3J0OiAyNDAxMAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIG5ldHdvcms6IHRjcAog" +
        "IHVkcDogdHJ1ZQogIHRsczogdHJ1ZQogIGZsb3c6IHh0bHMtcnByeC12aXNpb24KICBzZXJ2ZXJuYW1lOiB3d3cuYXBwbGUuY29t" +
        "CiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICByZWFsaXR5LW9wdHM6CiAgICBwdWJsaWMta2V5OiBXcDZQalRDM2dmY0NF" +
        "TVEzcEcwUk91c0hkZ0FzN0xmc3gwMjNnZkdERVZZCiAgICBzaG9ydC1pZDogMjFkZGUzYzMxMTJiYmM0YgotIG5hbWU6IFRlcm4t" +
        "VkxFU1MtVmlzaW9uCiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxMQogIHV1aWQ6IDZj" +
        "ZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQogIHRsczogdHJ1ZQog" +
        "IGZsb3c6IHh0bHMtcnByeC12aXNpb24KICBzZXJ2ZXJuYW1lOiB0ZXJuLnRlc3QKICBjbGllbnQtZmluZ2VycHJpbnQ6IGNocm9t" +
        "ZQogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLVZMRVNTLU1MS0VNCiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6" +
        "IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxOAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQog" +
        "IG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQogIGVuY3J5cHRpb246IG1sa2VtNzY4eDI1NTE5cGx1cy5uYXRpdmUuMHJ0dC5iUEs3" +
        "OFFKOTB3YjZHVDF3M0M2VzFrMEZjSUhyZnJUNjBnbXZKYmdkV3hnCi0gbmFtZTogVGVybi1Ucm9qYW4KICB0eXBlOiB0cm9qYW4K" +
        "ICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxMgogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVk" +
        "cDogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tSHlzdGVyaWEKICB0" +
        "eXBlOiBoeXN0ZXJpYQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDEzCiAgcHJvdG9jb2w6IHVkcAogIHVwOiA1" +
        "MCBNYnBzCiAgZG93bjogMTAwIE1icHMKICBhbHBuOgogIC0gaHlzdGVyaWEKICB1ZHA6IHRydWUKICBhdXRoLXN0cjogQkpPU3Vj" +
        "eGpac1VMSmRuc3lOUFQKICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLUh5c3Rl" +
        "cmlhMgogIHR5cGU6IGh5c3RlcmlhMgogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDE0CiAgcGFzc3dvcmQ6IHll" +
        "Q3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0g" +
        "bmFtZTogVGVybi1UVUlDCiAgdHlwZTogdHVpYwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDE1CiAgdXVpZDog" +
        "NmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgYWxw" +
        "bjoKICAtIGgzCiAgdWRwOiB0cnVlCiAgY29uZ2VzdGlvbi1jb250cm9sbGVyOiBiYnIKICBzbmk6IHRlcm4udGVzdAogIHNraXAt" +
        "Y2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLUFueVRMUwogIHR5cGU6IGFueXRscwogIHNlcnZlcjogNDUuOTIuMTU5LjE1" +
        "NQogIHBvcnQ6IDI0MDE2CiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRl" +
        "c3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1OYWl2ZS1IMgogIHR5cGU6IG5haXZlCiAgc2VydmVyOiA0" +
        "NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMTcKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1V" +
        "Z2RlaUMKICBxdWljOiBmYWxzZQogIHVkcDogdHJ1ZQogIHVkcC1vdmVyLXRjcDogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tp" +
        "cC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tTmFpdmUtSDMKICB0eXBlOiBuYWl2ZQogIHNlcnZlcjogNDUuOTIuMTU5" +
        "LjE1NQogIHBvcnQ6IDI0MDE3CiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAg" +
        "cXVpYzogdHJ1ZQogIHVkcDogdHJ1ZQogIHVkcC1vdmVyLXRjcDogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZl" +
        "cmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tU1MtT2JmcwogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDog" +
        "MjQwMjEKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDogZmFs" +
        "c2UKICBwbHVnaW46IG9iZnMKICBwbHVnaW4tb3B0czoKICAgIG1vZGU6IGh0dHAKICAgIGhvc3Q6IHd3dy5iaW5nLmNvbQotIG5h" +
        "bWU6IFRlcm4tU1MtVjJyYXkKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIyCiAgY2lwaGVy" +
        "OiBhZXMtMjU2LWdjbQogIHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiB2" +
        "MnJheS1wbHVnaW4KICBwbHVnaW4tb3B0czoKICAgIG1vZGU6IHdlYnNvY2tldAogICAgaG9zdDogdGVybi50ZXN0CiAgICBwYXRo" +
        "OiAveTU2NnlxMnQKLSBuYW1lOiBUZXJuLVNTLUtDUFR1bgogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9y" +
        "dDogMjQwMjMKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcQogIHVkcDog" +
        "ZmFsc2UKICBwbHVnaW46IGtjcHR1bgogIHBsdWdpbi1vcHRzOgogICAga2V5OiBISjhBZlk0akJ2NndjRDBYZjIyMAogICAgY3J5" +
        "cHQ6IGFlcwogICAgbW9kZTogZmFzdAogICAgbm9jb21wOiB0cnVlCiAgICBzbXV4dmVyOiAxCiAgICBkYXRhc2hhcmQ6IDEwCiAg" +
        "ICBwYXJpdHlzaGFyZDogMwogICAgbXR1OiAxMzUwCiAgICBzbmR3bmQ6IDEwMjQKICAgIHJjdnduZDogMTAyNAotIG5hbWU6IFRl" +
        "cm4tU1MtQ2xvYWsKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDI0CiAgY2lwaGVyOiBhZXMt" +
        "MjU2LWdjbQogIHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBjbG9hawog" +
        "IHBsdWdpbi1vcHRzOgogICAgVUlEOiBLQ1cvWW9SVjRKK0ZKRDdha1hhYXFBPT0KICAgIFB1YmxpY0tleTogdXVEbmU5S1pYWXJ0" +
        "My8xWWxza056cEZNNWkxb1JPTkFTM29ESlA5OHZrbz0KICAgIFNlcnZlck5hbWU6IHd3dy5iaW5nLmNvbQogICAgRW5jcnlwdGlv" +
        "bk1ldGhvZDogcGxhaW4KICAgIEJyb3dzZXJTaWc6IGNocm9tZQogICAgTnVtQ29ubjogNAogICAgUHJveHlNZXRob2Q6IHNoYWRv" +
        "d3NvY2tzCi0gbmFtZTogVGVybi1TUy1SZXN0bHMKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0" +
        "MDI1CiAgY2lwaGVyOiBhZXMtMjU2LWdjbQogIHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNl" +
        "CiAgcGx1Z2luOiByZXN0bHMKICBjbGllbnQtZmluZ2VycHJpbnQ6IGNocm9tZQogIHBsdWdpbi1vcHRzOgogICAgaG9zdDogd3d3" +
        "Lm1pY3Jvc29mdC5jb20KICAgIHBhc3N3b3JkOiBQNG5heDZRb3JDM3lKaW52VDBhVwogICAgdmVyc2lvbi1oaW50OiB0bHMxMwog" +
        "ICAgcmVzdGxzLXNjcmlwdDogMzAwPzEwMCw0MDB+MTAwLDM1MH4xMDAsNjAwfjEwMCwzMDB+MjAwLDMwMH4xMDAKLSBuYW1lOiBU" +
        "ZXJuLVNTUgogIHR5cGU6IHNzcgogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDI2CiAgY2lwaGVyOiBhZXMtMjU2" +
        "LWNmYgogIHBhc3N3b3JkOiBvOG5BcU12eGx1TDJDdlFvY3dkZwogIHByb3RvY29sOiBhdXRoX2FlczEyOF9tZDUKICBvYmZzOiB0" +
        "bHMxLjJfdGlja2V0X2F1dGgKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJuLVNuZWxsNAogIHR5cGU6IHNuZWxsCiAgc2VydmVyOiA0" +
        "NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMjcKICBwc2s6IGp5bmg1ejhVNmc1bGN0R0F5VW53RnhZRwogIHBhc3N3b3JkOiBqeW5o" +
        "NXo4VTZnNWxjdEdBeVVud0Z4WUcKICB2ZXJzaW9uOiA0CiAgdWRwOiB0cnVlCi0gbmFtZTogVGVybi1TbmVsbDUKICB0eXBlOiBz" +
        "bmVsbAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDI4CiAgcHNrOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcK" +
        "ICBwYXNzd29yZDoganluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgdmVyc2lvbjogNQogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4t" +
        "TWllcnUKICB0eXBlOiBtaWVydQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDI5CiAgdHJhbnNwb3J0OiBUQ1AK" +
        "ICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUKICBtdWx0aXBs" +
        "ZXhpbmc6IE1VTFRJUExFWElOR19MT1cKLSBuYW1lOiBUZXJuLVNTSAogIHR5cGU6IHNzaAogIHNlcnZlcjogNDUuOTIuMTU5LjE1" +
        "NQogIHBvcnQ6IDI0MDMwCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCi0gbmFt" +
        "ZTogVGVybi1Ccm9vawogIHR5cGU6IGJyb29rCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzEKICBwYXNzd29y" +
        "ZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB0cmFuc3BvcnQ6IHNlcnZlcgogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tR09TVC1S" +
        "ZWxheQogIHR5cGU6IGdvc3QtcmVsYXkKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzMgogIHVzZXJuYW1lOiB0" +
        "ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHRsczogdHJ1ZQogIHVkcDogdHJ1ZQogIHNuaTogdGVy" +
        "bi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tSnVpY2l0eQogIHR5cGU6IGp1aWNpdHkKICBzZXJ2" +
        "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzMwogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3" +
        "MQogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1ZQogIGNvbmdlc3Rpb24tY29udHJvbGxlcjogYmJy" +
        "CiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1XaXJlR3VhcmQKICB0eXBlOiB3" +
        "aXJlZ3VhcmQKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNAogIGlwOiAxMC42Ni4wLjIKICB1ZHA6IHRydWUK" +
        "ICBtdHU6IDEyODAKICBkbnM6CiAgLSAxLjEuMS4xCiAgcHJpdmF0ZS1rZXk6IE9KVlFjQVF1bWxOaUFEQnlqRjAzYkVxbHE1akhG" +
        "TjJrM0RGTjBCYUUvRW89CiAgcHVibGljLWtleTogcER1SGdyUnVJMHJXZG9ncm5kWnd1eXIvRDY4cFVEb2sxRmJYUDlSazBYMD0K" +
        "ICByZW1vdGUtZG5zLXJlc29sdmU6IHRydWUKLSBuYW1lOiBUZXJuLUFtbmV6aWFXRwogIHR5cGU6IHdpcmVndWFyZAogIHNlcnZl" +
        "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM1CiAgaXA6IDEwLjY3LjAuMgogIHVkcDogdHJ1ZQogIG10dTogMTI4MAogIGRu" +
        "czoKICAtIDEuMS4xLjEKICBwcml2YXRlLWtleTogU0VWZjhYZS94UWpWdER0czd6Q3NLZ0g1TW8xNGpUOUlVM3hBcW1vME9VTT0K" +
        "ICBwdWJsaWMta2V5OiBncXo5UnZtSXl1cEFnM3cyNXlQLzVuNFNhWXNoOVYxSWhyOGVUbWtKZkRRPQogIHJlbW90ZS1kbnMtcmVz" +
        "b2x2ZTogdHJ1ZQogIGFtbmV6aWEtd2ctb3B0aW9uOgogICAgamM6IDQKICAgIGptaW46IDQwCiAgICBqbWF4OiA3MAogICAgczE6" +
        "IDI5CiAgICBzMjogNTYKICAgIGgxOiA2MTA4OTgxNTEKICAgIGgyOiAxMjg1OTgxMDg0CiAgICBoMzogMTc2NzUxNzczMQogICAg" +
        "aDQ6IDE5OTUzMDQ2NTAKLSBuYW1lOiBUZXJuLU9wZW5Db25uZWN0CiAgdHlwZTogb3BlbmNvbm5lY3QKICBzZXJ2ZXI6IDQ1Ljky" +
        "LjE1OS4xNTUKICBwb3J0OiAyNDAzNgogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVp" +
        "QwogIGR0bHM6IHRydWUKICB1ZHA6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1l" +
        "OiBUZXJuLVRydXN0VHVubmVsLUgyCiAgdHlwZTogdHJ1c3R0dW5uZWwKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAy" +
        "NDAzNwogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IGZhbHNlCiAg" +
        "dWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1UcnVzdFR1bm5l" +
        "bC1IMwogIHR5cGU6IHRydXN0dHVubmVsCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzcKICB1c2VybmFtZTog" +
        "dGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICBxdWljOiB0cnVlCiAgdWRwOiB0cnVlCiAgc25pOiB0" +
        "ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1TdWRva3UKICB0eXBlOiBzdWRva3UKICBzZXJ2" +
        "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzOAogIGtleTogM2M3YmYwZjNlZWRhZTBiZTY2NjY0YjJiOTA0N2Y1NGQ4OWM3" +
        "NGRmMDM0NzU4YjM1YWU5MzU5YTQxYzRmNWQwZTZlMDIyOTUxMDM0OTc2ODZhYjU2NjMzOGMwNmZkZjdiMTlhYzBiNTBjMDY4YTJh" +
        "NDFmNWY2ZjUxNzZkYWU0MDIKICBhZWFkLW1ldGhvZDogY2hhY2hhMjAtcG9seTEzMDUKICB0YWJsZS10eXBlOiBwcmVmZXJfZW50" +
        "cm9weQotIG5hbWU6IFRlcm4tTUFTUVVFLUlQCiAgdHlwZTogbWFzcXVlCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDog" +
        "MjQwMzkKICBtb2RlOiBjb25uZWN0LWlwCiAgdXJpOiBodHRwczovL3Byb3h5OjI0MDM5L3ZwbgogIHNuaTogcHJveHkKICBtdHU6" +
        "IDEyMDAKICBkbnM6CiAgLSAxLjEuMS4xCiAgdWRwOiB0cnVlCiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4t" +
        "TUFTUVVFLVVEUAogIHR5cGU6IG1hc3F1ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDQwCiAgbW9kZTogY29u" +
        "bmVjdC11ZHAKICB1c2VybmFtZTogdGVybgogIHBhc3N3b3JkOiB0ZXJuCiAgdXJpOiBodHRwczovL3Rlcm4udGVzdDoyNDA0MC8u" +
        "d2VsbC1rbm93bi9tYXNxdWUvdWRwL3t0YXJnZXRfaG9zdH0ve3RhcmdldF9wb3J0fS8KICB1ZHA6IHRydWUKICBzbmk6IHRlcm4u" +
        "dGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKcHJveHktZ3JvdXBzOgotIG5hbWU6IFRlcm4tVGVzdAogIHR5cGU6IHNlbGVj" +
        "dAogIHByb3hpZXM6CiAgLSBUZXJuLVNPQ0tTNQogIC0gVGVybi1IVFRQCiAgLSBUZXJuLUhUVFBTCiAgLSBUZXJuLVNTLUFFQUQK" +
        "ICAtIFRlcm4tU1MyMDIyCiAgLSBUZXJuLVNTLVNoYWRvd1RMUwogIC0gVGVybi1WTWVzcwogIC0gVGVybi1WTWVzcy1XUwogIC0g" +
        "VGVybi1WTEVTUwogIC0gVGVybi1WTEVTUy1SZWFsaXR5CiAgLSBUZXJuLVZMRVNTLVZpc2lvbgogIC0gVGVybi1WTEVTUy1NTEtF" +
        "TQogIC0gVGVybi1Ucm9qYW4KICAtIFRlcm4tSHlzdGVyaWEKICAtIFRlcm4tSHlzdGVyaWEyCiAgLSBUZXJuLVRVSUMKICAtIFRl" +
        "cm4tQW55VExTCiAgLSBUZXJuLU5haXZlLUgyCiAgLSBUZXJuLU5haXZlLUgzCiAgLSBUZXJuLVNTLU9iZnMKICAtIFRlcm4tU1Mt" +
        "VjJyYXkKICAtIFRlcm4tU1MtS0NQVHVuCiAgLSBUZXJuLVNTLUNsb2FrCiAgLSBUZXJuLVNTLVJlc3RscwogIC0gVGVybi1TU1IK" +
        "ICAtIFRlcm4tU25lbGw0CiAgLSBUZXJuLVNuZWxsNQogIC0gVGVybi1NaWVydQogIC0gVGVybi1TU0gKICAtIFRlcm4tQnJvb2sK" +
        "ICAtIFRlcm4tR09TVC1SZWxheQogIC0gVGVybi1KdWljaXR5CiAgLSBUZXJuLVdpcmVHdWFyZAogIC0gVGVybi1BbW5lemlhV0cK" +
        "ICAtIFRlcm4tT3BlbkNvbm5lY3QKICAtIFRlcm4tVHJ1c3RUdW5uZWwtSDIKICAtIFRlcm4tVHJ1c3RUdW5uZWwtSDMKICAtIFRl" +
        "cm4tU3Vkb2t1CiAgLSBUZXJuLU1BU1FVRS1JUAogIC0gVGVybi1NQVNRVUUtVURQCnJ1bGVzOgotIE1BVENILFRlcm4tVGVzdAo="

    // MARK: stage 4 — the EXACT App-side path test99 drives
    //
    // test99 never starts the tunnel (the probe screenshot shows 未连接): the 策略
    // group test runs in the App process via ProfileInspector →
    // NCDelayTester.testDelayByName → NCNodeResolver over the profile FILE →
    // measureHttpDelay (unified-delay ON, 测速设置 defaults: https://www.gstatic.com/
    // generate_204, 5000 ms). Stage 3 above used the tunnel-side tester instead —
    // this stage replicates the App call verbatim against a temp profile file.

    func testAppSideDelayTester() throws {
        let dir = NSTemporaryDirectory() + "ssobfs-app-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let profile = dir + "/kit.yaml"
        // One literal for the whole file (concatenating two multiline literals
        // broke the second entry's indentation in the first version of this test:
        // the file parsed as ONE merged entry — resolver returned the v2ray fields
        // for the obfs name and no v2ray entry at all).
        let twoNodes = """
        proxies:
        - name: Tern-SS-Obfs
          type: ss
          server: \(server)
          port: 24021
          cipher: aes-256-gcm
          password: \(password)
          udp: false
          plugin: obfs
          plugin-opts:
            mode: http
            host: www.bing.com
        - name: Tern-SS-V2ray
          type: ss
          server: \(server)
          port: 24022
          cipher: aes-256-gcm
          password: \(password)
          udp: false
          plugin: v2ray-plugin
          plugin-opts:
            mode: websocket
            host: tern.test
            path: /y566yq2t
        """
        try twoNodes.write(toFile: profile, atomically: true, encoding: .utf8)
        for nm in ["Tern-SS-Obfs", "Tern-SS-V2ray"] {
            if let p = NCNodeResolver.shared.resolveByName(homeDir: dir, profilePath: profile, name: nm) {
                NSLog("[ssobfs-app] resolved %@: name=%@ port=%@ plugin=%@ plugin-opts=%@", nm, p.name,
                      p.fields["port"]?.number.map { String(Int($0)) } ?? "<nil>",
                      p.fields["plugin"]?.string ?? "<nil>", String(describing: p.fields["plugin-opts"]))
            } else {
                NSLog("[ssobfs-app] resolver returned nil for %@", nm)
            }
        }
        let ms = NCDelayTester.testDelayByName(homeDir: dir, profilePath: profile,
                                               name: "Tern-SS-Obfs",
                                               url: "https://www.gstatic.com/generate_204",
                                               timeoutMs: 5000)
        NSLog("[ssobfs-app] app-side delay Tern-SS-Obfs = %d", ms)
        XCTAssertGreaterThan(ms, 0, "app-side delay tester must measure SS-Obfs")
        let ms2 = NCDelayTester.testDelayByName(homeDir: dir, profilePath: profile,
                                                name: "Tern-SS-V2ray",
                                                url: "https://www.gstatic.com/generate_204",
                                                timeoutMs: 5000)
        NSLog("[ssobfs-app] app-side delay Tern-SS-V2ray = %d", ms2)
        XCTAssertGreaterThan(ms2, 0, "app-side delay tester must measure SS-V2ray")
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
