import XCTest

/// fix/kit-wireguard-prod PROBE: the production measurement path the kit probe (test99) uses —
/// App UI → ControllerClient → tunnel NCController → NCTunnelDelayTester → NCConnector — booted
/// in-process exactly like TernE2ETunnelTests does (NativeTunnelCore.start over a synthetic
/// NEPacketTunnelFlow, real controller on 127.0.0.1), with a home whose runtime.yaml is a minimal
/// profile carrying ONLY the real kit WireGuard node. Two variants: the outbound binding the E2E
/// harness installs (off) and the one PacketTunnelProvider installs when the tunnel setting
/// 接管所有网络流量 is on (NCOutboundBinding.start(includeAllNetworks: true)).
/// Verdicts print as [wg-tunnel] lines, including the tester's own [delay] stage lines captured
/// via NCDialTrace.logSink. Runs in proto-loopback.yml job `wireguard-zh` (env NC_WG_ZH=1).
final class NCWireGuardTunnelDelayTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private var delayLines: [String] = []
    private let lineLock = NSLock()

    private static let runtimeYAML = """
    mode: rule
    log-level: info
    dns:
      enable: true
      enhanced-mode: fake-ip
      nameserver:
        - 223.5.5.5
    proxies:
      - name: Tern-WireGuard
        type: wireguard
        server: 45.92.159.155
        port: 24034
        ip: 10.66.0.2
        udp: true
        mtu: 1280
        dns:
          - 1.1.1.1
        private-key: OJVQcAQumlNiADByjF03bEqlq5jHFN2k3DFN0BaE/Eo=
        public-key: pDuHgrRuI0rWdogrndZwuyr/D68pUDok1FbXP9Rk0X0=
        remote-dns-resolve: true
    proxy-groups:
      - name: Tern-Test
        type: select
        proxies:
          - Tern-WireGuard
    rules:
      - MATCH,Tern-Test
    """

    override func setUpWithError() throws {
        guard env["NC_WG_ZH"] == "1" else {
            throw XCTSkip("WireGuard tunnel delay probe: set TEST_RUNNER_NC_WG_ZH=1 (proto-loopback.yml wireguard-zh)")
        }
    }

    override func tearDown() {
        NativeTunnelCore.shared.stop()
        NCLwIP.queue.sync { NCWGStack.shared.teardownAll() }
        NCOutboundBinding.stop()
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    private func runProbe(tag: String, binding: Bool) throws -> Int {
        let home = NSTemporaryDirectory() + "wg-tunnel-home-" + tag
        try? FileManager.default.removeItem(atPath: home)
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        try Self.runtimeYAML.write(toFile: home + "/runtime.yaml", atomically: true, encoding: .utf8)

        E2EHarness.prepareProcess { NSLog("[wg-tunnel] setup: %@", $0) }
        if binding { NCOutboundBinding.start(includeAllNetworks: true) }
        NSLog("[wg-tunnel] %@ binding: %@", tag, NCOutboundBinding.describe)

        lineLock.lock(); delayLines = []; lineLock.unlock()
        NCDialTrace.logSink = { [weak self] line, _ in
            guard let self else { return }
            self.lineLock.lock(); self.delayLines.append(line); self.lineLock.unlock()
        }

        let flow = E2EFlow()
        _ = E2ENet(flow: flow)
        let port = E2EHarness.freePort()
        let secret = "wg-tunnel-" + String(UUID().uuidString.prefix(8))
        try NativeTunnelCore.shared.start(home: home, flow: flow, mtu: 1500, controllerPort: port, secret: secret)
        let api = E2EController(port: port, secret: secret)

        // Same call ControllerClient.proxyDelay makes for the policy page's group test
        // (default test URL https://www.gstatic.com/generate_204, unified-delay in the core).
        let rep = api.call("GET", "/proxies/Tern-WireGuard/delay",
                           query: ["url": "https://www.gstatic.com/generate_204", "timeout": "5000"], timeout: 25)
        let delay = (rep.object?["delay"] as? NSNumber)?.intValue ?? 0
        NSLog("[wg-tunnel] %@ /proxies/Tern-WireGuard/delay -> HTTP %d in %d ms, body %@",
              tag, rep.status, rep.ms, String(decoding: rep.data.prefix(300), as: UTF8.self))
        let info = api.call("GET", "/proxies/Tern-WireGuard")
        NSLog("[wg-tunnel] %@ /proxies/Tern-WireGuard -> HTTP %d, body %@",
              tag, info.status, String(decoding: info.data.prefix(400), as: UTF8.self))
        lineLock.lock(); let lines = delayLines; lineLock.unlock()
        for l in lines { NSLog("[wg-tunnel] %@ %@", tag, l) }
        NativeTunnelCore.shared.stop()
        return delay
    }

    func test1_DelayViaTunnelCore_BindingOff() throws {
        let d = try runProbe(tag: "unbound", binding: false)
        XCTAssertGreaterThan(d, 0, "WG delay through the tunnel core (binding off) is 0 — see [wg-tunnel] lines")
    }

    func test2_DelayViaTunnelCore_BindingOn() throws {
        let d = try runProbe(tag: "bound", binding: true)
        XCTAssertGreaterThan(d, 0, "WG delay through the tunnel core (binding on) is 0 — see [wg-tunnel] lines")
    }
}
