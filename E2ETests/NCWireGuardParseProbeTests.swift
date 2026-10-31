import XCTest

/// fix/kit-wireguard-prod PROBE: the field-by-field table between (a) the hand-built NCProxy the
/// passing loopback E2E uses and (b) the SAME node arriving through the production profile path —
/// the kit seed's exact YAML (block style, as embedded in UITestSeed.kitProbeB64 on probe/kit-e2e)
/// and the kit inventory's flow-style line (tools/server-test tern-nodes.yaml) — parsed by the
/// production chain NCYAML → NCConfig.decode → NCWGConfig.parse. Any drift (key material, ip,
/// mtu, dns, remote-dns-resolve, amnezia) prints as WG-PARSE-DIFF; a clean table prints
/// WG-PARSE-OK per style. Also dumps the parsed AmneziaWG node for the AWG连带判断.
final class NCWireGuardParseProbeTests: XCTestCase {
    private static let privB64 = "OJVQcAQumlNiADByjF03bEqlq5jHFN2k3DFN0BaE/Eo="
    private static let pubB64 = "pDuHgrRuI0rWdogrndZwuyr/D68pUDok1FbXP9Rk0X0="

    /// Verbatim block-style WG + AWG entries from the probe seed (base64-decoded from
    /// probe/kit-e2e's UITestSeed.swift, 2026-10-31).
    private static let blockYAML = """
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
    - name: Tern-AmneziaWG
      type: wireguard
      server: 45.92.159.155
      port: 24035
      ip: 10.67.0.2
      udp: true
      mtu: 1280
      dns:
      - 1.1.1.1
      private-key: SEVf8Xe/xQjVtDts7zCsKgH5Mo14jT9IU3xAqmo0OUM=
      public-key: gqz9RvmIyupAg3w25yP/5n4SaYsh9V1Ihr8eTmkJfDQ=
      remote-dns-resolve: true
      amnezia-wg-option:
        jc: 4
        jmin: 40
        jmax: 70
        s1: 29
        s2: 56
        h1: 610898151
        h2: 1285981084
        h3: 1767517731
        h4: 1995304650
    """

    /// Verbatim flow-style line from the kit inventory (tern-nodes.yaml) — what a subscription /
    /// hand-written profile in Clash flow form hands the importer.
    private static let flowYAML = """
    proxies:
      - {name: "Tern-WireGuard", type: "wireguard", server: "45.92.159.155", port: 24034, ip: "10.66.0.2", udp: true, mtu: 1280, dns: ["1.1.1.1"], private-key: "OJVQcAQumlNiADByjF03bEqlq5jHFN2k3DFN0BaE/Eo=", public-key: "pDuHgrRuI0rWdogrndZwuyr/D68pUDok1FbXP9Rk0X0=", remote-dns-resolve: true}
    """

    private func handBuilt() -> NCProxy {
        NCProxy(name: "Tern-WireGuard", type: "wireguard", fields: [
            "server": .string("45.92.159.155"),
            "port": .number(24034),
            "ip": .string("10.66.0.2"),
            "private-key": .string(Self.privB64),
            "public-key": .string(Self.pubB64),
            "mtu": .number(1280),
            "dns": .array([.string("1.1.1.1")]),
            "remote-dns-resolve": .bool(true),
            "udp": .bool(true),
        ])
    }

    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    private func describe(_ c: NCWGConfig) -> [String: String] {
        var d: [String: String] = [:]
        d["privateKey"] = hex(c.privateKey)
        d["ip4"] = c.ip4 ?? "nil"
        d["ip6"] = c.ip6 ?? "nil"
        d["mtu"] = "\(c.mtu)"
        d["keepalive"] = "\(c.keepalive)"
        d["dns"] = c.dns.joined(separator: ",")
        d["remoteDNS"] = "\(c.remoteDNS)"
        d["amnezia"] = c.amnezia.map { "jc\($0.jc) jmin\($0.jmin) jmax\($0.jmax) s\($0.s1)/\($0.s2)/\($0.s3)/\($0.s4) h\($0.h1.lo)/\($0.h2.lo)/\($0.h3.lo)/\($0.h4.lo)" } ?? "nil"
        d["peers.count"] = "\(c.peers.count)"
        if let p = c.peers.first {
            d["peer.server"] = p.server
            d["peer.port"] = "\(p.port)"
            d["peer.publicKey"] = hex(p.publicKey)
            d["peer.psk.zero"] = "\(p.preSharedKey.allSatisfy { $0 == 0 })"
            d["peer.reserved"] = p.reserved.map { hex($0) } ?? "nil"
            d["peer.allowed"] = p.allowed.map { "\($0.network.string)/\($0.bits)" }.joined(separator: ",")
        }
        return d
    }

    private func check(style: String, yaml: String) {
        let root = NCYAML.parse(yaml)?.object
        XCTAssertNotNil(root, "\(style): NCYAML.parse returned nil")
        guard let root else { return }
        let cfg = NCConfig.decode(root: root)
        let proxy = cfg.proxyMap["Tern-WireGuard"]
        XCTAssertNotNil(proxy, "\(style): Tern-WireGuard missing after NCConfig.decode")
        guard let proxy else { return }
        // Field-level dump of what the YAML chain produced (string vs number typing included).
        for k in ["server", "port", "ip", "mtu", "udp", "remote-dns-resolve"].sorted() {
            NSLog("[wg-parse] %@ field %@ = %@", style, k, String(describing: proxy.fields[k]))
        }
        let (parsed, why) = NCWGConfig.parse(proxy)
        XCTAssertNotNil(parsed, "\(style): NCWGConfig.parse failed: \(why ?? "?")")
        guard let parsed else { return }
        let (wantCfg, wantWhy) = NCWGConfig.parse(handBuilt())
        XCTAssertNotNil(wantCfg, "hand-built NCWGConfig.parse failed: \(wantWhy ?? "?")")
        guard let wantCfg else { return }
        let got = describe(parsed), exp = describe(wantCfg)
        var diffs: [String] = []
        for k in Set(Array(got.keys) + Array(exp.keys)).sorted() where got[k] != exp[k] {
            diffs.append("\(k): yaml=\(got[k] ?? "<none>") hand=\(exp[k] ?? "<none>")")
        }
        if diffs.isEmpty {
            NSLog("[wg-parse] WG-PARSE-OK %@", style)
        } else {
            for d in diffs { NSLog("[wg-parse] WG-PARSE-DIFF %@ %@", style, d) }
            XCTFail("\(style): \(diffs.count) field drift(s)")
        }
    }

    func testBlockStyleSeedParsesIdentically() { check(style: "block", yaml: Self.blockYAML) }
    func testFlowStyleInventoryParsesIdentically() { check(style: "flow", yaml: Self.flowYAML) }

    /// The AWG node through the same chain: dump the parsed Amnezia parameters so the
    /// phase-3 report can judge whether AWG's kit timeout shares WG's cause.
    func testAmneziaSeedParses() {
        let root = NCYAML.parse(Self.blockYAML)?.object
        XCTAssertNotNil(root)
        guard let root else { return }
        let cfg = NCConfig.decode(root: root)
        let proxy = cfg.proxyMap["Tern-AmneziaWG"]
        XCTAssertNotNil(proxy, "Tern-AmneziaWG missing after NCConfig.decode")
        guard let proxy else { return }
        let (parsed, why) = NCWGConfig.parse(proxy)
        XCTAssertNotNil(parsed, "AWG NCWGConfig.parse failed: \(why ?? "?")")
        guard let parsed else { return }
        for (k, v) in describe(parsed).sorted(by: { $0.key < $1.key }) {
            NSLog("[wg-parse] AWG %@ = %@", k, v)
        }
    }
}
