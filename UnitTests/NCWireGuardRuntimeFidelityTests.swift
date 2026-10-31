import XCTest
@testable import Tern

/// fix/kit-wireguard-prod PROBE: field fidelity of the WireGuard / AmneziaWG nodes through the
/// CONNECT path's runtime generation — NCRuntimeBuilder.build + lowerForNative, the exact calls
/// NativeRuntimePrep.prepareSyncLocked makes before the tunnel loads nativecore-runtime.json —
/// for both kit seed variants (full and reduced; the probe falls back to the reduced set when the
/// full profile will not import). The tunnel-side parse chain (YAML → NCConfig → NCWGConfig) is
/// already proven identical to hand-built values (E2ETests/NCWireGuardParseProbeTests); this is
/// the App-side half of the production path. Any dropped / renamed / retyped field prints as
/// WG-FIDELITY-DIFF; a clean run prints WG-FIDELITY-OK per variant.
final class NCWireGuardRuntimeFidelityTests: XCTestCase {

    private func dump(_ v: NCJSONValue) -> String {
        switch v {
        case .null: return "null"
        case .bool(let b): return "bool(\(b))"
        case .number(let n): return "number(\(n))"
        case .string(let s): return "string(\"\(s)\")"
        case .array(let a): return "[" + a.map(dump).joined(separator: ", ") + "]"
        case .object(let o): return "{" + o.keys.sorted().map { "\($0)=\(dump(o[$0]!))" }.joined(separator: ", ") + "}"
        }
    }

    private func check(variant: String, b64: String) throws {
        let data = try XCTUnwrap(Data(base64Encoded: b64), "\(variant): seed base64")
        let text = try XCTUnwrap(String(data: data, encoding: .utf8), "\(variant): seed utf8")
        let home = NSTemporaryDirectory() + "wg-fidelity-" + variant
        try? FileManager.default.removeItem(atPath: home)
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let profilePath = home + "/kit.yaml"
        try text.write(toFile: profilePath, atomically: true, encoding: .utf8)

        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        var rep = NCRuntimeBuilder.PrepReport()
        let built = try NCRuntimeBuilder.build(profile: data, req: req, fd: 0) { raw in
            NCRuntimeBuilder.lowerForNative(home: home, &raw, &rep, stageDir: nil) { _ in }
        }
        NSLog("[wg-fidelity] %@ built: %d B, isJSON %@", variant, built.data.count, built.isJSON ? "yes" : "no")
        if let w = rep.warnings, !w.isEmpty {
            for x in w { NSLog("[wg-fidelity] %@ warning: %@", variant, x) }
        }
        let cfg: NCConfig
        if built.isJSON {
            cfg = try NCConfig.decode(jsonData: built.data)
        } else {
            let root = NCYAML.parse(String(decoding: built.data, as: UTF8.self))?.object
            cfg = NCConfig.decode(root: try XCTUnwrap(root, "\(variant): runtime YAML root"))
        }
        NSLog("[wg-fidelity] %@ runtime proxies: %d, groups: %d", variant, cfg.proxies.count, cfg.groups.count)

        let expected: [String: NCJSONValue] = [
            "server": .string("45.92.159.155"),
            "port": .number(24034),
            "ip": .string("10.66.0.2"),
            "udp": .bool(true),
            "mtu": .number(1280),
            "dns": .array([.string("1.1.1.1")]),
            "private-key": .string("OJVQcAQumlNiADByjF03bEqlq5jHFN2k3DFN0BaE/Eo="),
            "public-key": .string("pDuHgrRuI0rWdogrndZwuyr/D68pUDok1FbXP9Rk0X0="),
            "remote-dns-resolve": .bool(true),
        ]
        guard let wg = cfg.proxyMap["Tern-WireGuard"] else {
            XCTFail("\(variant): Tern-WireGuard ABSENT from the built runtime (proxies: \(cfg.proxies.map(\.name).joined(separator: ",")))")
            return
        }
        NSLog("[wg-fidelity] %@ WG type=%@ fields: %@", variant, wg.type,
              wg.fields.keys.sorted().map { "\($0)=\(dump(wg.fields[$0]!))" }.joined(separator: " "))
        var diffs: [String] = []
        if wg.type != "wireguard" { diffs.append("type=\(wg.type)") }
        for (k, want) in expected.sorted(by: { $0.key < $1.key }) {
            if wg.fields[k] != want {
                diffs.append("\(k): runtime=\(wg.fields[k].map(dump) ?? "<absent>") want=\(dump(want))")
            }
        }
        if let awg = cfg.proxyMap["Tern-AmneziaWG"] {
            NSLog("[wg-fidelity] %@ AWG fields: %@", variant,
                  awg.fields.keys.sorted().map { "\($0)=\(dump(awg.fields[$0]!))" }.joined(separator: " "))
        } else {
            NSLog("[wg-fidelity] %@ AWG absent from runtime", variant)
        }
        if diffs.isEmpty {
            NSLog("[wg-fidelity] WG-FIDELITY-OK %@", variant)
        } else {
            for d in diffs { NSLog("[wg-fidelity] WG-FIDELITY-DIFF %@ %@", variant, d) }
            XCTFail("\(variant): \(diffs.count) WG field drift(s) through runtime generation")
        }
    }

    func testFullSeedWireGuardFidelity() throws { try check(variant: "full", b64: UITestSeed.kitProbeB64) }
    func testReducedSeedWireGuardFidelity() throws { try check(variant: "reduced", b64: UITestSeed.kitProbeReducedB64) }
}
