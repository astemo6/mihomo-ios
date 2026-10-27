import XCTest
@testable import Tern

/// fix/nc-e2e-real: NCYAMLEmitter wrote every key after the first of a nested mapping at column 0, so a QX / Surge
/// import with a ws node kept only its first node (E2E replay 40268229079: 1 / 1 / 3 runtime proxies / groups / rules
/// for an import of 9 / 29 / 85). Emitter round trip, the App's .conf import through the parser every reader uses, and
/// the one-time repair of profiles the old emitter already wrote.
final class NativeCoreYAMLEmitterTests: XCTestCase {

    private func obj(_ m: [String: NCJSONValue]) -> NCJSONValue { .object(m) }

    func testNestedMappingRoundTrip() {
        let tree = obj([
            "mode": .string("rule"),
            "proxies": .array([
                obj([
                    "name": .string("N1"), "type": .string("vmess"), "server": .string("192.0.2.1"), "port": .number(443),
                    "ws-opts": obj(["headers": obj(["Host": .string("a.example.com"), "X-A": .string("b")]), "path": .string("/ws")]),
                    "tls": .bool(true), "network": .string("ws"),
                ]),
                obj(["name": .string("N2"), "type": .string("ss"), "nested": .array([.array([.number(1), .number(2)]),
                                                                                    obj(["q": obj(["r": .number(1), "s": .number(2)])])])]),
            ]),
            "dns": obj([
                "enable": .bool(true), "ipv6": .bool(false),
                "nameserver-policy": obj(["+.example.com": .string("1.1.1.1"), "geosite:cn": .array([.string("223.5.5.5")])]),
                "fallback-filter": obj(["geoip": .bool(true), "ipcidr": .array([.string("240.0.0.0/4")])]),
            ]),
            "proxy-groups": .array([obj(["name": .string("Proxy"), "type": .string("select"), "proxies": .array([.string("N1"), .string("N2")])])]),
            "rules": .array([.string("DOMAIN-SUFFIX,example.com,Proxy"), .string("MATCH,DIRECT")]),
        ])
        let text = NCYAML.emit(tree)
        XCTAssertFalse(NCProfileYAMLRepair.looksTruncated(text), text)
        XCTAssertEqual(NCYAML.parse(text), tree, text)
    }

    private let qx = """
    [general]
    network_check_url=http://www.gstatic.com/generate_204

    [server_local]
    vmess=192.0.2.1:443, method=chacha20-ietf-poly1305, password=00000000-0000-0000-0000-000000000001, obfs=wss, obfs-host=a.example.com, obfs-uri=/ws1, tls-verification=false, fast-open=false, udp-relay=false, aead=true, tag=N1
    vmess=192.0.2.2:443, method=chacha20-ietf-poly1305, password=00000000-0000-0000-0000-000000000002, obfs=wss, obfs-host=b.example.com, obfs-uri=/ws2, tls-verification=false, fast-open=false, udp-relay=false, aead=true, tag=N2
    vmess=192.0.2.3:80, method=chacha20-ietf-poly1305, password=00000000-0000-0000-0000-000000000003, obfs=ws, obfs-host=c.example.com, obfs-uri=/ws3, fast-open=false, udp-relay=false, aead=true, tag=N3

    [policy]
    static=Proxy, N1, N2, N3, direct
    static=Video, Proxy, direct

    [filter_local]
    host-suffix, example.com, Proxy
    host-keyword, video, Video
    host, a.example.org, direct
    final, Proxy
    """

    func testQXImportKeepsEveryNodeGroupAndRule() throws {
        let res = NCConfImportPort.importConfResult(qx)
        XCTAssertTrue(res.error?.isEmpty ?? true, res.error ?? "")
        XCTAssertEqual(res.report.proxies, 3)
        XCTAssertFalse(NCProfileYAMLRepair.looksTruncated(res.yaml), res.yaml)
        guard case .object(let m)? = NCYAML.parse(res.yaml) else { return XCTFail("profile YAML does not parse:\n" + res.yaml) }
        func list(_ k: String) -> [NCJSONValue] { if case .array(let a)? = m[k] { return a }; return [] }
        XCTAssertEqual(list("proxies").count, res.report.proxies, res.yaml)
        XCTAssertGreaterThanOrEqual(list("proxy-groups").count, res.report.groups, res.yaml)
        XCTAssertGreaterThanOrEqual(list("rules").count, res.report.rules, res.yaml)
        XCTAssertGreaterThanOrEqual(res.report.groups, 2)
        XCTAssertGreaterThanOrEqual(res.report.rules, 4)
        // Every ws node keeps its path and Host header inside ws-opts.
        for p in list("proxies") {
            guard case .object(let n) = p, case .object(let ws)? = n["ws-opts"] else { return XCTFail("no ws-opts in \(p)") }
            guard case .string(let path)? = ws["path"] else { return XCTFail("no ws-opts.path in \(p)") }
            XCTAssertTrue(path.hasPrefix("/ws"), path)
            guard case .object(let h)? = ws["headers"], case .string(let host)? = h["Host"] else { return XCTFail("no Host in \(p)") }
            XCTAssertTrue(host.hasSuffix(".example.com"), host)
        }
        XCTAssertNil(m["path"], "a nested key leaked to the top level:\n" + res.yaml)
    }

    /// What the old emitter wrote for the same nodes (keys after the first of a nested map at column 0).
    private let oldEmitterOutput = """
    proxies:
      - name: N1
        type: vmess
        server: 192.0.2.1
        port: 443
        ws-opts:
          headers:
            Host: a.example.com
    path: /ws1
        tls: true
      - name: N2
        type: vmess
        server: 192.0.2.2
        port: 443
    proxy-groups:
      - name: Proxy
        type: select
        proxies:
          - N1
          - N2
    rules:
      - MATCH,Proxy

    """

    func testOldEmitterSignatureDetected() {
        XCTAssertTrue(NCProfileYAMLRepair.looksTruncated(oldEmitterOutput))
        // The parser every reader uses stops after the first node — the bug users hit.
        XCTAssertEqual(NCProfileYAMLRepair.itemCount(oldEmitterOutput), 1)
        // Last key of a nested block followed by a top-level key: caught by the nested-only key list.
        XCTAssertTrue(NCProfileYAMLRepair.looksTruncated("dns:\n  enable: true\nnameserver:\n  - 1.1.1.1\nrules:\n  - MATCH,DIRECT\n"))
        // Ordinary profiles are left alone.
        XCTAssertFalse(NCProfileYAMLRepair.looksTruncated("mode: rule\nproxies:\n  - name: a\n    type: ss\nrules:\n  - MATCH,DIRECT\n"))
        XCTAssertFalse(NCProfileYAMLRepair.looksTruncated("a: |\n  text\n  more\nb: [1,\n  2]\n"))
    }

    func testRepairReconvertsFromSourceOnce() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("yaml-repair-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("p.yaml").path
        try oldEmitterOutput.write(toFile: path, atomically: true, encoding: .utf8)
        try qx.write(toFile: path + ".source.conf", atomically: true, encoding: .utf8)

        XCTAssertTrue(NCProfileYAMLRepair.repair(profilePath: path))
        let fixed = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertFalse(NCProfileYAMLRepair.looksTruncated(fixed), fixed)
        XCTAssertGreaterThan(NCProfileYAMLRepair.itemCount(fixed), 1)
        XCTAssertEqual(try String(contentsOfFile: path + ".pre-yaml-fix", encoding: .utf8), oldEmitterOutput)
        // Once: the marker stops a second pass (and a profile without a source is never touched).
        XCTAssertFalse(NCProfileYAMLRepair.repair(profilePath: path))
        let other = dir.appendingPathComponent("q.yaml").path
        try oldEmitterOutput.write(toFile: other, atomically: true, encoding: .utf8)
        XCTAssertFalse(NCProfileYAMLRepair.repair(profilePath: other))
        XCTAssertEqual(try String(contentsOfFile: other, encoding: .utf8), oldEmitterOutput)
    }
}
