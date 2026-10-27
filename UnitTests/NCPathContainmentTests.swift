import XCTest
@testable import Tern

/// fix/nc-0.20.2: 「路径不在内核目录内」 on every rule-set / node-set update after a reinstall.
/// Root cause: providerStore compared NSString.standardizingPath of home (exists → "/private" stripped) with the
/// cache path (not downloaded yet → "/private" kept). Containment is now lexical with /private/var ≡ /var.
final class NCPathContainmentTests: XCTestCase {
    let H = "/private/var/mobile/Containers/Shared/AppGroup/AAAA/tern"

    private func tempHome(privatePrefix: Bool) throws -> (home: String, root: String) {
        // /private/tmp exists on macOS (simulator host) and /tmp → /private/tmp, the same shape as /private/var on iOS.
        let root = "/private/tmp/tern-ut-\(UUID().uuidString)"
        let home = root + "/tern"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(atPath: root) }
        return (privatePrefix ? home : String(home.dropFirst("/private".count)), root)
    }

    func testLexicalContainment() {
        XCTAssertTrue(NCPathContainment.isInside(home: H, H + "/./ruleset/x.txt"))
        XCTAssertTrue(NCPathContainment.isInside(home: H, "./proxies/a.yaml"))
        XCTAssertFalse(NCPathContainment.isInside(home: H, H + "x/a"))
        XCTAssertFalse(NCPathContainment.isInside(home: "", "/a"))
    }

    func testVarAndPrivateVarMix() {
        let varHome = "/var/mobile/Containers/Shared/AppGroup/AAAA/tern"
        XCTAssertTrue(NCPathContainment.isInside(home: varHome, H + "/rules/x"))
        XCTAssertTrue(NCPathContainment.isInside(home: H, varHome + "/rules/x"))
        XCTAssertEqual(NCPathContainment.relative(home: H, varHome + "/rules/x"), "rules/x")
    }

    func testTraversalStillRejected() {
        XCTAssertFalse(NCPathContainment.isInside(home: H, H + "/../../etc/passwd"))
        XCTAssertFalse(NCPathContainment.isInside(home: H, "../profiles/x"))
        XCTAssertFalse(NCPathContainment.isInside(home: H, "rules/../../x"))
        XCTAssertNil(NCPathContainment.rebaseForeignAbsolute(home: H, "/x/tern/../../etc", fallbackDir: "rules"))
        let out = NCProviderPorts.providerStore(home: H, kind: "rule", cachePath: H + "/../evil.txt", convert: "",
                                                data: Data("DOMAIN,a.com\n".utf8))
        XCTAssertTrue(out.contains("路径不在内核目录内"), out)
    }

    /// The device failure: an existing home under /private, a cache file that does not exist yet.
    func testProviderStoreNonexistentFileUnderPrivateHome() throws {
        let (home, _) = try tempHome(privatePrefix: true)
        let cache = home + "/./ruleset/custom-1.txt"
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache))
        let out = NCProviderPorts.providerStore(home: home, kind: "rule", cachePath: cache, convert: "",
                                                data: Data("DOMAIN-SUFFIX,example.com\n".utf8))
        XCTAssertTrue(out.contains("\"error\":\"\""), out)
        XCTAssertTrue(FileManager.default.fileExists(atPath: cache))
    }

    func testProviderStoreVarHomePrivateCache() throws {
        let (home, root) = try tempHome(privatePrefix: false) // "/tmp/…/tern"
        let cache = root + "/tern/proxies/sub.yaml"             // "/private/tmp/…/tern/proxies/sub.yaml"
        let out = NCProviderPorts.providerStore(home: home, kind: "proxy", cachePath: cache, convert: "",
                                                data: Data("proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: p}\n".utf8))
        XCTAssertTrue(out.contains("\"error\":\"\""), out)
    }

    /// An import's first-time downloads into an empty home (QX import: 「0 个已下载，28 个失败」).
    func testFirstDownloadsIntoEmptyHomeSucceed() throws {
        let (home, _) = try tempHome(privatePrefix: true)
        for i in 0..<5 {
            let m: [String: NCJSONValue] = ["path": .string("./ruleset/custom-\(i).txt"), "url": .string("https://e.invalid/\(i)")]
            let cache = ncProviderCachePath(home: home, kind: "rule", m)
            let out = NCProviderPorts.providerStore(home: home, kind: "rule", cachePath: cache, convert: "list",
                                                    data: Data("HOST-SUFFIX,example\(i).com,proxy\n".utf8))
            XCTAssertTrue(out.contains("\"error\":\"\""), out)
        }
    }

    func testOldContainerPathRebased() {
        let old = "/private/var/mobile/Containers/Shared/AppGroup/OLD/tern/ruleset/a.txt"
        XCTAssertEqual(NCPathContainment.rebaseForeignAbsolute(home: H, old, fallbackDir: "rules"), "./ruleset/a.txt")
        XCTAssertEqual(NCPathContainment.rebaseForeignAbsolute(home: H, "/elsewhere/b.yaml", fallbackDir: "proxies"), "./proxies/b.yaml")
        XCTAssertNil(NCPathContainment.rebaseForeignAbsolute(home: H, H + "/rules/c", fallbackDir: "rules"))
        let m: [String: NCJSONValue] = ["path": .string(old)]
        XCTAssertEqual(ncProviderCachePath(home: H, kind: "rule", m), H + "/ruleset/a.txt")
        var raw: [String: NCJSONValue] = ["rule-providers": .object(["a": .object(["path": .string(old)])]),
                                          "proxy-providers": .object(["p": .object(["path": .string("/old/x.yaml")])])]
        XCTAssertEqual(NCProviderPathRebase.rebase(&raw, home: H), 2)
        XCTAssertEqual(raw["rule-providers"]?.object?["a"]?.object?["path"], .string("./ruleset/a.txt"))
        XCTAssertEqual(raw["proxy-providers"]?.object?["p"]?.object?["path"], .string("./proxies/x.yaml"))
    }

    func testProfileTextMigrationIsTargetedAndIdempotent() {
        let y = """
        rule-providers:
          a:
            type: http
            path: /private/var/mobile/Containers/Shared/AppGroup/OLD/tern/ruleset/a.txt
          b: {type: http, path: '/var/mobile/Containers/Shared/AppGroup/OLD/tern/rules/b.yaml', url: x}
          c:
            path: ./ruleset/c.txt
        proxies:
          - {name: x, ws-opts: {path: /ws}}
        """
        guard let out = NCProviderPathRebase.migrateText(y, home: H) else { return XCTFail("not migrated") }
        XCTAssertTrue(out.contains("path: ./ruleset/a.txt"))
        XCTAssertTrue(out.contains("path: './rules/b.yaml', url: x}"))
        XCTAssertTrue(out.contains("path: ./ruleset/c.txt"))
        XCTAssertTrue(out.contains("path: /ws"))
        XCTAssertNil(NCProviderPathRebase.migrateText(out, home: H))
    }

    func testTailscaleStateDirAcceptsPrivateVarMix() throws {
        let varHome = "/var/mobile/Containers/Shared/AppGroup/AAAA/tern"
        let u = try TailscaleStatePath.resolveStateDir(home: varHome, stateDir: H + "/tailscale/n1", nodeName: "n1")
        XCTAssertTrue(u.path.hasSuffix("/tern/tailscale/n1"))
        XCTAssertThrowsError(try TailscaleStatePath.resolveStateDir(home: H, stateDir: "../x", nodeName: "n1"))
    }
}
