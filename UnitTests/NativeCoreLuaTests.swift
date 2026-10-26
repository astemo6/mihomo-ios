import XCTest
@testable import Mihomo

final class NativeCoreLuaTests: XCTestCase {

    func testShadowrocketConfLuaNodeImport() {
        let text = """
        [Proxy]
        Direct = direct
        MyLua = lua, 192.0.2.1, 1080, file=backend.lua, username=alice, password=secret
        """
        let c = NCConfImport.surge(text)
        XCTAssertEqual(c.nodes.count, 2)

        let node = c.nodeMap["MyLua"]
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.server, "192.0.2.1")
        XCTAssertEqual(node?.port, 1080)
        XCTAssertEqual(node?.fields["file"]?.string, "backend.lua")
        XCTAssertEqual(node?.fields["username"]?.string, "alice")
        XCTAssertEqual(node?.password, "secret")
        XCTAssertEqual(node?.isLua, true)
        XCTAssertEqual(node?.isLuaPendingS2, true)

        // Check warning reported
        XCTAssertTrue(c.report.warnings.contains { $0.contains("lua proxy backend recognized") })

        // Check NCSupport unsupported reason
        if let node {
            let reason = NCSupport.unsupportedReason(node)
            XCTAssertEqual(reason, "Lua 自定义后端已识别 (待 S2 接入)")
        }
    }

    func testShadowrocketConfLuaScriptImport() {
        let text = """
        [Script]
        script1 = type=http-response,pattern=^https?://api\\.example\\.com,script-path=rule.lua,requires-body=true
        script2 = type=http-request,pattern=^https?://api2\\.example\\.com,script-path=handler.js,engine=lua
        """
        let c = NCConfImport.surge(text)
        XCTAssertEqual(c.scripts.count, 2)

        let s1 = c.scripts.first { $0.name == "script1" }
        XCTAssertNotNil(s1)
        XCTAssertEqual(s1?.isLua, true)
        XCTAssertEqual(s1?.isPendingS2, true)
        XCTAssertEqual(s1?.extra["engine"], "lua")
        XCTAssertEqual(s1?.extra["status"], "pending_s2")

        let s2 = c.scripts.first { $0.name == "script2" }
        XCTAssertNotNil(s2)
        XCTAssertEqual(s2?.isLua, true)
        XCTAssertEqual(s2?.isPendingS2, true)
        XCTAssertEqual(s2?.extra["engine"], "lua")
        XCTAssertEqual(s2?.extra["status"], "pending_s2")

        XCTAssertTrue(c.report.warnings.contains { $0.contains("script 'script1': lua script recognized") })
        XCTAssertTrue(c.report.warnings.contains { $0.contains("script 'script2': lua script recognized") })
    }

    func testQuantumultXServerLocalAndRewriteLuaImport() {
        let text = """
        [server_local]
        lua = 10.0.0.1:8888, file=custom.lua, user=bob, password=pwd, tag=QX-Lua

        [rewrite_local]
        ^https?://example\\.com url script-response-body test_rewrite.lua
        """
        let c = NCQXImport.quantumultX(text)

        let node = c.nodeMap["QX-Lua"]
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.server, "10.0.0.1")
        XCTAssertEqual(node?.port, 8888)
        XCTAssertEqual(node?.fields["file"]?.string, "custom.lua")
        XCTAssertEqual(node?.fields["username"]?.string, "bob")
        XCTAssertEqual(node?.password, "pwd")
        XCTAssertEqual(node?.isLua, true)
        XCTAssertEqual(node?.isLuaPendingS2, true)

        let script = c.scripts.first { $0.scriptPath == "test_rewrite.lua" }
        XCTAssertNotNil(script)
        XCTAssertEqual(script?.isLua, true)
        XCTAssertEqual(script?.isPendingS2, true)
        XCTAssertEqual(script?.extra["engine"], "lua")

        XCTAssertTrue(c.report.warnings.contains { $0.contains("quantumultx [server_local]: lua proxy backend 'QX-Lua' recognized") })
        XCTAssertTrue(c.report.warnings.contains { $0.contains("quantumultx rewrite: lua script 'test_rewrite.lua' recognized") })
    }

    func testMihomoClashYAMLLuaNodeImport() {
        let root: [String: NCJSONValue] = [
            "proxies": .array([
                .object([
                    "name": .string("ClashLua"),
                    "type": .string("lua"),
                    "server": .string("203.0.113.5"),
                    "port": .number(9090),
                    "file": .string("client.lua")
                ])
            ])
        ]
        let cfg = NCConfig.decode(root: root)
        let c = NCCanonicalConfig.from(mihomo: cfg)

        XCTAssertEqual(c.nodes.count, 1)
        let node = c.nodes.first
        XCTAssertEqual(node?.name, "ClashLua")
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.isLua, true)
        XCTAssertEqual(node?.isLuaPendingS2, true)
        XCTAssertEqual(node?.fields["lua-status"]?.string, "pending_s2")
        XCTAssertTrue(c.report.warnings.contains { $0.contains("node 'ClashLua': lua proxy backend recognized") })

        if let node {
            let reason = NCSupport.unsupportedReason(node)
            XCTAssertEqual(reason, "Lua 自定义后端已识别 (待 S2 接入)")
        }
    }
}
