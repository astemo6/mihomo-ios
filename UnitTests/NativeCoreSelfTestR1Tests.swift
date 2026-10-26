import XCTest
@testable import Mihomo

/// fix/nc-selftest-r1 — test10_ProfileNodeEdit 定性复现: 编辑配置内节点（改名 + 改服务器）
/// 保存失败。用 UITestSeed 的演示配置原样走编辑器的保存路径
/// (NodeEditorView.save → ProfileStore.upsertProfileNode → NCProfileNodes.upsert),
/// 断言 upsert 无错误返回、文件落盘且组引用跟着改名。
final class NativeCoreSelfTestR1Tests: XCTestCase {

    private func seedProfileFile() throws -> (dir: URL, path: String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("selftest-r1-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("demo.yaml").path
        try UITestSeed.profileYAML.write(toFile: path, atomically: true, encoding: .utf8)
        return (dir, path)
    }

    /// 编辑器 build() 的等价物: 原节点字典改 name / server 后序列化为 nodeJSON。
    func testProfileNodeRenameSaveReproducesTest10() throws {
        let (dir, path) = try seedProfileFile()
        defer { try? FileManager.default.removeItem(at: dir) }

        let json = NCProfileNodes.get(path: path, name: "🇯🇵 Tokyo 02")
        XCTAssertFalse(json.isEmpty, "seed node must be readable: \(NCProfileNodes.lastError)")
        var node = try XCTUnwrap(
            (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any],
            "node JSON must parse")
        node["name"] = "Tokyo 02 Edited"
        node["server"] = "192.0.2.222"
        let nodeJSON = String(decoding: try JSONSerialization.data(withJSONObject: node), as: UTF8.self)

        let err = NCProfileNodes.upsert(homeDir: dir.path, path: path, nodeJSON: nodeJSON,
                                        oldName: "🇯🇵 Tokyo 02")
        XCTAssertEqual(err, "", "upsert must succeed (test10 save path)")

        let after = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertTrue(after.contains("Tokyo 02 Edited"), "renamed node written to the profile")
        XCTAssertTrue(after.contains("192.0.2.222"), "edited server written to the profile")
        XCTAssertFalse(after.contains("\"🇯🇵 Tokyo 02\""), "old name fully renamed (incl. group refs)")
    }
}
