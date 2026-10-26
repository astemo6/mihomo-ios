#if DEBUG
import Foundation

/// v0.19.6: the the old bridge calls the hosted unit tests exercise (UnitTests/, Debug only). The test bundle must not
/// link the old core framework itself (a second old runtime in the process), so it reaches the bridge through the app.
enum TestBridge {
    static func validate(home: String, path: String) -> String { NCConfigValidator.validateConfigIn(home: home, path: path) }
    static func inspect(home: String, path: String) -> String { NCProfileInspectorPort.inspectProfileJSON(home: home, path: path) }
    static func manualDelete(_ path: String, _ name: String) -> String { NCManualNodes.delete(path: path, name: name) }
    static func manualAdd(_ path: String, _ text: String) -> Int32 { NCManualNodes.addText(path: path, text: text).count }
    static func nodeUpsert(home: String, path: String, json: String, oldName: String) -> String {
        NCProfileNodes.upsert(homeDir: home, path: path, nodeJSON: json, oldName: oldName)
    }
    static func hasNode(_ path: String, _ name: String) -> Bool { NCProfileNodes.hasNode(path: path, name: name) }
    static func saveSelection(_ path: String, _ group: String, _ node: String) -> String { NCProfileSelections.save(path, group: group, node: node) }
}
#endif
