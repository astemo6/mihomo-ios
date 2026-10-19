#if DEBUG
import Foundation
import Libmihomo

/// v0.19.6: the gomobile calls the hosted unit tests exercise (UnitTests/, Debug only). The test bundle must not
/// link Libmihomo itself (a second Go runtime in the process), so it reaches the bridge through the app.
enum TestBridge {
    static func validate(home: String, path: String) -> String { LibmihomoValidateConfigIn(home, path) }
    static func inspect(home: String, path: String) -> String { LibmihomoInspectProfile(home, path) }
    static func manualDelete(_ path: String, _ name: String) -> String { LibmihomoManualDelete(path, name) }
    static func manualAdd(_ path: String, _ text: String) -> Int32 { LibmihomoManualAddText(path, text) }
    static func nodeUpsert(home: String, path: String, json: String, oldName: String) -> String {
        LibmihomoProfileNodeUpsert(home, path, json, oldName)
    }
    static func hasNode(_ path: String, _ name: String) -> Bool { LibmihomoProfileHasNode(path, name) }
    static func saveSelection(_ path: String, _ group: String, _ node: String) -> String { LibmihomoSaveSelection(path, group, node) }
}
#endif
