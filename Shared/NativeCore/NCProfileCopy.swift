import Foundation

/// Pure Swift helpers for copying per-profile settings and selections, matching the retired bridge.
enum NCProfileCopy {

    static let profileSettingFiles = ["group-edits.json", "groups.json", "subscriptions.json", "netpolicy.json"]

    /// Returns the .selected.json path for a given profile path (e.g. "path/to/profile.yaml" -> "path/to/profile.selected.json").
    static func selectionsPath(for profilePath: String) -> String {
        let ns = profilePath as NSString
        let ext = ns.pathExtension
        let base = ext.isEmpty ? profilePath : String(profilePath.dropLast(ext.count + 1))
        return base + ".selected.json"
    }

    /// Gives a new profile copy the source's offline selections (<profile>.selected.json),
    /// so the copy starts on the same nodes. An existing file of the copy is kept.
    static func copySelections(fromPath: String, toPath: String) -> String {
        guard !fromPath.isEmpty, !toPath.isEmpty, fromPath != toPath else { return "" }
        let src = selectionsPath(for: fromPath)
        let dst = selectionsPath(for: toPath)

        return NCPathLock.shared.withLock(for: dst) {
            guard FileManager.default.fileExists(atPath: src) else { return "" }
            guard !FileManager.default.fileExists(atPath: dst) else { return "" }

            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: src))
                let dstURL = URL(fileURLWithPath: dst)
                try? FileManager.default.createDirectory(at: dstURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                try data.write(to: dstURL, options: .atomic)
                return ""
            } catch {
                return error.localizedDescription
            }
        }
    }

    /// Gives a new profile copy the per-profile settings of its source.
    /// Entries the copy already has are kept; the source's stored group order is not copied.
    static func copySettings(homeDir: String, fromID: String, toID: String) -> String {
        guard !homeDir.isEmpty, !fromID.isEmpty, !toID.isEmpty, fromID != toID else { return "" }

        for file in profileSettingFiles {
            let path = (homeDir as NSString).appendingPathComponent(file)
            let err = copySingleSetting(path: path, filename: file, fromID: fromID, toID: toID)
            if !err.isEmpty {
                return err
            }
        }
        return ""
    }

    private static func copySingleSetting(path: String, filename: String, fromID: String, toID: String) -> String {
        return NCPathLock.shared.withLock(for: path) {
            let url = URL(fileURLWithPath: path)
            guard let data = try? Data(contentsOf: url),
                  var dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                return ""
            }

            guard var fromVal = dict[fromID] else { return "" }
            guard dict[toID] == nil else { return "" }

            if filename == "group-edits.json" {
                if var editMap = fromVal as? [String: Any] {
                    editMap.removeValue(forKey: "order")
                    if editMap.isEmpty { return "" }
                    fromVal = editMap
                }
            }

            dict[toID] = fromVal

            do {
                let outData = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
                try outData.write(to: url, options: .atomic)
                return ""
            } catch {
                return error.localizedDescription
            }
        }
    }
}
