import Foundation

/// nc-integrate: the small file-level bridge calls the app still made, in Swift.
/// - SaveConfSource
/// - ValidateHostEntry
/// - ResetRuleHits
/// Writes are atomic (Data.write .atomic = the old core writeFileAtomic: temp file + rename).
enum NCAppFilePorts {

    /// bridge SaveConfSource: keeps the original .conf of an imported profile at <profile>.source.conf.
    /// Returns "" or an error.
    static func saveConfSource(profilePath: String, text: String) -> String {
        if profilePath.isEmpty || text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "" }
        do {
            try Data(text.utf8).write(to: URL(fileURLWithPath: profilePath + ".source.conf"), options: .atomic)
            return ""
        } catch {
            return error.localizedDescription
        }
    }

    /// bridge ValidateHostEntry: "" when the 本地 DNS 映射 entry is usable, else a Chinese reason.
    static func validateHostEntry(domain: String, value: String) -> String {
        if !NCRuntimeSteps.validHostName(domain.trimmingCharacters(in: .whitespaces)) { return "域名无效" }
        if NCRuntimeSteps.hostValue(value) == nil { return "映射值应为一个或多个 IP（用逗号分隔），或一个域名" }
        return ""
    }

    private static let ruleHitsLock = NSLock()

    /// bridge ResetRuleHits: key "" deletes <home>/rule-hits.json, else drops that rule identity
    /// ("TYPE,payload,policy") from its `rules` map. Returns "" or an error.
    /// the old core also cleared the running core's in-process hit cache; the app process runs no core, so there is none.
    static func resetRuleHits(home: String, key: String) -> String {
        ruleHitsLock.lock()
        defer { ruleHitsLock.unlock() }
        let url = URL(fileURLWithPath: home).appendingPathComponent("rule-hits.json")
        let fm = FileManager.default
        if key.isEmpty {
            if fm.fileExists(atPath: url.path) {
                do { try fm.removeItem(at: url) } catch { return error.localizedDescription }
            }
            return ""
        }
        // the old core readRuleHits: a missing or broken file is an empty {since: 0, rules: {}}.
        var d: [String: Any] = ["since": 0, "rules": [String: Any]()]
        if let b = fm.contents(atPath: url.path),
           let o = try? JSONSerialization.jsonObject(with: b) as? [String: Any] {
            d = o
            if d["since"] == nil { d["since"] = 0 }
        }
        var rules = d["rules"] as? [String: Any] ?? [:]
        rules.removeValue(forKey: key)
        d["rules"] = rules
        do {
            let b = try JSONSerialization.data(withJSONObject: d)
            try b.write(to: url, options: .atomic)
            return ""
        } catch {
            return error.localizedDescription
        }
    }
}
