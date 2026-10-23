import Foundation

/// Paths of the HTTP engine (MitM / rewrite / scripts / modules) inside the App Group container.
/// The Go side (bridge/mitm) reads the same layout under <home>/engine.
enum EnginePaths {
    static var dir: URL { AppShared.ensureDir(AppShared.homeURL.appendingPathComponent("engine", isDirectory: true)) }
    static var configURL: URL { dir.appendingPathComponent("engine.json") }
    static var modulesDir: URL { AppShared.ensureDir(dir.appendingPathComponent("modules", isDirectory: true)) }
    static var scriptsDir: URL { AppShared.ensureDir(dir.appendingPathComponent("scripts", isDirectory: true)) }
    static var storeURL: URL { dir.appendingPathComponent("store.json") }
    static func moduleURL(_ id: String) -> URL { modulesDir.appendingPathComponent(safe(id) + ".txt") }
    static func scriptURL(_ name: String) -> URL { scriptsDir.appendingPathComponent(safe(name)) }

    static func safe(_ s: String) -> String {
        String(s.map { c in (c.isASCII && (c.isLetter || c.isNumber || "-_.".contains(c))) ? c : "_" })
    }
}

/// One rewrite rule / script line with an enable switch (Surge, QX, Loon syntax).
struct EngineItem: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var enabled: Bool = true
    var line: String
    var note: String? = nil
}

/// An imported module (.sgmodule / QX snippet / Loon plugin / Stash override / rewrite list).
struct EngineModule: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String
    var url: String
    var enabled: Bool = true
    var args: [String: String]? = nil
    /// Module policy name → profile group chosen by the user (for [Rule] lines naming unknown policies).
    var policies: [String: String]? = nil
    var updatedAt: Double? = nil
    /// Auto-update interval in seconds (nil = 1 day).
    var interval: Int? = nil
}

/// r7 R7A-10: tolerant field-by-field decoding; an entry without `line` cannot be used and is skipped by the list.
extension EngineItem {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        line = try c.decode(String.self, forKey: .line)
        id = (try? c.decodeIfPresent(String.self, forKey: .id)).flatMap { $0 }.flatMap { $0.isEmpty ? nil : $0 } ?? UUID().uuidString
        enabled = (try? c.decodeIfPresent(Bool.self, forKey: .enabled)) ?? true
        note = (try? c.decodeIfPresent(String.self, forKey: .note)) ?? nil
    }
}

/// r7 R7A-10: a module needs its url; everything else has a default.
extension EngineModule {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        url = try c.decode(String.self, forKey: .url)
        id = (try? c.decodeIfPresent(String.self, forKey: .id)).flatMap { $0 }.flatMap { $0.isEmpty ? nil : $0 } ?? UUID().uuidString
        let n = (try? c.decodeIfPresent(String.self, forKey: .name)) ?? nil
        name = n.flatMap { $0.isEmpty ? nil : $0 } ?? (URL(string: url)?.deletingPathExtension().lastPathComponent ?? url)
        enabled = (try? c.decodeIfPresent(Bool.self, forKey: .enabled)) ?? true
        args = (try? c.decodeIfPresent([String: String].self, forKey: .args)) ?? nil
        policies = (try? c.decodeIfPresent([String: String].self, forKey: .policies)) ?? nil
        updatedAt = (try? c.decodeIfPresent(Double.self, forKey: .updatedAt)) ?? nil
        interval = (try? c.decodeIfPresent(Int.self, forKey: .interval)) ?? nil
    }
}

/// r7 R7A-10: decodes an array, skipping elements that fail instead of failing the whole array.
struct LossyList<T: Decodable>: Decodable {
    var items: [T] = []
    /// Decodes (and so consumes) any element without reading it.
    private struct Skip: Decodable { init(from decoder: Decoder) throws {} }
    init(from decoder: Decoder) throws {
        var c = try decoder.unkeyedContainer()
        while !c.isAtEnd {
            if let v = try? c.decode(T.self) { items.append(v) } else { _ = try? c.decode(Skip.self) }
        }
    }
}

/// Per remote script URL settings from the resource manager (bridge/mitm ScriptResource).
struct ScriptResourceSetting: Codable, Hashable {
    var disabled: Bool? = nil
    var interval: Int? = nil
}

/// Mirrors <home>/engine/engine.json (bridge/mitm/config.go).
struct EngineConfig: Codable, Equatable {
    var enabled = false          // 复写总开关 (URL / header / body rewrite, map local)
    /// 脚本总开关. engine.json written before the two switches were split has no key: it takes `enabled`,
    /// so scripts keep running for users who had 重写与脚本 on.
    var scriptsEnabled = false
    var mitm = false             // HTTPS 解密总开关
    var skipCertVerify = false
    var h2: Bool? = true
    var captureBodies: Bool? = true
    var hostnames: [String] = []
    var rules: [EngineItem] = []
    var scripts: [EngineItem] = []
    var modules: [EngineModule] = []
    var scriptResources: [String: ScriptResourceSetting]? = nil
    /// "mitm" (default: block QUIC only for MitM hosts) or "all".
    var quic: String? = nil
    /// MitM hosts whose QUIC is not blocked.
    var quicAllow: [String]? = nil

    init() {}

    /// Either switch on: modules are parsed, their [Rule] lines and MitM hostnames apply.
    var anyEnabled: Bool { enabled || scriptsEnabled }

    enum CodingKeys: String, CodingKey { case enabled, scriptsEnabled, mitm, skipCertVerify, h2, captureBodies, hostnames, rules, scripts, modules, scriptResources, quic, quicAllow }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        enabled = (try? c.decodeIfPresent(Bool.self, forKey: .enabled)) ?? false
        scriptsEnabled = (try? c.decodeIfPresent(Bool.self, forKey: .scriptsEnabled)) ?? enabled
        mitm = (try? c.decodeIfPresent(Bool.self, forKey: .mitm)) ?? false
        skipCertVerify = (try? c.decodeIfPresent(Bool.self, forKey: .skipCertVerify)) ?? false
        h2 = (try? c.decodeIfPresent(Bool.self, forKey: .h2)) ?? true
        captureBodies = (try? c.decodeIfPresent(Bool.self, forKey: .captureBodies)) ?? true
        hostnames = (try? c.decodeIfPresent(LossyList<String>.self, forKey: .hostnames))?.items ?? []
        // r7 (review7 R7A-10): one bad entry (missing id / line, a mistyped field — a hand-edited backup, an older or
        // newer build) made the whole decode fail; load() then returned an empty config and the next save() wiped
        // every module. Lists now skip only the entries that cannot be read.
        rules = (try? c.decodeIfPresent(LossyList<EngineItem>.self, forKey: .rules))?.items ?? []
        scripts = (try? c.decodeIfPresent(LossyList<EngineItem>.self, forKey: .scripts))?.items ?? []
        modules = (try? c.decodeIfPresent(LossyList<EngineModule>.self, forKey: .modules))?.items ?? []
        scriptResources = try? c.decodeIfPresent([String: ScriptResourceSetting].self, forKey: .scriptResources)
        quic = try? c.decodeIfPresent(String.self, forKey: .quic)
        quicAllow = try? c.decodeIfPresent([String].self, forKey: .quicAllow)
    }

    static func load() -> EngineConfig {
        guard let data = try? Data(contentsOf: EnginePaths.configURL) else { return EngineConfig() }
        guard let c = try? JSONDecoder().decode(EngineConfig.self, from: data) else {
            // r7 R7A-10: not even an object (truncated / not JSON). Keep a copy before anything saves over it.
            let bad = EnginePaths.configURL.deletingLastPathComponent().appendingPathComponent("engine.json.unreadable")
            if !FileManager.default.fileExists(atPath: bad.path) { try? data.write(to: bad, options: .atomic) }
            return EngineConfig()
        }
        return c
    }

    func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard var data = try? enc.encode(self) else { return }
        if let lang = Self.uiLanguage, var obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            obj["language"] = lang
            if let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) { data = d }
        }
        try? data.write(to: EnginePaths.configURL, options: .atomic)
    }

    /// r7 B28: the UI language scripts see as $environment.language ("zh-Hans", "en" …). Not a stored
    /// setting (kept out of Equatable / CodingKeys): stamped into engine.json by save() and at app launch.
    /// nil outside the app (extension / widget bundles may carry fewer localizations).
    static var uiLanguage: String? {
        guard Bundle.main.bundlePath.hasSuffix(".app") else { return nil }
        return Bundle.main.preferredLocalizations.first
    }

    /// Writes the current UI language into engine.json when it differs (language switched in Settings).
    static func stampLanguage() {
        guard let lang = uiLanguage,
              let data = try? Data(contentsOf: EnginePaths.configURL),
              var obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              obj["language"] as? String != lang else { return }
        obj["language"] = lang
        if let d = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) {
            try? d.write(to: EnginePaths.configURL, options: .atomic)
        }
    }
}

/// Payload the Go engine sends for $notification.post / $notify.
struct ScriptNotification: Decodable {
    var title: String?
    var subtitle: String?
    var body: String?
    var url: String?
}
