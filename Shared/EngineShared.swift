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

/// Per remote script URL settings from the resource manager (bridge/mitm ScriptResource).
struct ScriptResourceSetting: Codable, Hashable {
    var disabled: Bool? = nil
    var interval: Int? = nil
}

/// Mirrors <home>/engine/engine.json (bridge/mitm/config.go).
struct EngineConfig: Codable, Equatable {
    var enabled = false          // 重写与脚本总开关
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

    enum CodingKeys: String, CodingKey { case enabled, mitm, skipCertVerify, h2, captureBodies, hostnames, rules, scripts, modules, scriptResources, quic, quicAllow }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        mitm = try c.decodeIfPresent(Bool.self, forKey: .mitm) ?? false
        skipCertVerify = try c.decodeIfPresent(Bool.self, forKey: .skipCertVerify) ?? false
        h2 = try c.decodeIfPresent(Bool.self, forKey: .h2) ?? true
        captureBodies = try c.decodeIfPresent(Bool.self, forKey: .captureBodies) ?? true
        hostnames = try c.decodeIfPresent([String].self, forKey: .hostnames) ?? []
        rules = try c.decodeIfPresent([EngineItem].self, forKey: .rules) ?? []
        scripts = try c.decodeIfPresent([EngineItem].self, forKey: .scripts) ?? []
        modules = try c.decodeIfPresent([EngineModule].self, forKey: .modules) ?? []
        scriptResources = try? c.decodeIfPresent([String: ScriptResourceSetting].self, forKey: .scriptResources)
        quic = try? c.decodeIfPresent(String.self, forKey: .quic)
        quicAllow = try? c.decodeIfPresent([String].self, forKey: .quicAllow)
    }

    static func load() -> EngineConfig {
        guard let data = try? Data(contentsOf: EnginePaths.configURL),
              let c = try? JSONDecoder().decode(EngineConfig.self, from: data) else { return EngineConfig() }
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
