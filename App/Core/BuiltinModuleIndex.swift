import Foundation

// 模块库 built-in curated index (feat/module-browser).
//
// App/Resources/BuiltinModules.json ships inside the app: a short hand-picked list of well-known modules
// (links only, every module stays maintained by its author), with names and descriptions in the six app
// languages. It is the one default index source, works offline, and is never fetched from the network;
// user-added index URLs sit next to it. Each entry has one preferred URL plus `alternates` — the same
// module published in other formats (Surge .sgmodule, Loon .plugin, Stash .stoverride, QX .snippet / .conf),
// which the preview lets the user pick from. bridge/v015_builtin_modules_test.go checks the file's shape.

enum BuiltinModuleIndex {
    static let sourceID = "builtin"
    /// Not a network URL: ModuleGallery.refresh loads the bundled file for this source.
    static let sourceURL = "builtin:curated"

    static var source: GallerySource { GallerySource(id: sourceID, name: "内置精选", url: sourceURL) }
    static var displayName: String { String(localized: "内置精选") }

    struct Entry: Decodable {
        var id: String
        var name: [String: String]
        var category: String
        var author: String?
        var homepage: String?
        var url: String
        var alternates: [String]?
        var desc: [String: String]
    }

    struct File: Decodable {
        var version: Int
        var updated: String
        var modules: [Entry]
    }

    /// Category ids used in the file → localized names (literals so the String Catalog picks them up).
    static func categoryName(_ id: String) -> String {
        switch id {
        case "adblock": return String(localized: "去广告")
        case "subtitles": return String(localized: "字幕与翻译")
        case "enhance": return String(localized: "功能增强")
        case "tools": return String(localized: "工具")
        default: return id
        }
    }

    /// The app's current localization (zh-Hans / zh-Hant / en / ja / ko / ru) as used by the JSON.
    static var languageKey: String {
        let l = (Bundle.main.preferredLocalizations.first ?? "zh-Hans").lowercased()
        if l.hasPrefix("zh") { return (l.contains("hant") || l.hasSuffix("tw") || l.hasSuffix("hk") || l.hasSuffix("mo")) ? "zh-Hant" : "zh-Hans" }
        return String(l.prefix(2))
    }

    static func pick(_ d: [String: String]) -> String {
        d[languageKey] ?? d["en"] ?? d["zh-Hans"] ?? d.values.first ?? ""
    }

    static func load() -> GalleryIndex {
        guard let url = Bundle.main.url(forResource: "BuiltinModules", withExtension: "json"),
              let data = try? Data(contentsOf: url) else {
            return GalleryIndex(items: [], fetchedAt: 0, error: String(localized: "内置索引缺失"))
        }
        do {
            let f = try JSONDecoder().decode(File.self, from: data)
            let items = f.modules.map { e in
                GalleryItem(name: pick(e.name), url: e.url, desc: pick(e.desc), category: categoryName(e.category),
                            author: e.author ?? "", icon: "", sourceID: sourceID,
                            alternates: (e.alternates ?? []).isEmpty ? nil : e.alternates, homepage: e.homepage)
            }
            return GalleryIndex(items: items, fetchedAt: Date().timeIntervalSince1970, error: nil)
        } catch {
            return GalleryIndex(items: [], fetchedAt: 0, error: String(localized: "无法识别的索引格式"))
        }
    }
}

extension ModuleGallery {
    /// Source name for display (the built-in source follows the app language).
    func displayName(_ s: GallerySource) -> String {
        switch s.id {
        case BuiltinModuleIndex.sourceID: return BuiltinModuleIndex.displayName
        case KeleeHub.sourceID: return KeleeHub.displayName
        default: return s.name
        }
    }

    /// Third-party index sources offered with one tap in 索引来源 (the user decides; not added by default).
    static let suggestedSources: [GallerySource] = [
        GallerySource(id: "suggested-maasea", name: "Maasea/sgmodule", url: "https://github.com/Maasea/sgmodule"),
        GallerySource(id: "suggested-loonkiss", name: "QingRex/LoonKissSurge", url: "https://github.com/QingRex/LoonKissSurge/tree/main/Surge"),
    ]

    /// Comparable form of a module URL: trimmed, no fragment, lower-case scheme/host, GitHub blob/raw page
    /// links mapped to raw.githubusercontent.com, so a module added from a link elsewhere still shows as added.
    nonisolated static func normalizedURL(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let h = s.firstIndex(of: "#") { s = String(s[..<h]) }
        guard var c = URLComponents(string: s) else { return s }
        c.scheme = c.scheme?.lowercased()
        c.host = c.host?.lowercased()
        if c.host == "github.com" {
            var p = c.path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
            if p.count >= 5, p[2] == "blob" || p[2] == "raw" {
                p.remove(at: 2)
                c.host = "raw.githubusercontent.com"
                c.path = "/" + p.joined(separator: "/")
                c.query = nil
            }
        }
        if c.scheme == "http" { c.scheme = "https" }
        return c.string ?? s
    }

    /// Every URL the item can be added from (preferred first).
    nonisolated static func urls(of item: GalleryItem) -> [String] {
        [item.url] + (item.alternates ?? [])
    }

    /// The added module for this item, matched on the preferred URL or any alternate format.
    static func installed(_ item: GalleryItem, in modules: [EngineModule]) -> EngineModule? {
        let keys = Set(urls(of: item).map(normalizedURL))
        return modules.first { !$0.url.isEmpty && keys.contains(normalizedURL($0.url)) }
    }
}
