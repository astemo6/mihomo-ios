import Foundation

// v0.15 模块库: browse / search modules from configurable index URLs, preview before adding.
//
// An index source is one URL in any of these shapes (detected from the URL and the reply):
//  - a GitHub repository or folder: https://github.com/<owner>/<repo>[/tree/<branch>/<path>]
//    → one git-trees call lists every module file below the path (sub-folder = category);
//  - JSON: an array of items, or an object with modules / plugins / items / list / lists / data (array), or
//    categories: [{ name, modules: [...] }], or { "<category>": [items] }. Item keys:
//    name|title, url|link|install|download, desc|description|summary, category|group|type|tag|tags (string or
//    array: the first entry), author (string, or [{ name }] / [string]), icon|img (relative to the index URL);
//  - text / Markdown / HTML: module links ([name](url), "name = url", bare URLs, surge:/// loon:// stash://
//    egern:/ install links).
// Parsed indexes are cached in Caches/module-gallery so the list opens offline.

struct GallerySource: Codable, Identifiable, Hashable {
    var id = UUID().uuidString
    var name: String
    var url: String
}

struct GalleryItem: Codable, Identifiable, Hashable {
    var id: String { url }
    var name: String
    var url: String
    var desc: String = ""
    var category: String = ""
    var author: String = ""
    var icon: String = ""
    var sourceID: String = ""
    /// Built-in index: the same module in other formats (optional for caches written before).
    var alternates: [String]? = nil
    var homepage: String? = nil

    /// SURGE / LOON / STASH / QX / EGERN from the file extension (the real format shows in the preview).
    var formatHint: String {
        let ext = (URL(string: url)?.pathExtension ?? "").lowercased()
        switch ext {
        case "sgmodule": return "surge"
        case "plugin", "lpx": return "loon"
        case "stoverride": return "stash"
        case "snippet", "qxrewrite", "conf": return "qx"
        case "yaml", "yml": return "egern"
        default: return ""
        }
    }
}

struct GalleryIndex: Codable {
    var items: [GalleryItem]
    var fetchedAt: Double
    var error: String?
}

@MainActor
final class ModuleGallery: ObservableObject {
    static let shared = ModuleGallery()

    /// The built-in curated index (BuiltinModuleIndex) and 可莉插件中心 (KeleeHub) are the defaults; other
    /// third-party repositories are offered as suggestions in 索引来源.
    static let defaultSources: [GallerySource] = [BuiltinModuleIndex.source, KeleeHub.source]

    @Published var sources: [GallerySource]
    @Published var indexes: [String: GalleryIndex] = [:]
    @Published var loading: Set<String> = []

    private let key = "moduleGallery.sources"

    init() {
        if let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode([GallerySource].self, from: d) {
            sources = s
        } else {
            sources = Self.defaultSources
        }
        // feat/kelee-hub: 可莉插件中心 joins the saved sources once; removing it afterwards is respected.
        if !AppShared.defaults.bool(forKey: KeleeHub.offeredKey) {
            AppShared.defaults.set(true, forKey: KeleeHub.offeredKey)
            if !sources.contains(where: { $0.id == KeleeHub.sourceID || $0.url == KeleeHub.indexURL }) {
                sources.append(KeleeHub.source)
                saveSources()
            }
        }
        for s in sources { if let i = Self.loadCache(s) { indexes[s.id] = i } }
        if sources.contains(where: { $0.id == BuiltinModuleIndex.sourceID }) { indexes[BuiltinModuleIndex.sourceID] = BuiltinModuleIndex.load() }
    }

    func saveSources() {
        if let d = try? JSONEncoder().encode(sources) { AppShared.defaults.set(d, forKey: key) }
    }

    func addSource(url raw: String, name: String) -> String? {
        let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let u = URL(string: url), u.scheme?.hasPrefix("http") == true, u.host != nil else { return String(localized: "请输入 http(s) 链接") }
        if sources.contains(where: { $0.url == url }) { return String(localized: "这个来源已经添加过了") }
        let n = name.trimmingCharacters(in: .whitespaces)
        let s = GallerySource(name: n.isEmpty ? Self.defaultName(u) : n, url: url)
        sources.append(s)
        saveSources()
        Task { await refresh(s) }
        return nil
    }

    func removeSource(_ s: GallerySource) {
        sources.removeAll { $0.id == s.id }
        indexes[s.id] = nil
        try? FileManager.default.removeItem(at: Self.cacheURL(s))
        saveSources()
    }

    func restoreDefaults() {
        for d in Self.defaultSources where !sources.contains(where: { $0.url == d.url }) { sources.append(d) }
        saveSources()
        Task { await refreshAll(force: false) }
    }

    static func defaultName(_ u: URL) -> String {
        if u.host == "github.com" {
            let p = u.pathComponents.filter { $0 != "/" }
            if p.count >= 2 { return p[0] + "/" + p[1] }
        }
        return u.host ?? u.absoluteString
    }

    var allItems: [GalleryItem] {
        sources.flatMap { indexes[$0.id]?.items ?? [] }
    }

    /// Refreshes sources never fetched (or older than 12 h unless `force`).
    func refreshAll(force: Bool) async {
        await withTaskGroup(of: Void.self) { g in
            for s in sources {
                let age = Date().timeIntervalSince1970 - (indexes[s.id]?.fetchedAt ?? 0)
                if force || indexes[s.id] == nil || age > 12 * 3600 { g.addTask { await self.refresh(s) } }
            }
        }
    }

    func refresh(_ s: GallerySource) async {
        if s.id == BuiltinModuleIndex.sourceID { indexes[s.id] = BuiltinModuleIndex.load(); return }
        guard !loading.contains(s.id) else { return }
        loading.insert(s.id)
        defer { loading.remove(s.id) }
        do {
            var items = try await Self.fetchIndex(s.url)
            for i in items.indices { items[i].sourceID = s.id }
            let idx = GalleryIndex(items: items, fetchedAt: Date().timeIntervalSince1970, error: items.isEmpty ? String(localized: "没有找到模块链接") : nil)
            indexes[s.id] = idx
            Self.saveCache(s, idx)
        } catch {
            var old = indexes[s.id] ?? GalleryIndex(items: [], fetchedAt: 0, error: nil)
            old.error = error.localizedDescription
            indexes[s.id] = old
        }
    }

    // MARK: cache

    static func cacheURL(_ s: GallerySource) -> URL {
        let dir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("module-gallery", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent(s.id + ".json")
    }

    static func loadCache(_ s: GallerySource) -> GalleryIndex? {
        guard let d = try? Data(contentsOf: cacheURL(s)) else { return nil }
        return try? JSONDecoder().decode(GalleryIndex.self, from: d)
    }

    static func saveCache(_ s: GallerySource, _ i: GalleryIndex) {
        if let d = try? JSONEncoder().encode(i) { try? d.write(to: cacheURL(s), options: .atomic) }
    }

    // MARK: fetching / parsing (nonisolated, also used by tests of the parsers)

    enum GalleryError: LocalizedError {
        case http(Int), badReply, rateLimited
        var errorDescription: String? {
            switch self {
            case .http(let c): return String(localized: "服务器返回 HTTP \(c)")
            case .badReply: return String(localized: "无法识别的索引格式")
            case .rateLimited: return String(localized: "GitHub 接口请求过于频繁，请稍后再试")
            }
        }
    }

    nonisolated static func get(_ url: URL) async throws -> Data {
        var req = URLRequest(url: url, timeoutInterval: 30)
        // A proxy client's User-Agent: hub.kelee.one / kelee.one answer browser and unknown agents with a
        // Cloudflare challenge page (HTTP 403).
        req.setValue("Surge iOS/3000", forHTTPHeaderField: "User-Agent")
        if url.host == "api.github.com" { req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept") }
        let (data, resp) = try await URLSession.shared.data(for: req)
        if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) {
            if url.host == "api.github.com", h.statusCode == 403 || h.statusCode == 429 { throw GalleryError.rateLimited }
            throw GalleryError.http(h.statusCode)
        }
        return data
    }

    nonisolated static func fetchIndex(_ raw: String) async throws -> [GalleryItem] {
        guard let u = URL(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw GalleryError.badReply }
        if u.host == "github.com", let gh = GitHubPath(u) { return try await fetchGitHub(gh) }
        let data = try await get(u)
        if let items = parseJSON(data, base: u) { return items }
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else { throw GalleryError.badReply }
        return parseText(text, base: u)
    }

    struct GitHubPath {
        var owner: String, repo: String, branch: String?, path: String
        init?(_ u: URL) {
            let p = u.pathComponents.filter { $0 != "/" }
            guard p.count >= 2 else { return nil }
            owner = p[0]; repo = p[1].replacingOccurrences(of: ".git", with: "")
            if p.count >= 4, p[2] == "tree" || p[2] == "blob" {
                branch = p[3]; path = p.dropFirst(4).joined(separator: "/")
            } else { branch = nil; path = "" }
        }
    }

    nonisolated static let moduleExtensions: Set<String> = ["sgmodule", "plugin", "lpx", "stoverride", "snippet", "qxrewrite"]

    nonisolated static func fetchGitHub(_ g: GitHubPath) async throws -> [GalleryItem] {
        var branch = g.branch
        if branch == nil {
            let d = try await get(URL(string: "https://api.github.com/repos/\(g.owner)/\(g.repo)")!)
            branch = (try? JSONSerialization.jsonObject(with: d) as? [String: Any])?["default_branch"] as? String ?? "main"
        }
        let b = branch!
        let encB = b.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? b
        let d = try await get(URL(string: "https://api.github.com/repos/\(g.owner)/\(g.repo)/git/trees/\(encB)?recursive=1")!)
        guard let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let tree = obj["tree"] as? [[String: Any]] else { throw GalleryError.badReply }
        let prefix = g.path.isEmpty ? "" : g.path + "/"
        var out: [GalleryItem] = []
        for t in tree where (t["type"] as? String) == "blob" {
            guard let path = t["path"] as? String, path.hasPrefix(prefix) else { continue }
            let rel = String(path.dropFirst(prefix.count))
            let file = (rel as NSString).lastPathComponent
            let ext = (file as NSString).pathExtension.lowercased()
            let egernYAML = (ext == "yaml" || ext == "yml") && path.lowercased().contains("egern")
            guard moduleExtensions.contains(ext) || egernYAML else { continue }
            let dir = (rel as NSString).deletingLastPathComponent
            let rawPath = path.split(separator: "/").map { String($0).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? String($0) }.joined(separator: "/")
            out.append(GalleryItem(name: (file as NSString).deletingPathExtension,
                                   url: "https://raw.githubusercontent.com/\(g.owner)/\(g.repo)/\(encB)/\(rawPath)",
                                   category: dir, author: g.owner))
        }
        return out.sorted { ($0.category, $0.name.localizedLowercase) < ($1.category, $1.name.localizedLowercase) }
    }

    /// v0.19.22: a category as shown (chips, section headers). Hub indexes (可莉插件中心 list.json, Loon hubs) tag
    /// modules with Chinese category names; the common ones are translated, anything else is shown as the index
    /// wrote it. Display only — filtering keeps comparing the stored value.
    nonisolated static func categoryTitle(_ raw: String) -> String {
        switch raw.trimmingCharacters(in: .whitespaces) {
        case "去广告": return String(localized: "去广告")
        case "功能增强": return String(localized: "功能增强")
        case "配置管理": return String(localized: "配置管理")
        case "数据管理": return String(localized: "数据管理")
        case "签到": return String(localized: "签到")
        case "资源转换": return String(localized: "资源转换")
        case "订阅管理": return String(localized: "订阅管理")
        case "节点检测": return String(localized: "节点检测")
        case "定时任务": return String(localized: "定时任务")
        case "依赖": return String(localized: "依赖")
        case "工具": return String(localized: "工具")
        default: return raw
        }
    }

    nonisolated static func parseJSON(_ data: Data, base: URL) -> [GalleryItem]? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) else { return nil }
        var out: [GalleryItem] = []
        func str(_ d: [String: Any], _ keys: [String]) -> String {
            for k in keys { if let s = d[k] as? String, !s.isEmpty { return s } }
            return ""
        }
        /// A string, or the first string of an array (Loon hubs list tags as ["去广告", "依赖"]).
        func strOrFirst(_ d: [String: Any], _ keys: [String]) -> String {
            for k in keys {
                if let s = d[k] as? String, !s.isEmpty { return s }
                if let a = d[k] as? [String], let f = a.first(where: { !$0.isEmpty }) { return f }
            }
            return ""
        }
        /// "a", ["a", "b"] or [{ "name": "a" }, …] → "a, b".
        func names(_ d: [String: Any], _ keys: [String]) -> String {
            for k in keys {
                if let s = d[k] as? String, !s.isEmpty { return s }
                if let a = d[k] as? [Any] {
                    let n = a.compactMap { ($0 as? String) ?? (($0 as? [String: Any])?["name"] as? String) }.filter { !$0.isEmpty }
                    if !n.isEmpty { return n.joined(separator: ", ") }
                }
            }
            return ""
        }
        func item(_ d: [String: Any], category: String) {
            var url = str(d, ["url", "link", "install", "download", "module", "plugin", "href"])
            if case .moduleURL(let inner, _)? = ImportRouter.parse(url) { url = inner }
            guard let resolved = URL(string: url, relativeTo: base)?.absoluteURL, resolved.scheme?.hasPrefix("http") == true else { return }
            let name = str(d, ["name", "title"])
            let cat = strOrFirst(d, ["category", "group", "type", "tag", "tags"])
            var icon = str(d, ["icon", "img", "image", "logo"])
            if !icon.isEmpty, let iu = URL(string: icon, relativeTo: base)?.absoluteURL, iu.scheme?.hasPrefix("http") == true { icon = iu.absoluteString } else { icon = "" }
            // Some indexes keep a literal "\n" (backslash-n) for line breaks in descriptions.
            let desc = str(d, ["desc", "description", "summary", "intro"]).replacingOccurrences(of: "\\n", with: "\n")
            out.append(GalleryItem(name: name.isEmpty ? (resolved.deletingPathExtension().lastPathComponent) : name,
                                   url: resolved.absoluteString,
                                   desc: desc.trimmingCharacters(in: .whitespacesAndNewlines),
                                   category: cat.isEmpty ? category : cat,
                                   author: names(d, ["author", "by", "owner"]),
                                   icon: icon))
        }
        func walk(_ v: Any, category: String, depth: Int) {
            guard depth < 4 else { return }
            if let arr = v as? [Any] {
                for e in arr {
                    guard let d = e as? [String: Any] else { continue }
                    let nested = ["modules", "plugins", "items", "list", "children"].compactMap { d[$0] as? [Any] }.first
                    if let nested { walk(nested, category: str(d, ["name", "title", "category"]), depth: depth + 1) } else { item(d, category: category) }
                }
            } else if let d = v as? [String: Any] {
                if let arr = ["modules", "plugins", "items", "list", "lists", "data", "categories"].compactMap({ d[$0] as? [Any] }).first {
                    walk(arr, category: category, depth: depth + 1)
                } else {
                    for (k, sub) in d.sorted(by: { $0.key < $1.key }) where sub is [Any] { walk(sub, category: k, depth: depth + 1) }
                }
            }
        }
        walk(obj, category: "", depth: 0)
        return out.isEmpty && !(obj is [Any]) && !(obj is [String: Any]) ? nil : dedupe(out)
    }

    nonisolated static func parseText(_ text: String, base: URL) -> [GalleryItem] {
        var out: [GalleryItem] = []
        var category = ""
        let md = try! NSRegularExpression(pattern: #"\[([^\]]+)\]\(([^)\s]+)\)"#)
        let bare = try! NSRegularExpression(pattern: #"(?:https?|surge|loon|stash|egern|quantumult-x)://?/?[^\s"'<>)\]]+"#)
        func add(_ name: String, _ raw: String) {
            var u = raw.trimmingCharacters(in: CharacterSet(charactersIn: " ,;"))
            if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { u = inner }
            guard let url = URL(string: u, relativeTo: base)?.absoluteURL, url.scheme?.hasPrefix("http") == true else { return }
            let isLink = raw.lowercased().hasPrefix("http") == false
            guard isLink || moduleExtensions.contains(url.pathExtension.lowercased()) else { return }
            let n = name.trimmingCharacters(in: .whitespaces)
            out.append(GalleryItem(name: n.isEmpty ? url.deletingPathExtension().lastPathComponent : n, url: url.absoluteString, category: category))
        }
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("#") && !line.contains("://") { category = line.trimmingCharacters(in: CharacterSet(charactersIn: "# ")); continue }
            let ns = line as NSString
            let mds = md.matches(in: line, range: NSRange(location: 0, length: ns.length))
            if !mds.isEmpty {
                for m in mds { add(ns.substring(with: m.range(at: 1)), ns.substring(with: m.range(at: 2))) }
                continue
            }
            let urls = bare.matches(in: line, range: NSRange(location: 0, length: ns.length))
            for m in urls {
                let u = ns.substring(with: m.range)
                // "Name = url" / "Name, url" / "Name url" → the text before the link is the name.
                var name = m.range.location > 0 ? ns.substring(to: m.range.location) : ""
                name = name.trimmingCharacters(in: CharacterSet(charactersIn: " =,:-|*\t"))
                add(urls.count == 1 ? name : "", u)
            }
        }
        return dedupe(out)
    }

    nonisolated static func dedupe(_ items: [GalleryItem]) -> [GalleryItem] {
        var seen = Set<String>()
        return items.filter { seen.insert($0.url).inserted }
    }

    // MARK: preview

    struct Preview {
        var text: String
        var parsed: ParsedEngineText
    }

    nonisolated static func preview(_ url: String) async throws -> Preview {
        let text = try await EngineStore.download(url)
        let p = NCEngineParser.parseText(text, argsJSON: "{}")
        return Preview(text: text, parsed: p)
    }
}
