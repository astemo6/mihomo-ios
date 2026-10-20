import SwiftUI
import CryptoKit

// Policy group icons (v0.7). Sources, in order: the user's choice (group-icons.json in our override store,
// never written into the profile), the profile's own `icon:` (mihomo proxy-groups; QX img-url / Surge
// icon-url are mapped to it on import), then an SF Symbol for the group type. Images are cached on disk in
// the App Group (icon-cache/), downscaled, and fetched through the jsDelivr mirror like the geo databases.

@MainActor
final class GroupIconStore: ObservableObject {
    static let shared = GroupIconStore()

    /// group name → icon. An image URL (http / https), "sf:<symbol>" (v0.19.8), an emoji / flag (v0.19.8, e.g. the
    /// 筛选节点 flag), or "" = the user chose the default symbol even if the profile has an icon.
    @Published private(set) var custom: [String: String] = [:]

    static var url: URL { AppShared.homeURL.appendingPathComponent("group-icons.json") }

    init() { reload() }

    func reload() {
        if let d = try? Data(contentsOf: Self.url), let m = try? JSONDecoder().decode([String: String].self, from: d) {
            custom = m
        } else {
            custom = [:]
        }
    }

    /// The image URL to show for a group, or nil for the SF Symbol / the user's glyph.
    func iconURL(group: String, profileIcon: String?) -> String? {
        if let c = custom[group] {
            if case .url(let u) = IconValue(c) { return u }
            return nil
        }
        if let p = profileIcon?.trimmingCharacters(in: .whitespaces), p.hasPrefix("http://") || p.hasPrefix("https://") { return p }
        return nil
    }

    /// nil = follow the profile; "" = always the default symbol; otherwise an image URL, "sf:…" or an emoji.
    func set(group: String, url: String?) {
        if let url { custom[group] = url } else { custom.removeValue(forKey: group) }
        write()
    }

    /// v0.19.8: a renamed group keeps its icon.
    func rename(_ old: String, to new: String) {
        guard old != new, let v = custom[old] else { return }
        custom.removeValue(forKey: old)
        custom[new] = v
        write()
    }

    private func write() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(custom) { try? d.write(to: Self.url, options: .atomic) }
    }

    /// v0.19.8: the user's non-image choice for a group (an emoji / flag or an SF Symbol), nil otherwise.
    func glyph(group: String) -> IconValue? {
        guard let c = custom[group], !c.isEmpty else { return nil }
        let v = IconValue(c)
        if case .url = v { return nil }
        return v
    }
}

/// v0.19.8: one stored icon value, the same strings group-icons.json and 筛选节点 flags keep.
enum IconValue: Equatable {
    case url(String)
    case symbol(String)
    case emoji(String)

    init(_ s: String) {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("http://") || t.hasPrefix("https://") { self = .url(t) }
        else if t.hasPrefix("sf:") { self = .symbol(String(t.dropFirst(3))) }
        else { self = .emoji(t) }
    }
}

/// An icon value drawn at a size: image, SF Symbol, or emoji / flag (FlagGlyph keeps 🇹🇼 readable on CN devices).
struct IconGlyph: View {
    let value: String
    var size: CGFloat = 24
    var body: some View {
        switch IconValue(value) {
        case .url(let u): RemoteIcon(url: u, size: size)
        case .symbol(let n): Image(systemName: n).font(.system(size: size * 0.7, weight: .semibold)).foregroundStyle(Theme.accent).frame(width: size, height: size)
        case .emoji(let e):
            if e.isEmpty { Image(systemName: "square.dashed").foregroundStyle(.tertiary).frame(width: size, height: size) }
            else { FlagGlyph(flag: e).frame(minWidth: size, minHeight: size) }
        }
    }
}

/// Memory + disk cache for small remote images (group icons, icon-set previews).
final class IconCache {
    static let shared = IconCache()
    private let memory = NSCache<NSString, UIImage>()
    private var inflight: [String: Task<UIImage?, Never>] = [:]
    private let lock = NSLock()

    static var dir: URL {
        let d = AppShared.containerURL.appendingPathComponent("icon-cache", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    init() { memory.countLimit = 300 }

    static func key(_ url: String) -> String {
        SHA256.hash(data: Data(url.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    /// raw.githubusercontent.com → testingcf.jsdelivr.net (unless the user picked GitHub for downloads).
    static func mirrored(_ s: String) -> String {
        guard CoreOverrides.load().geoMirror != "github", let u = URL(string: s), u.host == "raw.githubusercontent.com" else { return s }
        let parts = u.path.split(separator: "/").map(String.init)
        guard parts.count >= 4 else { return s }
        let rest = parts[3...].joined(separator: "/")
        return "https://testingcf.jsdelivr.net/gh/\(parts[0])/\(parts[1])@\(parts[2])/\(rest)"
    }

    func cached(_ url: String) -> UIImage? {
        if let m = memory.object(forKey: url as NSString) { return m }
        let f = Self.dir.appendingPathComponent(Self.key(url) + ".png")
        if let d = try? Data(contentsOf: f), let img = UIImage(data: d) {
            memory.setObject(img, forKey: url as NSString)
            return img
        }
        return nil
    }

    func image(for url: String) async -> UIImage? {
        if let c = cached(url) { return c }
        lock.lock()
        if let t = inflight[url] { lock.unlock(); return await t.value }
        let t = Task<UIImage?, Never> { await Self.download(url) }
        inflight[url] = t
        lock.unlock()
        let img = await t.value
        lock.lock(); inflight[url] = nil; lock.unlock()
        if let img {
            memory.setObject(img, forKey: url as NSString)
            if let png = img.pngData() {
                try? png.write(to: Self.dir.appendingPathComponent(Self.key(url) + ".png"), options: .atomic)
            }
        }
        return img
    }

    private static func download(_ url: String) async -> UIImage? {
        guard let u = URL(string: mirrored(url)) else { return nil }
        var req = URLRequest(url: u, timeoutInterval: 15)
        req.cachePolicy = .reloadIgnoringLocalCacheData
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode ?? 200 < 400, data.count < 2_000_000,
              let img = UIImage(data: data) else { return nil }
        return downscale(img, to: 120)
    }

    private static func downscale(_ img: UIImage, to side: CGFloat) -> UIImage {
        let s = img.size
        guard s.width > side || s.height > side, s.width > 0, s.height > 0 else { return img }
        let scale = side / max(s.width, s.height)
        let size = CGSize(width: s.width * scale, height: s.height * scale)
        let fmt = UIGraphicsImageRendererFormat()
        fmt.scale = 1
        return UIGraphicsImageRenderer(size: size, format: fmt).image { _ in img.draw(in: CGRect(origin: .zero, size: size)) }
    }

    /// Bytes on disk (shown in the picker with a clear button).
    static func diskUsage() -> Int64 {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey])) ?? []
        return files.reduce(Int64(0)) { $0 + Int64((try? $1.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) }
    }

    func clear() {
        memory.removeAllObjects()
        try? FileManager.default.removeItem(at: Self.dir)
    }
}

/// A remote image from the cache, or nothing while it loads / when it fails.
struct RemoteIcon: View {
    let url: String
    var size: CGFloat = 34
    @State private var image: UIImage?
    @State private var failed = false

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFit()
            } else if failed {
                Image(systemName: "photo").foregroundStyle(.tertiary)
            } else {
                ProgressView().controlSize(.mini)
            }
        }
        .frame(width: size, height: size)
        .task(id: url) {
            image = IconCache.shared.cached(url)
            if image == nil {
                image = await IconCache.shared.image(for: url)
                failed = image == nil
            }
        }
    }
}

/// The group's icon in the card style: image when there is one, else the type symbol.
struct GroupIconView: View {
    let group: String
    let profileIcon: String?
    let fallback: String
    var size: CGFloat = 34
    @ObservedObject private var store = GroupIconStore.shared
    @State private var image: UIImage?

    var body: some View {
        let url = store.iconURL(group: group, profileIcon: profileIcon)
        let glyph = store.glyph(group: group)
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.29).fill(Theme.accent.opacity(image == nil ? 0.15 : 0.06))
            if let image {
                Image(uiImage: image).resizable().scaledToFit().padding(size * 0.1)
            } else if case .emoji(let e) = glyph {
                // v0.19.8: an emoji / flag icon (筛选节点 flag, 自定义 emoji)
                if let l = FlagSafe.letters(e), !FlagSafe.renders(e) {
                    Text(verbatim: l).font(.system(size: size * 0.36, weight: .heavy).monospaced()).foregroundStyle(Theme.accent)
                } else {
                    Text(verbatim: e).font(.system(size: size * 0.55))
                }
            } else if case .symbol(let n) = glyph {
                Image(systemName: n).font(size > 30 ? .headline : .caption.weight(.semibold)).foregroundStyle(Theme.accent)
            } else {
                Image(systemName: fallback).font(size > 30 ? .headline : .caption.weight(.semibold)).foregroundStyle(Theme.accent)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
        .task(id: url ?? "") {
            guard let url else { image = nil; return }
            image = IconCache.shared.cached(url)
            if image == nil { image = await IconCache.shared.image(for: url) }
        }
    }
}

// MARK: - Picker

struct IconSetSource: Identifiable, Hashable {
    var id: String { index }
    let name: String
    let author: String
    let index: String

    /// Popular QX-style icon galleries (JSON: {name, icons: [{name, url}]}), loaded through the mirror.
    static let popular: [IconSetSource] = [
        IconSetSource(name: "Qure Color", author: "Koolson/Qure", index: "https://raw.githubusercontent.com/Koolson/Qure/master/Other/QureColor.json"),
        IconSetSource(name: "mini", author: "Orz-3/mini", index: "https://raw.githubusercontent.com/Orz-3/mini/master/mini.json"),
        IconSetSource(name: "Hand Painted", author: "Semporia/Hand-Painted-icon", index: "https://raw.githubusercontent.com/Semporia/Hand-Painted-icon/master/Semporia.json"),
    ]
}

struct IconGallery: Decodable {
    struct Icon: Decodable, Hashable { var name: String; var url: String }
    var name: String?
    var icons: [Icon]
}

/// 策略 → 更换图标 for one group: the shared picker writing group-icons.json right away.
struct GroupIconPicker: View {
    let group: String
    let profileIcon: String?
    @ObservedObject private var store = GroupIconStore.shared

    var body: some View {
        IconPickerSheet(title: group, current: store.custom[group], profileIcon: profileIcon) { v in
            store.set(group: group, url: v)
        }
    }
}

/// v0.19.8: one icon picker for groups and 筛选节点 (device report: the flag was an 80 pt text field where 🇹🇼
/// showed ☒). Region flags (drawn by FlagGlyph, so TW stays readable), common emoji, SF Symbols, a custom emoji,
/// an image address and the icon libraries. Values are stored as before: an emoji, "sf:<symbol>" or a URL;
/// onPick(nil) = follow the profile / default, onPick("") = the default symbol.
struct IconPickerSheet: View {
    let title: String
    let current: String?
    var profileIcon: String? = nil
    /// false for 筛选节点 (a filter always has an icon): no 恢复默认 / 默认符号 rows.
    var allowsReset = true
    let onPick: (String?) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var emojiText = ""
    @State private var urlText = ""
    @State private var urlError: String?
    @State private var checking = false
    @State private var cacheBytes: Int64 = 0

    static let flags: [String] = NodeFilterView.regions.map(\.flag) + ["🇲🇴", "🇨🇳", "🇮🇳", "🇹🇭", "🇻🇳", "🇲🇾", "🇵🇭", "🇮🇩", "🇹🇷", "🇳🇱", "🇮🇹", "🇪🇸", "🇧🇷", "🇦🇷", "🇦🇪", "🇺🇦", "🇸🇪", "🇨🇭", "🇮🇪", "🇳🇿", "🇿🇦", "🇮🇱"]
    static let emoji: [String] = ["🚀", "🎯", "🌍", "🌐", "⚡️", "🎬", "📺", "🎵", "🎮", "💬", "🤖", "🍎", "🛑", "🐟", "🔒", "🏠", "📱", "☁️", "🧭", "⭐️"]
    static let symbols: [String] = ["globe", "globe.asia.australia", "hand.tap.fill", "bolt.badge.clock.fill", "arrow.triangle.branch", "scalemass.fill",
                                    "airplane", "play.tv.fill", "music.note", "gamecontroller.fill", "message.fill", "sparkles", "apple.logo",
                                    "shield.lefthalf.filled", "nosign", "house.fill", "cloud.fill", "server.rack", "network", "star.fill"]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 14) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 14).fill(Theme.accent.opacity(0.15))
                            if let c = current, !c.isEmpty { IconGlyph(value: c, size: 32) }
                            else { Image(systemName: "square.grid.2x2").font(.headline).foregroundStyle(Theme.accent) }
                        }
                        .frame(width: 48, height: 48)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: title).font(.headline).lineLimit(1)
                            Text(sourceText).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .listRowBackground(Theme.card)

                grid("地区旗帜", Self.flags)
                grid("常用", Self.emoji)
                grid("符号", Self.symbols.map { "sf:" + $0 })

                Section {
                    HStack {
                        TextField("输入一个 emoji", text: $emojiText)
                            .accessibilityIdentifier("icon.emoji")
                        Button("使用") { pick(emojiText.trimmingCharacters(in: .whitespaces)) }
                            .disabled(emojiText.trimmingCharacters(in: .whitespaces).isEmpty)
                            .accessibilityIdentifier("icon.emoji.use")
                    }
                } header: { Text("自定义 emoji") }
                .listRowBackground(Theme.card)

                Section {
                    TextField("https://…/icon.png", text: $urlText)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.body.monospaced())
                    if let urlError { Text(urlError).font(.caption).foregroundStyle(Theme.warn) }
                    Button { useURL() } label: { if checking { ProgressView() } else { Text("使用此地址") } }
                        .disabled(urlText.trimmingCharacters(in: .whitespaces).isEmpty || checking)
                } header: { Text("图片地址") }
                .listRowBackground(Theme.card)

                Section {
                    ForEach(IconSetSource.popular) { set in
                        NavigationLink {
                            IconSetGrid(source: set) { url in pick(url) }
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(set.name)
                                Text(set.author).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: { Text("图标库") } footer: {
                    Text("图标来自 GitHub 上的开源图标库，经 jsDelivr 镜像加载并缓存在本机。")
                }
                .listRowBackground(Theme.card)

                Section {
                    if allowsReset {
                        if current != nil {
                            Button(LocalizedStringKey(profileIcon?.isEmpty == false ? "使用配置文件的图标" : "恢复默认")) { pick(nil) }
                        }
                        if current != "" && (current != nil || profileIcon?.isEmpty == false) {
                            Button("使用默认符号") { pick("") }
                        }
                    }
                    Button("清除图标缓存（\(Fmt.bytes(cacheBytes))）", role: .destructive) {
                        IconCache.shared.clear()
                        cacheBytes = 0
                    }
                } footer: { Text("选择只保存在本机的设置里，不会改动配置文件。") }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("选择图标")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } } }
            .onAppear {
                if let c = current {
                    switch IconValue(c) {
                    case .url(let u): urlText = u
                    case .emoji(let e): emojiText = e
                    case .symbol: break
                    }
                }
                cacheBytes = IconCache.diskUsage()
            }
        }
    }

    func grid(_ header: LocalizedStringKey, _ values: [String]) -> some View {
        Section {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 44), spacing: 8)], spacing: 8) {
                ForEach(values, id: \.self) { v in
                    Button { pick(v) } label: {
                        IconGlyph(value: v, size: 28)
                            .frame(width: 44, height: 44)
                            .background(RoundedRectangle(cornerRadius: 10).fill(v == current ? Theme.accent.opacity(0.22) : Theme.ink(0.04)))
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(v == current ? Theme.accent : .clear, lineWidth: 1.5))
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text(verbatim: FlagSafe.letters(v) ?? v))
                    .accessibilityIdentifier("icon.pick." + (FlagSafe.letters(v) ?? v))
                }
            }
            .padding(.vertical, 4)
        } header: { Text(header) }
        .listRowBackground(Theme.card)
    }

    var sourceText: String {
        if let c = current { return c.isEmpty ? String(localized: "默认符号（你的选择）") : String(localized: "你选择的图标") }
        if profileIcon?.isEmpty == false { return String(localized: "来自配置文件") }
        return String(localized: "默认符号")
    }

    func pick(_ v: String?) {
        onPick(v)
        dismiss()
    }

    func useURL() {
        let t = urlText.trimmingCharacters(in: .whitespaces)
        guard let u = URL(string: t), let sc = u.scheme?.lowercased(), sc == "http" || sc == "https", u.host != nil else {
            urlError = String(localized: "请输入以 http:// 或 https:// 开头的图片地址")
            return
        }
        urlError = nil
        checking = true
        Task {
            defer { checking = false }
            if await IconCache.shared.image(for: t) == nil {
                urlError = String(localized: "无法加载这张图片")
                return
            }
            pick(t)
        }
    }
}

struct IconSetGrid: View {
    let source: IconSetSource
    let onPick: (String) -> Void
    @State private var icons: [IconGallery.Icon] = []
    @State private var error: String?
    @State private var loading = true
    @State private var search = ""

    var shown: [IconGallery.Icon] {
        guard !search.isEmpty else { return icons }
        return icons.filter { $0.name.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        ScrollView {
            if loading && icons.isEmpty { LoadingRow(text: "正在加载图标库…").padding() }
            if let error { ErrorRow(message: error).padding() }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 64), spacing: 10)], spacing: 12) {
                ForEach(shown, id: \.self) { icon in
                    Button { onPick(icon.url) } label: {
                        VStack(spacing: 4) {
                            RemoteIcon(url: icon.url, size: 44)
                                .padding(8)
                                .background(RoundedRectangle(cornerRadius: 12).fill(Theme.card))
                            Text(icon.name.replacingOccurrences(of: ".png", with: ""))
                                .scaledFont(9).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(source.name)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索图标")
        .task { await load() }
    }

    func load() async {
        let cacheFile = IconCache.dir.appendingPathComponent("index-" + IconCache.key(source.index) + ".json")
        if let d = try? Data(contentsOf: cacheFile), let g = try? JSONDecoder().decode(IconGallery.self, from: d) {
            icons = g.icons
            loading = false
        }
        guard let u = URL(string: IconCache.mirrored(source.index)) else { return }
        do {
            let (data, _) = try await URLSession.shared.data(for: URLRequest(url: u, timeoutInterval: 20))
            let g = try JSONDecoder().decode(IconGallery.self, from: data)
            icons = g.icons
            try? data.write(to: cacheFile, options: .atomic)
            error = nil
        } catch {
            if icons.isEmpty { self.error = String(localized: "图标库加载失败：\(error.localizedDescription)") }
        }
        loading = false
    }
}
