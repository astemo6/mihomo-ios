import SwiftUI
import CryptoKit

// Policy group icons (v0.7). Sources, in order: the user's choice (group-icons.json in our override store,
// never written into the profile), the profile's own `icon:` (mihomo proxy-groups; QX img-url / Surge
// icon-url are mapped to it on import), then an SF Symbol for the group type. Images are cached on disk in
// the App Group (icon-cache/), downscaled, and fetched through the jsDelivr mirror like the geo databases.

@MainActor
final class GroupIconStore: ObservableObject {
    static let shared = GroupIconStore()

    /// group name → image URL. "" = the user chose the default symbol even if the profile has an icon.
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

    /// The image URL to show for a group, or nil for the SF Symbol.
    func iconURL(group: String, profileIcon: String?) -> String? {
        if let c = custom[group] { return c.isEmpty ? nil : c }
        if let p = profileIcon?.trimmingCharacters(in: .whitespaces), p.hasPrefix("http://") || p.hasPrefix("https://") { return p }
        return nil
    }

    /// nil = follow the profile; "" = always the default symbol; otherwise an image URL.
    func set(group: String, url: String?) {
        if let url { custom[group] = url } else { custom.removeValue(forKey: group) }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(custom) { try? d.write(to: Self.url, options: .atomic) }
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
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.29).fill(Theme.accent.opacity(image == nil ? 0.15 : 0.06))
            if let image {
                Image(uiImage: image).resizable().scaledToFit().padding(size * 0.1)
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

struct GroupIconPicker: View {
    let group: String
    let profileIcon: String?
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = GroupIconStore.shared
    @State private var urlText = ""
    @State private var urlError: String?
    @State private var cacheBytes: Int64 = 0

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 14) {
                        GroupIconView(group: group, profileIcon: profileIcon, fallback: "square.grid.2x2", size: 48)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group).font(.headline).lineLimit(1)
                            Text(sourceText).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .listRowBackground(Theme.card)

                Section {
                    TextField("https://…/icon.png", text: $urlText)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.body.monospaced())
                    if let urlError { Text(urlError).font(.caption).foregroundStyle(Theme.warn) }
                    Button("使用此地址") { useURL() }
                        .disabled(urlText.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: { Text("图片地址") }
                .listRowBackground(Theme.card)

                Section {
                    ForEach(IconSetSource.popular) { set in
                        NavigationLink {
                            IconSetGrid(source: set) { url in
                                store.set(group: group, url: url)
                                dismiss()
                            }
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
                    if store.custom[group] != nil {
                        Button(LocalizedStringKey(profileIcon?.isEmpty == false ? "使用配置文件的图标" : "恢复默认")) {
                            store.set(group: group, url: nil); dismiss()
                        }
                    }
                    if store.custom[group] != "" && (store.custom[group] != nil || profileIcon?.isEmpty == false) {
                        Button("使用默认符号") { store.set(group: group, url: ""); dismiss() }
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
            .navigationTitle("策略组图标")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } } }
            .onAppear {
                urlText = store.custom[group] ?? ""
                cacheBytes = IconCache.diskUsage()
            }
        }
    }

    var sourceText: String {
        if let c = store.custom[group] { return c.isEmpty ? String(localized: "默认符号（你的选择）") : String(localized: "你选择的图标") }
        if profileIcon?.isEmpty == false { return String(localized: "来自配置文件") }
        return String(localized: "默认符号")
    }

    func useURL() {
        let t = urlText.trimmingCharacters(in: .whitespaces)
        guard let u = URL(string: t), let sc = u.scheme?.lowercased(), sc == "http" || sc == "https", u.host != nil else {
            urlError = String(localized: "请输入以 http:// 或 https:// 开头的图片地址")
            return
        }
        urlError = nil
        Task {
            if await IconCache.shared.image(for: t) == nil {
                urlError = String(localized: "无法加载这张图片")
                return
            }
            store.set(group: group, url: t)
            dismiss()
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
        .searchable(text: $search, prompt: "搜索图标")
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
