import Foundation
import Libmihomo

struct SubscriptionUserInfo: Codable, Hashable {
    var upload: Int64 = 0
    var download: Int64 = 0
    var total: Int64 = 0
    var expire: Int64 = 0

    var used: Int64 { upload + download }
    var fraction: Double { total > 0 ? min(Double(used) / Double(total), 1) : 0 }
    var expireDate: Date? { expire > 0 ? Date(timeIntervalSince1970: TimeInterval(expire)) : nil }

    /// Parses "upload=123; download=456; total=789; expire=1700000000".
    static func parse(_ header: String?) -> SubscriptionUserInfo? {
        guard let header, !header.isEmpty else { return nil }
        var info = SubscriptionUserInfo()
        var found = false
        for part in header.split(whereSeparator: { $0 == ";" || $0 == "," }) {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            guard kv.count == 2 else { continue }
            let v = Int64(Double(kv[1]) ?? 0)
            switch kv[0] {
            case "upload": info.upload = v; found = true
            case "download": info.download = v; found = true
            case "total": info.total = v; found = true
            case "expire": info.expire = v; found = true
            default: break
            }
        }
        return found ? info : nil
    }
}

struct Profile: Codable, Identifiable, Hashable {
    enum Kind: String, Codable { case remote, local }
    var id: String = UUID().uuidString
    var name: String
    var kind: Kind
    var url: String?
    var userAgent: String = "clash.meta"
    var updateIntervalHours: Int = 24
    var lastUpdated: Date?
    var userInfo: SubscriptionUserInfo?

    var fileURL: URL { AppShared.profileURL(id: id) }
}

@MainActor
final class ProfileStore: ObservableObject {
    static let shared = ProfileStore()

    @Published private(set) var profiles: [Profile] = []
    @Published var activeID: String? = AppShared.activeProfileID
    @Published var updating: Set<String> = []

    init() { load() }

    var active: Profile? { profiles.first { $0.id == activeID } }

    func load() {
        if let data = try? Data(contentsOf: AppShared.profilesIndexURL),
           let list = try? JSONDecoder().decode([Profile].self, from: data) {
            profiles = list
        }
        if activeID == nil || !profiles.contains(where: { $0.id == activeID }) {
            activeID = profiles.first?.id
            AppShared.activeProfileID = activeID
        }
        // v0.8.1: profiles converted by v0.8.0 and earlier get source URLs and readable provider names.
        let paths = profiles.filter { $0.kind == .local }.map { $0.fileURL.path }
        Task.detached(priority: .utility) {
            for path in paths { _ = LibmihomoMigrateProfileProviders(path) }
        }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(profiles) {
            try? data.write(to: AppShared.profilesIndexURL, options: .atomic)
        }
    }

    func setActive(_ p: Profile) async -> String? {
        activeID = p.id
        AppShared.activeProfileID = p.id
        return await VPNManager.shared.reload()
    }

    func delete(_ p: Profile) {
        try? FileManager.default.removeItem(at: p.fileURL)
        SubRulesStore.set(p.id, nil)
        profiles.removeAll { $0.id == p.id }
        if activeID == p.id {
            activeID = profiles.first?.id
            AppShared.activeProfileID = activeID
        }
        persist()
    }

    func rename(_ p: Profile, to name: String) {
        guard let i = profiles.firstIndex(where: { $0.id == p.id }) else { return }
        profiles[i].name = name
        persist()
    }

    func update(_ p: Profile) {
        guard let i = profiles.firstIndex(where: { $0.id == p.id }) else { return }
        profiles[i] = p
        persist()
    }

    func content(of p: Profile) -> String {
        (try? String(contentsOf: p.fileURL, encoding: .utf8)) ?? ""
    }

    // MARK: Validation / conversion

    /// Validates YAML text with the real mihomo parser. Returns nil if OK, else the error.
    nonisolated static func validate(text: String) async -> String? {
        await Task.detached(priority: .userInitiated) {
            let tmp = AppShared.homeURL.appendingPathComponent("validate-\(UUID().uuidString).yaml")
            defer { try? FileManager.default.removeItem(at: tmp) }
            do { try text.write(to: tmp, atomically: true, encoding: .utf8) } catch { return error.localizedDescription }
            let r = LibmihomoValidateConfigIn(AppShared.homeURL.path, tmp.path)
            return r.isEmpty ? nil : r
        }.value
    }

    /// If text is not a mihomo YAML (no proxies / proxy-providers), try converting share links / base64.
    nonisolated static func normalize(_ text: String) -> String {
        let looksYAML = text.contains("proxies:") || text.contains("proxy-providers:") || text.contains("proxy-groups:")
        if looksYAML { return text }
        let converted = LibmihomoConvertShareLinks(text)
        return converted.isEmpty ? text : converted
    }

    // MARK: Add / import

    func addLocal(name: String, text: String) async throws -> Profile {
        let yaml = Self.normalize(text)
        if let err = await Self.validate(text: yaml) { throw StoreError.invalid(err) }
        let p = Profile(name: name.isEmpty ? "本地配置" : name, kind: .local)
        try yaml.write(to: p.fileURL, atomically: true, encoding: .utf8)
        profiles.append(p)
        persist()
        if activeID == nil { _ = await setActive(p) }
        return p
    }

    func saveLocalEdit(_ p: Profile, text: String) async throws {
        if let err = await Self.validate(text: text) { throw StoreError.invalid(err) }
        try text.write(to: p.fileURL, atomically: true, encoding: .utf8)
        if p.id == activeID { _ = await VPNManager.shared.reload() }
    }

    func addRemote(url: String, name: String, userAgent: String, intervalHours: Int) async throws -> Profile {
        var p = Profile(name: name, kind: .remote, url: url.trimmingCharacters(in: .whitespacesAndNewlines),
                        userAgent: userAgent.isEmpty ? "clash.meta" : userAgent, updateIntervalHours: intervalHours)
        p = try await download(p)
        profiles.append(p)
        persist()
        if activeID == nil { _ = await setActive(p) }
        return p
    }

    enum StoreError: LocalizedError {
        case invalid(String), badURL, http(Int), empty
        var errorDescription: String? {
            switch self {
            case .invalid(let s): return String(localized: "配置校验失败：\(s)")
            case .badURL: return String(localized: "订阅链接无效")
            case .http(let c): return String(localized: "下载失败：HTTP \(c)")
            case .empty: return String(localized: "订阅内容为空")
            }
        }
    }

    /// Downloads a remote profile, parses subscription-userinfo, validates, and writes it.
    private func download(_ input: Profile) async throws -> Profile {
        var p = input
        guard let s = p.url, let url = URL(string: s), url.scheme?.hasPrefix("http") == true else { throw StoreError.badURL }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue(p.userAgent, forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await URLSession.shared.data(for: req)
        let http = resp as? HTTPURLResponse
        if let code = http?.statusCode, !(200..<300).contains(code) { throw StoreError.http(code) }
        guard var text = String(data: data, encoding: .utf8), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw StoreError.empty }
        text = Self.normalize(text)
        if let err = await Self.validate(text: text) { throw StoreError.invalid(err) }
        try text.write(to: p.fileURL, atomically: true, encoding: .utf8)
        p.userInfo = SubscriptionUserInfo.parse(http?.value(forHTTPHeaderField: "subscription-userinfo")) ?? p.userInfo
        if p.name.trimmingCharacters(in: .whitespaces).isEmpty {
            p.name = Self.nameFromHeaders(http) ?? url.host ?? "订阅"
        }
        p.lastUpdated = Date()
        return p
    }

    static func nameFromHeaders(_ http: HTTPURLResponse?) -> String? {
        if let t = http?.value(forHTTPHeaderField: "profile-title"), !t.isEmpty {
            if t.hasPrefix("base64:"), let d = Data(base64Encoded: String(t.dropFirst(7))), let s = String(data: d, encoding: .utf8) { return s }
            return t
        }
        if let cd = http?.value(forHTTPHeaderField: "Content-Disposition") {
            if let r = cd.range(of: "filename*=UTF-8''") {
                let raw = String(cd[r.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
                if let dec = raw.removingPercentEncoding, !dec.isEmpty { return dec.replacingOccurrences(of: ".yaml", with: "") }
            }
            if let r = cd.range(of: "filename=") {
                let raw = String(cd[r.upperBound...]).trimmingCharacters(in: CharacterSet(charactersIn: "\" ;"))
                if !raw.isEmpty { return raw.replacingOccurrences(of: ".yaml", with: "") }
            }
        }
        return nil
    }

    func refresh(_ p: Profile) async -> String? {
        guard p.kind == .remote else { return nil }
        updating.insert(p.id)
        defer { updating.remove(p.id) }
        do {
            let np = try await download(p)
            update(np)
            if np.id == activeID { _ = await VPNManager.shared.reload() }
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    func refreshAll() async -> [String] {
        var errors: [String] = []
        for p in profiles where p.kind == .remote {
            if let e = await refresh(p) { errors.append("\(p.name)：\(e)") }
        }
        return errors
    }

    /// Updates remote profiles whose interval has elapsed (called on foreground).
    func autoUpdateIfNeeded() async {
        for p in profiles where p.kind == .remote && p.updateIntervalHours > 0 {
            let due = (p.lastUpdated ?? .distantPast).addingTimeInterval(TimeInterval(p.updateIntervalHours * 3600))
            if due < Date() { _ = await refresh(p) }
        }
    }

    // MARK: Manual nodes (Shadowrocket style) — a local profile "手动节点"

    static let manualID = "manual-nodes"

    var manualProfile: Profile? { profiles.first { $0.id == Self.manualID } }

    @discardableResult
    func ensureManualProfile() -> Profile {
        if let p = manualProfile { return p }
        let p = Profile(id: Self.manualID, name: "手动节点", kind: .local)
        if !FileManager.default.fileExists(atPath: p.fileURL.path) {
            _ = LibmihomoManualDelete(p.fileURL.path, "") // writes an empty manual profile
        }
        profiles.insert(p, at: 0)
        persist()
        return p
    }

    func manualNodes() -> [[String: Any]] {
        guard let p = manualProfile else { return [] }
        let json = LibmihomoManualList(p.fileURL.path)
        return (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]]) ?? []
    }

    /// Parses links / lines and adds them. Returns the number of nodes added.
    func addManualNodes(text: String) async throws -> Int {
        let p = ensureManualProfile()
        let n = LibmihomoManualAddText(p.fileURL.path, text)
        if n < 0 { throw StoreError.invalid(LibmihomoLastError()) }
        objectWillChange.send()
        if activeID == nil { _ = await setActive(p) } else if activeID == p.id { _ = await VPNManager.shared.reload() }
        return Int(n)
    }

    func upsertManualNode(_ node: [String: Any], oldName: String?) async throws {
        let p = ensureManualProfile()
        let data = try JSONSerialization.data(withJSONObject: node)
        let err = LibmihomoManualUpsert(p.fileURL.path, String(decoding: data, as: UTF8.self), oldName ?? "")
        if !err.isEmpty { throw StoreError.invalid(err) }
        objectWillChange.send()
        if activeID == nil { _ = await setActive(p) } else if activeID == p.id { _ = await VPNManager.shared.reload() }
    }

    func deleteManualNode(_ name: String) async {
        guard let p = manualProfile else { return }
        _ = LibmihomoManualDelete(p.fileURL.path, name)
        objectWillChange.send()
        if activeID == p.id { _ = await VPNManager.shared.reload() }
    }
}

