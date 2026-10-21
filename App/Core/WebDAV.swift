import Foundation
import CryptoKit
import CommonCrypto
import Security

// v0.19 WebDAV 备份: the existing backup file (BackupManager.make, BackupFile JSON) uploaded to a WebDAV
// folder (坚果云, Nextcloud, Synology, …) as mihomo-backup-<yyyyMMdd-HHmmss>.json, the newest N kept,
// any version listed / restored. Optional password encryption wraps the same JSON in an envelope:
// {"app":"mihomo-ios","encrypted":"aes-256-gcm","kdf":"pbkdf2-sha256","iterations":…,"salt":…,"data":…}
// (AES-256-GCM, key = PBKDF2-HMAC-SHA256(password, 16-byte salt, 210 000 rounds), data = nonce‖ciphertext‖tag).
// The server password and the encryption password are kept in the Keychain; URL / user / options in defaults.

enum BackupCrypto {
    static let iterations: UInt32 = 210_000
    /// Accepted rounds from a file: below is too weak to be ours, above would hang the app (no cancel).
    static let iterationRange: ClosedRange<UInt32> = 100_000...5_000_000

    struct Envelope: Codable {
        var app = "mihomo-ios"
        var encrypted = "aes-256-gcm"
        var kdf = "pbkdf2-sha256"
        var iterations: UInt32
        var salt: String
        var data: String
        var created: Date?
    }

    enum CryptoError: LocalizedError {
        case wrongPassword, badFile, kdf
        var errorDescription: String? {
            switch self {
            case .wrongPassword: return String(localized: "密码不对，或备份已损坏")
            case .badFile: return String(localized: "不是 Tern 加密备份")
            case .kdf: return String(localized: "无法生成密钥")
            }
        }
    }

    static func isEncrypted(_ data: Data) -> Bool {
        guard data.count < 64 << 20, let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return o["encrypted"] is String && o["data"] is String
    }

    static func key(_ password: String, salt: Data, rounds: UInt32) throws -> SymmetricKey {
        var out = [UInt8](repeating: 0, count: 32)
        let pw = Array(password.utf8)
        let status = salt.withUnsafeBytes { s -> Int32 in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, pw.count,
                                 s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, &out, out.count)
        }
        guard status == Int32(kCCSuccess) else { throw CryptoError.kdf }
        return SymmetricKey(data: out)
    }

    static func encrypt(_ plain: Data, password: String) throws -> Data {
        var salt = Data(count: 16)
        let ok = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard ok == errSecSuccess else { throw CryptoError.kdf }
        let k = try key(password, salt: salt, rounds: iterations)
        guard let combined = try AES.GCM.seal(plain, using: k).combined else { throw CryptoError.kdf }
        let env = Envelope(iterations: iterations, salt: salt.base64EncodedString(), data: combined.base64EncodedString(), created: Date())
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        enc.outputFormatting = [.sortedKeys]
        return try enc.encode(env)
    }

    static func decrypt(_ data: Data, password: String) throws -> Data {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        guard let env = try? dec.decode(Envelope.self, from: data), env.app == "mihomo-ios", env.encrypted == "aes-256-gcm",
              let salt = Data(base64Encoded: env.salt), let blob = Data(base64Encoded: env.data),
              iterationRange.contains(env.iterations) else { throw CryptoError.badFile }
        let k = try key(password, salt: salt, rounds: env.iterations)
        do {
            return try AES.GCM.open(try AES.GCM.SealedBox(combined: blob), using: k)
        } catch {
            throw CryptoError.wrongPassword
        }
    }
}

struct WebDAVSettings: Equatable {
    var url: String = ""
    var username: String = ""
    var keep: Int = 10
    var encrypt = false
    var includeCA = false
    /// The user confirmed an http:// server (credentials and unencrypted backups travel in clear text).
    var allowInsecure = false

    static let passwordAccount = "webdav-password"
    static let encryptionAccount = "webdav-encryption-password"
    private static let key = "webdav.settings"

    static func load() -> WebDAVSettings {
        var s = WebDAVSettings()
        guard let d = UserDefaults.standard.dictionary(forKey: key) else { return s }
        s.url = d["url"] as? String ?? ""
        s.username = d["username"] as? String ?? ""
        s.keep = min(max(d["keep"] as? Int ?? 10, 1), 100)
        s.encrypt = d["encrypt"] as? Bool ?? false
        s.includeCA = d["includeCA"] as? Bool ?? false
        s.allowInsecure = d["allowInsecure"] as? Bool ?? false
        if s.includeCA { s.encrypt = true }
        return s
    }

    func save() {
        UserDefaults.standard.set(["url": url, "username": username, "keep": keep, "encrypt": encrypt, "includeCA": includeCA, "allowInsecure": allowInsecure], forKey: Self.key)
    }

    /// http:// (not https://): Basic auth and the backup would be readable on the network.
    var isInsecure: Bool { folderURL?.scheme?.lowercased() == "http" }

    var configured: Bool { folderURL != nil }

    /// The folder URL with a trailing slash.
    var folderURL: URL? {
        var s = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if !s.hasSuffix("/") { s += "/" }
        guard let u = Self.parseURL(s), u.scheme?.lowercased().hasPrefix("http") == true, u.host != nil else { return nil }
        return u
    }

    /// v0.19.1: folder names with spaces or non-ASCII characters (「我的坚果云/备份」) as typed. URL(string:)
    /// rejects them before iOS 17, which left the page saying 「请先填写 WebDAV 地址」. Already-encoded URLs
    /// (%E6…) are kept as they are.
    static func parseURL(_ s: String) -> URL? {
        if let u = URL(string: s) { return u }
        guard let schemeEnd = s.range(of: "://") else { return nil }
        let afterScheme = s[schemeEnd.upperBound...]
        let slash = afterScheme.firstIndex(of: "/") ?? afterScheme.endIndex
        let head = String(s[..<slash]), path = String(s[slash...])
        var allowed = CharacterSet.urlPathAllowed
        allowed.insert("%")
        guard let enc = path.addingPercentEncoding(withAllowedCharacters: allowed) else { return nil }
        return URL(string: head + enc)
    }
}

struct WebDAVFile: Identifiable, Hashable {
    var name: String
    var size: Int64?
    var modified: Date?
    var id: String { name }
    var encrypted: Bool { name.hasSuffix(".enc.json") }
    /// mihomo-backup-20261018-153000Z(.enc).json (UTC, review 5 P2-4) or the older local-time
    /// mihomo-backup-20261018-153000(.enc).json → that time.
    var stamp: Date? {
        let base = name.replacingOccurrences(of: WebDAVClient.prefix, with: "").replacingOccurrences(of: ".enc.json", with: "").replacingOccurrences(of: ".json", with: "")
        if base.hasSuffix("Z") { return WebDAVClient.stampFormatterUTC.date(from: String(base.dropLast())) }
        return WebDAVClient.stampFormatter.date(from: base)
    }
}

/// What a WebDAV server does, so the UI tests can use an in-memory server (-UITestDemoWebDAV).
protocol WebDAVTransport {
    func ensureFolder() async throws
    func list() async throws -> [WebDAVFile]
    func put(_ name: String, _ data: Data) async throws
    func get(_ name: String) async throws -> Data
    func delete(_ name: String) async throws
}

enum WebDAVError: LocalizedError {
    case notConfigured, http(Int, String), badResponse, auth, insecure, caNeedsEncryption
    var errorDescription: String? {
        switch self {
        case .insecure: return String(localized: "这是 http:// 地址，密码和备份会以明文传输。请改用 https://，或确认「允许不安全的 http 连接」。")
        case .caNeedsEncryption: return String(localized: "包含 MitM 根证书私钥的备份必须加密")
        case .notConfigured: return String(localized: "请先填写 WebDAV 地址")
        case .auth: return String(localized: "用户名或密码不对（HTTP 401）")
        case .http(let c, let m): return String(localized: "WebDAV 请求失败：HTTP \(c)") + (m.isEmpty ? "" : " · \(m)")
        case .badResponse: return String(localized: "WebDAV 服务器的回应无法解析")
        }
    }
}

final class WebDAVHTTP: WebDAVTransport {
    let folder: URL
    let auth: String?
    let session: URLSession

    init(folder: URL, username: String, password: String) {
        self.folder = folder
        if !username.isEmpty || !password.isEmpty {
            auth = "Basic " + Data("\(username):\(password)".utf8).base64EncodedString()
        } else {
            auth = nil
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: cfg, delegate: WebDAVRedirectGuard(), delegateQueue: nil)
    }

    deinit { session.finishTasksAndInvalidate() }

    func request(_ url: URL, _ method: String, body: Data? = nil, headers: [String: String] = [:]) async throws -> (Data, Int) {
        var r = URLRequest(url: url)
        r.httpMethod = method
        r.httpBody = body
        if let auth { r.setValue(auth, forHTTPHeaderField: "Authorization") }
        for (k, v) in headers { r.setValue(v, forHTTPHeaderField: k) }
        let (d, resp) = try await session.data(for: r)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code == 401 { throw WebDAVError.auth }
        return (d, code)
    }

    func check(_ code: Int, _ data: Data, ok: Set<Int>) throws {
        guard ok.contains(code) else {
            let msg = String(data: data.prefix(200), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw WebDAVError.http(code, msg.contains("<") ? "" : msg)
        }
    }

    func ensureFolder() async throws {
        let (d, code) = try await request(folder, "PROPFIND", headers: ["Depth": "0", "Content-Type": "application/xml"])
        if code == 207 || code == 200 { return }
        if code == 404 {
            try await makeCollection(folder, depth: 0)
            return
        }
        try check(code, d, ok: [207, 200])
    }

    /// MKCOL; a 409 means a parent folder is missing too (RFC 4918 §9.3.1; 坚果云 / Nextcloud with a nested
    /// path such as …/dav/Mihomo/backup/), so the parents are created first, at most 8 levels up.
    func makeCollection(_ url: URL, depth: Int) async throws {
        let (d, c) = try await request(url, "MKCOL")
        if c == 409, depth < 8 {
            let parent = url.deletingLastPathComponent()
            if parent.path.count > 1, parent != url {
                try await makeCollection(parent, depth: depth + 1)
                let (d2, c2) = try await request(url, "MKCOL")
                try check(c2, d2, ok: [201, 405])
                return
            }
        }
        try check(c, d, ok: [201, 405])
    }

    static let propfindBody = Data("""
    <?xml version="1.0" encoding="utf-8"?>
    <d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getcontentlength/><d:resourcetype/></d:prop></d:propfind>
    """.utf8)

    func list() async throws -> [WebDAVFile] {
        let (d, code) = try await request(folder, "PROPFIND", body: Self.propfindBody, headers: ["Depth": "1", "Content-Type": "application/xml; charset=utf-8"])
        if code == 404 { return [] }
        try check(code, d, ok: [207, 200])
        guard let entries = PropfindParser.parse(d) else { throw WebDAVError.badResponse }
        return entries.compactMap { e -> WebDAVFile? in
            let name = (e.href.removingPercentEncoding ?? e.href).split(separator: "/").last.map(String.init) ?? ""
            guard !e.isCollection, name.hasPrefix(WebDAVClient.prefix), name.hasSuffix(".json") else { return nil }
            return WebDAVFile(name: name, size: e.length, modified: e.modified)
        }
    }

    func fileURL(_ name: String) -> URL {
        folder.appendingPathComponent(name)
    }

    func put(_ name: String, _ data: Data) async throws {
        let (d, code) = try await request(fileURL(name), "PUT", body: data, headers: ["Content-Type": "application/json"])
        try check(code, d, ok: [200, 201, 204])
    }

    func get(_ name: String) async throws -> Data {
        let (d, code) = try await request(fileURL(name), "GET")
        try check(code, d, ok: [200])
        return d
    }

    func delete(_ name: String) async throws {
        let (d, code) = try await request(fileURL(name), "DELETE")
        try check(code, d, ok: [200, 204, 404])
    }
}

/// Review 5 P2-3: the Basic-auth header is set by hand and NSAllowsArbitraryLoads is on, so a 30x to another host
/// or from https to http must not be followed (the password, or an unencrypted backup in a PUT, would go where
/// the user never approved). Same-host, same-or-stronger-scheme redirects (e.g. a missing trailing slash) still work.
final class WebDAVRedirectGuard: NSObject, URLSessionTaskDelegate {
    static func allows(from old: URL?, to new: URL?) -> Bool {
        guard let old, let new, let oh = old.host?.lowercased(), let nh = new.host?.lowercased() else { return false }
        let oldScheme = old.scheme?.lowercased() ?? "", ns = new.scheme?.lowercased() ?? ""
        guard oh == nh else { return false }
        if oldScheme == "https" && ns != "https" { return false }
        return ns == "https" || ns == "http"
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        let from = task.currentRequest?.url ?? task.originalRequest?.url
        completionHandler(Self.allows(from: from, to: request.url) ? request : nil)
    }
}

/// Minimal multistatus parser: href, getlastmodified, getcontentlength, collection flag per response.
final class PropfindParser: NSObject, XMLParserDelegate {
    struct Entry { var href = ""; var modified: Date?; var length: Int64?; var isCollection = false }
    private var entries: [Entry] = []
    private var cur: Entry?
    private var text = ""

    static let httpDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 0)
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return f
    }()

    static func parse(_ data: Data) -> [Entry]? {
        let p = XMLParser(data: data)
        let d = PropfindParser()
        p.delegate = d
        p.shouldProcessNamespaces = true
        return p.parse() ? d.entries : nil
    }

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
        text = ""
        switch name.lowercased() {
        case "response": cur = Entry()
        case "collection": cur?.isCollection = true
        default: break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name.lowercased() {
        case "href": cur?.href = t
        case "getlastmodified": cur?.modified = Self.httpDate.date(from: t)
        case "getcontentlength": cur?.length = Int64(t)
        case "response":
            if let c = cur { entries.append(c) }
            cur = nil
        default: break
        }
        text = ""
    }
}

/// In-memory server for the simulator UI tests.
final class WebDAVMemory: WebDAVTransport {
    static let shared = WebDAVMemory()
    private var files: [String: (Data, Date)] = [:]
    private let lock = NSLock()
    func ensureFolder() async throws {}
    func list() async throws -> [WebDAVFile] {
        lock.lock(); defer { lock.unlock() }
        return files.map { WebDAVFile(name: $0.key, size: Int64($0.value.0.count), modified: $0.value.1) }
    }
    func put(_ name: String, _ data: Data) async throws { lock.lock(); files[name] = (data, Date()); lock.unlock() }
    func get(_ name: String) async throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let f = files[name] else { throw WebDAVError.http(404, "") }
        return f.0
    }
    func delete(_ name: String) async throws { lock.lock(); files[name] = nil; lock.unlock() }
}

enum WebDAVClient {
    static let prefix = "mihomo-backup-"
    /// Names written before review 5: device-local time (parse only).
    static let stampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f
    }()
    /// Review 5 P2-4: new names are UTC with a trailing Z, so devices in other time zones and the repeated DST
    /// hour cannot make pruning rank an older backup as newer.
    static let stampFormatterUTC: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f
    }()
    static func stampName(_ date: Date = Date()) -> String { prefix + stampFormatterUTC.string(from: date) + "Z" }

    static var demo: Bool { UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoWebDAV") }

    /// `password`: the value the page holds (the Keychain copy can be unreadable, e.g. a signature whose
    /// access group differs); nil = read the Keychain.
    static func transport(_ s: WebDAVSettings, password: String? = nil) throws -> WebDAVTransport {
        if demo { return WebDAVMemory.shared }
        guard let folder = s.folderURL else { throw WebDAVError.notConfigured }
        if s.isInsecure && !s.allowInsecure { throw WebDAVError.insecure }
        return WebDAVHTTP(folder: folder, username: s.username, password: password ?? Keychain.read(WebDAVSettings.passwordAccount) ?? "")
    }

    /// Newest first (by the time in the name, else the server's date).
    static func sorted(_ l: [WebDAVFile]) -> [WebDAVFile] {
        l.sorted { ($0.stamp ?? $0.modified ?? .distantPast) > ($1.stamp ?? $1.modified ?? .distantPast) }
    }

    /// Uploads a new backup and keeps the newest `keep`. Returns (file name, files in the backup, removed).
    @MainActor
    static func backup(_ s: WebDAVSettings, password: String? = nil, encryptionPassword: String? = nil) async throws -> (String, Int, Int) {
        if s.includeCA && !s.encrypt { throw WebDAVError.caNeedsEncryption }
        let t = try transport(s, password: password)
        // Review 5 P2-1: the scripts' store (cookies, tokens) only goes into encrypted backups.
        let (url, n) = try BackupManager.make(includeCA: s.includeCA, includeStore: s.encrypt)
        var data = try Data(contentsOf: url)
        try? FileManager.default.removeItem(at: url)
        var name = stampName()
        if s.encrypt {
            // v0.19: the page passes the password it shows; the Keychain copy is only a fallback (it is not
            // readable when the keychain write failed, which left encrypted backups failing with a KDF error).
            guard let pw = encryptionPassword.flatMap({ $0.isEmpty ? nil : $0 }) ?? Keychain.read(WebDAVSettings.encryptionAccount), !pw.isEmpty else {
                throw BackupCrypto.CryptoError.kdf
            }
            let plain = data
            data = try await Task.detached(priority: .userInitiated) { try BackupCrypto.encrypt(plain, password: pw) }.value
            name += ".enc.json"
        } else {
            name += ".json"
        }
        try await t.ensureFolder()
        try await t.put(name, data)
        var removed = 0
        // Pruning is best effort: the backup is on the server already.
        let all = sorted((try? await t.list()) ?? [])
        if all.count > s.keep {
            for f in all.dropFirst(s.keep) where f.name != name {
                try? await t.delete(f.name)
                removed += 1
            }
        }
        return (name, n, removed)
    }
}
