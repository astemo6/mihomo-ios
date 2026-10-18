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
            case .badFile: return String(localized: "不是 Mihomo 加密备份")
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
              let salt = Data(base64Encoded: env.salt), let blob = Data(base64Encoded: env.data) else { throw CryptoError.badFile }
        let k = try key(password, salt: salt, rounds: max(env.iterations, 1))
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
        return s
    }

    func save() {
        UserDefaults.standard.set(["url": url, "username": username, "keep": keep, "encrypt": encrypt, "includeCA": includeCA], forKey: Self.key)
    }

    var configured: Bool { URL(string: url.trimmingCharacters(in: .whitespaces))?.scheme?.hasPrefix("http") == true }

    /// The folder URL with a trailing slash.
    var folderURL: URL? {
        var s = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if !s.hasSuffix("/") { s += "/" }
        guard let u = URL(string: s), u.scheme?.hasPrefix("http") == true else { return nil }
        return u
    }
}

struct WebDAVFile: Identifiable, Hashable {
    var name: String
    var size: Int64?
    var modified: Date?
    var id: String { name }
    var encrypted: Bool { name.hasSuffix(".enc.json") }
    /// mihomo-backup-20261018-153000(.enc).json → that time.
    var stamp: Date? {
        let base = name.replacingOccurrences(of: WebDAVClient.prefix, with: "").replacingOccurrences(of: ".enc.json", with: "").replacingOccurrences(of: ".json", with: "")
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
    case notConfigured, http(Int, String), badResponse, auth
    var errorDescription: String? {
        switch self {
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
        session = URLSession(configuration: cfg)
    }

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
            let (d2, c2) = try await request(folder, "MKCOL")
            try check(c2, d2, ok: [201, 405])
            return
        }
        try check(code, d, ok: [207, 200])
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
    static let stampFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f
    }()

    static var demo: Bool { UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoWebDAV") }

    /// `password`: the value the page holds (the Keychain copy can be unreadable, e.g. a signature whose
    /// access group differs); nil = read the Keychain.
    static func transport(_ s: WebDAVSettings, password: String? = nil) throws -> WebDAVTransport {
        if demo { return WebDAVMemory.shared }
        guard let folder = s.folderURL else { throw WebDAVError.notConfigured }
        return WebDAVHTTP(folder: folder, username: s.username, password: password ?? Keychain.read(WebDAVSettings.passwordAccount) ?? "")
    }

    /// Newest first (by the time in the name, else the server's date).
    static func sorted(_ l: [WebDAVFile]) -> [WebDAVFile] {
        l.sorted { ($0.stamp ?? $0.modified ?? .distantPast) > ($1.stamp ?? $1.modified ?? .distantPast) }
    }

    /// Uploads a new backup and keeps the newest `keep`. Returns (file name, files in the backup, removed).
    @MainActor
    static func backup(_ s: WebDAVSettings, password: String? = nil, encryptionPassword: String? = nil) async throws -> (String, Int, Int) {
        let t = try transport(s, password: password)
        let (url, n) = try BackupManager.make(includeCA: s.includeCA)
        var data = try Data(contentsOf: url)
        try? FileManager.default.removeItem(at: url)
        var name = prefix + stampFormatter.string(from: Date())
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
        let all = sorted(try await t.list())
        if all.count > s.keep {
            for f in all.dropFirst(s.keep) where f.name != name {
                try? await t.delete(f.name)
                removed += 1
            }
        }
        return (name, n, removed)
    }
}
