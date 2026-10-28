import CryptoKit
import Foundation

/// feat/nc-warp-register: in-app Cloudflare WARP registration (the Swift port of tools/loopback/warp/register.py).
///
/// Flow (Cloudflare's unofficial client API, the one the official apps and the open-source WARP MASQUE clients use):
///   1. POST  {api}/reg       — new free device. Its WireGuard key is a random placeholder that is never used.
///   2. PATCH {api}/reg/{id}  — enroll our fresh P-256 public key (SPKI): key_type secp256r1, tunnel_type masque.
///      The answer's config.peers[0] carries the MASQUE endpoint (v4 / v6 as "host:0") and the endpoint's P-256
///      public key (PEM SPKI, the key NCMASQUEWarp pins); config.interface.addresses the tunnel v4 / v6.
///   3. DELETE {api}/reg/{id} — `unregister`, e.g. when the node is deleted or saving it failed.
///
/// The result is a canonical Tern `type: masque` node (the fields NCMASQUE.Config reads for a WARP node: server, port,
/// private-key = SEC 1 DER base64, public-key = SPKI DER base64, ip / ipv6, mtu, dns, udp). The node itself goes into
/// the manual-node profile in the App Group like every other manual node (WarpRegisterModel); the device id / bearer
/// token / licence, which only `unregister` needs, go to the shared Keychain (`saveAccount`).
///
/// Self-contained on purpose: Foundation + CryptoKit + Shared/Keychain.swift only, so the TernE2ETunnelTests bundle
/// (which never imports the app module) compiles this file for the live registration test.
enum WarpRegistration {

    // MARK: constants (same as register.py, verified against the real API by proto-loopback.yml masque-warp)

    static let apiBase = URL(string: "https://api.cloudflareclient.com/v0a4471")!
    static let headers: [String: String] = [
        "User-Agent": "WARP for Android",
        "CF-Client-Version": "a-6.35-4471",
        "Content-Type": "application/json; charset=UTF-8",
    ]
    /// Cloudflare's anycast MASQUE endpoint; only used when the enrollment answer has no v4 endpoint at all.
    static let defaultServer = "162.159.198.2"
    static let defaultPort = 443
    /// Same MTU the WARP interop uses (the netif clamps to what the QUIC datagram allows).
    static let defaultMTU = 1280
    static let defaultName = "Cloudflare WARP"
    /// Keychain account prefix for the stored device credentials (`warp-account:<node name>`).
    static let keychainPrefix = "warp-account:"

    // MARK: types

    /// The device credentials Cloudflare issued; only needed to delete the device again.
    struct Account: Codable, Equatable {
        var id: String
        var token: String
        var license: String
        var accountType: String
        var created: Date
    }

    /// A registered WARP device as a Tern node.
    struct Node: Equatable {
        var name: String
        var server: String
        var server6: String
        var port: Int
        /// SEC 1 DER (RFC 5915, with curve OID and public key), base64 — what register.py / NCMASQUEWarp use.
        var privateKey: String
        /// The endpoint's P-256 key as SPKI DER base64 (PEM armour stripped) — pinned by NCMASQUEWarp.
        var publicKey: String
        var ipv4: String
        var ipv6: String
        var mtu: Int
        var account: Account

        /// The canonical `type: masque` node dictionary (ProfileStore.upsertManualNode / NCJSONValue(_:)).
        var proxyFields: [String: Any] {
            var f: [String: Any] = [
                "name": name, "type": "masque", "server": server, "port": port,
                "private-key": privateKey, "public-key": publicKey,
                "ip": ipv4, "mtu": mtu, "udp": true, "dns": ["1.1.1.1", "1.0.0.1"],
            ]
            if !ipv6.isEmpty { f["ipv6"] = ipv6 }
            return f
        }
    }

    enum Failure: LocalizedError, Equatable {
        case http(step: String, status: Int, body: String)
        case transport(String)
        case badResponse(String)

        var errorDescription: String? {
            switch self {
            case .http(let step, let status, let body):
                let tail = body.isEmpty ? "" : "：" + body
                if status == 429 {
                    return String(localized: "Cloudflare WARP 注册被限流（HTTP 429），请稍后重试", table: "WarpRegister") + tail
                }
                return String(localized: "Cloudflare WARP 注册失败（\(step) HTTP \(status)）\(tail)", table: "WarpRegister")
            case .transport(let why):
                return String(localized: "无法连接 Cloudflare WARP 注册接口：\(why)", table: "WarpRegister")
            case .badResponse(let what):
                return String(localized: "Cloudflare WARP 注册返回的数据不完整：\(what)", table: "WarpRegister")
            }
        }
    }

    /// The transport, injectable for tests (recorded / mock HTTP).
    typealias HTTP = (URLRequest) async throws -> (Data, HTTPURLResponse)

    static let urlSession: HTTP = { req in
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw Failure.transport("not HTTP") }
        return (data, http)
    }

    /// One fresh P-256 key pair: (SEC 1 DER base64 private key, SPKI DER base64 public key).
    typealias KeyPair = (privateKey: String, publicKeySPKI: String)

    static func generateKeyPair() -> KeyPair {
        let k = P256.Signing.PrivateKey()
        return (sec1DER(scalar: k.rawRepresentation, publicX963: k.publicKey.x963Representation).base64EncodedString(),
                k.publicKey.derRepresentation.base64EncodedString())
    }

    // MARK: public entry point

    /// Registers a new free WARP device, enrolls a fresh P-256 MASQUE key and returns it as a Tern node.
    /// On a failed enrollment the half-registered device is deleted again (best effort).
    static func register(name: String = defaultName,
                         http: @escaping HTTP = urlSession,
                         now: Date = Date(),
                         keyPair: KeyPair? = nil) async throws -> Node {
        let reg = try await send(registerRequest(now: now), step: "POST /reg", http: http, retries: 1)
        let account = try parseRegisterResponse(reg, now: now)
        let keys = keyPair ?? generateKeyPair()
        let enroll: Data
        do {
            try Task.checkCancellation()
            enroll = try await send(enrollRequest(deviceID: account.id, token: account.token,
                                                  publicKeySPKI: keys.publicKeySPKI),
                                    step: "PATCH /reg", http: http, retries: 0)
        } catch {
            try? await unregister(account, http: http)
            throw error
        }
        do {
            try Task.checkCancellation()
            return try parseEnrollResponse(enroll, name: name, privateKey: keys.privateKey, account: account)
        } catch {
            try? await unregister(account, http: http)
            throw error
        }
    }

    /// DELETE /reg/{id}: removes the device from Cloudflare. 204 / 200 / 404 (already gone) all count as done.
    static func unregister(_ account: Account, http: @escaping HTTP = urlSession) async throws {
        var req = URLRequest(url: apiBase.appendingPathComponent("reg").appendingPathComponent(account.id))
        req.httpMethod = "DELETE"
        applyHeaders(&req, token: account.token)
        let (data, resp) = try await callHTTP(req, http: http)
        guard (200..<300).contains(resp.statusCode) || resp.statusCode == 404 else {
            throw Failure.http(step: "DELETE /reg", status: resp.statusCode, body: snippet(data))
        }
    }

    // MARK: requests (internal for the unit tests)

    static func registerRequest(now: Date, placeholderKey: Data? = nil, serial: String? = nil) -> URLRequest {
        var req = URLRequest(url: apiBase.appendingPathComponent("reg"))
        req.httpMethod = "POST"
        applyHeaders(&req, token: nil)
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let body: [String: Any] = [
            "key": (placeholderKey ?? randomBytes(32)).base64EncodedString(),
            "install_id": "", "fcm_token": "",
            "tos": fmt.string(from: now),
            "model": "PC",
            "serial_number": serial ?? randomBytes(8).map { String(format: "%02x", $0) }.joined(),
            "os_version": "",
            "key_type": "curve25519", "tunnel_type": "wireguard",
            "locale": "en_US",
        ]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        return req
    }

    static func enrollRequest(deviceID: String, token: String, publicKeySPKI: String) -> URLRequest {
        var req = URLRequest(url: apiBase.appendingPathComponent("reg").appendingPathComponent(deviceID))
        req.httpMethod = "PATCH"
        applyHeaders(&req, token: token)
        let body: [String: Any] = ["key": publicKeySPKI, "key_type": "secp256r1", "tunnel_type": "masque", "name": "Tern"]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        return req
    }

    // MARK: response parsing (internal for the unit tests)

    static func parseRegisterResponse(_ data: Data, now: Date) throws -> Account {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.badResponse("POST /reg: not JSON")
        }
        let id = o["id"] as? String ?? "", token = o["token"] as? String ?? ""
        guard !id.isEmpty, !token.isEmpty else { throw Failure.badResponse("POST /reg: id / token") }
        let acct = o["account"] as? [String: Any] ?? [:]
        return Account(id: id, token: token, license: acct["license"] as? String ?? "",
                       accountType: acct["account_type"] as? String ?? "", created: now)
    }

    static func parseEnrollResponse(_ data: Data, name: String, privateKey: String, account: Account) throws -> Node {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.badResponse("PATCH /reg: not JSON")
        }
        let cfg = o["config"] as? [String: Any] ?? [:]
        let peer = (cfg["peers"] as? [[String: Any]])?.first ?? [:]
        let ep = peer["endpoint"] as? [String: Any] ?? [:]
        let addrs = (cfg["interface"] as? [String: Any])?["addresses"] as? [String: Any] ?? [:]
        let server4 = stripPort(ep["v4"] as? String ?? "")
        let server6 = stripPort(ep["v6"] as? String ?? "")
        let pub = spkiFromPEM(peer["public_key"] as? String ?? "")
        let ip4 = stripPrefix(addrs["v4"] as? String ?? ""), ip6 = stripPrefix(addrs["v6"] as? String ?? "")
        var missing: [String] = []
        if pub.isEmpty || Data(base64Encoded: pub) == nil { missing.append("peers[0].public_key") }
        if ip4.isEmpty && ip6.isEmpty { missing.append("interface.addresses") }
        if !missing.isEmpty { throw Failure.badResponse(missing.joined(separator: ", ")) }
        // The endpoint answers "host:0"; MASQUE listens on 443 (also on the ports list when the API gives one).
        let ports = (ep["ports"] as? [Any])?.compactMap { ($0 as? NSNumber)?.intValue } ?? []
        let port = ports.isEmpty || ports.contains(defaultPort) ? defaultPort : ports[0]
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return Node(name: trimmed.isEmpty ? defaultName : trimmed,
                    server: server4.isEmpty ? defaultServer : server4, server6: server6, port: port,
                    privateKey: privateKey, publicKey: pub, ipv4: ip4, ipv6: ip6, mtu: defaultMTU, account: account)
    }

    // MARK: Keychain (device credentials; the node's own keys live in the manual profile like other nodes)

    /// Where the device credentials are kept; the shared Keychain in the app, an in-memory store in tests.
    struct CredentialStore {
        var read: (String) -> String?
        var write: (String, String) -> Bool
        var delete: (String) -> Void

        static let keychain = CredentialStore(read: { Keychain.read($0) }, write: { Keychain.write($0, $1) },
                                              delete: { Keychain.delete($0) })
    }

    @discardableResult
    static func saveAccount(_ account: Account, nodeName: String, store: CredentialStore = .keychain) -> Bool {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        guard let d = try? enc.encode(account) else { return false }
        return store.write(keychainPrefix + nodeName, String(decoding: d, as: UTF8.self))
    }

    static func account(nodeName: String, store: CredentialStore = .keychain) -> Account? {
        guard let s = store.read(keychainPrefix + nodeName) else { return nil }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(Account.self, from: Data(s.utf8))
    }

    static func forgetAccount(nodeName: String, store: CredentialStore = .keychain) {
        store.delete(keychainPrefix + nodeName)
    }

    // MARK: helpers

    /// RFC 5915 ECPrivateKey for P-256: version 1, the 32-byte scalar, [0] prime256v1, [1] the uncompressed point.
    static func sec1DER(scalar: Data, publicX963: Data) -> Data {
        precondition(scalar.count == 32 && publicX963.count == 65)
        var d = Data([0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20])
        d.append(scalar)
        d.append(contentsOf: [0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        d.append(contentsOf: [0xA1, 0x44, 0x03, 0x42, 0x00])
        d.append(publicX963)
        return d
    }

    /// "162.159.198.2:0" → "162.159.198.2", "[2606:4700:103::2]:0" → "2606:4700:103::2", a bare host unchanged.
    static func stripPort(_ ep: String) -> String {
        let s = ep.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            return String(s[s.index(after: s.startIndex)..<close])
        }
        if s.filter({ $0 == ":" }).count == 1, let colon = s.lastIndex(of: ":") { return String(s[..<colon]) }
        return s
    }

    /// "172.16.0.2/32" → "172.16.0.2" (the API answers bare addresses today; tolerate a prefix length).
    static func stripPrefix(_ a: String) -> String {
        let s = a.trimmingCharacters(in: .whitespaces)
        return s.split(separator: "/").first.map(String.init) ?? s
    }

    static func spkiFromPEM(_ pem: String) -> String {
        pem.split(whereSeparator: \.isNewline).filter { !$0.contains("-----") }
            .map { $0.trimmingCharacters(in: .whitespaces) }.joined()
    }

    private static func applyHeaders(_ req: inout URLRequest, token: String?) {
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let token { req.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        req.timeoutInterval = 30
    }

    private static func callHTTP(_ req: URLRequest, http: HTTP) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await http(req)
        } catch let f as Failure {
            throw f
        } catch {
            throw Failure.transport(error.localizedDescription)
        }
    }

    /// Sends `req`; 2xx → body. A 429 / 5xx / transport error is retried `retries` times after a short pause
    /// (registration is rate-limited per address; the CI job sees the odd 5xx too).
    private static func send(_ req: URLRequest, step: String, http: HTTP, retries: Int) async throws -> Data {
        var attempt = 0
        while true {
            do {
                let (data, resp) = try await callHTTP(req, http: http)
                if (200..<300).contains(resp.statusCode) { return data }
                let f = Failure.http(step: step, status: resp.statusCode, body: snippet(data))
                guard attempt < retries, resp.statusCode == 429 || resp.statusCode >= 500 else { throw f }
            } catch let f as Failure {
                guard attempt < retries, case .transport = f else { throw f }
            }
            attempt += 1
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
    }

    private static func snippet(_ d: Data) -> String {
        String(decoding: d.prefix(200), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func randomBytes(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }
}
