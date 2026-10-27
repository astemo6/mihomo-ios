import CryptoKit
import XCTest
@testable import Tern

/// feat/nc-warp-register: WarpRegistration (Swift port of tools/loopback/warp/register.py) with recorded / mock HTTP —
/// request shape, response parsing into the canonical masque node, cleanup on failure, key encoding, Keychain record,
/// and the view-model. The live registration + MASQUE connect is E2ETests/WarpRegistrationLiveTests (proto-loopback.yml
/// job `warp-register`, opt-in).
final class WarpRegistrationTests: XCTestCase {

    // MARK: mock transport

    actor Recorder {
        private(set) var requests: [URLRequest] = []
        private var replies: [(Int, Data)]
        init(_ replies: [(Int, Data)]) { self.replies = replies }
        func next(_ r: URLRequest) -> (Int, Data) {
            requests.append(r)
            return replies.isEmpty ? (500, Data("no reply scripted".utf8)) : replies.removeFirst()
        }
    }

    private func http(_ rec: Recorder) -> WarpRegistration.HTTP {
        { req in
            let (status, body) = await rec.next(req)
            let resp = HTTPURLResponse(url: req.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
            return (body, resp)
        }
    }

    private func body(_ r: URLRequest) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: r.httpBody ?? Data()) as? [String: Any]) ?? [:]
    }

    // MARK: recorded responses (shape of the real v0a4471 answers, as logged by proto-loopback masque-warp)

    private let serverKey = P256.Signing.PrivateKey()

    private var serverPEM: String {
        let b64 = serverKey.publicKey.derRepresentation.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----\n"
    }

    private let regReply = Data("""
    {"id":"t.0a1b2c3d-dev","type":"a","model":"PC","name":"","key":"x","account":{"id":"acc-1","account_type":"free",
     "created":"2026-10-27T14:00:00Z","warp_plus":false,"premium_data":0,"quota":0,"license":"LIC-123-abc"},
     "token":"tok-secret-1","warp_enabled":false,"waitlist_enabled":false,"created":"2026-10-27T14:00:00Z",
     "updated":"2026-10-27T14:00:00Z","tos":"2026-10-27T14:00:00.000Z","place":0,"locale":"en_US","enabled":true,
     "install_id":"","fcm_token":""}
    """.utf8)

    private func enrollReply(v4: String = "162.159.198.2:0", v6: String = "[2606:4700:103::2]:0", ports: String = "[443,500,1701,4500]",
                             publicKey: String? = nil, addrV4: String = "172.16.0.2", addrV6: String = "2606:4700:110:8a36::2") -> Data {
        let pk = (publicKey ?? serverPEM).replacingOccurrences(of: "\n", with: "\\n")
        return Data("""
        {"id":"t.0a1b2c3d-dev","key":"MFkw","key_type":"secp256r1","tunnel_type":"masque","account":{"account_type":"free"},
         "config":{"client_id":"AAAA","peers":[{"public_key":"\(pk)","endpoint":{"v4":"\(v4)","v6":"\(v6)",
           "host":"engage.cloudflareclient.com:2408","ports":\(ports)}}],
          "interface":{"addresses":{"v4":"\(addrV4)","v6":"\(addrV6)"}},
          "services":{"http_proxy":"172.16.0.1:2480"}},
         "policy":{"tunnel_protocol":"masque"}}
        """.utf8)
    }

    // MARK: request shape

    func testRegisterRequestShape() throws {
        let now = Date(timeIntervalSince1970: 1_793_109_600.125) // 2026-10-27T14:00:00.125Z
        let r = WarpRegistration.registerRequest(now: now)
        XCTAssertEqual(r.httpMethod, "POST")
        XCTAssertEqual(r.url?.absoluteString, "https://api.cloudflareclient.com/v0a4471/reg")
        XCTAssertEqual(r.value(forHTTPHeaderField: "User-Agent"), "WARP for Android")
        XCTAssertEqual(r.value(forHTTPHeaderField: "CF-Client-Version"), "a-6.35-4471")
        XCTAssertEqual(r.value(forHTTPHeaderField: "Content-Type"), "application/json; charset=UTF-8")
        XCTAssertNil(r.value(forHTTPHeaderField: "Authorization"))
        let b = body(r)
        XCTAssertEqual(b["key_type"] as? String, "curve25519")
        XCTAssertEqual(b["tunnel_type"] as? String, "wireguard")
        XCTAssertEqual(b["model"] as? String, "PC")
        XCTAssertEqual(b["locale"] as? String, "en_US")
        XCTAssertEqual(b["install_id"] as? String, "")
        XCTAssertEqual(b["fcm_token"] as? String, "")
        XCTAssertEqual(b["os_version"] as? String, "")
        XCTAssertEqual(Data(base64Encoded: b["key"] as? String ?? "")?.count, 32)
        let serial = b["serial_number"] as? String ?? ""
        XCTAssertEqual(serial.count, 16)
        XCTAssertTrue(serial.allSatisfy { $0.isHexDigit })
        XCTAssertEqual(b["tos"] as? String, "2026-10-27T14:00:00.125Z")
        // Two requests never share the placeholder key / serial.
        let b2 = body(WarpRegistration.registerRequest(now: now))
        XCTAssertNotEqual(b["key"] as? String, b2["key"] as? String)
    }

    func testEnrollRequestShape() {
        let r = WarpRegistration.enrollRequest(deviceID: "t.dev-1", token: "tok", publicKeySPKI: "MFkwEw==")
        XCTAssertEqual(r.httpMethod, "PATCH")
        XCTAssertEqual(r.url?.absoluteString, "https://api.cloudflareclient.com/v0a4471/reg/t.dev-1")
        XCTAssertEqual(r.value(forHTTPHeaderField: "Authorization"), "Bearer tok")
        XCTAssertEqual(r.value(forHTTPHeaderField: "CF-Client-Version"), "a-6.35-4471")
        let b = body(r)
        XCTAssertEqual(b["key"] as? String, "MFkwEw==")
        XCTAssertEqual(b["key_type"] as? String, "secp256r1")
        XCTAssertEqual(b["tunnel_type"] as? String, "masque")
        XCTAssertEqual(b["name"] as? String, "Tern")
    }

    // MARK: keys

    func testGeneratedKeyPairEncoding() throws {
        let kp = WarpRegistration.generateKeyPair()
        let der = try XCTUnwrap(Data(base64Encoded: kp.privateKey))
        XCTAssertEqual(der.count, 121)
        XCTAssertEqual(Array(der.prefix(7)), [0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20])
        // The private key is accepted by the WARP data plane (SecKey + identity source) …
        XCTAssertNotNil(NCMASQUEWarp.parsePrivateKey(kp.privateKey))
        // … and the enrolled SPKI is exactly its public key.
        let scalar = der[7..<39]
        let priv = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let spki = try XCTUnwrap(Data(base64Encoded: kp.publicKeySPKI))
        XCTAssertEqual(spki, priv.publicKey.derRepresentation)
        XCTAssertEqual(Data(der.suffix(65)), priv.publicKey.x963Representation)
        XCTAssertNil(NCMASQUEWarp.validate(privateKey: kp.privateKey, publicKey: kp.publicKeySPKI))
        XCTAssertNotEqual(kp.privateKey, WarpRegistration.generateKeyPair().privateKey)
    }

    // MARK: full flow against recorded replies

    func testRegisterProducesCanonicalMasqueNode() async throws {
        let rec = Recorder([(200, regReply), (200, enrollReply())])
        let kp = WarpRegistration.generateKeyPair()
        let node = try await WarpRegistration.register(name: "  My WARP ", http: http(rec), keyPair: kp)

        let reqs = await rec.requests
        XCTAssertEqual(reqs.map { $0.httpMethod ?? "" }, ["POST", "PATCH"])
        XCTAssertEqual(reqs[1].url?.path, "/v0a4471/reg/t.0a1b2c3d-dev")
        XCTAssertEqual(reqs[1].value(forHTTPHeaderField: "Authorization"), "Bearer tok-secret-1")
        XCTAssertEqual(body(reqs[1])["key"] as? String, kp.publicKeySPKI)

        XCTAssertEqual(node.name, "My WARP")
        XCTAssertEqual(node.server, "162.159.198.2")
        XCTAssertEqual(node.server6, "2606:4700:103::2")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.privateKey, kp.privateKey)
        XCTAssertEqual(node.publicKey, serverKey.publicKey.derRepresentation.base64EncodedString())
        XCTAssertEqual(node.ipv4, "172.16.0.2")
        XCTAssertEqual(node.ipv6, "2606:4700:110:8a36::2")
        XCTAssertEqual(node.mtu, 1280)
        XCTAssertEqual(node.account.id, "t.0a1b2c3d-dev")
        XCTAssertEqual(node.account.token, "tok-secret-1")
        XCTAssertEqual(node.account.license, "LIC-123-abc")
        XCTAssertEqual(node.account.accountType, "free")

        // The node dictionary is what NativeCore reads as a WARP MASQUE node, and it is available.
        let f = node.proxyFields
        XCTAssertEqual(f["type"] as? String, "masque")
        XCTAssertEqual(f["udp"] as? Bool, true)
        let p = NCProxy(name: node.name, type: "masque", fields: f.mapValues(NCJSONValue.init))
        XCTAssertNil(NCSupport.unsupportedReason(p))
        let cfg = try XCTUnwrap(NCMASQUE.Config(proxy: p))
        XCTAssertTrue(cfg.isWarp)
        XCTAssertEqual(cfg.mode, .connectIP)
        XCTAssertEqual(cfg.port, 443)
        XCTAssertEqual(cfg.sni, NCMASQUE.defaultWarpSNI)
        XCTAssertEqual(cfg.ip, "172.16.0.2")
        XCTAssertEqual(cfg.ipv6, "2606:4700:110:8a36::2")
        // It survives the manual-node JSON round trip (what ProfileStore.upsertManualNode receives).
        let json = try JSONSerialization.data(withJSONObject: f)
        let back = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertEqual(back["private-key"] as? String, kp.privateKey)
    }

    func testPortFallbackAndMissingEndpoint() async throws {
        // No v4 endpoint → Cloudflare's anycast default; a ports list without 443 → its first port.
        let rec = Recorder([(200, regReply), (200, enrollReply(v4: "", ports: "[8443,500]"))])
        let node = try await WarpRegistration.register(http: http(rec))
        XCTAssertEqual(node.server, WarpRegistration.defaultServer)
        XCTAssertEqual(node.port, 8443)
        XCTAssertEqual(node.name, WarpRegistration.defaultName)
    }

    func testEnrollFailureDeletesDevice() async {
        let rec = Recorder([(200, regReply), (400, Data(#"{"success":false,"errors":[{"code":1000}]}"#.utf8)), (204, Data())])
        do {
            _ = try await WarpRegistration.register(http: http(rec))
            XCTFail("expected failure")
        } catch WarpRegistration.Failure.http(let step, let status, let body) {
            XCTAssertEqual(step, "PATCH /reg")
            XCTAssertEqual(status, 400)
            XCTAssertTrue(body.contains("1000"))
        } catch { XCTFail("\(error)") }
        let reqs = await rec.requests
        XCTAssertEqual(reqs.map { $0.httpMethod ?? "" }, ["POST", "PATCH", "DELETE"])
        XCTAssertEqual(reqs[2].url?.path, "/v0a4471/reg/t.0a1b2c3d-dev")
        XCTAssertEqual(reqs[2].value(forHTTPHeaderField: "Authorization"), "Bearer tok-secret-1")
    }

    func testIncompleteEnrollAnswerDeletesDevice() async {
        let rec = Recorder([(200, regReply), (200, enrollReply(publicKey: "", addrV4: "", addrV6: "")), (204, Data())])
        do {
            _ = try await WarpRegistration.register(http: http(rec))
            XCTFail("expected failure")
        } catch WarpRegistration.Failure.badResponse(let what) {
            XCTAssertTrue(what.contains("public_key"), what)
            XCTAssertTrue(what.contains("addresses"), what)
        } catch { XCTFail("\(error)") }
        let methods = await rec.requests.map { $0.httpMethod ?? "" }
        XCTAssertEqual(methods, ["POST", "PATCH", "DELETE"])
    }

    func testRegistrationRetriesTransientOnce() async throws {
        let rec = Recorder([(503, Data("busy".utf8)), (200, regReply), (200, enrollReply())])
        let node = try await WarpRegistration.register(http: http(rec))
        XCTAssertEqual(node.ipv4, "172.16.0.2")
        let methods = await rec.requests.map { $0.httpMethod ?? "" }
        XCTAssertEqual(methods, ["POST", "POST", "PATCH"])
    }

    func testRateLimitedTwiceSurfacesError() async {
        let rec = Recorder([(429, Data("slow down".utf8)), (429, Data("slow down".utf8))])
        do {
            _ = try await WarpRegistration.register(http: http(rec))
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            XCTAssertEqual(f, .http(step: "POST /reg", status: 429, body: "slow down"))
            XCTAssertTrue((f.errorDescription ?? "").contains("429"))
        } catch { XCTFail("\(error)") }
    }

    func testBadRegisterAnswer() async {
        let rec = Recorder([(200, Data(#"{"id":"x"}"#.utf8))])
        do {
            _ = try await WarpRegistration.register(http: http(rec))
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            XCTAssertEqual(f, .badResponse("POST /reg: id / token"))
        } catch { XCTFail("\(error)") }
    }

    func testTransportErrorIsWrapped() async {
        let failing: WarpRegistration.HTTP = { _ in throw URLError(.notConnectedToInternet) }
        do {
            _ = try await WarpRegistration.register(http: failing)
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            guard case .transport = f else { return XCTFail("\(f)") }
        } catch { XCTFail("\(error)") }
    }

    func testUnregisterAcceptsGoneDevice() async throws {
        let acct = WarpRegistration.Account(id: "t.d", token: "k", license: "", accountType: "free", created: Date())
        try await WarpRegistration.unregister(acct, http: http(Recorder([(404, Data())])))
        do {
            try await WarpRegistration.unregister(acct, http: http(Recorder([(401, Data("no".utf8))])))
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            XCTAssertEqual(f, .http(step: "DELETE /reg", status: 401, body: "no"))
        }
    }

    // MARK: helpers

    func testEndpointAndPEMHelpers() {
        XCTAssertEqual(WarpRegistration.stripPort("162.159.198.2:0"), "162.159.198.2")
        XCTAssertEqual(WarpRegistration.stripPort("[2606:4700:103::2]:0"), "2606:4700:103::2")
        XCTAssertEqual(WarpRegistration.stripPort("2606:4700:103::2"), "2606:4700:103::2")
        XCTAssertEqual(WarpRegistration.stripPort("162.159.198.2"), "162.159.198.2")
        XCTAssertEqual(WarpRegistration.stripPort(""), "")
        XCTAssertEqual(WarpRegistration.stripPrefix("172.16.0.2/32"), "172.16.0.2")
        XCTAssertEqual(WarpRegistration.stripPrefix("2606:4700::2"), "2606:4700::2")
        XCTAssertEqual(WarpRegistration.spkiFromPEM("-----BEGIN PUBLIC KEY-----\nMFkw\r\nEwYH\n-----END PUBLIC KEY-----\n"), "MFkwEwYH")
        XCTAssertEqual(WarpRegistration.spkiFromPEM("MFkwEwYH"), "MFkwEwYH")
    }

    // MARK: credentials record

    private func memoryStore() -> (WarpRegistration.CredentialStore, () -> [String: String]) {
        final class Box { var d: [String: String] = [:] }
        let box = Box()
        let s = WarpRegistration.CredentialStore(read: { box.d[$0] }, write: { box.d[$0] = $1; return true },
                                                 delete: { box.d[$0] = nil })
        return (s, { box.d })
    }

    func testAccountRoundTrip() {
        let (store, dump) = memoryStore()
        let acct = WarpRegistration.Account(id: "t.d", token: "tok", license: "L", accountType: "free",
                                            created: Date(timeIntervalSince1970: 1_793_109_600))
        XCTAssertTrue(WarpRegistration.saveAccount(acct, nodeName: "WARP", store: store))
        XCTAssertEqual(Array(dump().keys), ["warp-account:WARP"])
        XCTAssertEqual(WarpRegistration.account(nodeName: "WARP", store: store), acct)
        WarpRegistration.forgetAccount(nodeName: "WARP", store: store)
        XCTAssertNil(WarpRegistration.account(nodeName: "WARP", store: store))
    }

    // MARK: view-model

    func testUniqueName() {
        XCTAssertEqual(WarpRegisterModel.uniqueName("WARP", taken: []), "WARP")
        XCTAssertEqual(WarpRegisterModel.uniqueName("WARP", taken: ["WARP", "WARP 2"]), "WARP 3")
        XCTAssertEqual(WarpRegisterModel.uniqueName("  ", taken: []), WarpRegistration.defaultName)
    }

    @MainActor
    func testModelSavesNodeAndCredentials() async throws {
        let rec = Recorder([(200, regReply), (200, enrollReply())])
        let (store, dump) = memoryStore()
        var saved: [[String: Any]] = []
        let m = WarpRegisterModel()
        m.http = http(rec)
        m.credentials = store
        m.existingNames = { [WarpRegistration.defaultName] }
        m.save = { saved.append($0) }
        XCTAssertFalse(m.canRegister, "terms must be accepted first")
        let none = await m.register()
        XCTAssertNil(none)
        let noneReqs = await rec.requests
        XCTAssertTrue(noneReqs.isEmpty)
        m.acceptedTerms = true
        let got = await m.register()
        let node = try XCTUnwrap(got)
        XCTAssertEqual(node.name, "Cloudflare WARP 2")
        XCTAssertEqual(m.phase, .done("Cloudflare WARP 2"))
        XCTAssertEqual(saved.count, 1)
        XCTAssertEqual(saved.first?["name"] as? String, "Cloudflare WARP 2")
        XCTAssertEqual(saved.first?["type"] as? String, "masque")
        XCTAssertEqual(Array(dump().keys), ["warp-account:Cloudflare WARP 2"])
    }

    @MainActor
    func testModelSaveFailureDeletesDevice() async {
        struct Boom: LocalizedError { var errorDescription: String? { "disk full" } }
        let rec = Recorder([(200, regReply), (200, enrollReply()), (204, Data())])
        let (store, dump) = memoryStore()
        let m = WarpRegisterModel()
        m.http = http(rec)
        m.credentials = store
        m.existingNames = { [] }
        m.save = { _ in throw Boom() }
        m.acceptedTerms = true
        let node = await m.register()
        XCTAssertNil(node)
        XCTAssertEqual(m.phase, .failed("disk full"))
        XCTAssertTrue(dump().isEmpty)
        let methods = await rec.requests.map { $0.httpMethod ?? "" }
        XCTAssertEqual(methods, ["POST", "PATCH", "DELETE"])
    }
}
