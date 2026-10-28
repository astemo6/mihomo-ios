import CryptoKit
import XCTest
@testable import Tern

/// feat/nc-warp-register-ui (#166): WarpNodeLifecycle — the hooks that keep the Cloudflare device
/// registration in step with the node list: re-register replaces the node in place and deletes the
/// old device, deleting a node unregisters its device (best effort, the record is always forgotten),
/// renaming a node migrates its record. Plus the secrecy invariant: tokens and private keys never
/// appear in user-visible error text, and 429 gets its own rate-limit wording.
final class WarpLifecycleTests: XCTestCase {

    // MARK: mock transport / store (same Recorder pattern as WarpRegistrationTests)

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

    private func memoryStore() -> (WarpRegistration.CredentialStore, () -> [String: String]) {
        final class Box { var d: [String: String] = [:] }
        let box = Box()
        let s = WarpRegistration.CredentialStore(read: { box.d[$0] }, write: { box.d[$0] = $1; return true },
                                                 delete: { box.d[$0] = nil })
        return (s, { box.d })
    }

    private let serverKey = P256.Signing.PrivateKey()

    private var serverPEM: String {
        let b64 = serverKey.publicKey.derRepresentation.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----\n"
    }

    private func regReply(id: String, token: String) -> Data {
        Data("""
        {"id":"\(id)","type":"a","model":"PC","name":"","key":"x","account":{"id":"acc-1","account_type":"free",
         "created":"2026-10-27T14:00:00Z","warp_plus":false,"premium_data":0,"quota":0,"license":"LIC-123-abc"},
         "token":"\(token)","warp_enabled":false,"waitlist_enabled":false,"created":"2026-10-27T14:00:00Z",
         "updated":"2026-10-27T14:00:00Z","tos":"2026-10-27T14:00:00.000Z","place":0,"locale":"en_US","enabled":true,
         "install_id":"","fcm_token":""}
        """.utf8)
    }

    private var enrollReply: Data {
        let pk = serverPEM.replacingOccurrences(of: "\n", with: "\\n")
        return Data("""
        {"id":"t.new","key":"MFkw","key_type":"secp256r1","tunnel_type":"masque","account":{"account_type":"free"},
         "config":{"client_id":"AAAA","peers":[{"public_key":"\(pk)","endpoint":{"v4":"162.159.198.2:0","v6":"[2606:4700:103::2]:0",
          "host":"engage.cloudflareclient.com:2408","ports":[443,500,1701,4500]}}],
          "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8a36::2"}},
          "services":{"http_proxy":"172.16.0.1:2480"}},
         "policy":{"tunnel_protocol":"masque"}}
        """.utf8)
    }

    // The lifecycle reads its injection points from WarpNodeLifecycle statics; swap + restore.
    private var savedHTTP: WarpRegistration.HTTP?
    private var savedCreds: WarpRegistration.CredentialStore?

    override func setUp() {
        savedHTTP = WarpNodeLifecycle.http
        savedCreds = WarpNodeLifecycle.credentials
    }

    override func tearDown() {
        if let savedHTTP { WarpNodeLifecycle.http = savedHTTP }
        if let savedCreds { WarpNodeLifecycle.credentials = savedCreds }
    }

    private func install(_ rec: Recorder, _ store: WarpRegistration.CredentialStore) {
        WarpNodeLifecycle.http = http(rec)
        WarpNodeLifecycle.credentials = store
    }

    private func account(_ id: String, _ token: String) -> WarpRegistration.Account {
        WarpRegistration.Account(id: id, token: token, license: "L", accountType: "free",
                                 created: Date(timeIntervalSince1970: 1_793_109_600))
    }

    // MARK: re-register

    @MainActor
    func testReregisterReplacesNodeKeepsNameDeletesOldDevice() async throws {
        let (store, _) = memoryStore()
        WarpRegistration.saveAccount(account("t.old", "old-tok"), nodeName: "Cloudflare WARP", store: store)
        let rec = Recorder([(200, regReply(id: "t.new", token: "new-tok")), (200, enrollReply), (204, Data())])
        install(rec, store)
        var saved: [[String: Any]] = []
        let warning = try await WarpNodeLifecycle.reregister(nodeName: "Cloudflare WARP") { saved.append($0) }
        XCTAssertNil(warning)
        XCTAssertEqual(saved.count, 1)
        XCTAssertEqual(saved.first?["name"] as? String, "Cloudflare WARP", "same name, replaced in place")
        XCTAssertEqual(saved.first?["type"] as? String, "masque")
        let reqs = await rec.requests
        XCTAssertEqual(reqs.map { $0.httpMethod ?? "" }, ["POST", "PATCH", "DELETE"])
        XCTAssertEqual(reqs[2].url?.path, "/v0a4471/reg/t.old", "the OLD device is deleted")
        XCTAssertEqual(reqs[2].value(forHTTPHeaderField: "Authorization"), "Bearer old-tok")
        XCTAssertEqual(WarpRegistration.account(nodeName: "Cloudflare WARP", store: store)?.id, "t.new",
                       "the credential record now holds the new device")
    }

    @MainActor
    func testReregisterSaveFailureDeletesNewDeviceAndThrows() async {
        struct Boom: Error {}
        let (store, _) = memoryStore()
        WarpRegistration.saveAccount(account("t.old", "old-tok"), nodeName: "Cloudflare WARP", store: store)
        let rec = Recorder([(200, regReply(id: "t.new", token: "new-tok")), (200, enrollReply), (204, Data())])
        install(rec, store)
        do {
            _ = try await WarpNodeLifecycle.reregister(nodeName: "Cloudflare WARP") { _ in throw Boom() }
            XCTFail("expected throw")
        } catch is Boom {} catch { XCTFail("\(error)") }
        let reqs = await rec.requests
        XCTAssertEqual(reqs.map { $0.httpMethod ?? "" }, ["POST", "PATCH", "DELETE"])
        XCTAssertEqual(reqs[2].url?.path, "/v0a4471/reg/t.new", "the NEW device is deleted again")
        XCTAssertEqual(WarpRegistration.account(nodeName: "Cloudflare WARP", store: store)?.id, "t.old",
                       "the old record is untouched")
    }

    // MARK: delete cleanup

    func testDeleteCleanupSuccess() async {
        let (store, dump) = memoryStore()
        WarpRegistration.saveAccount(account("t.d", "tok"), nodeName: "W", store: store)
        let rec = Recorder([(204, Data())])
        install(rec, store)
        let warning = await WarpNodeLifecycle.deleteCleanup(nodeName: "W")
        XCTAssertNil(warning)
        XCTAssertTrue(dump().isEmpty, "record forgotten")
        let methods = await rec.requests.map { $0.httpMethod ?? "" }
        XCTAssertEqual(methods, ["DELETE"])
    }

    func testDeleteCleanupFailureStillForgetsAndWarns() async {
        let (store, dump) = memoryStore()
        WarpRegistration.saveAccount(account("t.d", "tok"), nodeName: "W", store: store)
        let rec = Recorder([(500, Data("boom".utf8))])
        install(rec, store)
        let warning = await WarpNodeLifecycle.deleteCleanup(nodeName: "W")
        XCTAssertEqual(warning, String(localized: "节点已删除，但设备未能注销", table: "WarpRegister"))
        XCTAssertTrue(dump().isEmpty, "record forgotten even when unregister fails")
    }

    func testDeleteCleanupWithoutRecordIsSilent() async {
        let (store, _) = memoryStore()
        let rec = Recorder([])
        install(rec, store)
        let warning = await WarpNodeLifecycle.deleteCleanup(nodeName: "plain-node")
        XCTAssertNil(warning)
        let reqs = await rec.requests
        XCTAssertTrue(reqs.isEmpty, "no API call for a node that was never registered")
    }

    // MARK: rename migration

    func testMigrateRename() {
        let (store, _) = memoryStore()
        let acct = account("t.d", "tok")
        WarpRegistration.saveAccount(acct, nodeName: "Old", store: store)
        WarpNodeLifecycle.credentials = store
        WarpNodeLifecycle.migrateRename(from: "Old", to: "New")
        XCTAssertEqual(WarpRegistration.account(nodeName: "New", store: store), acct)
        XCTAssertNil(WarpRegistration.account(nodeName: "Old", store: store))
        // A non-WARP rename and a same-name save are no-ops.
        WarpNodeLifecycle.migrateRename(from: "New", to: "New")
        XCTAssertEqual(WarpRegistration.account(nodeName: "New", store: store), acct)
        WarpNodeLifecycle.migrateRename(from: "ghost", to: "Other")
        XCTAssertNil(WarpRegistration.account(nodeName: "Other", store: store))
    }

    // MARK: secrets & 429 wording

    func testSecretsStayOutOfErrorText() async {
        // Fixed key pair + a token in the recorded reply; the PATCH then fails 403.
        let kp = WarpRegistration.generateKeyPair()
        let rec = Recorder([(200, regReply(id: "t.sec", token: "tok-secret-1")),
                            (403, Data(#"{"success":false}"#.utf8)), (204, Data())])
        do {
            _ = try await WarpRegistration.register(name: "W", http: http(rec), keyPair: kp)
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            let desc = f.errorDescription ?? ""
            XCTAssertFalse(desc.contains("tok-secret-1"), "token leaked into error text: \(desc)")
            XCTAssertFalse(desc.contains(kp.privateKey), "private key leaked into error text")
            XCTAssertFalse(desc.contains(kp.publicKeySPKI), "public key leaked into error text")
        } catch { XCTFail("\(error)") }
    }

    func testRateLimitWording() async {
        let rec = Recorder([(429, Data("slow down".utf8)), (429, Data("slow down".utf8))])
        do {
            _ = try await WarpRegistration.register(http: http(rec))
            XCTFail("expected failure")
        } catch let f as WarpRegistration.Failure {
            let desc = f.errorDescription ?? ""
            XCTAssertTrue(desc.contains("429"), desc)
            XCTAssertTrue(desc.contains("重试") || desc.contains("try again"), "rate-limit wording: \(desc)")
        } catch { XCTFail("\(error)") }
    }
}
