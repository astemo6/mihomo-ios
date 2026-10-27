import XCTest
import Security
@testable import Tern

/// feat/fresh-reinstall: install marker (reinstall detection) and the wipe routine, on scratch directories, a scratch
/// defaults suite and a scratch Keychain service — never the real App Group, defaults or Keychain items.
final class DataResetTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("DataResetTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func dir(_ name: String) throws -> URL {
        let u = root.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    private func put(_ rel: String, in base: URL, _ text: String = "x") throws {
        let u = base.appendingPathComponent(rel)
        try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: u)
    }

    private func listing(_ base: URL) -> [String] {
        guard let e = FileManager.default.enumerator(atPath: base.path) else { return [] }
        return (e.allObjects as? [String] ?? []).sorted()
    }

    // MARK: marker / decision

    func testDecisionTable() {
        XCTAssertEqual(InstallMarker.decide(markerPresent: true, containerHasData: true), .known)
        XCTAssertEqual(InstallMarker.decide(markerPresent: true, containerHasData: false), .known)
        XCTAssertEqual(InstallMarker.decide(markerPresent: false, containerHasData: false), .firstInstall)
        XCTAssertEqual(InstallMarker.decide(markerPresent: false, containerHasData: true), .reinstall)
    }

    func testMarkerWriteAndExists() throws {
        let sandbox = try dir("AppSupport")
        XCTAssertFalse(InstallMarker.exists(in: sandbox))
        XCTAssertTrue(InstallMarker.write(in: sandbox))
        XCTAssertTrue(InstallMarker.exists(in: sandbox))
        XCTAssertEqual(InstallMarker.url(in: sandbox).lastPathComponent, ".tern-install")
        // Writes into a directory that does not exist yet (fresh sandbox: no Application Support).
        let fresh = root.appendingPathComponent("not-yet/Application Support", isDirectory: true)
        XCTAssertTrue(InstallMarker.write(in: fresh))
        XCTAssertTrue(InstallMarker.exists(in: fresh))
    }

    func testContainerHasDataIgnoresSystemFilesMarkerAndLibrary() throws {
        let group = try dir("group")
        XCTAssertFalse(DataReset.containerHasData(group, groupDomain: nil), "empty container")
        try put(".com.apple.mobile_container_manager.metadata.plist", in: group)
        try put(AppShared.groupMarkerName, in: group, "com.astemo6.tern")
        try put("Library/Preferences/group.com.astemo6.tern.plist", in: group)
        try put("Library/Caches/x", in: group)
        XCTAssertFalse(DataReset.containerHasData(group, groupDomain: nil), "only system / App Group marker / Library")
        XCTAssertFalse(DataReset.containerHasData(group, groupDomain: [:]), "empty suite")
        XCTAssertTrue(DataReset.containerHasData(group, groupDomain: ["activeProfileID": "a"]), "suite holds settings")
        try put("profiles.json", in: group, "[]")
        XCTAssertTrue(DataReset.containerHasData(group, groupDomain: nil), "profiles index")
    }

    /// First install → marker written silently; next launch known; delete (sandbox gone, group kept) → reinstall,
    /// marker NOT written until the user chooses; after 保留 (marker written) → known.
    func testLaunchEvaluationAcrossInstallReinstall() throws {
        let sandbox = try dir("sandbox/Library/Application Support")
        let group = try dir("group")
        try put(AppShared.groupMarkerName, in: group, "com.astemo6.tern")

        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil), .firstInstall)
        XCTAssertTrue(InstallMarker.exists(in: sandbox), "first install writes the marker silently")

        try put("profiles.json", in: group, "[]")
        try put("tern/overrides.json", in: group, "{}")
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil), .known, "update / relaunch")

        // The app is deleted: iOS removes its own sandbox, the App Group container stays.
        try FileManager.default.removeItem(at: root.appendingPathComponent("sandbox"))
        try FileManager.default.createDirectory(at: sandbox, withIntermediateDirectories: true)
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil), .reinstall)
        XCTAssertFalse(InstallMarker.exists(in: sandbox), "no marker until 保留 / 全部清除")
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil), .reinstall, "asked again if the app was killed before choosing")

        InstallMarker.write(in: sandbox) // 保留
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil), .known)
    }

    func testNoAppGroupIsNeverAReinstall() throws {
        let sandbox = try dir("sb")
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: nil, groupDomain: ["k": 1]), .firstInstall)
    }

    // MARK: wipe

    func testWipeContainerRemovesEveryTernFile() throws {
        let group = try dir("group")
        let tern = [
            "profiles.json", "profiles/abc.yaml", "profiles/abc.source.conf",
            "tern/overrides.json", "tern/secrets.json", "tern/rules.json", "tern/dns.json",
            "tern/engine/modules/m.sgmodule", "tern/engine/scripts/s.js", "tern/engine/store.json",
            "tern/engine/ca/ca.key", "tern/engine/ca/ca.crt", "tern/engine/ca/ca.p12",
            "tern/ruleset/custom-1.txt", "tern/proxies/p.yaml", "tern/cache.db", "tern/geoip.metadb",
            "tern/logs/tunnel.log", "traffic-history.json", "snapshots/1.json", ".hidden-ours",
            AppShared.groupMarkerName,
            "Library/Caches/tern-cache.bin",
        ]
        for rel in tern { try put(rel, in: group) }
        try put(".com.apple.mobile_container_manager.metadata.plist", in: group)
        try put("Library/Preferences/group.com.astemo6.tern.plist", in: group)

        let failed = DataReset.wipeContainer(group)
        XCTAssertEqual(failed, [])
        XCTAssertEqual(listing(group), [
            ".com.apple.mobile_container_manager.metadata.plist",
            "Library", "Library/Preferences", "Library/Preferences/group.com.astemo6.tern.plist",
        ])
        XCTAssertFalse(DataReset.containerHasData(group, groupDomain: nil), "a wiped container reads as empty")
        // Idempotent.
        XCTAssertEqual(DataReset.wipeContainer(group), [])
    }

    func testWipeContentsKeepsTheDirectories() throws {
        let docs = try dir("Documents"), caches = try dir("Caches"), support = try dir("Application Support")
        try put("UITestSamples/a.conf", in: docs)
        try put("module-gallery/index.json", in: caches)
        try put(InstallMarker.fileName, in: support)
        XCTAssertEqual(DataReset.wipeContents(of: [docs, caches, support]), [])
        for d in [docs, caches, support] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: d.path))
            XCTAssertEqual(listing(d), [])
        }
    }

    func testWipeDefaultsClearsSuiteAndStandardDomain() throws {
        let suiteName = "com.astemo6.tern.unittests.reset-\(UUID().uuidString)"
        let stdName = "com.astemo6.tern.unittests.std-\(UUID().uuidString)"
        let suite = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        let std = try XCTUnwrap(UserDefaults(suiteName: stdName))
        suite.set("p1", forKey: "activeProfileID")
        suite.set(["mode": "always"], forKey: "onDemandSettings")
        std.set(true, forKey: "onboardingDone.v1")
        std.set("group.x", forKey: AppShared.rememberedGroupKey)
        XCTAssertFalse((suite.persistentDomain(forName: suiteName) ?? [:]).isEmpty)

        DataReset.wipeDefaults(suite: suite, suiteName: suiteName, standard: std, standardDomain: stdName)
        XCTAssertNil(suite.string(forKey: "activeProfileID"))
        XCTAssertNil(suite.object(forKey: "onDemandSettings"))
        XCTAssertTrue((suite.persistentDomain(forName: suiteName) ?? [:]).isEmpty)
        XCTAssertNil(std.object(forKey: "onboardingDone.v1"))
        XCTAssertNil(std.string(forKey: AppShared.rememberedGroupKey))
    }

    func testWipeKeychainDeletesEveryAccountOfTheService() throws {
        let service = "com.astemo6.tern.unittests.reset-\(UUID().uuidString)"
        let other = service + ".other"
        func add(_ svc: String, _ account: String) -> OSStatus {
            SecItemAdd([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc,
                        kSecAttrAccount as String: account, kSecValueData as String: Data("v".utf8)] as CFDictionary, nil)
        }
        func count(_ svc: String) -> Int {
            var out: CFTypeRef?
            let s = SecItemCopyMatching([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: svc,
                                         kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll] as CFDictionary, &out)
            return s == errSecSuccess ? ((out as? [[String: Any]])?.count ?? 0) : 0
        }
        let first = add(service, Keychain.controllerSecretAccount)
        try XCTSkipIf(first != errSecSuccess, "Keychain not available to this test host (OSStatus \(first))")
        for a in [Keychain.lanSharePasswordAccount, Keychain.lanUsersAccount, WebDAVSettings.passwordAccount, WebDAVSettings.encryptionAccount] {
            XCTAssertEqual(add(service, a), errSecSuccess, a)
        }
        XCTAssertEqual(add(other, "keep-me"), errSecSuccess)
        XCTAssertEqual(count(service), 5)
        defer { SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: other] as CFDictionary) }

        XCTAssertTrue(DataReset.wipeKeychain(service: service))
        XCTAssertEqual(count(service), 0)
        XCTAssertEqual(count(other), 1, "only the given service")
        XCTAssertTrue(DataReset.wipeKeychain(service: service), "nothing left = still OK")
    }

    func testRealServiceNameIsTheOneKeychainUses() {
        XCTAssertEqual(Keychain.service, "com.astemo6.tern")
    }

    // MARK: settings search

    @MainActor
    func testSettingsSearchFindsResetAll() {
        let first = SettingsSearchIndex.search("清除全部数据").first?.entry
        XCTAssertEqual(first?.id, "resetAll")
        XCTAssertEqual(first?.destination, .backup)
        XCTAssertTrue(SettingsSearchIndex.search("wipe").map(\.entry.id).contains("resetAll"))
        XCTAssertTrue(SettingsSearchIndex.search("factory reset").map(\.entry.id).contains("resetAll"))
    }
}
