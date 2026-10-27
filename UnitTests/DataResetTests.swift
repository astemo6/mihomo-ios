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

    /// Updating from a build without the marker: the app's own preferences survived (they hold Tern keys), so it is
    /// not a reinstall even though the group has data; the marker is written silently.
    func testUpdateFromPreMarkerBuildIsNotAReinstall() throws {
        XCTAssertEqual(InstallMarker.decide(markerPresent: false, containerHasData: true, sandboxHasState: true), .known)
        XCTAssertTrue(InstallMarker.sandboxHasTernState([AppShared.rememberedGroupKey: "group.com.astemo6.tern"]))
        XCTAssertTrue(InstallMarker.sandboxHasTernState(["onboardingDone.v1": true]))
        XCTAssertTrue(InstallMarker.sandboxHasTernState(["panels.pinned": ["speed"]]))
        XCTAssertTrue(InstallMarker.sandboxHasTernState(["panels.home.hidden": ["speed"]]))
        XCTAssertFalse(InstallMarker.sandboxHasTernState(nil))
        XCTAssertFalse(InstallMarker.sandboxHasTernState(["AppleLanguages": ["zh-Hans"], "NSInterfaceStyle": "x"]), "system keys only")
        let sandbox = try dir("sb-update"), group = try dir("group-update")
        try put("profiles.json", in: group, "[]")
        XCTAssertEqual(InstallMarker.evaluate(markerDir: sandbox, container: group, groupDomain: nil, sandboxHasState: true), .known)
        XCTAssertTrue(InstallMarker.exists(in: sandbox), "marker written on the update")
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

    // MARK: defaults migration (standard → App Group)

    func testDefaultsMigrationMovesUserSettingsOnce() throws {
        let stdName = "com.astemo6.tern.unittests.mig-std-\(UUID().uuidString)"
        let grpName = "com.astemo6.tern.unittests.mig-grp-\(UUID().uuidString)"
        let std = try XCTUnwrap(UserDefaults(suiteName: stdName))
        let grp = try XCTUnwrap(UserDefaults(suiteName: grpName))
        defer { std.removePersistentDomain(forName: stdName); grp.removePersistentDomain(forName: grpName) }
        std.set(["speed", "memory"], forKey: "panels.pinned")
        std.set(Data("[]".utf8), forKey: "panels.home.tasks")
        std.set(["speed": "网速"], forKey: "panels.home.names")
        std.set("dark", forKey: "appearance")
        std.set(3, forKey: "ui.launchTab")
        std.set(["url": "https://dav.example/tern", "keep": 5], forKey: "webdav.settings")
        std.set("abc", forKey: "unlock.services")
        std.set(true, forKey: "onboardingDone.v1")          // device state: stays
        std.set(Data("x".utf8), forKey: "ipinfo.lastLookup.v1") // cache: stays
        std.set("old", forKey: "policy.sort")
        grp.set("custom", forKey: "policy.sort")             // the group already has it: group wins

        let moved = DefaultsMigration.run(standard: std, standardDomain: stdName, group: grp, groupDomain: grpName)
        XCTAssertEqual(Set(moved), ["panels.pinned", "panels.home.tasks", "panels.home.names",
                                    "appearance", "ui.launchTab", "webdav.settings", "unlock.services"])
        XCTAssertEqual(grp.stringArray(forKey: "panels.pinned"), ["speed", "memory"])
        XCTAssertEqual(grp.data(forKey: "panels.home.tasks"), Data("[]".utf8))
        XCTAssertEqual(grp.dictionary(forKey: "panels.home.names") as? [String: String], ["speed": "网速"])
        XCTAssertEqual(grp.string(forKey: "appearance"), "dark")
        XCTAssertEqual(grp.integer(forKey: "ui.launchTab"), 3)
        XCTAssertEqual(grp.dictionary(forKey: "webdav.settings")?["url"] as? String, "https://dav.example/tern")
        XCTAssertEqual(grp.string(forKey: "policy.sort"), "custom", "existing group value is not overwritten")
        for k in DefaultsMigration.movedKeys { XCTAssertNil(std.persistentDomain(forName: stdName)?[k], "standard copy dropped: \(k)") }
        XCTAssertEqual(std.bool(forKey: "onboardingDone.v1"), true, "device state stays in standard")
        XCTAssertNotNil(std.data(forKey: "ipinfo.lastLookup.v1"), "cache stays in standard")
        XCTAssertTrue(std.bool(forKey: DefaultsMigration.flagKey))

        // Once: a value written to standard later (an old code path) is not moved again.
        std.set("light", forKey: "appearance")
        XCTAssertEqual(DefaultsMigration.run(standard: std, standardDomain: stdName, group: grp, groupDomain: grpName), [])
        XCTAssertEqual(grp.string(forKey: "appearance"), "dark")
        // Same object for both (no App Group): nothing is moved or dropped.
        XCTAssertEqual(DefaultsMigration.run(standard: grp, standardDomain: grpName, group: grp, groupDomain: grpName), [])
    }

    /// 「在首页隐藏」 retired: hidden ids are unpinned (from either store's hidden list), the key is gone from both.
    @MainActor
    func testDropLegacyHiddenUnpinsHiddenIDs() throws {
        let stdName = "com.astemo6.tern.unittests.hid-std-\(UUID().uuidString)"
        let grpName = "com.astemo6.tern.unittests.hid-grp-\(UUID().uuidString)"
        let std = try XCTUnwrap(UserDefaults(suiteName: stdName))
        let grp = try XCTUnwrap(UserDefaults(suiteName: grpName))
        defer { std.removePersistentDomain(forName: stdName); grp.removePersistentDomain(forName: grpName) }
        grp.set(["speed", "memory", "task-abc", "uptime", "panel-x"], forKey: "panels.pinned")
        grp.set(["memory", "task-abc"], forKey: HomePanelStore.legacyHiddenKey)
        std.set(["panel-x", "gone"], forKey: HomePanelStore.legacyHiddenKey) // pre-move copy left in standard
        XCTAssertFalse(DefaultsMigration.movedKeys.contains(HomePanelStore.legacyHiddenKey), "not moved to the group")

        let removed = HomePanelStore.dropLegacyHidden(group: grp, standard: std)
        XCTAssertEqual(Set(removed), ["memory", "task-abc", "panel-x"])
        XCTAssertEqual(grp.stringArray(forKey: "panels.pinned"), ["speed", "uptime"], "order of the rest kept")
        XCTAssertNil(grp.object(forKey: HomePanelStore.legacyHiddenKey))
        XCTAssertNil(std.object(forKey: HomePanelStore.legacyHiddenKey))
        XCTAssertEqual(HomePanelStore.dropLegacyHidden(group: grp, standard: std), [], "second run: nothing")
        XCTAssertEqual(grp.stringArray(forKey: "panels.pinned"), ["speed", "uptime"])
    }

    func testMovedKeysCoverEveryBackedUpStandardSetting() {
        // Every key the full backup carries from the old "s:" domain that is a user setting now lives in the group.
        for k in ["panels.pinned", "appearance", "ui.launchTab", "webdav.settings", "moduleGallery.sources", "qx.resourceParserURL",
                  "usageAlerts.rules", "analytics.range", "rules.sortByHits", "policy.sort", "nodes.sort", "unlock.services"] {
            XCTAssertTrue(DefaultsMigration.movedKeys.contains(k), k)
        }
        XCTAssertEqual(Set(DefaultsMigration.movedKeys).count, DefaultsMigration.movedKeys.count, "no duplicates")
        XCTAssertFalse(DefaultsMigration.movedKeys.contains("onboardingDone.v1"))
        XCTAssertFalse(DefaultsMigration.movedKeys.contains { $0.hasPrefix("UITest") })
    }

    /// A pre-move backup tags these settings "s:"; restoring it writes them into the group (where they are read now).
    func testOldBackupPrefsRestoreIntoTheGroup() throws {
        let stdName = "com.astemo6.tern.unittests.bk-std-\(UUID().uuidString)"
        let grpName = "com.astemo6.tern.unittests.bk-grp-\(UUID().uuidString)"
        let std = try XCTUnwrap(UserDefaults(suiteName: stdName))
        let grp = try XCTUnwrap(UserDefaults(suiteName: grpName))
        defer { std.removePersistentDomain(forName: stdName); grp.removePersistentDomain(forName: grpName) }
        func enc(_ v: Any) throws -> String {
            try PropertyListSerialization.data(fromPropertyList: [v], format: .binary, options: 0).base64EncodedString()
        }
        BackupManager.applyPrefs(["s:panels.pinned": try enc(["speed"]), "s:appearance": try enc("dark"),
                                  "g:home.unlockPolicy": try enc("Netflix")], group: grp, standard: std)
        XCTAssertEqual(grp.stringArray(forKey: "panels.pinned"), ["speed"])
        XCTAssertEqual(grp.string(forKey: "appearance"), "dark")
        XCTAssertEqual(grp.string(forKey: "home.unlockPolicy"), "Netflix")
        XCTAssertNil(std.object(forKey: "panels.pinned"))
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
