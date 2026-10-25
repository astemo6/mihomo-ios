import XCTest
@testable import Mihomo

final class TernBackupTests: XCTestCase {
    private var scratchDirs: [URL] = []

    override func tearDown() {
        for url in scratchDirs {
            try? FileManager.default.removeItem(at: url)
        }
        scratchDirs.removeAll()
        super.tearDown()
    }

    private func makeScratchDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("TernBackupTest-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        scratchDirs.append(url)
        return url
    }

    private func makeScratchDefaults() -> UserDefaults {
        let suite = "test.tern.backup.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return defaults
    }

    // MARK: - Test 1: build -> parse -> apply(overwrite) roundtrip

    func testRoundTripBuildParseApplyOverwrite() throws {
        let root1 = makeScratchDirectory()
        let root2 = makeScratchDirectory()
        let defaults1 = makeScratchDefaults()
        let defaults2 = makeScratchDefaults()
        let fm = FileManager.default

        // 1. Prepare files in root1
        let mainProfileText = """
        port: 7890
        # 主配置注释 🚀
        proxies:
          - name: "香港节点 🇭🇰"
            type: ss
            server: 1.2.3.4
            port: 8388
            cipher: chacha20-ietf-poly1305
            password: "secret-密码"
        """ + "\n"

        let subProfileText = """
        port: 7891
        # 备用配置 🎯
        proxies:
          - name: "日本节点 🇯🇵"
            type: ss
            server: 5.6.7.8
            port: 8388
        """ + "\n"

        let profilesJson = """
        [
          {"id": "main-profile", "name": "主配置 🚀", "kind": "local"},
          {"id": "sub-profile", "name": "备用配置 🎯", "kind": "local"}
        ]
        """ + "\n"

        let engineJson = """
        {
          "enabled": true,
          "scriptsEnabled": true,
          "mitm": true,
          "hostnames": ["*.example.com", "api.github.com"],
          "rules": [
            {"line": "DOMAIN-SUFFIX,google.com,PROXY", "enabled": true, "note": "谷歌规则 🔍"}
          ]
        }
        """ + "\n"

        let caPem = "-----BEGIN CERTIFICATE-----\nTEST_CERT_DATA\n-----END CERTIFICATE-----\n"
        let caKey = "-----BEGIN EC PRIVATE KEY-----\nTEST_KEY_DATA\n-----END EC PRIVATE KEY-----\n"
        let moduleContent = "# 广告拦截模块 🛡️\n[Rule]\nDOMAIN,ad.example.com,REJECT\n"
        let scriptContent = "// 脚本内容 📝\nconsole.log('测试');\n"
        let subsJson = "{\"subscriptions\": [\"https://example.com/sub.yaml\"]}\n"
        let overridesJson = "{\"overrides\": {\"port\": 9090}}\n"

        // Write files to root1
        try AppShared.ensureDir(root1.appendingPathComponent("profiles")).path.write("", atomically: true, encoding: .utf8)
        try profilesJson.write(to: root1.appendingPathComponent("profiles.json"), atomically: true, encoding: .utf8)
        try mainProfileText.write(to: root1.appendingPathComponent("profiles/main-profile.yaml"), atomically: true, encoding: .utf8)
        try subProfileText.write(to: root1.appendingPathComponent("profiles/sub-profile.yaml"), atomically: true, encoding: .utf8)

        let engineDir = AppShared.ensureDir(root1.appendingPathComponent("mihomo/engine", isDirectory: true))
        try engineJson.write(to: engineDir.appendingPathComponent("engine.json"), atomically: true, encoding: .utf8)

        let caDir = AppShared.ensureDir(root1.appendingPathComponent("mihomo/engine/ca", isDirectory: true))
        try caPem.write(to: caDir.appendingPathComponent("ca.pem"), atomically: true, encoding: .utf8)
        try caKey.write(to: caDir.appendingPathComponent("ca.key"), atomically: true, encoding: .utf8)

        let modDir = AppShared.ensureDir(root1.appendingPathComponent("mihomo/engine/modules", isDirectory: true))
        try moduleContent.write(to: modDir.appendingPathComponent("去广告 🎯.txt"), atomically: true, encoding: .utf8)

        let scriptDir = AppShared.ensureDir(root1.appendingPathComponent("mihomo/engine/scripts", isDirectory: true))
        try scriptContent.write(to: scriptDir.appendingPathComponent("测试脚本 ⚡.js"), atomically: true, encoding: .utf8)

        let mihomoDir = AppShared.ensureDir(root1.appendingPathComponent("mihomo", isDirectory: true))
        try subsJson.write(to: mihomoDir.appendingPathComponent("subscriptions.json"), atomically: true, encoding: .utf8)
        try overridesJson.write(to: mihomoDir.appendingPathComponent("overrides.json"), atomically: true, encoding: .utf8)

        // Setup defaults1
        defaults1.set("main-profile", forKey: "activeProfileID")
        defaults1.set(true, forKey: "onDemandSettings.enabled")
        defaults1.set("dark", forKey: "appearance")

        let customData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let customDateStr = "2026-10-25T12:00:00Z"
        let testPrefs: [String: Any] = [
            "g:onDemandSettings.enabled": true,
            "g:appearance": "dark",
            "g:panels.customData": ["$data": customData.base64EncodedString()],
            "g:home.savedDate": ["$date": customDateStr]
        ]

        // 2. Build backup
        let otherProfiles = [("sub-profile.yaml", subProfileText)]
        let backupText = try TernBackup.build(
            profileText: mainProfileText,
            profileName: "主配置 🚀",
            otherProfiles: otherProfiles,
            includeResourceCache: true,
            root: root1,
            defaults: defaults1,
            prefs: testPrefs
        )

        XCTAssertTrue(TernBackup.containsBackup(backupText))
        XCTAssertTrue(backupText.contains("[profile]"))
        XCTAssertTrue(backupText.contains("[profile sub-profile.yaml]"))
        XCTAssertTrue(backupText.contains("[json profiles.json]"))
        XCTAssertTrue(backupText.contains("[text mihomo/engine/ca/ca.key]"))
        XCTAssertTrue(backupText.contains("[prefs]"))
        XCTAssertTrue(backupText.contains("[defaults]"))
        XCTAssertTrue(backupText.contains("[end]"))

        // 3. Parse backup
        let parsed = try TernBackup.parse(backupText)
        XCTAssertEqual(parsed.format, 1)
        XCTAssertEqual(parsed.profileName, "主配置 🚀")
        XCTAssertEqual(parsed.profileText, mainProfileText)
        XCTAssertEqual(parsed.otherProfiles.count, 1)
        XCTAssertEqual(parsed.otherProfiles[0].fileName, "sub-profile.yaml")
        XCTAssertEqual(parsed.otherProfiles[0].text, subProfileText)
        XCTAssertEqual(parsed.defaults["activeProfileID"], "main-profile")
        XCTAssertNotNil(parsed.prefs)

        // 4. Apply to root2 (overwrite)
        let selection: [String: Mode] = [
            "profiles": .overwrite,
            "subscriptions": .overwrite,
            "overrides": .overwrite,
            "engine": .overwrite,
            "resources": .overwrite,
            "ca": .overwrite,
            "settings": .overwrite
        ]

        let written = try TernBackup.apply(parsed, selection: selection, root: root2, defaults: defaults2)
        XCTAssertGreaterThan(written, 0)

        // 5. Verify byte-for-byte consistency
        func assertFileEqual(_ rel: String) throws {
            let u1 = root1.appendingPathComponent(rel)
            let u2 = root2.appendingPathComponent(rel)
            XCTAssertTrue(fm.fileExists(atPath: u2.path), "目标文件应当存在：\(rel)")
            let d1 = try Data(contentsOf: u1)
            let d2 = try Data(contentsOf: u2)
            XCTAssertEqual(d1, d2, "文件内容字节不一致：\(rel)")
        }

        try assertFileEqual("profiles.json")
        try assertFileEqual("profiles/main-profile.yaml")
        try assertFileEqual("profiles/sub-profile.yaml")
        try assertFileEqual("mihomo/engine/engine.json")
        try assertFileEqual("mihomo/engine/ca/ca.pem")
        try assertFileEqual("mihomo/engine/ca/ca.key")
        try assertFileEqual("mihomo/engine/modules/去广告 🎯.txt")
        try assertFileEqual("mihomo/engine/scripts/测试脚本 ⚡.js")
        try assertFileEqual("mihomo/subscriptions.json")
        try assertFileEqual("mihomo/overrides.json")

        // 6. Verify prefs readback in defaults2
        XCTAssertEqual(defaults2.string(forKey: "activeProfileID"), "main-profile")
        XCTAssertEqual(defaults2.bool(forKey: "onDemandSettings.enabled"), true)
        XCTAssertEqual(defaults2.string(forKey: "appearance"), "dark")
        XCTAssertEqual(defaults2.data(forKey: "panels.customData"), customData)
        if let restoredDate = defaults2.object(forKey: "home.savedDate") as? Date {
            let iso = ISO8601DateFormatter()
            iso.formatOptions = [.withInternetDateTime]
            XCTAssertEqual(iso.string(from: restoredDate), customDateStr)
        } else {
            XCTFail("home.savedDate 未能成功反序列化为 Date")
        }
    }

    // MARK: - Test 2: Damaged [json] section throws corrupt and writes nothing

    func testDamagedJSONSectionThrowsCorruptAndWritesNothing() throws {
        let root = makeScratchDirectory()
        let defaults = makeScratchDefaults()
        let fm = FileManager.default

        let validBackup = """
        ; Tern 完整备份
        #!name = Tern 完整备份
        #!created = 2026-10-25T12:00:00Z

        [general]
        tern_backup = 1
        format = 1
        created = 2026-10-25T12:00:00Z
        app_version = 1.0.0

        [json mihomo/engine/engine.json]
        { invalid json here :::: }

        [end]
        """

        XCTAssertThrowsError(try TernBackup.parse(validBackup)) { error in
            guard let backupError = error as? TernBackupError else {
                XCTFail("抛出的错误类型不是 TernBackupError")
                return
            }
            if case .corrupt(let msg) = backupError {
                XCTAssertTrue(msg.contains("JSON 解析失败"))
            } else {
                XCTFail("预期 corrupt 错误，实际为：\(backupError)")
            }
        }

        // Verify root directory is completely untouched
        let contents = try fm.contentsOfDirectory(atPath: root.path)
        XCTAssertTrue(contents.isEmpty, "损坏的备份解析失败时，目标 root 不得写入任何文件")
    }

    // MARK: - Test 3: Missing [end] -> corrupt; format=2 -> unsupportedVersion

    func testMissingEndAndUnsupportedVersion() throws {
        let baseBackup = """
        ; Tern 完整备份
        #!name = Tern 完整备份
        #!created = 2026-10-25T12:00:00Z

        [general]
        tern_backup = 1
        format = 1
        created = 2026-10-25T12:00:00Z
        app_version = 1.0.0
        profile = 主配置

        [profile]
        port: 7890

        [end]
        """

        // 3a. Missing [end]
        let withoutEnd = baseBackup.replacingOccurrences(of: "[end]", with: "")
        XCTAssertThrowsError(try TernBackup.parse(withoutEnd)) { error in
            if case TernBackupError.corrupt(let msg)? = error as? TernBackupError {
                XCTAssertTrue(msg.contains("缺少 [end]"))
            } else {
                XCTFail("预期缺少 [end] 报错，实际：\(error)")
            }
        }

        // 3b. Format = 2
        let format2 = baseBackup.replacingOccurrences(of: "format = 1", with: "format = 2")
        XCTAssertThrowsError(try TernBackup.parse(format2)) { error in
            if case TernBackupError.unsupportedVersion(let v)? = error as? TernBackupError {
                XCTAssertEqual(v, 2)
            } else {
                XCTFail("预期 unsupportedVersion(2)，实际：\(error)")
            }
        }

        // 3c. Declared profile but missing [profile] section
        let missingProfileSec = baseBackup.replacingOccurrences(of: "[profile]\nport: 7890\n\n", with: "")
        XCTAssertThrowsError(try TernBackup.parse(missingProfileSec)) { error in
            if case TernBackupError.corrupt(let msg)? = error as? TernBackupError {
                XCTAssertTrue(msg.contains("声明了活动配置但缺少 [profile] 节"))
            } else {
                XCTFail("预期缺少 [profile] 节报错，实际：\(error)")
            }
        }
    }

    // MARK: - Test 4: merge retains extra files and overwrite deletes them

    func testMergeRetainsExtraFilesAndOverwriteDeletesThem() throws {
        let root = makeScratchDirectory()
        let defaults = makeScratchDefaults()
        let fm = FileManager.default

        // Pre-create extra file in resources
        let extraURL = root.appendingPathComponent("mihomo/engine/modules/existing_extra.txt")
        AppShared.ensureDir(extraURL.deletingLastPathComponent())
        try "extra content".write(to: extraURL, atomically: true, encoding: .utf8)
        XCTAssertTrue(fm.fileExists(atPath: extraURL.path))

        // Create backup containing only one module
        let backupText = """
        ; Tern 完整备份
        [general]
        tern_backup = 1
        format = 1
        created = 2026-10-25T12:00:00Z
        app_version = 1.0.0

        [text mihomo/engine/modules/package_module.txt]
        package content

        [end]
        """

        let parsed = try TernBackup.parse(backupText)

        // 4a. Apply with merge: existing extra file must be retained
        try TernBackup.apply(parsed, selection: ["resources": .merge], root: root, defaults: defaults)
        XCTAssertTrue(fm.fileExists(atPath: extraURL.path), "merge 模式必须保留目标已有的额外文件")
        let packageModuleURL = root.appendingPathComponent("mihomo/engine/modules/package_module.txt")
        XCTAssertTrue(fm.fileExists(atPath: packageModuleURL.path), "包内文件必须写入")

        // 4b. Apply with overwrite: existing extra file must be removed
        try TernBackup.apply(parsed, selection: ["resources": .overwrite], root: root, defaults: defaults)
        XCTAssertFalse(fm.fileExists(atPath: extraURL.path), "overwrite 模式必须删除目标未包含的额外文件")
        XCTAssertTrue(fm.fileExists(atPath: packageModuleURL.path), "包内文件仍然存在")
    }

    // MARK: - Test 5: Plain config rejection and verbatim profile text

    func testPlainConfigRejectionAndVerbatimProfileText() throws {
        let plainYAML = """
        port: 7890
        socks-port: 7891
        allow-lan: false
        mode: rule
        log-level: info
        proxies:
          - name: "ss1"
            type: ss
            server: 1.1.1.1
            port: 80
            cipher: chacha20-ietf-poly1305
            password: "pwd"
        """

        XCTAssertFalse(TernBackup.containsBackup(plainYAML))
        XCTAssertThrowsError(try TernBackup.parse(plainYAML)) { error in
            XCTAssertEqual(error as? TernBackupError, TernBackupError.notABackup)
        }

        // Test complex YAML verbatim preservation in [profile] section
        let complexYAML = """
        # Line 1 with comments & symbols: %$#@!
        port: 7890
        rules:
          - DOMAIN-SUFFIX,example.com,DIRECT
          - GEOIP,CN,DIRECT

        # Blank lines and indentation
          custom-key: "value with \n newline and emoji 🌟"
        """ + "\n"

        let backupWithComplexProfile = """
        ; Tern 完整备份
        [general]
        tern_backup = 1
        format = 1
        created = 2026-10-25T12:00:00Z
        app_version = 1.0.0
        profile = 测试复杂配置

        [profile]
        \(complexYAML)
        [end]
        """

        let parsed = try TernBackup.parse(backupWithComplexProfile)
        XCTAssertEqual(parsed.profileText, complexYAML, "[profile] 节内容与原配置逐字节完全一致")

        // 断言：内容不以 "\n" 结尾的文本节往返后等于原文 + "\n"（已声明的结尾换行规范化）
        let yamlWithoutTrailingNewline = "port: 7890\nname: test-no-newline"
        let backupWithoutTrailingNewline = """
        ; Tern 完整备份
        [general]
        tern_backup = 1
        format = 1
        created = 2026-10-25T12:00:00Z
        app_version = 1.0.0
        profile = 无换行配置

        [profile]
        \(yamlWithoutTrailingNewline)

        [end]
        """
        let parsedWithoutTrailingNewline = try TernBackup.parse(backupWithoutTrailingNewline)
        XCTAssertEqual(
            parsedWithoutTrailingNewline.profileText,
            yamlWithoutTrailingNewline + "\n",
            "内容不以 \\n 结尾的文本节往返后等于原文 + \\n（规范化保真）"
        )
    }

    // MARK: - Test 6: ca.key roundtrip and 0600 POSIX permissions

    func testCAKeyRoundTripAndFilePermissions() throws {
        let root1 = makeScratchDirectory()
        let root2 = makeScratchDirectory()
        let defaults1 = makeScratchDefaults()
        let defaults2 = makeScratchDefaults()
        let fm = FileManager.default

        let caKeyContent = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIBA/3q7vX0T2+testKeyBytesForUnitTestingTernBackup12345678
        AoGCCqGSM49AwEHoUQDQgAE8Z7x...fakeKeyContentForTest==
        -----END EC PRIVATE KEY-----
        """ + "\n"

        let caKeyURL1 = root1.appendingPathComponent("mihomo/engine/ca/ca.key")
        AppShared.ensureDir(caKeyURL1.deletingLastPathComponent())
        try caKeyContent.write(to: caKeyURL1, atomically: true, encoding: .utf8)

        let backupText = try TernBackup.build(
            profileText: nil,
            profileName: nil,
            otherProfiles: [],
            includeResourceCache: false,
            root: root1,
            defaults: defaults1
        )

        let parsed = try TernBackup.parse(backupText)
        XCTAssertNotNil(parsed.files["mihomo/engine/ca/ca.key"])

        try TernBackup.apply(parsed, selection: ["ca": .overwrite], root: root2, defaults: defaults2)

        let caKeyURL2 = root2.appendingPathComponent("mihomo/engine/ca/ca.key")
        XCTAssertTrue(fm.fileExists(atPath: caKeyURL2.path))

        let d1 = try Data(contentsOf: caKeyURL1)
        let d2 = try Data(contentsOf: caKeyURL2)
        XCTAssertEqual(d1, d2, "ca.key 字节内容必须往返完全一致")

        let attrs = try fm.attributesOfItem(atPath: caKeyURL2.path)
        let perms = attrs[.posixPermissions] as? NSNumber
        XCTAssertEqual(perms?.intValue, 0o600, "ca.key 写入后的 POSIX 文件权限必须为 0600")
    }

    // MARK: - Test 7: Normalization of text files without trailing newline

    func testTextWithoutTrailingNewlineNormalizedWithNewline() throws {
        let root1 = makeScratchDirectory()
        let root2 = makeScratchDirectory()
        let defaults1 = makeScratchDefaults()
        let defaults2 = makeScratchDefaults()

        // 文本文件原文末尾不带 \n
        let rawContentNoNewline = "# 规则列表无换行\nDOMAIN,raw.example.com,DIRECT"
        let fileRel = "mihomo/engine/modules/raw-rule.txt"
        let fileURL1 = root1.appendingPathComponent(fileRel)
        AppShared.ensureDir(fileURL1.deletingLastPathComponent())
        try rawContentNoNewline.write(to: fileURL1, atomically: true, encoding: .utf8)

        let backupText = try TernBackup.build(
            profileText: nil,
            profileName: nil,
            otherProfiles: [],
            includeResourceCache: true,
            root: root1,
            defaults: defaults1
        )

        let parsed = try TernBackup.parse(backupText)
        guard let data = parsed.files[fileRel], let parsedStr = String(data: data, encoding: .utf8) else {
            XCTFail("未能在 parsed.files 中找到 \(fileRel)")
            return
        }
        XCTAssertEqual(parsedStr, rawContentNoNewline + "\n", "parse 解析后应规范化补齐单个结尾换行")

        try TernBackup.apply(parsed, selection: ["resources": .overwrite], root: root2, defaults: defaults2)

        let fileURL2 = root2.appendingPathComponent(fileRel)
        let restoredData = try Data(contentsOf: fileURL2)
        let restoredStr = String(data: restoredData, encoding: .utf8)
        XCTAssertEqual(restoredStr, rawContentNoNewline + "\n", "内容不以 \\n 结尾的文本文件往返后等于原文 + \\n")
    }
}
