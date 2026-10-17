import XCTest

/// test/selftest: shared helpers. Language / appearance come from the runner environment
/// (xcodebuild passes TEST_RUNNER_UI_LANG etc. as UI_LANG …), screenshots go to UI_SHOT_DIR on the host
/// (the simulator shares the Mac's file system) and into the .xcresult as attachments.
enum Env {
    static let env = ProcessInfo.processInfo.environment
    static var lang: String { env["UI_LANG"] ?? "zh-Hans" }
    static var style: String { env["UI_STYLE"] ?? "light" }
    static var shotDir: String? { env["UI_SHOT_DIR"].flatMap { $0.isEmpty ? nil : $0 } }
    static var isEnglish: Bool { lang.hasPrefix("en") }
    static var tag: String { "\(lang)-\(style)" }
}

/// Localized strings from the app's own String Catalog (compiled into this test bundle as well), so the same
/// test drives zh-Hans and en.
enum L10n {
    static let bundle: Bundle = {
        let b = Bundle(for: BundleToken.self)
        for name in [Env.lang, Env.lang.components(separatedBy: "-").first ?? Env.lang] {
            if let p = b.path(forResource: name, ofType: "lproj"), let lb = Bundle(path: p) { return lb }
        }
        return b
    }()

    static func s(_ key: String) -> String {
        let v = bundle.localizedString(forKey: key, value: "\u{1}", table: "Localizable")
        return v == "\u{1}" ? key : v
    }

    static func f(_ key: String, _ args: CVarArg...) -> String { String(format: s(key), arguments: args) }
}

private final class BundleToken {}

func L(_ key: String) -> String { L10n.s(key) }

extension XCUIElement {
    /// Any descendant whose label equals `label`.
    func element(label: String) -> XCUIElement {
        descendants(matching: .any).matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    func element(labelContains s: String) -> XCUIElement {
        descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", s)).firstMatch
    }

    func element(id: String) -> XCUIElement {
        descendants(matching: .any).matching(identifier: id).firstMatch
    }

    func button(_ label: String) -> XCUIElement {
        buttons.matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    func waitHittable(_ timeout: TimeInterval = 8) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if exists && isHittable { return true }
            usleep(200_000)
        }
        return exists && isHittable
    }
}

class MihomoUITestCase: XCTestCase {
    var app: XCUIApplication!
    /// Problems found on the way (missing translations, specifiers, overflow); reported together at the end
    /// so one bad string does not hide the rest of the screens.
    var issues: [String] = []
    var warnings: [String] = []
    var screens: [String] = []
    /// v0.18: screens that show user content in Chinese on purpose (示例配置 text) skip the untranslated check.
    var allowHan = false

    override func setUp() {
        continueAfterFailure = true
        issues = []
        warnings = []
    }

    override func tearDown() {
        writeReport()
        if !issues.isEmpty {
            XCTFail("\(issues.count) issue(s):\n" + issues.joined(separator: "\n"))
        }
        app?.terminate()
    }

    @discardableResult
    func launch(_ extra: [String] = []) -> XCUIApplication {
        let a = XCUIApplication()
        let locale = Env.isEnglish ? "en_US" : "zh_CN"
        a.launchArguments = ["-UITestSeed", "-AppleLanguages", "(\(Env.lang))", "-AppleLocale", locale,
                             "-appearance", Env.style] + extra
        a.launch()
        app = a
        let ready = a.element(id: "uitest.ready")
        XCTAssertTrue(ready.waitForExistence(timeout: 40), "seed did not finish")
        return a
    }

    // MARK: Checks

    func assertAlive(_ step: String, file: StaticString = #filePath, line: UInt = #line) {
        if app.state != .runningForeground {
            XCTFail("app not running after \(step) (state \(app.state.rawValue)) — crash?", file: file, line: line)
        }
    }

    static let han = try! NSRegularExpression(pattern: "[\\u4e00-\\u9fff]")
    static let specifier = try! NSRegularExpression(pattern: "%(\\d\\$)?(lld|ld|llu|lu|d|@|f|s|\\.\\d+f)")
    static let labelRE = try! NSRegularExpression(pattern: "(label|placeholderValue|title): '((?:[^'\\\\]|\\\\.)*)'")
    static let frameRE = try! NSRegularExpression(pattern: "\\{\\{(-?[0-9.]+), (-?[0-9.]+)\\}, \\{([0-9.]+), ([0-9.]+)\\}\\}")
    /// Text that is legitimately Chinese in English mode (language names, data the seed does not control).
    static let allowedHan: [String] = ["简体中文", "繁體中文", "中文"]

    /// Screenshot + audit of what is on screen now.
    func snap(_ name: String, file: StaticString = #filePath, line: UInt = #line) {
        assertAlive(name, file: file, line: line)
        usleep(600_000)
        let shot = XCUIScreen.main.screenshot()
        let att = XCTAttachment(screenshot: shot)
        att.name = "\(Env.tag)-\(name)"
        att.lifetime = .keepAlways
        add(att)
        if let dir = Env.shotDir {
            let d = URL(fileURLWithPath: dir).appendingPathComponent(Env.tag, isDirectory: true)
            try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
            try? shot.pngRepresentation.write(to: d.appendingPathComponent("\(String(format: "%02d", screens.count))-\(name).png"))
        }
        screens.append(name)
        audit(name)
    }

    func audit(_ screen: String) {
        let tree = app.debugDescription
        let width = app.windows.firstMatch.frame.width
        for raw in tree.components(separatedBy: "\n") {
            let ns = raw as NSString
            for m in Self.labelRE.matches(in: raw, range: NSRange(location: 0, length: ns.length)) {
                let text = ns.substring(with: m.range(at: 2))
                if text.isEmpty { continue }
                let tns = text as NSString
                let r = NSRange(location: 0, length: tns.length)
                if Self.specifier.firstMatch(in: text, range: r) != nil {
                    issues.append("[\(Env.tag)] \(screen): unformatted specifier in “\(text)”")
                }
                if Env.isEnglish, !allowHan, Self.han.firstMatch(in: text, range: r) != nil,
                   !Self.allowedHan.contains(where: { text.contains($0) }) {
                    let msg = "[\(Env.tag)] \(screen): untranslated “\(text)”"
                    if !issues.contains(msg) { issues.append(msg) }
                }
            }
            // Text running past the right edge of the window (layout overflow); reported as a warning.
            if raw.contains("StaticText"), width > 0,
               let m = Self.frameRE.firstMatch(in: raw, range: NSRange(location: 0, length: ns.length)) {
                let x = Double(ns.substring(with: m.range(at: 1))) ?? 0
                let w = Double(ns.substring(with: m.range(at: 3))) ?? 0
                if x >= 0, x < Double(width), x + w > Double(width) + 2 {
                    warnings.append("[\(Env.tag)] \(screen): text past the right edge (x \(Int(x)) w \(Int(w))): \(raw.trimmingCharacters(in: .whitespaces).prefix(160))")
                }
            }
        }
    }

    func writeReport() {
        guard let dir = Env.shotDir else { return }
        let d = URL(fileURLWithPath: dir).appendingPathComponent(Env.tag, isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        let name = (self.name.components(separatedBy: " ").last ?? "test").trimmingCharacters(in: CharacterSet(charactersIn: "]"))
        let body = (["# \(name) \(Env.tag)", "screens: \(screens.joined(separator: ", "))", "", "## issues"] + issues
                    + ["", "## warnings"] + warnings).joined(separator: "\n")
        try? body.write(to: d.appendingPathComponent("report-\(name).md"), atomically: true, encoding: .utf8)
    }

    // MARK: Navigation

    func tab(_ i: Int) {
        let b = app.tabBars.buttons.element(boundBy: i)
        XCTAssertTrue(b.waitForExistence(timeout: 10), "tab \(i)")
        b.tap()
        usleep(500_000)
    }

    /// Scrolls the frontmost scroll view until `e` is hittable.
    @discardableResult
    func scrollTo(_ e: XCUIElement, maxSwipes: Int = 12, file: StaticString = #filePath, line: UInt = #line) -> Bool {
        if e.exists && e.isHittable { return true }
        for _ in 0..<maxSwipes {
            app.swipeUp(velocity: .slow)
            if e.exists && e.isHittable { return true }
        }
        for _ in 0..<maxSwipes {
            app.swipeDown(velocity: .slow)
            if e.exists && e.isHittable { return true }
        }
        XCTFail("not found on screen: \(e)", file: file, line: line)
        return false
    }

    func back() {
        let b = app.navigationBars.buttons.element(boundBy: 0)
        if b.waitForExistence(timeout: 4) { b.tap() }
        usleep(400_000)
    }

    /// Dismisses a sheet with its cancel / done button (any language), or by swiping down.
    func closeSheet() {
        for k in ["取消", "完成", "关闭", "好"] {
            let b = app.navigationBars.buttons.matching(NSPredicate(format: "label == %@", L(k))).firstMatch
            if b.exists && b.isHittable { b.tap(); usleep(500_000); return }
        }
        app.swipeDown(velocity: .fast)
        usleep(500_000)
    }

    func tapIfExists(_ e: XCUIElement, timeout: TimeInterval = 4) -> Bool {
        if e.waitForExistence(timeout: timeout), e.isHittable { e.tap(); return true }
        return false
    }
}
