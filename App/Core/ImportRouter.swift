import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Libmihomo

/// One entry point for everything that arrives from outside: our own mihomo:// links, pasted links of
/// other clients (loon:// stash:// surge:/// quantumult-x:/// — recognised, never registered as URL
/// schemes), and opened documents (.yaml .sgmodule .plugin .stoverride .conf .list).
/// Everything ends up in the one internal model: a mihomo profile, or a module in the module store.
enum ImportAction: Identifiable, Equatable {
    case profileURL(url: String, name: String)
    case profileText(name: String, text: String)
    case moduleURL(url: String, source: String)
    case moduleText(name: String, text: String, source: String)
    case confText(name: String, text: String)
    case nodesText(text: String)
    case connect, disconnect, toggle
    case unsupported(String)

    var id: String {
        switch self {
        case .profileURL(let u, _): return "p:" + u
        case .profileText(let n, _): return "pt:" + n
        case .moduleURL(let u, _): return "m:" + u
        case .moduleText(let n, _, _): return "mt:" + n
        case .confText(let n, _): return "c:" + n
        case .nodesText(let t): return "n:" + String(t.prefix(64))
        case .connect: return "connect"
        case .disconnect: return "disconnect"
        case .toggle: return "toggle"
        case .unsupported(let s): return "u:" + s
        }
    }

    /// Review 5 P1-2: what the startup log may say about an import — kind and size only, never the URL
    /// (subscription path tokens) or pasted text (ss:// / Loon / Surge lines carry the password).
    var logSummary: String {
        func host(_ u: String) -> String { URL(string: u)?.host.map { " host=\($0)" } ?? "" }
        switch self {
        case .profileURL(let u, _): return "profileURL bytes=\(u.utf8.count)" + host(u)
        case .profileText(_, let t): return "profileText bytes=\(t.utf8.count)"
        case .moduleURL(let u, _): return "moduleURL bytes=\(u.utf8.count)" + host(u)
        case .moduleText(_, let t, _): return "moduleText bytes=\(t.utf8.count)"
        case .confText(_, let t): return "confText bytes=\(t.utf8.count)"
        case .nodesText(let t): return "nodesText bytes=\(t.utf8.count)"
        case .connect: return "connect"
        case .disconnect: return "disconnect"
        case .toggle: return "toggle"
        case .unsupported(let s): return "unsupported bytes=\(s.utf8.count)"
        }
    }
}

@MainActor
final class ImportRouter: ObservableObject {
    static let shared = ImportRouter()

    /// Setting an action presents the import sheet (v0.8.1: through `present`, never a SwiftUI .sheet that
    /// another presentation could swallow). Kept as a property so call sites stay one line.
    var pending: ImportAction? {
        get { nil }
        set { if let a = newValue { present(a) } }
    }
    /// Tab to show after routing (0 首页 … 4 更多).
    /// feat/surge-ui: starts on the 开始标签页 chosen in 更多 → 开始标签页 (UI tests always start on 首页).
    @Published var selectedTab = LaunchTab.initial
    /// URLs from the scene's launch options (cold launch); drained once the UI exists if onOpenURL did not.
    var coldLaunchURLs: [URL] = []
    private var recentURLs: [(String, Date)] = []
    private weak var presented: UIViewController?
    /// v0.13.1: an import is running in the sheet; a new presentation waits instead of replacing it.
    var importing = false
    private var pickerDelegate: PickerDelegate?

    /// Everything is selectable (v0.13.1): other apps export their own UTIs for .conf / .snippet that do not
    /// conform to public.data or public.plain-text, which greyed QX configs out. Content decides afterwards.
    nonisolated static var pickerTypes: [UTType] {
        var t: [UTType] = [.item, .data, .content, .text, .plainText, .utf8PlainText, .yaml, .json, .javaScript]
        for ext in ["conf", "txt", "list", "snippet", "plugin", "lpx", "sgmodule", "module", "stoverride", "yaml", "yml", "js"] {
            if let u = UTType(filenameExtension: ext), !t.contains(u) { t.append(u) }
        }
        return t
    }

    /// 从文件导入 (v0.13.1): a UIKit document picker in copy mode from the topmost controller, replacing
    /// SwiftUI's fileImporter (which could greys out files and lose the selection with several presenters).
    func pickFile() {
        guard let top = Self.topViewController() else { return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: Self.pickerTypes, asCopy: true)
        picker.allowsMultipleSelection = false
        picker.shouldShowFileExtensions = true
        let d = PickerDelegate { [weak self] urls in
            guard let self else { return }
            self.pickerDelegate = nil
            guard let url = urls.first else { return }
            StartupLog.write("import: picked \(url.lastPathComponent)", tag: "app")
            let a = ImportRouter.action(forFile: url)
            try? FileManager.default.removeItem(at: url) // our own copy (asCopy)
            self.present(a)
        } onCancel: { [weak self] in self?.pickerDelegate = nil }
        pickerDelegate = d
        picker.delegate = d
        top.present(picker, animated: true)
    }

    @MainActor final class PickerDelegate: NSObject, UIDocumentPickerDelegate {
        let onPick: @MainActor ([URL]) -> Void
        let onCancel: @MainActor () -> Void
        init(onPick: @escaping @MainActor ([URL]) -> Void, onCancel: @escaping @MainActor () -> Void) { self.onPick = onPick; self.onCancel = onCancel }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { onPick(urls) }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { onCancel() }
    }

    /// Same document within 10 s = handled once, even when onOpenURL and the cold-launch fallback give it
    /// different paths (/private/var vs /var, Inbox copy vs original).
    nonisolated static func fingerprint(_ url: URL) -> String {
        guard url.isFileURL else { return url.absoluteString }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? -1
        return "file:\(url.lastPathComponent):\(size)"
    }

    // MARK: Parsing

    nonisolated static func query(_ comps: URLComponents?, _ names: [String]) -> String? {
        for n in names {
            if let v = comps?.queryItems?.first(where: { $0.name.lowercased() == n })?.value, !v.isEmpty { return v }
        }
        return nil
    }

    /// Recognises a link or a pasted string. Returns nil when it is not an import link at all.
    nonisolated static func parse(_ raw: String) -> ImportAction? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let scheme = s.split(separator: ":", maxSplits: 1).first?.lowercased() else { return nil }
        let comps = URLComponents(string: s)
        let path = (comps?.host ?? "") + (comps?.path ?? "")
        let action = path.trimmingCharacters(in: CharacterSet(charactersIn: "/")).lowercased()

        switch scheme {
        case "mihomo", "clash", "clash-meta":
            switch action {
            case "connect", "start": return .connect
            case "disconnect", "stop": return .disconnect
            case "toggle": return .toggle
            case "install-config", "install-profile", "import-profile", "subscribe":
                if let u = query(comps, ["url"]) { return .profileURL(url: u, name: query(comps, ["name"]) ?? "") }
            case "install-module", "install-plugin", "install-override", "import-module":
                if let u = query(comps, ["url"]) { return .moduleURL(url: u, source: "mihomo") }
            default: break
            }
            return .unsupported(s)
        case "loon":
            // loon://import?plugin=<url>  loon://import?sub=<url>  loon://import?nodelist=<url>
            if let u = query(comps, ["plugin"]) { return .moduleURL(url: u, source: "Loon") }
            if let u = query(comps, ["sub", "nodelist"]) { return .profileURL(url: u, name: "") }
            return .unsupported(s)
        case "stash":
            // stash://install-override?url=<url>  stash://install-config?url=<url>
            if action.contains("override"), let u = query(comps, ["url"]) { return .moduleURL(url: u, source: "Stash") }
            if action.contains("config"), let u = query(comps, ["url"]) { return .profileURL(url: u, name: query(comps, ["name"]) ?? "") }
            return .unsupported(s)
        case "surge":
            // surge:///install-module?url=<url>  surge:///install-config?url=<url>
            if action.contains("module"), let u = query(comps, ["url"]) { return .moduleURL(url: u, source: "Surge") }
            if action.contains("config"), let u = query(comps, ["url"]) { return .profileURL(url: u, name: "") }
            return .unsupported(s)
        case "egern":
            // egern:/modules/new?url=<url>  egern:/profiles/new?url=<url>  egern:/subscriptions/new?url=<url>
            if action.hasPrefix("modules"), let u = query(comps, ["url"]) { return .moduleURL(url: u, source: "Egern") }
            if action.hasPrefix("profiles") || action.hasPrefix("subscriptions"), let u = query(comps, ["url"]) { return .profileURL(url: u, name: query(comps, ["name"]) ?? "") }
            if action == "start" { return .connect }
            if action == "stop" { return .disconnect }
            return .unsupported(s)
        case "quantumult-x":
            // quantumult-x:///add-resource?remote-resource=<url-encoded JSON {"rewrite_remote": ["url, tag=…"], …}>
            if let json = query(comps, ["remote-resource"]), let d = json.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                if let first = (obj["rewrite_remote"] as? [String])?.first, let u = firstURL(first) {
                    return .moduleURL(url: u, source: "Quantumult X")
                }
                if let first = (obj["server_remote"] as? [String])?.first, let u = firstURL(first) {
                    return .profileURL(url: u, name: "")
                }
                if obj["filter_remote"] != nil {
                    return .unsupported("Quantumult X 远程分流请在 更多 → 分流规则 → 自定义 中添加（filter_remote 行）")
                }
            }
            return .unsupported(s)
        default:
            return nil
        }
    }

    nonisolated static func firstURL(_ qxLine: String) -> String? {
        let u = qxLine.split(separator: ",").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        return u.hasPrefix("http") ? u : nil
    }

    /// Reads an opened / picked file synchronously inside its security scope (coordinated, so iCloud files
    /// are downloaded first) and decodes it: UTF-8 (BOM stripped), UTF-16 with BOM, GB18030, then Latin-1.
    /// Returns the text or a Chinese reason, plus byte count and UTI for the log.
    nonisolated static func readText(at url: URL) -> (text: String?, bytes: Int, uti: String, error: String?) {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        let values = try? url.resourceValues(forKeys: [.contentTypeKey, .isDirectoryKey, .fileSizeKey, .totalFileSizeKey])
        let uti = values?.contentType?.identifier ?? "?"
        if values?.isDirectory == true {
            return (nil, 0, uti, String(localized: "「\(url.lastPathComponent)」是文件夹，请选择其中的配置文件"))
        }
        // Review 5 P2-8: refuse big files before copying or reading them (a video opened "in Mihomo" used to be
        // copied to tmp and loaded whole before the 16 MB check).
        let limit = 16 << 20
        let tooBig = String(localized: "文件太大（超过 16 MB），不是配置或模块")
        if let n = values?.totalFileSize ?? values?.fileSize, n > limit { return (nil, n, uti, tooBig) }
        var data: Data?
        var readErr: Error?
        var coordErr: NSError?
        var bigSize: Int?
        // v0.13.1: copy into our temp dir inside the scope / coordination, then read the copy (provider files
        // and Inbox copies can disappear or lose access right after the open call).
        NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: [.withoutChanges], error: &coordErr) { u in
            // The coordinated URL is the downloaded copy for iCloud placeholders: check its real size too.
            if let n = (try? FileManager.default.attributesOfItem(atPath: u.path)[.size] as? NSNumber)?.intValue, n > limit {
                bigSize = n
                return
            }
            let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("import-\(UUID().uuidString)-\(u.lastPathComponent)")
            defer { try? FileManager.default.removeItem(at: tmp) }
            do {
                try FileManager.default.copyItem(at: u, to: tmp)
                data = try Data(contentsOf: tmp)
            } catch {
                do { data = try Data(contentsOf: u) } catch let e { readErr = e }
            }
        }
        if let n = bigSize { return (nil, n, uti, tooBig) }
        if data == nil, coordErr != nil {
            // Some providers refuse coordination; a plain read still works for them.
            data = try? Data(contentsOf: url)
        }
        guard let data else {
            let why = (readErr ?? coordErr).map { $0.localizedDescription } ?? String(localized: "未知错误")
            return (nil, 0, uti, String(localized: "无法读取文件「\(url.lastPathComponent)」：\(why)"))
        }
        if data.isEmpty { return (nil, 0, uti, String(localized: "文件「\(url.lastPathComponent)」是空的")) }
        if data.count > limit { return (nil, data.count, uti, tooBig) }
        if let t = decodeText(data) { return (t, data.count, uti, nil) }
        return (nil, data.count, uti, String(localized: "「\(url.lastPathComponent)」不是文本文件，无法导入"))
    }

    nonisolated static func decodeText(_ data: Data) -> String? {
        let b = [UInt8](data.prefix(4))
        if b.count >= 3, b[0] == 0xEF, b[1] == 0xBB, b[2] == 0xBF {
            return String(data: data.dropFirst(3), encoding: .utf8)
        }
        if b.count >= 2, (b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF) {
            return String(data: data, encoding: .utf16)
        }
        if let s = String(data: data, encoding: .utf8) { return s.contains("\u{0}") ? nil : s }
        let gb = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue)))
        if let s = String(data: data, encoding: gb), !s.contains("\u{0}") { return s }
        // Binary data has NUL bytes; Latin-1 decodes anything, so only accept it without them.
        if !data.contains(0), let s = String(data: data, encoding: .isoLatin1) { return s }
        return nil
    }

    /// Decides what an opened document is: by extension for the unambiguous ones, otherwise by content
    /// (QX / Surge configs, modules and rewrite snippets all use .conf / .txt / .snippet or no extension).
    nonisolated static func action(forFile url: URL) -> ImportAction {
        let r = readText(at: url)
        let ext = url.pathExtension.lowercased()
        StartupLog.write("open file: ext=\(ext.isEmpty ? "-" : ext) uti=\(r.uti) bytes=\(r.bytes)\(r.error.map { " error=" + $0 } ?? "")", tag: "app")
        guard let text = r.text else { return .unsupported(r.error ?? String(localized: "无法读取文件")) }
        let name = url.deletingPathExtension().lastPathComponent
        switch ext {
        case "sgmodule": return .moduleText(name: name, text: text, source: "Surge")
        case "plugin", "lpx": return .moduleText(name: name, text: text, source: "Loon")
        case "stoverride": return .moduleText(name: name, text: text, source: "Stash")
        case "list": return .moduleText(name: name, text: text, source: "列表")
        case "module": return .moduleText(name: name, text: text, source: "Surge")
        case "yaml", "yml":
            // Egern modules and Stash overrides are YAML too.
            let c = LibmihomoClassifyText(text)
            if c.hasPrefix("module:") { return .moduleText(name: name, text: text, source: sourceName(c)) }
            return .profileText(name: name, text: text)
        case "conf":
            // A full Surge / QX config, or a QX rewrite snippet saved as .conf.
            let c = LibmihomoClassifyText(text)
            if c.hasPrefix("module:") { return .moduleText(name: name, text: text, source: sourceName(c)) }
            if c == "profile" { return .profileText(name: name, text: text) }
            return .confText(name: name, text: text)
        default:
            if let a = route(text: text, name: name) { return a }
            if ext == "snippet" { return .moduleText(name: name, text: text, source: "Quantumult X") }
            return .unsupported(String(localized: "无法识别「\(url.lastPathComponent)」的内容：支持 mihomo 配置、Surge / QX 配置、模块、规则列表和节点链接"))
        }
    }

    nonisolated static func sourceName(_ classification: String) -> String {
        switch classification.replacingOccurrences(of: "module:", with: "") {
        case "egern": return "Egern"
        case "stash": return "Stash"
        case "loon": return "Loon"
        case "qx": return "Quantumult X"
        default: return "Surge"
        }
    }

    nonisolated static let moduleExtensions = ["sgmodule", "plugin", "lpx", "stoverride", "snippet", "module"]

    /// Routes pasted or shared text into the one internal model: an import link, a profile / module URL,
    /// a profile, a Surge / QX config, a module, or nodes. nil = nothing recognisable.
    nonisolated static func route(text raw: String, name: String = "") -> ImportAction? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        if !text.contains("\n"), let a = parse(text) { return a }
        if !text.contains("\n"), !text.contains(" "), text.hasPrefix("http://") || text.hasPrefix("https://"), let u = URL(string: text) {
            let ext = u.pathExtension.lowercased()
            if moduleExtensions.contains(ext) { return .moduleURL(url: text, source: "URL") }
            if ext == "js" { return .unsupported("这是一个脚本链接：请在 更多 → 模块 → 脚本 中添加脚本规则，或导入引用它的模块") }
            if ext == "list" { return .unsupported("这是一个规则列表：请在 更多 → 模块 → + → 添加远程规则集 中添加") }
            return .profileURL(url: text, name: name)
        }
        let c = LibmihomoClassifyText(text)
        switch c {
        case "profile": return .profileText(name: name.isEmpty ? String(localized: "剪贴板配置") : name, text: text)
        case "conf": return .confText(name: name.isEmpty ? String(localized: "导入的配置") : name, text: text)
        case "nodes": return .nodesText(text: text)
        default:
            if c.hasPrefix("module:") { return .moduleText(name: name.isEmpty ? String(localized: "本地模块") : name, text: text, source: sourceName(c)) }
            return nil
        }
    }

    // MARK: Routing

    /// Text from the paste banner (PasteButton, so iOS shows no paste prompt).
    func handle(pasted text: String) {
        if let a = Self.route(text: text) { run(a) } else { present(.unsupported(String(localized: "剪贴板内容无法识别：支持订阅 / 模块链接、配置、模块内容、节点链接"))) }
    }

    /// Every URL / document opened in the app ends in a visible sheet (an import or the reason it cannot be
    /// imported). The same URL within 10 s is handled once (onOpenURL and the cold-launch fallback).
    func handle(url: URL) {
        let fp = Self.fingerprint(url)
        recentURLs.removeAll { Date().timeIntervalSince($0.1) > 10 }
        if recentURLs.contains(where: { $0.0 == fp }) {
            StartupLog.write("open: duplicate \(url.lastPathComponent) ignored", tag: "app")
            return
        }
        recentURLs.append((fp, Date()))
        coldLaunchURLs.removeAll { $0 == url || Self.fingerprint($0) == fp }
        if url.isFileURL {
            // Read synchronously now: the security scope of an opened document does not survive an async hop.
            let a = Self.action(forFile: url)
            // Copies iOS put in Documents/Inbox are ours to delete once read.
            if url.pathComponents.contains("Inbox") { try? FileManager.default.removeItem(at: url) }
            present(a)
        } else {
            StartupLog.write("open url: scheme=\(url.scheme ?? "-") bytes=\(url.absoluteString.utf8.count)", tag: "app")
            if let a = Self.parse(url.absoluteString) {
                run(a)
            } else if let a = Self.route(text: url.absoluteString) {
                run(a) // v0.13.1: a shared http(s) link (profile / module URL)
            } else {
                present(.unsupported(String(localized: "无法识别的链接：\(url.scheme ?? "")://…")))
            }
        }
    }

    /// Cold launch: URLs iOS handed to the scene before SwiftUI's onOpenURL could see them.
    func drainColdLaunchURLs() {
        let urls = coldLaunchURLs
        coldLaunchURLs = []
        for u in urls { handle(url: u) }
    }

    // MARK: Presenting

    /// Presents ImportSheet from the topmost view controller, waiting until no presentation is appearing or
    /// dismissing (a file picker that just closed, a sheet sliding away) and until a window exists (cold
    /// launch). An import sheet that is already up is replaced.
    func present(_ a: ImportAction, attempt: Int = 0) {
        guard let top = Self.topViewController() else {
            if attempt < 50 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { self.present(a, attempt: attempt + 1) }
            } else {
                StartupLog.write("import sheet: no window to present from", tag: "app")
            }
            return
        }
        if top.isBeingDismissed || top.isBeingPresented || top.presentingViewController?.isBeingDismissed == true
            || top is UIDocumentPickerViewController || top.transitionCoordinator != nil {
            if attempt < 50 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { self.present(a, attempt: attempt + 1) }
                return
            }
        }
        if importing, presented?.presentingViewController != nil {
            // v0.13.1: never pull the sheet away from a running import (that looked like 导入 doing nothing).
            if attempt < 200 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.present(a, attempt: attempt + 1) }
            }
            return
        }
        if let old = presented, old.presentingViewController != nil {
            old.dismiss(animated: false) { self.present(a, attempt: attempt + 1) }
            presented = nil
            return
        }
        weak var host: UIViewController?
        let sheet = ImportSheet(action: a, onClose: { host?.dismiss(animated: true) })
            .environmentObject(ProfileStore.shared)
            .environmentObject(VPNManager.shared)
            .tint(Theme.accent)
        let vc = UIHostingController(rootView: AnyView(sheet))
        host = vc
        vc.overrideUserInterfaceStyle = AppAppearance.current.style
        vc.modalPresentationStyle = .pageSheet
        presented = vc
        top.present(vc, animated: true)
        // UIKit refuses a presentation silently when another one starts in the same run loop; check that the
        // sheet is really up and try again (bounded by `attempt`) instead of losing the import.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            guard self.presented === vc, vc.presentingViewController == nil, vc.view.window == nil else { return }
            self.presented = nil
            if attempt < 50 {
                StartupLog.write("import sheet: presentation refused, retrying", tag: "app")
                self.present(a, attempt: attempt + 5)
            }
        }
    }

    static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let windows = scenes.sorted { ($0.activationState == .foregroundActive ? 0 : 1) < ($1.activationState == .foregroundActive ? 0 : 1) }
            .flatMap { $0.windows }
        guard let root = (windows.first { $0.isKeyWindow } ?? windows.first)?.rootViewController else { return nil }
        var top = root
        while let p = top.presentedViewController, !p.isBeingDismissed { top = p }
        return top
    }

    /// Simple actions run immediately; imports wait for the user's confirmation in ImportSheet.
    func run(_ a: ImportAction) {
        switch a {
        case .connect: Task { _ = await VPNManager.shared.connectAndWait() }
        case .disconnect: Task { await VPNManager.shared.disconnectAndWait() }
        case .toggle: Task { await VPNManager.shared.toggle() }
        default: pending = a
        }
    }
}

/// Confirmation sheet for every import kind.
struct ImportSheet: View {
    let action: ImportAction
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var store: ProfileStore
    @ObservedObject var engine = EngineStore.shared
    @State private var name = ""
    @State private var busy = false
    @State private var result: String?
    @State private var failed = false
    @State private var conf: ConfImportResult?
    /// v0.13.1: what the import is doing right now, and an alert for every failure (never silent).
    @State private var stage: String?
    @State private var errorAlert: String?

    /// Set when presented through UIKit (ImportRouter.present); SwiftUI's dismiss is the fallback.
    var onClose: (() -> Void)? = nil

    init(action: ImportAction, onClose: (() -> Void)? = nil) {
        self.action = action
        self.onClose = onClose
    }

    func close() { if let onClose { onClose() } else { dismiss() } }

    var body: some View {
        NavigationStack {
            Form {
                switch action {
                case .profileURL(let url, _):
                    header("订阅配置", "doc.badge.arrow.up", url)
                    TextField("名称（留空自动获取）", text: $name).listRowBackground(Theme.card)
                case .profileText(_, let text):
                    header("本地配置", "doc.text", String(localized: "\(text.count) 字符"))
                    TextField("名称", text: $name).listRowBackground(Theme.card)
                case .moduleURL(let url, let source):
                    header(String(localized: "\(source) 模块"), "puzzlepiece.extension", url)
                case .moduleText(_, let text, let source):
                    header(String(localized: "\(source) 模块"), "puzzlepiece.extension", String(localized: "\(text.split(separator: "\n").count) 行"))
                    TextField("名称", text: $name).listRowBackground(Theme.card)
                case .nodesText(let text):
                    header("节点", "server.rack", String(localized: "\(text.split(separator: "\n").count) 行 → 手动节点"))
                case .confText(_, let text):
                    ConfReportSection(text: text, result: $conf)
                    TextField("配置名称", text: $name).listRowBackground(Theme.card)
                case .unsupported(let s):
                    Section {
                        Label("无法导入", systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.warn)
                        Text(s).font(.footnote).textSelection(.enabled)
                    }
                    .listRowBackground(Theme.card)
                default:
                    EmptyView()
                }
                if result != nil, !failed, needsMitM {
                    Section {
                        NavigationLink { MitMView() } label: {
                            Label("开启 MitM 并安装证书", systemImage: "lock.shield")
                        }
                    } footer: {
                        Text("导入的重写和脚本需要解密这些主机的 HTTPS 才能生效。MitM 当前未开启或证书未信任。")
                    }
                    .listRowBackground(Theme.card)
                }
                if busy, let stage {
                    Section { LoadingRow(text: stage) }.listRowBackground(Theme.card)
                }
                if canImport {
                    // v0.13.1: a plain in-content button as well as the toolbar one (the toolbar button was
                    // reported as doing nothing on device).
                    Section {
                        Button { start() } label: {
                            HStack {
                                Spacer()
                                Label(failed ? "重试导入" : "导入", systemImage: "square.and.arrow.down").font(.headline)
                                Spacer()
                            }
                        }
                        .disabled(busy)
                    }
                    .listRowBackground(Theme.accent.opacity(0.15))
                }
                if let result {
                    if failed {
                        Section {
                            Label("导入失败", systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.warn)
                            Text(result).font(.footnote).textSelection(.enabled)
                        }
                        .listRowBackground(Theme.card)
                    } else {
                        Text(result).font(.footnote).foregroundStyle(.secondary).listRowBackground(Theme.card)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("导入").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(result == nil ? "取消" : "完成") { close() } }
                ToolbarItem(placement: .confirmationAction) {
                    if case .unsupported = action {
                        EmptyView()
                    } else if busy {
                        ProgressView()
                    } else if result == nil || failed {
                        Button("导入") { start() }
                    }
                }
            }
            .interactiveDismissDisabled(busy)
            .alert("导入失败", isPresented: Binding(get: { errorAlert != nil }, set: { if !$0 { errorAlert = nil } })) {
                Button("复制错误") { UIPasteboard.general.string = errorAlert; errorAlert = nil }
                Button("好", role: .cancel) { errorAlert = nil }
            } message: { Text(errorAlert ?? "") }
            .onAppear {
                switch action {
                case .profileURL(_, let n): name = n
                case .profileText(let n, _), .moduleText(let n, _, _), .confText(let n, _): name = n
                default: break
                }
            }
        }
    }

    var isConf: Bool { if case .confText = action { return true } else { return false } }

    var canImport: Bool {
        switch action {
        case .unsupported, .connect, .disconnect, .toggle: return false
        default: return result == nil || failed
        }
    }

    /// Both 导入 buttons: one import at a time, the router keeps the sheet up while it runs.
    func start() {
        guard !busy else { return }
        busy = true
        stage = String(localized: "正在导入…")
        ImportRouter.shared.importing = true
        StartupLog.write("import: start \(action.logSummary)", tag: "app")
        Task { @MainActor in
            await perform()
            ImportRouter.shared.importing = false
        }
    }

    func fail(_ why: String) {
        failed = true
        result = why
        errorAlert = why
        StartupLog.write("import: FAILED \(why.prefix(300))", tag: "app")
    }

    /// v0.8.1: the import brought MitM hostnames, but MitM is off or the CA is not trusted.
    var needsMitM: Bool {
        let hosts: Int
        if isConf { hosts = conf?.report?.hostnames ?? 0 } else { hosts = engine.enabledModuleCounts.hosts }
        return hosts > 0 && (!engine.config.mitm || engine.caTrusted != true)
    }

    func header(_ title: String, _ icon: String, _ detail: String) -> some View {
        Section {
            Label(LocalizedStringKey(title), systemImage: icon).font(.headline)
            Text(detail).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(3)
        }
        .listRowBackground(Theme.card)
    }

    func perform() async {
        busy = true
        failed = false
        result = nil
        defer { busy = false; stage = nil }
        do {
            switch action {
            case .profileURL(let url, _):
                let p = try await store.addRemote(url: url, name: name, userAgent: "clash.meta", intervalHours: 24)
                result = String(localized: "已添加配置「\(p.name)」")
            case .profileText(_, let text):
                let p = try await store.addLocal(name: name, text: text)
                result = String(localized: "已导入配置「\(p.name)」")
            case .moduleURL(let url, _):
                await engine.addModule(url: url)
                result = engine.message ?? String(localized: "已添加模块")
                engine.message = nil
            case .moduleText(_, let text, _):
                let moduleName = name.isEmpty ? String(localized: "本地模块") : name
                engine.addModule(text: text, name: moduleName)
                result = String(localized: "已添加模块「\(moduleName)」")
            case .confText(_, let text):
                if conf == nil {
                    stage = String(localized: "正在转换配置…")
                    conf = await ConfImportResult.convert(text)
                }
                if let e = conf?.error, !e.isEmpty { fail(String(localized: "转换失败：\(e)")); return }
                result = try await ConfImport.save(text: text, name: name, result: conf, store: store) { s in stage = s }
            case .nodesText(let text):
                let n = try await store.addManualNodes(text: text)
                result = String(localized: "已添加 \(n) 个节点到手动节点")
            default:
                break
            }
            StartupLog.write("import: done \(String((result ?? "").prefix(120)))", tag: "app")
        } catch {
            let why = error.localizedDescription
            fail(why.isEmpty ? String(localized: "未知错误") : why)
        }
    }
}
