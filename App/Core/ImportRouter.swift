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
    @Published var selectedTab = 0
    /// URLs from the scene's launch options (cold launch); drained once the UI exists if onOpenURL did not.
    var coldLaunchURLs: [URL] = []
    private var recentURLs: [(URL, Date)] = []
    private weak var presented: UIViewController?

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
                    return .unsupported("Quantumult X 远程分流请在 更多 → 规则 → 自定义 中添加（filter_remote 行）")
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
        let uti = (try? url.resourceValues(forKeys: [.contentTypeKey]))?.contentType?.identifier ?? "?"
        var data: Data?
        var readErr: Error?
        var coordErr: NSError?
        NSFileCoordinator(filePresenter: nil).coordinate(readingItemAt: url, options: [.withoutChanges], error: &coordErr) { u in
            do { data = try Data(contentsOf: u) } catch { readErr = error }
        }
        if data == nil, coordErr != nil {
            // Some providers refuse coordination; a plain read still works for them.
            data = try? Data(contentsOf: url)
        }
        guard let data else {
            let why = (readErr ?? coordErr).map { $0.localizedDescription } ?? String(localized: "未知错误")
            return (nil, 0, uti, String(localized: "无法读取文件「\(url.lastPathComponent)」：\(why)"))
        }
        if data.isEmpty { return (nil, 0, uti, String(localized: "文件「\(url.lastPathComponent)」是空的")) }
        if data.count > 16 << 20 { return (nil, data.count, uti, String(localized: "文件太大（超过 16 MB），不是配置或模块")) }
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
            if ext == "js" { return .unsupported("这是一个脚本链接：请在 更多 → 脚本 中添加脚本规则，或导入引用它的模块") }
            if ext == "list" { return .unsupported("这是一个规则列表：请在 更多 → 模块与资源 → + → 添加远程规则集 中添加") }
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
        recentURLs.removeAll { Date().timeIntervalSince($0.1) > 10 }
        if recentURLs.contains(where: { $0.0 == url }) { return }
        recentURLs.append((url, Date()))
        coldLaunchURLs.removeAll { $0 == url }
        if url.isFileURL {
            // Read synchronously now: the security scope of an opened document does not survive an async hop.
            present(Self.action(forFile: url))
        } else {
            StartupLog.write("open url: scheme=\(url.scheme ?? "-") bytes=\(url.absoluteString.utf8.count)", tag: "app")
            if let a = Self.parse(url.absoluteString) {
                run(a)
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
        if let old = presented, old.presentingViewController != nil {
            old.dismiss(animated: false) { self.present(a, attempt: attempt + 1) }
            presented = nil
            return
        }
        weak var host: UIViewController?
        let sheet = ImportSheet(action: a, onClose: { host?.dismiss(animated: true) })
            .environmentObject(ProfileStore.shared)
            .environmentObject(VPNManager.shared)
            .preferredColorScheme(.dark)
            .tint(Theme.accent)
        let vc = UIHostingController(rootView: AnyView(sheet))
        host = vc
        vc.overrideUserInterfaceStyle = .dark
        vc.modalPresentationStyle = .pageSheet
        presented = vc
        top.present(vc, animated: true)
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
    @State private var conf: ConfImportResult?

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
                    header("本地配置", "doc.text", "\(text.count) 字符")
                    TextField("名称", text: $name).listRowBackground(Theme.card)
                case .moduleURL(let url, let source):
                    header("\(source) 模块", "puzzlepiece.extension", url)
                case .moduleText(_, let text, let source):
                    header("\(source) 模块", "puzzlepiece.extension", "\(text.split(separator: "\n").count) 行")
                    TextField("名称", text: $name).listRowBackground(Theme.card)
                case .nodesText(let text):
                    header("节点", "server.rack", "\(text.split(separator: "\n").count) 行 → 手动节点")
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
                if let result {
                    Text(result).font(.footnote).foregroundStyle(.secondary).listRowBackground(Theme.card)
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
                    } else if result == nil {
                        Button("导入") { Task { await perform() } }
                            .disabled(isConf && conf?.error?.isEmpty == false)
                    }
                }
            }
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

    func header(_ title: String, _ icon: String, _ detail: String) -> some View {
        Section {
            Label(LocalizedStringKey(title), systemImage: icon).font(.headline)
            Text(detail).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(3)
        }
        .listRowBackground(Theme.card)
    }

    func perform() async {
        busy = true
        defer { busy = false }
        do {
            switch action {
            case .profileURL(let url, _):
                let p = try await store.addRemote(url: url, name: name, userAgent: "clash.meta", intervalHours: 24)
                result = "已添加配置「\(p.name)」"
            case .profileText(_, let text):
                let p = try await store.addLocal(name: name, text: text)
                result = "已导入配置「\(p.name)」"
            case .moduleURL(let url, _):
                await engine.addModule(url: url)
                result = engine.message ?? "已添加模块"
                engine.message = nil
            case .moduleText(_, let text, _):
                engine.addModule(text: text, name: name.isEmpty ? "本地模块" : name)
                result = "已添加模块「\(name)」"
            case .confText(_, let text):
                result = try await ConfImport.save(text: text, name: name, result: conf, store: store)
            case .nodesText(let text):
                let n = try await store.addManualNodes(text: text)
                result = String(localized: "已添加 \(n) 个节点到手动节点")
            default:
                break
            }
        } catch {
            result = error.localizedDescription
        }
    }
}
