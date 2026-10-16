import Foundation
import SwiftUI
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

    @Published var pending: ImportAction?
    /// Tab to show after routing (0 首页 … 4 更多).
    @Published var selectedTab = 0

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

    /// Decides what an opened document is by its extension.
    nonisolated static func action(forFile url: URL) -> ImportAction? {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return .unsupported("无法读取 \(url.lastPathComponent)") }
        let name = url.deletingPathExtension().lastPathComponent
        switch url.pathExtension.lowercased() {
        case "sgmodule": return .moduleText(name: name, text: text, source: "Surge")
        case "plugin", "lpx": return .moduleText(name: name, text: text, source: "Loon")
        case "stoverride": return .moduleText(name: name, text: text, source: "Stash")
        case "snippet": return .moduleText(name: name, text: text, source: "Quantumult X")
        case "list": return .moduleText(name: name, text: text, source: "列表")
        case "module": return .moduleText(name: name, text: text, source: "Surge")
        case "conf": return .confText(name: name, text: text)
        case "yaml", "yml":
            // Egern modules and Stash overrides are YAML too.
            let c = LibmihomoClassifyText(text)
            if c.hasPrefix("module:") { return .moduleText(name: name, text: text, source: sourceName(c)) }
            return .profileText(name: name, text: text)
        default:
            return route(text: text, name: name) ?? .unsupported("不支持的文件类型 .\(url.pathExtension)")
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
        if let a = Self.route(text: text) { run(a) } else { pending = .unsupported(String(localized: "剪贴板内容无法识别：支持订阅 / 模块链接、配置、模块内容、节点链接")) }
    }

    func handle(url: URL) {
        if url.isFileURL {
            pending = Self.action(forFile: url)
        } else if let a = Self.parse(url.absoluteString) {
            run(a)
        }
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

    init(action: ImportAction) { self.action = action }

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
                ToolbarItem(placement: .cancellationAction) { Button(result == nil ? "取消" : "完成") { dismiss() } }
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
