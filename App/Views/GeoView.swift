import SwiftUI
import Libmihomo

// 地理与规则库: the four databases the core reads (geoip.metadb, GeoIP.dat, GeoSite.dat, ASN.mmdb).
// Downloads run in the app with a progress bar; the Go bridge validates and installs the file.

struct GeoFileInfo: Decodable, Identifiable, Hashable {
    var id: String { kind }
    var kind: String
    var file: String
    var remote: String?
    var exists: Bool?
    var size: Int64?
    var modified: Double?
    var buildDate: Double?
    var dbType: String?
    var error: String?

    var title: String {
        switch kind {
        case "mmdb": return "GeoIP（MMDB）"
        case "geoip": return "GEOIP（dat）"
        case "geosite": return "GEOSITE"
        case "asn": return "GeoLite2-ASN"
        default: return kind
        }
    }

    var purpose: String {
        switch kind {
        case "mmdb": return String(localized: "GEOIP 规则与 fallback-filter 使用（默认）")
        case "geoip": return String(localized: "仅在配置开启 geodata-mode 时使用")
        case "geosite": return String(localized: "GEOSITE 规则与 DNS 分流（geosite:cn 等）")
        case "asn": return String(localized: "IP-ASN 规则、请求详情里的 ASN")
        default: return ""
        }
    }

    var icon: String {
        switch kind {
        case "mmdb": return "globe.asia.australia.fill"
        case "geoip": return "globe"
        case "geosite": return "list.bullet.rectangle.portrait.fill"
        case "asn": return "building.2.fill"
        default: return "shippingbox"
        }
    }
}

@MainActor
final class GeoModel: NSObject, ObservableObject, URLSessionDownloadDelegate {
    static let kinds = ["mmdb", "geosite", "asn", "geoip"]

    @Published var files: [GeoFileInfo] = []
    @Published var progress: [String: Double] = [:]
    @Published var errors: [String: String] = [:]
    @Published var overrides = CoreOverrides.load()

    private var session: URLSession!
    private var taskKind: [Int: String] = [:]
    private var continuations: [Int: CheckedContinuation<URL, Error>] = [:]

    override init() {
        super.init()
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 30
        cfg.timeoutIntervalForResource = 600
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: .main)
        refresh()
    }

    var home: String { AppShared.homeURL.path }

    func refresh() {
        let json = LibmihomoGeoInfo(home)
        let list = (try? JSONDecoder().decode([GeoFileInfo].self, from: Data(json.utf8))) ?? []
        files = Self.kinds.compactMap { k in list.first { $0.kind == k } }
        overrides = CoreOverrides.load()
    }

    var chinaMirror: Bool { overrides.geoMirror != "github" }

    func setMirror(_ m: String) {
        var o = CoreOverrides.load()
        o.geoMirror = m
        o.save()
        IconCache.mirrorChanged() // B23
        overrides = o
    }

    /// feat/geo-mirror-edit: the jsDelivr template a custom base starts from.
    static let templateBase = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"

    /// A usable custom base (https, host, no query, no spaces) with a trailing "/", else nil. Same rules as the
    /// bridge's GeoCustomBase, so what the page previews is what the core downloads.
    nonisolated static func normalizedBase(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, !t.contains(" "), let u = URLComponents(string: t), u.scheme?.lowercased() == "https",
              let h = u.host, !h.isEmpty, u.query == nil, u.fragment == nil else { return nil }
        return t.hasSuffix("/") ? t : t + "/"
    }

    /// Saves the custom base and selects 自定义. Returns false when the address is not usable.
    @discardableResult
    func setCustomBase(_ text: String) -> Bool {
        guard let b = Self.normalizedBase(text) else { return false }
        var o = CoreOverrides.load()
        o.geoMirror = "custom"
        o.geoMirrorBase = b
        o.save()
        IconCache.mirrorChanged()
        overrides = o
        return true
    }

    /// 重置: forget the custom base and go back to the default mirror (jsDelivr).
    func resetCustomBase() {
        var o = CoreOverrides.load()
        o.geoMirror = "jsdelivr"
        o.geoMirrorBase = ""
        o.save()
        IconCache.mirrorChanged()
        overrides = o
    }

    /// The base the 默认地址 boxes use right now.
    var currentBase: String {
        let u = LibmihomoGeoMirrorURL("mmdb", overrides.geoMirror, overrides.geoMirrorBase)
        return u.hasSuffix("geoip.metadb") ? String(u.dropLast("geoip.metadb".count)) : u
    }

    func setCustomURL(_ kind: String, _ url: String) {
        var o = CoreOverrides.load()
        let t = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { o.geoURLs.removeValue(forKey: kind) } else { o.geoURLs[kind] = t }
        o.save()
        overrides = o
    }

    func defaultURL(_ kind: String) -> String { LibmihomoGeoMirrorURL(kind, overrides.geoMirror, overrides.geoMirrorBase) }

    func effectiveURL(_ kind: String) -> String {
        if let u = overrides.geoURLs[kind], !u.isEmpty { return u }
        return defaultURL(kind)
    }

    func update(_ kind: String) async {
        guard progress[kind] == nil, let url = URL(string: effectiveURL(kind)) else {
            if URL(string: effectiveURL(kind)) == nil { errors[kind] = String(localized: "地址无效") }
            return
        }
        errors[kind] = nil
        progress[kind] = 0
        defer { progress[kind] = nil }
        do {
            var req = URLRequest(url: url)
            req.setValue("mihomo-ios", forHTTPHeaderField: "User-Agent")
            let tmp = try await download(req, kind: kind)
            let home = self.home
            let result: String? = await Task.detached(priority: .userInitiated) { () -> String? in
                var err: NSError?
                _ = LibmihomoGeoInstallFile(home, kind, tmp.path, &err)
                return err?.localizedDescription
            }.value
            if let result { errors[kind] = result; return }
            refresh()
            await applyToRunningCore(kind)
        } catch {
            errors[kind] = String(localized: "下载失败：\(error.localizedDescription)")
        }
    }

    /// User 2026-10-22 「只有安装，没有卸载吗」: delete an installed database. A rule or DNS setting that still needs it
    /// makes the core download it again on the next reload.
    func remove(_ kind: String) async {
        guard let f = files.first(where: { $0.kind == kind }) else { return }
        let url = URL(fileURLWithPath: home).appendingPathComponent(f.file)
        do { try FileManager.default.removeItem(at: url) } catch {
            errors[kind] = String(localized: "删除失败：\(error.localizedDescription)")
            return
        }
        errors[kind] = nil
        refresh()
        if VPNManager.shared.isConnected { _ = await VPNManager.shared.reload() }
    }

    func updateAll() async {
        await withTaskGroup(of: Void.self) { g in
            for k in files.filter({ $0.exists == true || $0.kind != "geoip" }).map(\.kind) {
                g.addTask { await self.update(k) }
            }
        }
    }

    /// mmdb files are reopened in place; .dat databases are read at config load, so reload the profile.
    private func applyToRunningCore(_ kind: String) async {
        guard VPNManager.shared.isConnected else { return }
        if kind == "mmdb" || kind == "asn" {
            _ = try? await ControllerClient.shared.send("/tools/reload-geo", method: "POST")
        } else {
            _ = await VPNManager.shared.reload()
        }
    }

    private func download(_ req: URLRequest, kind: String) async throws -> URL {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<URL, Error>) in
            let t = session.downloadTask(with: req)
            taskKind[t.taskIdentifier] = kind
            continuations[t.taskIdentifier] = c
            t.resume()
        }
    }

    // MARK: URLSessionDownloadDelegate (delegate queue = main)

    nonisolated func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                                totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        let id = downloadTask.taskIdentifier
        let frac = totalBytesExpectedToWrite > 0 ? Double(totalBytesWritten) / Double(totalBytesExpectedToWrite) : -1
        Task { @MainActor in
            if let k = self.taskKind[id], self.progress[k] != nil { self.progress[k] = frac }
        }
    }

    nonisolated func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        let id = downloadTask.taskIdentifier
        let status = (downloadTask.response as? HTTPURLResponse)?.statusCode ?? 200
        // The file at `location` is removed when this returns: move it now.
        let dst = FileManager.default.temporaryDirectory.appendingPathComponent("geo-\(UUID().uuidString).download")
        let moved: Result<URL, Error>
        if !(200..<300).contains(status) {
            moved = .failure(NSError(domain: "Geo", code: status, userInfo: [NSLocalizedDescriptionKey: "HTTP \(status)"]))
        } else {
            do {
                try FileManager.default.moveItem(at: location, to: dst)
                moved = .success(dst)
            } catch {
                moved = .failure(error)
            }
        }
        Task { @MainActor in
            self.continuations.removeValue(forKey: id)?.resume(with: moved)
            self.taskKind.removeValue(forKey: id)
        }
    }

    nonisolated func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // Success is delivered by didFinishDownloadingTo; only failures end the continuation here.
        guard let error else { return }
        let id = task.taskIdentifier
        Task { @MainActor in
            self.continuations.removeValue(forKey: id)?.resume(throwing: error)
            self.taskKind.removeValue(forKey: id)
        }
    }
}

struct GeoView: View {
    @StateObject private var model = GeoModel()
    @State private var editing: String?
    @State private var urlText = ""
    @State private var baseText = ""
    @State private var removing: GeoFileInfo?
    @FocusState private var baseFocused: Bool

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                mirrorCard
                ForEach(model.files) { f in card(f) }
                Text("内置数据库随扩展安装，首次连接无需下载。更新后 GeoIP / ASN 立即生效，GEOSITE / GEOIP(dat) 会重载配置。规则集（rule-providers）在「工具 → 规则 → 订阅」中更新。")
                    .font(.caption2).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 4)
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("地理数据库") // r7 P3-8: same name as the 高级设置 row
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("全部更新") { Task { await model.updateAll() } }
                    .disabled(!model.progress.isEmpty)
            }
        }
        .onAppear {
            model.refresh()
            baseText = model.overrides.geoMirrorBase.isEmpty ? model.currentBase : model.overrides.geoMirrorBase
        }
        .confirmationDialog(Text("删除 \(removing?.title ?? "")？"), isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                if let k = removing?.kind { Task { await model.remove(k) } }
                removing = nil
            }
        } message: {
            Text("配置里的规则或 DNS 仍需要它时，内核会在下次加载时重新下载。")
        }
        .alert("自定义下载地址", isPresented: Binding(get: { editing != nil }, set: { if !$0 { editing = nil } })) {
            TextField("https://…", text: $urlText).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            Button("保存") { if let k = editing { model.setCustomURL(k, urlText) }; editing = nil }
            Button("恢复默认", role: .destructive) { if let k = editing { model.setCustomURL(k, "") }; editing = nil }
            Button("取消", role: .cancel) { editing = nil }
        } message: { Text("留空使用默认地址") }
    }

    var mirrorCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: Binding(get: { model.chinaMirror }, set: { model.setMirror($0 ? "jsdelivr" : "github") })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("国内镜像").font(.subheadline.weight(.semibold))
                    Text(model.chinaMirror ? "通过 CDN 下载 MetaCubeX/meta-rules-dat，中国大陆可直接访问" : "直接从 GitHub Releases 下载").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .tint(Theme.accent)
            .accessibilityIdentifier("geo.mirror.toggle")
            if model.chinaMirror {
                Picker("镜像", selection: Binding(get: { model.overrides.geoMirror }, set: { m in
                    if m == "custom" {
                        // Start from the saved custom base, else from the address in use (a template to edit).
                        if model.overrides.geoMirrorBase.isEmpty { baseText = model.currentBase } else { baseText = model.overrides.geoMirrorBase }
                    }
                    model.setMirror(m)
                })) {
                    Text("jsDelivr").tag("jsdelivr")
                    Text("Fastly").tag("fastly")
                    Text("自定义").tag("custom")
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("geo.mirror.picker")
                if model.overrides.geoMirror == "custom" {
                    customBaseEditor
                } else {
                    Text(verbatim: model.currentBase)
                        .scaledFont(9, design: .monospaced).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                        .accessibilityIdentifier("geo.mirror.base")
                }
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
    }

    /// 自定义 mirror: an editable base URL (the file name is appended), a live preview for geoip.metadb, 保存 / 重置.
    var customBaseEditor: some View {
        let normalized = GeoModel.normalizedBase(baseText)
        let saved = model.overrides.geoMirrorBase
        let dirty = normalized != nil && normalized != saved
        return VStack(alignment: .leading, spacing: 6) {
            Text("镜像地址").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                TextField(GeoModel.templateBase, text: $baseText)
                    .scaledFont(11, design: .monospaced)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .submitLabel(.done)
                    .focused($baseFocused)
                    .onSubmit { if dirty { model.setCustomBase(baseText) } }
                    .accessibilityIdentifier("geo.mirror.field")
                // Always in the row (hidden while empty): inserting / removing a view next to the field while
                // clearing it and moving focus in the same update left the field focused but not taking typed
                // text (UI test r2). Clearing leaves focus where the user put it.
                Button {
                    baseText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .opacity(baseText.isEmpty ? 0 : 1)
                .disabled(baseText.isEmpty)
                .accessibilityHidden(baseText.isEmpty)
                .accessibilityLabel(Text("清除"))
                .accessibilityIdentifier("geo.mirror.clear")
            }
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(normalized == nil && !baseText.isEmpty ? Theme.bad.opacity(0.7) : Color.clear, lineWidth: 1))
            if let n = normalized {
                VStack(alignment: .leading, spacing: 2) {
                    Text("预览（geoip.metadb）").font(.caption2).foregroundStyle(.secondary)
                    Text(verbatim: n + "geoip.metadb")
                        .scaledFont(9, design: .monospaced).foregroundStyle(Theme.accent)
                        .lineLimit(2).textSelection(.enabled)
                        .accessibilityIdentifier("geo.mirror.preview")
                }
            } else {
                Label("请输入以 https:// 开头的有效地址", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(Theme.bad)
                    .accessibilityIdentifier("geo.mirror.invalid")
            }
            Text("文件名会自动接在地址后面，例如 geoip.metadb、geosite.dat。")
                .font(.caption2).foregroundStyle(.secondary)
            if saved.isEmpty {
                Text("尚未保存，暂用 jsDelivr").font(.caption2).foregroundStyle(Theme.warn)
                    .accessibilityIdentifier("geo.mirror.unsaved")
            }
            HStack(spacing: 10) {
                Button {
                    baseFocused = false
                    model.setCustomBase(baseText)
                } label: { Text("保存").font(.caption.weight(.semibold)).frame(maxWidth: .infinity) }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .disabled(!dirty)
                .accessibilityIdentifier("geo.mirror.save")
                Button(role: .destructive) {
                    baseFocused = false
                    model.resetCustomBase()
                    baseText = model.currentBase
                } label: { Text("重置").font(.caption.weight(.semibold)).frame(maxWidth: .infinity) }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("geo.mirror.reset")
            }
            .controlSize(.small)
        }
    }

    func statusChip(_ f: GeoFileInfo) -> some View {
        let (text, color): (String, Color) = {
            if let e = f.error, !e.isEmpty { return ("损坏", Theme.bad) }
            if f.exists == true { return ("已安装", Theme.good) }
            return ("未安装", Theme.warn)
        }()
        return Text(LocalizedStringKey(text)).scaledFont(10, weight: .bold)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(color.opacity(0.18)))
            .foregroundStyle(color)
            .accessibilityIdentifier("geo.status.\(f.kind)")
    }

    func card(_ f: GeoFileInfo) -> some View {
        let custom = model.overrides.geoURLs[f.kind]
        let busy = model.progress[f.kind] != nil
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Image(systemName: f.icon)
                    .font(.title3)
                    .foregroundStyle(Theme.accent)
                    .frame(width: 40, height: 40)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.accent.opacity(0.14)))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(f.title).font(.headline)
                        statusChip(f)
                    }
                    Text(f.purpose).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                actionButton(f, busy: busy)
            }

            HStack(spacing: 14) {
                metric("文件", f.file)
                metric("大小", f.size.map { Fmt.bytes($0) } ?? "—")
                metric("更新于", f.modified.map { Date(timeIntervalSince1970: $0).formatted(date: .abbreviated, time: .shortened) } ?? "—")
                if f.exists == true && !busy {
                    Spacer(minLength: 0)
                    Button(role: .destructive) { removing = f } label: {
                        Image(systemName: "trash").font(.subheadline)
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Theme.bad)
                    .accessibilityLabel(Text("删除"))
                    .accessibilityIdentifier("geo.delete.\(f.kind)")
                }
            }
            if let b = f.buildDate, b > 0 {
                Text("数据版本 \(Date(timeIntervalSince1970: b).formatted(date: .abbreviated, time: .omitted))\(f.dbType.map { " · " + $0 } ?? "")")
                    .font(.caption2).foregroundStyle(.secondary)
            }

            if let p = model.progress[f.kind] {
                if p >= 0 {
                    ProgressView(value: p).tint(Theme.accent)
                    Text("下载中 \(Int(p * 100))%").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                } else {
                    ProgressView().tint(Theme.accent)
                }
            }
            if let e = model.errors[f.kind] ?? f.error, !e.isEmpty {
                Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.bad)
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(custom == nil ? "默认地址" : "自定义地址").font(.caption2.weight(.semibold)).foregroundStyle(custom == nil ? Color.secondary : Theme.warn)
                    Spacer()
                    Button(custom == nil ? "自定义" : "修改") {
                        urlText = custom ?? ""
                        editing = f.kind
                    }
                    .font(.caption2.weight(.semibold))
                    .buttonStyle(.borderless)
                }
                Text(verbatim: model.effectiveURL(f.kind)).scaledFont(9, design: .monospaced).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                    .accessibilityIdentifier("geo.url.\(f.kind)")
                if custom != nil {
                    Text("默认：\(model.defaultURL(f.kind))").scaledFont(9, design: .monospaced).foregroundStyle(Color.secondary.opacity(0.7)).lineLimit(1).truncationMode(.middle)
                }
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
    }

    /// feat/geo-mirror-edit: download arrow only while not installed; installed → 更新 (arrow.clockwise);
    /// a spinner while downloading; red 重试 after an error or for a damaged file.
    @ViewBuilder
    func actionButton(_ f: GeoFileInfo, busy: Bool) -> some View {
        let failed = !(model.errors[f.kind] ?? f.error ?? "").isEmpty
        if busy {
            ProgressView()
                .tint(Theme.accent)
                .frame(width: 32, height: 32)
                .accessibilityLabel(Text("下载中"))
                .accessibilityIdentifier("geo.busy.\(f.kind)")
        } else {
            let st = actionStyle(f, failed: failed)
            Button {
                Task { await model.update(f.kind) }
            } label: {
                Image(systemName: st.symbol)
                    .font(.subheadline.weight(.bold))
                    .foregroundStyle(st.soft ? st.color : Color.white)
                    .frame(width: 32, height: 32)
                    .background(Circle().fill(st.soft ? st.color.opacity(0.14) : st.color))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(Text(LocalizedStringKey(st.label)))
            .accessibilityIdentifier(st.id)
        }
    }

    /// soft = tinted circle (installed → 更新, the quiet action); solid = the call to action (下载, red 重试).
    func actionStyle(_ f: GeoFileInfo, failed: Bool) -> (symbol: String, color: Color, label: String, id: String, soft: Bool) {
        if failed { return ("arrow.clockwise", Theme.bad, "重试", "geo.retry.\(f.kind)", false) }
        if f.exists == true { return ("arrow.clockwise", Theme.accent, "更新", "geo.update.\(f.kind)", true) }
        return ("arrow.down", Theme.accent, "下载", "geo.download.\(f.kind)", false)
    }

    func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.caption.weight(.semibold).monospacedDigit()).lineLimit(1)
        }
    }
}
