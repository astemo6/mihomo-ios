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
        overrides = o
    }

    func setCustomURL(_ kind: String, _ url: String) {
        var o = CoreOverrides.load()
        let t = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { o.geoURLs.removeValue(forKey: kind) } else { o.geoURLs[kind] = t }
        o.save()
        overrides = o
    }

    func defaultURL(_ kind: String) -> String { LibmihomoGeoDefaultURL(kind, overrides.geoMirror) }

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

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                mirrorCard
                ForEach(model.files) { f in card(f) }
                Text("内置数据库随扩展安装，首次连接无需下载。更新后 GeoIP / ASN 立即生效，GEOSITE / GEOIP(dat) 会重载配置。规则集（rule-providers）在「工具 → 模块 → 配置里的规则集」中更新。")
                    .font(.caption2).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 4)
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("地理与规则库")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("全部更新") { Task { await model.updateAll() } }
                    .disabled(!model.progress.isEmpty)
            }
        }
        .onAppear { model.refresh() }
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
            if model.chinaMirror {
                Picker("镜像", selection: Binding(get: { model.overrides.geoMirror }, set: { model.setMirror($0) })) {
                    Text("jsDelivr（testingcf）").tag("jsdelivr")
                    Text("Fastly").tag("fastly")
                }
                .pickerStyle(.segmented)
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
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
                Button {
                    Task { await model.update(f.kind) }
                } label: {
                    Image(systemName: "arrow.down.circle.fill").font(.title2)
                }
                .buttonStyle(.plain)
                .foregroundStyle(busy ? Color.secondary : Theme.accent)
                .disabled(busy)
            }

            HStack(spacing: 14) {
                metric("文件", f.file)
                metric("大小", f.size.map { Fmt.bytes($0) } ?? "—")
                metric("更新于", f.modified.map { Date(timeIntervalSince1970: $0).formatted(date: .abbreviated, time: .shortened) } ?? "—")
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
                Text(model.effectiveURL(f.kind)).scaledFont(9, design: .monospaced).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
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

    func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.caption.weight(.semibold).monospacedDigit()).lineLimit(1)
        }
    }
}
