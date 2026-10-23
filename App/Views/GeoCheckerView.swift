import SwiftUI

/// 更多 → 设置 → 出口信息查询 (v0.12, QX geo_location_checker). Same choices and App Group keys as
/// qx/rebuild's 出口位置查询 (自动 / 优先接口 / 自定义 JSON 接口 / 关闭) plus an optional QX script for the
/// custom API.
struct GeoCheckerView: View {
    @EnvironmentObject var ipinfo: IPInfoModel
    @State private var choice = IPInfoFetcher.checker
    @State private var url = IPInfoFetcher.checkerURL
    @State private var script = GeoChecker.script
    @State private var testing = false
    @State private var result: IPInfo?
    @State private var message: String?
    @AppStorage(ExitDetailField.storageKey, store: AppShared.defaults) private var detailFields = ExitDetailField.defaultValue

    var body: some View {
        Form {
            Section {
                Picker("查询接口", selection: $choice) {
                    Text("自动").tag("")
                    ForEach(IPInfoFetcher.endpoints, id: \.name) { e in Text(verbatim: e.name).tag(e.name) }
                    Text("自定义").tag("custom")
                    Text("关闭").tag("disabled")
                }
            } footer: {
                Text("首页的国旗、地区、ASN 与 IP 来自这里选择的接口（对应 Quantumult X 的 geo_location_checker）。查询经过当前连接，所以显示的是代理出口。「关闭」不发出任何查询。")
            }
            .listRowBackground(Theme.card)

            Section {
                ForEach(ExitDetailField.allCases) { f in
                    Toggle(isOn: detailBinding(f)) { Text(Self.label(f)) }
                        .accessibilityIdentifier("geo.detail." + f.rawValue)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("预览").font(.caption).foregroundStyle(.secondary)
                    Text(verbatim: previewText)
                        .font(.caption.monospacedDigit())
                        .lineLimit(1).minimumScaleFactor(0.75)
                        .accessibilityIdentifier("geo.detail.preview")
                }
            } header: { Text("首页副标题显示") } footer: {
                Text("选择首页地区下方那一行显示的内容。运营商未知时改显示时区。自定义脚本设置了第二行时，以脚本为准。")
            }
            .listRowBackground(Theme.card)

            if choice == "custom" {
                Section {
                    TextField("http://ip-api.com/json/?lang=zh-CN", text: $url, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("脚本地址或本地脚本名（可选）", text: $script, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                } header: { Text("自定义查询") } footer: {
                    Text("查询地址返回 JSON。脚本与 Quantumult X 的 geo_location_checker 脚本相同：读取 $response.body，用 $done({title, subtitle}) 设置首页的标题和第二行。自定义接口失败时使用内置接口。")
                }
                .listRowBackground(Theme.card)
            }

            Section {
                Button {
                    Task { await test() }
                } label: {
                    HStack {
                        Label("测试", systemImage: "play.circle")
                        if testing { Spacer(); ProgressView() }
                    }
                }
                .disabled(testing || choice == "disabled")
                if let r = result {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: "\(r.flag) \(r.placeText)").font(.subheadline.weight(.semibold))
                        Text(verbatim: r.org ?? r.asnText).font(.caption).foregroundStyle(.secondary)
                        Text(verbatim: "\(r.ip) · \(r.source ?? "")").font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
                if let m = message, !m.isEmpty {
                    Text(verbatim: m).font(.footnote).foregroundStyle(Theme.bad)
                }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("出口信息来源") // r7 P3-8: same name as the 高级设置 row
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: choice) { _ in persist() }
        .onDisappear { persist() }
    }

    static func label(_ f: ExitDetailField) -> LocalizedStringKey {
        switch f {
        case .isp: return "运营商"
        case .asn: return "ASN"
        case .timezone: return "时区"
        case .ip: return "IP 地址"
        }
    }

    func detailBinding(_ f: ExitDetailField) -> Binding<Bool> {
        Binding(
            get: { ExitDetailField.parse(detailFields).contains(f) },
            set: { on in
                var set = ExitDetailField.parse(detailFields)
                if on { set.insert(f) } else { set.remove(f) }
                detailFields = ExitDetailField.encode(set)
            })
    }

    var previewText: String {
        guard let info = result ?? ipinfo.exit else { return "—" }
        let t = info.detailText(fields: ExitDetailField.parse(detailFields))
        return t.isEmpty ? String(localized: "（不显示）") : t
    }

    func persist() {
        guard choice != IPInfoFetcher.checker || url != IPInfoFetcher.checkerURL || script != GeoChecker.script else { return }
        GeoChecker.save(checker: choice, url: url, script: script)
        ipinfo.scheduleRefresh(after: 0.2)
    }

    func test() async {
        testing = true
        defer { testing = false }
        // Clear the last outcome first, so a repeat failure visibly re-runs instead of looking like a dead button.
        message = nil
        result = nil
        GeoChecker.save(checker: choice, url: url, script: script)
        await MainActor.run { GeoChecker.lastError = "" }
        if choice == "custom" {
            result = await GeoChecker.fetchCustom()
            message = GeoChecker.lastError.isEmpty ? (result == nil ? String(localized: "查询失败") : nil) : GeoChecker.lastError
        } else {
            result = await IPInfoFetcher.fetch()
            message = result == nil ? String(localized: "查询失败") : nil
        }
        ipinfo.scheduleRefresh(after: 0.2)
    }
}
