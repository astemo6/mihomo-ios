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
        .navigationTitle("出口信息查询")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: choice) { _ in persist() }
        .onDisappear { persist() }
    }

    func persist() {
        guard choice != IPInfoFetcher.checker || url != IPInfoFetcher.checkerURL || script != GeoChecker.script else { return }
        GeoChecker.save(checker: choice, url: url, script: script)
        ipinfo.scheduleRefresh(after: 0.2)
    }

    func test() async {
        testing = true
        defer { testing = false }
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
