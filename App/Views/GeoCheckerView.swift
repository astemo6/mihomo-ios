import SwiftUI

/// 更多 → 设置 → 出口信息查询 (v0.12, QX geo_location_checker).
struct GeoCheckerView: View {
    @EnvironmentObject var ipinfo: IPInfoModel
    @State private var s = GeoCheckerSettings.load()
    @State private var testing = false
    @State private var result: IPInfo?
    @State private var message: String?

    var body: some View {
        Form {
            Section {
                Toggle("显示出口信息", isOn: Binding(get: { !s.disabled }, set: { s.disabled = !$0 }))
            } footer: {
                Text("关闭后首页不再查询出口 IP（与 Quantumult X 的 geo_location_checker = disabled 相同）。")
            }
            .listRowBackground(Theme.card)

            Section {
                TextField("留空使用内置接口", text: $s.api, axis: .vertical)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                TextField("脚本地址或本地脚本名（可选）", text: $s.script, axis: .vertical)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            } header: { Text("自定义查询") } footer: {
                Text("查询地址返回 JSON（如 http://ip-api.com/json/?lang=zh-CN）。脚本与 Quantumult X 的 geo_location_checker 脚本相同：读取 $response.body，用 $done({title, subtitle}) 设置首页的标题和第二行。查询经过当前连接，所以显示的是代理出口。")
            }
            .listRowBackground(Theme.card)
            .disabled(s.disabled)

            Section {
                Button {
                    Task { await test() }
                } label: {
                    HStack {
                        Label("测试", systemImage: "play.circle")
                        if testing { Spacer(); ProgressView() }
                    }
                }
                .disabled(testing || s.disabled || !s.isCustom)
                if let r = result {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: "\(r.flag) \(r.placeText)").font(.subheadline.weight(.semibold))
                        Text(verbatim: r.org ?? r.asnText).font(.caption).foregroundStyle(.secondary)
                        Text(verbatim: r.ip).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
                if let m = message, !m.isEmpty {
                    Text(verbatim: m).font(.footnote).foregroundStyle(Theme.bad)
                }
                Button("恢复默认", role: .destructive) {
                    s = GeoCheckerSettings()
                    persist()
                }
                .disabled(s == GeoCheckerSettings())
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("出口信息查询")
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { persist() }
    }

    func persist() {
        guard s != GeoCheckerSettings.load() else { return }
        s.save()
        ipinfo.scheduleRefresh(after: 0.2)
    }

    func test() async {
        testing = true
        defer { testing = false }
        s.save()
        result = await GeoChecker.fetch(s)
        message = GeoChecker.lastError.isEmpty ? (result == nil ? String(localized: "查询失败") : nil) : GeoChecker.lastError
        ipinfo.scheduleRefresh(after: 0.2)
    }
}
