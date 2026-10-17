import SwiftUI

// QX-4: 出口位置查询 (QX [general] geo_location_checker): which API fills the home header, a custom API
// (any JSON with ip / country_code / city / asn / org style fields), or disabled.
// QX-5: one implementation — main v0.12's GeoChecker (same App Group keys + the optional QX script that
// turns the API reply into {title, subtitle}); this page is its QX screen.

struct QXGeoCheckerView: View {
    @EnvironmentObject var ip: IPInfoModel
    @State private var choice = IPInfoFetcher.checker
    @State private var url = IPInfoFetcher.checkerURL
    @State private var script = GeoChecker.script
    @State private var testing = false
    @State private var result: String?

    var options: [(String, String)] {
        [("", String(localized: "自动（内置顺序）"))]
            + IPInfoFetcher.endpoints.map { ($0.name, $0.name) }
            + [("custom", String(localized: "自定义 API")), ("disabled", String(localized: "关闭"))]
    }

    var body: some View {
        QXPage(title: String(localized: "出口位置查询")) {
            List {
                Section {
                    QXLargeTitle(title: String(localized: "出口位置查询"),
                                 caption: String(localized: "首页顶部的国旗、城市、ASN 与 IP 来自这里选择的接口（对应 Quantumult X 的 geo_location_checker）。请求经由当前代理发出，所以显示的是出口位置。选择「关闭」则不发出任何查询，顶部只显示连接状态。"))
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets(top: 0, leading: 4, bottom: 8, trailing: 4))
                }
                Section {
                    ForEach(options, id: \.0) { o in
                        Button {
                            choice = o.0
                            save()
                        } label: {
                            HStack {
                                Text(verbatim: o.1).foregroundStyle(.primary)
                                Spacer()
                                if choice == o.0 { Image(systemName: "checkmark").foregroundStyle(QXColor.switchOn) }
                            }
                        }
                        .accessibilityAddTraits(choice == o.0 ? .isSelected : [])
                    }
                } header: { Text("接口") } footer: {
                    Text("自动：依次尝试内置接口，第一个成功的为准。选择某个接口时它最先尝试，失败后再用其余接口。")
                }
                .listRowBackground(QXPalette.card)

                if choice == "custom" {
                    Section {
                        TextField("https://api.example.com/json", text: $url)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(.system(.body, design: .monospaced))
                            .onSubmit { save() }
                        TextField("脚本地址（可选，QX geo_location_checker 脚本）", text: $script)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(.system(.footnote, design: .monospaced))
                            .onSubmit { save() }
                        Button("保存并测试") { save(); test() }
                            .disabled(URL(string: url)?.host == nil || testing)
                    } header: { Text("自定义 API") } footer: {
                        Text("返回 JSON 的地址即可，常见字段名（ip / query、country_code / countryCode、city、region、asn / as、org / isp）会自动识别。填写脚本时按 Quantumult X 的「API, 脚本」写法：脚本读取 $response.body，用 $done({title, subtitle, ip}) 决定顶部显示的文字。")
                    }
                    .listRowBackground(QXPalette.card)
                }

                if choice != "disabled" {
                    Section {
                        Button {
                            test()
                        } label: {
                            HStack {
                                Text("立即查询")
                                Spacer()
                                if testing { ProgressView().controlSize(.small) }
                            }
                        }
                        .disabled(testing)
                        if let result {
                            Text(verbatim: result).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                    }
                    .listRowBackground(QXPalette.card)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
    }

    func save() {
        GeoChecker.save(checker: choice, url: url, script: script)
        ip.scheduleRefresh(after: 0.2)
    }

    func test() {
        testing = true
        result = nil
        Task {
            defer { testing = false }
            await MainActor.run { GeoChecker.lastError = "" }
            let info: IPInfo?
            if choice == "custom" { info = await GeoChecker.fetchCustom() } else { info = await IPInfoFetcher.fetch() }
            if let i = info {
                result = [i.flag + " " + i.placeText, i.detailText, String(localized: "来源：\(i.source ?? "—")")].joined(separator: "\n")
            } else {
                result = GeoChecker.lastError.isEmpty ? String(localized: "查询失败") : GeoChecker.lastError
            }
        }
    }
}

/// GeoIP of the remote address in the 网络活动 detail (QX: 策略走向 · exit IP ⓘ).
struct QXRemoteGeoRow: View {
    let ip: String
    @State private var info: IPInfo?
    @State private var loading = false
    @State private var failed = false

    var body: some View {
        HStack(alignment: .top) {
            Text("IP 归属").foregroundStyle(.secondary)
            Spacer(minLength: 12)
            if let info {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(verbatim: info.flag + " " + info.placeText)
                    Text(verbatim: [info.asn, info.org].compactMap { $0 }.joined(separator: " ")).font(.caption).foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
            } else if loading {
                ProgressView().controlSize(.small)
            } else {
                Button(failed ? LocalizedStringKey("查询失败，重试") : LocalizedStringKey("查询")) { Task { await load() } }
                    .font(.subheadline.weight(.semibold))
            }
        }
        .font(.subheadline)
        .padding(.horizontal, 16).padding(.vertical, 11)
    }

    func load() async {
        loading = true
        defer { loading = false }
        info = await IPInfoFetcher.lookup(ip: ip)
        failed = info == nil
    }
}
