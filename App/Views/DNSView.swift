import SwiftUI

/// Mirrors <home>/dns.json (bridge/dns.go DNSOverride). When enabled it replaces the profile's resolvers.
struct DNSOverrideSettings: Codable, Equatable {
    struct Fallback: Codable, Equatable {
        var geoip: Bool = true
        var geoipCode: String = "CN"
        var ipcidr: [String] = []
        var domain: [String] = []
        var geosite: [String] = []
    }
    struct Policy: Codable, Equatable, Identifiable {
        var id = UUID()
        var match: String
        var servers: [String]
        enum CodingKeys: String, CodingKey { case match, servers }
    }

    var enabled = false
    var nameserver: [String] = ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"]
    var foreign: [String] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    var split = true
    var defaultNameserver: [String] = ["223.5.5.5", "119.29.29.29"]
    var directNameserver: [String] = []
    var proxyNameserver: [String] = []
    var fallback: [String] = []
    var fallbackFilter = Fallback()
    var fakeIPRange = ""
    var fakeIPFilter: [String] = []
    var fakeIPFilterMode = "blacklist"
    var policy: [Policy] = []
    var preferH3 = false
    var respectRules = false
    var cacheAlgorithm = ""

    init() {}

    enum CodingKeys: String, CodingKey {
        case enabled, nameserver, foreign, split, defaultNameserver, directNameserver, proxyNameserver, fallback, fallbackFilter
        case fakeIPRange, fakeIPFilter, fakeIPFilterMode, policy, preferH3, respectRules, cacheAlgorithm
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = DNSOverrideSettings()
        func get<T: Decodable>(_ k: CodingKeys, _ f: T) -> T { (try? c.decodeIfPresent(T.self, forKey: k)) ?? f }
        enabled = get(.enabled, d.enabled)
        nameserver = get(.nameserver, d.nameserver)
        foreign = get(.foreign, d.foreign)
        split = get(.split, d.split)
        defaultNameserver = get(.defaultNameserver, d.defaultNameserver)
        directNameserver = get(.directNameserver, d.directNameserver)
        proxyNameserver = get(.proxyNameserver, d.proxyNameserver)
        fallback = get(.fallback, d.fallback)
        fallbackFilter = get(.fallbackFilter, d.fallbackFilter)
        fakeIPRange = get(.fakeIPRange, d.fakeIPRange)
        fakeIPFilter = get(.fakeIPFilter, d.fakeIPFilter)
        fakeIPFilterMode = get(.fakeIPFilterMode, d.fakeIPFilterMode)
        policy = get(.policy, d.policy)
        preferH3 = get(.preferH3, d.preferH3)
        respectRules = get(.respectRules, d.respectRules)
        cacheAlgorithm = get(.cacheAlgorithm, d.cacheAlgorithm)
    }

    static var url: URL { AppShared.homeURL.appendingPathComponent("dns.json") }

    static func load() -> DNSOverrideSettings {
        guard let d = try? Data(contentsOf: url), let s = try? JSONDecoder().decode(DNSOverrideSettings.self, from: d) else { return DNSOverrideSettings() }
        return s
    }

    func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(self) { try? d.write(to: Self.url, options: .atomic) }
    }
}

/// Edits a list of strings as one-per-line text.
struct LinesField: View {
    let title: String
    let placeholder: String
    @Binding var lines: [String]
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(LocalizedStringKey(title)).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            TextField(placeholder, text: $text, axis: .vertical)
                .font(.system(size: 12, design: .monospaced))
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .lineLimit(1...8)
                .onAppear { text = lines.joined(separator: "\n") }
                .onChange(of: text) { t in
                    lines = t.components(separatedBy: CharacterSet(charactersIn: "\n,")).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                }
        }
    }
}

struct DNSView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var s = DNSOverrideSettings.load()
    @State private var dnsMode = CoreOverrides.load().dnsMode
    @State private var status: String?
    @State private var newMatch = ""
    @State private var newServers = ""

    var body: some View {
        Form {
            Section {
                Toggle("使用自定义 DNS", isOn: $s.enabled)
                Picker("DNS 模式", selection: $dnsMode) {
                    Text("Fake-IP").tag("fake-ip")
                    Text("Redir-Host").tag("redir-host")
                }
            } footer: {
                Text(s.enabled ? "以下设置会覆盖配置文件里的 dns 段。" : "关闭时使用配置文件自带的 DNS 设置（没有时使用内置的国内 DoH）。")
            }
            .listRowBackground(Theme.card)

            if s.enabled {
                Section {
                    Toggle("国内 / 国外分流", isOn: $s.split)
                    LinesField(title: "国内 DNS", placeholder: "https://223.5.5.5/dns-query", lines: $s.nameserver)
                    if s.split {
                        LinesField(title: "国外 DNS", placeholder: "https://1.1.1.1/dns-query", lines: $s.foreign)
                    }
                } header: { Text("解析服务器") } footer: {
                    Text(s.split ? "geosite:cn 与私有域名用国内 DNS，其余域名用国外 DNS（通过代理查询）。支持 udp / tcp / DoH (https://) / DoT (tls://) / DoQ (quic://)。" : "所有域名都用这里的服务器。")
                }
                .listRowBackground(Theme.card)

                Section {
                    LinesField(title: "引导 DNS（纯 IP）", placeholder: "223.5.5.5", lines: $s.defaultNameserver)
                    LinesField(title: "节点域名解析（proxy-server-nameserver）", placeholder: "可留空", lines: $s.proxyNameserver)
                    LinesField(title: "直连解析（direct-nameserver）", placeholder: "可留空", lines: $s.directNameserver)
                    Toggle("优先 HTTP/3", isOn: $s.preferH3)
                    Toggle("DNS 查询遵循规则（respect-rules）", isOn: $s.respectRules)
                } header: { Text("高级") } footer: {
                    Text("引导 DNS 用来解析 DoH / DoT 服务器自身的域名，必须是 IP。")
                }
                .listRowBackground(Theme.card)

                Section {
                    ForEach(s.policy) { p in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.match).font(.system(size: 12, design: .monospaced))
                            Text(p.servers.joined(separator: ", ")).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .onDelete { s.policy.remove(atOffsets: $0) }
                    VStack(spacing: 6) {
                        TextField("域名 / +.后缀 / geosite:xx", text: $newMatch).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("服务器，多个用逗号分隔", text: $newServers).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("添加") {
                            let servers = newServers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                            let m = newMatch.trimmingCharacters(in: .whitespaces)
                            guard !m.isEmpty, !servers.isEmpty else { return }
                            s.policy.append(.init(match: m, servers: servers))
                            newMatch = ""; newServers = ""
                        }
                        .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                } header: { Text("指定域名的 DNS（nameserver-policy）") }
                .listRowBackground(Theme.card)

                if dnsMode == "fake-ip" {
                    Section {
                        Picker("过滤模式", selection: $s.fakeIPFilterMode) {
                            Text("列表内不用 Fake-IP").tag("blacklist")
                            Text("仅列表内用 Fake-IP").tag("whitelist")
                        }
                        LinesField(title: "Fake-IP 过滤", placeholder: "+.lan", lines: $s.fakeIPFilter)
                    } header: { Text("Fake-IP") }
                    .listRowBackground(Theme.card)
                }

                Section {
                    Button("恢复推荐设置") {
                        let keepPolicy = s.policy
                        s = DNSOverrideSettings()
                        s.enabled = true
                        s.policy = keepPolicy
                    }
                }
                .listRowBackground(Theme.card)
            }

            Section {
                Button { save() } label: { HStack { Spacer(); Text(vpn.isConnected ? "保存并重载" : "保存").bold(); Spacer() } }
                if let status { Text(status).font(.footnote).foregroundStyle(.secondary) }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("DNS")
    }

    func save() {
        s.save()
        var o = CoreOverrides.load()
        o.dnsMode = dnsMode
        o.save()
        Task {
            if vpn.isConnected {
                status = (await vpn.reload()).map { "重载失败：\($0)" } ?? "已保存并重载"
            } else {
                status = "已保存，下次连接生效"
            }
        }
    }
}
