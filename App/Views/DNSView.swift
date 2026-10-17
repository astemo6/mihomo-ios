import SwiftUI
import Darwin
import Libmihomo

/// Mirrors <home>/localdns.json (bridge/localdns.go, v0.7): 本地 DNS 映射 (mihomo `hosts:`) and 真实 IP 域名
/// (added to fake-ip-filter). Applied on top of the profile whether or not the custom DNS override is on.
struct LocalDNSSettings: Codable, Equatable {
    struct Host: Codable, Equatable, Identifiable {
        var id = UUID()
        var domain: String
        var value: String
        var disabled = false
        enum CodingKeys: String, CodingKey { case domain, value, disabled }
        init(domain: String, value: String, disabled: Bool = false) { self.domain = domain; self.value = value; self.disabled = disabled }
        init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            domain = (try? c.decode(String.self, forKey: .domain)) ?? ""
            value = (try? c.decode(String.self, forKey: .value)) ?? ""
            disabled = (try? c.decodeIfPresent(Bool.self, forKey: .disabled)) ?? false
        }
    }
    var hosts: [Host] = []
    var realIP: [String] = []

    static var url: URL { AppShared.homeURL.appendingPathComponent("localdns.json") }

    static func load() -> LocalDNSSettings {
        guard let d = try? Data(contentsOf: url), let s = try? JSONDecoder().decode(LocalDNSSettings.self, from: d) else { return LocalDNSSettings() }
        return s
    }

    func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(self) { try? d.write(to: Self.url, options: .atomic) }
    }
}

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

/// v0.13: one-tap DNS servers (Surge / Shadowrocket style presets).
struct DNSPreset: Identifiable {
    var id: String { url }
    let name: String
    let kind: String // DoH / DoT / DoQ / UDP
    let url: String

    static let domestic: [DNSPreset] = [
        DNSPreset(name: "阿里 DNS", kind: "DoH", url: "https://dns.alidns.com/dns-query"),
        DNSPreset(name: "阿里 DNS", kind: "DoT", url: "tls://dns.alidns.com"),
        DNSPreset(name: "阿里 DNS", kind: "DoQ", url: "quic://dns.alidns.com:853"),
        DNSPreset(name: "腾讯 DNSPod", kind: "DoH", url: "https://doh.pub/dns-query"),
        DNSPreset(name: "腾讯 DNSPod", kind: "DoT", url: "tls://dot.pub"),
        DNSPreset(name: "360 DNS", kind: "DoH", url: "https://doh.360.cn/dns-query"),
        DNSPreset(name: "阿里 DNS", kind: "UDP", url: "223.5.5.5"),
        DNSPreset(name: "腾讯 DNSPod", kind: "UDP", url: "119.29.29.29"),
    ]
    static let foreign: [DNSPreset] = [
        DNSPreset(name: "Cloudflare", kind: "DoH", url: "https://1.1.1.1/dns-query"),
        DNSPreset(name: "Cloudflare", kind: "DoT", url: "tls://1.1.1.1"),
        DNSPreset(name: "Google", kind: "DoH", url: "https://dns.google/dns-query"),
        DNSPreset(name: "Google", kind: "DoT", url: "tls://dns.google"),
        DNSPreset(name: "Quad9", kind: "DoH", url: "https://dns.quad9.net/dns-query"),
        DNSPreset(name: "AdGuard", kind: "DoH", url: "https://dns.adguard-dns.com/dns-query"),
        DNSPreset(name: "AdGuard", kind: "DoQ", url: "quic://dns.adguard-dns.com"),
        DNSPreset(name: "OpenDNS", kind: "DoH", url: "https://doh.opendns.com/dns-query"),
    ]
}

/// Edits a list of strings as one-per-line text.
struct LinesField: View {
    static func parse(_ t: String) -> [String] {
        t.components(separatedBy: CharacterSet(charactersIn: "\n,")).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    let title: String
    let placeholder: String
    @Binding var lines: [String]
    var presets: [DNSPreset] = []
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(LocalizedStringKey(title)).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                if !presets.isEmpty {
                    Menu {
                        ForEach(presets) { p in
                            Button {
                                guard !lines.contains(p.url) else { return }
                                text = (text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "" : text.trimmingCharacters(in: .whitespacesAndNewlines) + "\n") + p.url
                            } label: {
                                Label { Text("\(String(localized: String.LocalizationValue(p.name))) · \(p.kind)") } icon: {
                                    if lines.contains(p.url) { Image(systemName: "checkmark") }
                                }
                            }
                        }
                    } label: {
                        Label("预设", systemImage: "plus.circle").font(.caption.weight(.semibold))
                    }
                }
            }
            TextField(LocalizedStringKey(placeholder), text: $text, axis: .vertical)
                .scaledFont(12, design: .monospaced)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .lineLimit(1...8)
                .onAppear { text = lines.joined(separator: "\n") }
                .onChange(of: text) { t in
                    let l = Self.parse(t)
                    if l != lines { lines = l }
                }
                .onChange(of: lines) { l in
                    if Self.parse(text) != l { text = l.joined(separator: "\n") }
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
    @State private var local = LocalDNSSettings.load()
    @State private var newHost = ""
    @State private var newHostValue = ""
    @State private var hostError: String?
    @State private var cacheMessage: String?
    // v0.15.4: applied on change (debounced), no 保存 button. What was last written, to skip no-op applies.
    @State private var savedS = DNSOverrideSettings.load()
    @State private var savedLocal = LocalDNSSettings.load()
    @State private var savedMode = CoreOverrides.load().dnsMode
    @StateObject private var debounce = Debouncer()

    func flush(_ path: String, _ ok: String) async {
        do {
            _ = try await ControllerClient.shared.send(path, method: "POST")
            cacheMessage = ok
        } catch {
            cacheMessage = error.localizedDescription
        }
    }

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
                    LinesField(title: "国内 DNS", placeholder: "https://223.5.5.5/dns-query", lines: $s.nameserver, presets: DNSPreset.domestic)
                    if s.split {
                        LinesField(title: "国外 DNS", placeholder: "https://1.1.1.1/dns-query", lines: $s.foreign, presets: DNSPreset.foreign)
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
                            Text(p.match).scaledFont(12, design: .monospaced)
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

            hostsSection
            if VPNManager.shared.isConnected {
                // v0.12: mihomo /cache/dns/flush + /cache/fakeip/flush (QX dns_clear_cache).
                Section {
                    Button { Task { await flush("/cache/dns/flush", String(localized: "DNS 缓存已清空")) } } label: {
                        Label("清空 DNS 缓存", systemImage: "arrow.counterclockwise")
                    }
                    if dnsMode == "fake-ip" {
                        Button { Task { await flush("/cache/fakeip/flush", String(localized: "Fake-IP 缓存已清空")) } } label: {
                            Label("清空 Fake-IP 缓存", systemImage: "arrow.counterclockwise.circle")
                        }
                    }
                    if let m = cacheMessage { Text(verbatim: m).font(.footnote).foregroundStyle(.secondary) }
                } header: { Text("缓存") } footer: {
                    Text("修改 DNS 或 hosts 后清空缓存，新的解析结果立即生效。清空 Fake-IP 缓存会让已有连接重新解析。")
                }
                .listRowBackground(Theme.card)
            }
            if dnsMode == "fake-ip" {
                Section {
                    LinesField(title: "真实 IP 域名", placeholder: "+.stun.example.com", lines: $local.realIP)
                } header: { Text("真实 IP 域名") } footer: {
                    Text(s.enabled && s.fakeIPFilterMode == "whitelist"
                         ? "当前 Fake-IP 过滤是「仅列表内用 Fake-IP」，这里的域名不会生效。"
                         : "这些域名解析为真实 IP 而不是 Fake-IP（加入 fake-ip-filter），适合 STUN、游戏、局域网服务或需要真实地址的 App。支持 example.com、+.后缀、*.通配，每行一个；与配置文件自带的列表合并。")
                }
                .listRowBackground(Theme.card)
            }

            if !invalidEntries.isEmpty || status != nil {
                Section {
                    if !invalidEntries.isEmpty {
                        Label("无效：\(invalidEntries.joined(separator: ", "))", systemImage: "exclamationmark.triangle")
                            .font(.footnote).foregroundStyle(Theme.warn)
                        Text("修改前不会应用。").font(.footnote).foregroundStyle(Theme.warn)
                    }
                    AutoApplyFooter(status: status)
                }
                .listRowBackground(Theme.card)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("DNS")
        // selftest B17: the NavigationLink builds DNSView when 更多 renders, so the @State initial values above
        // are read then — reopening the page after a change showed (and would re-apply) the old settings.
        // Read the files again whenever the page appears.
        .onAppear {
            let fs = DNSOverrideSettings.load(), fl = LocalDNSSettings.load(), fm = CoreOverrides.load().dnsMode
            savedS = fs; savedLocal = fl; savedMode = fm
            if s != fs { s = fs }
            if local != fl { local = fl }
            if dnsMode != fm { dnsMode = fm }
        }
        .onChange(of: s) { _ in debounce.schedule { save() } }
        .onChange(of: local) { _ in debounce.schedule { save() } }
        .onChange(of: dnsMode) { _ in debounce.schedule { save() } }
        .onDisappear { debounce.flush() }
    }

    /// Entries the core would reject; while any exist nothing is applied.
    var invalidEntries: [String] {
        guard s.enabled else { return [] }
        var bad: [String] = []
        for e in s.nameserver + (s.split ? s.foreign : []) + s.proxyNameserver + s.directNameserver + s.policy.flatMap(\.servers)
        where !DNSServerSpec.isValidServer(e) { bad.append(e) }
        for e in s.defaultNameserver where !DNSServerSpec.isValidBootstrap(e) { bad.append(e) }
        return bad
    }

    var hostsSection: some View {
        Section {
            ForEach($local.hosts) { $h in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(h.domain).scaledFont(12, design: .monospaced).strikethrough(h.disabled)
                        Text(h.value).font(.caption2.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(get: { !h.disabled }, set: { h.disabled = !$0 }))
                        .labelsHidden()
                        .accessibilityLabel(Text("启用"))
                }
            }
            .onDelete { local.hosts.remove(atOffsets: $0) }
            VStack(spacing: 6) {
                TextField("域名，例如 router.lan 或 +.example.com", text: $newHost)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("IP（多个用逗号分隔）或一个域名", text: $newHostValue)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                if let hostError { Text(hostError).font(.caption).foregroundStyle(Theme.warn).frame(maxWidth: .infinity, alignment: .leading) }
                Button("添加") { addHost() }
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
        } header: { Text("本地 DNS 映射") } footer: {
            Text("相当于 hosts：这些域名直接解析为你填的地址，不再查询 DNS。值可以是一个或多个 IP，或一个域名（按该域名解析）。与配置文件里的 hosts 合并，同名以这里为准。左滑删除。")
        }
        .listRowBackground(Theme.card)
    }

    func addHost() {
        let d = newHost.trimmingCharacters(in: .whitespaces)
        let v = newHostValue.trimmingCharacters(in: .whitespaces)
        let err = LibmihomoValidateHostEntry(d, v)
        guard err.isEmpty else { hostError = err; return }
        hostError = nil
        if let i = local.hosts.firstIndex(where: { $0.domain.lowercased() == d.lowercased() }) {
            local.hosts[i].value = v
            local.hosts[i].disabled = false
        } else {
            local.hosts.append(.init(domain: d, value: v))
        }
        newHost = ""; newHostValue = ""
    }

    func save() {
        guard s != savedS || local != savedLocal || dnsMode != savedMode else { return }
        guard invalidEntries.isEmpty else { return }
        local.save()
        s.save()
        var o = CoreOverrides.load()
        o.dnsMode = dnsMode
        o.save()
        savedS = s; savedLocal = local; savedMode = dnsMode
        Task {
            if vpn.isConnected {
                status = (await ReloadCoalescer.shared.reload(vpn)).map { String(localized: "重载失败：\($0)") } ?? String(localized: "已保存并重载")
            } else {
                status = String(localized: "已保存，下次连接生效")
            }
        }
    }
}

/// v0.15.4: light validation for the DNS lists (applied on change, so a half-typed entry must not reach the core).
enum DNSServerSpec {
    static let schemes = ["udp", "tcp", "tls", "https", "quic", "h3", "dhcp", "system", "rcode"]

    static func isValidServer(_ e: String) -> Bool {
        let v = e.trimmingCharacters(in: .whitespaces)
        if v.isEmpty || v.contains(" ") { return false }
        if v == "system" || v == "dhcp://system" { return true }
        if let r = v.range(of: "://") {
            let scheme = v[..<r.lowerBound].lowercased()
            let rest = v[r.upperBound...]
            return schemes.contains(scheme) && !rest.isEmpty
        }
        return isHostPort(String(v.split(separator: "#").first ?? ""))
    }

    /// default-nameserver must be IP based (it resolves the DoH / DoT hosts).
    static func isValidBootstrap(_ e: String) -> Bool {
        var v = e.trimmingCharacters(in: .whitespaces)
        if let r = v.range(of: "://") {
            guard ["udp", "tcp", "tls", "dhcp"].contains(v[..<r.lowerBound].lowercased()) else { return false }
            v = String(v[r.upperBound...])
            if v == "system" { return true }
        }
        v = String(v.split(separator: "#").first ?? "")
        v = String(v.split(separator: "/").first ?? "")
        return isIP(stripPort(v))
    }

    static func stripPort(_ v: String) -> String {
        if v.hasPrefix("["), let close = v.firstIndex(of: "]") { return String(v[v.index(after: v.startIndex)..<close]) }
        let parts = v.split(separator: ":", omittingEmptySubsequences: false)
        if parts.count == 2, Int(parts[1]) != nil { return String(parts[0]) }
        return v
    }

    static func isIP(_ v: String) -> Bool {
        var a4 = in_addr(), a6 = in6_addr()
        return inet_pton(AF_INET, v, &a4) == 1 || inet_pton(AF_INET6, v, &a6) == 1
    }

    static func isHostPort(_ v: String) -> Bool {
        let h = stripPort(v)
        if isIP(h) { return true }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        return !h.isEmpty && h.contains(".") && h.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}
