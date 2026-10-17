import SwiftUI

/// 订阅管理 (v0.9): every subscription in one list — config subscriptions (remote profiles), node
/// providers inside the current profile (incl. QX server_remote imports) and node subscriptions the user
/// added (merged into every profile as proxy-providers).
struct SubscriptionsView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var nodes = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @State private var parserURL = ResourceParserSetting.url
    @State private var showAdd = false
    @State private var editingProfile: Profile?
    @State private var editingSub: NodeSubscription?
    @State private var rulesFor: RulesTarget?
    @State private var message: String?
    @State private var busyAll = false

    struct RulesTarget: Identifiable {
        let id = UUID()
        let profile: Profile
        var key: String? = nil
        var path: String? = nil
        var title: String
    }

    var remoteProfiles: [Profile] { store.profiles.filter { $0.kind == .remote } }
    /// Providers of the current profile that are not our own node subscriptions.
    var profileProviders: [InspectProvider] {
        let ours = Set(nodes.subs.map(\.name))
        return offline.result.proxyProviders.filter { $0.vehicle == "http" && !ours.contains($0.name) }
    }

    var body: some View {
        List {
            Section {
                if remoteProfiles.isEmpty {
                    Text("没有配置订阅。在「配置」页 + → 添加订阅链接。").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(remoteProfiles) { p in profileCard(p) }
            } header: { Text("配置订阅 \(remoteProfiles.count)") }
            .listRowBackground(Theme.card)

            Section {
                if nodes.subs.isEmpty {
                    Text("节点订阅只提供节点，会以节点集的形式加入每个配置的策略组。轻点右上角 + 添加。").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(nodes.subs) { s in nodeSubCard(s) }
            } header: { Text("节点订阅 \(nodes.subs.count)") }
            .listRowBackground(Theme.card)

            if !profileProviders.isEmpty {
                Section {
                    ForEach(profileProviders) { pv in providerCard(pv) }
                } header: { Text("当前配置中的节点集 \(profileProviders.count)") } footer: {
                    Text("来自当前配置的 proxy-providers（包括 Quantumult X 的 server_remote）。")
                }
                .listRowBackground(Theme.card)
            }

            UpdateNotifySection()

            // v0.12: QX resource_parser_url, stored only (mihomo parses resources natively).
            Section {
                DisclosureGroup("高级") {
                    TextField("资源解析器地址（resource_parser_url）", text: $parserURL, axis: .vertical)
                        .font(.footnote.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        .onSubmit { ResourceParserSetting.url = parserURL }
                        .onChange(of: parserURL) { ResourceParserSetting.url = $0 }
                }
            } footer: {
                Text("Mihomo 直接识别 Quantumult X / Surge / Clash / sing-box / 分享链接等格式，不需要资源解析器。这里只保存 Quantumult X 配置中的 resource_parser_url，不会下载或运行。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("订阅管理")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if busyAll { ProgressView() } else {
                    Button { Task { await updateAll() } } label: { Image(systemName: "arrow.triangle.2.circlepath") }
                        .accessibilityLabel(Text("全部更新"))
                }
                Button { showAdd = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加节点订阅"))
            }
        }
        .refreshable { await updateAll() }
        .task { await offline.load() }
        .sheet(isPresented: $showAdd) { NodeSubEditor(sub: nil).environmentObject(store) }
        .sheet(item: $editingSub) { s in NodeSubEditor(sub: s).environmentObject(store) }
        .sheet(item: $editingProfile) { p in ProfileSubEditor(profile: p).environmentObject(store) }
        .sheet(item: $rulesFor) { t in
            NavigationStack {
                SubscriptionRulesView(profile: t.profile, rulesKey: t.key, previewPath: t.path)
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("取消") { rulesFor = nil } } }
            }
            .environmentObject(store)
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    // MARK: Cards

    func profileCard(_ p: Profile) -> some View {
        let active = p.id == store.activeID
        let count = active ? offline.result.proxies.count + offline.result.proxyProviders.reduce(0) { $0 + max($1.count, 0) } : nil
        return SubscriptionCard(name: p.name, badge: "配置", active: active, enabled: true, count: count,
                                info: p.userInfo, updated: p.lastUpdated, intervalHours: p.updateIntervalHours,
                                updating: store.updating.contains(p.id), error: nil, alerts: UsageAlerts.rule(for: p.id).enabled)
            .contentShape(Rectangle())
            .onTapGesture { if !active { Task { if let e = await store.setActive(p) { message = e } } } }
            .swipeActions(edge: .trailing) {
                Button { Task { if let e = await store.refresh(p) { message = e } } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
                Button { editingProfile = p } label: { Label("编辑", systemImage: "pencil") }.tint(.indigo)
            }
            .contextMenu {
                if !active { Button { Task { _ = await store.setActive(p) } } label: { Label("设为当前配置", systemImage: "checkmark.circle") } }
                Button { Task { if let e = await store.refresh(p) { message = e } } } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                Button { editingProfile = p } label: { Label("编辑链接 / 名称 / UA / 间隔", systemImage: "pencil") }
                Button { rulesFor = RulesTarget(profile: p, title: p.name) } label: { Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle") }
                Button { UIPasteboard.general.string = p.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
                Button(role: .destructive) { store.delete(p) } label: { Label("删除", systemImage: "trash") }
            }
    }

    func nodeSubCard(_ s: NodeSubscription) -> some View {
        SubscriptionCard(name: s.name, badge: "节点", active: false, enabled: s.enabled, count: s.count,
                         info: s.userInfo, updated: s.lastUpdated, intervalHours: s.updateIntervalHours,
                         updating: nodes.updating.contains(s.id), error: s.lastError, alerts: UsageAlerts.rule(for: s.id).enabled)
            .swipeActions(edge: .trailing) {
                Button(role: .destructive) { Task { await nodes.delete(s) } } label: { Label("删除", systemImage: "trash") }
                Button { editingSub = s } label: { Label("编辑", systemImage: "pencil") }.tint(.indigo)
            }
            .swipeActions(edge: .leading) {
                Button { Task { if let e = await nodes.refresh(s) { message = e } } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
            }
            .contextMenu {
                Button { Task { var n = s; n.enabled.toggle(); await nodes.save(n) } } label: {
                    Label(LocalizedStringKey(s.enabled ? "停用" : "启用"), systemImage: s.enabled ? "pause.circle" : "play.circle")
                }
                Button { Task { if let e = await nodes.refresh(s) { message = e } } } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                Button { editingSub = s } label: { Label("编辑链接 / 名称 / UA / 间隔", systemImage: "pencil") }
                if let p = store.active {
                    Button { rulesFor = RulesTarget(profile: p, key: s.rulesKey, path: s.cacheURL.path, title: s.name) } label: {
                        Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle")
                    }
                }
                Button { UIPasteboard.general.string = s.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
                Button(role: .destructive) { Task { await nodes.delete(s) } } label: { Label("删除", systemImage: "trash") }
            }
    }

    func providerCard(_ pv: InspectProvider) -> some View {
        let key = "proxy:" + pv.name
        return SubscriptionCard(name: pv.name, badge: "节点", active: false, enabled: true, count: pv.cached ? pv.count : nil,
                                info: nil, updated: pv.cachedDate, intervalHours: (pv.interval ?? 0) / 3600,
                                updating: updater.busy.contains(key), error: updater.errors[key], note: "来自配置")
            .swipeActions(edge: .leading) {
                Button { Task { await updater.update(key) } } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
            }
            .contextMenu {
                Button { Task { await updater.update(key) } } label: { Label("更新", systemImage: "arrow.clockwise") }
                if let u = pv.url { Button { UIPasteboard.general.string = u } label: { Label("复制订阅链接", systemImage: "doc.on.doc") } }
            }
    }

    func updateAll() async {
        busyAll = true
        defer { busyAll = false }
        var errs = await store.refreshAll()
        errs += await nodes.refreshAll()
        let r = await updater.updateAll(only: Set(profileProviders.map { "proxy:" + $0.name }))
        if r.failed > 0 { errs.append(String(localized: "\(r.failed) 个配置内节点集更新失败")) }
        if !errs.isEmpty { message = errs.joined(separator: "\n") }
    }
}

/// One subscription card: name + badge, node count, traffic bar, expiry, last update, interval.
struct SubscriptionCard: View {
    let name: String
    let badge: String
    let active: Bool
    let enabled: Bool
    let count: Int?
    let info: SubscriptionUserInfo?
    let updated: Date?
    let intervalHours: Int
    let updating: Bool
    let error: String?
    var note: String? = nil
    var alerts = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(name).font(.subheadline.weight(.semibold)).lineLimit(1)
                Text(LocalizedStringKey(badge))
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Capsule().fill((badge == "配置" ? Theme.accent : Theme.good).opacity(0.16)))
                    .foregroundStyle(badge == "配置" ? Theme.accent : Theme.good)
                if active { Image(systemName: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.accent).accessibilityLabel(Text("当前配置")) }
                if !enabled { Text("已停用").font(.caption2).foregroundStyle(.secondary) }
                if alerts { Image(systemName: "bell.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("用量提醒")) }
                Spacer()
                if updating { ProgressView().controlSize(.small) }
                else if let count { Text("\(count) 个节点").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
            }
            if let info, info.total > 0 {
                ProgressView(value: info.fraction).tint(info.fraction > 0.9 ? Theme.bad : info.fraction > 0.75 ? Theme.warn : Theme.accent)
                HStack {
                    Text("已用 \(Fmt.bytes(info.used)) / \(Fmt.bytes(info.total))").font(.caption2.monospacedDigit())
                    Spacer()
                    Text("剩余 \(Fmt.bytes(max(info.total - info.used, 0)))").font(.caption2.monospacedDigit())
                }
                .foregroundStyle(.secondary)
            }
            HStack(spacing: 10) {
                if let d = info?.expireDate {
                    Label(d.formatted(date: .abbreviated, time: .omitted), systemImage: "calendar")
                        .foregroundStyle(d < Date().addingTimeInterval(7 * 86400) ? Theme.warn : .secondary)
                }
                if let updated { Label(updated.formatted(.relative(presentation: .named)), systemImage: "clock") }
                Label(intervalHours > 0 ? String(localized: "每 \(intervalHours) 小时") : String(localized: "手动更新"), systemImage: "arrow.clockwise")
                if let note { Text(LocalizedStringKey(note)) }
            }
            .font(.caption2).foregroundStyle(.secondary).labelStyle(.titleAndIcon).lineLimit(1)
            if let error { Text(error).font(.caption2).foregroundStyle(Theme.bad).lineLimit(2) }
        }
        .padding(.vertical, 4)
        .opacity(enabled ? 1 : 0.55)
        .accessibilityElement(children: .combine)
    }
}

/// Add / edit a node subscription: URL, name, UA, interval, groups that include it.
struct NodeSubEditor: View {
    let sub: NodeSubscription?
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var nodes = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State private var url = ""
    @State private var name = ""
    @State private var ua = "clash.meta"
    @State private var interval = 24
    @State private var customGroups = false
    @State private var groups: Set<String> = []
    @State private var alert = UsageAlertRule()
    @State private var busy = false
    @State private var error: String?

    var groupNames: [String] { offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name) }

    var body: some View {
        NavigationStack {
            Form {
                Section("订阅") {
                    TextField("订阅链接 https://…", text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("名称（留空自动获取）", text: $name)
                }
                .listRowBackground(Theme.card)
                Section("选项") {
                    Picker("User-Agent", selection: $ua) {
                        Text("clash.meta").tag("clash.meta")
                        Text("mihomo").tag("mihomo")
                        Text("Quantumult X").tag("Quantumult%20X/1.5.2")
                        Text("Shadowrocket").tag("Shadowrocket/2070")
                    }
                    Picker("自动更新", selection: $interval) {
                        Text("关闭").tag(0)
                        Text("每 6 小时").tag(6)
                        Text("每 12 小时").tag(12)
                        Text("每天").tag(24)
                        Text("每周").tag(168)
                    }
                }
                .listRowBackground(Theme.card)
                Section {
                    Toggle("指定策略组", isOn: $customGroups)
                    if customGroups {
                        ForEach(groupNames, id: \.self) { g in
                            Toggle(g, isOn: Binding(get: { groups.contains(g) }, set: { if $0 { groups.insert(g) } else { groups.remove(g) } }))
                        }
                    }
                } header: { Text("加入的策略组") } footer: {
                    Text("默认加入含节点的手动选择组和自动选择（url-test）组；这些组在别的配置中不存在时也按默认处理。")
                }
                .listRowBackground(Theme.card)
                UsageAlertSection(rule: $alert)
                if let error { Section { Text(error).foregroundStyle(Theme.bad).font(.footnote) }.listRowBackground(Theme.card) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(sub == nil ? "添加节点订阅" : "编辑节点订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button(sub == nil ? "添加" : "保存") { Task { await save() } }
                            .disabled(!url.hasPrefix("http"))
                    }
                }
            }
            .onAppear {
                if let s = sub {
                    url = s.url; name = s.name; ua = s.userAgent; interval = s.updateIntervalHours
                    alert = UsageAlerts.rule(for: s.id)
                    if let g = s.groups, !g.isEmpty { customGroups = true; groups = Set(g) }
                }
            }
        }
    }

    func save() async {
        busy = true
        defer { busy = false }
        let g: [String]? = customGroups && !groups.isEmpty ? groupNames.filter { groups.contains($0) } : nil
        if var s = sub {
            let urlChanged = s.url != url || s.userAgent != ua
            s.url = url; s.name = name; s.userAgent = ua; s.updateIntervalHours = interval; s.groups = g
            UsageAlerts.setRule(alert, for: s.id)
            await nodes.save(s)
            if urlChanged, let e = await nodes.refresh(s) { error = e; return }
            dismiss()
        } else {
            do {
                let s = try await nodes.add(url: url, name: name, userAgent: ua, intervalHours: interval, groups: g)
                UsageAlerts.setRule(alert, for: s.id)
                UsageAlerts.evaluate(id: s.id, name: s.name, info: s.userInfo)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

/// Edit a config subscription's URL / name / UA / interval.
struct ProfileSubEditor: View {
    let profile: Profile
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var url = ""
    @State private var name = ""
    @State private var ua = "clash.meta"
    @State private var interval = 24
    @State private var alert = UsageAlertRule()
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section("订阅") {
                    TextField("订阅链接 https://…", text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("名称", text: $name)
                }
                .listRowBackground(Theme.card)
                Section("选项") {
                    Picker("User-Agent", selection: $ua) {
                        Text("clash.meta").tag("clash.meta")
                        Text("mihomo").tag("mihomo")
                        Text("clash-verge/v2").tag("clash-verge/v2")
                    }
                    Picker("自动更新", selection: $interval) {
                        Text("关闭").tag(0)
                        Text("每 6 小时").tag(6)
                        Text("每 12 小时").tag(12)
                        Text("每天").tag(24)
                        Text("每周").tag(168)
                    }
                }
                .listRowBackground(Theme.card)
                UsageAlertSection(rule: $alert)
                if let error { Section { Text(error).foregroundStyle(Theme.bad).font(.footnote) }.listRowBackground(Theme.card) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("编辑订阅").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else { Button("保存") { Task { await save() } }.disabled(!url.hasPrefix("http") || name.isEmpty) }
                }
            }
            .onAppear {
                url = profile.url ?? ""; name = profile.name; ua = profile.userAgent; interval = profile.updateIntervalHours
                alert = UsageAlerts.rule(for: profile.id)
            }
        }
    }

    func save() async {
        busy = true
        defer { busy = false }
        var p = profile
        let changed = p.url != url || p.userAgent != ua
        p.url = url; p.name = name; p.userAgent = ua; p.updateIntervalHours = interval
        store.update(p)
        UsageAlerts.setRule(alert, for: p.id)
        UsageAlerts.evaluate(id: p.id, name: p.name, info: p.userInfo)
        if changed, let e = await store.refresh(p) { error = e; return }
        dismiss()
    }
}

// MARK: - v0.14 notifications

/// 用量提醒 in both subscription editors: quota threshold + days before expiry.
struct UsageAlertSection: View {
    @Binding var rule: UsageAlertRule

    var body: some View {
        Section {
            Toggle("用量提醒", isOn: $rule.enabled)
            if rule.enabled {
                Picker("流量用到", selection: $rule.quotaPercent) {
                    Text("关闭").tag(0)
                    ForEach(UsageAlertRule.quotaChoices, id: \.self) { Text("\($0)%").tag($0) }
                }
                Picker("到期前", selection: $rule.expiryDays) {
                    Text("关闭").tag(0)
                    ForEach(UsageAlertRule.expiryChoices, id: \.self) { Text("\($0) 天").tag($0) }
                }
            }
        } header: { Text("提醒") } footer: {
            Text("用订阅返回的流量与到期信息（subscription-userinfo）发本地通知：每次更新后检查流量，用完时再提醒一次；到期提醒由系统按时送达，不需要打开 App。没有这些信息的订阅不会提醒。")
        }
        .listRowBackground(Theme.card)
    }
}

/// 订阅管理 → 通知: opt-in summary after automatic updates.
struct UpdateNotifySection: View {
    @State private var on = ScheduledUpdates.notifyEnabled
    @State private var mode = ScheduledUpdates.mode
    @State private var denied = false

    var body: some View {
        Section {
            Toggle("自动更新后通知", isOn: $on)
                .onChange(of: on) { ScheduledUpdates.notifyEnabled = $0 }
            if on {
                Picker("何时通知", selection: $mode) {
                    ForEach(UpdateNotifyMode.allCases) { Text(LocalizedStringKey($0.title)).tag($0) }
                }
                .onChange(of: mode) { ScheduledUpdates.mode = $0 }
            }
            if denied && (on || hasAlerts) {
                Button {
                    if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                } label: {
                    Label("通知已在系统设置中关闭，轻点前往打开", systemImage: "bell.slash").font(.footnote).foregroundStyle(Theme.warn)
                }
            }
        } header: { Text("通知") } footer: {
            Text("按各订阅的更新间隔自动更新（打开 App 时，以及系统允许的后台刷新）。成功默认不打扰；失败或节点数减少三成以上时提醒。")
        }
        .listRowBackground(Theme.card)
        .task { denied = await NotificationAuth.allowed() == false }
    }

    var hasAlerts: Bool {
        ProfileStore.shared.profiles.contains { UsageAlerts.rule(for: $0.id).enabled }
            || NodeSubStore.shared.subs.contains { UsageAlerts.rule(for: $0.id).enabled }
    }
}
