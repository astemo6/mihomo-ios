import SwiftUI

// v0.8 节点探测 UI: the 解锁检测 page (更多 → 工具与数据), the per-node sheet opened from 策略, and the
// small per-node badge. All probes run in the app through PolicyProbe (see App/Core/PolicyProbe.swift).

/// Results of one 解锁检测 as rows: service, region flag, status pill.
struct UnlockResultRows: View {
    let results: [UnlockResult]

    /// v0.19: grouped by category (AI 服务 / 国际流媒体 / 港澳台与亚洲) when results span more than one.
    var groups: [(UnlockService.Category, [UnlockResult])] {
        UnlockService.Category.allCases.compactMap { c in
            let l = results.filter { $0.service.category == c }
            return l.isEmpty ? nil : (c, l)
        }
    }

    var body: some View {
        let g = groups
        ForEach(g.indices, id: \.self) { i in
            if g.count > 1 {
                Text(verbatim: g[i].0.title.uppercased())
                    .font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                    .padding(.top, i == 0 ? 0 : 6)
                    .accessibilityAddTraits(.isHeader)
            }
            rows(g[i].1)
        }
    }

    @ViewBuilder
    func rows(_ list: [UnlockResult]) -> some View {
        ForEach(list) { r in
            HStack(spacing: 10) {
                Image(systemName: r.service.symbol)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 22)
                    .accessibilityHidden(true)
                Text(r.service.title).font(.subheadline)
                Spacer(minLength: 8)
                if let region = r.region {
                    Text("\(r.flag ?? "") \(region)").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Text(r.statusText)
                    .font(.caption.weight(.semibold))
                    .lineLimit(1)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(r.color.opacity(0.18)))
                    .foregroundStyle(r.color)
            }
            .accessibilityElement(children: .combine)
            if r.status != .yes, let note = r.note, r.status != .partial {
                Text(note).font(.caption2).foregroundStyle(.secondary).padding(.leading, 32)
            }
        }
    }
}

/// "解锁 n/m" capsule on a node cell (from the last 解锁检测 of that node).
struct UnlockBadge: View {
    let ok: Int
    let total: Int

    var body: some View {
        HStack(spacing: 2) {
            Image(systemName: "lock.open.fill").scaledFont(8, weight: .bold)
            Text(verbatim: "\(ok)/\(total)").scaledFont(9, weight: .bold, monospacedDigit: true)
        }
        .foregroundStyle(ok == total ? Theme.good : (ok == 0 ? Theme.bad : Theme.warn))
        .accessibilityLabel(Text("解锁 \(ok)/\(total)"))
    }
}

/// Opened from a node's context menu on 策略: its exit IP / region / ASN and 解锁检测.
struct NodeProbeSheet: View {
    let policy: String
    @ObservedObject private var store = ProbeStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var exitError: String?
    @State private var unlockError: String?
    @State private var exitLoading = false
    @State private var unlockLoading = false

    var body: some View {
        NavigationStack {
            List {
                let e = store.entry(policy)
                Section {
                    ExitInfoRow(info: e?.exit, loading: exitLoading, failed: exitError != nil,
                                placeholder: String(localized: "出口 · \(policy)"), showOrg: true, fields: ExitDetailField.legacy)
                        .padding(.vertical, 4)
                    if let exitError { ErrorRow(message: exitError) }
                    Button {
                        Task { await lookupExit() }
                    } label: {
                        Label(exitLoading ? "正在查询…" : "重新查询出口", systemImage: "arrow.clockwise")
                    }
                    .disabled(exitLoading || unlockLoading)
                    if let ip = e?.exit {
                        Button {
                            UIPasteboard.general.string = ip.copyText
                            UINotificationFeedbackGenerator().notificationOccurred(.success)
                        } label: { Label("复制出口信息", systemImage: "doc.on.doc") }
                    }
                } header: { Text("出口") } footer: {
                    if let d = e?.exitDate { Text("查询于 \(d.formatted(date: .abbreviated, time: .shortened)) · \(e?.exit?.source ?? "")") }
                }
                .listRowBackground(Theme.card)

                Section {
                    if let r = e?.unlock, !r.isEmpty {
                        UnlockResultRows(results: r)
                    } else if !unlockLoading {
                        Text("还没有检测过这个节点").font(.footnote).foregroundStyle(.secondary)
                    }
                    if let unlockError { ErrorRow(message: unlockError) }
                    Button {
                        Task { await runUnlock() }
                    } label: {
                        HStack {
                            Label(unlockLoading ? "正在检测…" : "开始解锁检测", systemImage: "play.circle")
                            if unlockLoading { Spacer(); ProgressView().controlSize(.small) }
                        }
                    }
                    .disabled(exitLoading || unlockLoading)
                } header: { Text("解锁检测") } footer: {
                    if let d = e?.unlockDate { Text("检测于 \(d.formatted(date: .abbreviated, time: .shortened))") }
                }
                .listRowBackground(Theme.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(policy)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } } }
            .task {
                // Fresh enough results (10 min) are shown as they are.
                if let d = store.entry(policy)?.exitDate, Date().timeIntervalSince(d) < 600 { return }
                await lookupExit()
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func lookupExit() async {
        exitLoading = true
        exitError = await store.probeExit(policy)
        exitLoading = false
    }

    private func runUnlock() async {
        unlockLoading = true
        unlockError = await store.probeUnlock(policy)
        unlockLoading = false
    }
}

/// 更多 → 工具与数据 → 解锁检测: pick a group (its current selection) or one of its nodes, then check.
struct UnlockView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var store = ProbeStore.shared
    /// Read once when the page is built (review 6): was CoreOverrides.load() (Keychain + file) in body, re-run on every probe result.
    @State private var probePort = CoreOverrides.load().probePort
    @State private var all: [String: ProxyItem] = [:]
    @State private var groups: [String] = []
    @AppStorage("unlock.group", store: AppShared.defaults) private var group = ""
    @AppStorage("unlock.member", store: AppShared.defaults) private var member = ""
    @State private var error: String?
    @State private var running = false
    @State private var batch: Task<Void, Never>?
    @State private var batchDone = 0
    @State private var batchTotal = 0

    private static let skipMembers: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]

    @AppStorage(ProbeStore.autoKey, store: AppShared.defaults) private var autoRetest = false
    @State private var selectedCount = UnlockService.selected.count

    var members: [String] { (all[group]?.all ?? []).filter { !Self.skipMembers.contains($0) } }
    var policy: String { member.isEmpty ? group : member }

    var body: some View {
        List {
            if !vpn.isConnected {
                Section {
                    EmptyStateRow(icon: "lock.open", title: "连接后可用",
                                  message: "解锁检测经由正在运行的内核，按所选策略发出请求。请先连接代理。")
                }
                .listRowBackground(Theme.card)
                optionsSection
            } else {
                optionsSection
                Section {
                    Picker("策略组", selection: $group) {
                        ForEach(groups, id: \.self) { Text($0).tag($0) }
                    }
                    Picker("节点", selection: $member) {
                        Text("组的当前选择\(all[group]?.now.map { "（\($0)）" } ?? "")").tag("")
                        ForEach(members, id: \.self) { Text($0).tag($0) }
                    }
                } header: { Text("检测对象") }
                .listRowBackground(Theme.card)

                let e = store.entry(policy)
                Section {
                    ExitInfoRow(info: e?.exit, loading: running && e?.exit == nil, failed: false,
                                placeholder: String(localized: "出口 · \(policy)"), showOrg: true, fields: ExitDetailField.legacy)
                        .padding(.vertical, 4)
                    if let r = e?.unlock, !r.isEmpty { UnlockResultRows(results: r) }
                    if let error { ErrorRow(message: error) }
                    Button {
                        Task { await runOne() }
                    } label: {
                        HStack {
                            Label(running && batch == nil ? "正在检测…" : "开始检测", systemImage: "play.circle.fill")
                            if running && batch == nil { Spacer(); ProgressView().controlSize(.small) }
                        }
                    }
                    .disabled(running || policy.isEmpty)
                } header: { Text("结果") } footer: {
                    if let d = e?.unlockDate { Text("检测于 \(d.formatted(date: .abbreviated, time: .shortened))") }
                }
                .listRowBackground(Theme.card)

                if member.isEmpty && !members.isEmpty {
                    Section {
                        if batch != nil {
                            HStack {
                                ProgressView(value: Double(batchDone), total: Double(max(batchTotal, 1)))
                                Text(verbatim: "\(batchDone)/\(batchTotal)").font(.caption.monospacedDigit())
                            }
                            Button("停止", role: .destructive) { batch?.cancel() }
                        } else {
                            Button {
                                startBatch()
                            } label: { Label("逐个检测组内 \(members.count) 个节点", systemImage: "list.bullet.circle") }
                            .disabled(running)
                        }
                        ForEach(members, id: \.self) { m in
                            HStack {
                                Text(m).font(.footnote).lineLimit(1)
                                Spacer()
                                if store.running.contains(m) { ProgressView().controlSize(.small) }
                                if let cc = store.entry(m)?.exit?.countryCode { Text(store.entry(m)?.exit?.flag ?? cc) }
                                if let b = store.badge(for: m) { UnlockBadge(ok: b.ok, total: b.total) }
                            }
                            .contentShape(Rectangle())
                            .onTapGesture { member = m }
                        }
                    } header: { Text("组内节点") } footer: {
                        Text("逐个检测时，每个节点依次经由同一个内部策略组发出请求，耗时约每个节点 10 秒。")
                    }
                    .listRowBackground(Theme.card)
                }

                Section {
                    Button("清除检测记录", role: .destructive) { store.clear() }
                } footer: {
                    Text("检测在本 App 内进行：请求经由本机回环端口 \(String(probePort)) 送入内核，再按所选策略发出，不经过分流规则。结果按各服务网页与接口的公开表现判断，服务改版后可能失准；「检测失败」表示没能读出结果，不代表被封锁。")
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("流媒体解锁") // ui-audit: same name as the 工具 card
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .task(id: vpn.isConnected) { await load() }
        .onChange(of: group) { _ in member = "" }
        .onDisappear { batch?.cancel() }
    }

    /// v0.19: what to check and the auto re-test switch (also while disconnected).
    var optionsSection: some View {
        Section {
            NavigationLink { UnlockServicesView { selectedCount = UnlockService.selected.count } } label: {
                LabeledContent("检测项目") { Text(verbatim: "\(selectedCount)/\(UnlockService.allCases.count)").monospacedDigit() }
            }
            .accessibilityIdentifier("unlock.services")
            Toggle("切换节点后自动重新检测", isOn: $autoRetest)
                .accessibilityIdentifier("unlock.auto")
        } footer: {
            if autoRetest { Text("选「组的当前选择」时，在策略页或首页切换这个组的节点后约 3 秒自动重新检测。") }
        }
        .listRowBackground(Theme.card)
    }

    private func load() async {
        guard vpn.isConnected else { return }
        do {
            let p = try await ControllerClient.shared.proxies()
            all = p
            let order = LiveGroupOrder.names(p)
            groups = order.filter { p[$0]?.isGroup == true && p[$0]?.hidden != true }
            if !groups.contains(group) { group = groups.first ?? "" }
            if !member.isEmpty && !members.contains(member) { member = "" }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func runOne() async {
        running = true
        error = await store.probeUnlock(policy)
        running = false
    }

    private func startBatch() {
        let list = members
        batchTotal = list.count
        batchDone = 0
        running = true
        // ui-audit: clear the previous run's error, or `error == nil` below kept the old one and hid every new failure.
        error = nil
        batch = Task {
            for m in list {
                if Task.isCancelled { break }
                if let e = await store.probeUnlock(m), error == nil { error = "\(m)：\(e)" }
                batchDone += 1
            }
            running = false
            batch = nil
        }
    }
}

/// v0.19 解锁检测 → 检测项目: services by category, each one on / off (at least one stays on).
struct UnlockServicesView: View {
    var changed: () -> Void
    @State private var on: Set<UnlockService> = Set(UnlockService.selected)

    var body: some View {
        List {
            ForEach(UnlockService.Category.allCases) { c in
                Section {
                    ForEach(c.services) { s in
                        Toggle(isOn: Binding(get: { on.contains(s) }, set: { v in set(s, v) })) {
                            Label { Text(verbatim: s.title) } icon: { Image(systemName: s.symbol).foregroundStyle(Theme.accent) }
                        }
                        .accessibilityIdentifier("unlock.service.\(s.rawValue)")
                    }
                } header: {
                    HStack {
                        Text(verbatim: c.title)
                        Spacer()
                        Button(c.services.allSatisfy { on.contains($0) } ? LocalizedStringKey("全不选") : LocalizedStringKey("全选")) { toggleAll(c) }
                            .font(.caption).textCase(nil)
                    }
                }
                .listRowBackground(Theme.card)
            }
            Section {
                EmptyView()
            } footer: {
                Text("只检测开启的项目，结果按类别显示。每个项目约 1–3 个请求，同时进行，单项最长 10 秒。")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("检测项目")
        .navigationBarTitleDisplayMode(.inline)
    }

    func set(_ s: UnlockService, _ v: Bool) {
        if v { on.insert(s) } else if on.count > 1 { on.remove(s) }
        save()
    }

    func toggleAll(_ c: UnlockService.Category) {
        if c.services.allSatisfy({ on.contains($0) }) {
            let rest = on.subtracting(c.services)
            if !rest.isEmpty { on = rest }
        } else {
            on.formUnion(c.services)
        }
        save()
    }

    func save() {
        UnlockService.setSelected(UnlockService.allCases.filter { on.contains($0) })
        changed()
    }
}
