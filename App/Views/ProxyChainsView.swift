import SwiftUI

/// 工具 → 节点与订阅 → 代理链 (Loon 代理链): the list of chains. A row shows the hops in order; the switch is 启用,
/// tap edits, left swipe 删除, long-press shows every action. bridge/proxychains.go builds the chains.
struct ProxyChainsView: View {
    @ObservedObject private var store = ProxyChainStore.shared
    @State private var editing: ProxyChain?
    @State private var adding = false
    @State private var confirmDelete: ProxyChain?
    @State private var message: String?

    var body: some View {
        List {
            Section {
                if store.chains.isEmpty {
                    EmptyStateRow(icon: "link", title: "还没有代理链", message: "点右上角 + 添加。代理链让流量依次经过多个节点或策略组。")
                }
                ForEach(store.chains) { c in row(c) }
                    .onMove { from, to in Task { if let e = await store.move(from: from, to: to) { message = e } } }
            } footer: {
                if !store.chains.isEmpty {
                    Text("启用的代理链会作为策略出现在策略组和规则里。成员在当前配置里找不到时，这条链不生效。")
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("代理链")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if store.chains.count > 1 { EditButton() }
                Button { adding = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel(Text("添加代理链"))
                    .accessibilityIdentifier("chains.add")
            }
        }
        .onAppear { store.reload() }
        .sheet(isPresented: $adding) { ProxyChainEditor(chain: ProxyChain(name: ""), isNew: true) }
        .sheet(item: $editing) { c in ProxyChainEditor(chain: c, isNew: false) }
        .deleteConfirmation({ c in Text("删除代理链「\(c.name)」？") }, item: $confirmDelete,
                            message: { _ in Text("引用它的策略组和规则会一并移除这条链。") },
                            id: "chain.confirmDelete") { c in
            Task { if let e = await store.delete(c) { message = e } }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    func setEnabled(_ c: ProxyChain, _ on: Bool) {
        Task { if let e = await store.setEnabled(c, on) { message = e } }
    }

    @ViewBuilder
    func row(_ c: ProxyChain) -> some View {
        HStack(spacing: 12) {
            Button { editing = c } label: {
                HStack(spacing: 12) {
                    SourceIcon(systemName: "link", color: c.enabled ? Theme.accent : .secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(c.name).font(.subheadline.weight(.semibold)).foregroundStyle(.primary).lineLimit(1)
                            if c.udp {
                                Text(verbatim: "UDP").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
                            }
                        }
                        Text(c.members.isEmpty ? String(localized: "还没有成员") : c.members.joined(separator: " → "))
                            .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("chain.row." + c.name)
            Toggle("", isOn: Binding(get: { c.enabled }, set: { on in setEnabled(c, on) }))
                .labelsHidden()
                .accessibilityLabel(Text(verbatim: c.name))
                .accessibilityIdentifier("chain.row." + c.name + ".toggle")
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) { confirmDelete = c } label: { Label("删除", systemImage: "trash") }
        }
        .contextMenu {
            Button { editing = c } label: { Label("编辑", systemImage: "pencil") }
            if c.enabled {
                Button { setEnabled(c, false) } label: { Label("停用", systemImage: "pause.circle") }
            } else {
                Button { setEnabled(c, true) } label: { Label("启用", systemImage: "play.circle") }
            }
            Button(role: .destructive) { confirmDelete = c } label: { Label("删除", systemImage: "trash") }
        }
    }
}

/// Add / edit one chain: 名称, UDP, 启用 and the ordered members (entry first → exit last).
struct ProxyChainEditor: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = ProxyChainStore.shared
    let isNew: Bool
    @State private var chain: ProxyChain
    @State private var candidates: [ChainCandidate] = []
    @State private var loading = true
    @State private var showPicker = false
    @State private var confirmDelete = false
    @State private var saving = false
    @State private var message: String?

    init(chain: ProxyChain, isNew: Bool) {
        self.isNew = isNew
        _chain = State(initialValue: chain)
    }

    var trimmedName: String { chain.name.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("名称", text: $chain.name)
                        .accessibilityIdentifier("chain.name")
                    Toggle("UDP", isOn: $chain.udp)
                        .accessibilityIdentifier("chain.udp")
                    Toggle("启用", isOn: $chain.enabled)
                        .accessibilityIdentifier("chain.enabled")
                } footer: {
                    Text("关闭 UDP 后，这条链只转发 TCP。")
                }
                .listRowBackground(Theme.card)

                Section {
                    if chain.members.isEmpty {
                        Text("还没有成员").font(.footnote).foregroundStyle(.secondary)
                    }
                    ForEach(chain.members, id: \.self) { m in memberRow(m) }
                        .onDelete { chain.members.remove(atOffsets: $0) }
                        .onMove { chain.members.move(fromOffsets: $0, toOffset: $1) }
                    Button { showPicker = true } label: { Label("添加节点或策略组", systemImage: "plus.circle") }
                        .disabled(loading)
                        .accessibilityIdentifier("chain.addMember")
                } header: {
                    HStack { Text("成员 \(chain.members.count)"); Spacer(); EditButton().font(.caption) }
                } footer: {
                    Text("从上到下依次连接：第一个是入口，最后一个是出口，至少两个。左滑删除，点「编辑」拖动排序。")
                }
                .listRowBackground(Theme.card)

                if !isNew {
                    Section {
                        Button(role: .destructive) { confirmDelete = true } label: { Label("删除代理链", systemImage: "trash") }
                            .accessibilityIdentifier("chain.delete")
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(isNew ? "添加代理链" : "编辑代理链")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if saving {
                        ProgressView()
                    } else {
                        Button("保存") { Task { await save() } }
                            .disabled(trimmedName.isEmpty || chain.members.count < 2)
                            .accessibilityIdentifier("chain.save")
                    }
                }
            }
            .sheet(isPresented: $showPicker) {
                ProxyChainMemberPicker(candidates: candidates, chosen: Set(chain.members)) { picked in
                    chain.members.append(contentsOf: picked.filter { !chain.members.contains($0) })
                }
            }
            .confirmationDialog("删除代理链「\(chain.name)」？", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("删除", role: .destructive) {
                    Task {
                        let original = store.chains.first { $0.id == chain.id } ?? chain
                        if let e = await store.delete(original) { message = e } else { dismiss() }
                    }
                }
            } message: { Text("引用它的策略组和规则会一并移除这条链。") }
            .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(message ?? "") }
            .task {
                candidates = await ProxyChainCandidates.load()
                loading = false
            }
        }
    }

    func hopLabel(_ m: String) -> String {
        guard let i = chain.members.firstIndex(of: m) else { return "" }
        if i == 0 { return String(localized: "入口") }
        if i == chain.members.count - 1 { return String(localized: "出口") }
        return String(localized: "中转")
    }

    @ViewBuilder
    func memberRow(_ m: String) -> some View {
        let c = candidates.first { $0.name == m }
        HStack(spacing: 10) {
            Text(hopLabel(m)).font(.caption2.weight(.semibold)).foregroundStyle(Theme.accent)
                .frame(minWidth: 30, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(m).lineLimit(1)
                if let c {
                    Text(c.group ? String(localized: "策略组") : ProxyItem.label(for: c.type)).font(.caption2).foregroundStyle(.secondary)
                } else if !loading {
                    Text("当前配置里没有").font(.caption2).foregroundStyle(Theme.warn)
                }
            }
        }
    }

    func save() async {
        let name = trimmedName
        if name.isEmpty { message = String(localized: "名称不能为空"); return }
        if store.nameTaken(name, except: chain.id) { message = String(localized: "已有同名的代理链"); return }
        if candidates.contains(where: { $0.name == name }) || ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL"].contains(name.uppercased()) {
            message = String(localized: "已有同名的策略组或节点")
            return
        }
        if chain.members.count < 2 { message = String(localized: "至少需要两个节点或策略组"); return }
        saving = true
        var c = chain
        c.name = name
        let err = await store.save(c)
        saving = false
        if let err { message = err } else { dismiss() }
    }
}

/// Multi-select of the nodes and groups to add to a chain (current profile, without other chains).
struct ProxyChainMemberPicker: View {
    let candidates: [ChainCandidate]
    let chosen: Set<String>
    let onAdd: ([String]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var picked: [String] = []
    @State private var search = ""

    var shown: [ChainCandidate] {
        candidates.filter { !chosen.contains($0.name) && (search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)) }
    }

    var body: some View {
        NavigationStack {
            List {
                let groups = shown.filter(\.group)
                let nodes = shown.filter { !$0.group }
                if !groups.isEmpty {
                    Section("策略组 \(groups.count)") {
                        ForEach(groups, id: \.self) { c in row(c, subtitle: c.type) }
                    }
                    .listRowBackground(Theme.card)
                }
                if !nodes.isEmpty {
                    Section("节点 \(nodes.count)") {
                        ForEach(nodes, id: \.self) { c in row(c, subtitle: ProxyItem.label(for: c.type)) }
                    }
                    .listRowBackground(Theme.card)
                }
                if candidates.isEmpty {
                    EmptyStateRow(icon: "link", title: "没有可用的节点或策略组", message: "当前配置里没有节点或策略组。")
                        .listRowBackground(Theme.card)
                }
            }
            .listStyle(.insetGrouped)
            .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always))
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("添加成员").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加 \(picked.count)") { onAdd(picked); dismiss() }.disabled(picked.isEmpty)
                        .accessibilityIdentifier("chain.picker.add")
                }
            }
        }
    }

    func row(_ c: ChainCandidate, subtitle: String) -> some View {
        Button {
            if let i = picked.firstIndex(of: c.name) { picked.remove(at: i) } else { picked.append(c.name) }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.name).foregroundStyle(.primary).lineLimit(1)
                    Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                if let i = picked.firstIndex(of: c.name) {
                    Text(verbatim: "\(i + 1)").font(.caption.weight(.semibold).monospacedDigit()).foregroundStyle(Theme.accent)
                    Image(systemName: "checkmark").foregroundStyle(Theme.accent)
                }
            }
        }
    }
}
