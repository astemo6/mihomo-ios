import SwiftUI
import NetworkExtension

@MainActor
final class RequestsModel: ObservableObject {
    @Published var active: [ConnectionItem] = []
    @Published var recent: [ConnectionItem] = []   // closed connections, newest first
    @Published var paused = false
    private var task: Task<Void, Never>?

    func start() {
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                if self?.paused == false { await self?.poll() }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    private func poll() async {
        guard let r = try? await ControllerClient.shared.connections() else { return }
        let now = r.connections ?? []
        let ids = Set(now.map(\.id))
        let closed = active.filter { !ids.contains($0.id) }.map { c -> ConnectionItem in
            var c = c; c.closedAt = Date(); return c
        }
        if !closed.isEmpty {
            recent.insert(contentsOf: closed, at: 0)
            if recent.count > 300 { recent.removeLast(recent.count - 300) }
        }
        active = now.sorted { ($0.startDate ?? .distantPast) > ($1.startDate ?? .distantPast) }
    }

    func close(_ c: ConnectionItem) async {
        try? await ControllerClient.shared.closeConnection(c.id)
        await poll()
    }

    func closeAll() async {
        try? await ControllerClient.shared.closeAllConnections()
        await poll()
    }
}

struct RequestsView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = RequestsModel()
    @StateObject private var http = HTTPLogModel()
    @State private var search = ""
    @State private var tab = 0
    @State private var confirmCloseAll = false
    @State private var harProgress: (Int, Int)?
    @State private var harShare: ShareItem?
    @State private var harError: String?

    var items: [ConnectionItem] {
        let list = tab == 0 ? model.active : model.recent
        guard !search.isEmpty else { return list }
        let q = search.lowercased()
        return list.filter {
            $0.metadata.displayHost.lowercased().contains(q) ||
            $0.chainText.lowercased().contains(q) ||
            $0.ruleText.lowercased().contains(q)
        }
    }

    var httpItems: [HTTPRequestSummary] {
        guard !search.isEmpty else { return http.items }
        return http.items.filter { $0.url.localizedCaseInsensitiveContains(search) || ($0.matched ?? []).joined().localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        NavigationStack {
            Group {
                if !vpn.isConnected {
                    NotConnectedPlaceholder(text: "连接后可查看实时请求")
                } else {
                    List {
                        Picker("", selection: $tab) {
                            Text("活跃 \(model.active.count)").tag(0)
                            Text("最近 \(model.recent.count)").tag(1)
                            Text("HTTP \(http.items.count)").tag(2)
                        }
                        .pickerStyle(.segmented)
                        .listRowBackground(Color.clear)
                        if tab == 2 {
                            if http.items.isEmpty {
                                EmptyStateRow(icon: "lock.open", title: "还没有 HTTP 请求",
                                              message: "经过 MitM / 重写引擎的 HTTP(S) 请求会显示在这里。需要在 更多 → 重写 / MitM 中启用。")
                                    .listRowBackground(Theme.card)
                            }
                            ForEach(httpItems) { r in
                                NavigationLink { HTTPRequestDetailView(id: r.id) } label: { HTTPRequestRow(r: r) }
                                    .listRowBackground(Theme.card)
                            }
                        }
                        ForEach(tab == 2 ? [] : items) { c in
                            ConnectionRow(c: c, engineMarks: http.hosts[c.metadata.host ?? ""] ?? http.hosts[c.metadata.sniffHost ?? ""])
                                .listRowBackground(Theme.card)
                                .swipeActions {
                                    if tab == 0 {
                                        Button(role: .destructive) { Task { await model.close(c) } } label: { Label("断开", systemImage: "xmark") }
                                    }
                                }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .scrollContentBackground(.hidden)
                    .searchable(text: $search, prompt: "搜索主机、规则、策略")
                }
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("请求")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button { model.paused.toggle() } label: { Image(systemName: model.paused ? "play.fill" : "pause.fill") }
                    if tab == 2 {
                        Button { exportHAR() } label: { Image(systemName: "square.and.arrow.up") }
                            .disabled(httpItems.isEmpty || harProgress != nil)
                            .accessibilityLabel(Text("导出 HAR"))
                        Button(role: .destructive) { Task { await http.clear() } } label: { Image(systemName: "trash") }
                    } else {
                        Button(role: .destructive) { confirmCloseAll = true } label: { Image(systemName: "xmark.circle") }
                    }
                }
            }
            .confirmationDialog("断开全部连接？", isPresented: $confirmCloseAll, titleVisibility: .visible) {
                Button("全部断开", role: .destructive) { Task { await model.closeAll() } }
            }
            .overlay(alignment: .bottom) {
                if let p = harProgress {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("正在导出 HAR \(p.0)/\(p.1)").font(.footnote.monospacedDigit())
                    }
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(Capsule().fill(Theme.cardHi))
                    .padding(.bottom, 12)
                }
            }
            .sheet(item: $harShare) { ActivityView(items: [$0.url]) }
            .alert("导出失败", isPresented: Binding(get: { harError != nil }, set: { if !$0 { harError = nil } })) {
                Button("好") { harError = nil }
            } message: { Text(harError ?? "") }
        }
        .onAppear { if vpn.isConnected { model.start(); http.start() } }
        .onDisappear { model.stop(); http.stop() }
        .onChange(of: vpn.isConnected) { on in if on { model.start(); http.start() } else { model.stop(); http.stop() } }
    }
}

extension RequestsView {
    /// HAR 1.2 of the HTTP requests currently listed (search filter applies).
    func exportHAR() {
        let ids = httpItems.filter { $0.method != "TLS" }.map(\.id)
        guard !ids.isEmpty else { return }
        harProgress = (0, ids.count)
        Task {
            do {
                let url = try await HARExport.export(ids: ids) { done, total in harProgress = (done, total) }
                harProgress = nil
                harShare = ShareItem(url: url)
            } catch {
                harProgress = nil
                harError = error.localizedDescription
            }
        }
    }
}

struct ConnectionRow: View {
    let c: ConnectionItem
    /// Rules / scripts the HTTP engine matched for this host (nil = not seen by the engine).
    var engineMarks: [String]? = nil
    var isMitM: Bool { (c.chains ?? []).contains("__MITM__") }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Text((c.metadata.network ?? "tcp").uppercased())
                    .scaledFont(9, weight: .bold)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(Capsule().fill((c.metadata.network == "udp" ? Color.purple : Theme.accent).opacity(0.2)))
                if isMitM {
                    Text(c.metadata.destinationPort == "80" ? "HTTP" : "MitM")
                        .scaledFont(9, weight: .bold)
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .background(Capsule().fill(Theme.warn.opacity(0.2)))
                        .foregroundStyle(Theme.warn)
                }
                Text(c.metadata.displayHost)
                    .font(.system(.subheadline, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if isMitM, let m = engineMarks, !m.isEmpty {
                Text(m.joined(separator: " · ")).font(.caption2).foregroundStyle(Theme.accent).lineLimit(2)
            }
            HStack(spacing: 6) {
                Image(systemName: "arrow.triangle.branch").font(.caption2)
                Text(c.ruleText).lineLimit(1)
                Text("→").foregroundStyle(.secondary)
                Text(isMitM ? "MitM 引擎" : c.chainText).foregroundStyle(Theme.accent).lineLimit(1)
            }
            .font(.caption)
            HStack(spacing: 10) {
                Label(Fmt.bytes(c.upload), systemImage: "arrow.up").foregroundStyle(Theme.up)
                Label(Fmt.bytes(c.download), systemImage: "arrow.down").foregroundStyle(Theme.down)
                Spacer()
                if let s = c.startDate {
                    Text(Fmt.duration((c.closedAt ?? Date()).timeIntervalSince(s)))
                        .foregroundStyle(.secondary)
                }
                if c.closedAt != nil {
                    Text("已关闭").foregroundStyle(.secondary)
                }
            }
            .font(.caption2.monospacedDigit())
        }
        .padding(.vertical, 2)
    }
}
