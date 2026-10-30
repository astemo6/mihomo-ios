import SwiftUI
import UIKit

// v0.16 DNS 日志: the tunnel's DNS queries, read back from the core's recorded history.
// The lines are the canonical NCDNSLogLine formats (Shared):
//   [DNS] example.com --> [93.184.216.34] A from https://1.1.1.1/dns-query
//   [DNS] cache hit example.com --> [93.184.216.34] A, expire at 2026-…
//   [DNS] resolve example.com error: …
//
// feat/session-records (user 2026-10-29): this page is DNS QUERIES ONLY — the old 已拦截
// tab (REJECT *connection* lines aggregated by domain, never DNS answers) is removed;
// rejected connections live on the 连接 page's 已拦截 filter. Records now persist for the
// whole connection: the tunnel archives every [DNS] line to a session file
// (NCSessionArchive) behind GET /hark/logs?kind=dns, and this store keeps them all —
// reconnecting (or 清空) is what zeroes them.

struct DNSLogEntry: Identifiable, Hashable {
    let id = UUID()
    var time: Date
    var domain: String
    var qtype: String
    var answer: String
    var upstream: String
    var cached = false
    var failed = false
}

@MainActor
final class DNSLogStore: ObservableObject {
    static let shared = DNSLogStore()

    @Published private(set) var queries: [DNSLogEntry] = []   // newest first
    @Published var paused = false
    @Published private(set) var running = false
    /// Session-scale ceiling (sanity bound only — records are kept for the whole connection).
    static let limit = 100_000
    private var task: Task<Void, Never>?
    private var bgObserver: NSObjectProtocol?
    /// fix/nc-ui-smooth: live /logs lines are parsed and published at most 10 times a second.
    private lazy var batcher = UIBatcher<(String, Date)>(cap: Self.limit) { [weak self] batch in
        for (line, at) in batch { self?.ingest(line, at: at) }
    }

    init() {
        bgObserver = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.stop() }
        }
        if UITestSeed.enabled { seedDemo() }
    }

    /// 清空 time: history older than this is skipped when the history is read again.
    private var clearedAt = Date.distantPast
    /// Bumped by every start(); a finishing old task only clears `task` / `running` while it is still the current
    /// one (review 5: a stop() + start() during the history fetch let the old task null out the new one).
    private var generation = 0

    /// The extension archives DNS queries from tunnel start (GET /hark/logs?kind=dns); the page
    /// rebuilds from that history, then attaches the live /logs stream (lines repeated across the seam skipped).
    func start() {
        guard task == nil, VPNManager.shared.isConnected else { return }
        running = true
        generation += 1
        let gen = generation
        task = Task { [weak self] in
            var join = LogJoin(history: [])
            let c = ControllerClient.shared
            if let dns = try? await c.harkLogs(kind: "dns"), let self, !Task.isCancelled {
                let cut = self.clearedAt
                let all = (dns.logs ?? [])
                    .filter { Date(timeIntervalSince1970: Double($0.time) / 1000) >= cut }
                    .sorted { $0.time != $1.time ? $0.time < $1.time : $0.seq < $1.seq }
                if !all.isEmpty {
                    self.queries = []
                    for e in all { self.ingest(e.payload, at: Date(timeIntervalSince1970: Double(e.time) / 1000)) }
                }
                join = LogJoin(history: all)
            }
            while !Task.isCancelled {
                for await l in c.stream("/logs", query: [URLQueryItem(name: "level", value: "debug")], as: LogPayload.self) {
                    guard let self else { return }
                    if Task.isCancelled { break }
                    if !self.paused && l.payload.hasPrefix("[DNS]") && !join.isDuplicate(l.payload) { self.batcher.add((l.payload, Date())) }
                }
                if Task.isCancelled || !VPNManager.shared.isConnected { break }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            guard let self, self.generation == gen else { return }
            self.task = nil
            self.running = false
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        running = false
        batcher.drain()
    }

    func clear() {
        batcher.reset()
        queries = []
        clearedAt = Date()
        Task { try? await ControllerClient.shared.harkClearLogs(kind: "dns") }
    }

    // MARK: Parsing

    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
    private static let answerRE = re(#"^\[DNS\] (\S+) --> (.*) (\S+) from (\S+)$"#)
    private static let cacheRE = re(#"^\[DNS\] cache hit (\S+) --> (.*) (\S+), expire at"#)
    private static let errorRE = re(#"^\[DNS\] resolve (\S+) error: (.*)$"#)

    private static func groups(_ r: NSRegularExpression, _ s: String) -> [String]? {
        let ns = s as NSString
        guard let m = r.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }

    private static func clean(_ domain: String) -> String {
        domain.hasSuffix(".") ? String(domain.dropLast()) : domain
    }

    private static func answerText(_ s: String) -> String {
        s.trimmingCharacters(in: CharacterSet(charactersIn: "[] ")).replacingOccurrences(of: " ", with: ", ")
    }

    func ingest(_ line: String, at time: Date = Date()) {
        guard line.hasPrefix("[DNS]") else { return }
        var e: DNSLogEntry?
        if let g = Self.groups(Self.cacheRE, line) {
            e = DNSLogEntry(time: time, domain: Self.clean(g[0]), qtype: g[2], answer: Self.answerText(g[1]), upstream: "", cached: true)
        } else if let g = Self.groups(Self.answerRE, line) {
            e = DNSLogEntry(time: time, domain: Self.clean(g[0]), qtype: g[2], answer: Self.answerText(g[1]), upstream: g[3])
        } else if let g = Self.groups(Self.errorRE, line) {
            e = DNSLogEntry(time: time, domain: Self.clean(g[0]), qtype: "", answer: g[1], upstream: "", failed: true)
        }
        guard let e else { return }
        queries.insert(e, at: 0)
        if queries.count > Self.limit { queries.removeLast(queries.count - Self.limit) }
    }

    /// Synthetic lines for the simulator UI tests (documentation names and addresses only).
    private func seedDemo() {
        let t = Date()
        let lines = [
            "[DNS] www.example.com --> [93.184.216.34] A from https://1.1.1.1/dns-query",
            "[DNS] cache hit api.example.org --> [192.0.2.10 192.0.2.11] A, expire at 2026-10-17 22:00:00",
            "[DNS] v6.example.net --> [2001:db8::1] AAAA from 223.5.5.5",
            "[DNS] resolve broken.example.invalid error: all DNS requests failed",
        ]
        for (i, l) in lines.enumerated() { ingest(l, at: t.addingTimeInterval(Double(i - lines.count))) }
    }
}

struct DNSLogView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var store = DNSLogStore.shared
    @State private var search = ""

    private var shownQueries: [DNSLogEntry] {
        guard !search.isEmpty else { return store.queries }
        return store.queries.filter { $0.domain.localizedCaseInsensitiveContains(search) || $0.answer.localizedCaseInsensitiveContains(search) }
    }

    private var footer: LocalizedStringKey {
        if !vpn.isConnected { return "未连接 · 显示已记录的内容。连接后从连接开始记录。" }
        return store.running ? "从连接开始记录，本次连接内一直保留，重连后清零。" : "记录已停止，重新打开本页继续。"
    }

    var body: some View {
        List {
            if store.paused && (vpn.isConnected || UITestSeed.enabled) {
                PausedChip(id: "dnslog.paused") { store.paused = false }
                    .listRowInsets(EdgeInsets(top: 2, leading: 4, bottom: 2, trailing: 4))
                    .listRowBackground(Color.clear)
            }
            Section {
                ForEach(shownQueries) { e in DNSQueryRow(e: e).listRowBackground(Theme.card) }
            } footer: {
                Text(footer)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索域名")
        .overlay {
            if shownQueries.isEmpty && search.isEmpty {
                EmptyStateView(icon: "network", title: "没有 DNS 查询")
                    .allowsHitTesting(false)
            }
        }
        .navigationTitle("域名解析记录") // ui-audit: same name as the 工具 card
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if vpn.isConnected || UITestSeed.enabled { // UI tests: seeded demo lines, no VPN
                    PauseToggleButton(paused: $store.paused, id: "dnslog.pause")
                }
                Button(role: .destructive) { store.clear() } label: { Image(systemName: "trash") }
                    .disabled(store.queries.isEmpty)
                    .accessibilityLabel(Text("清空"))
                    .accessibilityIdentifier("dnslog.clear")
            }
        }
        .onAppear { store.start() }
        .onChange(of: vpn.isConnected) { on in if on { store.start() } else { store.stop() } }
    }
}

struct DNSQueryRow: View {
    let e: DNSLogEntry
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(verbatim: e.domain).font(.system(.subheadline, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                if !e.qtype.isEmpty { RuleTypeTag(type: e.qtype) }
                if e.cached {
                    Text("缓存").scaledFont(9, weight: .bold)
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                        .background(Capsule().fill(Theme.good.opacity(0.16)))
                        .foregroundStyle(Theme.good)
                }
            }
            Text(verbatim: e.answer.isEmpty ? "—" : e.answer)
                .scaledFont(11, design: .monospaced)
                .foregroundStyle(e.failed ? Theme.bad : Color.secondary)
                .lineLimit(2)
            HStack(spacing: 6) {
                Text(e.time.formatted(date: .omitted, time: .standard)).monospacedDigit()
                if !e.upstream.isEmpty { Text(verbatim: e.upstream).lineLimit(1).truncationMode(.middle) }
            }
            .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("dnslog.query")
    }
}
