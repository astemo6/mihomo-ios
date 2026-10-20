import SwiftUI
import UIKit

// v0.16 DNS 日志: queries and blocked domains read from the core's /logs stream (debug level). mihomo publishes
// every log event to subscribers whatever its own log-level is, so nothing changes in the tunnel; the stream
// only runs from the moment this page is opened until the app goes to the background or disconnects.
//
// Lines used (mihomo v1.19.32):
//   [DNS] example.com --> [93.184.216.34] A from https://1.1.1.1/dns-query     dns/util.go batchExchange
//   [DNS] cache hit example.com --> [93.184.216.34] A, expire at 2026-…          dns/resolver.go
//   [DNS] resolve example.com error: …                                          tunnel/tunnel.go
//   [TCP] 198.18.0.1:5000 --> ads.example.com:443 match DomainSuffix(example.com) using REJECT   tunnel/tunnel.go

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

struct BlockedDomain: Identifiable, Hashable {
    var id: String { domain }
    var domain: String
    var count: Int
    var rule: String
    var last: Date
}

@MainActor
final class DNSLogStore: ObservableObject {
    static let shared = DNSLogStore()

    @Published private(set) var queries: [DNSLogEntry] = []   // newest first
    @Published private(set) var blocked: [String: BlockedDomain] = [:]
    @Published var paused = false
    @Published private(set) var running = false
    static let limit = 2000
    private var task: Task<Void, Never>?
    private var bgObserver: NSObjectProtocol?

    var blockedSorted: [BlockedDomain] {
        blocked.values.sorted { $0.count != $1.count ? $0.count > $1.count : $0.last > $1.last }
    }
    var blockedTotal: Int { blocked.values.reduce(0) { $0 + $1.count } }

    init() {
        bgObserver = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.stop() }
        }
        if UITestSeed.enabled { seedDemo() }
    }

    /// 清空 time: the general history (REJECT lines) is shared with 日志 and not cleared from here, so entries
    /// older than this are skipped when the history is read again.
    private var clearedAt = Date.distantPast

    /// v0.19.8: the extension records DNS queries and REJECT hits from tunnel start (GET /hark/logs); the page
    /// rebuilds from that history, then attaches the live /logs stream (lines repeated across the seam skipped).
    func start() {
        guard task == nil, VPNManager.shared.isConnected else { return }
        running = true
        task = Task { [weak self] in
            var join = LogJoin(history: [])
            let c = ControllerClient.shared
            if let dns = try? await c.harkLogs(kind: "dns"), let gen = try? await c.harkLogs(kind: "general", level: "info"),
               let self, !Task.isCancelled {
                let cut = self.clearedAt
                let rejects = (gen.logs ?? []).filter { $0.payload.contains("REJECT") }
                let all = ((dns.logs ?? []) + rejects)
                    .filter { Date(timeIntervalSince1970: Double($0.time) / 1000) >= cut }
                    .sorted { $0.time != $1.time ? $0.time < $1.time : $0.seq < $1.seq }
                if !all.isEmpty {
                    self.queries = []
                    self.blocked = [:]
                    for e in all { self.ingest(e.payload, at: Date(timeIntervalSince1970: Double(e.time) / 1000)) }
                }
                join = LogJoin(history: all)
            }
            while !Task.isCancelled {
                for await l in c.stream("/logs", query: [URLQueryItem(name: "level", value: "debug")], as: LogPayload.self) {
                    guard let self else { return }
                    if Task.isCancelled { break }
                    if !self.paused && !join.isDuplicate(l.payload) { self.ingest(l.payload) }
                }
                if Task.isCancelled || !VPNManager.shared.isConnected { break }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            self?.task = nil
            self?.running = false
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        running = false
    }

    func clear() {
        queries = []
        blocked = [:]
        clearedAt = Date()
        Task { try? await ControllerClient.shared.harkClearLogs(kind: "dns") }
    }

    // MARK: Parsing

    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
    private static let answerRE = re(#"^\[DNS\] (\S+) --> (.*) (\S+) from (\S+)$"#)
    private static let cacheRE = re(#"^\[DNS\] cache hit (\S+) --> (.*) (\S+), expire at"#)
    private static let errorRE = re(#"^\[DNS\] resolve (\S+) error: (.*)$"#)
    private static let rejectRE = re(#"^\[(?:TCP|UDP)\] \S+ --> (\S+) (?:match (.+) )?using (\S*REJECT\S*)$"#)

    private static func groups(_ r: NSRegularExpression, _ s: String) -> [String]? {
        let ns = s as NSString
        guard let m = r.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }

    private static func clean(_ domain: String) -> String {
        domain.hasSuffix(".") ? String(domain.dropLast()) : domain
    }

    /// "ads.example.com:443" / "[2001:db8::1]:443" → host.
    private static func host(of address: String) -> String {
        if address.hasPrefix("["), let end = address.firstIndex(of: "]") { return String(address[address.index(after: address.startIndex)..<end]) }
        if let colon = address.lastIndex(of: ":"), address.filter({ $0 == ":" }).count == 1 { return String(address[..<colon]) }
        return address
    }

    private static func answerText(_ s: String) -> String {
        s.trimmingCharacters(in: CharacterSet(charactersIn: "[] ")).replacingOccurrences(of: " ", with: ", ")
    }

    func ingest(_ line: String, at time: Date = Date()) {
        if line.hasPrefix("[DNS]") {
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
        } else if line.hasPrefix("[TCP]") || line.hasPrefix("[UDP]"), line.contains("REJECT"), let g = Self.groups(Self.rejectRE, line) {
            let h = Self.host(of: g[0])
            guard !h.isEmpty else { return }
            var b = blocked[h] ?? BlockedDomain(domain: h, count: 0, rule: "", last: time)
            b.count += 1
            b.last = time
            b.rule = g[1].isEmpty ? g[2] : g[1]
            blocked[h] = b
        }
    }

    /// Synthetic lines for the simulator UI tests (documentation names and addresses only).
    private func seedDemo() {
        let t = Date()
        let lines = [
            "[DNS] www.example.com --> [93.184.216.34] A from https://1.1.1.1/dns-query",
            "[DNS] cache hit api.example.org --> [192.0.2.10 192.0.2.11] A, expire at 2026-10-17 22:00:00",
            "[DNS] v6.example.net --> [2001:db8::1] AAAA from 223.5.5.5",
            "[DNS] resolve broken.example.invalid error: all DNS requests failed",
            "[TCP] 198.18.0.1:50001 --> ads.example.com:443 match DomainSuffix(ads.example.com) using REJECT",
            "[TCP] 198.18.0.1:50002 --> ads.example.com:443 match DomainSuffix(ads.example.com) using REJECT",
            "[UDP] 198.18.0.1:50003 --> tracker.example.net:443 match RuleSet(ads) using AdBlock[REJECT-DROP]",
        ]
        for (i, l) in lines.enumerated() { ingest(l, at: t.addingTimeInterval(Double(i - lines.count))) }
    }
}

struct DNSLogView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var store = DNSLogStore.shared
    @State private var tab = 0
    @State private var search = ""

    private var shownQueries: [DNSLogEntry] {
        guard !search.isEmpty else { return store.queries }
        return store.queries.filter { $0.domain.localizedCaseInsensitiveContains(search) || $0.answer.localizedCaseInsensitiveContains(search) }
    }

    private var shownBlocked: [BlockedDomain] {
        let all = store.blockedSorted
        guard !search.isEmpty else { return all }
        return all.filter { $0.domain.localizedCaseInsensitiveContains(search) || $0.rule.localizedCaseInsensitiveContains(search) }
    }

    private var footer: LocalizedStringKey {
        if !vpn.isConnected { return "未连接 · 显示已记录的内容。连接后从连接开始记录。" }
        return store.running ? "从连接开始记录，最多保留最近 2000 条。拦截按域名累计 REJECT 规则命中的连接。" : "记录已停止，重新打开本页继续。"
    }

    var body: some View {
        List {
            Picker("", selection: $tab) {
                Text("查询 \(store.queries.count)").tag(0)
                Text("拦截 \(store.blockedTotal)").tag(1)
            }
            .pickerStyle(.segmented)
            .listRowBackground(Color.clear)
            .accessibilityIdentifier("dnslog.tabs")

            Section {
                if tab == 0 {
                    ForEach(shownQueries) { e in DNSQueryRow(e: e).listRowBackground(Theme.card) }
                } else {
                    ForEach(shownBlocked) { b in BlockedDomainRow(b: b).listRowBackground(Theme.card) }
                }
            } footer: {
                Text(footer)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索域名")
        .overlay {
            if (tab == 0 ? shownQueries.isEmpty : shownBlocked.isEmpty) && search.isEmpty {
                EmptyStateView(icon: tab == 0 ? "network" : "hand.raised", title: tab == 0 ? "没有 DNS 查询" : "没有被拦截的域名")
                    .allowsHitTesting(false)
            }
        }
        .navigationTitle("DNS 日志")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                if vpn.isConnected {
                    Button { store.paused.toggle() } label: { Image(systemName: store.paused ? "play.fill" : "pause.fill") }
                        .accessibilityLabel(Text(LocalizedStringKey(store.paused ? "继续" : "暂停")))
                }
                Button(role: .destructive) { store.clear() } label: { Image(systemName: "trash") }
                    .disabled(store.queries.isEmpty && store.blocked.isEmpty)
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

struct BlockedDomainRow: View {
    let b: BlockedDomain
    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: b.domain).font(.system(.subheadline, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Text(verbatim: b.rule).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 6)
            Text(verbatim: "\(b.count)")
                .font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
                .padding(.horizontal, 8).padding(.vertical, 2)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(Theme.bad.opacity(0.14)))
                .foregroundStyle(Theme.bad)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("dnslog.blocked")
    }
}
