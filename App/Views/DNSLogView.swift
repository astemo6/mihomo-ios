import SwiftUI
import UIKit

// v0.16 DNS 日志: queries and blocked domains read from the core's /logs stream (debug level). Clash.Meta publishes
// every log event to subscribers whatever its own log-level is, so nothing changes in the tunnel; the stream
// only runs from the moment this page is opened until the app goes to the background or disconnects.
//
// Lines used (Clash.Meta v1.19.33):
//   [DNS] example.com --> [93.184.216.34] A from https://1.1.1.1/dns-query     dns/util.go batchExchange
//   [DNS] cache hit example.com --> [93.184.216.34] A, expire at 2026-…          dns/resolver.go
//   [DNS] resolve example.com error: …                                          tunnel/tunnel.go
//   [TCP] 198.18.0.1:5000 --> ads.example.com:443 match DomainSuffix(example.com) using REJECT   tunnel/tunnel.go
//
// The 已拦截 tab is built from those REJECT *connection* lines, not from DNS answers (the core never refuses a DNS
// query here). Device report 2026-10-21: most hits were the QUIC fallback rule (UDP 443 → REJECT, apps retry over
// TCP), which read as hundreds of "blocked DNS". QUIC refusals now have their own collapsed group and count
// (RejectClassifier), and the tab counts only real blocks.

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
    /// QUIC (HTTP/3) refused so the app falls back to TCP — not a real block.
    var quic = false
    var network = ""
    var port: Int?

    /// Readable rule: 「UDP 443（QUIC）」, 「域名后缀 · ads.example.com」…
    var ruleLabel: String { RejectClassifier.friendlyRule(rule, network: network, port: port) }
}

@MainActor
final class DNSLogStore: ObservableObject {
    static let shared = DNSLogStore()

    @Published private(set) var queries: [DNSLogEntry] = []   // newest first
    @Published private(set) var blocked: [String: BlockedDomain] = [:]      // real blocks (ads, trackers, user rules)
    @Published private(set) var quicBlocked: [String: BlockedDomain] = [:]  // QUIC refused → TCP fallback
    @Published var paused = false
    @Published private(set) var running = false
    static let limit = 2000
    private var task: Task<Void, Never>?
    private var bgObserver: NSObjectProtocol?
    /// fix/nc-ui-smooth: live /logs lines are parsed and published at most 10 times a second (each line used to
    /// insert into the 2000-row list and re-render the page on its own).
    private lazy var batcher = UIBatcher<(String, Date)>(cap: Self.limit) { [weak self] batch in
        for (line, at) in batch { self?.ingest(line, at: at) }
    }

    var blockedSorted: [BlockedDomain] { Self.sorted(blocked) }
    var quicSorted: [BlockedDomain] { Self.sorted(quicBlocked) }
    /// Real blocks only; QUIC fallbacks are counted separately (quicTotal).
    var blockedTotal: Int { blocked.values.reduce(0) { $0 + $1.count } }
    var quicTotal: Int { quicBlocked.values.reduce(0) { $0 + $1.count } }

    private static func sorted(_ d: [String: BlockedDomain]) -> [BlockedDomain] {
        d.values.sorted { $0.count != $1.count ? $0.count > $1.count : $0.last > $1.last }
    }

    init() {
        bgObserver = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.stop() }
        }
        if UITestSeed.enabled { seedDemo() }
    }

    /// 清空 time: the general history (REJECT lines) is shared with 日志 and not cleared from here, so entries
    /// older than this are skipped when the history is read again.
    private var clearedAt = Date.distantPast
    /// Bumped by every start(); a finishing old task only clears `task` / `running` while it is still the current
    /// one (review 5: a stop() + start() during the history fetch let the old task null out the new one).
    private var generation = 0

    /// v0.19.8: the extension records DNS queries and REJECT hits from tunnel start (GET /hark/logs); the page
    /// rebuilds from that history, then attaches the live /logs stream (lines repeated across the seam skipped).
    func start() {
        guard task == nil, VPNManager.shared.isConnected else { return }
        running = true
        generation += 1
        let gen = generation
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
                    self.quicBlocked = [:]
                    for e in all { self.ingest(e.payload, at: Date(timeIntervalSince1970: Double(e.time) / 1000)) }
                }
                join = LogJoin(history: all)
            }
            while !Task.isCancelled {
                for await l in c.stream("/logs", query: [URLQueryItem(name: "level", value: "debug")], as: LogPayload.self) {
                    guard let self else { return }
                    if Task.isCancelled { break }
                    if !self.paused && !join.isDuplicate(l.payload) { self.batcher.add((l.payload, Date())) }
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
        blocked = [:]
        quicBlocked = [:]
        clearedAt = Date()
        Task { try? await ControllerClient.shared.harkClearLogs(kind: "dns") }
    }

    // MARK: Parsing

    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
    private static let answerRE = re(#"^\[DNS\] (\S+) --> (.*) (\S+) from (\S+)$"#)
    private static let cacheRE = re(#"^\[DNS\] cache hit (\S+) --> (.*) (\S+), expire at"#)
    private static let errorRE = re(#"^\[DNS\] resolve (\S+) error: (.*)$"#)
    private static let rejectRE = re(#"^\[(TCP|UDP)\] .+? --> (\S+) (?:match (.+) )?using (\S*REJECT\S*)$"#)

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

    /// "host:443" / "[2001:db8::1]:443" → 443.
    private static func port(of address: String) -> Int? {
        guard let colon = address.lastIndex(of: ":") else { return nil }
        if !address.hasPrefix("[") && address.filter({ $0 == ":" }).count != 1 { return nil }
        return Int(address[address.index(after: colon)...])
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
            let h = Self.host(of: g[1])
            guard !h.isEmpty else { return }
            let rule = g[2].isEmpty ? g[3] : g[2]
            let port = Self.port(of: g[1])
            let quic = RejectClassifier.isQUIC(rule: rule, network: g[0], port: port)
            var b = (quic ? quicBlocked[h] : blocked[h]) ?? BlockedDomain(domain: h, count: 0, rule: "", last: time, quic: quic)
            b.count += 1
            b.last = time
            b.rule = rule
            b.network = g[0]
            b.port = port
            if quic { quicBlocked[h] = b } else { blocked[h] = b }
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
            "[UDP] 198.18.0.1:50004 --> app.example.com:443 match AND(((Network,udp) && (DstPort,443))) using REJECT",
            "[UDP] 198.18.0.1:50005 --> app.example.com:443 match AND(((Network,udp) && (DstPort,443))) using REJECT",
            "[UDP] 198.18.0.1:50006 --> video.example.org:443 match AND(((Network,udp) && (DstPort,443) && (NOT,(!(InType,INNER))))) using REJECT",
        ]
        for (i, l) in lines.enumerated() { ingest(l, at: t.addingTimeInterval(Double(i - lines.count))) }
    }
}

struct DNSLogView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var store = DNSLogStore.shared
    @State private var tab = 0
    @State private var search = ""
    @State private var showQUIC = false

    private var shownQueries: [DNSLogEntry] {
        guard !search.isEmpty else { return store.queries }
        return store.queries.filter { $0.domain.localizedCaseInsensitiveContains(search) || $0.answer.localizedCaseInsensitiveContains(search) }
    }

    private var shownBlocked: [BlockedDomain] {
        let all = store.blockedSorted
        guard !search.isEmpty else { return all }
        return all.filter { matches($0) }
    }

    private var shownQUIC: [BlockedDomain] {
        let all = store.quicSorted
        guard !search.isEmpty else { return all }
        return all.filter { matches($0) }
    }

    private func matches(_ b: BlockedDomain) -> Bool {
        b.domain.localizedCaseInsensitiveContains(search) || b.rule.localizedCaseInsensitiveContains(search)
            || b.ruleLabel.localizedCaseInsensitiveContains(search)
    }

    private var footer: LocalizedStringKey {
        // 已拦截 is built from REJECT connections, not DNS answers: say so on that tab whatever the recording state.
        if tab == 1 { return "「已拦截」统计被规则拒绝的连接（按域名累计），不是 DNS 查询失败。QUIC 是 HTTP/3 用的 UDP 通道，被拒后 App 会自动改用 TCP，不影响访问，所以单独列出、不计入拦截数。" }
        if !vpn.isConnected { return "未连接 · 显示已记录的内容。连接后从连接开始记录。" }
        return store.running ? "从连接开始记录，最多保留最近 2000 条。" : "记录已停止，重新打开本页继续。"
    }

    private var isEmpty: Bool {
        tab == 0 ? shownQueries.isEmpty : (shownBlocked.isEmpty && shownQUIC.isEmpty)
    }

    var body: some View {
        List {
            Picker("", selection: $tab) {
                Text("查询 \(store.queries.count)").tag(0)
                Text("已拦截 \(store.blockedTotal)").tag(1)
            }
            .pickerStyle(.segmented)
            .listRowBackground(Color.clear)
            .accessibilityIdentifier("dnslog.tabs")
            if store.paused && (vpn.isConnected || UITestSeed.enabled) {
                PausedChip(id: "dnslog.paused") { store.paused = false }
                    .listRowInsets(EdgeInsets(top: 2, leading: 4, bottom: 2, trailing: 4))
                    .listRowBackground(Color.clear)
            }

            if tab == 0 {
                Section {
                    ForEach(shownQueries) { e in DNSQueryRow(e: e).listRowBackground(Theme.card) }
                } footer: {
                    Text(footer)
                }
            } else {
                if !shownBlocked.isEmpty {
                    Section {
                        ForEach(shownBlocked) { b in BlockedDomainRow(b: b).listRowBackground(Theme.card) }
                    } header: {
                        Text("广告与隐私拦截")
                    }
                }
                if !shownQUIC.isEmpty {
                    Section {
                        Button {
                            withAnimation(.easeInOut(duration: 0.2)) { showQUIC.toggle() }
                        } label: {
                            QUICSummaryRow(count: store.quicTotal, domains: store.quicBlocked.count, expanded: showQUIC || !search.isEmpty)
                        }
                        .buttonStyle(.plain)
                        .listRowBackground(Theme.card)
                        .accessibilityIdentifier("dnslog.quic")
                        if showQUIC || !search.isEmpty {
                            ForEach(shownQUIC) { b in BlockedDomainRow(b: b).listRowBackground(Theme.card) }
                        }
                    }
                }
                Section {} footer: { Text(footer) }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索域名")
        .overlay {
            if isEmpty && search.isEmpty {
                EmptyStateView(icon: tab == 0 ? "network" : "hand.raised", title: tab == 0 ? "没有 DNS 查询" : "没有被拦截的域名")
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
                Text(verbatim: b.ruleLabel).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 6)
            // QUIC fallbacks are not a problem: neutral grey count, red only for real blocks.
            Text(verbatim: "\(b.count)")
                .font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
                .padding(.horizontal, 8).padding(.vertical, 2)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(b.quic ? Theme.ink(0.08) : Theme.bad.opacity(0.14)))
                .foregroundStyle(b.quic ? Color.secondary : Theme.bad)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(b.quic ? "dnslog.quicDomain" : "dnslog.blocked")
    }
}

/// Collapsed group for QUIC refusals: what happened in plain words, the technical term as the subtitle.
struct QUICSummaryRow: View {
    let count: Int
    let domains: Int
    let expanded: Bool
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.triangle.swap")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.good)
                .frame(width: 28, height: 28)
                .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Theme.good.opacity(0.14)))
            VStack(alignment: .leading, spacing: 3) {
                Text("QUIC 已拦截 · 自动改走 TCP").font(.subheadline.weight(.medium))
                Text("不影响访问 · UDP 443（HTTP/3）· \(domains) 个域名").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 6)
            Text(verbatim: "\(count)")
                .font(.system(.subheadline, design: .rounded).weight(.semibold).monospacedDigit())
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Image(systemName: "chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
                .rotationEffect(.degrees(expanded ? 90 : 0))
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
    }
}
