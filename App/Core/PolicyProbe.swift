import Foundation
import SwiftUI

/// v0.8 节点探测: HTTP(S) requests from the main app through one chosen policy (node or group).
///
/// The runtime config (bridge/probe.go) carries a hidden select group `MIHOMO-PROBE` and a loopback-only
/// mixed listener whose traffic always goes to that group. A probe selects the policy in the group over the
/// controller, then sends ordinary URLSession requests through 127.0.0.1:<probePort>. Nothing extra runs
/// in the extension; probes are serialised because the group has one selection at a time.
enum PolicyProbe {
    static let group = "MIHOMO-PROBE"
    private static let lock = ProbeLock()

    enum ProbeError: LocalizedError {
        case notConnected
        case needsReconnect
        case unknownPolicy(String)
        var errorDescription: String? {
            switch self {
            case .notConnected: return String(localized: "未连接：节点探测需要先连接代理")
            case .needsReconnect: return String(localized: "当前连接的配置不含节点探测，请断开后重新连接一次")
            case .unknownPolicy(let p): return String(localized: "策略「\(p)」不在当前配置中")
            }
        }
    }

    static let browserUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"

    /// Runs `body` with a session whose requests all leave through `policy`. One probe at a time.
    static func run<T>(policy: String, timeout: TimeInterval = 10, _ body: (URLSession) async throws -> T) async throws -> T {
        await lock.lock()
        do {
            let r = try await runLocked(policy: policy, timeout: timeout, body)
            await lock.unlock()
            return r
        } catch {
            await lock.unlock()
            throw error
        }
    }

    private static func runLocked<T>(policy: String, timeout: TimeInterval, _ body: (URLSession) async throws -> T) async throws -> T {
        let connected = await MainActor.run { VPNManager.shared.isConnected }
        guard connected else { throw ProbeError.notConnected }
        do {
            try await ControllerClient.shared.select(group: group, node: policy)
        } catch ControllerClient.APIError.http(404, _) {
            throw ProbeError.needsReconnect
        } catch ControllerClient.APIError.http(400, _) {
            throw ProbeError.unknownPolicy(policy)
        }
        let session = URLSession(configuration: configuration(timeout: timeout))
        defer { session.invalidateAndCancel() }
        return try await body(session)
    }

    static func configuration(timeout: TimeInterval) -> URLSessionConfiguration {
        let c = IPInfoFetcher.sessionConfiguration(timeout: timeout)
        c.httpMaximumConnectionsPerHost = 4
        let port = CoreOverrides.load().probePort
        c.connectionProxyDictionary = [
            "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": port,
            "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": port,
        ]
        return c
    }

    /// Exit IP / region / ASN of one policy (the same endpoints as the Home header).
    static func exitInfo(policy: String) async throws -> IPInfo? {
        try await run(policy: policy, timeout: 8) { session in await IPInfoFetcher.fetch(using: session) }
    }
}

/// FIFO async mutex (the probe group can hold one selection at a time).
actor ProbeLock {
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func lock() async {
        if !busy { busy = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func unlock() {
        if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() }
    }
}

// MARK: - Results store

/// Per-policy probe results (exit info + 解锁检测), kept in the app's own store (App Group JSON).
@MainActor
final class ProbeStore: ObservableObject {
    static let shared = ProbeStore()

    struct Entry: Codable, Equatable {
        var exit: IPInfo?
        var exitDate: Date?
        var unlock: [UnlockResult]?
        var unlockDate: Date?
    }

    @Published private(set) var entries: [String: Entry] = [:]
    /// Policies being probed right now (exit or unlock).
    @Published var running: Set<String> = []

    private var url: URL { AppShared.containerURL.appendingPathComponent("probe-results.json") }
    static let maxEntries = 300

    init() {
        if let d = try? Data(contentsOf: url), let e = try? JSONDecoder().decode([String: Entry].self, from: d) { entries = e }
        // v0.19 切换节点后自动重新检测: the group last checked on 解锁检测, a few seconds after its node changed.
        observer = NotificationCenter.default.addObserver(forName: .egressMayHaveChanged, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.scheduleAutoRetest() }
        }
    }

    private var observer: NSObjectProtocol?
    private var autoTask: Task<Void, Never>?
    static let autoKey = "unlock.autoRetest"

    private func scheduleAutoRetest() {
        guard UserDefaults.standard.bool(forKey: Self.autoKey), VPNManager.shared.isConnected else { return }
        let group = UserDefaults.standard.string(forKey: "unlock.group") ?? ""
        let member = UserDefaults.standard.string(forKey: "unlock.member") ?? ""
        guard !group.isEmpty, member.isEmpty else { return } // a fixed node did not change
        autoTask?.cancel()
        autoTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard !Task.isCancelled, let self, !self.running.contains(group) else { return }
            _ = await self.probeUnlock(group)
        }
    }

    func entry(_ policy: String) -> Entry? { entries[policy] }

    func setExit(_ info: IPInfo?, for policy: String) {
        var e = entries[policy] ?? Entry()
        e.exit = info
        e.exitDate = Date()
        entries[policy] = e
        save()
    }

    func setUnlock(_ results: [UnlockResult], for policy: String) {
        var e = entries[policy] ?? Entry()
        e.unlock = results
        e.unlockDate = Date()
        entries[policy] = e
        save()
    }

    func clear() {
        entries = [:]
        try? FileManager.default.removeItem(at: url)
    }

    /// Small badge for a node cell: "解锁 n/m" from the last 解锁检测.
    func badge(for policy: String) -> (ok: Int, total: Int)? {
        guard let r = entries[policy]?.unlock, !r.isEmpty else { return nil }
        let considered = r.filter { $0.status != .failed }
        guard !considered.isEmpty else { return nil }
        return (considered.filter { $0.status == .yes }.count, considered.count)
    }

    private func save() {
        if entries.count > Self.maxEntries {
            // Drop the oldest results first.
            let sorted = entries.sorted { max($0.value.exitDate ?? .distantPast, $0.value.unlockDate ?? .distantPast) < max($1.value.exitDate ?? .distantPast, $1.value.unlockDate ?? .distantPast) }
            for (k, _) in sorted.prefix(entries.count - Self.maxEntries) { entries.removeValue(forKey: k) }
        }
        if let d = try? JSONEncoder().encode(entries) { try? d.write(to: url, options: .atomic) }
    }

    /// Exit lookup with bookkeeping; returns an error message or nil.
    func probeExit(_ policy: String) async -> String? {
        running.insert(policy)
        defer { running.remove(policy) }
        do {
            let info = try await PolicyProbe.exitInfo(policy: policy)
            setExit(info, for: policy)
            return info == nil ? String(localized: "所有查询接口都没有响应（节点可能不可用）") : nil
        } catch {
            return error.localizedDescription
        }
    }

    /// 解锁检测 (+ exit info in the same probe session); returns an error message or nil.
    func probeUnlock(_ policy: String, services: [UnlockService] = UnlockService.selected) async -> String? {
        running.insert(policy)
        defer { running.remove(policy) }
        do {
            let (info, results) = try await PolicyProbe.run(policy: policy, timeout: 10) { session -> (IPInfo?, [UnlockResult]) in
                async let exit = IPInfoFetcher.fetch(using: session)
                async let unlock = UnlockChecker.runAll(services, session: session)
                return await (exit, unlock)
            }
            if let info { setExit(info, for: policy) }
            setUnlock(results, for: policy)
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}

// MARK: - 解锁检测

enum UnlockService: String, CaseIterable, Codable, Identifiable {
    case netflix, disney, youtube, chatgpt, claude, gemini, tiktok, spotify, bilibiliHKMOTW, bilibiliTW
    // v0.19 (Bettbox list, checks with a readable answer only)
    case copilot, youtubeMusic, iqiyi, mytvsuper

    var id: String { rawValue }

    /// v0.19 解锁检测 categories (display order).
    enum Category: String, CaseIterable, Identifiable {
        case ai, streaming, asia
        var id: String { rawValue }
        var title: String {
            switch self {
            case .ai: return String(localized: "AI 服务")
            case .streaming: return String(localized: "国际流媒体")
            case .asia: return String(localized: "港澳台与亚洲")
            }
        }
        var services: [UnlockService] { UnlockService.allCases.filter { $0.category == self } }
    }

    var category: Category {
        switch self {
        case .chatgpt, .claude, .gemini, .copilot: return .ai
        case .netflix, .disney, .youtube, .youtubeMusic, .spotify, .tiktok: return .streaming
        case .bilibiliHKMOTW, .bilibiliTW, .iqiyi, .mytvsuper: return .asia
        }
    }

    /// The user's choice (更多 → 解锁检测 → 检测项目); default = every service.
    static var selected: [UnlockService] {
        guard let raw = UserDefaults.standard.string(forKey: "unlock.services") else { return allCases }
        let set = Set(raw.split(separator: ",").map(String.init))
        let l = allCases.filter { set.contains($0.rawValue) }
        return l.isEmpty ? allCases : l
    }

    static func setSelected(_ l: [UnlockService]) {
        UserDefaults.standard.set(l.map(\.rawValue).joined(separator: ","), forKey: "unlock.services")
    }

    var title: String {
        switch self {
        case .netflix: return "Netflix"
        case .disney: return "Disney+"
        case .youtube: return "YouTube Premium"
        case .chatgpt: return "ChatGPT"
        case .claude: return "Claude"
        case .gemini: return "Gemini"
        case .tiktok: return "TikTok"
        case .spotify: return "Spotify"
        case .bilibiliHKMOTW: return String(localized: "哔哩哔哩 港澳台")
        case .bilibiliTW: return String(localized: "哔哩哔哩 台湾")
        case .copilot: return "Microsoft Copilot"
        case .youtubeMusic: return "YouTube Music"
        case .iqiyi: return String(localized: "爱奇艺国际版")
        case .mytvsuper: return "myTV SUPER"
        }
    }

    var symbol: String {
        switch self {
        case .netflix, .disney: return "film.fill"
        case .youtube: return "play.rectangle.fill"
        case .chatgpt, .claude, .gemini, .copilot: return "sparkles"
        case .tiktok: return "music.note"
        case .spotify, .youtubeMusic: return "headphones"
        case .bilibiliHKMOTW, .bilibiliTW, .iqiyi, .mytvsuper: return "tv.fill"
        }
    }
}

struct UnlockResult: Codable, Hashable, Identifiable {
    enum Status: String, Codable { case yes, partial, no, failed }
    var service: UnlockService
    var status: Status
    var region: String? = nil   // ISO code as the service reports it (2 or 3 letters)
    var note: String? = nil

    var id: String { service.rawValue }

    var statusText: String {
        switch status {
        case .yes: return String(localized: "解锁")
        case .partial: return note ?? String(localized: "部分")
        case .no: return String(localized: "不可用")
        case .failed: return String(localized: "检测失败")
        }
    }

    var color: Color {
        switch status {
        case .yes: return Theme.good
        case .partial: return Theme.warn
        case .no: return Theme.bad
        case .failed: return .secondary
        }
    }

    var flag: String? {
        guard let r = region?.uppercased(), r.count == 2, r.allSatisfy({ $0.isASCII && $0.isLetter }) else { return nil }
        var s = ""
        for u in r.unicodeScalars { if let v = UnicodeScalar(127397 + u.value) { s.unicodeScalars.append(v) } }
        return s
    }
}

/// Fixed probe table (no scripts). Each check is a couple of plain requests whose answer tells whether the
/// service serves this exit and in which region. Heuristics follow the widely used region-check scripts and
/// can drift when a service changes its pages; "检测失败" means the answer could not be read, not "blocked".
enum UnlockChecker {
    struct Page {
        var status: Int
        var url: URL?
        var body: String
    }

    static func runAll(_ services: [UnlockService], session: URLSession) async -> [UnlockResult] {
        await withTaskGroup(of: UnlockResult.self) { g in
            for s in services { g.addTask { await check(s, session: session) } }
            var out: [UnlockResult] = []
            for await r in g { out.append(r) }
            return services.compactMap { s in out.first { $0.service == s } }
        }
    }

    static func get(_ url: String, session: URLSession, headers: [String: String] = [:], maxBytes: Int = 1_500_000) async throws -> Page {
        guard let u = URL(string: url) else { throw URLError(.badURL) }
        var req = URLRequest(url: u)
        req.setValue(PolicyProbe.browserUA, forHTTPHeaderField: "User-Agent")
        req.setValue("en-US,en;q=0.9", forHTTPHeaderField: "Accept-Language")
        req.setValue("text/html,application/json;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        let (data, resp) = try await session.data(for: req)
        let http = resp as? HTTPURLResponse
        let body = String(decoding: data.prefix(maxBytes), as: UTF8.self)
        return Page(status: http?.statusCode ?? 0, url: http?.url, body: body)
    }

    static func firstMatch(_ pattern: String, in s: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)), m.numberOfRanges > 1 else { return nil }
        let r = m.range(at: 1)
        return r.location == NSNotFound ? nil : ns.substring(with: r)
    }

    /// Cloudflare trace "loc=XX" of a host (the region the service sees).
    static func traceLoc(_ host: String, session: URLSession) async -> String? {
        guard let p = try? await get("https://\(host)/cdn-cgi/trace", session: session, maxBytes: 4096) else { return nil }
        return firstMatch("(?m)^loc=([A-Z]{2})$", in: p.body)
    }

    static func failed(_ s: UnlockService, _ error: Error) -> UnlockResult {
        let msg: String
        if let u = error as? URLError {
            switch u.code {
            case .timedOut: msg = String(localized: "超时")
            case .cannotConnectToHost, .networkConnectionLost, .cannotFindHost: msg = String(localized: "连接失败")
            case .secureConnectionFailed, .serverCertificateUntrusted: msg = String(localized: "TLS 失败")
            default: msg = u.localizedDescription
            }
        } else {
            msg = error.localizedDescription
        }
        return UnlockResult(service: s, status: .failed, note: msg)
    }

    static func check(_ s: UnlockService, session: URLSession) async -> UnlockResult {
        do {
            switch s {
            case .netflix: return try await netflix(session)
            case .disney: return try await disney(session)
            case .youtube: return try await youtube(session)
            case .chatgpt: return try await chatgpt(session)
            case .claude: return try await claude(session)
            case .gemini: return try await gemini(session)
            case .tiktok: return try await tiktok(session)
            case .spotify: return try await spotify(session)
            case .bilibiliHKMOTW:
                return try await bilibili(s, session, "avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1&fnver=0&fnval=16&module=bangumi")
            case .bilibiliTW:
                return try await bilibili(s, session, "avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1&fnver=0&fnval=16&module=bangumi")
            case .copilot: return try await copilot(session)
            case .youtubeMusic: return try await youtubeMusic(session)
            case .iqiyi: return try await iqiyi(session)
            case .mytvsuper: return try await mytvsuper(session)
            }
        } catch {
            return failed(s, error)
        }
    }

    // Netflix: a licensed title (LEGO Ninjago) and Breaking Bad. "Oh no!" on both = originals only.
    static func netflix(_ session: URLSession) async throws -> UnlockResult {
        async let a = get("https://www.netflix.com/title/81280792", session: session)
        async let b = get("https://www.netflix.com/title/70143836", session: session)
        let (p1, p2) = try await (a, b)
        if p1.status == 403 || p2.status == 403 { return UnlockResult(service: .netflix, status: .no, note: String(localized: "被拒绝访问")) }
        let region = firstMatch("data-country=\"([A-Z]{2})\"", in: p1.body)
            ?? firstMatch("\"requestCountry\":\\{\"id\":\"([A-Z]{2})\"", in: p1.body)
            ?? firstMatch("\"countryCode\":\"([A-Z]{2})\"", in: p1.body)
            ?? p1.url.flatMap { firstMatch("netflix\\.com/([a-z]{2})(?:-[a-z]{2})?/title", in: $0.absoluteString)?.uppercased() }
        let ohNo1 = p1.body.contains("Oh no!") || p1.status == 404
        let ohNo2 = p2.body.contains("Oh no!") || p2.status == 404
        if ohNo1 && ohNo2 { return UnlockResult(service: .netflix, status: .partial, region: region, note: String(localized: "仅自制剧")) }
        if (200..<400).contains(p1.status) || (200..<400).contains(p2.status) {
            return UnlockResult(service: .netflix, status: .yes, region: region ?? (p1.url?.path.hasPrefix("/title") == true ? "US" : nil))
        }
        return UnlockResult(service: .netflix, status: .failed, note: "HTTP \(p1.status)")
    }

    // Disney+: unsupported regions are redirected to an "unavailable" page.
    static func disney(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://www.disneyplus.com/", session: session)
        let final = p.url?.absoluteString.lowercased() ?? ""
        if p.status == 403 || final.contains("unavailable") || final.contains("unsupported") {
            return UnlockResult(service: .disney, status: .no)
        }
        guard (200..<400).contains(p.status) else { return UnlockResult(service: .disney, status: .failed, note: "HTTP \(p.status)") }
        let region = firstMatch("disneyplus\\.com/[a-z]{2}-([a-z]{2})(?:/|$)", in: final)?.uppercased()
            ?? firstMatch("\"countryCode\":\"([A-Z]{2})\"", in: p.body)
            ?? firstMatch("\"region\":\"([A-Z]{2})\"", in: p.body)
        return UnlockResult(service: .disney, status: .yes, region: region)
    }

    static func youtube(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://www.youtube.com/premium", session: session,
                              headers: ["Cookie": "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY"])
        if p.body.contains("www.google.cn") { return UnlockResult(service: .youtube, status: .no, region: "CN") }
        let region = firstMatch("\"INNERTUBE_CONTEXT_GL\":\"([A-Z]{2})\"", in: p.body) ?? firstMatch("\"countryCode\":\"([A-Z]{2})\"", in: p.body)
        if p.body.contains("Premium is not available in your country") {
            return UnlockResult(service: .youtube, status: .no, region: region)
        }
        if p.body.localizedCaseInsensitiveContains("ad-free") {
            return UnlockResult(service: .youtube, status: .yes, region: region)
        }
        return UnlockResult(service: .youtube, status: .failed, region: region, note: p.status == 200 ? String(localized: "页面无法识别") : "HTTP \(p.status)")
    }

    static func chatgpt(_ session: URLSession) async throws -> UnlockResult {
        async let loc = traceLoc("chatgpt.com", session: session)
        async let cookie = get("https://api.openai.com/compliance/cookie_requirements", session: session, headers: ["Authorization": "Bearer null"], maxBytes: 20000)
        async let ios = get("https://ios.chat.openai.com/", session: session, maxBytes: 200_000)
        let region = await loc
        let c = try await cookie
        if c.body.contains("unsupported_country") { return UnlockResult(service: .chatgpt, status: .no, region: region, note: String(localized: "地区不支持")) }
        let i = try await ios
        if i.body.contains("unsupported_country") { return UnlockResult(service: .chatgpt, status: .no, region: region, note: String(localized: "地区不支持")) }
        if i.body.contains("VPN") { return UnlockResult(service: .chatgpt, status: .partial, region: region, note: String(localized: "仅网页版（App 拒绝此 IP）")) }
        return UnlockResult(service: .chatgpt, status: .yes, region: region)
    }

    static func claude(_ session: URLSession) async throws -> UnlockResult {
        async let loc = traceLoc("claude.ai", session: session)
        let p = try await get("https://claude.ai/", session: session, maxBytes: 200_000)
        let region = await loc
        let final = p.url?.absoluteString ?? ""
        if final.contains("app-unavailable-in-region") || p.body.contains("app-unavailable-in-region") {
            return UnlockResult(service: .claude, status: .no, region: region, note: String(localized: "地区不支持"))
        }
        if (200..<400).contains(p.status) { return UnlockResult(service: .claude, status: .yes, region: region) }
        if p.status == 403 { return UnlockResult(service: .claude, status: .failed, region: region, note: String(localized: "被风控拦截（HTTP 403）")) }
        return UnlockResult(service: .claude, status: .failed, region: region, note: "HTTP \(p.status)")
    }

    static func gemini(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://gemini.google.com/", session: session)
        let region = firstMatch(",2,1,200,\"([A-Z]{3})\"", in: p.body)
        if p.body.contains("45631641,null,true") { return UnlockResult(service: .gemini, status: .yes, region: region) }
        if p.status == 200 { return UnlockResult(service: .gemini, status: .no, region: region) }
        return UnlockResult(service: .gemini, status: .failed, note: "HTTP \(p.status)")
    }

    static func tiktok(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://www.tiktok.com/explore", session: session)
        if let region = firstMatch("\"region\":\"([A-Z]{2})\"", in: p.body) {
            return UnlockResult(service: .tiktok, status: .yes, region: region)
        }
        let final = p.url?.absoluteString ?? ""
        if p.status == 403 || final.contains("notfound") || final.contains("unavailable") {
            return UnlockResult(service: .tiktok, status: .no)
        }
        return UnlockResult(service: .tiktok, status: .failed, note: p.status == 200 ? String(localized: "页面无法识别") : "HTTP \(p.status)")
    }

    // Spotify picks the site market from the IP: /jp-ja/premium etc.; unsupported markets get a chooser.
    static func spotify(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://www.spotify.com/premium/", session: session, maxBytes: 100_000)
        let final = p.url?.absoluteString ?? ""
        if final.contains("select-your-country") { return UnlockResult(service: .spotify, status: .no) }
        guard (200..<400).contains(p.status) else { return UnlockResult(service: .spotify, status: .failed, note: "HTTP \(p.status)") }
        let region = firstMatch("spotify\\.com/([a-z]{2})(?:-[a-z]{2})?/premium", in: final)?.uppercased()
        return UnlockResult(service: .spotify, status: .yes, region: region ?? "US")
    }

    // v0.19 Copilot: copilot.microsoft.com sends unsupported markets to cn.bing.com / an error page; the
    // market is Bing's Region field. Regions Microsoft does not serve Copilot in count as not available.
    static let copilotUnsupported: Set<String> = ["CN", "HK", "MO", "RU", "BY", "IR", "KP", "SY", "CU"]
    static func copilot(_ session: URLSession) async throws -> UnlockResult {
        async let bing = get("https://www.bing.com/search?q=curl", session: session, maxBytes: 600_000)
        let p = try await get("https://copilot.microsoft.com/", session: session, maxBytes: 200_000)
        let b = try? await bing
        let final = (p.url?.absoluteString ?? "").lowercased()
        var region = b.flatMap { firstMatch("Region\\s*:\\s*\"([A-Z]{2})\"", in: $0.body) }
        if final.contains("cn.bing.com") || (b?.url?.host ?? "").hasPrefix("cn.bing") { region = region ?? "CN" }
        if let r = region, copilotUnsupported.contains(r) { return UnlockResult(service: .copilot, status: .no, region: r, note: String(localized: "地区不支持")) }
        if p.status == 403 || p.status == 451 { return UnlockResult(service: .copilot, status: .no, region: region, note: "HTTP \(p.status)") }
        if (200..<400).contains(p.status) { return UnlockResult(service: .copilot, status: .yes, region: region) }
        return UnlockResult(service: .copilot, status: .failed, region: region, note: "HTTP \(p.status)")
    }

    static func youtubeMusic(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://music.youtube.com/", session: session, maxBytes: 300_000)
        let final = p.url?.absoluteString ?? ""
        let region = firstMatch("\"INNERTUBE_CONTEXT_GL\":\"([A-Z]{2})\"", in: p.body) ?? firstMatch("\"countryCode\":\"([A-Z]{2})\"", in: p.body)
        if final.contains("sorry.google.com") || final.contains("unavailable") || p.body.contains("not available in your") || p.body.contains("unavailable in your country") {
            return UnlockResult(service: .youtubeMusic, status: .no, region: region)
        }
        if p.status == 200 { return UnlockResult(service: .youtubeMusic, status: .yes, region: region) }
        return UnlockResult(service: .youtubeMusic, status: .failed, region: region, note: "HTTP \(p.status)")
    }

    // iQIYI international: the site sets mod=<region> in a cookie / x-custom-client-ip.
    static func iqiyi(_ session: URLSession) async throws -> UnlockResult {
        guard let u = URL(string: "https://www.iq.com/") else { throw URLError(.badURL) }
        var req = URLRequest(url: u)
        req.httpMethod = "HEAD"
        req.setValue(PolicyProbe.browserUA, forHTTPHeaderField: "User-Agent")
        let (_, resp) = try await session.data(for: req)
        let http = resp as? HTTPURLResponse
        let cookies = (http?.value(forHTTPHeaderField: "Set-Cookie") ?? "") + " " + (http?.value(forHTTPHeaderField: "x-custom-client-ip") ?? "")
        let mod = firstMatch("mod=([a-zA-Z]+)", in: cookies)?.uppercased()
        let region = mod == "NTW" ? "TW" : (mod == "INTL" ? nil : mod)
        if http?.statusCode == 200 { return UnlockResult(service: .iqiyi, status: .yes, region: region) }
        return UnlockResult(service: .iqiyi, status: .no, region: region, note: "HTTP \(http?.statusCode ?? 0)")
    }

    static func mytvsuper(_ session: URLSession) async throws -> UnlockResult {
        let p = try await get("https://www.mytvsuper.com/api/auth/getSession/self/", session: session, maxBytes: 50_000)
        guard p.status == 200, let o = try? JSONSerialization.jsonObject(with: Data(p.body.utf8)) as? [String: Any] else {
            return UnlockResult(service: .mytvsuper, status: .failed, note: "HTTP \(p.status)")
        }
        let cc = (o["country_code"] as? String)?.uppercased()
        return UnlockResult(service: .mytvsuper, status: (o["supported_country"] as? Bool) == true ? .yes : .no, region: cc)
    }

    static func bilibili(_ s: UnlockService, _ session: URLSession, _ query: String) async throws -> UnlockResult {
        let p = try await get("https://api.bilibili.com/pgc/player/web/playurl?\(query)", session: session, maxBytes: 100_000)
        guard let obj = try? JSONSerialization.jsonObject(with: Data(p.body.utf8)) as? [String: Any],
              let code = (obj["code"] as? NSNumber)?.intValue else {
            return UnlockResult(service: s, status: .failed, note: "HTTP \(p.status)")
        }
        switch code {
        case 0: return UnlockResult(service: s, status: .yes)
        case -10403: return UnlockResult(service: s, status: .no)
        default: return UnlockResult(service: s, status: .failed, note: "code \(code)")
        }
    }
}
