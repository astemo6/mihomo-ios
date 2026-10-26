import Foundation
import Network

/// 设置 → 诊断 → 一键自检 (feat/nc-e2e): the on-device half of the E2E replay. Runs the checks that need the real
/// extension, the real network and the user's real trust settings, one after another with live status, then writes
/// selfcheck.txt into the home directory (DiagnosticSummary puts it first in the 诊断包) and builds the 诊断包.
/// Lean on purpose: no new dependencies, a handful of requests, nothing kept in memory after the run but the text.
@MainActor
final class SelfCheck: ObservableObject {
    enum State: Equatable { case pending, running, pass, fail, skip, needsDevice }

    struct Step: Identifiable, Equatable {
        let id: String
        let title: String
        var state: State = .pending
        var detail = ""
    }

    @Published private(set) var steps: [Step] = SelfCheck.makeSteps()
    @Published private(set) var running = false
    @Published private(set) var finished = false
    @Published private(set) var bundleURL: URL?
    @Published private(set) var bundleError: String?

    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static func makeSteps() -> [Step] {
        [
            Step(id: "vpn", title: String(localized: "启动 VPN（分阶段计时）")),
            Step(id: "controller", title: String(localized: "内核控制接口 /version")),
            Step(id: "counts", title: String(localized: "加载数量（节点 / 节点集 / 策略组 / 规则）")),
            Step(id: "delay", title: String(localized: "策略组测延迟")),
            Step(id: "fetch", title: String(localized: "经隧道访问 3 个网址")),
            Step(id: "mitm", title: String(localized: "MitM 自检与证书信任")),
            Step(id: "script", title: String(localized: "运行一个脚本并确认有日志")),
            Step(id: "restart", title: String(localized: "断开重连与旧 Fake-IP 处理")),
        ]
    }

    private func set(_ id: String, _ state: State, _ detail: String = "") {
        guard let i = steps.firstIndex(where: { $0.id == id }) else { return }
        steps[i].state = state
        steps[i].detail = detail
    }

    var summaryLine: String {
        let p = steps.filter { $0.state == .pass }.count
        let f = steps.filter { $0.state == .fail }.count
        let s = steps.filter { $0.state == .skip || $0.state == .needsDevice }.count
        return String(localized: "通过 \(p) · 失败 \(f) · 跳过 \(s)")
    }

    func run(vpn: VPNManager) async {
        guard !running else { return }
        running = true
        finished = false
        bundleURL = nil
        bundleError = nil
        steps = Self.makeSteps()
        let started = Date()
        if Self.isSimulator {
            for s in steps { set(s.id, .needsDevice, String(localized: "需要真机")) }
        } else {
            await stepVPN(vpn)
            let up = vpn.isConnected
            if up {
                await stepController()
                await stepCounts()
                await stepDelay()
                await stepFetch()
                await stepMitM()
                await stepScript()
                await stepRestart(vpn)
            } else {
                for id in ["controller", "counts", "delay", "fetch", "mitm", "script", "restart"] {
                    set(id, .skip, String(localized: "VPN 未连接"))
                }
            }
        }
        let text = report(started: started)
        let home = AppShared.homeURL.path
        try? text.write(toFile: (home as NSString).appendingPathComponent(Self.reportFile), atomically: true, encoding: .utf8)
        do {
            bundleURL = try await DiagnosticsExporter.export(vpn: vpn)
        } catch {
            bundleError = String(localized: "导出失败：") + error.localizedDescription
        }
        running = false
        finished = true
    }

    static let reportFile = "selfcheck.txt"

    private func report(started: Date) -> String {
        let f = ISO8601DateFormatter()
        var lines = ["Tern 一键自检 \(f.string(from: started))", summaryLine, ""]
        for s in steps {
            let mark: String
            switch s.state {
            case .pass: mark = "PASS"
            case .fail: mark = "FAIL"
            case .skip: mark = "SKIP"
            case .needsDevice: mark = "SKIP(需要真机)"
            case .pending, .running: mark = "-"
            }
            lines.append("[\(mark)] \(s.title)")
            if !s.detail.isEmpty { lines.append("    " + s.detail.replacingOccurrences(of: "\n", with: "\n    ")) }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: steps

    private static func ms(_ t: Date) -> Int { Int(Date().timeIntervalSince(t) * 1000) }

    /// Start the VPN from cold and split the time with the extension's own startup-log stamps.
    private func stepVPN(_ vpn: VPNManager) async {
        set("vpn", .running)
        if vpn.isConnected { await vpn.disconnectAndWait() }
        let t0 = Date()
        let ok = await vpn.connectAndWait(timeout: 30)
        let total = Self.ms(t0)
        guard ok else {
            set("vpn", .fail, String(localized: "未能连接（\(total) ms）：") + (vpn.lastError ?? "-"))
            return
        }
        let phases = Self.startupPhases(StartupLog.read(), since: t0)
        set("vpn", .pass, String(localized: "已连接，用时 \(total) ms") + (phases.isEmpty ? "" : "\n" + phases))
    }

    /// "HH:mm:ss.SSS [tag] msg" lines of the current startup log → per-phase durations.
    static func startupPhases(_ log: String, since t0: Date) -> String {
        let marks: [(String, String)] = [
            ("startTunnel called", String(localized: "扩展启动")),
            ("settings applied", String(localized: "隧道网络设置")),
            ("core start begin", String(localized: "内核加载开始")),
            ("core start returned OK", String(localized: "内核启动完成")),
            ("startTunnel completed OK", String(localized: "连接完成")),
        ]
        let current = log.components(separatedBy: "\n--- 上一次 ---\n").first ?? log
        let cal = Calendar.current
        let day = cal.dateComponents([.year, .month, .day], from: t0)
        func stamp(_ line: String) -> Date? {
            let p = line.prefix(12).split(separator: ":")
            guard p.count == 3, let h = Int(p[0]), let m = Int(p[1]), let s = Double(p[2]) else { return nil }
            var c = day
            c.hour = h; c.minute = m; c.second = Int(s); c.nanosecond = Int((s - Double(Int(s))) * 1e9)
            return cal.date(from: c)
        }
        var prev = t0
        var out: [String] = []
        for (needle, label) in marks {
            guard let line = current.split(separator: "\n").last(where: { $0.contains(needle) }), let t = stamp(String(line)) else { continue }
            out.append("\(label) +\(max(0, Int(t.timeIntervalSince(prev) * 1000))) ms")
            prev = t
        }
        return out.joined(separator: " · ")
    }

    private func stepController() async {
        set("controller", .running)
        let t0 = Date()
        do {
            let v = try await ControllerClient.shared.version()
            set("controller", .pass, "\(v) · \(Self.ms(t0)) ms")
        } catch {
            set("controller", .fail, error.localizedDescription)
        }
    }

    private var groupNames: [String] = []

    private func stepCounts() async {
        set("counts", .running)
        do {
            let px = try await ControllerClient.shared.proxies()
            let groups = px.values.filter { $0.all != nil }
            let proxies = px.count - groups.count
            let rules = (try? await ControllerClient.shared.rules().count) ?? 0
            let providers = (try? await ControllerClient.shared.proxyProviders()) ?? []
            let empty = providers.filter { ($0.proxies ?? []).isEmpty }.map(\.name)
            let nodes = providers.reduce(0) { $0 + ($1.proxies?.count ?? 0) }
            var d = String(localized: "节点 \(proxies) · 节点集 \(providers.count)（\(nodes) 个节点）· 策略组 \(groups.count) · 规则 \(rules)")
            if !empty.isEmpty { d += "\n" + String(localized: "没有节点的节点集：") + empty.joined(separator: ", ") }
            let order = (try? Data(contentsOf: AppShared.homeURL.appendingPathComponent("runtime-groups.json")))
                .flatMap { try? JSONDecoder().decode([String].self, from: $0) } ?? []
            groupNames = (order + groups.map(\.name).sorted()).filter { n in n != "GLOBAL" && (px[n]?.all?.count ?? 0) > 1 }
            set("counts", proxies + nodes > 0 && groups.count > 0 && rules > 0 && empty.isEmpty ? .pass : .fail, d)
        } catch {
            set("counts", .fail, error.localizedDescription)
        }
    }

    private func stepDelay() async {
        set("delay", .running)
        guard let g = groupNames.first, let members = try? await ControllerClient.shared.proxies()[g]?.all, !members.isEmpty else {
            set("delay", .skip, String(localized: "没有可测的策略组")); return
        }
        let since = (try? await Self.logSeq()) ?? 0
        do {
            let r = try await ControllerClient.shared.membersDelay(members)
            let ok = r.values.filter { $0 > 0 }.count
            let slow = r.filter { $0.value > 0 }.max { $0.value < $1.value }
            let stages = (try? await Self.delayStages(since: since)) ?? [:]
            var d = String(localized: "策略组「\(g)」：\(ok) 个可用 · \(members.count - ok) 个超时")
            if let slow { d += " · " + String(localized: "最慢 \(slow.key) \(slow.value) ms") }
            if let worst = stages.max(by: { $0.value < $1.value }) {
                d += "\n" + String(localized: "失败最多的阶段：\(worst.key)（\(worst.value) 次）")
            } else if ok < members.count {
                d += "\n" + String(localized: "内核没有给出失败阶段")
            }
            set("delay", ok > 0 ? .pass : .fail, d)
        } catch {
            set("delay", .fail, error.localizedDescription)
        }
    }

    private static func logSeq() async throws -> UInt64 {
        let data = try await ControllerClient.shared.send("/hark/logs", query: [URLQueryItem(name: "since", value: "0")], timeout: 4)
        let o = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (o?["seq"] as? NSNumber)?.uint64Value ?? 0
    }

    /// `[delay] node: timeout at stage X …` / `failed at stage X` lines since `since` → count per stage.
    private static func delayStages(since: UInt64) async throws -> [String: Int] {
        let data = try await ControllerClient.shared.send("/hark/logs", query: [URLQueryItem(name: "since", value: String(since))], timeout: 4)
        let o = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        var out: [String: Int] = [:]
        for l in o?["logs"] as? [[String: Any]] ?? [] {
            guard let p = l["payload"] as? String, p.hasPrefix("[delay]"), let r = p.range(of: " at stage ") else { continue }
            let stage = p[r.upperBound...].split(whereSeparator: { $0 == " " || $0 == "(" || $0 == "," }).first.map(String.init) ?? "?"
            out[stage, default: 0] += 1
        }
        return out
    }

    private static func mitmHost() -> String? {
        guard let d = try? Data(contentsOf: AppShared.homeURL.appendingPathComponent("nativecore-rewrite.json")),
              let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { return nil }
        let hosts = (o["inc"] as? [Any] ?? []).compactMap { ($0 as? String) ?? (($0 as? [String: Any])?["host"] as? String) }
        return hosts.first { !$0.contains("*") && !$0.hasPrefix("-") && $0.contains(".") && !$0.contains(":") }
    }

    private func stepFetch() async {
        set("fetch", .running)
        var targets: [(String, String)] = [
            (String(localized: "国内直连"), "https://www.baidu.com/"),
            (String(localized: "代理"), "https://www.gstatic.com/generate_204"),
        ]
        if let h = Self.mitmHost() { targets.append(("MitM", "https://\(h)/")) }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 10
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        let since = (try? await Self.logSeq()) ?? 0
        var lines: [String] = []
        var failed = 0
        for (label, u) in targets {
            guard let url = URL(string: u) else { continue }
            let t0 = Date()
            do {
                let (_, resp) = try await session.data(from: url)
                lines.append("\(label) \(url.host ?? ""): HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0) · \(Self.ms(t0)) ms")
            } catch {
                // A pinned / untrusted MitM host failing is reported by the MitM step; it is not a tunnel failure.
                if label != "MitM" { failed += 1 }
                lines.append("\(label) \(url.host ?? ""): \(error.localizedDescription)")
            }
        }
        if let routes = try? await Self.routeLines(since: since, hosts: targets.compactMap { URL(string: $0.1)?.host }) {
            lines += routes
        }
        set("fetch", failed == 0 ? .pass : .fail, lines.joined(separator: "\n"))
    }

    /// The data plane's `[TCP] host:443 rule … → policy` lines for these hosts (which rule / node each took).
    private static func routeLines(since: UInt64, hosts: [String]) async throws -> [String] {
        let data = try await ControllerClient.shared.send("/hark/logs", query: [URLQueryItem(name: "since", value: String(since))], timeout: 4)
        let o = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let all = (o?["logs"] as? [[String: Any]] ?? []).compactMap { $0["payload"] as? String }
        return hosts.compactMap { h in all.last { $0.hasPrefix("[TCP] \(h):") || $0.hasPrefix("[MITM] \(h)") } }
            .map { String($0.prefix(160)) }
    }

    private func stepMitM() async {
        set("mitm", .running)
        let home = AppShared.homeURL.path
        let trusted = await Task.detached { NCCAManager.checkTrust(home: home) }.value
        let log = StartupLog.read().components(separatedBy: "\n--- 上一次 ---\n").first ?? ""
        let probe = log.split(separator: "\n").last { $0.contains("MITM self-probe") || $0.contains("MITM: ") }.map { String($0.dropFirst(13)) }
        var d = String(localized: "证书受 iOS 信任：") + (trusted ? String(localized: "是") : String(localized: "否（设置 → 通用 → 关于本机 → 证书信任设置）"))
        d += "\n" + (probe ?? String(localized: "扩展没有写 MitM 自检行（此版本不支持）"))
        let probeFailed = probe?.contains("FAILED") == true || probe?.contains("inactive") == true
        let hasHosts = Self.mitmHost() != nil
        if !hasHosts {
            set("mitm", trusted ? .pass : .skip, d + "\n" + String(localized: "当前配置没有 MitM 主机"))
        } else {
            set("mitm", trusted && !probeFailed ? .pass : .fail, d)
        }
    }

    private func stepScript() async {
        set("script", .running)
        do {
            let data = try await ControllerClient.shared.send("/mitm/tasks")
            let tasks = (try JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
            guard let t = tasks.first(where: { ($0["enabled"] as? Bool) != false }) ?? tasks.first, let id = t["id"] as? String else {
                set("script", .skip, String(localized: "当前配置没有脚本任务")); return
            }
            let name = (t["script"] as? [String: Any])?["name"] as? String ?? id
            let before = try await Self.scriptLogCount()
            let r = try await ControllerClient.shared.send("/mitm/tasks/\(ControllerClient.enc(id))/run", method: "POST", body: [String: Any](), timeout: 40)
            let obj = (try? JSONSerialization.jsonObject(with: r)) as? [String: Any] ?? [:]
            try? await Task.sleep(nanoseconds: 800_000_000)
            let after = try await Self.scriptLogCount()
            let ok = (obj["ok"] as? Bool) == true
            var d = String(localized: "任务「\(name)」：") + (ok ? String(localized: "运行成功") : String(localized: "运行失败 \(obj["error"] as? String ?? "")"))
            d += " · " + String(localized: "脚本日志 \(before) → \(after) 行")
            set("script", ok && after > before ? .pass : .fail, d)
        } catch {
            set("script", .fail, error.localizedDescription)
        }
    }

    private static func scriptLogCount() async throws -> Int {
        let data = try await ControllerClient.shared.send("/mitm/logs", timeout: 4)
        return ((try? JSONSerialization.jsonObject(with: data)) as? [Any])?.count ?? 0
    }

    /// Resolve a name while connected (fake-ip mode → 198.18.x), reconnect, then: the same fake IP must still route
    /// (persisted map), and a fake IP nobody was given must be refused at once (RST), not accepted and closed.
    private func stepRestart(_ vpn: VPNManager) async {
        set("restart", .running)
        let host = "www.gstatic.com"
        let ip = await Task.detached { Self.resolve(host) }.value
        guard let ip, ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") else {
            set("restart", .skip, String(localized: "当前不是 Fake-IP 模式（\(host) → \(ip ?? "-")）")); return
        }
        await vpn.disconnectAndWait()
        let t0 = Date()
        guard await vpn.connectAndWait(timeout: 30) else {
            set("restart", .fail, String(localized: "重连失败：") + (vpn.lastError ?? "-")); return
        }
        let reconnectMs = Self.ms(t0)
        let mapped = await Self.httpProbe(ip: ip, host: host)
        let stale = await Self.httpProbe(ip: "198.18.251.77", host: host)
        let mappedOK = mapped.hasPrefix("HTTP/")
        let staleOK = stale.hasPrefix("refused") || stale.hasPrefix("reset")
        let d = String(localized: "重连 \(reconnectMs) ms") + "\n"
            + String(localized: "旧映射 \(ip)：") + mapped + "\n"
            + String(localized: "无映射的 Fake-IP：") + stale
        set("restart", mappedOK && staleOK ? .pass : .fail, d)
    }

    nonisolated private static func resolve(_ host: String) -> String? {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard let sa = first.pointee.ai_addr else { return nil }
        let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var a = sin.sin_addr
        inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }

    /// One HTTP HEAD to ip:80 with Host: host. Returns the status line, "refused …" / "reset …" / "closed …" / "timeout".
    nonisolated private static func httpProbe(ip: String, host: String) async -> String {
        await withCheckedContinuation { (c: CheckedContinuation<String, Never>) in
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: 80, using: .tcp)
            let q = DispatchQueue(label: "selfcheck.probe")
            let lock = NSLock()
            var done = false
            func finish(_ s: String) {
                lock.lock(); let first = !done; done = true; lock.unlock()
                guard first else { return }
                conn.cancel()
                c.resume(returning: s)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: Data("HEAD /generate_204 HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8), completion: .contentProcessed { _ in })
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, eof, err in
                        if let data, !data.isEmpty {
                            finish(String(decoding: data.prefix(40), as: UTF8.self).components(separatedBy: "\r\n").first ?? "HTTP/?")
                        } else if let err {
                            finish("reset (\(err))")
                        } else if eof {
                            finish("closed (FIN)")
                        }
                    }
                case .failed(let e), .waiting(let e):
                    if case .posix(let code) = e, code == .ECONNRESET { finish("reset (\(e))") } else { finish("refused (\(e))") }
                default: break
                }
            }
            conn.start(queue: q)
            q.asyncAfter(deadline: .now() + 8) { finish("timeout") }
        }
    }
}
