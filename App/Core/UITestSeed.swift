import SwiftUI
import UIKit

/// test/selftest: synthetic demo state for the simulator UI tests (UITests/, .github/workflows/ui-tests.yml).
///
/// Active only when the app is launched with `-UITestSeed` (never on a device otherwise):
/// - `TernApp.init` calls `resetIfNeeded()` first: the app's container and defaults are wiped, onboarding and
///   the exit-IP lookups are switched off (no network data in screenshots).
/// - `RootView` runs `seedIfNeeded()`: one demo profile (documentation IPs 192.0.2.x / 198.51.100.x, fake keys,
///   select / url-test / fallback / hidden groups, a file proxy-provider stub), manual nodes from share links,
///   a node subscription stub with a cached node file, a local module with a panel, and the sample import files
///   (QX, Surge, Clash, Loon, share links) under Documents/UITestSamples.
/// - `-UITestImport <file>` then opens that sample through ImportRouter like 「用 Tern 打开」.
/// Nothing here is real user data.
enum UITestSeed {
    static var args: [String] { ProcessInfo.processInfo.arguments }
    /// r7 (review7 OPT-1): Debug builds only. The UI tests build Debug (ui-tests.yml); a Release build launched with
    /// -UITestSeed (devicectl / Xcode) must never wipe the container, so the seed and the wipe are compiled out.
    static var enabled: Bool {
        #if DEBUG
        return args.contains("-UITestSeed")
        #else
        return false
        #endif
    }

    static func value(after flag: String) -> String? {
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    /// Marker the tests wait for (`uitest.ready`).
    @MainActor static var ready = false

    static var samplesURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("UITestSamples", isDirectory: true)
    }

    /// Synchronous, before any store exists.
    /// v0.19.5 relaunch tests: `-UITestKeepData` keeps what the previous launch wrote (no wipe, no re-seed).
    static var keepData: Bool { args.contains("-UITestKeepData") }

    @MainActor static func resetIfNeeded() {
        #if DEBUG
        guard enabled, !keepData else { return }
        let fm = FileManager.default
        for dir in [AppShared.containerURL, fm.urls(for: .documentDirectory, in: .userDomainMask)[0]] {
            for u in (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] { try? fm.removeItem(at: u) }
        }
        if let bid = Bundle.main.bundleIdentifier { UserDefaults.standard.removePersistentDomain(forName: bid) }
        UserDefaults(suiteName: AppShared.appGroup)?.removePersistentDomain(forName: AppShared.appGroup)
        UserDefaults.standard.set(true, forKey: "onboardingDone.v1")
        AppShared.defaults.set("disabled", forKey: IPInfoFetcher.checkerKey)
        #endif
    }

    @MainActor
    static func seedIfNeeded() async {
        guard enabled, !ready else { return }
        defer { ready = true }
        // feat/surge-ui: first-run look (no profile at all) for the empty-state screenshots.
        if args.contains("-UITestNoProfile") { return }
        // feat/nc-warp-register-ui (#166): scripted WARP API for the register UI tests
        // (-UITestWarpMock429 makes every call fail 429, like a rate-limited client).
        if args.contains("-UITestWarpMock") || args.contains("-UITestWarpMock429") {
            WarpMockTransport.install(rateLimited: args.contains("-UITestWarpMock429"))
        }
        let store = ProfileStore.shared
        if keepData && !store.profiles.isEmpty {
            await ProfileInspector.shared.load()
            return
        }
        do {
            let home = AppShared.homeURL
            try FileManager.default.createDirectory(at: home.appendingPathComponent("proxies"), withIntermediateDirectories: true)
            try providerYAML.write(to: home.appendingPathComponent("proxies/uitest-provider.yaml"), atomically: true, encoding: .utf8)
            if store.profiles.isEmpty {
                // fix/modules-only (unified subscription rows): an http 节点集 whose link can be edited in the shared sheet.
                let demo = args.contains("-UITestHTTPProvider") ? profileYAML.replacingOccurrences(of: "\nproxy-providers:\n", with: "\nproxy-providers:\n" + httpProviderYAML) : profileYAML
                _ = try await store.addLocal(name: "UITest Demo", text: demo)
            }
            _ = try await store.addManualNodes(text: manualLinks)
            // v0.19.5 profile switch test: a second local profile with its own groups (stays inactive).
            if args.contains("-UITestSecondProfile"), !store.profiles.contains(where: { $0.name == "UITest Second" }) {
                _ = try await store.addLocal(name: "UITest Second", text: secondProfileYAML)
            }
            // fb-subs-global: an inactive config subscription (remote kind, never downloaded: manual updates only)
            // for the 节点与订阅 swipes and 停用.
            if args.contains("-UITestRemoteProfile"), !store.profiles.contains(where: { $0.name == "UITest Remote" }) {
                var r = try await store.addLocal(name: "UITest Remote", text: secondProfileYAML)
                r.kind = .remote
                r.url = "https://sub.example.invalid/config?token=uitest"
                r.updateIntervalHours = 0
                store.update(r)
            }
            // Back to the demo profile (adding manual nodes keeps the active profile, but be explicit).
            if let demo = store.profiles.first(where: { $0.name == "UITest Demo" }), store.activeID != demo.id {
                _ = await store.setActive(demo)
            }
            // hotfix/group-test-offline: a profile whose top select group holds only other groups (and one group of
            // DIRECT only), made active.
            if args.contains("-UITestGroupsOnly"), !store.profiles.contains(where: { $0.name == "UITest Groups" }) {
                let p = try await store.addLocal(name: "UITest Groups", text: groupsOnlyYAML)
                _ = await store.setActive(p)
            }
            // probe/kit-e2e: the tools/server-test kit profile (40 reference servers on the zhiheng VPS,
            // ports 24001+) as a base64-embedded Clash YAML; test99 drives a group delay test over all of them.
            if args.contains("-UITestKitProbe"), !store.profiles.contains(where: { $0.name == "UITest Kit" }) {
                if let data = Data(base64Encoded: kitProbeB64), let text = String(data: data, encoding: .utf8) {
                    let p = try await store.addLocal(name: "UITest Kit", text: text)
                    _ = await store.setActive(p)
                }
            }
            // feat/policy-chain: nested groups with CJK names (节点选择 → 日本节点 → 东京 …) for the chain subtitles on 策略.
            if args.contains("-UITestPolicyChain"), !store.profiles.contains(where: { $0.name == "UITest Chain" }) {
                let p = try await store.addLocal(name: "UITest Chain", text: policyChainYAML)
                _ = await store.setActive(p)
            }
            // fix/app-policy-ui #3 / #4: a profile with three remote rule sets (http providers, already on disk — never fetched) for 分流规则 →
            // 编辑排序 and the 策略 / 分流规则 row-height comparison.
            if args.contains("-UITestRuleSets"), !store.profiles.contains(where: { $0.name == "UITest RuleSets" }) {
                try FileManager.default.createDirectory(at: home.appendingPathComponent("ruleset"), withIntermediateDirectories: true)
                for n in ["china", "ai", "facebook"] {
                    try "payload:\n  - DOMAIN-SUFFIX,\(n).example\n".write(to: home.appendingPathComponent("ruleset/uitest-\(n).yaml"),
                                                                     atomically: true, encoding: .utf8)
                }
                let p = try await store.addLocal(name: "UITest RuleSets", text: ruleSetsYAML)
                _ = await store.setActive(p)
            }
            // v0.19.6 stress test: a large profile (3000 nodes in one select group, 10000 rules) becomes the active
            // profile, plus 1500 more manual nodes.
            if args.contains("-UITestBigProfile"), !store.profiles.contains(where: { $0.name == "UITest Big" }) {
                let big = try await store.addLocal(name: "UITest Big", text: bigProfileYAML(nodes: 3000, rules: 10000))
                _ = try await store.addManualNodes(text: bigManualLinks(1500))
                _ = await store.setActive(big)
            }
            try seedNodeSubscription()
            EngineStore.shared.addModule(text: moduleText, name: "UITest Panel Module")
            // fix/nc-0.20.2: a second rewrite subscription and two local cron tasks for the reorder-persists tests.
            if args.contains("-UITestReorder") {
                let es = EngineStore.shared
                es.addModule(text: "#!name=UITest Order B\n[URL Rewrite]\n^https?://b\\.example\\.com/ - reject\n", name: "UITest Order B")
                es.config.scripts.append(EngineItem(line: "UITest Task A = type=cron,cronexp=\"0 8 * * *\",script-path=https://example.invalid/uitest-a.js"))
                es.config.scripts.append(EngineItem(line: "UITest Task B = type=cron,cronexp=\"0 9 * * *\",script-path=https://example.invalid/uitest-b.js"))
                es.save()
            }
            try writeSamples()
            if args.contains("-UITestDemoScripts"), let demo = store.profiles.first(where: { $0.name == "UITest Demo" }) {
                OverrideScriptStore.shared.add(demo.id, name: "bettbox-demo.js", source: demoScript)
                var broken = OverrideScriptStore.shared.add(demo.id, name: "broken.js", source: brokenScript)
                broken.enabled = false
                OverrideScriptStore.shared.update(demo.id, broken)
            }
            await ProfileInspector.shared.load()
            await NodeManagerModel.shared.reload()
        } catch {
            StartupLog.write("uitest seed: \(error.localizedDescription)", tag: "app")
        }
        if let name = value(after: "-UITestImport") {
            let url = samplesURL.appendingPathComponent(name)
            try? await Task.sleep(nanoseconds: 400_000_000)
            ImportRouter.shared.handle(url: url)
        }
        if let tab = value(after: "-UITestTab").flatMap(Int.init) { ImportRouter.shared.selectedTab = tab }
        // v0.19 覆写脚本 of the demo profile (the entry is a context-menu / swipe action on 配置).
        if value(after: "-UITestScreen") == "scripts", let p = store.active, let top = ImportRouter.topViewController() {
            let root = NavigationStack { OverrideScriptsView(profile: p) }
                .environmentObject(VPNManager.shared)
                .environmentObject(ProfileStore.shared)
            let vc = UIHostingController(rootView: AnyView(root))
            vc.overrideUserInterfaceStyle = AppAppearance.current.style
            top.present(vc, animated: false)
        }
        // Pages that are only linked while connected (panels): presented directly.
        if value(after: "-UITestScreen") == "panels", let top = ImportRouter.topViewController() {
            let root = NavigationStack { PanelsView() }
                .environmentObject(VPNManager.shared)
                .environmentObject(ProfileStore.shared)
                .environmentObject(DashboardModel.shared)
            let vc = UIHostingController(rootView: AnyView(root))
            vc.overrideUserInterfaceStyle = AppAppearance.current.style
            top.present(vc, animated: false)
        }
    }

    /// v0.19.6: synthetic large profile (documentation addresses, placeholder passwords).
    static func bigProfileYAML(nodes: Int, rules: Int) -> String {
        var y = "mode: rule\nproxies:\n"
        y.reserveCapacity(nodes * 140 + rules * 50)
        for i in 0..<nodes {
            y += "  - {name: \"Big \(String(format: "%05d", i))\", type: ss, server: 192.0.2.\(i % 250 + 1), port: \(10000 + i), cipher: aes-128-gcm, password: pw\(i), udp: true}\n"
        }
        y += "proxy-groups:\n  - name: Big Select\n    type: select\n    proxies:\n"
        for i in 0..<nodes { y += "      - \"Big \(String(format: "%05d", i))\"\n" }
        y += "  - {name: Big Auto, type: url-test, url: 'http://www.gstatic.com/generate_204', interval: 600, include-all-proxies: true}\n"
        y += "  - {name: Big Final, type: select, proxies: [Big Select, Big Auto, DIRECT]}\n"
        y += "rules:\n"
        for i in 0..<rules {
            switch i % 3 {
            case 0: y += "  - DOMAIN-SUFFIX,d\(i).example.com,Big Select\n"
            case 1: y += "  - DOMAIN-KEYWORD,kw\(i),DIRECT\n"
            default: y += "  - IP-CIDR,10.\((i / 256) % 256).\(i % 256).0/24,Big Auto,no-resolve\n"
            }
        }
        y += "  - MATCH,Big Final\n"
        return y
    }

    static func bigManualLinks(_ n: Int) -> String {
        let ui = Data("aes-128-gcm:pw".utf8).base64EncodedString()
        return (0..<n).map { "ss://\(ui)@198.51.100.\($0 % 250 + 1):\(20000 + $0)#BM%20\(String(format: "%04d", $0))" }.joined(separator: "\n")
    }

    /// v0.16 请求 summary test: two TCP + one UDP connection (documentation addresses).
    static func demoConnections() -> [ConnectionItem] {
        let start = ConnectionItem.iso.string(from: Date().addingTimeInterval(-42))
        let json = """
        [{"id":"d1","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"192.0.2.20","sourcePort":"50001","destinationPort":"443","host":"www.example.com"},"upload":20480,"download":1048576,"start":"\(start)","chains":["🇯🇵 Tokyo 01","Proxy"],"rule":"DomainSuffix","rulePayload":"example.com"},
         {"id":"d2","metadata":{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"192.0.2.21","sourcePort":"50002","destinationPort":"443","host":"api.example.org"},"upload":4096,"download":65536,"start":"\(start)","chains":["DIRECT"],"rule":"Match","rulePayload":""},
         {"id":"d3","metadata":{"network":"udp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"192.0.2.53","sourcePort":"50003","destinationPort":"443","host":"quic.example.net"},"upload":1024,"download":8192,"start":"\(start)","chains":["🇺🇸 San Jose 02","Auto"],"rule":"GeoIP","rulePayload":"US"}]
        """
        return (try? JSONDecoder().decode([ConnectionItem].self, from: Data(json.utf8))) ?? []
    }

    /// feat/home-analysis demo (UI tests only, -UITestDemoAnalytics): a private ConnectionAnalytics filled from
    /// synthetic connections (example.* hosts, documentation IPs). Never the live session, never saved to history.
    @MainActor static func demoAnalytics() -> ConnectionAnalytics {
        let a = ConnectionAnalytics()
        a.recordsHistory = false
        // (host, final policy, leaf, rule, payload, connections, MB down per connection)
        let rows: [(String, String, String, String, String, Int, Double)] = [
            ("video.example.com", "Proxy", "🇯🇵 Tokyo 01", "DomainSuffix", "example.com", 12, 6.2),
            ("cdn.example.net", "Streaming", "🇸🇬 Singapore 02", "RuleSet", "streaming", 9, 3.1),
            ("api.example.org", "AI", "🇺🇸 San Jose 02", "DomainKeyword", "example", 18, 0.35),
            ("updates.example.com", "DIRECT", "DIRECT", "GeoIP", "CN", 31, 0.12),
            ("photos.example.net", "Apple", "DIRECT", "DomainSuffix", "example.net", 7, 0.9),
            ("static.example.org", "Proxy", "🇯🇵 Tokyo 01", "Match", "", 14, 0.25),
            ("ads.example.com", "REJECT", "REJECT", "RuleSet", "reject", 23, 0),
            ("mail.example.com", "Auto", "🇺🇸 San Jose 02", "DomainSuffix", "example.com", 5, 0.4),
        ]
        var conns: [ConnectionItem] = []
        var n = 0
        for (host, policy, leaf, rule, payload, count, mb) in rows {
            for i in 0..<count {
                n += 1
                let down = Int64(mb * 1_048_576 * (0.6 + 0.8 * Double(i % 5) / 4))
                let chains = policy == leaf ? [policy] : [leaf, policy]
                conns.append(ConnectionItem(id: "demo-\(n)",
                                            metadata: ConnectionMetadata(network: "tcp", type: "Tun", destinationIP: "192.0.2.\(n % 250 + 1)",
                                                                         destinationPort: "443", host: host),
                                            upload: down / 40 + 2048, download: down, start: nil, chains: chains,
                                            rule: rule, rulePayload: payload))
            }
        }
        a.ingest(conns)
        // A second snapshot: 20 of them are still open (活跃连接).
        a.ingest(Array(conns.prefix(20)))
        return a
    }

    /// v0.17 磁贴编辑 demo (UI tests only): a Surge script panel and a static Stash tile.
    static func demoPanels() -> [PanelItem] {
        let now = Date().timeIntervalSince1970 - 120
        return [
            PanelItem(id: "demo-script", name: "demo-script", title: "Demo Script Panel", content: "Synthetic content", style: "info", icon: "globe",
                      iconColor: nil, script: "demo-script-js", interval: 3600, source: "UITest Panel Module", format: "surge", updated: now,
                      error: nil, running: false),
            PanelItem(id: "demo-tile", name: "demo-tile", title: "Demo Tile", content: "Static tile", style: nil, icon: "info.circle",
                      iconColor: nil, script: nil, interval: nil, source: "UITest Panel Module", format: "stash", updated: nil,
                      error: nil, running: false),
        ]
    }

    /// v0.17 请求时间线 demo (UI tests only): passive records for d1 (proxied) and d2 (DIRECT, DNS seen).
    static func demoTimeline() -> [String: TimelineRecord] {
        let json = """
        [{"id":"d1","host":"www.example.com","network":"tcp","firstUp":{"lo":0,"hi":12.4},"firstDown":{"lo":180.2,"hi":200.2}},
         {"id":"d2","host":"api.example.org","network":"tcp","dns":{"ms":23.5,"upstream":"udp://223.5.5.5:53","beforeMs":4.1},"firstUp":{"lo":0,"hi":9.8},"firstDown":{"lo":40.1,"hi":60.1}},
         {"id":"d3","host":"quic.example.net","network":"udp","preexisting":true}]
        """
        let recs = (try? JSONDecoder().decode([TimelineRecord].self, from: Data(json.utf8))) ?? []
        return Dictionary(uniqueKeysWithValues: recs.map { ($0.id, $0) })
    }

    static func demoProbe(for c: ConnectionItem) -> TimelineProbe {
        let direct = c.chains?.first == "DIRECT"
        let json = direct ? """
        {"host":"\(c.metadata.displayHost)","port":"443","policy":"DIRECT","chain":"DIRECT","remote":"192.0.2.21:443","dns":{"ms":18.2,"note":"内核直连解析器（命中缓存时接近 0）"},"connect":{"ms":31.6,"note":"到目标的 TCP 连接"},"tls":{"ms":64.0},"firstByte":{"ms":88.9,"note":"HEAD / 到第一个响应字节"},"totalMs":202.7,"tlsInfo":"TLS 1.3 · http/1.1","status":"200","ok":true}
        """ : """
        {"host":"\(c.metadata.displayHost)","port":"443","policy":"Proxy","chain":"Proxy → 🇯🇵 Tokyo 01","remote":"192.0.2.20:443","dns":{"note":"经代理时域名由代理服务器解析，本机看不到这段耗时"},"connect":{"ms":52.3,"note":"到代理服务器的连接与代理握手；部分协议在发送数据时才连目标，这部分计入下一阶段"},"tls":{"ms":143.8},"firstByte":{"ms":97.1,"note":"HEAD / 到第一个响应字节"},"totalMs":293.2,"tlsInfo":"TLS 1.3 · http/1.1","status":"301","ok":true}
        """
        return try! JSONDecoder().decode(TimelineProbe.self, from: Data(json.utf8))
    }

    @MainActor static func seedNodeSubscription() throws {
        let id = "uitest-sub"
        let dir = AppShared.homeURL.appendingPathComponent("nodesubs", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try subYAML.write(to: dir.appendingPathComponent("\(id).yaml"), atomically: true, encoding: .utf8)
        let day: TimeInterval = 86400
        let sub = NodeSubscription(id: id, name: "Demo Sub", url: "https://sub.example.invalid/nodes?token=uitest", enabled: true,
                                   lastUpdated: Date().addingTimeInterval(-3600),
                                   userInfo: SubscriptionUserInfo(upload: 3 << 30, download: 21 << 30, total: 100 << 30,
                                                                  expire: Int64(Date().addingTimeInterval(40 * day).timeIntervalSince1970)),
                                   count: 3)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode([sub]).write(to: NodeSubStore.url, options: .atomic)
        NodeSubStore.shared.load()
    }

    static func writeSamples() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: samplesURL, withIntermediateDirectories: true)
        for (name, text) in samples {
            try text.write(to: samplesURL.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
    }

    // MARK: Synthetic data (documentation IP ranges, fake keys)

    /// hotfix/group-test-offline: 「Node Select」 lists only groups (url-test / select / fallback / DIRECT-only).
    /// probe/kit-e2e: tools/server-test kit profile (zhiheng, 40 nodes), base64 of the generated Clash YAML.
    static let kitProbeB64 =
        "IyBUZXJuIOiHqua1i+iuoumYhSDigJQg55SxIHRvb2xzL3NlcnZlci10ZXN0L2luc3RhbGwuc2gg55Sf5oiQCnByb3hpZXM6CiAg" +
        "LSB7bmFtZTogIlRlcm4tU09DS1M1IiwgdHlwZTogInNvY2tzNSIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAw" +
        "MSwgdXNlcm5hbWU6ICJ0ZXJuZHBhMyIsIHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCB1ZHA6IHRydWV9CiAgLSB7" +
        "bmFtZTogIlRlcm4tSFRUUCIsIHR5cGU6ICJodHRwIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDAyLCB1c2Vy" +
        "bmFtZTogInRlcm5kcGEzIiwgcGFzc3dvcmQ6ICJ5ZUNzVXdzRmJBaFVZTVVnZGVpQyJ9CiAgLSB7bmFtZTogIlRlcm4tSFRUUFMi" +
        "LCB0eXBlOiAiaHR0cCIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAwMywgdXNlcm5hbWU6ICJ0ZXJuZHBhMyIs" +
        "IHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCB0bHM6IHRydWUsIHNuaTogInRlcm4udGVzdCIsIHNraXAtY2VydC12" +
        "ZXJpZnk6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tU1MtQUVBRCIsIHR5cGU6ICJzcyIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUi" +
        "LCBwb3J0OiAyNDAwNCwgY2lwaGVyOiAiYWVzLTI1Ni1nY20iLCBwYXNzd29yZDogIkswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcSIs" +
        "IHVkcDogdHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1TUzIwMjIiLCB0eXBlOiAic3MiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1Iiwg" +
        "cG9ydDogMjQwMDUsIGNpcGhlcjogIjIwMjItYmxha2UzLWFlcy0xMjgtZ2NtIiwgcGFzc3dvcmQ6ICJhMitJZ1RMbW50cms2Y0ll" +
        "RjZVQUZ3PT0iLCB1ZHA6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tU1MtU2hhZG93VExTIiwgdHlwZTogInNzIiwgc2VydmVyOiAi" +
        "NDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDA2LCBjaXBoZXI6ICJhZXMtMTI4LWdjbSIsIHBhc3N3b3JkOiAiU0FJMUcxSGk5SU1X" +
        "eFQ4ajFkWXN0MFJxIiwgdWRwOiBmYWxzZSwgcGx1Z2luOiAic2hhZG93LXRscyIsIGNsaWVudC1maW5nZXJwcmludDogImNocm9t" +
        "ZSIsIHBsdWdpbi1vcHRzOiB7aG9zdDogInd3dy5taWNyb3NvZnQuY29tIiwgcGFzc3dvcmQ6ICJvMTJEM1lGN1ltbHhETExObFRE" +
        "VyIsIHZlcnNpb246IDN9fQogIC0ge25hbWU6ICJUZXJuLVZNZXNzIiwgdHlwZTogInZtZXNzIiwgc2VydmVyOiAiNDUuOTIuMTU5" +
        "LjE1NSIsIHBvcnQ6IDI0MDA3LCB1dWlkOiAiNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxIiwgYWx0ZXJJZDog" +
        "MCwgY2lwaGVyOiAiYXV0byIsIG5ldHdvcms6ICJ0Y3AiLCB1ZHA6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tVk1lc3MtV1MiLCB0" +
        "eXBlOiAidm1lc3MiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMDgsIHV1aWQ6ICI2Y2ViNTIxNS0xNWI5LTRl" +
        "ZjMtOGE0OC02MWVlNmZmM2FlNzEiLCBhbHRlcklkOiAwLCBjaXBoZXI6ICJhdXRvIiwgbmV0d29yazogIndzIiwgdWRwOiB0cnVl" +
        "LCB3cy1vcHRzOiB7cGF0aDogIi95OWRnbG01dSIsIGhlYWRlcnM6IHtIb3N0OiAidGVybi50ZXN0In19fQogIC0ge25hbWU6ICJU" +
        "ZXJuLVZMRVNTIiwgdHlwZTogInZsZXNzIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDA5LCB1dWlkOiAiNmNl" +
        "YjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxIiwgbmV0d29yazogInRjcCIsIHVkcDogdHJ1ZX0KICAtIHtuYW1lOiAi" +
        "VGVybi1WTEVTUy1SZWFsaXR5IiwgdHlwZTogInZsZXNzIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDEwLCB1" +
        "dWlkOiAiNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxIiwgbmV0d29yazogInRjcCIsIHVkcDogdHJ1ZSwgdGxz" +
        "OiB0cnVlLCBmbG93OiAieHRscy1ycHJ4LXZpc2lvbiIsIHNlcnZlcm5hbWU6ICJ3d3cubWljcm9zb2Z0LmNvbSIsIGNsaWVudC1m" +
        "aW5nZXJwcmludDogImNocm9tZSIsIHJlYWxpdHktb3B0czoge3B1YmxpYy1rZXk6ICJXcDZQalRDM2dmY0NFTVEzcEcwUk91c0hk" +
        "Z0FzN0xmc3gwMjNnZkdERVZZIiwgc2hvcnQtaWQ6ICIyMWRkZTNjMzExMmJiYzRiIn19CiAgLSB7bmFtZTogIlRlcm4tVkxFU1Mt" +
        "VmlzaW9uIiwgdHlwZTogInZsZXNzIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDExLCB1dWlkOiAiNmNlYjUy" +
        "MTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNhZTcxIiwgbmV0d29yazogInRjcCIsIHVkcDogdHJ1ZSwgdGxzOiB0cnVlLCBmbG93" +
        "OiAieHRscy1ycHJ4LXZpc2lvbiIsIHNlcnZlcm5hbWU6ICJ0ZXJuLnRlc3QiLCBjbGllbnQtZmluZ2VycHJpbnQ6ICJjaHJvbWUi" +
        "LCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlfQogIC0ge25hbWU6ICJUZXJuLVZMRVNTLU1MS0VNIiwgdHlwZTogInZsZXNzIiwgc2Vy" +
        "dmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDE4LCB1dWlkOiAiNmNlYjUyMTUtMTViOS00ZWYzLThhNDgtNjFlZTZmZjNh" +
        "ZTcxIiwgbmV0d29yazogInRjcCIsIHVkcDogdHJ1ZSwgZW5jcnlwdGlvbjogIm1sa2VtNzY4eDI1NTE5cGx1cy5uYXRpdmUuMHJ0" +
        "dC5iUEs3OFFKOTB3YjZHVDF3M0M2VzFrMEZjSUhyZnJUNjBnbXZKYmdkV3hnIn0KICAtIHtuYW1lOiAiVGVybi1Ucm9qYW4iLCB0" +
        "eXBlOiAidHJvamFuIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDEyLCBwYXNzd29yZDogInllQ3NVd3NGYkFo" +
        "VVlNVWdkZWlDIiwgdWRwOiB0cnVlLCBzbmk6ICJ0ZXJuLnRlc3QiLCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlfQogIC0ge25hbWU6" +
        "ICJUZXJuLUh5c3RlcmlhIiwgdHlwZTogImh5c3RlcmlhIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDEzLCBw" +
        "cm90b2NvbDogInVkcCIsIHVwOiAiNTAgTWJwcyIsIGRvd246ICIxMDAgTWJwcyIsIGFscG46IFsiaHlzdGVyaWEiXSwgdWRwOiB0" +
        "cnVlLCBhdXRoLXN0cjogIkJKT1N1Y3hqWnNVTEpkbnN5TlBUIiwgc25pOiAidGVybi50ZXN0Iiwgc2tpcC1jZXJ0LXZlcmlmeTog" +
        "dHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1IeXN0ZXJpYTIiLCB0eXBlOiAiaHlzdGVyaWEyIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1" +
        "NSIsIHBvcnQ6IDI0MDE0LCBwYXNzd29yZDogInllQ3NVd3NGYkFoVVlNVWdkZWlDIiwgdWRwOiB0cnVlLCBzbmk6ICJ0ZXJuLnRl" +
        "c3QiLCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlfQogIC0ge25hbWU6ICJUZXJuLVRVSUMiLCB0eXBlOiAidHVpYyIsIHNlcnZlcjog" +
        "IjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAxNSwgdXVpZDogIjZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MSIs" +
        "IHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCBhbHBuOiBbImgzIl0sIHVkcDogdHJ1ZSwgY29uZ2VzdGlvbi1jb250" +
        "cm9sbGVyOiAiYmJyIiwgc25pOiAidGVybi50ZXN0Iiwgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1B" +
        "bnlUTFMiLCB0eXBlOiAiYW55dGxzIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDE2LCBwYXNzd29yZDogInll" +
        "Q3NVd3NGYkFoVVlNVWdkZWlDIiwgdWRwOiB0cnVlLCBzbmk6ICJ0ZXJuLnRlc3QiLCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlfQog" +
        "IC0ge25hbWU6ICJUZXJuLU5haXZlLUgyIiwgdHlwZTogIm5haXZlIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0" +
        "MDE3LCB1c2VybmFtZTogInRlcm5kcGEzIiwgcGFzc3dvcmQ6ICJ5ZUNzVXdzRmJBaFVZTVVnZGVpQyIsIHF1aWM6IGZhbHNlLCB1" +
        "ZHA6IHRydWUsIHVkcC1vdmVyLXRjcDogdHJ1ZSwgc25pOiAidGVybi50ZXN0Iiwgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZX0KICAt" +
        "IHtuYW1lOiAiVGVybi1OYWl2ZS1IMyIsIHR5cGU6ICJuYWl2ZSIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAx" +
        "NywgdXNlcm5hbWU6ICJ0ZXJuZHBhMyIsIHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCBxdWljOiB0cnVlLCB1ZHA6" +
        "IHRydWUsIHVkcC1vdmVyLXRjcDogdHJ1ZSwgc25pOiAidGVybi50ZXN0Iiwgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZX0KICAtIHtu" +
        "YW1lOiAiVGVybi1TUy1PYmZzIiwgdHlwZTogInNzIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDIxLCBjaXBo" +
        "ZXI6ICJhZXMtMjU2LWdjbSIsIHBhc3N3b3JkOiAiSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxIiwgdWRwOiBmYWxzZSwgcGx1Z2lu" +
        "OiAib2JmcyIsIHBsdWdpbi1vcHRzOiB7bW9kZTogImh0dHAiLCBob3N0OiAid3d3LmJpbmcuY29tIn19CiAgLSB7bmFtZTogIlRl" +
        "cm4tU1MtVjJyYXkiLCB0eXBlOiAic3MiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjIsIGNpcGhlcjogImFl" +
        "cy0yNTYtZ2NtIiwgcGFzc3dvcmQ6ICJLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EiLCB1ZHA6IGZhbHNlLCBwbHVnaW46ICJ2MnJh" +
        "eS1wbHVnaW4iLCBwbHVnaW4tb3B0czoge21vZGU6ICJ3ZWJzb2NrZXQiLCBob3N0OiAidGVybi50ZXN0IiwgcGF0aDogIi95NTY2" +
        "eXEydCJ9fQogIC0ge25hbWU6ICJUZXJuLVNTLUtDUFR1biIsIHR5cGU6ICJzcyIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBw" +
        "b3J0OiAyNDAyMywgY2lwaGVyOiAiYWVzLTI1Ni1nY20iLCBwYXNzd29yZDogIkswQWx0OHJnM09Oa0s2Zjk3SVNsUW5LcSIsIHVk" +
        "cDogZmFsc2UsIHBsdWdpbjogImtjcHR1biIsIHBsdWdpbi1vcHRzOiB7a2V5OiAiSEo4QWZZNGpCdjZ3Y0QwWGYyMjAiLCBjcnlw" +
        "dDogImFlcyIsIG1vZGU6ICJmYXN0Iiwgbm9jb21wOiB0cnVlLCBzbXV4dmVyOiAxLCBkYXRhc2hhcmQ6IDEwLCBwYXJpdHlzaGFy" +
        "ZDogMywgbXR1OiAxMzUwLCBzbmR3bmQ6IDEwMjQsIHJjdnduZDogMTAyNH19CiAgLSB7bmFtZTogIlRlcm4tU1MtQ2xvYWsiLCB0" +
        "eXBlOiAic3MiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjQsIGNpcGhlcjogImFlcy0yNTYtZ2NtIiwgcGFz" +
        "c3dvcmQ6ICJLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EiLCB1ZHA6IGZhbHNlLCBwbHVnaW46ICJjbG9hayIsIHBsdWdpbi1vcHRz" +
        "OiB7VUlEOiAiS0NXL1lvUlY0SitGSkQ3YWtYYWFxQT09IiwgUHVibGljS2V5OiAidXVEbmU5S1pYWXJ0My8xWWxza056cEZNNWkx" +
        "b1JPTkFTM29ESlA5OHZrbz0iLCBTZXJ2ZXJOYW1lOiAid3d3LmJpbmcuY29tIiwgRW5jcnlwdGlvbk1ldGhvZDogInBsYWluIiwg" +
        "QnJvd3NlclNpZzogImNocm9tZSIsIE51bUNvbm46IDQsIFByb3h5TWV0aG9kOiAic2hhZG93c29ja3MifX0KICAtIHtuYW1lOiAi" +
        "VGVybi1TUy1SZXN0bHMiLCB0eXBlOiAic3MiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjUsIGNpcGhlcjog" +
        "ImFlcy0yNTYtZ2NtIiwgcGFzc3dvcmQ6ICJLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EiLCB1ZHA6IGZhbHNlLCBwbHVnaW46ICJy" +
        "ZXN0bHMiLCBjbGllbnQtZmluZ2VycHJpbnQ6ICJjaHJvbWUiLCBwbHVnaW4tb3B0czoge2hvc3Q6ICJ3d3cubWljcm9zb2Z0LmNv" +
        "bSIsIHBhc3N3b3JkOiAiUDRuYXg2UW9yQzN5SmludlQwYVciLCB2ZXJzaW9uLWhpbnQ6ICJ0bHMxMyIsIHJlc3Rscy1zY3JpcHQ6" +
        "ICIzMDA/MTAwLDQwMH4xMDAsMzUwfjEwMCw2MDB+MTAwLDMwMH4yMDAsMzAwfjEwMCJ9fQogIC0ge25hbWU6ICJUZXJuLVNTUiIs" +
        "IHR5cGU6ICJzc3IiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjYsIGNpcGhlcjogImFlcy0yNTYtY2ZiIiwg" +
        "cGFzc3dvcmQ6ICJvOG5BcU12eGx1TDJDdlFvY3dkZyIsIHByb3RvY29sOiAiYXV0aF9hZXMxMjhfbWQ1Iiwgb2JmczogInRsczEu" +
        "Ml90aWNrZXRfYXV0aCIsIHVkcDogdHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1TbmVsbDQiLCB0eXBlOiAic25lbGwiLCBzZXJ2ZXI6" +
        "ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjcsIHBzazogImp5bmg1ejhVNmc1bGN0R0F5VW53RnhZRyIsIHBhc3N3b3JkOiAi" +
        "anluaDV6OFU2ZzVsY3RHQXlVbndGeFlHIiwgdmVyc2lvbjogNCwgdWRwOiB0cnVlfQogIC0ge25hbWU6ICJUZXJuLVNuZWxsNSIs" +
        "IHR5cGU6ICJzbmVsbCIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAyOCwgcHNrOiAianluaDV6OFU2ZzVsY3RH" +
        "QXlVbndGeFlHIiwgcGFzc3dvcmQ6ICJqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUciLCB2ZXJzaW9uOiA1LCB1ZHA6IHRydWV9CiAg" +
        "LSB7bmFtZTogIlRlcm4tTWllcnUiLCB0eXBlOiAibWllcnUiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMjks" +
        "IHRyYW5zcG9ydDogIlRDUCIsIHVzZXJuYW1lOiAidGVybmRwYTMiLCBwYXNzd29yZDogInllQ3NVd3NGYkFoVVlNVWdkZWlDIiwg" +
        "dWRwOiB0cnVlLCBtdWx0aXBsZXhpbmc6ICJNVUxUSVBMRVhJTkdfTE9XIn0KICAtIHtuYW1lOiAiVGVybi1TU0giLCB0eXBlOiAi" +
        "c3NoIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDMwLCB1c2VybmFtZTogInRlcm5kcGEzIiwgcGFzc3dvcmQ6" +
        "ICJ5ZUNzVXdzRmJBaFVZTVVnZGVpQyJ9CiAgLSB7bmFtZTogIlRlcm4tQnJvb2siLCB0eXBlOiAiYnJvb2siLCBzZXJ2ZXI6ICI0" +
        "NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMzEsIHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCB0cmFuc3BvcnQ6ICJz" +
        "ZXJ2ZXIiLCB1ZHA6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tR09TVC1SZWxheSIsIHR5cGU6ICJnb3N0LXJlbGF5Iiwgc2VydmVy" +
        "OiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6IDI0MDMyLCB1c2VybmFtZTogInRlcm5kcGEzIiwgcGFzc3dvcmQ6ICJ5ZUNzVXdzRmJB" +
        "aFVZTVVnZGVpQyIsIHRsczogdHJ1ZSwgdWRwOiB0cnVlLCBzbmk6ICJ0ZXJuLnRlc3QiLCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVl" +
        "fQogIC0ge25hbWU6ICJUZXJuLUp1aWNpdHkiLCB0eXBlOiAianVpY2l0eSIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0" +
        "OiAyNDAzMywgdXVpZDogIjZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MSIsIHBhc3N3b3JkOiAieWVDc1V3c0Zi" +
        "QWhVWU1VZ2RlaUMiLCB1ZHA6IHRydWUsIGNvbmdlc3Rpb24tY29udHJvbGxlcjogImJiciIsIHNuaTogInRlcm4udGVzdCIsIHNr" +
        "aXAtY2VydC12ZXJpZnk6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tV2lyZUd1YXJkIiwgdHlwZTogIndpcmVndWFyZCIsIHNlcnZl" +
        "cjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAzNCwgaXA6ICIxMC42Ni4wLjIiLCB1ZHA6IHRydWUsIG10dTogMTI4MCwgZG5z" +
        "OiBbIjEuMS4xLjEiXSwgcHJpdmF0ZS1rZXk6ICJPSlZRY0FRdW1sTmlBREJ5akYwM2JFcWxxNWpIRk4yazNERk4wQmFFL0VvPSIs" +
        "IHB1YmxpYy1rZXk6ICJwRHVIZ3JSdUkwcldkb2dybmRad3V5ci9ENjhwVURvazFGYlhQOVJrMFgwPSIsIHJlbW90ZS1kbnMtcmVz" +
        "b2x2ZTogdHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1BbW5lemlhV0ciLCB0eXBlOiAid2lyZWd1YXJkIiwgc2VydmVyOiAiNDUuOTIu" +
        "MTU5LjE1NSIsIHBvcnQ6IDI0MDM1LCBpcDogIjEwLjY3LjAuMiIsIHVkcDogdHJ1ZSwgbXR1OiAxMjgwLCBkbnM6IFsiMS4xLjEu" +
        "MSJdLCBwcml2YXRlLWtleTogIlNFVmY4WGUveFFqVnREdHM3ekNzS2dINU1vMTRqVDlJVTN4QXFtbzBPVU09IiwgcHVibGljLWtl" +
        "eTogImdxejlSdm1JeXVwQWczdzI1eVAvNW40U2FZc2g5VjFJaHI4ZVRta0pmRFE9IiwgcmVtb3RlLWRucy1yZXNvbHZlOiB0cnVl" +
        "LCBhbW5lemlhLXdnLW9wdGlvbjoge2pjOiA0LCBqbWluOiA0MCwgam1heDogNzAsIHMxOiAyOSwgczI6IDU2LCBoMTogNjEwODk4" +
        "MTUxLCBoMjogMTI4NTk4MTA4NCwgaDM6IDE3Njc1MTc3MzEsIGg0OiAxOTk1MzA0NjUwfX0KICAtIHtuYW1lOiAiVGVybi1PcGVu" +
        "Q29ubmVjdCIsIHR5cGU6ICJvcGVuY29ubmVjdCIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAzNiwgdXNlcm5h" +
        "bWU6ICJ0ZXJuZHBhMyIsIHBhc3N3b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCBkdGxzOiB0cnVlLCB1ZHA6IHRydWUsIHNu" +
        "aTogInRlcm4udGVzdCIsIHNraXAtY2VydC12ZXJpZnk6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tVHJ1c3RUdW5uZWwtSDIiLCB0" +
        "eXBlOiAidHJ1c3R0dW5uZWwiLCBzZXJ2ZXI6ICI0NS45Mi4xNTkuMTU1IiwgcG9ydDogMjQwMzcsIHVzZXJuYW1lOiAidGVybmRw" +
        "YTMiLCBwYXNzd29yZDogInllQ3NVd3NGYkFoVVlNVWdkZWlDIiwgcXVpYzogZmFsc2UsIHVkcDogdHJ1ZSwgc25pOiAidGVybi50" +
        "ZXN0Iiwgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZX0KICAtIHtuYW1lOiAiVGVybi1UcnVzdFR1bm5lbC1IMyIsIHR5cGU6ICJ0cnVz" +
        "dHR1bm5lbCIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDAzNywgdXNlcm5hbWU6ICJ0ZXJuZHBhMyIsIHBhc3N3" +
        "b3JkOiAieWVDc1V3c0ZiQWhVWU1VZ2RlaUMiLCBxdWljOiB0cnVlLCB1ZHA6IHRydWUsIHNuaTogInRlcm4udGVzdCIsIHNraXAt" +
        "Y2VydC12ZXJpZnk6IHRydWV9CiAgLSB7bmFtZTogIlRlcm4tU3Vkb2t1IiwgdHlwZTogInN1ZG9rdSIsIHNlcnZlcjogIjQ1Ljky" +
        "LjE1OS4xNTUiLCBwb3J0OiAyNDAzOCwga2V5OiAiM2M3YmYwZjNlZWRhZTBiZTY2NjY0YjJiOTA0N2Y1NGQ4OWM3NGRmMDM0NzU4" +
        "YjM1YWU5MzU5YTQxYzRmNWQwZTZlMDIyOTUxMDM0OTc2ODZhYjU2NjMzOGMwNmZkZjdiMTlhYzBiNTBjMDY4YTJhNDFmNWY2ZjUx" +
        "NzZkYWU0MDIiLCBhZWFkLW1ldGhvZDogImNoYWNoYTIwLXBvbHkxMzA1IiwgdGFibGUtdHlwZTogInByZWZlcl9lbnRyb3B5In0K" +
        "ICAtIHtuYW1lOiAiVGVybi1NQVNRVUUtSVAiLCB0eXBlOiAibWFzcXVlIiwgc2VydmVyOiAiNDUuOTIuMTU5LjE1NSIsIHBvcnQ6" +
        "IDI0MDM5LCBtb2RlOiAiY29ubmVjdC1pcCIsIHVyaTogImh0dHBzOi8vcHJveHk6MjQwMzkvdnBuIiwgc25pOiAicHJveHkiLCBt" +
        "dHU6IDEyMDAsIGRuczogWyIxLjEuMS4xIl0sIHVkcDogdHJ1ZSwgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZX0KICAtIHtuYW1lOiAi" +
        "VGVybi1NQVNRVUUtVURQIiwgdHlwZTogIm1hc3F1ZSIsIHNlcnZlcjogIjQ1LjkyLjE1OS4xNTUiLCBwb3J0OiAyNDA0MCwgbW9k" +
        "ZTogImNvbm5lY3QtdWRwIiwgdXNlcm5hbWU6ICJ0ZXJuIiwgcGFzc3dvcmQ6ICJ0ZXJuIiwgdXJpOiAiaHR0cHM6Ly90ZXJuLnRl" +
        "c3Q6MjQwNDAvLndlbGwta25vd24vbWFzcXVlL3VkcC97dGFyZ2V0X2hvc3R9L3t0YXJnZXRfcG9ydH0vIiwgdWRwOiB0cnVlLCBz" +
        "bmk6ICJ0ZXJuLnRlc3QiLCBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlfQpwcm94eS1ncm91cHM6CiAgLSB7bmFtZTogIlRlcm4tVGVz" +
        "dCIsIHR5cGU6ICJzZWxlY3QiLCBwcm94aWVzOiBbIlRlcm4tU09DS1M1IiwgIlRlcm4tSFRUUCIsICJUZXJuLUhUVFBTIiwgIlRl" +
        "cm4tU1MtQUVBRCIsICJUZXJuLVNTMjAyMiIsICJUZXJuLVNTLVNoYWRvd1RMUyIsICJUZXJuLVZNZXNzIiwgIlRlcm4tVk1lc3Mt" +
        "V1MiLCAiVGVybi1WTEVTUyIsICJUZXJuLVZMRVNTLVJlYWxpdHkiLCAiVGVybi1WTEVTUy1WaXNpb24iLCAiVGVybi1WTEVTUy1N" +
        "TEtFTSIsICJUZXJuLVRyb2phbiIsICJUZXJuLUh5c3RlcmlhIiwgIlRlcm4tSHlzdGVyaWEyIiwgIlRlcm4tVFVJQyIsICJUZXJu" +
        "LUFueVRMUyIsICJUZXJuLU5haXZlLUgyIiwgIlRlcm4tTmFpdmUtSDMiLCAiVGVybi1TUy1PYmZzIiwgIlRlcm4tU1MtVjJyYXki" +
        "LCAiVGVybi1TUy1LQ1BUdW4iLCAiVGVybi1TUy1DbG9hayIsICJUZXJuLVNTLVJlc3RscyIsICJUZXJuLVNTUiIsICJUZXJuLVNu" +
        "ZWxsNCIsICJUZXJuLVNuZWxsNSIsICJUZXJuLU1pZXJ1IiwgIlRlcm4tU1NIIiwgIlRlcm4tQnJvb2siLCAiVGVybi1HT1NULVJl" +
        "bGF5IiwgIlRlcm4tSnVpY2l0eSIsICJUZXJuLVdpcmVHdWFyZCIsICJUZXJuLUFtbmV6aWFXRyIsICJUZXJuLU9wZW5Db25uZWN0" +
        "IiwgIlRlcm4tVHJ1c3RUdW5uZWwtSDIiLCAiVGVybi1UcnVzdFR1bm5lbC1IMyIsICJUZXJuLVN1ZG9rdSIsICJUZXJuLU1BU1FV" +
        "RS1JUCIsICJUZXJuLU1BU1FVRS1VRFAiXX0KcnVsZXM6CiAgLSBNQVRDSCxUZXJuLVRlc3QK" 

    static let groupsOnlyYAML = """
    mode: rule
    proxies:
      - {name: "GT Tokyo A", type: ss, server: 192.0.2.41, port: 8388, cipher: aes-128-gcm, password: uitest-gt-a}
      - {name: "GT Tokyo B", type: ss, server: 192.0.2.42, port: 8388, cipher: aes-128-gcm, password: uitest-gt-b}
      - {name: "GT Hong Kong", type: ss, server: 192.0.2.43, port: 8388, cipher: aes-128-gcm, password: uitest-gt-c}
      - {name: "GT Singapore", type: ss, server: 192.0.2.44, port: 8388, cipher: aes-128-gcm, password: uitest-gt-d}
    proxy-groups:
      - {name: Node Select, type: select, proxies: [Auto Select, Japan, Failover, Direct Only]}
      - {name: Auto Select, type: url-test, proxies: ["GT Tokyo A", "GT Hong Kong"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: Japan, type: select, proxies: ["GT Tokyo A", "GT Tokyo B"]}
      - {name: Failover, type: fallback, proxies: ["GT Singapore", "GT Hong Kong"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: Direct Only, type: select, proxies: [DIRECT]}
    rules:
      - MATCH,Node Select
    """

    /// feat/policy-chain: 流媒体 → 节点选择 → 日本节点 → 东京 AZ JP01 (three hops), automatic groups, a node that already
    /// carries its flag, DIRECT / REJECT groups. Servers on 192.0.2.x (TEST-NET-1) never answer.
    static let policyChainYAML = """
    mode: rule
    proxies:
      - {name: "东京 AZ JP01", type: ss, server: 192.0.2.51, port: 8388, cipher: aes-128-gcm, password: uitest-pc-a}
      - {name: "大阪 JP02", type: ss, server: 192.0.2.52, port: 8388, cipher: aes-128-gcm, password: uitest-pc-b}
      - {name: "香港 HK01", type: ss, server: 192.0.2.53, port: 8388, cipher: aes-128-gcm, password: uitest-pc-c}
      - {name: "新加坡 SG01", type: ss, server: 192.0.2.54, port: 8388, cipher: aes-128-gcm, password: uitest-pc-d}
      - {name: "🇺🇸 洛杉矶 US01", type: ss, server: 192.0.2.55, port: 8388, cipher: aes-128-gcm, password: uitest-pc-e}
    proxy-groups:
      - {name: 节点选择, type: select, proxies: [日本节点, 自动选择, 故障转移, 香港节点, DIRECT]}
      - {name: 流媒体, type: select, proxies: [节点选择, 日本节点, DIRECT]}
      - {name: 日本节点, type: select, proxies: ["东京 AZ JP01", "大阪 JP02"]}
      - {name: 自动选择, type: url-test, proxies: ["香港 HK01", "新加坡 SG01"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: 故障转移, type: fallback, proxies: ["🇺🇸 洛杉矶 US01", "新加坡 SG01"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: 香港节点, type: select, proxies: ["香港 HK01"]}
      - {name: 国内直连, type: select, proxies: [DIRECT, 节点选择]}
      - {name: 广告拦截, type: select, proxies: [REJECT, DIRECT]}
    rules:
      - MATCH,节点选择
    """

    static let httpProviderYAML = """
      Demo HTTP Provider:
        type: http
        url: https://provider.uitest.invalid/nodes.yaml
        path: ./proxies/uitest-http-provider.yaml
        interval: 86400

    """

    static let profileYAML = """
    mode: rule
    log-level: info
    proxies:
      - {name: "🇯🇵 Tokyo 01", type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: uitest-secret-ss, udp: true}
      - {name: "🇯🇵 Tokyo 02", type: vmess, server: 192.0.2.2, port: 443, uuid: 00000000-0000-4000-8000-000000000001, alterId: 0, cipher: auto, network: ws, tls: true, servername: example.com, ws-opts: {path: /ws}}
      - {name: "🇭🇰 Hong Kong 01", type: trojan, server: 192.0.2.3, port: 443, password: uitest-secret-trojan, sni: example.com}
      - {name: "🇭🇰 Hong Kong XHTTP", type: vless, server: 192.0.2.4, port: 443, uuid: 00000000-0000-4000-8000-000000000002, tls: true, servername: example.com, network: xhttp, xhttp-opts: {path: /x, mode: auto}, client-fingerprint: chrome}
      - {name: "🇸🇬 Singapore Hy2", type: hysteria2, server: 192.0.2.5, port: 443, password: uitest-secret-hy2, sni: example.com}
      - {name: "🇺🇸 Los Angeles TUIC", type: tuic, server: 192.0.2.6, port: 443, uuid: 00000000-0000-4000-8000-000000000003, password: uitest-secret-tuic, alpn: [h3]}
      - {name: "🇺🇸 San Jose AWG", type: wireguard, server: 192.0.2.7, port: 51820, ip: 10.7.0.2, private-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=, udp: true, amnezia-wg-option: {jc: 4, jmin: 40, jmax: 70, s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4}}
      - {name: "🇩🇪 Frankfurt AnyTLS", type: anytls, server: 192.0.2.8, port: 443, password: uitest-secret-anytls, sni: example.com}
    proxy-providers:
      Demo Provider:
        type: file
        path: ./proxies/uitest-provider.yaml
        health-check: {enable: false, url: "http://www.gstatic.com/generate_204", interval: 600}
    proxy-groups:
      - {name: Proxy, type: select, proxies: [Auto, Fallback, "🇯🇵 Tokyo 01", "🇯🇵 Tokyo 02", "🇭🇰 Hong Kong 01", "🇭🇰 Hong Kong XHTTP", "🇸🇬 Singapore Hy2", "🇺🇸 Los Angeles TUIC", "🇺🇸 San Jose AWG", "🇩🇪 Frankfurt AnyTLS", DIRECT], use: [Demo Provider]}
      - {name: Auto, type: url-test, proxies: ["🇯🇵 Tokyo 01", "🇯🇵 Tokyo 02", "🇭🇰 Hong Kong 01"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: Fallback, type: fallback, proxies: ["🇸🇬 Singapore Hy2", "🇺🇸 Los Angeles TUIC"], url: "http://www.gstatic.com/generate_204", interval: 600}
      - {name: Streaming, type: select, proxies: [Proxy, "🇭🇰 Hong Kong XHTTP", "🇸🇬 Singapore Hy2"]}
      - {name: Apple, type: select, proxies: [DIRECT, Proxy]}
      - {name: Hidden Probe, type: select, hidden: true, proxies: [DIRECT, "🇯🇵 Tokyo 01"]}
      - {name: Final, type: select, proxies: [Proxy, DIRECT]}
    rules:
      - DOMAIN-SUFFIX,apple.com,Apple
      - DOMAIN-KEYWORD,netflix,Streaming
      - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
      - MATCH,Final
    """

    /// fix/app-policy-ui: the demo profile plus three rule sets between its own rules.
    static var ruleSetsYAML: String {
        profileYAML.replacingOccurrences(of: "\nrules:\n", with: """

        rule-providers:
          China: {type: http, behavior: domain, url: "https://rules.example.invalid/china.yaml", path: ./ruleset/uitest-china.yaml, interval: 86400}
          AI: {type: http, behavior: domain, url: "https://rules.example.invalid/ai.yaml", path: ./ruleset/uitest-ai.yaml, interval: 86400}
          Facebook: {type: http, behavior: domain, url: "https://rules.example.invalid/facebook.yaml", path: ./ruleset/uitest-facebook.yaml, interval: 86400}
        rules:
          - RULE-SET,China,DIRECT
          - RULE-SET,AI,Proxy
          - RULE-SET,Facebook,Streaming

        """)
    }

    /// v0.19 覆写脚本 demo: Bettbox-compatible switches (2 policy-group switches + 2 others).
    static let demoScript = """
    const Compatible_With_Bettbox = { ruleOptionsEnable: true, policyGroupOptions: ['AI', 'Video'] };
    const ruleOptionsEnable = { AI: true, Video: true, 'Block Ads': false, 'Low Ratio': false };
    function main(config, profileName) {
      const names = (config.proxies || []).map((p) => p.name);
      const groups = config['proxy-groups'] || [];
      const extra = [];
      if (ruleOptionsEnable.AI) extra.push({ name: 'AI', type: 'select', proxies: ['Proxy', ...names] });
      if (ruleOptionsEnable.Video) extra.push({ name: 'Video', type: 'select', proxies: ['Proxy', 'DIRECT'] });
      const rules = [];
      if (ruleOptionsEnable.AI) rules.push('DOMAIN-SUFFIX,openai.com,AI');
      if (ruleOptionsEnable.Video) rules.push('DOMAIN-SUFFIX,youtube.com,Video');
      if (ruleOptionsEnable['Block Ads']) rules.push('DOMAIN-KEYWORD,adservice,REJECT');
      console.log('profile', profileName, 'groups', extra.length);
      return { ...config, 'proxy-groups': [...groups, ...extra], rules: [...rules, ...(config.rules || [])] };
    }
    """

    static let brokenScript = """
    function main(config) {
      const x = config.proxies.length;
      throw new Error('boom ' + x);
    }
    """

    static let providerYAML = """
    proxies:
      - {name: "🇬🇧 London Provider", type: ss, server: 198.51.100.1, port: 8388, cipher: aes-256-gcm, password: uitest-secret-prov}
      - {name: "🇫🇷 Paris Provider", type: trojan, server: 198.51.100.2, port: 443, password: uitest-secret-prov2, sni: example.com}
    """

    static let subYAML = """
    proxies:
      - {name: "🇰🇷 Seoul Sub 01", type: ss, server: 198.51.100.11, port: 8388, cipher: aes-128-gcm, password: uitest-secret-sub}
      - {name: "🇰🇷 Seoul Sub 02", type: vless, server: 198.51.100.12, port: 443, uuid: 00000000-0000-4000-8000-000000000011, tls: true, servername: example.com, flow: xtls-rprx-vision, client-fingerprint: chrome}
      - {name: "🇹🇼 Taipei Sub", type: hysteria2, server: 198.51.100.13, port: 443, password: uitest-secret-sub2}
    """

    static let secondProfileYAML = """
    proxies:
      - {name: "Second Node A", type: ss, server: 192.0.2.50, port: 8388, cipher: aes-128-gcm, password: uitest-second}
      - {name: "Second Node B", type: ss, server: 192.0.2.51, port: 8388, cipher: aes-128-gcm, password: uitest-second}
    proxy-groups:
      - {name: Second Select, type: select, proxies: ["Second Node A", "Second Node B", DIRECT]}
    rules:
      - MATCH,Second Select
    """

    static let manualLinks = """
    ss://YWVzLTEyOC1nY206dWl0ZXN0LXNlY3JldC1tYW51YWw@203.0.113.1:8388#Manual%20SS
    hysteria2://uitest-secret-manual-hy2@203.0.113.2:443/?sni=example.com#Manual%20Hy2
    trojan://uitest-secret-manual-trojan@203.0.113.3:443?sni=example.com#Manual%20Trojan
    """

    static let moduleText = """
    #!name=UITest Panel Module
    #!desc=Synthetic module for UI tests
    [Panel]
    uitest-panel = script-name=uitest-panel-script, title="UITest Panel", content="Synthetic panel", style=info, update-interval=3600

    [Script]
    uitest-panel-script = type=generic, script-path=https://example.invalid/uitest-panel.js, timeout=5

    [URL Rewrite]
    ^https?://ad\\.example\\.com/ - reject

    [MITM]
    hostname = %APPEND% ad.example.com
    """

    static let samples: [(String, String)] = [
        ("uitest-qx.conf", """
        [general]
        server_check_url=http://www.gstatic.com/generate_204
        [dns]
        server=223.5.5.5
        [policy]
        static=QX Proxy, QX Tokyo, QX Hong Kong, direct
        url-latency-benchmark=QX Auto, QX Tokyo, QX Hong Kong, check-interval=600
        [server_local]
        shadowsocks=192.0.2.21:8388, method=aes-128-gcm, password=uitest-secret-qx, tag=QX Tokyo
        trojan=192.0.2.22:443, password=uitest-secret-qx2, over-tls=true, tls-host=example.com, tag=QX Hong Kong
        [filter_local]
        host-suffix, apple.com, direct
        host-keyword, uitest, QX Proxy
        final, QX Proxy
        [rewrite_local]
        ^https?://ad\\.example\\.com/ url reject
        [mitm]
        hostname = ad.example.com
        """),
        ("uitest-surge.conf", """
        [General]
        loglevel = notify
        dns-server = 223.5.5.5
        [Proxy]
        Surge SS = ss, 192.0.2.31, 8388, encrypt-method=aes-128-gcm, password=uitest-secret-surge
        Surge Trojan = trojan, 192.0.2.32, 443, password=uitest-secret-surge2, sni=example.com
        [Proxy Group]
        Surge Proxy = select, Surge SS, Surge Trojan, DIRECT
        Surge Auto = url-test, Surge SS, Surge Trojan, url=http://www.gstatic.com/generate_204, interval=600
        [Rule]
        DOMAIN-SUFFIX,apple.com,DIRECT
        DOMAIN-KEYWORD,uitest,Surge Proxy
        FINAL,Surge Proxy
        """),
        ("uitest-clash.yaml", """
        mixed-port: 7890
        mode: rule
        proxies:
          - {name: Clash SS, type: ss, server: 192.0.2.41, port: 8388, cipher: aes-128-gcm, password: uitest-secret-clash}
          - {name: Clash Hy2, type: hysteria2, server: 192.0.2.42, port: 443, password: uitest-secret-clash2}
        proxy-groups:
          - {name: Clash Proxy, type: select, proxies: [Clash SS, Clash Hy2, DIRECT]}
        rules:
          - DOMAIN-SUFFIX,apple.com,DIRECT
          - MATCH,Clash Proxy
        """),
        ("uitest-loon.plugin", """
        #!name=UITest Loon Plugin
        #!desc=Synthetic Loon plugin for UI tests
        [Rewrite]
        ^https?:\\/\\/ad\\.example\\.com\\/ reject
        [Script]
        http-response ^https?:\\/\\/api\\.example\\.com\\/v1 script-path=https://example.invalid/uitest.js, requires-body=true, tag=uitest-loon
        [MITM]
        hostname = api.example.com, ad.example.com
        """),
        ("uitest-links.txt", """
        vless://00000000-0000-4000-8000-000000000051@192.0.2.51:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=%2Fx&mode=auto#Link%20VLESS%20XHTTP
        hysteria2://uitest-secret-link@192.0.2.52:443/?sni=example.com#Link%20Hy2
        ss://YWVzLTEyOC1nY206dWl0ZXN0LXNlY3JldC1saW5r@192.0.2.53:8388#Link%20SS
        """),
    ]
}

/// feat/nc-warp-register-ui (#166): a scripted stand-in for the Cloudflare WARP registration API,
/// installed into WarpNodeLifecycle (the one injection point the register sheet, the delete cleanup
/// and re-register all read) when a UI test launches with -UITestWarpMock. Replies mirror the recorded
/// real answers in WarpRegistrationTests; the peer key is a throwaway P-256 public key.
enum WarpMockTransport {
    private static let serverPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyLQM6w+SKoemwhAgPoI/o7uW19Mj
    /qubwonyx+lmqdYjVDGZJFLh4uE4O0xj59VS6k8I7RM/vUhwyZ6/iFQkog==
    -----END PUBLIC KEY-----
    """

    private static func json(_ o: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: o)) ?? Data()
    }

    private static var regReply: Data {
        json(["id": "t.uitest-warp", "type": "a", "model": "PC", "name": "", "key": "x",
              "account": ["id": "acc-uitest", "account_type": "free", "created": "2026-10-27T14:00:00Z",
                          "warp_plus": false, "premium_data": 0, "quota": 0, "license": "LIC-UITEST"],
              "token": "uitest-token", "warp_enabled": false, "waitlist_enabled": false,
              "created": "2026-10-27T14:00:00Z", "updated": "2026-10-27T14:00:00Z",
              "tos": "2026-10-27T14:00:00.000Z", "place": 0, "locale": "en_US", "enabled": true,
              "install_id": "", "fcm_token": ""])
    }

    private static var enrollReply: Data {
        json(["id": "t.uitest-warp", "key": "MFkw", "key_type": "secp256r1", "tunnel_type": "masque",
              "account": ["account_type": "free"],
              "config": ["client_id": "AAAA",
                         "peers": [["public_key": serverPEM,
                                    "endpoint": ["v4": "162.159.198.2:0", "v6": "[2606:4700:103::2]:0",
                                                 "host": "engage.cloudflareclient.com:2408",
                                                 "ports": [443, 500, 1701, 4500]]]],
                         "interface": ["addresses": ["v4": "172.16.0.2", "v6": "2606:4700:110:8a36::2"]],
                         "services": ["http_proxy": "172.16.0.1:2480"]],
              "policy": ["tunnel_protocol": "masque"]])
    }

    static func install(rateLimited: Bool) {
        WarpNodeLifecycle.http = { req in
            let (status, body): (Int, Data)
            if rateLimited {
                (status, body) = (429, Data("slow down".utf8))
            } else {
                switch req.httpMethod ?? "" {
                case "POST": (status, body) = (200, regReply)
                case "PATCH": (status, body) = (200, enrollReply)
                case "DELETE": (status, body) = (204, Data())
                default: (status, body) = (500, Data("unscripted".utf8))
                }
            }
            let resp = HTTPURLResponse(url: req.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
            return (body, resp)
        }
    }
}

/// Invisible marker for the UI tests once the seed has finished.
struct UITestReadyMarker: View {
    @State private var ready = false
    var body: some View {
        Group {
            if UITestSeed.enabled {
                Text(verbatim: ready ? "uitest ready" : "uitest seeding")
                    .font(.system(size: 1))
                    .opacity(0.02)
                    .accessibilityIdentifier(ready ? "uitest.ready" : "uitest.seeding")
                    .allowsHitTesting(false)
                    .task {
                        await UITestSeed.seedIfNeeded()
                        ready = true
                    }
            }
        }
    }
}
