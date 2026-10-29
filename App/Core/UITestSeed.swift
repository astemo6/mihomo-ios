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
                // The kit generator emits mihomo flow-style YAML; if the full profile will not
                // import, fall back to the reduced set (proto5 types dropped) so the probe still
                // measures everything else instead of silently staying on the demo profile.
                var imported: Profile?
                for b64 in [kitProbeB64, kitProbeReducedB64] {
                    if let data = Data(base64Encoded: b64), let text = String(data: data, encoding: .utf8) {
                        if let p = try? await store.addLocal(name: "UITest Kit", text: text) { imported = p; break }
                    }
                }
                if let imported { _ = await store.setActive(imported) }
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
        "cHJveGllczoKLSBuYW1lOiBUZXJuLVNPQ0tTNQogIHR5cGU6IHNvY2tzNQogIHNlcnZlcjogNDUu" +
        "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAxCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6" +
        "IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVybi1IVFRQCiAgdHlw" +
        "ZTogaHR0cAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAyCiAgdXNlcm5hbWU6" +
        "IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCi0gbmFtZTogVGVybi1I" +
        "VFRQUwogIHR5cGU6IGh0dHAKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwMwog" +
        "IHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHRs" +
        "czogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6" +
        "IFRlcm4tU1MtQUVBRAogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDog" +
        "MjQwMDQKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3" +
        "SVNsUW5LcQogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tU1MyMDIyCiAgdHlwZTogc3MKICBzZXJ2" +
        "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNQogIGNpcGhlcjogMjAyMi1ibGFrZTMtYWVz" +
        "LTEyOC1nY20KICBwYXNzd29yZDogYTIrSWdUTG1udHJrNmNJZUY2VUFGdz09CiAgdWRwOiB0cnVl" +
        "Ci0gbmFtZTogVGVybi1TUy1TaGFkb3dUTFMKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5" +
        "LjE1NQogIHBvcnQ6IDI0MDA2CiAgY2lwaGVyOiBhZXMtMTI4LWdjbQogIHBhc3N3b3JkOiBTQUkx" +
        "RzFIaTlJTVd4VDhqMWRZc3QwUnEKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBzaGFkb3ctdGxzCiAg" +
        "Y2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAgIGhvc3Q6IHd3dy5t" +
        "aWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogbzEyRDNZRjdZbWx4RExMTmxURFcKICAgIHZlcnNp" +
        "b246IDMKLSBuYW1lOiBUZXJuLVZNZXNzCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1" +
        "OS4xNTUKICBwb3J0OiAyNDAwNwogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2" +
        "ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB0Y3AKICB1ZHA6" +
        "IHRydWUKLSBuYW1lOiBUZXJuLVZNZXNzLVdTCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1Ljky" +
        "LjE1OS4xNTUKICBwb3J0OiAyNDAwOAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYx" +
        "ZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB3cwogIHVk" +
        "cDogdHJ1ZQogIHdzLW9wdHM6CiAgICBwYXRoOiAveTlkZ2xtNXUKICAgIGhlYWRlcnM6CiAgICAg" +
        "IEhvc3Q6IHRlcm4udGVzdAotIG5hbWU6IFRlcm4tVkxFU1MKICB0eXBlOiB2bGVzcwogIHNlcnZl" +
        "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDA5CiAgdXVpZDogNmNlYjUyMTUtMTViOS00ZWYz" +
        "LThhNDgtNjFlZTZmZjNhZTcxCiAgbmV0d29yazogdGNwCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVy" +
        "bi1WTEVTUy1SZWFsaXR5CiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBw" +
        "b3J0OiAyNDAxMAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQog" +
        "IG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQogIHRsczogdHJ1ZQogIGZsb3c6IHh0bHMtcnByeC12" +
        "aXNpb24KICBzZXJ2ZXJuYW1lOiB3d3cubWljcm9zb2Z0LmNvbQogIGNsaWVudC1maW5nZXJwcmlu" +
        "dDogY2hyb21lCiAgcmVhbGl0eS1vcHRzOgogICAgcHVibGljLWtleTogV3A2UGpUQzNnZmNDRU1R" +
        "M3BHMFJPdXNIZGdBczdMZnN4MDIzZ2ZHREVWWQogICAgc2hvcnQtaWQ6IDIxZGRlM2MzMTEyYmJj" +
        "NGIKLSBuYW1lOiBUZXJuLVZMRVNTLVZpc2lvbgogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45" +
        "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMTEKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
        "MWVlNmZmM2FlNzEKICBuZXR3b3JrOiB0Y3AKICB1ZHA6IHRydWUKICB0bHM6IHRydWUKICBmbG93" +
        "OiB4dGxzLXJwcngtdmlzaW9uCiAgc2VydmVybmFtZTogdGVybi50ZXN0CiAgY2xpZW50LWZpbmdl" +
        "cnByaW50OiBjaHJvbWUKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1WTEVT" +
        "Uy1NTEtFTQogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQw" +
        "MTgKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02MWVlNmZmM2FlNzEKICBuZXR3b3Jr" +
        "OiB0Y3AKICB1ZHA6IHRydWUKICBlbmNyeXB0aW9uOiBtbGtlbTc2OHgyNTUxOXBsdXMubmF0aXZl" +
        "LjBydHQuYlBLNzhRSjkwd2I2R1QxdzNDNlcxazBGY0lIcmZyVDYwZ212SmJnZFd4ZwotIG5hbWU6" +
        "IFRlcm4tVHJvamFuCiAgdHlwZTogdHJvamFuCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9y" +
        "dDogMjQwMTIKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUKICBz" +
        "bmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLUh5c3Rl" +
        "cmlhCiAgdHlwZTogaHlzdGVyaWEKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAx" +
        "MwogIHByb3RvY29sOiB1ZHAKICB1cDogNTAgTWJwcwogIGRvd246IDEwMCBNYnBzCiAgYWxwbjoK" +
        "ICAtIGh5c3RlcmlhCiAgdWRwOiB0cnVlCiAgYXV0aC1zdHI6IEJKT1N1Y3hqWnNVTEpkbnN5TlBU" +
        "CiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1I" +
        "eXN0ZXJpYTIKICB0eXBlOiBoeXN0ZXJpYTIKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
        "OiAyNDAxNAogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1ZQogIHNu" +
        "aTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tVFVJQwog" +
        "IHR5cGU6IHR1aWMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNQogIHV1aWQ6" +
        "IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIHBhc3N3b3JkOiB5ZUNzVXdz" +
        "RmJBaFVZTVVnZGVpQwogIGFscG46CiAgLSBoMwogIHVkcDogdHJ1ZQogIGNvbmdlc3Rpb24tY29u" +
        "dHJvbGxlcjogYmJyCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0g" +
        "bmFtZTogVGVybi1BbnlUTFMKICB0eXBlOiBhbnl0bHMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
        "ICBwb3J0OiAyNDAxNgogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1" +
        "ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4t" +
        "TmFpdmUtSDIKICB0eXBlOiBuYWl2ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0" +
        "MDE3CiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
        "CiAgcXVpYzogZmFsc2UKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRl" +
        "cm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLU5haXZlLUgzCiAg" +
        "dHlwZTogbmFpdmUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNwogIHVzZXJu" +
        "YW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IHRy" +
        "dWUKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNr" +
        "aXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLVNTLU9iZnMKICB0eXBlOiBzcwogIHNl" +
        "cnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIxCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQog" +
        "IHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2lu" +
        "OiBvYmZzCiAgcGx1Z2luLW9wdHM6CiAgICBtb2RlOiBodHRwCiAgICBob3N0OiB3d3cuYmluZy5j" +
        "b20KLSBuYW1lOiBUZXJuLVNTLVYycmF5CiAgdHlwZTogc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4x" +
        "NTUKICBwb3J0OiAyNDAyMgogIGNpcGhlcjogYWVzLTI1Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4" +
        "cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdpbjogdjJyYXktcGx1Z2luCiAg" +
        "cGx1Z2luLW9wdHM6CiAgICBtb2RlOiB3ZWJzb2NrZXQKICAgIGhvc3Q6IHRlcm4udGVzdAogICAg" +
        "cGF0aDogL3k1NjZ5cTJ0Ci0gbmFtZTogVGVybi1TUy1LQ1BUdW4KICB0eXBlOiBzcwogIHNlcnZl" +
        "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIzCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQogIHBh" +
        "c3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBr" +
        "Y3B0dW4KICBwbHVnaW4tb3B0czoKICAgIGtleTogSEo4QWZZNGpCdjZ3Y0QwWGYyMjAKICAgIGNy" +
        "eXB0OiBhZXMKICAgIG1vZGU6IGZhc3QKICAgIG5vY29tcDogdHJ1ZQogICAgc211eHZlcjogMQog" +
        "ICAgZGF0YXNoYXJkOiAxMAogICAgcGFyaXR5c2hhcmQ6IDMKICAgIG10dTogMTM1MAogICAgc25k" +
        "d25kOiAxMDI0CiAgICByY3Z3bmQ6IDEwMjQKLSBuYW1lOiBUZXJuLVNTLUNsb2FrCiAgdHlwZTog" +
        "c3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNAogIGNpcGhlcjogYWVzLTI1" +
        "Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQog" +
        "IHBsdWdpbjogY2xvYWsKICBwbHVnaW4tb3B0czoKICAgIFVJRDogS0NXL1lvUlY0SitGSkQ3YWtY" +
        "YWFxQT09CiAgICBQdWJsaWNLZXk6IHV1RG5lOUtaWFlydDMvMVlsc2tOenBGTTVpMW9ST05BUzNv" +
        "REpQOTh2a289CiAgICBTZXJ2ZXJOYW1lOiB3d3cuYmluZy5jb20KICAgIEVuY3J5cHRpb25NZXRo" +
        "b2Q6IHBsYWluCiAgICBCcm93c2VyU2lnOiBjaHJvbWUKICAgIE51bUNvbm46IDQKICAgIFByb3h5" +
        "TWV0aG9kOiBzaGFkb3dzb2NrcwotIG5hbWU6IFRlcm4tU1MtUmVzdGxzCiAgdHlwZTogc3MKICBz" +
        "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNQogIGNpcGhlcjogYWVzLTI1Ni1nY20K" +
        "ICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdp" +
        "bjogcmVzdGxzCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAg" +
        "IGhvc3Q6IHd3dy5taWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogUDRuYXg2UW9yQzN5SmludlQw" +
        "YVcKICAgIHZlcnNpb24taGludDogdGxzMTMKICAgIHJlc3Rscy1zY3JpcHQ6IDMwMD8xMDAsNDAw" +
        "fjEwMCwzNTB+MTAwLDYwMH4xMDAsMzAwfjIwMCwzMDB+MTAwCi0gbmFtZTogVGVybi1TU1IKICB0" +
        "eXBlOiBzc3IKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNgogIGNpcGhlcjog" +
        "YWVzLTI1Ni1jZmIKICBwYXNzd29yZDogbzhuQXFNdnhsdUwyQ3ZRb2N3ZGcKICBwcm90b2NvbDog" +
        "YXV0aF9hZXMxMjhfbWQ1CiAgb2JmczogdGxzMS4yX3RpY2tldF9hdXRoCiAgdWRwOiB0cnVlCi0g" +
        "bmFtZTogVGVybi1TbmVsbDQKICB0eXBlOiBzbmVsbAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQog" +
        "IHBvcnQ6IDI0MDI3CiAgcHNrOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcKICBwYXNzd29yZDog" +
        "anluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgdmVyc2lvbjogNAogIHVkcDogdHJ1ZQotIG5hbWU6" +
        "IFRlcm4tU25lbGw1CiAgdHlwZTogc25lbGwKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
        "OiAyNDAyOAogIHBzazoganluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgcGFzc3dvcmQ6IGp5bmg1" +
        "ejhVNmc1bGN0R0F5VW53RnhZRwogIHZlcnNpb246IDUKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJu" +
        "LU1pZXJ1CiAgdHlwZTogbWllcnUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAy" +
        "OQogIHRyYW5zcG9ydDogVENQCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NV" +
        "d3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgbXVsdGlwbGV4aW5nOiBNVUxUSVBMRVhJTkdf" +
        "TE9XCi0gbmFtZTogVGVybi1TU0gKICB0eXBlOiBzc2gKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
        "ICBwb3J0OiAyNDAzMAogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJB" +
        "aFVZTVVnZGVpQwotIG5hbWU6IFRlcm4tQnJvb2sKICB0eXBlOiBicm9vawogIHNlcnZlcjogNDUu" +
        "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDMxCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
        "CiAgdHJhbnNwb3J0OiBzZXJ2ZXIKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJuLUdPU1QtUmVsYXkK" +
        "ICB0eXBlOiBnb3N0LXJlbGF5CiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzIK" +
        "ICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB0" +
        "bHM6IHRydWUKICB1ZHA6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6" +
        "IHRydWUKLSBuYW1lOiBUZXJuLUp1aWNpdHkKICB0eXBlOiBqdWljaXR5CiAgc2VydmVyOiA0NS45" +
        "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzMKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
        "MWVlNmZmM2FlNzEKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUK" +
        "ICBjb25nZXN0aW9uLWNvbnRyb2xsZXI6IGJicgogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0" +
        "LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tV2lyZUd1YXJkCiAgdHlwZTogd2lyZWd1YXJkCiAg" +
        "c2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzQKICBpcDogMTAuNjYuMC4yCiAgdWRw" +
        "OiB0cnVlCiAgbXR1OiAxMjgwCiAgZG5zOgogIC0gMS4xLjEuMQogIHByaXZhdGUta2V5OiBPSlZR" +
        "Y0FRdW1sTmlBREJ5akYwM2JFcWxxNWpIRk4yazNERk4wQmFFL0VvPQogIHB1YmxpYy1rZXk6IHBE" +
        "dUhnclJ1STByV2RvZ3JuZFp3dXlyL0Q2OHBVRG9rMUZiWFA5UmswWDA9CiAgcmVtb3RlLWRucy1y" +
        "ZXNvbHZlOiB0cnVlCi0gbmFtZTogVGVybi1BbW5lemlhV0cKICB0eXBlOiB3aXJlZ3VhcmQKICBz" +
        "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNQogIGlwOiAxMC42Ny4wLjIKICB1ZHA6" +
        "IHRydWUKICBtdHU6IDEyODAKICBkbnM6CiAgLSAxLjEuMS4xCiAgcHJpdmF0ZS1rZXk6IFNFVmY4" +
        "WGUveFFqVnREdHM3ekNzS2dINU1vMTRqVDlJVTN4QXFtbzBPVU09CiAgcHVibGljLWtleTogZ3F6" +
        "OVJ2bUl5dXBBZzN3MjV5UC81bjRTYVlzaDlWMUlocjhlVG1rSmZEUT0KICByZW1vdGUtZG5zLXJl" +
        "c29sdmU6IHRydWUKICBhbW5lemlhLXdnLW9wdGlvbjoKICAgIGpjOiA0CiAgICBqbWluOiA0MAog" +
        "ICAgam1heDogNzAKICAgIHMxOiAyOQogICAgczI6IDU2CiAgICBoMTogNjEwODk4MTUxCiAgICBo" +
        "MjogMTI4NTk4MTA4NAogICAgaDM6IDE3Njc1MTc3MzEKICAgIGg0OiAxOTk1MzA0NjUwCi0gbmFt" +
        "ZTogVGVybi1PcGVuQ29ubmVjdAogIHR5cGU6IG9wZW5jb25uZWN0CiAgc2VydmVyOiA0NS45Mi4x" +
        "NTkuMTU1CiAgcG9ydDogMjQwMzYKICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVD" +
        "c1V3c0ZiQWhVWU1VZ2RlaUMKICBkdGxzOiB0cnVlCiAgdWRwOiB0cnVlCiAgc25pOiB0ZXJuLnRl" +
        "c3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1UcnVzdFR1bm5lbC1IMgog" +
        "IHR5cGU6IHRydXN0dHVubmVsCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzcK" +
        "ICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICBx" +
        "dWljOiBmYWxzZQogIHVkcDogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlm" +
        "eTogdHJ1ZQotIG5hbWU6IFRlcm4tVHJ1c3RUdW5uZWwtSDMKICB0eXBlOiB0cnVzdHR1bm5lbAog" +
        "IHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM3CiAgdXNlcm5hbWU6IHRlcm5kcGEz" +
        "CiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgcXVpYzogdHJ1ZQogIHVkcDogdHJ1" +
        "ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4t" +
        "U3Vkb2t1CiAgdHlwZTogc3Vkb2t1CiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQw" +
        "MzgKICBrZXk6IDNjN2JmMGYzZWVkYWUwYmU2NjY2NGIyYjkwNDdmNTRkODljNzRkZjAzNDc1OGIz" +
        "NWFlOTM1OWE0MWM0ZjVkMGU2ZTAyMjk1MTAzNDk3Njg2YWI1NjYzMzhjMDZmZGY3YjE5YWMwYjUw" +
        "YzA2OGEyYTQxZjVmNmY1MTc2ZGFlNDAyCiAgYWVhZC1tZXRob2Q6IGNoYWNoYTIwLXBvbHkxMzA1" +
        "CiAgdGFibGUtdHlwZTogcHJlZmVyX2VudHJvcHkKLSBuYW1lOiBUZXJuLU1BU1FVRS1JUAogIHR5" +
        "cGU6IG1hc3F1ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDM5CiAgbW9kZTog" +
        "Y29ubmVjdC1pcAogIHVyaTogaHR0cHM6Ly9wcm94eToyNDAzOS92cG4KICBzbmk6IHByb3h5CiAg" +
        "bXR1OiAxMjAwCiAgZG5zOgogIC0gMS4xLjEuMQogIHVkcDogdHJ1ZQogIHNraXAtY2VydC12ZXJp" +
        "Znk6IHRydWUKLSBuYW1lOiBUZXJuLU1BU1FVRS1VRFAKICB0eXBlOiBtYXNxdWUKICBzZXJ2ZXI6" +
        "IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDA0MAogIG1vZGU6IGNvbm5lY3QtdWRwCiAgdXNlcm5h" +
        "bWU6IHRlcm4KICBwYXNzd29yZDogdGVybgogIHVyaTogaHR0cHM6Ly90ZXJuLnRlc3Q6MjQwNDAv" +
        "LndlbGwta25vd24vbWFzcXVlL3VkcC97dGFyZ2V0X2hvc3R9L3t0YXJnZXRfcG9ydH0vCiAgdWRw" +
        "OiB0cnVlCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCnByb3h5LWdy" +
        "b3VwczoKLSBuYW1lOiBUZXJuLVRlc3QKICB0eXBlOiBzZWxlY3QKICBwcm94aWVzOgogIC0gVGVy" +
        "bi1TT0NLUzUKICAtIFRlcm4tSFRUUAogIC0gVGVybi1IVFRQUwogIC0gVGVybi1TUy1BRUFECiAg" +
        "LSBUZXJuLVNTMjAyMgogIC0gVGVybi1TUy1TaGFkb3dUTFMKICAtIFRlcm4tVk1lc3MKICAtIFRl" +
        "cm4tVk1lc3MtV1MKICAtIFRlcm4tVkxFU1MKICAtIFRlcm4tVkxFU1MtUmVhbGl0eQogIC0gVGVy" +
        "bi1WTEVTUy1WaXNpb24KICAtIFRlcm4tVkxFU1MtTUxLRU0KICAtIFRlcm4tVHJvamFuCiAgLSBU" +
        "ZXJuLUh5c3RlcmlhCiAgLSBUZXJuLUh5c3RlcmlhMgogIC0gVGVybi1UVUlDCiAgLSBUZXJuLUFu" +
        "eVRMUwogIC0gVGVybi1OYWl2ZS1IMgogIC0gVGVybi1OYWl2ZS1IMwogIC0gVGVybi1TUy1PYmZz" +
        "CiAgLSBUZXJuLVNTLVYycmF5CiAgLSBUZXJuLVNTLUtDUFR1bgogIC0gVGVybi1TUy1DbG9hawog" +
        "IC0gVGVybi1TUy1SZXN0bHMKICAtIFRlcm4tU1NSCiAgLSBUZXJuLVNuZWxsNAogIC0gVGVybi1T" +
        "bmVsbDUKICAtIFRlcm4tTWllcnUKICAtIFRlcm4tU1NICiAgLSBUZXJuLUJyb29rCiAgLSBUZXJu" +
        "LUdPU1QtUmVsYXkKICAtIFRlcm4tSnVpY2l0eQogIC0gVGVybi1XaXJlR3VhcmQKICAtIFRlcm4t" +
        "QW1uZXppYVdHCiAgLSBUZXJuLU9wZW5Db25uZWN0CiAgLSBUZXJuLVRydXN0VHVubmVsLUgyCiAg" +
        "LSBUZXJuLVRydXN0VHVubmVsLUgzCiAgLSBUZXJuLVN1ZG9rdQogIC0gVGVybi1NQVNRVUUtSVAK" +
        "ICAtIFRlcm4tTUFTUVVFLVVEUApydWxlczoKLSBNQVRDSCxUZXJuLVRlc3QK"
    static let kitProbeReducedB64 =
        "cHJveGllczoKLSBuYW1lOiBUZXJuLVNPQ0tTNQogIHR5cGU6IHNvY2tzNQogIHNlcnZlcjogNDUu" +
        "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAxCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6" +
        "IHllQ3NVd3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVybi1IVFRQCiAgdHlw" +
        "ZTogaHR0cAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDAyCiAgdXNlcm5hbWU6" +
        "IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlDCi0gbmFtZTogVGVybi1I" +
        "VFRQUwogIHR5cGU6IGh0dHAKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwMwog" +
        "IHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHRs" +
        "czogdHJ1ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6" +
        "IFRlcm4tU1MtQUVBRAogIHR5cGU6IHNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDog" +
        "MjQwMDQKICBjaXBoZXI6IGFlcy0yNTYtZ2NtCiAgcGFzc3dvcmQ6IEswQWx0OHJnM09Oa0s2Zjk3" +
        "SVNsUW5LcQogIHVkcDogdHJ1ZQotIG5hbWU6IFRlcm4tU1MyMDIyCiAgdHlwZTogc3MKICBzZXJ2" +
        "ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAwNQogIGNpcGhlcjogMjAyMi1ibGFrZTMtYWVz" +
        "LTEyOC1nY20KICBwYXNzd29yZDogYTIrSWdUTG1udHJrNmNJZUY2VUFGdz09CiAgdWRwOiB0cnVl" +
        "Ci0gbmFtZTogVGVybi1TUy1TaGFkb3dUTFMKICB0eXBlOiBzcwogIHNlcnZlcjogNDUuOTIuMTU5" +
        "LjE1NQogIHBvcnQ6IDI0MDA2CiAgY2lwaGVyOiBhZXMtMTI4LWdjbQogIHBhc3N3b3JkOiBTQUkx" +
        "RzFIaTlJTVd4VDhqMWRZc3QwUnEKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBzaGFkb3ctdGxzCiAg" +
        "Y2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAgIGhvc3Q6IHd3dy5t" +
        "aWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogbzEyRDNZRjdZbWx4RExMTmxURFcKICAgIHZlcnNp" +
        "b246IDMKLSBuYW1lOiBUZXJuLVZNZXNzCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1" +
        "OS4xNTUKICBwb3J0OiAyNDAwNwogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2" +
        "ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB0Y3AKICB1ZHA6" +
        "IHRydWUKLSBuYW1lOiBUZXJuLVZNZXNzLVdTCiAgdHlwZTogdm1lc3MKICBzZXJ2ZXI6IDQ1Ljky" +
        "LjE1OS4xNTUKICBwb3J0OiAyNDAwOAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYx" +
        "ZWU2ZmYzYWU3MQogIGFsdGVySWQ6IDAKICBjaXBoZXI6IGF1dG8KICBuZXR3b3JrOiB3cwogIHVk" +
        "cDogdHJ1ZQogIHdzLW9wdHM6CiAgICBwYXRoOiAveTlkZ2xtNXUKICAgIGhlYWRlcnM6CiAgICAg" +
        "IEhvc3Q6IHRlcm4udGVzdAotIG5hbWU6IFRlcm4tVkxFU1MKICB0eXBlOiB2bGVzcwogIHNlcnZl" +
        "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDA5CiAgdXVpZDogNmNlYjUyMTUtMTViOS00ZWYz" +
        "LThhNDgtNjFlZTZmZjNhZTcxCiAgbmV0d29yazogdGNwCiAgdWRwOiB0cnVlCi0gbmFtZTogVGVy" +
        "bi1WTEVTUy1SZWFsaXR5CiAgdHlwZTogdmxlc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBw" +
        "b3J0OiAyNDAxMAogIHV1aWQ6IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQog" +
        "IG5ldHdvcms6IHRjcAogIHVkcDogdHJ1ZQogIHRsczogdHJ1ZQogIGZsb3c6IHh0bHMtcnByeC12" +
        "aXNpb24KICBzZXJ2ZXJuYW1lOiB3d3cubWljcm9zb2Z0LmNvbQogIGNsaWVudC1maW5nZXJwcmlu" +
        "dDogY2hyb21lCiAgcmVhbGl0eS1vcHRzOgogICAgcHVibGljLWtleTogV3A2UGpUQzNnZmNDRU1R" +
        "M3BHMFJPdXNIZGdBczdMZnN4MDIzZ2ZHREVWWQogICAgc2hvcnQtaWQ6IDIxZGRlM2MzMTEyYmJj" +
        "NGIKLSBuYW1lOiBUZXJuLVZMRVNTLVZpc2lvbgogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45" +
        "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMTEKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
        "MWVlNmZmM2FlNzEKICBuZXR3b3JrOiB0Y3AKICB1ZHA6IHRydWUKICB0bHM6IHRydWUKICBmbG93" +
        "OiB4dGxzLXJwcngtdmlzaW9uCiAgc2VydmVybmFtZTogdGVybi50ZXN0CiAgY2xpZW50LWZpbmdl" +
        "cnByaW50OiBjaHJvbWUKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1WTEVT" +
        "Uy1NTEtFTQogIHR5cGU6IHZsZXNzCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQw" +
        "MTgKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02MWVlNmZmM2FlNzEKICBuZXR3b3Jr" +
        "OiB0Y3AKICB1ZHA6IHRydWUKICBlbmNyeXB0aW9uOiBtbGtlbTc2OHgyNTUxOXBsdXMubmF0aXZl" +
        "LjBydHQuYlBLNzhRSjkwd2I2R1QxdzNDNlcxazBGY0lIcmZyVDYwZ212SmJnZFd4ZwotIG5hbWU6" +
        "IFRlcm4tVHJvamFuCiAgdHlwZTogdHJvamFuCiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9y" +
        "dDogMjQwMTIKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUKICBz" +
        "bmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLUh5c3Rl" +
        "cmlhCiAgdHlwZTogaHlzdGVyaWEKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAx" +
        "MwogIHByb3RvY29sOiB1ZHAKICB1cDogNTAgTWJwcwogIGRvd246IDEwMCBNYnBzCiAgYWxwbjoK" +
        "ICAtIGh5c3RlcmlhCiAgdWRwOiB0cnVlCiAgYXV0aC1zdHI6IEJKT1N1Y3hqWnNVTEpkbnN5TlBU" +
        "CiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0gbmFtZTogVGVybi1I" +
        "eXN0ZXJpYTIKICB0eXBlOiBoeXN0ZXJpYTIKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
        "OiAyNDAxNAogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1ZQogIHNu" +
        "aTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tVFVJQwog" +
        "IHR5cGU6IHR1aWMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNQogIHV1aWQ6" +
        "IDZjZWI1MjE1LTE1YjktNGVmMy04YTQ4LTYxZWU2ZmYzYWU3MQogIHBhc3N3b3JkOiB5ZUNzVXdz" +
        "RmJBaFVZTVVnZGVpQwogIGFscG46CiAgLSBoMwogIHVkcDogdHJ1ZQogIGNvbmdlc3Rpb24tY29u" +
        "dHJvbGxlcjogYmJyCiAgc25pOiB0ZXJuLnRlc3QKICBza2lwLWNlcnQtdmVyaWZ5OiB0cnVlCi0g" +
        "bmFtZTogVGVybi1BbnlUTFMKICB0eXBlOiBhbnl0bHMKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
        "ICBwb3J0OiAyNDAxNgogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHVkcDogdHJ1" +
        "ZQogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4t" +
        "TmFpdmUtSDIKICB0eXBlOiBuYWl2ZQogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0" +
        "MDE3CiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
        "CiAgcXVpYzogZmFsc2UKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRl" +
        "cm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLU5haXZlLUgzCiAg" +
        "dHlwZTogbmFpdmUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAxNwogIHVzZXJu" +
        "YW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJBaFVZTVVnZGVpQwogIHF1aWM6IHRy" +
        "dWUKICB1ZHA6IHRydWUKICB1ZHAtb3Zlci10Y3A6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNr" +
        "aXAtY2VydC12ZXJpZnk6IHRydWUKLSBuYW1lOiBUZXJuLVNTLU9iZnMKICB0eXBlOiBzcwogIHNl" +
        "cnZlcjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIxCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQog" +
        "IHBhc3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2lu" +
        "OiBvYmZzCiAgcGx1Z2luLW9wdHM6CiAgICBtb2RlOiBodHRwCiAgICBob3N0OiB3d3cuYmluZy5j" +
        "b20KLSBuYW1lOiBUZXJuLVNTLVYycmF5CiAgdHlwZTogc3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4x" +
        "NTUKICBwb3J0OiAyNDAyMgogIGNpcGhlcjogYWVzLTI1Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4" +
        "cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdpbjogdjJyYXktcGx1Z2luCiAg" +
        "cGx1Z2luLW9wdHM6CiAgICBtb2RlOiB3ZWJzb2NrZXQKICAgIGhvc3Q6IHRlcm4udGVzdAogICAg" +
        "cGF0aDogL3k1NjZ5cTJ0Ci0gbmFtZTogVGVybi1TUy1LQ1BUdW4KICB0eXBlOiBzcwogIHNlcnZl" +
        "cjogNDUuOTIuMTU5LjE1NQogIHBvcnQ6IDI0MDIzCiAgY2lwaGVyOiBhZXMtMjU2LWdjbQogIHBh" +
        "c3N3b3JkOiBLMEFsdDhyZzNPTmtLNmY5N0lTbFFuS3EKICB1ZHA6IGZhbHNlCiAgcGx1Z2luOiBr" +
        "Y3B0dW4KICBwbHVnaW4tb3B0czoKICAgIGtleTogSEo4QWZZNGpCdjZ3Y0QwWGYyMjAKICAgIGNy" +
        "eXB0OiBhZXMKICAgIG1vZGU6IGZhc3QKICAgIG5vY29tcDogdHJ1ZQogICAgc211eHZlcjogMQog" +
        "ICAgZGF0YXNoYXJkOiAxMAogICAgcGFyaXR5c2hhcmQ6IDMKICAgIG10dTogMTM1MAogICAgc25k" +
        "d25kOiAxMDI0CiAgICByY3Z3bmQ6IDEwMjQKLSBuYW1lOiBUZXJuLVNTLUNsb2FrCiAgdHlwZTog" +
        "c3MKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNAogIGNpcGhlcjogYWVzLTI1" +
        "Ni1nY20KICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQog" +
        "IHBsdWdpbjogY2xvYWsKICBwbHVnaW4tb3B0czoKICAgIFVJRDogS0NXL1lvUlY0SitGSkQ3YWtY" +
        "YWFxQT09CiAgICBQdWJsaWNLZXk6IHV1RG5lOUtaWFlydDMvMVlsc2tOenBGTTVpMW9ST05BUzNv" +
        "REpQOTh2a289CiAgICBTZXJ2ZXJOYW1lOiB3d3cuYmluZy5jb20KICAgIEVuY3J5cHRpb25NZXRo" +
        "b2Q6IHBsYWluCiAgICBCcm93c2VyU2lnOiBjaHJvbWUKICAgIE51bUNvbm46IDQKICAgIFByb3h5" +
        "TWV0aG9kOiBzaGFkb3dzb2NrcwotIG5hbWU6IFRlcm4tU1MtUmVzdGxzCiAgdHlwZTogc3MKICBz" +
        "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNQogIGNpcGhlcjogYWVzLTI1Ni1nY20K" +
        "ICBwYXNzd29yZDogSzBBbHQ4cmczT05rSzZmOTdJU2xRbktxCiAgdWRwOiBmYWxzZQogIHBsdWdp" +
        "bjogcmVzdGxzCiAgY2xpZW50LWZpbmdlcnByaW50OiBjaHJvbWUKICBwbHVnaW4tb3B0czoKICAg" +
        "IGhvc3Q6IHd3dy5taWNyb3NvZnQuY29tCiAgICBwYXNzd29yZDogUDRuYXg2UW9yQzN5SmludlQw" +
        "YVcKICAgIHZlcnNpb24taGludDogdGxzMTMKICAgIHJlc3Rscy1zY3JpcHQ6IDMwMD8xMDAsNDAw" +
        "fjEwMCwzNTB+MTAwLDYwMH4xMDAsMzAwfjIwMCwzMDB+MTAwCi0gbmFtZTogVGVybi1TU1IKICB0" +
        "eXBlOiBzc3IKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAyNgogIGNpcGhlcjog" +
        "YWVzLTI1Ni1jZmIKICBwYXNzd29yZDogbzhuQXFNdnhsdUwyQ3ZRb2N3ZGcKICBwcm90b2NvbDog" +
        "YXV0aF9hZXMxMjhfbWQ1CiAgb2JmczogdGxzMS4yX3RpY2tldF9hdXRoCiAgdWRwOiB0cnVlCi0g" +
        "bmFtZTogVGVybi1TbmVsbDQKICB0eXBlOiBzbmVsbAogIHNlcnZlcjogNDUuOTIuMTU5LjE1NQog" +
        "IHBvcnQ6IDI0MDI3CiAgcHNrOiBqeW5oNXo4VTZnNWxjdEdBeVVud0Z4WUcKICBwYXNzd29yZDog" +
        "anluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgdmVyc2lvbjogNAogIHVkcDogdHJ1ZQotIG5hbWU6" +
        "IFRlcm4tU25lbGw1CiAgdHlwZTogc25lbGwKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0" +
        "OiAyNDAyOAogIHBzazoganluaDV6OFU2ZzVsY3RHQXlVbndGeFlHCiAgcGFzc3dvcmQ6IGp5bmg1" +
        "ejhVNmc1bGN0R0F5VW53RnhZRwogIHZlcnNpb246IDUKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJu" +
        "LU1pZXJ1CiAgdHlwZTogbWllcnUKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAy" +
        "OQogIHRyYW5zcG9ydDogVENQCiAgdXNlcm5hbWU6IHRlcm5kcGEzCiAgcGFzc3dvcmQ6IHllQ3NV" +
        "d3NGYkFoVVlNVWdkZWlDCiAgdWRwOiB0cnVlCiAgbXVsdGlwbGV4aW5nOiBNVUxUSVBMRVhJTkdf" +
        "TE9XCi0gbmFtZTogVGVybi1TU0gKICB0eXBlOiBzc2gKICBzZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUK" +
        "ICBwb3J0OiAyNDAzMAogIHVzZXJuYW1lOiB0ZXJuZHBhMwogIHBhc3N3b3JkOiB5ZUNzVXdzRmJB" +
        "aFVZTVVnZGVpQwotIG5hbWU6IFRlcm4tQnJvb2sKICB0eXBlOiBicm9vawogIHNlcnZlcjogNDUu" +
        "OTIuMTU5LjE1NQogIHBvcnQ6IDI0MDMxCiAgcGFzc3dvcmQ6IHllQ3NVd3NGYkFoVVlNVWdkZWlD" +
        "CiAgdHJhbnNwb3J0OiBzZXJ2ZXIKICB1ZHA6IHRydWUKLSBuYW1lOiBUZXJuLUdPU1QtUmVsYXkK" +
        "ICB0eXBlOiBnb3N0LXJlbGF5CiAgc2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzIK" +
        "ICB1c2VybmFtZTogdGVybmRwYTMKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB0" +
        "bHM6IHRydWUKICB1ZHA6IHRydWUKICBzbmk6IHRlcm4udGVzdAogIHNraXAtY2VydC12ZXJpZnk6" +
        "IHRydWUKLSBuYW1lOiBUZXJuLUp1aWNpdHkKICB0eXBlOiBqdWljaXR5CiAgc2VydmVyOiA0NS45" +
        "Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzMKICB1dWlkOiA2Y2ViNTIxNS0xNWI5LTRlZjMtOGE0OC02" +
        "MWVlNmZmM2FlNzEKICBwYXNzd29yZDogeWVDc1V3c0ZiQWhVWU1VZ2RlaUMKICB1ZHA6IHRydWUK" +
        "ICBjb25nZXN0aW9uLWNvbnRyb2xsZXI6IGJicgogIHNuaTogdGVybi50ZXN0CiAgc2tpcC1jZXJ0" +
        "LXZlcmlmeTogdHJ1ZQotIG5hbWU6IFRlcm4tV2lyZUd1YXJkCiAgdHlwZTogd2lyZWd1YXJkCiAg" +
        "c2VydmVyOiA0NS45Mi4xNTkuMTU1CiAgcG9ydDogMjQwMzQKICBpcDogMTAuNjYuMC4yCiAgdWRw" +
        "OiB0cnVlCiAgbXR1OiAxMjgwCiAgZG5zOgogIC0gMS4xLjEuMQogIHByaXZhdGUta2V5OiBPSlZR" +
        "Y0FRdW1sTmlBREJ5akYwM2JFcWxxNWpIRk4yazNERk4wQmFFL0VvPQogIHB1YmxpYy1rZXk6IHBE" +
        "dUhnclJ1STByV2RvZ3JuZFp3dXlyL0Q2OHBVRG9rMUZiWFA5UmswWDA9CiAgcmVtb3RlLWRucy1y" +
        "ZXNvbHZlOiB0cnVlCi0gbmFtZTogVGVybi1BbW5lemlhV0cKICB0eXBlOiB3aXJlZ3VhcmQKICBz" +
        "ZXJ2ZXI6IDQ1LjkyLjE1OS4xNTUKICBwb3J0OiAyNDAzNQogIGlwOiAxMC42Ny4wLjIKICB1ZHA6" +
        "IHRydWUKICBtdHU6IDEyODAKICBkbnM6CiAgLSAxLjEuMS4xCiAgcHJpdmF0ZS1rZXk6IFNFVmY4" +
        "WGUveFFqVnREdHM3ekNzS2dINU1vMTRqVDlJVTN4QXFtbzBPVU09CiAgcHVibGljLWtleTogZ3F6" +
        "OVJ2bUl5dXBBZzN3MjV5UC81bjRTYVlzaDlWMUlocjhlVG1rSmZEUT0KICByZW1vdGUtZG5zLXJl" +
        "c29sdmU6IHRydWUKICBhbW5lemlhLXdnLW9wdGlvbjoKICAgIGpjOiA0CiAgICBqbWluOiA0MAog" +
        "ICAgam1heDogNzAKICAgIHMxOiAyOQogICAgczI6IDU2CiAgICBoMTogNjEwODk4MTUxCiAgICBo" +
        "MjogMTI4NTk4MTA4NAogICAgaDM6IDE3Njc1MTc3MzEKICAgIGg0OiAxOTk1MzA0NjUwCnByb3h5" +
        "LWdyb3VwczoKLSBuYW1lOiBUZXJuLVRlc3QKICB0eXBlOiBzZWxlY3QKICBwcm94aWVzOgogIC0g" +
        "VGVybi1TT0NLUzUKICAtIFRlcm4tSFRUUAogIC0gVGVybi1IVFRQUwogIC0gVGVybi1TUy1BRUFE" +
        "CiAgLSBUZXJuLVNTMjAyMgogIC0gVGVybi1TUy1TaGFkb3dUTFMKICAtIFRlcm4tVk1lc3MKICAt" +
        "IFRlcm4tVk1lc3MtV1MKICAtIFRlcm4tVkxFU1MKICAtIFRlcm4tVkxFU1MtUmVhbGl0eQogIC0g" +
        "VGVybi1WTEVTUy1WaXNpb24KICAtIFRlcm4tVkxFU1MtTUxLRU0KICAtIFRlcm4tVHJvamFuCiAg" +
        "LSBUZXJuLUh5c3RlcmlhCiAgLSBUZXJuLUh5c3RlcmlhMgogIC0gVGVybi1UVUlDCiAgLSBUZXJu" +
        "LUFueVRMUwogIC0gVGVybi1OYWl2ZS1IMgogIC0gVGVybi1OYWl2ZS1IMwogIC0gVGVybi1TUy1P" +
        "YmZzCiAgLSBUZXJuLVNTLVYycmF5CiAgLSBUZXJuLVNTLUtDUFR1bgogIC0gVGVybi1TUy1DbG9h" +
        "awogIC0gVGVybi1TUy1SZXN0bHMKICAtIFRlcm4tU1NSCiAgLSBUZXJuLVNuZWxsNAogIC0gVGVy" +
        "bi1TbmVsbDUKICAtIFRlcm4tTWllcnUKICAtIFRlcm4tU1NICiAgLSBUZXJuLUJyb29rCiAgLSBU" +
        "ZXJuLUdPU1QtUmVsYXkKICAtIFRlcm4tSnVpY2l0eQogIC0gVGVybi1XaXJlR3VhcmQKICAtIFRl" +
        "cm4tQW1uZXppYVdHCnJ1bGVzOgotIE1BVENILFRlcm4tVGVzdAo="

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
