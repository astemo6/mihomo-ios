import SwiftUI
import UIKit

/// test/selftest: synthetic demo state for the simulator UI tests (UITests/, .github/workflows/ui-tests.yml).
///
/// Active only when the app is launched with `-UITestSeed` (never on a device otherwise):
/// - `MihomoApp.init` calls `resetIfNeeded()` first: the app's container and defaults are wiped, onboarding and
///   the exit-IP lookups are switched off (no network data in screenshots).
/// - `RootView` runs `seedIfNeeded()`: one demo profile (documentation IPs 192.0.2.x / 198.51.100.x, fake keys,
///   select / url-test / fallback / hidden groups, a file proxy-provider stub), manual nodes from share links,
///   a node subscription stub with a cached node file, a local module with a panel, and the sample import files
///   (QX, Surge, Clash, Loon, share links) under Documents/UITestSamples.
/// - `-UITestImport <file>` then opens that sample through ImportRouter like 「用 Mihomo 打开」.
/// Nothing here is real user data.
enum UITestSeed {
    static var args: [String] { ProcessInfo.processInfo.arguments }
    static var enabled: Bool { args.contains("-UITestSeed") }

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
        guard enabled, !keepData else { return }
        let fm = FileManager.default
        for dir in [AppShared.containerURL, fm.urls(for: .documentDirectory, in: .userDomainMask)[0]] {
            for u in (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] { try? fm.removeItem(at: u) }
        }
        if let bid = Bundle.main.bundleIdentifier { UserDefaults.standard.removePersistentDomain(forName: bid) }
        UserDefaults(suiteName: AppShared.appGroup)?.removePersistentDomain(forName: AppShared.appGroup)
        UserDefaults.standard.set(true, forKey: "onboardingDone.v1")
        AppShared.defaults.set("disabled", forKey: IPInfoFetcher.checkerKey)
    }

    @MainActor
    static func seedIfNeeded() async {
        guard enabled, !ready else { return }
        defer { ready = true }
        // feat/surge-ui: first-run look (no profile at all) for the empty-state screenshots.
        if args.contains("-UITestNoProfile") { return }
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
                _ = try await store.addLocal(name: "UITest Demo", text: profileYAML)
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
            // feat/policy-chain: nested groups with CJK names (节点选择 → 日本节点 → 东京 …) for the chain subtitles on 策略.
            if args.contains("-UITestPolicyChain"), !store.profiles.contains(where: { $0.name == "UITest Chain" }) {
                let p = try await store.addLocal(name: "UITest Chain", text: policyChainYAML)
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
