import SwiftUI

/// QX preview 6: demo data + screen selection for the simulator screenshot job in CI
/// (`-qxDemo` adds a local sample profile and skips the first-run page; `-qxScreen home|settings|nodes|policy|other`
/// opens that page). Never active on a device unless launched with these arguments.
enum QXDemo {
    static var args: [String] { ProcessInfo.processInfo.arguments }
    static var enabled: Bool { args.contains("-qxDemo") }
    static var screen: String? {
        guard let i = args.firstIndex(of: "-qxScreen"), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    @MainActor
    static func prepare(store: ProfileStore, nav: QXNavigator) async {
        guard enabled else { return }
        Onboarding.isDone = true
        if store.profiles.isEmpty {
            do { _ = try await store.addLocal(name: "Demo", text: yaml) } catch { StartupLog.write("qxDemo: \(error.localizedDescription)", tag: "app") }
        }
        try? await Task.sleep(nanoseconds: 600_000_000)
        switch screen {
        case "settings": nav.push(.settings)
        case "nodes": nav.push(.dest(.nodeResources))
        case "policy": nav.push(.group("节点选择"))
        case "other": nav.push(.otherSettings)
        case "add": nav.push(.dest(.addNode))
        default: break
        }
    }

    static let yaml = """
    mode: rule
    log-level: info
    proxies:
      - {name: "🇯🇵 东京 01", type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: demo, udp: true}
      - {name: "🇯🇵 东京 02", type: ss, server: 192.0.2.2, port: 8388, cipher: aes-128-gcm, password: demo}
      - {name: "🇭🇰 香港 01", type: trojan, server: 192.0.2.3, port: 443, password: demo, sni: example.com}
      - {name: "🇭🇰 香港 02", type: vless, server: 192.0.2.4, port: 443, uuid: 2f1d5c0e-8c3b-4c4e-9d61-2b8f0a1c7e11, tls: true, servername: example.com}
      - {name: "🇸🇬 新加坡 01", type: hysteria2, server: 192.0.2.5, port: 443, password: demo}
      - {name: "🇺🇸 洛杉矶 01", type: tuic, server: 192.0.2.6, port: 443, uuid: 2f1d5c0e-8c3b-4c4e-9d61-2b8f0a1c7e12, password: demo}
    proxy-groups:
      - {name: "节点选择", type: select, proxies: ["🇯🇵 东京 01", "🇭🇰 香港 01", "🇸🇬 新加坡 01", "🇺🇸 洛杉矶 01", DIRECT]}
      - {name: "回国", type: select, proxies: [DIRECT, "🇭🇰 香港 02"]}
      - {name: "自动测速", type: url-test, proxies: ["🇯🇵 东京 01", "🇯🇵 东京 02", "🇭🇰 香港 01"], url: "https://www.gstatic.com/generate_204", interval: 600}
      - {name: "流媒体", type: select, proxies: ["节点选择", "🇭🇰 香港 02", "🇸🇬 新加坡 01"]}
    rules:
      - DOMAIN-SUFFIX,apple.com,DIRECT
      - DOMAIN-KEYWORD,netflix,流媒体
      - GEOIP,CN,DIRECT
      - MATCH,节点选择
    """
}
