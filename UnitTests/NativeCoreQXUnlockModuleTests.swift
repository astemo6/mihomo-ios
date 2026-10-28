import XCTest
@testable import Tern

/// fix/nc-tls-scripts (device build506: 喜马拉雅解锁 scripts never fired, 脚本日志 empty): the real Quantumult X unlock
/// module (rewrite_local + 246-entry `hostname =` line with duplicates, wildcards, IP globs and fake-ip globs) through
/// the App's module build → rewrite snapshot → the tunnel's NativeRewriteEngine / NCMitmGate.
final class NativeCoreQXUnlockModuleTests: XCTestCase {

    static let module = #"""
#!name=喜马拉雅解锁 (QX fixture)
[rewrite_local]

# > 喜马拉雅+会员解锁+大师课+音质/音效/下载/播放器皮肤
^https?:\/\/.+((ximalaya)|(xmcdn)).+(mobile-user\/v2\/homePage|product\/detail\/v1|v1\/album\/track\/ts|mobile-playpage\/track\/v4\/baseInfo\/ts|mobile-playpage\/playpage\/tabs\/v2|mobile-playpage\/playpage\/track\/qualityAndEffect|mobile\/download\/v2\/track|mobile-user-grade\/decoratorV2\/decorationDetails\/page|mobile-album\/album\/plant\/grass) url script-response-body https://raw.githubusercontent.com/WeiGiegie/666/main/ximalaya.js
#  > 去广告
^https?://passport\.ximalaya\.com/friendship-mobile/v1/findFriendsBanner/show/ url reject
^https?://xdcs-collector\.ximalaya\.com/api/v1/realtime url reject
^https?://adse\.wsa\.ximalaya\.com url reject
^https?://adse\.ximalaya\.com url reject
^https?://ad\.ximalaya\.com url reject
^https?://ulogs\.umeng\.com\/unify_logs url reject
^https?://.+ximalaya\.com/x-web-activity/signIn/getHomePageSignInInfo/ url reject-200
^https?://.+ximalaya\.com/product/promotion/v1/album/price url reject-200
#底部弹出会员购买页面
^https?://mobile\.ximalaya\.com/business-sale-promotion-guide-mobile-web/popup/info/ url reject
[mitm]
hostname = mobwsa.ximalaya.com,mobile.ximalaya.com, apisg.himalaya.com,36.150.215.*,61.172.194.*,180.153.*.*,180.153.255.*,180.153.140.*,180.153.250.*,114.80.99.*,114.80.139.2*,61.162.174.*,119.188.123.*,59.83.227.*,114.80.161.29,1.62.62.64,1.194.255.171,23.236.99.89,36.99.200.135,42.81.4.198,42.81.26.128,42.81.120.58,43.152.24.12,43.152.24.18,43.152.25.127,43.152.29.38,43.175.16.34,43.175.22.25,43.175.44.15,49.7.69.197,49.51.224.95,101.33.11.32,101.33.11.106,101.33.20.34,101.33.29.110,103.105.60.99,140.249.84.135,140.249.85.189,150.109.90.80,150.109.91.35,150.138.47.94,150.138.136.145,203.205.13*.*,203.205.250.*, 211.152.137.*,47.100.227.85,61.164.145.12, 106.41.204.126,118.25.119.177,223.111.231.198,120.22*.2*.*,43.132.8*.*,101.33.27.*,43.141.11.*,117.34.49.212,36.103.197.65,198.18.1*.*,198.18.2*.*,101.91.13*,36.42.77.*,118.180.43.252,49.119.120.*,58.144.235.61,58.251.62*,221.204.4*.*,112.84.131.*,112.80.180.72,112.98.170.228,112.99.146.108,116.136.188.184,116.162.203.111,116.177.225.247,123.138.8.*,183.204.35.*,183.201.114.*,101.91.135.*,101.91.133.*,101.91.134.*,adse.ximalaya.com,61.170.88.*,101.91.134.*,42.56.64.*,*.xmcdn.com,*.ximalaya.com,61.172.194.*,180.153.*.*,180.153.255.*,180.153.140.*,180.153.250.*,114.80.99.*,114.80.139.2*,61.162.174.*,119.188.123.*,59.83.227.*,114.80.161.29,1.62.62.64,1.194.255.171,23.236.99.89,36.99.200.135,42.81.4.198,42.81.26.128,42.81.120.58,43.152.24.12,43.152.24.18,43.152.25.127,43.152.29.38,43.175.16.34,43.175.22.25,43.175.44.15,49.7.69.197,49.51.224.95,101.33.11.32,101.33.11.106,101.33.20.34,101.33.29.110,103.105.60.99,140.249.84.135,140.249.85.189,150.109.90.80,150.109.91.35,150.138.47.94,150.138.136.145,203.205.13*.*,203.205.250.*,211.152.137.*,47.100.227.85,61.164.145.12,106.41.204.126,112.80.180.72,112.98.170.228, 112.99.146.108,118.25.119.177,223.111.231.198,120.22*.2*.*,43.132.8*.*,101.33.27.*,43.141.11.*,101.89.53.*,36.131.221.*,111.42.194.*,adse.ximalaya.com,36.131.221.*,112.84.131.*,111.6.56.*,111.6.56.228,*.xmcdn.com,120.232.165.228,43.159.71.*,ulogs.umeng.com,www.taobao.com,43.132.81.*,101.33.27.*,61.172.1*.*,43.141.11.*,114.80.99.86,180.153.255.*,114.80.99.*,*.mysteel.*,61.172.194.196,180.153.*.*,*xima*,*xmcdn*,*.ximalaya.com,*.xmcdn.com,180.153.255.*,180.153.140.*,180.153.250.*,114.80.99.*,114.80.139.237,114.80.161.29,1.62.62.64,51*.com,1.194.255.171,23.236.99.89,36.99.200.135,42.81.4.198,42.81.26.128,42.81.120.58,43.132.80.77,43.132.83.175,43.132.84.11,43.152.24.12,43.152.24.18,43.152.25.127,43.152.29.38,43.175.16.34,43.175.22.25,43.175.44.15,49.7.69.197,49.51.224.95,101.33.11.32,101.33.11.106,101.33.20.34,101.33.29.110,103.105.60.99,114.80.99.90,114.80.99.70,114.80.99.71,114.80.99.89,114.80.99.91,114.80.99.88,114.80.99.87,140.249.84.135,140.249.85.189,150.109.90.80,150.109.91.35,150.138.47.94,150.138.136.145,203.205.136.87,203.205.136.100,203.205.136.102,203.205.136.159,203.205.137.27,203.205.137.87,203.205.137.241,203.205.250.111,203.205.250.113,211.152.137.25,ulogs.umeng.com,passport.ximalaya.com,m.ximalaya.com,116.153.*.*,39.156.8.*,183.204.64.*,61.241.178.*,112.64.213.*,43.174.54.*,27.152.187.*,117.161.*.*,183.204.64.*,182.242.50.*,101.91.134.*,123.12.235.*,101.91.135.*,85.211.193.*,111.12.187.*,117.161.169.*,59.37.143.*,42.202.164.*,219.144.82.*,152.67.253.*,42.200.166.*,163.177.58.*,120.240.179.*,36.170.27.*,74.226.216.*
"""#

    private func engine() throws -> (NativeRewriteEngine, NCEngineRuleset, String) {
        let home = NSTemporaryDirectory() + "nc-qx-unlock-\(UUID().uuidString)"
        let modulesDir = home + "/engine/modules"
        try FileManager.default.createDirectory(atPath: modulesDir, withIntermediateDirectories: true)
        try #"{"enabled":true,"scriptsEnabled":true,"mitm":true,"modules":[{"id":"xmly","name":"ximalaya","enabled":true}]}"#
            .write(toFile: home + "/engine/engine.json", atomically: true, encoding: .utf8)
        try Self.module.write(toFile: modulesDir + "/xmly.txt", atomically: true, encoding: .utf8)
        let cfg = NCEngineConfig.load(home: home)
        let rs = NCMitmBuild.build(home: home, cfg: cfg)
        let (data, _) = try NCRewriteSnapshotBuilder.exportData(home: home, cfg: cfg, rs: rs)
        let e = try XCTUnwrap(NativeRewriteEngine(json: String(decoding: data, as: UTF8.self)))
        return (e, rs, home)
    }

    func testHostListParsedDedupedAndKeyHostsIntercepted() throws {
        let (e, rs, home) = try engine()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let distinct = Set(rs.hostnames.map { $0.lowercased() })
        XCTAssertGreaterThanOrEqual(distinct.count, 140, "QX hostname line: 246 entries, ~145 distinct")
        XCTAssertGreaterThanOrEqual(e.mitmHostCount, distinct.count - 2, "no truncation between the module and the snapshot")
        for h in ["mobile.ximalaya.com", "passportws.ximalaya.com", "mwsa.ximalaya.com", "web.c.ximalaya.com",
                  "mobwsa.ximalaya.com", "adse.ximalaya.com", "mermaid.ximalaya.com", "fdfs.xmcdn.com"] {
            XCTAssertTrue(e.intercepts(host: h, port: 443), "\(h) must be a MitM host")
        }
        // HTTPDNS clients connect by IP: IP globs / literals of the list match the destination address.
        for ip in ["180.153.12.34", "114.80.139.237", "203.205.136.87", "61.172.194.196", "101.91.134.7"] {
            XCTAssertTrue(e.intercepts(host: ip, port: 443), "\(ip) (IP glob in the hostname list)")
        }
        XCTAssertFalse(e.intercepts(host: "www.apple.com", port: 443))
    }

    func testGateDecidesMitmForSNIAndForIPWithoutSNI() throws {
        let (e, _, home) = try engine()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let isMitm: (String, Int) -> Bool = { e.intercepts(host: $0, port: $1) }
        let hello = NCTLS13.buildClientHello(random: Data(count: 32), sessionID: Data(count: 32),
                                             serverName: "mobile.ximalaya.com", alpn: ["h2", "http/1.1"], keyShare: Data(count: 32))
        var record = Data([0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)]); record.append(hello)
        // bare IP (HTTPDNS) with SNI
        XCTAssertEqual(NCMitmGate.decide(firstBytes: record, knownDomain: nil, dstIP: "180.153.1.2", port: 443, isMitm: isMitm),
                       .mitm(host: "mobile.ximalaya.com", alpn: ["h2", "http/1.1"]))
        // fake-ip with a known domain: the gate peeks
        XCTAssertTrue(NCMitmGate.shouldPeek(knownDomain: "mobile.ximalaya.com", port: 443, mitmActive: true, mitmPorts: [443], isMitm: isMitm))
    }

    func testScriptRuleMatchesTheUnlockEndpoints() throws {
        let (e, rs, home) = try engine()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let scripts = rs.rules.filter { $0.kind == "script" }
        XCTAssertEqual(scripts.count, 1, "the unlock script-response-body rule: \(rs.rules.map(\.kind)) errors \(rs.errors)")
        XCTAssertEqual(e.scriptRuleCount, scripts.count, "snapshot carries the script rule")
        let re = try NSRegularExpression(pattern: try XCTUnwrap(scripts.first?.pattern))
        for u in ["https://mobile.ximalaya.com/mobile-user/v2/homePage/1700000000000",
                  "https://mobile.ximalaya.com/product/detail/v1/basicInfo/dynamic/ts-1",
                  "http://mobwsa.ximalaya.com/mobile-playpage/track/v4/baseInfo/ts-1?device=iPhone"] {
            XCTAssertNotNil(re.firstMatch(in: u, range: NSRange(u.startIndex..., in: u)), u)
        }
        XCTAssertEqual(scripts.first?.phase, "response")
        XCTAssertEqual(rs.rules.filter { $0.kind != "script" }.count, 9, "9 reject / reject-200 rewrites")
    }

    /// Probe (takeover, 2026-10-28): the regex matches and the snapshot carries the rule, yet on
    /// device the script host is never invoked (no [SCRIPT] ok / skipped / error line in any
    /// diagnostics package). NativeRewriteDriver.native() only creates a ScriptFlow when the
    /// decision is .forward with response.scripts != nil — so: does decide() attach the script
    /// for the unlock endpoints, in either request-target form the session layer can produce?
    func testDecideAttachesResponseScriptForUnlockEndpoints() throws {
        let (e, _, home) = try engine()
        defer { try? FileManager.default.removeItem(atPath: home) }
        func q(_ url: String, absolute: Bool) -> RewriteRequest {
            let u = URL(string: url)!
            var target = u.path
            if let query = u.query { target += "?" + query }
            if absolute { target = url }
            return RewriteRequest(method: "GET", target: target, host: u.host ?? "",
                                  headers: [["Host", u.host ?? ""]], length: 0,
                                  connHost: u.host ?? "", connPort: u.scheme == "http" ? 80 : 443,
                                  tls: u.scheme == "https")
        }
        for url in ["https://mobile.ximalaya.com/mobile-user/v2/homePage/1700000000000",
                    "https://mobile.ximalaya.com/product/detail/v1/basicInfo/dynamic/ts-1",
                    "http://mobwsa.ximalaya.com/mobile-playpage/track/v4/baseInfo/ts-1?device=iPhone"] {
            var attached = false
            for absolute in [false, true] {
                let d = e.decide(q(url, absolute: absolute), bodies: false, scripts: true)
                if case .forward(let f) = d {
                    let has = f.response.scripts != nil
                    print("PROBE decide absolute=\(absolute) \(url) -> forward, response.scripts=\(has ? "\(f.response.scripts!.count) step(s)" : "nil")")
                    attached = attached || has
                } else {
                    print("PROBE decide absolute=\(absolute) \(url) -> \(d)")
                }
            }
            XCTAssertTrue(attached, "no request-target form attached the response script for \(url)")
        }
        // Control: a non-matching path on the same host must not gain the script.
        for absolute in [false, true] {
            let d = e.decide(q("https://mobile.ximalaya.com/some/other/path", absolute: absolute), bodies: false, scripts: true)
            if case .forward(let f) = d {
                XCTAssertNil(f.response.scripts, "control URL unexpectedly gained a script (absolute=\(absolute))")
            }
        }
    }
}
