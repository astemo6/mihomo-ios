import XCTest
import UIKit

/// probe/kit-e2e: drive a REAL group delay test over every node of the tools/server-test kit
/// profile (seed "UITest Kit", group "Tern-Test", 40 reference servers on the zhiheng VPS).
/// Nothing hard-asserts a measurement: the verdicts are the printed KIT-RESULT lines
/// (a numeric label = the node's handshake + proxied fetch worked; anything else is evidence).
extension TernUITests {

    /// test97 — readback only (probe/kit-e2e): which members the 策略 page ACTUALLY renders
    /// for Tern-Test in a real -UITestKitProbe launch, and whether the page is live
    /// (测速经由内核) or offline (离线测速). Every app-process audit says 40/40, yet
    /// test99's per-name lookup misses exactly the YAML tail six — this separates
    /// "the page has 34" from "the page has 40 but the lookup/scroll misses them".
    func test97_KitMembersReadback() {
        allowHan = true
        launch(["-UITestKitProbe"])
        tab(1)
        var out = "===== MEMBERS READBACK =====\n"
        let group = app.element(id: "policy.card.Tern-Test")
        out += "card-exists: \(group.waitForExistence(timeout: 30))\n"
        // live vs offline caption (TestTargetCaption on the policy page)
        let liveCap = app.staticTexts.containing(NSPredicate(format: "label CONTAINS '测速经由内核'")).firstMatch
        let offCap = app.staticTexts.containing(NSPredicate(format: "label CONTAINS '离线测速'")).firstMatch
        out += "caption: live=\(liveCap.exists) offline=\(offCap.exists)\n"
        if group.exists { group.tap() }
        let pred = NSPredicate(format: "identifier BEGINSWITH 'policy.member.Tern-Test.' AND identifier ENDSWITH '.delay'")
        var found = Set<String>()
        for _ in 0..<30 {
            let els = app.staticTexts.matching(pred)
            for i in 0..<els.count {
                let idf = els.element(boundBy: i).identifier
                let name = idf.dropFirst("policy.member.Tern-Test.".count).dropLast(".delay".count)
                found.insert(String(name))
            }
            if found.count >= 40 { break }
            app.swipeUp()
        }
        out += "rendered(\(found.count)): \(found.sorted().joined(separator: ", "))\n"
        out += "SIX rendered: \(["Tern-OpenConnect", "Tern-TrustTunnel-H2", "Tern-TrustTunnel-H3", "Tern-Sudoku", "Tern-MASQUE-IP", "Tern-MASQUE-UDP"].map { found.contains($0) ? $0 : "\($0)(ABSENT)" }.joined(separator: " | "))\n"
        print(out)
        let att = XCTAttachment(string: out)
        att.name = "kit-members-readback"
        att.lifetime = .keepAlways
        add(att)
    }

    func test99_KitProbe() {
        let names = ["Tern-SOCKS5", "Tern-HTTP", "Tern-HTTPS", "Tern-SS-AEAD", "Tern-SS2022",
                     "Tern-SS-ShadowTLS", "Tern-VMess", "Tern-VMess-WS", "Tern-VLESS",
                     "Tern-VLESS-Reality", "Tern-VLESS-Vision", "Tern-VLESS-MLKEM", "Tern-Trojan",
                     "Tern-Hysteria", "Tern-Hysteria2", "Tern-TUIC", "Tern-AnyTLS",
                     "Tern-Naive-H2", "Tern-Naive-H3", "Tern-SS-Obfs", "Tern-SS-V2ray",
                     "Tern-SS-KCPTun", "Tern-SS-Cloak", "Tern-SS-Restls", "Tern-SSR",
                     "Tern-Snell4", "Tern-Snell5", "Tern-Mieru", "Tern-SSH", "Tern-Brook",
                     "Tern-GOST-Relay", "Tern-Juicity", "Tern-WireGuard", "Tern-AmneziaWG",
                     "Tern-OpenConnect", "Tern-TrustTunnel-H2", "Tern-TrustTunnel-H3",
                     "Tern-Sudoku", "Tern-MASQUE-IP", "Tern-MASQUE-UDP"]
        allowHan = true
        launch(["-UITestKitProbe"])
        tab(1)
        let group = app.element(id: "policy.card.Tern-Test")
        if !group.waitForExistence(timeout: 30) {
            // Self-diagnose: dump what the proxies page actually holds (any policy cards?
            // which labels?) so a missing seed/active state is visible in the log.
            let cards = app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH 'policy.card.'"))
            var ids: [String] = []
            for i in 0..<min(cards.count, 20) { ids.append(cards.element(boundBy: i).identifier) }
            let labels = app.staticTexts.allElementsBoundByIndex.prefix(25).map(\.label)
            print("KIT-DIAG cards=\(ids) labels=\(labels)")
            XCTFail("Tern-Test group card — diag printed above")
            return
        }
        group.tap()
        let test = app.element(id: "policy.test.Tern-Test")
        XCTAssertTrue(test.waitForExistence(timeout: 10), "Tern-Test test button")
        // Wait until the member grid exists (first member's delay label).
        let firstDelay = app.element(id: "policy.member.Tern-Test.Tern-SOCKS5.delay")
        XCTAssertTrue(firstDelay.waitForExistence(timeout: 10), "member grid")
        test.tap()
        // Members probe in parallel with a 5 s per-node timeout; slow starters and the
        // tunnel-type nodes can take longer to settle — poll the labels for up to 3 minutes.
        // probe/kit-e2e fix: the member rows live in a LazyVStack — a row that has never
        // been scrolled into the build window does not exist as an accessibility element.
        // The old version never scrolled, so the last three rows (the YAML tail:
        // OpenConnect, TrustTunnel-H2/H3, Sudoku, MASQUE-IP/UDP) were reported
        // "<missing>" although the app renders all 40 (test97 readback: rendered 40/40).
        // Collect labels DURING scroll passes into a local map — a row scrolled past is
        // destroyed again, so re-querying at the end would lose it the same way.
        var labels: [String: String] = [:]
        func collect() {
            for n in names {
                let el = app.element(id: "policy.member.Tern-Test.\(n).delay")
                if el.exists, !el.label.isEmpty { labels[n] = el.label }
            }
        }
        let deadline = Date().addingTimeInterval(180)
        var round = 0
        while Date() < deadline {
            collect()
            let pending = names.filter { labels[$0] == nil || labels[$0] == "—" }
            if pending.isEmpty { break }
            // Sweep down through the list, then back up: every row gets built (and its
            // settled label collected) on at least one pass per round.
            if round % 2 == 0 { app.swipeUp() } else { app.swipeDown() }
            round += 1
            usleep(500_000)
        }
        // Final full pass in both directions so a label that settled late is picked up.
        for _ in 0..<8 { collect(); app.swipeUp() }
        for _ in 0..<8 { collect(); app.swipeDown() }
        collect()
        snap("kit-probe-result")
        var report = ""
        for n in names {
            report += "KIT-RESULT \(n) = \(labels[n] ?? "<missing>")\n"
        }
        print(report)
        // The workflow's log step greps the runner output and drops print() lines on a
        // passing run — carry the verdicts as a text attachment in the xcresult instead.
        let att = XCTAttachment(string: report)
        att.name = "kit-results"
        att.lifetime = .keepAlways
        add(att)
        // WG phase-3 diagnostics (fix/kit-wireguard-prod): pull the extension's own words out
        // through the pasteboard (shared on the simulator): 更多 → 复制启动日志, and
        // 工具 → 运行日志 → copy-all toolbar button.
        var dump = ""
        tab(4)
        let copyStart = app.buttons["复制启动日志"]
        for _ in 0..<10 where !copyStart.exists { app.swipeUp() }
        if copyStart.exists {
            copyStart.tap()
            usleep(800_000)
            if let s = UIPasteboard.general.string, !s.isEmpty {
                dump += "STARTUP-PASTE:\n\(s)\n"
            }
        }
        tab(3)
        let logsCard = app.staticTexts["运行日志"]
        if logsCard.waitForExistence(timeout: 8) {
            logsCard.tap()
            usleep(3_000_000)
            UIPasteboard.general.string = "WG-PASTE-MARKER"
            let candidates = app.buttons.allElementsBoundByIndex.filter {
                $0.label.contains("doc.on.doc") || $0.identifier.contains("doc.on.doc")
            }
            if let b = candidates.first {
                b.tap()
                usleep(800_000)
                if let s = UIPasteboard.general.string, s != "WG-PASTE-MARKER" {
                    let wg = s.split(separator: "\n").filter { $0.contains("WireGuard") || $0.contains("AmneziaWG") }
                    dump += "CORELOG-PASTE (\(wg.count) wg lines of \(s.split(separator: "\n").count)):\n" + wg.joined(separator: "\n") + "\n"
                } else {
                    dump += "CORELOG-PASTE: <pasteboard unchanged>\n"
                }
            } else {
                dump += "CORELOG-PASTE: <copy button not found; buttons: \(app.buttons.allElementsBoundByIndex.map(\.label))>\n"
            }
        }
        let att2 = XCTAttachment(string: dump.isEmpty ? "<no wg log lines found>" : dump)
        att2.name = "wg-logs"
        att2.lifetime = .keepAlways
        add(att2)
        assertAlive("kit probe")
    }
}
