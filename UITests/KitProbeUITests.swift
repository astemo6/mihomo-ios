import XCTest

/// probe/kit-e2e: drive a REAL group delay test over every node of the tools/server-test kit
/// profile (seed "UITest Kit", group "Tern-Test", 40 reference servers on the zhiheng VPS).
/// Nothing hard-asserts a measurement: the verdicts are the printed KIT-RESULT lines
/// (a numeric label = the node's handshake + proxied fetch worked; anything else is evidence).
extension TernUITests {

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
        let deadline = Date().addingTimeInterval(180)
        while Date() < deadline {
            let pending = names.filter { n in
                let el = app.element(id: "policy.member.Tern-Test.\(n).delay")
                return !el.exists || el.label.isEmpty || el.label == "—"
            }
            if pending.isEmpty { break }
            usleep(2_000_000)
        }
        snap("kit-probe-result")
        for n in names {
            let el = app.element(id: "policy.member.Tern-Test.\(n).delay")
            print("KIT-RESULT \(n) = \(el.exists ? el.label : "<missing>")")
        }
        assertAlive("kit probe")
    }
}
