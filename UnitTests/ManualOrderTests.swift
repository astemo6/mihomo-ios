import XCTest
@testable import Mihomo

/// 2026-10-23 「这个规则要能手动调顺序」「三个路径…也都要可以手动调顺序」: ManualOrder follows the bridge's
/// mitm.ReorderSlots (saved names sorted among the slots they hold, everything else in place), and a drag inside a
/// part of the list keeps that part's slots.
final class ManualOrderTests: XCTestCase {
    func testApplyKeepsUnnamedItemsInPlace() {
        let items = ["a", "new", "b", "c"]
        XCTAssertEqual(ManualOrder.apply(items, order: ["c", "gone", "b", "a"]) { $0 }, ["c", "new", "b", "a"])
        XCTAssertEqual(ManualOrder.apply(items, order: []) { $0 }, items)
        // Items the key skips never move.
        let mixed = ["a", "-x", "b"]
        XCTAssertEqual(ManualOrder.apply(mixed, order: ["b", "a"]) { $0.hasPrefix("-") ? nil : $0 }, ["b", "-x", "a"])
    }

    func testApplyIsIdempotent() {
        let order = ["c", "a", "b"]
        let once = ManualOrder.apply(["a", "b", "c", "d"], order: order) { $0 }
        XCTAssertEqual(once, ["c", "a", "b", "d"])
        XCTAssertEqual(ManualOrder.apply(once, order: order) { $0 }, once)
    }

    func testMovedInsideASection() {
        // Tasks of two kinds interleaved: moving the last cron task to the top of the cron section leaves the event
        // tasks where they are.
        let all = ["cron1", "event1", "cron2", "event2", "cron3"]
        let crons = all.filter { $0.hasPrefix("cron") }
        let moved = ManualOrder.moved(all, visible: crons, from: IndexSet(integer: 2), to: 0) { $0 }
        XCTAssertEqual(moved, ["cron3", "event1", "cron1", "event2", "cron2"])
        XCTAssertEqual(moved.filter { $0.hasPrefix("event") }, ["event1", "event2"])
    }

    func testRuleOrderOverrideIsNotEmpty() {
        var o = ProviderOverride()
        XCTAssertTrue(o.isEmpty)
        o.order = ["a", "b"]
        XCTAssertFalse(o.isEmpty, "an order-only entry is kept in provider-overrides.json")
        XCTAssertFalse(ProviderOverride.ruleOrderKey.hasPrefix("rule:"), "the order entry is not a rule-set override")
    }

    func testTaskPrefsDeletedTaskIsOff() throws {
        let json = #"{"paused":false,"order":["b","a"],"deleted":{"a":true}}"#
        let p = try JSONDecoder().decode(TaskPrefs.self, from: Data(json.utf8))
        XCTAssertEqual(p.order ?? [], ["b", "a"])
        let t = try JSONDecoder().decode(ScriptTaskState.self, from: Data(#"{"id":"a","kind":"cron","script":{"name":"A","path":"a.js"},"source":"M","line":"x"}"#.utf8))
        XCTAssertFalse(p.isOn(t))
    }
}
