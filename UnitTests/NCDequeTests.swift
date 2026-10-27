import XCTest
@testable import Tern

/// selfreview-g2 (F13): NCDeque keeps Array's FIFO semantics with O(1) pops.
final class NCDequeTests: XCTestCase {
    func testFIFOOrderAndArrayLiteral() {
        var q: NCDeque<Int> = []
        XCTAssertTrue(q.isEmpty)
        XCTAssertNil(q.first)
        XCTAssertNil(q.popFirst())
        for i in 0..<5 { q.append(i) }
        XCTAssertEqual(q.count, 5)
        XCTAssertEqual(q.first, 0)
        XCTAssertEqual(q.last, 4)
        XCTAssertEqual(q.removeFirst(), 0)
        XCTAssertEqual(q.popFirst(), 1)
        XCTAssertEqual(Array(q), [2, 3, 4])
        q = []
        XCTAssertTrue(q.isEmpty)
        XCTAssertEqual(q.count, 0)
    }

    func testInterleavedMatchesArray() {
        var q = NCDeque<Int>()
        var ref: [Int] = []
        var next = 0
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<20_000 {
            if Bool.random(using: &rng) || ref.isEmpty {
                let n = Int.random(in: 1...4, using: &rng)
                for _ in 0..<n { q.append(next); ref.append(next); next += 1 }
            } else {
                XCTAssertEqual(q.removeFirst(), ref.removeFirst())
            }
            XCTAssertEqual(q.count, ref.count)
            XCTAssertEqual(q.first, ref.first)
        }
        XCTAssertEqual(Array(q), ref)
    }

    func testCompactionBoundsDeadSlots() {
        var q = NCDeque<Data>()
        for i in 0..<1000 { q.append(Data([UInt8(i & 0xff)])) }
        for _ in 0..<900 { q.removeFirst() }
        XCTAssertEqual(q.count, 100)
        XCTAssertLessThan(q.deadPrefix, NCDeque<Data>.compactMin + q.count + 1, "dead prefix is compacted once it reaches half")
        XCTAssertEqual(q.first, Data([UInt8(900 & 0xff)]))
        while !q.isEmpty { q.removeFirst() }
        XCTAssertEqual(q.deadPrefix, 0)
    }

    func testPoppedElementIsReleased() {
        final class Box {}
        weak var weakBox: Box?
        var q = NCDeque<Box>()
        do {
            let b = Box()
            weakBox = b
            q.append(b)
            q.append(Box())
        }
        _ = q.removeFirst()
        XCTAssertNil(weakBox, "a popped element must not stay referenced by the dead slot")
        XCTAssertEqual(q.count, 1)
    }

    func testRemoveAllWhereAndIteration() {
        var q: NCDeque<Int> = [1, 2, 3, 4, 5, 6]
        q.removeFirst()
        q.removeAll { $0 % 2 == 0 }
        XCTAssertEqual(Array(q), [3, 5])
        XCTAssertEqual(q.reduce(0, +), 8)
        q.removeAll()
        XCTAssertTrue(q.isEmpty)
    }
}
