import Foundation

/// selfreview-g2 (F13): FIFO queue with an O(1) amortised `removeFirst()`, for the kernel's per-stream inboxes /
/// outboxes. `Array.removeFirst()` moves every remaining element on each pop (O(n)); here a pop only advances a head
/// index and clears the slot (so a popped `Data` is released at once), and the storage is compacted when the dead
/// prefix is at least half of it. Order, `first`, `count`, iteration and `removeAll` behave like the Array it replaces;
/// an array literal (`[]`) assigns, so call sites keep their shape.
struct NCDeque<Element>: Sequence, ExpressibleByArrayLiteral {
    private var slots: [Element?] = []
    private var head = 0
    /// Compaction starts only past this many dead slots (small queues never move anything).
    static var compactMin: Int { 32 }

    init() {}
    init(arrayLiteral elements: Element...) { slots = elements.map { $0 } }
    init<S: Sequence>(_ s: S) where S.Element == Element { slots = s.map { $0 } }

    var count: Int { slots.count - head }
    var isEmpty: Bool { head == slots.count }
    var first: Element? { head < slots.count ? slots[head] : nil }
    var last: Element? { head < slots.count ? slots[slots.count - 1] : nil }

    mutating func append(_ e: Element) { slots.append(e) }
    mutating func append<S: Sequence>(contentsOf s: S) where S.Element == Element { for e in s { slots.append(e) } }

    /// Precondition: not empty (as Array.removeFirst()).
    @discardableResult
    mutating func removeFirst() -> Element {
        precondition(head < slots.count, "removeFirst() on an empty NCDeque")
        let e = slots[head]!
        slots[head] = nil
        head += 1
        compactIfNeeded()
        return e
    }

    mutating func popFirst() -> Element? { isEmpty ? nil : removeFirst() }

    mutating func removeAll() {
        slots.removeAll()
        head = 0
    }

    mutating func removeAll(where shouldRemove: (Element) throws -> Bool) rethrows {
        var kept: [Element?] = []
        kept.reserveCapacity(count)
        for i in head..<slots.count { if let e = slots[i], try !shouldRemove(e) { kept.append(e) } }
        slots = kept
        head = 0
    }

    private mutating func compactIfNeeded() {
        if head == slots.count {
            slots.removeAll(keepingCapacity: slots.count <= 256)
            head = 0
        } else if head >= Self.compactMin && head * 2 >= slots.count {
            slots.removeFirst(head)
            head = 0
        }
    }

    /// Dead slots currently held (tests).
    var deadPrefix: Int { head }

    struct Iterator: IteratorProtocol {
        fileprivate let slots: [Element?]
        fileprivate var i: Int
        mutating func next() -> Element? {
            guard i < slots.count else { return nil }
            defer { i += 1 }
            return slots[i]
        }
    }

    func makeIterator() -> Iterator { Iterator(slots: slots, i: head) }
    var underestimatedCount: Int { count }
}
