import Foundation

/// feat/policy-chain: the flag a node name stands for, from the same region patterns 筛选节点 uses
/// (NodeFilterView.regions). A name that already carries a flag, DIRECT / REJECT and names no region matches are
/// left as they are — never a guessed flag.
@MainActor
enum NodeFlag {
    private static let patterns: [(flag: String, re: NSRegularExpression)] = NodeFilterView.regions.compactMap { r in
        // CountryFlag.emoji: same substitutes as the Home header (TW drawn as CN, user 2026-10-21).
        (try? NSRegularExpression(pattern: r.filter)).map { (CountryFlag.emoji(r.code) ?? r.flag, $0) }
    }
    private static var cache: [String: String] = [:]
    /// r7: insertion order for FIFO eviction (a full clear at 2000 re-ran every regex for the whole visible list).
    private static var order: [String] = []
    private static var head = 0
    static let cacheLimit = 2000

    /// The region flag for `name`, nil when it has one already, is a built-in policy or matches no region.
    static func flag(for name: String) -> String? {
        if GroupGraph.builtins.contains(name) || name.unicodeScalars.contains(where: FlagSafe.isRegional) { return nil }
        if let c = cache[name] { return c.isEmpty ? nil : c }
        let range = NSRange(name.startIndex..., in: name)
        let f = patterns.first { $0.re.firstMatch(in: name, range: range) != nil }?.flag
        if cache.count >= cacheLimit {
            cache.removeValue(forKey: order[head])
            head += 1
            if head > cacheLimit { order.removeFirst(head); head = 0 } // compact now and then, O(1) amortised
        }
        cache[name] = f ?? ""
        order.append(name)
        return f
    }

    /// 「🇯🇵 Tokyo 01」 for 「Tokyo 01」; unchanged when `flag(for:)` is nil.
    static func decorate(_ name: String) -> String {
        guard let f = flag(for: name) else { return name }
        return f + " " + name
    }
}

/// feat/policy-chain: the subtitle of a 策略 card, Egern style: every hop the group goes through, the final node with
/// its flag — 「日本节点 › 🇯🇵 东京 AZ JP01」. DIRECT / REJECT plainly; 「最快 / 可用」 on the last hop when the offline
/// page picked it from measurements; 「…」 before the last hop when the path is cut (cycle or deeper than GroupGraph.chainMaxDepth).
@MainActor
enum PolicyChainText {
    static let separator = " › "

    static func text(_ c: GroupGraph.Chain) -> String {
        parts(c).joined(separator: separator)
    }

    /// The display hops of `text(_:)` one by one (feat/egern-style ChainLine keeps the last one visible).
    static func parts(_ c: GroupGraph.Chain) -> [String] {
        guard !c.hops.isEmpty else { return ["—"] }
        var parts = c.hops.dropLast().map { FlagSafe.text($0) }
        let last = c.hops[c.hops.count - 1]
        let shown = FlagSafe.text(NodeFlag.decorate(last))
        // r7: 「…」 marks the cut BEFORE the last hop, so the last element is always the last hop reached —
        // ChainLine keeps the last element visible as the final node.
        if c.truncated || c.looped { parts.append("…") }
        switch c.how {
        case .selected: parts.append(shown)
        case .fastest: parts.append(String(localized: "最快 \(shown)"))
        case .firstAvailable: parts.append(String(localized: "可用 \(shown)"))
        }
        return parts
    }
}
