import Foundation

/// hotfix/group-test-offline (device v0.19.13-build206 「未开启状态下，策略里，节点选择点测速无反应」): a policy group
/// whose members are all other groups (节点选择 → 自动选择 / 日本 / proxy …) had nothing the offline tester could dial,
/// so 测速 returned at once without a spinner or a result. This graph expands such a group to the real nodes it can
/// reach (member order, each node once, cycles cut) and says which node a group currently resolves to, so the card can
/// show that node's measured delay — never an invented number.
struct GroupGraph {
    struct Group: Equatable {
        var type: String          // select / url-test / fallback / load-balance / relay (offline names)
        var members: [String]
        var now: String?
    }

    /// How a group arrived at its node.
    enum How: Equatable {
        case selected       // the selected member (select groups, and live mode everywhere: the core's own choice)
        case fastest        // offline url-test / load-balance: the lowest measured delay among its members
        case firstAvailable // offline fallback: the first member, in order, that answered
    }

    struct Resolution: Equatable {
        var node: String
        var delay: Int?     // nil = not measured, 0 = timeout
        var how: How
    }

    var groups: [String: Group]
    /// A real node the tester can dial (not a group, not DIRECT / REJECT …).
    var isTestable: (String) -> Bool

    static let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]

    /// Testable nodes reachable from `root`, depth-first in member order, each once; a group met again is skipped.
    func leaves(of root: String) -> [String] {
        var out: [String] = []
        var seenNodes: Set<String> = []
        var seenGroups: Set<String> = []
        func walk(_ name: String) {
            if let g = groups[name] {
                guard seenGroups.insert(name).inserted else { return }
                for m in g.members { walk(m) }
            } else if isTestable(name), seenNodes.insert(name).inserted {
                out.append(name)
            }
        }
        walk(root)
        return out
    }

    /// The union of `leaves(of:)` for several groups (first appearance order).
    func leaves(of roots: [String]) -> [String] {
        var out: [String] = []
        var seen: Set<String> = []
        for r in roots { for n in leaves(of: r) where seen.insert(n).inserted { out.append(n) } }
        return out
    }

    /// Offline: which node `name` resolves to with the measured `delays`, and that node's delay.
    /// select → its selected member; url-test / load-balance → the fastest measured member; fallback → the first
    /// member that answered. With nothing measured yet an automatic group falls back to its listed current member.
    /// nil for relay (a chain's delay is not the delay of one node), an empty group, or a cycle.
    func resolve(_ name: String, delays: [String: Int]) -> Resolution? {
        var visiting: Set<String> = []
        return resolve(name, delays: delays, visiting: &visiting)
    }

    private func resolve(_ name: String, delays: [String: Int], visiting: inout Set<String>) -> Resolution? {
        guard let g = groups[name] else {
            return Resolution(node: name, delay: isTestable(name) ? delays[name] : nil, how: .selected)
        }
        guard visiting.insert(name).inserted else { return nil }
        defer { visiting.remove(name) }
        switch g.type {
        case "relay":
            return nil
        case "url-test", "load-balance", "fallback":
            let rs = g.members.compactMap { resolve($0, delays: delays, visiting: &visiting) }
            let how: How = g.type == "fallback" ? .firstAvailable : .fastest
            let answered = rs.filter { ($0.delay ?? 0) > 0 }
            let pick: Resolution? = g.type == "fallback" ? answered.first : answered.min { $0.delay! < $1.delay! }
            if let p = pick { return Resolution(node: p.node, delay: p.delay, how: how) }
            guard let now = g.now ?? g.members.first else { return nil }
            let listed = resolve(now, delays: delays, visiting: &visiting)
            // Every member timed out (none still unmeasured): nothing answers. Show the listed member as timed out,
            // not as 「最快」.
            let measured = rs.filter { $0.delay != nil }
            if !measured.isEmpty && measured.count == rs.filter({ isTestable($0.node) }).count {
                return Resolution(node: listed?.node ?? measured[0].node, delay: 0, how: .selected)
            }
            return listed
        default:
            guard let now = g.now ?? g.members.first else { return nil }
            return resolve(now, delays: delays, visiting: &visiting)
        }
    }

    /// Live: the node the core has picked, following each group's `now` (the core already chose for url-test /
    /// fallback / load-balance). nil when `name` is not a group or the chain loops / ends nowhere.
    func follow(_ name: String) -> String? {
        guard groups[name] != nil else { return nil }
        var seen: Set<String> = []
        var cur = name
        while let g = groups[cur] {
            guard seen.insert(cur).inserted, let n = g.now, !n.isEmpty else { return nil }
            cur = n
        }
        return cur
    }
}
