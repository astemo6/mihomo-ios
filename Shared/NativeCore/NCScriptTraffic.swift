// NativeCore (fix/nc-script-stats) — traffic ledger for script-issued outbound connections.
//
// Every $httpClient call a script makes — http-request / http-response scripts, cron tasks, MitM
// scripts — funnels through NativeScriptHost.fetch into NCScriptHTTPClient, which reports each of its
// connections here (begin on connect, add per write / read chunk, end on close). NCDataPlane's stats
// refresh folds snapshot() into NCDataPlaneStats (the same mirror the controller serves), so script
// traffic shows up in the home totals and the connections list with chains ["script:<name>"] instead
// of being invisible like before. Script bytes never pass the TUN sessions, so nothing is counted
// twice. Deliberately tiny: one lock, one live-entry table, cumulative counters — no per-byte work
// beyond the caller's chunk callbacks.

import Foundation

final class NCScriptTrafficLedger {
    private struct Entry {
        var source: String // the full chain label, "script:<name>"
        var host: String
        var port: Int
        var start: Date
        var up: Int64 = 0
        var down: Int64 = 0
    }

    private let lock = NSLock()
    private var live: [Int64: Entry] = [:]
    private var seq: Int64 = 0
    private var upTotal: Int64 = 0
    private var downTotal: Int64 = 0
    private var connTotal: Int64 = 0

    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Registers one outbound connection; call once per real connection, after it is established.
    /// Returns the id the caller passes to add / end.
    func begin(source: String, host: String, port: Int) -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        seq += 1
        connTotal += 1
        live[seq] = Entry(source: source, host: host, port: port, start: Date())
        return seq
    }

    /// Accumulates wire bytes for a live connection. Bytes for an unknown / already-ended id are
    /// dropped, so a late callback can never inflate the totals.
    func add(_ id: Int64, up: Int, down: Int) {
        guard up > 0 || down > 0 else { return }
        lock.lock()
        defer { lock.unlock() }
        guard var e = live[id] else { return }
        e.up += Int64(up)
        e.down += Int64(down)
        live[id] = e
        upTotal += Int64(up)
        downTotal += Int64(down)
    }

    /// Closes a connection's entry (its bytes stay in the cumulative totals).
    func end(_ id: Int64) {
        lock.lock()
        live.removeValue(forKey: id)
        lock.unlock()
    }

    /// Live connections in the controller's connection shape (same keys as NCDataPlane.refreshStats,
    /// id prefixed "sc" so it cannot collide with TUN session ids or the local proxy's "lp" ids),
    /// plus the cumulative totals since the ledger was created.
    func snapshot() -> (connections: [[String: Any]], up: Int64, down: Int64) {
        lock.lock()
        defer { lock.unlock() }
        let fmt = Self.formatter
        let conns: [[String: Any]] = live.sorted { $0.key < $1.key }.map { (id, e) in
            [
                "id": "sc" + String(id),
                "metadata": [
                    "network": "tcp",
                    "type": "Script",
                    "sourceIP": "",
                    "sourcePort": "",
                    "destinationIP": "",
                    "destinationPort": String(e.port),
                    "host": e.host,
                    "sniffHost": "",
                    "process": "",
                    "remoteDestination": e.host,
                ],
                "upload": e.up,
                "download": e.down,
                "start": fmt.string(from: e.start),
                "chains": [e.source],
                "rule": "",
                "rulePayload": "",
            ]
        }
        return (conns, upTotal, downTotal)
    }

    /// Cumulative totals (bytes + connection count) for tests and diagnostics.
    func totals() -> (up: Int64, down: Int64, connections: Int64) {
        lock.lock()
        defer { lock.unlock() }
        return (upTotal, downTotal, connTotal)
    }
}
