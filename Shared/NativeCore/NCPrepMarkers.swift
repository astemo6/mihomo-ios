import Foundation

/// fix/nc-vpn-start-crash: markers the app's runtime preparation (NativeRuntimePrep) leaves in the shared home so
/// that a prepare which died part-way (build #374: a Swift runtime trap while building the rewrite snapshot) is
/// noticed by the next prepare and by the tunnel, instead of silently leaving stale state behind.
///
/// - `inflight`: written when a prepare starts (and updated with the stage it is in), removed when it returns —
///   success or error. Still present = the app process died inside a prepare. The live runtime files are then the
///   previous generation (PrepTransaction only renames at commit), never a half-written set.
/// - `quarantine`: the rewrite / MitM snapshot of exactly this rule set (fingerprint + app build) crashed the app
///   once; further prepares skip the snapshot (run without rewrite / MitM, with a warning) until the modules,
///   rules or the app build change. Trap-class failures cannot be caught in Swift, so this is the only way one bad
///   rule cannot crash every connect forever.
///
/// Note: `.nativecore-prepare.lock` is NOT a file. It is only the key of an in-process NCPathLock, so a crashed
/// prepare cannot leave a lock behind that blocks the next one.
enum NCPrepMarkers {
    static let inflightFile = ".nativecore-prepare-inflight.json"
    static let quarantineFile = ".nativecore-rewrite-quarantine.json"

    struct Inflight: Codable, Equatable {
        var stage: String
        var at: Int64
        var build: String
        var fp: String?
    }

    struct Quarantine: Codable, Equatable {
        var fp: String
        var build: String
        var at: Int64
    }

    /// "<CFBundleShortVersionString> (<CFBundleVersion>)" of the running bundle (app and tunnel share both).
    static var currentBuild: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }

    private static func url(_ home: String, _ name: String) -> URL {
        URL(fileURLWithPath: home).appendingPathComponent(name)
    }

    static func readInflight(home: String) -> Inflight? {
        guard let d = try? Data(contentsOf: url(home, inflightFile)) else { return nil }
        // An unreadable marker still means "a prepare died": keep the information that it exists.
        return (try? JSONDecoder().decode(Inflight.self, from: d)) ?? Inflight(stage: "?", at: 0, build: "?", fp: nil)
    }

    static func writeInflight(home: String, _ m: Inflight) {
        guard let d = try? JSONEncoder().encode(m) else { return }
        try? d.write(to: url(home, inflightFile), options: .atomic)
    }

    static func clearInflight(home: String) {
        try? FileManager.default.removeItem(at: url(home, inflightFile))
    }

    static func readQuarantine(home: String) -> Quarantine? {
        guard let d = try? Data(contentsOf: url(home, quarantineFile)) else { return nil }
        return try? JSONDecoder().decode(Quarantine.self, from: d)
    }

    static func writeQuarantine(home: String, _ q: Quarantine) {
        guard let d = try? JSONEncoder().encode(q) else { return }
        try? d.write(to: url(home, quarantineFile), options: .atomic)
    }

    static func clearQuarantine(home: String) {
        try? FileManager.default.removeItem(at: url(home, quarantineFile))
    }

    /// Stable (process-independent) FNV-1a 64 over the given strings, hex. Swift's Hasher is seeded per process
    /// and cannot be persisted.
    static func fingerprint(_ parts: [String]) -> String {
        var h: UInt64 = 0xcbf29ce484222325
        for p in parts {
            for b in p.utf8 {
                h ^= UInt64(b)
                h = h &* 0x100000001b3
            }
            h ^= 0x1f
            h = h &* 0x100000001b3
        }
        return String(h, radix: 16)
    }
}
