import Foundation
import CryptoKit

/// fix/app-toggle-hitch: skip regenerating the native runtime on a connect when nothing it is built from changed.
///
/// build #404 (iPhone17,1): a tap on the Home switch spent ~1.5 s generating the runtime (profile + 31 modules,
/// 299 rewrite rules, 139 scripts, 312 MitM hosts) before startVPNTunnel — every connect, even when the user had
/// only switched the VPN off and on again.
///
/// The inputs of NativeRuntimePrep are spread over many files (profile, override output, overrides.json /
/// secrets.json, custom rules, group chains, sub rules, engine.json + engine/modules, scripts, MitM CA, provider
/// files, geo databases …), so instead of listing them (and silently missing the next one added) the fingerprint
/// covers EVERY file under `<home>` and the profiles directory, minus an explicit list of files that are
/// prepare's own outputs or written only by the tunnel / logs (never read by the prepare). An unknown file that
/// changes only costs a cache miss; it can never make the cache hit wrongly.
///
/// Files ≤ 256 KiB are fingerprinted by content (SHA-256), so rewriting identical bytes (overrides.json is saved on
/// every connect) still hits; larger files (geo databases) by size + mtime (ns) + inode.
///
/// The record is written after a successful prepare (fingerprint taken AFTER the commit, so files the prepare
/// itself writes — script code, rewrite download cache, migrated secrets — are part of it) and removed at the
/// start of every prepare, so a failed / interrupted prepare never leaves a record behind. A hit also requires
/// the output files to be exactly the ones that prepare committed (size + mtime + inode).
enum NativeRuntimePrepCache {
    static let recordFile = ".nativecore-prep-cache.json"
    static let smallFileLimit: Int64 = 256 << 10

    /// Top-level names in `<home>` that are not inputs: prepare outputs, tunnel state, logs, locks, markers.
    static let excludedTopLevel: Set<String> = [
        // prepare outputs
        "runtime.yaml", "nativecore-runtime.json", "nativecore-rewrite.json", "nativecore-scripts.json",
        "nativecore-prep.json", "runtime-groups.json", "nativecore-geosite",
        // written by the tunnel only (NativeCoreEngine / NCController / NativeTunnelCore / TrafficHistory …)
        "nativecore-fakeip.json", "nativecore-selections.json", "nativecore-controller.json",
        "nativecore-unsupported.json", "nativecore-rulesets", "nativecore-nodesubs",
        "tunnel-memory.json", "tunnel-alive.txt", "tunnel-last-stop.txt", "tunnel-last-error.txt",
        "traffic-history.json", "panel-cache.json", "task-history.json",
        // logs / diagnostics
        "startup-log.txt", "startup-log.prev.txt", "core-log.txt", "memory.txt", "diag",
        "mitm-requests.jsonl", "mitm-requests.prev.jsonl",
        // markers / locks
        ".nativecore-prepare.lock", ".nativecore-prepare-inflight.json", "overrides.lock", "traffic-history.lock",
        recordFile,
    ]
    /// Relative paths below `<home>` that are not inputs (script persistent store, written by scripts in the tunnel).
    static let excludedRelative: Set<String> = ["engine/store.json"]

    /// Outputs whose identity a hit requires unchanged (a missing file is part of the identity).
    static let outputs = ["runtime.yaml", "nativecore-runtime.json", "nativecore-rewrite.json",
                          "nativecore-scripts.json", "nativecore-prep.json", "runtime-groups.json"]

    struct Record: Codable, Equatable {
        var inputs: String
        var outputs: String
    }

    static func isExcluded(relative rel: String) -> Bool {
        let first = rel.split(separator: "/", maxSplits: 1).first.map(String.init) ?? rel
        if excludedTopLevel.contains(first) { return true }
        if first.hasPrefix(PrepTransaction.stagePrefix) { return true }
        if excludedRelative.contains(rel) { return true }
        let name = (rel as NSString).lastPathComponent
        if name.hasSuffix(".lock") || name.contains(".tmp") { return true } // locks, atomic-write temporaries
        return false
    }

    private static func statKey(_ path: String) -> (size: Int64, key: String)? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        let mt = Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec)
        return (Int64(st.st_size), "\(st.st_size):\(mt):\(st.st_ino)")
    }

    /// Fingerprint of every input file (see the type comment). `build` and `profilePath` are part of it.
    static func inputsFingerprint(home: String, profilesDir: String?, extraFiles: [String], profilePath: String, build: String) -> String {
        var h = SHA256()
        func add(_ s: String) { h.update(data: Data(s.utf8)); h.update(data: Data([0])) }
        add("v1"); add(build); add(profilePath)
        func addFile(label: String, root: String, rel: String) {
            let p = (root as NSString).appendingPathComponent(rel)
            guard let st = statKey(p) else { add(label + "/" + rel + ":gone"); return }
            if st.size <= smallFileLimit, let d = FileManager.default.contents(atPath: p) {
                add(label + "/" + rel + ":sha:" + SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined())
            } else {
                add(label + "/" + rel + ":stat:" + st.key)
            }
        }
        func walk(root: String, label: String, filter: (String) -> Bool) {
            guard let en = FileManager.default.enumerator(atPath: root) else { add(label + ":missing"); return }
            var rels: [String] = []
            while let r = en.nextObject() as? String {
                if filter(r) {
                    if (en.fileAttributes?[.type] as? FileAttributeType) == .typeDirectory { en.skipDescendants() }
                    continue
                }
                if (en.fileAttributes?[.type] as? FileAttributeType) == .typeRegular { rels.append(r) }
            }
            for r in rels.sorted() { addFile(label: label, root: root, rel: r) }
        }
        walk(root: home, label: "home", filter: isExcluded(relative:))
        if let pd = profilesDir { walk(root: pd, label: "profiles", filter: { $0.contains(".tmp") }) }
        for f in extraFiles {
            addFile(label: "extra", root: (f as NSString).deletingLastPathComponent, rel: (f as NSString).lastPathComponent)
        }
        return h.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func outputsFingerprint(home: String) -> String {
        outputs.map { n in "\(n)=\(statKey((home as NSString).appendingPathComponent(n))?.key ?? "-")" }.joined(separator: ",")
    }

    static func recordPath(_ home: String) -> String { (home as NSString).appendingPathComponent(recordFile) }

    static func read(home: String) -> Record? {
        guard let d = FileManager.default.contents(atPath: recordPath(home)) else { return nil }
        return try? JSONDecoder().decode(Record.self, from: d)
    }

    static func write(home: String, _ r: Record) {
        guard let d = try? JSONEncoder().encode(r) else { return }
        try? d.write(to: URL(fileURLWithPath: recordPath(home)), options: .atomic)
    }

    static func invalidate(home: String) {
        unlink(recordPath(home))
    }

    /// Whether the outputs on disk are still exactly what the last prepare built from `inputs`.
    static func hit(home: String, inputs: String) -> Bool {
        guard let r = read(home: home), r.inputs == inputs else { return false }
        // A prepare that died mid-way (marker left) gets a full prepare, which handles the quarantine.
        if FileManager.default.fileExists(atPath: (home as NSString).appendingPathComponent(NCPrepMarkers.inflightFile)) { return false }
        return r.outputs == outputsFingerprint(home: home)
    }
}
