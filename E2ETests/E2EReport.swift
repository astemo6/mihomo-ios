import Foundation

// Tern E2E replay (feat/nc-e2e): the result sink both replay stages share. Compiled into MihomoUnitTests
// (stage 1, app import → runtime generation) and TernE2ETunnelTests (stage 2, NativeCore in-process), so it only
// uses Foundation.
//
// Every scenario ends in exactly one named line:
//     E2E-RESULT|<stage>|<scenario>|PASS|FAIL|SKIP|INFO|<detail>
// printed to stdout (xcodebuild's log, which the workflow greps) and appended as JSON to
// <out>/results.jsonl. The detail is redacted first: node hosts / passwords / uuids / subscription and script URLs of
// the fixture never reach a log, the job summary or an artifact (the workflow also ::add-mask::s them).

enum E2EStatus: String {
    case pass = "PASS", fail = "FAIL", skip = "SKIP", info = "INFO"
}

final class E2EReport {
    static func env(_ key: String) -> String? {
        let e = ProcessInfo.processInfo.environment
        return e[key] ?? e["TEST_RUNNER_" + key]
    }

    /// The replay only runs when the workflow asks for it (TEST_RUNNER_TERN_E2E=1); the normal unit-test runs skip.
    static var enabled: Bool { env("TERN_E2E") == "1" }

    /// <Documents>/tern-e2e in the host app's container: both stages are hosted in Mihomo.app, so they share it
    /// (handoff.json, fixture copy).
    static let workDir: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let u = docs.appendingPathComponent("tern-e2e", isDirectory: true)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }()

    /// Where results go: $TERN_E2E_OUT (a host path the simulator can write), else <Documents>/tern-e2e/out in the
    /// app container (the workflow copies it back with `simctl get_app_container`).
    static let outDir: URL = {
        let fm = FileManager.default
        if let p = env("TERN_E2E_OUT"), !p.isEmpty {
            let u = URL(fileURLWithPath: p, isDirectory: true)
            if (try? fm.createDirectory(at: u, withIntermediateDirectories: true)) != nil, fm.isWritableFile(atPath: u.path) {
                return u
            }
        }
        let u = workDir.appendingPathComponent("out", isDirectory: true)
        try? fm.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }()

    let stage: String
    private var secrets: [String] = []
    private let lock = NSLock()
    private(set) var counts: [E2EStatus: Int] = [:]

    init(stage: String) { self.stage = stage }

    /// Values that must never be printed (node servers, passwords, uuids, provider / module / script URLs).
    func addSecrets<S: Sequence>(_ values: S) where S.Element == String {
        lock.lock(); defer { lock.unlock() }
        for v in values {
            let t = v.trimmingCharacters(in: .whitespacesAndNewlines)
            guard t.count >= 4, !Self.harmless.contains(t), !secrets.contains(t) else { continue }
            secrets.append(t)
        }
        secrets.sort { $0.count > $1.count }
    }

    private static let harmless: Set<String> = ["127.0.0.1", "localhost", "true", "false", "none", "auto", "http", "https",
                                                "DIRECT", "REJECT", "direct", "reject"]
    private static let urlRe = try! NSRegularExpression(pattern: #"(https?|wss?)://[^\s,"'<>)\]]+"#)
    private static let ipRe = try! NSRegularExpression(pattern: #"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"#)

    /// Secrets → ‹redacted›; URLs → scheme://‹url› unless they point at the local fixture servers; public IPv4
    /// addresses → ‹ip› (127.x, 198.18/15 fake-ip and private ranges stay readable); one line, ≤ 700 chars.
    func redact(_ input: String) -> String {
        lock.lock(); let secrets = self.secrets; lock.unlock()
        var s = input.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ⏎ ")
            .replacingOccurrences(of: "|", with: "¦")
        for v in secrets { s = s.replacingOccurrences(of: v, with: "‹redacted›") }
        s = Self.replace(Self.urlRe, in: s) { m in
            let lower = m.lowercased()
            if lower.contains("://127.0.0.1") || lower.contains("://localhost") || lower.contains(".localtest.me") { return m }
            let scheme = m.components(separatedBy: "://").first ?? "url"
            return scheme + "://‹url›"
        }
        s = Self.replace(Self.ipRe, in: s) { m in
            let p = m.split(separator: ".").compactMap { Int($0) }
            guard p.count == 4 else { return m }
            if p[0] == 127 || p[0] == 10 || p[0] == 0 || (p[0] == 198 && (p[1] == 18 || p[1] == 19))
                || (p[0] == 192 && p[1] == 168) || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 0 && p[2] == 2) {
                return m
            }
            return "‹ip›"
        }
        if s.count > 700 { s = String(s.prefix(700)) + "…" }
        return s
    }

    private static func replace(_ re: NSRegularExpression, in s: String, _ f: (String) -> String) -> String {
        let ns = s as NSString
        var out = ""
        var last = 0
        for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(ns.substring(with: m.range))
            last = m.range.location + m.range.length
        }
        out += ns.substring(from: last)
        return out
    }

    @discardableResult
    func record(_ name: String, _ status: E2EStatus, _ detail: String = "") -> E2EStatus {
        let d = redact(detail)
        lock.lock(); counts[status, default: 0] += 1; lock.unlock()
        print("E2E-RESULT|\(stage)|\(name)|\(status.rawValue)|\(d)")
        let obj: [String: Any] = ["stage": stage, "name": name, "status": status.rawValue, "detail": d,
                                  "at": Int(Date().timeIntervalSince1970)]
        if let data = try? JSONSerialization.data(withJSONObject: obj), var line = String(data: data, encoding: .utf8) {
            line += "\n"
            Self.append(line, to: Self.outDir.appendingPathComponent("results.jsonl"))
        }
        return status
    }

    /// A free-form redacted line for the report artifact (counts tables, timings): `E2E-NOTE|stage|text`.
    func note(_ text: String) {
        let d = redact(text)
        print("E2E-NOTE|\(stage)|\(d)")
        Self.append("[\(stage)] \(d)\n", to: Self.outDir.appendingPathComponent("notes.txt"))
    }

    private static let fileLock = NSLock()
    private static func append(_ text: String, to url: URL) {
        fileLock.lock(); defer { fileLock.unlock() }
        let data = Data(text.utf8)
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile()
            h.write(data)
            try? h.close()
        } else {
            try? data.write(to: url)
        }
    }

    /// Small JSON handoff between the stages (no secrets: paths, counts, flags).
    static func writeHandoff(_ obj: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: workDir.appendingPathComponent("handoff.json"), options: .atomic)
            try? data.write(to: outDir.appendingPathComponent("handoff.json"), options: .atomic)
        }
    }

    static func readHandoff() -> [String: Any]? {
        for dir in [workDir, outDir] {
            if let data = try? Data(contentsOf: dir.appendingPathComponent("handoff.json")),
               let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                return obj
            }
        }
        return nil
    }

    /// The fixture text: $TERN_E2E_FIXTURE (host path), else <Documents>/tern-e2e/fixture.conf (copied in by the
    /// workflow), else nil.
    static func fixtureText() -> (text: String, source: String)? {
        var candidates: [String] = []
        if let p = env("TERN_E2E_FIXTURE"), !p.isEmpty { candidates.append(p) }
        candidates.append(workDir.appendingPathComponent("fixture.conf").path)
        for p in candidates {
            if let data = FileManager.default.contents(atPath: p), let t = String(data: data, encoding: .utf8), !t.isEmpty {
                return (t, p == candidates.last ? "app container copy" : "env path")
            }
        }
        return nil
    }

    /// Network-dependent scenarios skip (not fail) when the runner said it cannot reach the outside / public DNS.
    static var publicDNSOK: Bool { env("TERN_E2E_PUBLIC_DNS") != "0" }
    static var internetOK: Bool { env("TERN_E2E_INTERNET") != "0" }
}
