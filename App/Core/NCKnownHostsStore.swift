import Foundation

/// App-side access to the SSH trust-on-first-use store the kernel maintains:
/// `<home>/engine/ssh_known_hosts.json`, a JSON object `"server:port" -> "SHA256:<base64>"`
/// (NCSSHKnownHosts in Shared/NativeCore/NCSSH.swift owns the format). The kernel re-reads the
/// file whenever its mtime moves, so an edit here is picked up without a tunnel restart.
/// Call from a background queue: every entry point does file IO. Writes hold the shared per-path
/// lock (same discipline as the profile editors) and are atomic, mirroring the kernel's save.
enum NCKnownHostsStore {
    static var fileURL: URL {
        AppShared.homeURL.appendingPathComponent("engine/ssh_known_hosts.json")
    }

    /// The kernel's key for one host; the port is normalized through Int so "022" keys as "22".
    static func id(server: String, port: String) -> String {
        let s = server.trimmingCharacters(in: .whitespaces)
        let p = port.trimmingCharacters(in: .whitespaces)
        return "\(s):\(Int(p).map { String($0) } ?? p)"
    }

    static func load() -> [String: String] {
        guard let data = try? Data(contentsOf: fileURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return [:] }
        return obj
    }

    /// The stored fingerprint for one host; nil = not trusted yet (or no store file yet).
    static func fingerprint(server: String, port: String) -> String? {
        load()[id(server: server, port: port)]
    }

    /// Removes one host's entry so the next connection trusts (and records) the key it presents
    /// again. Returns true when an entry was actually removed.
    @discardableResult
    static func forget(server: String, port: String) -> Bool {
        let url = fileURL
        return NCPathLock.shared.withLock(for: url.path) {
            var map = load()
            guard map.removeValue(forKey: id(server: server, port: port)) != nil else { return false }
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            if let data = try? JSONSerialization.data(withJSONObject: map, options: [.sortedKeys]) {
                try? data.write(to: url, options: .atomic)
            }
            return true
        }
    }
}
