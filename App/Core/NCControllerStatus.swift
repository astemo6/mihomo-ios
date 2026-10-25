import Foundation

/// The tunnel's external-controller listen status, read from `<home>/nativecore-controller.json`.
/// NCController (PacketTunnel) rewrites that file on every start, late failure and stop:
/// `{"listening": Bool, "port": Int, "at": epochSeconds, "error": String?}` (error only on failure).
/// Display-only: a missing or unreadable file means the status is unknown — never guess one,
/// because a stale "listening" would hide exactly the failure this file exists to surface.
struct NCControllerStatus {
    var listening: Bool
    var port: Int
    var at: Date
    var error: String?

    static var fileURL: URL {
        AppShared.homeURL.appendingPathComponent("nativecore-controller.json")
    }

    /// Reads and parses the status file; nil when it is absent or malformed. Call off the main thread.
    static func load() -> NCControllerStatus? {
        guard let data = try? Data(contentsOf: fileURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let listening = obj["listening"] as? Bool,
              let port = (obj["port"] as? NSNumber)?.intValue else { return nil }
        return NCControllerStatus(
            listening: listening,
            port: port,
            at: Date(timeIntervalSince1970: (obj["at"] as? NSNumber)?.doubleValue ?? 0),
            error: obj["error"] as? String)
    }
}
