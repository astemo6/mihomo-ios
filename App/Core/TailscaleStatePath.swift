import Foundation

// MARK: - Tailscale State Directory & Status File Manager (App)
//
// Handles App-side path boundary verification, status file reading, and state
// directory deletion for Tailscale nodes.
//
// Hard boundary constraint:
// Resolves `<state-dir>` strictly under the App Group home container.
// Matches `NCRuntimeSteps.normalizeTailscale` and `NCTailscalePath` (PacketTunnel):
// - Rejects empty stateDir (falls back to default `tailscale/<name>-<hash8>`).
// - Rejects any path starting with `..` or traversing outside `home`.
// - Rejects any absolute path outside `home`.
// - Prevents directory deletion targeting `home` itself.
//
// Note: This file is compiled exclusively into the App target. It does not import
// or depend on any PacketTunnel target files.

enum TailscaleStatePathError: Error, LocalizedError {
    case emptyPath
    case pathEscapesHome(stateDir: String, home: String)
    case deletionRefused(String)

    var errorDescription: String? {
        switch self {
        case .emptyPath:
            return "Tailscale state-dir path cannot be empty"
        case .pathEscapesHome(let stateDir, let home):
            return "Tailscale state-dir '\(stateDir)' escapes home container '\(home)'"
        case .deletionRefused(let reason):
            return "Tailscale state directory deletion refused: \(reason)"
        }
    }
}

enum TailscaleStatePath {
    private static let statusFileName = "status.json"

    /// Resolves and validates the absolute URL of the state directory for a Tailscale node.
    /// Strictly aligns with `NCTailscalePath` / `NCRuntimeSteps.normalizeTailscale`:
    /// 1. If `stateDir` is nil or empty, defaults to `NCRuntimeSteps.tailscaleStateDir(nodeName)`.
    /// 2. Enforces that `home` is valid and non-empty.
    /// 3. If absolute, standardizes and enforces that it starts with `homeClean + "/"`, and != `homeClean`.
    /// 4. If relative, rejects any path starting with `..` or traversing outside `home`.
    /// 5. Ensures the standardized candidate URL is strictly a subpath within `homeClean + "/"`.
    static func resolveStateDir(home: String, stateDir: String?, nodeName: String) throws -> URL {
        let dir = (stateDir ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let effectiveDir = dir.isEmpty ? NCRuntimeSteps.tailscaleStateDir(nodeName) : dir

        let homeClean = (home as NSString).standardizingPath
        guard !homeClean.isEmpty else {
            throw TailscaleStatePathError.pathEscapesHome(stateDir: effectiveDir, home: home)
        }

        let resolvedURL: URL
        if (effectiveDir as NSString).isAbsolutePath {
            let clean = (effectiveDir as NSString).standardizingPath
            guard clean != homeClean, (clean + "/").hasPrefix(homeClean + "/") else {
                throw TailscaleStatePathError.pathEscapesHome(stateDir: effectiveDir, home: homeClean)
            }
            resolvedURL = URL(fileURLWithPath: clean, isDirectory: true)
        } else {
            let clean = (effectiveDir as NSString).standardizingPath
            if clean == ".." || clean.hasPrefix("../") {
                throw TailscaleStatePathError.pathEscapesHome(stateDir: effectiveDir, home: homeClean)
            }
            let candidate = URL(fileURLWithPath: homeClean, isDirectory: true).appendingPathComponent(clean, isDirectory: true)
            let standardizedCandidate = (candidate.path as NSString).standardizingPath
            guard standardizedCandidate != homeClean, (standardizedCandidate + "/").hasPrefix(homeClean + "/") else {
                throw TailscaleStatePathError.pathEscapesHome(stateDir: effectiveDir, home: homeClean)
            }
            resolvedURL = URL(fileURLWithPath: standardizedCandidate, isDirectory: true)
        }

        return resolvedURL
    }

    /// Reads and decodes `<state-dir>/status.json` if it exists.
    /// Returns nil if the file does not exist, is unreadable, or contains invalid data.
    static func readStatusFile(at stateDirURL: URL) -> NCTailscaleStatusFile? {
        let fileURL = stateDirURL.appendingPathComponent(statusFileName)
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            return nil
        }

        // Standard ISO8601 decoder matching PacketTunnel's NCTailscaleStatusStore
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let status = try? decoder.decode(NCTailscaleStatusFile.self, from: data) {
            return status
        }

        // Fallback decoder supporting ISO8601 with fractional seconds or unix epoch timestamps
        let fallbackDecoder = JSONDecoder()
        fallbackDecoder.dateDecodingStrategy = .custom { d in
            let container = try d.singleValueContainer()
            if let str = try? container.decode(String.self) {
                let iso = ISO8601DateFormatter()
                if let date = iso.date(from: str) { return date }
                let isoFrac = ISO8601DateFormatter()
                isoFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                if let date = isoFrac.date(from: str) { return date }
            }
            if let num = try? container.decode(Double.self) {
                return Date(timeIntervalSince1970: num)
            }
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: d.codingPath, debugDescription: "Invalid date format"))
        }
        return try? fallbackDecoder.decode(NCTailscaleStatusFile.self, from: data)
    }

    /// Safely deletes the node state directory after verifying boundary safety.
    /// Never deletes the root home container or directories outside home.
    static func deleteStateDir(at stateDirURL: URL, home: String) throws {
        let homeClean = (home as NSString).standardizingPath
        let clean = (stateDirURL.path as NSString).standardizingPath

        guard !homeClean.isEmpty else {
            throw TailscaleStatePathError.deletionRefused("Home path is empty")
        }
        guard clean != homeClean, (clean + "/").hasPrefix(homeClean + "/") else {
            throw TailscaleStatePathError.deletionRefused("Target path '\(clean)' is not strictly inside home '\(homeClean)'")
        }

        if FileManager.default.fileExists(atPath: clean) {
            try FileManager.default.removeItem(atPath: clean)
        }
    }
}
