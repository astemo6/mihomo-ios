import CryptoKit
import Foundation

// MARK: - Tailscale Node State & Key Material Store (PacketTunnel)
//
// Manages the persistent Curve25519 keypairs (machine key, node key, disco key)
// and status file read/writes inside the validated node state directory.
//
// File Format:
// - Machine/Node/Disco keys: Stored in `<state-dir>/{machine,node,disco}.key`
//   formatted as `privkey:<64 hex digits>\n` (Tailscale standard) with fallback
//   parsing for raw hex and 32-byte binary representations.
// - Status: Stored in `<state-dir>/status.json` as UTF-8 encoded JSON.
//
// Security & Atomicity:
// - All writes are performed via unique temporary files (`.tmp.<uuid>`) followed
//   by atomic rename/replace.
// - Best-effort POSIX file permission 0600 is applied upon write (defense-in-depth
//   within the iOS Network Extension App Group sandbox).
// - State dir paths are strictly verified to never escape the App Group home container.

enum NCTailscaleStateError: Error, LocalizedError {
    case emptyStateDir
    case pathEscapesHome(stateDir: String, home: String)
    case invalidKeyFormat(file: String)
    case keyFileCorrupted(file: String)
    case ioError(String)

    var errorDescription: String? {
        switch self {
        case .emptyStateDir:
            return "Tailscale state-dir path cannot be empty"
        case .pathEscapesHome(let stateDir, let home):
            return "Tailscale state-dir '\(stateDir)' escapes home container '\(home)'"
        case .invalidKeyFormat(let file):
            return "Tailscale key file '\(file)' has invalid format"
        case .keyFileCorrupted(let file):
            return "Tailscale key file '\(file)' is corrupted or invalid Curve25519 scalar"
        case .ioError(let msg):
            return "Tailscale state IO error: \(msg)"
        }
    }
}

// MARK: - State Directory Path Resolver

enum NCTailscalePath {
    /// Resolves and validates the absolute URL of the state directory for a Tailscale node.
    /// Strictly aligns with the validation rules of `NCRuntimeSteps.normalizeTailscale`:
    /// 1. Rejects empty paths.
    /// 2. If absolute, standardizes and enforces that it starts with `home + "/"`.
    /// 3. If relative, rejects any path starting with `..` or traversing outside `home`.
    /// 4. Ensures the directory is created if it does not already exist.
    static func resolveStateDir(home: String, stateDir: String) throws -> URL {
        let trimmedDir = stateDir.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedDir.isEmpty else {
            throw NCTailscaleStateError.emptyStateDir
        }

        let homeClean = (home as NSString).standardizingPath
        guard !homeClean.isEmpty else {
            throw NCTailscaleStateError.pathEscapesHome(stateDir: trimmedDir, home: home)
        }

        let resolvedURL: URL
        if (trimmedDir as NSString).isAbsolutePath {
            let clean = (trimmedDir as NSString).standardizingPath
            guard (clean + "/").hasPrefix(homeClean + "/") else {
                throw NCTailscaleStateError.pathEscapesHome(stateDir: trimmedDir, home: homeClean)
            }
            resolvedURL = URL(fileURLWithPath: clean, isDirectory: true)
        } else {
            let clean = (trimmedDir as NSString).standardizingPath
            if clean == ".." || clean.hasPrefix("../") {
                throw NCTailscaleStateError.pathEscapesHome(stateDir: trimmedDir, home: homeClean)
            }
            let candidate = URL(fileURLWithPath: homeClean, isDirectory: true).appendingPathComponent(clean, isDirectory: true)
            let standardizedCandidate = (candidate.path as NSString).standardizingPath
            guard (standardizedCandidate + "/").hasPrefix(homeClean + "/") else {
                throw NCTailscaleStateError.pathEscapesHome(stateDir: trimmedDir, home: homeClean)
            }
            resolvedURL = URL(fileURLWithPath: standardizedCandidate, isDirectory: true)
        }

        // Ensure directory exists
        do {
            try FileManager.default.createDirectory(at: resolvedURL, withIntermediateDirectories: true)
        } catch {
            throw NCTailscaleStateError.ioError("Failed to create state-dir at \(resolvedURL.path): \(error.localizedDescription)")
        }

        return resolvedURL
    }
}

// MARK: - Tailscale Key Material

/// Holds the three long-term Curve25519 private keys required for a Tailscale node.
public struct NCTailscaleKeys {
    /// Long-term machine private key (used to authenticate the device to the control plane).
    public let machineKey: Curve25519.KeyAgreement.PrivateKey
    /// Node private key (used for node-to-node WireGuard peer traffic).
    public let nodeKey: Curve25519.KeyAgreement.PrivateKey
    /// Discovery private key (used for peer discovery and STUN probing).
    public let discoKey: Curve25519.KeyAgreement.PrivateKey

    public init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: Curve25519.KeyAgreement.PrivateKey,
        discoKey: Curve25519.KeyAgreement.PrivateKey
    ) {
        self.machineKey = machineKey
        self.nodeKey = nodeKey
        self.discoKey = discoKey
    }

    /// Hex-encoded public key representations for logging and inspection.
    public var machinePublicKeyHex: String {
        [UInt8](machineKey.publicKey.rawRepresentation).map { String(format: "%02x", $0) }.joined()
    }

    public var nodePublicKeyHex: String {
        [UInt8](nodeKey.publicKey.rawRepresentation).map { String(format: "%02x", $0) }.joined()
    }

    public var discoPublicKeyHex: String {
        [UInt8](discoKey.publicKey.rawRepresentation).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Key Store & Status Store

enum NCTailscaleKeyStore {
    private static let machineKeyFileName = "machine.key"
    private static let nodeKeyFileName = "node.key"
    private static let discoKeyFileName = "disco.key"

    /// Loads existing keypairs from `stateDirURL` or generates new ones atomically.
    static func loadOrCreate(in stateDirURL: URL) throws -> NCTailscaleKeys {
        let machineKey = try loadOrCreateSingleKey(
            at: stateDirURL.appendingPathComponent(machineKeyFileName),
            name: machineKeyFileName
        )
        let nodeKey = try loadOrCreateSingleKey(
            at: stateDirURL.appendingPathComponent(nodeKeyFileName),
            name: nodeKeyFileName
        )
        let discoKey = try loadOrCreateSingleKey(
            at: stateDirURL.appendingPathComponent(discoKeyFileName),
            name: discoKeyFileName
        )

        return NCTailscaleKeys(
            machineKey: machineKey,
            nodeKey: nodeKey,
            discoKey: discoKey
        )
    }

    /// Loads a single Curve25519 private key from disk or generates and saves a new one.
    private static func loadOrCreateSingleKey(at fileURL: URL, name: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        if FileManager.default.fileExists(atPath: fileURL.path) {
            guard let rawData = try? Data(contentsOf: fileURL) else {
                throw NCTailscaleStateError.ioError("Could not read key file \(name)")
            }
            guard let key = parseKey(from: rawData) else {
                throw NCTailscaleStateError.keyFileCorrupted(file: name)
            }
            return key
        }

        // Generate fresh Curve25519 key
        let newKey = Curve25519.KeyAgreement.PrivateKey()
        let serialized = formatKey(newKey)
        try atomicWrite(data: serialized, to: fileURL)
        return newKey
    }

    /// Formats a key according to Tailscale conventions (`privkey:<64-hex>\n`).
    static func formatKey(_ key: Curve25519.KeyAgreement.PrivateKey) -> Data {
        let raw = [UInt8](key.rawRepresentation)
        let hex = raw.map { String(format: "%02x", $0) }.joined()
        return Data("privkey:\(hex)\n".utf8)
    }

    /// Parses a key from raw data: supports `privkey:<hex>`, raw hex, or 32 raw bytes.
    static func parseKey(from data: Data) -> Curve25519.KeyAgreement.PrivateKey? {
        if data.count == 32 {
            return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
        }

        guard let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return nil
        }

        var hexStr = str
        if hexStr.hasPrefix("privkey:") {
            hexStr = String(hexStr.dropFirst("privkey:".count)).trimmingCharacters(in: .whitespaces)
        }

        guard hexStr.count == 64, hexStr.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var i = hexStr.startIndex
        while i < hexStr.endIndex {
            let nextIndex = hexStr.index(i, offsetBy: 2)
            guard let b = UInt8(hexStr[i..<nextIndex], radix: 16) else { return nil }
            bytes.append(b)
            i = nextIndex
        }

        return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes)
    }

    /// Writes data atomically using temporary file + rename, applying POSIX 0600 permissions.
    /// (Note on 0600 permissions: Best-effort. Within the iOS sandbox, files are isolated by
    /// the kernel to the App Group UID/GID; 0600 provides uniform defense-in-depth).
    static func atomicWrite(data: Data, to destinationURL: URL) throws {
        let dir = destinationURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let tmpURL = dir.appendingPathComponent(".\(destinationURL.lastPathComponent).tmp.\(UUID().uuidString)")
        do {
            try data.write(to: tmpURL, options: .withoutOverwriting)
            // Best-effort 0600 file permission (owner read/write only)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmpURL.path)

            if FileManager.default.fileExists(atPath: destinationURL.path) {
                _ = try FileManager.default.replaceItemAt(destinationURL, withItemAt: tmpURL)
            } else {
                try FileManager.default.moveItem(at: tmpURL, to: destinationURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: tmpURL)
            throw NCTailscaleStateError.ioError("Atomic write to \(destinationURL.path) failed: \(error.localizedDescription)")
        }
    }
}

// MARK: - Tailscale Status File Store

enum NCTailscaleStatusStore {
    private static let statusFileName = "status.json"

    /// Loads `<state-dir>/status.json` from the specified state directory.
    static func load(stateDirURL: URL) -> NCTailscaleStatusFile? {
        let fileURL = stateDirURL.appendingPathComponent(statusFileName)
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(NCTailscaleStatusFile.self, from: data)
    }

    /// Atomically saves `NCTailscaleStatusFile` to `<state-dir>/status.json`.
    static func save(status: NCTailscaleStatusFile, stateDirURL: URL) throws {
        let fileURL = stateDirURL.appendingPathComponent(statusFileName)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        do {
            let data = try encoder.encode(status)
            try NCTailscaleKeyStore.atomicWrite(data: data, to: fileURL)
        } catch {
            throw NCTailscaleStateError.ioError("Failed to save status.json: \(error.localizedDescription)")
        }
    }
}
