import Foundation
import CryptoKit

/// RFC 9849: TLS Encrypted Client Hello (ECH) Configuration Parser & Selector.
///
/// Implements parsing of `ECHConfigList` and `ECHConfig` structures per RFC 9849 §4,
/// and selection of the preferred supported HPKE suite (X25519 + HKDF-SHA256 with
/// AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305).

public enum NCECHConfigError: Error, LocalizedError, Equatable {
    case truncatedData(String)
    case invalidLength(String)
    case invalidCipherSuiteLength(Int)
    case unsupportedVersion(UInt16)
    case unsupportedKEM(UInt16)
    case emptyConfigList
    case noSupportedConfig(String)
    case invalidPublicName(String)

    public var errorDescription: String? {
        switch self {
        case .truncatedData(let msg): return "ECHConfig truncated: \(msg)"
        case .invalidLength(let msg): return "ECHConfig invalid length: \(msg)"
        case .invalidCipherSuiteLength(let len): return "ECHConfig invalid cipher suite list byte length: \(len)"
        case .unsupportedVersion(let v): return "ECHConfig unsupported version: 0x\(String(v, radix: 16))"
        case .unsupportedKEM(let k): return "ECHConfig unsupported KEM id: 0x\(String(k, radix: 16))"
        case .emptyConfigList: return "ECHConfigList contains no configurations"
        case .noSupportedConfig(let msg): return "No supported ECHConfig found: \(msg)"
        case .invalidPublicName(let msg): return "ECHConfig invalid public_name: \(msg)"
        }
    }
}

/// An ECH configuration extension: RFC 9849 §4.
public struct NCECHConfigExtension: Equatable, Sendable {
    public let type: UInt16
    public let data: Data

    public init(type: UInt16, data: Data) {
        self.type = type
        self.data = data
    }

    /// Whether this extension is marked mandatory per RFC 9849 §4:
    /// either has the high-order bit set (`type & 0x8000 != 0`) or is the `mandatory` extension (0x0020).
    public var isMandatory: Bool {
        (type & 0x8000) != 0 || type == NCECHConfigParser.mandatoryExtensionType
    }
}

/// An HPKE symmetric cipher suite pair (kdf_id, aead_id): RFC 9849 §4.
public struct NCECHSymmetricCipherSuite: Equatable, Sendable {
    public let kdfID: UInt16
    public let aeadID: UInt16

    public init(kdfID: UInt16, aeadID: UInt16) {
        self.kdfID = kdfID
        self.aeadID = aeadID
    }
}

/// A parsed ECHConfig: RFC 9849 §4.
public struct NCECHConfig: Equatable, Sendable {
    /// RFC 9849 version code point (0xfe0d for draft-13 / RFC 9849).
    public let version: UInt16
    /// The length of contents in bytes.
    public let length: UInt16
    /// One-byte configuration identifier allocated by the client-facing server.
    public let configID: UInt8
    /// HPKE KEM identifier (0x0020 for DHKEM(X25519, HKDF-SHA256)).
    public let kemID: UInt16
    /// Serialized HPKE public key of the client-facing server.
    public let publicKey: Data
    /// List of symmetric cipher suites advertised by the server in preference order.
    public let cipherSuites: [NCECHSymmetricCipherSuite]
    /// Longest name of a backend server, if known (or 0).
    public let maximumNameLength: UInt8
    /// DNS name of the client-facing server.
    public let publicName: String
    /// Extensions attached to this ECHConfig.
    public let extensions: [NCECHConfigExtension]
    /// The complete serialized ECHConfig bytes (version + length + contents),
    /// required for computing HPKE info = "tls ech\0" || ECHConfig (RFC 9849 §6.1).
    public let rawBytes: Data

    /// Whether this configuration contains any unsupported mandatory extension.
    public var hasUnsupportedMandatoryExtension: Bool {
        NCECHConfigParser.hasUnsupportedMandatoryExtension(self)
    }

    public init(
        version: UInt16,
        length: UInt16,
        configID: UInt8,
        kemID: UInt16,
        publicKey: Data,
        cipherSuites: [NCECHSymmetricCipherSuite],
        maximumNameLength: UInt8,
        publicName: String,
        extensions: [NCECHConfigExtension],
        rawBytes: Data
    ) {
        self.version = version
        self.length = length
        self.configID = configID
        self.kemID = kemID
        self.publicKey = publicKey
        self.cipherSuites = cipherSuites
        self.maximumNameLength = maximumNameLength
        self.publicName = publicName
        self.extensions = extensions
        self.rawBytes = rawBytes
    }
}

/// The result of selecting a compatible ECHConfig and cipher suite from an ECHConfigList.
public struct NCECHSelectedConfig: Equatable, Sendable {
    public let config: NCECHConfig
    public let cipherSuite: NCECHSymmetricCipherSuite
    public let hpkeSuite: NCHPKECipherSuite

    public init(config: NCECHConfig, cipherSuite: NCECHSymmetricCipherSuite, hpkeSuite: NCHPKECipherSuite) {
        self.config = config
        self.cipherSuite = cipherSuite
        self.hpkeSuite = hpkeSuite
    }

    /// RFC 9849 §6.1: info = "tls ech" || 0x00 || ECHConfig
    public var hpkeInfo: Data {
        var info = Data("tls ech".utf8)
        info.append(0x00)
        info.append(config.rawBytes)
        return info
    }

    /// Sets up HPKE sender encryption context for this selected ECHConfig.
    public func setupSender(
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey? = nil
    ) throws -> (enc: Data, context: NCHPKEContextS) {
        try NCHPKE.setupBaseS(
            recipientPublicKey: config.publicKey,
            info: hpkeInfo,
            suite: hpkeSuite,
            ephemeralPrivateKey: ephemeralPrivateKey
        )
    }
}

// MARK: - ECHConfigList Parser & Selector

public enum NCECHConfigParser {
    /// Supported ECH version: RFC 9849 (0xfe0d)
    public static let supportedVersion: UInt16 = 0xfe0d
    /// Supported HPKE KEM: DHKEM(X25519, HKDF-SHA256) (0x0020)
    public static let supportedKEM: UInt16 = 0x0020
    /// Supported HPKE KDF: HKDF-SHA256 (0x0001)
    public static let supportedKDF: UInt16 = 0x0001

    /// Supported ECH configuration extension types.
    ///
    /// RFC 9849 §4:
    /// - Extension types with the high bit set (`type & 0x8000 != 0`) are mandatory.
    /// - Extension type 0x0020 is the `mandatory` extension listing required extension types.
    ///
    /// The current implementation recognizes the `mandatory` extension (0x0020) and
    /// evaluates its required extension types against the supported extension set.
    /// No additional ECH extensions are currently supported.
    public static let mandatoryExtensionType: UInt16 = 0x0020
    public static let supportedExtensionTypes: Set<UInt16> = [
        mandatoryExtensionType
    ]

    /// Evaluates whether an ECHConfig contains any unsupported mandatory extensions per RFC 9849 §4.
    ///
    /// An extension is mandatory if:
    /// 1. Its type code point has the high-order bit set (`type & 0x8000 != 0`).
    /// 2. It is listed in the `mandatory` extension (type 0x0020).
    ///
    /// Returns `true` if any mandatory extension required by this config is not supported.
    public static func hasUnsupportedMandatoryExtension(_ config: NCECHConfig) -> Bool {
        for ext in config.extensions {
            // Case 1: Extension marked mandatory by high bit (type & 0x8000 != 0)
            if (ext.type & 0x8000) != 0 && !supportedExtensionTypes.contains(ext.type) {
                return true
            }

            // Case 2: The `mandatory` extension (0x0020) listing required extension types
            if ext.type == mandatoryExtensionType {
                guard let requiredTypes = parseMandatoryExtensionPayload(ext.data) else {
                    // Malformed mandatory extension payload -> cannot satisfy requirements
                    return true
                }
                for reqType in requiredTypes {
                    if !supportedExtensionTypes.contains(reqType) {
                        return true
                    }
                }
            }
        }
        return false
    }

    /// Parses the payload of a `mandatory` extension (type 0x0020).
    /// Supports both uint16-length prefixed vector and raw uint16 list.
    private static func parseMandatoryExtensionPayload(_ data: Data) -> [UInt16]? {
        let bytes = Data(data)
        if bytes.isEmpty {
            return []
        }
        guard bytes.count >= 2 else {
            return nil
        }

        // Check for 2-byte length prefix matching remaining payload
        let prefixLen = (Int(bytes[0]) << 8) | Int(bytes[1])
        if prefixLen + 2 == bytes.count && prefixLen >= 2 && prefixLen % 2 == 0 {
            var types: [UInt16] = []
            var offset = 2
            while offset < bytes.count {
                let t = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
                types.append(t)
                offset += 2
            }
            return types
        } else if bytes.count % 2 == 0 {
            // Direct sequence of uint16
            var types: [UInt16] = []
            var offset = 0
            while offset < bytes.count {
                let t = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
                types.append(t)
                offset += 2
            }
            return types
        } else {
            return nil
        }
    }

    /// Parses an ECHConfigList (or raw ECHConfig bytes) per RFC 9849 §4.
    ///
    /// Skips entries with unsupported version or malformed headers while advancing
    /// through the list, but reports discrete errors if the list is truncated or corrupt.
    public static func parseList(_ data: Data) throws -> [NCECHConfig] {
        // Normalize input Data to guarantee contiguous 0-indexed storage.
        // If data is a subdata/slice with startIndex != 0, Data(data) creates a fresh 0-indexed copy.
        let normalizedData = Data(data)
        guard normalizedData.count >= 4 else {
            throw NCECHConfigError.truncatedData("Data too short (\(normalizedData.count) bytes)")
        }

        // RFC 9849 §4: ECHConfigList is prefixed by uint16 list_length
        let listLen = (Int(normalizedData[0]) << 8) | Int(normalizedData[1])
        let contentBytes: Data
        if normalizedData.count == 2 + listLen {
            contentBytes = Data(normalizedData[2..<normalizedData.count])
        } else {
            // If the outer 2-byte list prefix is omitted (e.g. raw single ECHConfig or direct stream),
            // check if the first 2 bytes are a valid version code point.
            contentBytes = normalizedData
        }

        var configs: [NCECHConfig] = []
        var offset = 0
        let total = contentBytes.count

        while offset < total {
            guard offset + 4 <= total else {
                throw NCECHConfigError.truncatedData("ECHConfig header truncated at offset \(offset)")
            }

            let configStart = offset
            let version = (UInt16(contentBytes[offset]) << 8) | UInt16(contentBytes[offset + 1])
            let length = (Int(contentBytes[offset + 2]) << 8) | Int(contentBytes[offset + 3])
            offset += 4

            guard offset + length <= total else {
                throw NCECHConfigError.truncatedData("ECHConfig contents truncated: expected \(length) bytes, remaining \(total - offset)")
            }

            let contentsEnd = offset + length
            let rawConfig = Data(contentBytes[configStart..<contentsEnd])

            if version != supportedVersion {
                // RFC 9849 §4: Clients MUST ignore any ECHConfig structure with a version they do not support.
                offset = contentsEnd
                continue
            }

            // Parse ECHConfigContents for version 0xfe0d
            guard offset < contentsEnd else {
                throw NCECHConfigError.truncatedData("Empty ECHConfigContents")
            }

            // 1. HpkeKeyConfig
            // config_id: uint8
            let configID = contentBytes[offset]
            offset += 1

            // kem_id: uint16
            guard offset + 2 <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated kem_id")
            }
            let kemID = (UInt16(contentBytes[offset]) << 8) | UInt16(contentBytes[offset + 1])
            offset += 2

            // public_key: opaque HpkePublicKey<1..2^16-1> (uint16 length prefix)
            guard offset + 2 <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated public_key length")
            }
            let pkLen = (Int(contentBytes[offset]) << 8) | Int(contentBytes[offset + 1])
            offset += 2

            guard pkLen > 0, offset + pkLen <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated public_key payload (len: \(pkLen))")
            }
            let publicKey = Data(contentBytes[offset..<offset + pkLen])
            offset += pkLen

            // cipher_suites: HpkeSymmetricCipherSuite cipher_suites<4..2^16-4> (uint16 length prefix)
            guard offset + 2 <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated cipher_suites length")
            }
            let csLen = (Int(contentBytes[offset]) << 8) | Int(contentBytes[offset + 1])
            offset += 2

            guard csLen >= 4, csLen % 4 == 0, offset + csLen <= contentsEnd else {
                throw NCECHConfigError.invalidCipherSuiteLength(csLen)
            }

            var cipherSuites: [NCECHSymmetricCipherSuite] = []
            let csEnd = offset + csLen
            while offset < csEnd {
                let kdf = (UInt16(contentBytes[offset]) << 8) | UInt16(contentBytes[offset + 1])
                let aead = (UInt16(contentBytes[offset + 2]) << 8) | UInt16(contentBytes[offset + 3])
                cipherSuites.append(NCECHSymmetricCipherSuite(kdfID: kdf, aeadID: aead))
                offset += 4
            }

            // 2. maximum_name_length: uint8
            guard offset < contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated maximum_name_length")
            }
            let maxNameLength = contentBytes[offset]
            offset += 1

            // 3. public_name: opaque public_name<1..255> (uint8 length prefix)
            guard offset < contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated public_name length")
            }
            let nameLen = Int(contentBytes[offset])
            offset += 1

            guard nameLen > 0, offset + nameLen <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated public_name payload (len: \(nameLen))")
            }
            let nameData = Data(contentBytes[offset..<offset + nameLen])
            guard let publicName = String(data: nameData, encoding: .utf8) else {
                throw NCECHConfigError.invalidPublicName("public_name is not valid UTF-8 string")
            }
            offset += nameLen

            // 4. extensions: ECHConfigExtension extensions<0..2^16-1> (uint16 length prefix)
            guard offset + 2 <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated extensions length")
            }
            let extLen = (Int(contentBytes[offset]) << 8) | Int(contentBytes[offset + 1])
            offset += 2

            guard offset + extLen <= contentsEnd else {
                throw NCECHConfigError.truncatedData("Truncated extensions payload (len: \(extLen))")
            }

            var extensions: [NCECHConfigExtension] = []
            let extEnd = offset + extLen
            while offset < extEnd {
                guard offset + 4 <= extEnd else {
                    throw NCECHConfigError.truncatedData("Truncated extension header")
                }
                let extType = (UInt16(contentBytes[offset]) << 8) | UInt16(contentBytes[offset + 1])
                let extDataLen = (Int(contentBytes[offset + 2]) << 8) | Int(contentBytes[offset + 3])
                offset += 4

                guard offset + extDataLen <= extEnd else {
                    throw NCECHConfigError.truncatedData("Truncated extension data (len: \(extDataLen))")
                }
                let extData = Data(contentBytes[offset..<offset + extDataLen])
                extensions.append(NCECHConfigExtension(type: extType, data: extData))
                offset += extDataLen
            }

            guard offset == contentsEnd else {
                throw NCECHConfigError.invalidLength("Trailing bytes in ECHConfig contents: \(contentsEnd - offset) unparsed")
            }

            configs.append(NCECHConfig(
                version: version,
                length: UInt16(length),
                configID: configID,
                kemID: kemID,
                publicKey: publicKey,
                cipherSuites: cipherSuites,
                maximumNameLength: maxNameLength,
                publicName: publicName,
                extensions: extensions,
                rawBytes: rawConfig
            ))
        }

        guard !configs.isEmpty else {
            throw NCECHConfigError.emptyConfigList
        }

        return configs
    }

    /// Selects the first compatible ECHConfig and cipher suite from the parsed configs list.
    ///
    /// Requirements:
    /// - `version == 0xfe0d`
    /// - `kem_id == 0x0020` (DHKEM(X25519, HKDF-SHA256))
    /// - `public_key.count == 32`
    /// - `kdf_id == 0x0001` (HKDF-SHA256)
    /// - `aead_id` in [0x0001 (AES-128-GCM), 0x0002 (AES-256-GCM), 0x0003 (ChaCha20Poly1305)]
    public static func selectSupported(from configs: [NCECHConfig]) throws -> NCECHSelectedConfig {
        guard !configs.isEmpty else {
            throw NCECHConfigError.emptyConfigList
        }

        for config in configs {
            guard config.version == supportedVersion else { continue }
            guard !hasUnsupportedMandatoryExtension(config) else { continue }
            guard config.kemID == supportedKEM else { continue }
            guard config.publicKey.count == 32 else { continue }

            for suite in config.cipherSuites {
                guard suite.kdfID == supportedKDF else { continue }
                let aead: NCHPKESuite.AEAD
                switch suite.aeadID {
                case 0x0001: aead = .aes128GCM
                case 0x0002: aead = .aes256GCM
                case 0x0003: aead = .chaCha20Poly1305
                default: continue
                }

                let hpkeSuite = NCHPKECipherSuite(
                    kem: .dhkemX25519HKDFSHA256,
                    kdf: .hkdfSHA256,
                    aead: aead
                )
                return NCECHSelectedConfig(
                    config: config,
                    cipherSuite: suite,
                    hpkeSuite: hpkeSuite
                )
            }
        }

        throw NCECHConfigError.noSupportedConfig("No compatible KEM (0x0020) and AEAD suite found in \(configs.count) configs")
    }

    /// Selects the first compatible ECHConfig and cipher suite from the parsed configs list,
    /// or returns `nil` if none is supported.
    public static func selectOptional(from configs: [NCECHConfig]) -> NCECHSelectedConfig? {
        try? selectSupported(from: configs)
    }

    /// Parses an ECHConfigList byte string and selects the first supported configuration and cipher suite.
    public static func select(fromECHConfigList data: Data) throws -> NCECHSelectedConfig {
        let configs = try parseList(data)
        return try selectSupported(from: configs)
    }

    /// Parses an ECHConfigList byte string and selects the first supported configuration,
    /// or returns `nil` if none is supported.
    public static func selectOptional(fromECHConfigList data: Data) -> NCECHSelectedConfig? {
        try? select(fromECHConfigList: data)
    }
}
