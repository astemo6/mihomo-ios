import Foundation

/// Structured model for node ECH options (`ech-opts`), aligned with mihomo's `ECHOptions`
/// (adapter/outbound/ech.go).
///
/// Sub-fields:
/// - `enable`: whether ECH is enabled.
/// - `config`: base64-encoded `ECHConfigList` raw bytes. When present, the TLS client
///   uses this static config list instead of querying DNS.
/// - `queryServerName`: domain name override used for ECH HTTPS (Type 65 / SVCB) DNS record queries
///   when `config` is omitted.
public struct NCECHOpts: Equatable, Hashable, Codable {
    public var enable: Bool
    public var config: String?
    public var queryServerName: String?

    public init(enable: Bool = false, config: String? = nil, queryServerName: String? = nil) {
        self.enable = enable
        let trimmedConfig = config?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.config = (trimmedConfig?.isEmpty ?? true) ? nil : trimmedConfig
        let trimmedQSN = queryServerName?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.queryServerName = (trimmedQSN?.isEmpty ?? true) ? nil : trimmedQSN
    }

    /// Decode from an NCJSONValue object map (e.g. from `proxy.fields["ech-opts"]`).
    public init?(object: [String: NCJSONValue]) {
        guard !object.isEmpty else { return nil }
        let enableVal: Bool
        if let b = object["enable"]?.bool {
            enableVal = b
        } else if let s = object["enable"]?.string {
            enableVal = s.lowercased() == "true" || s == "1"
        } else {
            // If enable key is omitted but config or query-server-name is present, default enable to true.
            enableVal = object["config"] != nil || object["query-server-name"] != nil || object["query_server_name"] != nil
        }

        let cfg = object["config"]?.string
        let qsn = object["query-server-name"]?.string
            ?? object["query_server_name"]?.string
            ?? object["queryServerName"]?.string

        guard object["enable"] != nil || cfg != nil || qsn != nil else { return nil }
        self.init(enable: enableVal, config: cfg, queryServerName: qsn)
    }

    /// Decode from an untyped dictionary (e.g. from YAML parser or NodeEditorView).
    public init?(dictionary: [String: Any]) {
        guard !dictionary.isEmpty else { return nil }
        let enableVal: Bool
        if let b = dictionary["enable"] as? Bool {
            enableVal = b
        } else if let s = dictionary["enable"] as? String {
            enableVal = s.lowercased() == "true" || s == "1"
        } else if let n = dictionary["enable"] as? NSNumber {
            enableVal = n.boolValue
        } else {
            enableVal = dictionary["config"] != nil || dictionary["query-server-name"] != nil || dictionary["query_server_name"] != nil
        }

        let cfg = dictionary["config"] as? String
        let qsn = dictionary["query-server-name"] as? String
            ?? dictionary["query_server_name"] as? String
            ?? dictionary["queryServerName"] as? String

        guard dictionary["enable"] != nil || cfg != nil || qsn != nil else { return nil }
        self.init(enable: enableVal, config: cfg, queryServerName: qsn)
    }

    /// Convert to NCJSONValue map for storage in `NCProxy.fields["ech-opts"]`.
    public func toObject() -> [String: NCJSONValue] {
        var obj: [String: NCJSONValue] = ["enable": .bool(enable)]
        if let config, !config.isEmpty {
            obj["config"] = .string(config)
        }
        if let queryServerName, !queryServerName.isEmpty {
            obj["query-server-name"] = .string(queryServerName)
        }
        return obj
    }

    /// Convert to plain dictionary representation.
    public func toDictionary() -> [String: Any] {
        var d: [String: Any] = ["enable": enable]
        if let config, !config.isEmpty {
            d["config"] = config
        }
        if let queryServerName, !queryServerName.isEmpty {
            d["query-server-name"] = queryServerName
        }
        return d
    }

    // MARK: - Base64 / Base64URL conversions

    /// Convert standard base64 string to unpadded base64url string.
    public static func toBase64URL(_ base64: String) -> String {
        base64
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    /// Convert base64url string (with or without padding) to standard base64 string with padding.
    public static func fromBase64URL(_ base64URL: String) -> String {
        var s = base64URL
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = s.count % 4
        if rem > 0 {
            s.append(String(repeating: "=", count: 4 - rem))
        }
        return s
    }

    /// Raw ECHConfigList bytes decoded from `config`.
    /// Tolerates standard base64 and unpadded base64url.
    public var configBytes: Data? {
        guard let config, !config.isEmpty else { return nil }
        if let data = Data(base64Encoded: config) {
            return data
        }
        let std = Self.fromBase64URL(config)
        return Data(base64Encoded: std)
    }

    /// Unpadded base64url representation of `config` for URL query strings.
    public var configBase64URL: String? {
        guard let config, !config.isEmpty else { return nil }
        return Self.toBase64URL(config)
    }

    // MARK: - Query Parameter Parsing

    /// Parse from URL query parameters (e.g. `ech=<base64url>` or `ech=1`, plus optional `ech-qsn=<name>`).
    public static func parse(query: [String: String]) -> NCECHOpts? {
        guard let echVal = query["ech"] ?? query["ech-opts"] ?? query["ech_opts"] else {
            if let cfg = query["ech-config"] ?? query["ech_config"] {
                let qsn = query["ech-qsn"] ?? query["ech-query-server-name"] ?? query["query-server-name"]
                return NCECHOpts(enable: true, config: fromBase64URL(cfg), queryServerName: qsn)
            }
            return nil
        }

        let trimmed = echVal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let qsn = query["ech-qsn"] ?? query["ech-query-server-name"] ?? query["query-server-name"]

        if trimmed == "1" || trimmed.lowercased() == "true" {
            let cfg = query["ech-config"] ?? query["ech_config"]
            return NCECHOpts(enable: true, config: cfg.map(fromBase64URL), queryServerName: qsn)
        } else if trimmed == "0" || trimmed.lowercased() == "false" {
            return NCECHOpts(enable: false, config: nil, queryServerName: nil)
        } else {
            // Value is a base64 or base64url encoded ECHConfigList
            let stdConfig = fromBase64URL(trimmed)
            return NCECHOpts(enable: true, config: stdConfig, queryServerName: qsn)
        }
    }
}
