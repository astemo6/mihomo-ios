import Foundation

// MARK: - Tailscale DERP Map & Node Models (tailcfg JSON)
//
// Pure Swift Codable models matching the official Tailscale `tailcfg.DERPMap` JSON specification.
// Reference: `tailscale.com/tailcfg.DERPMap`, `tailscale.com/tailcfg.DERPRegion`, `tailscale.com/tailcfg.DERPNode`.
//
// Field names and JSON keys strictly follow official casing:
// - DERPRegion: RegionID, RegionCode, RegionName, Avoid, Nodes
// - DERPNode: Name, RegionID, HostName, IPv4, IPv6, STUNPort, STUNOnly, DERPPort, CertName, InsecureForTests

/// A specific DERP packet relay node running within a DERPRegion.
public struct NCTailscaleDERPNode: Codable, Equatable, Sendable {
    /// Unique node name across all regions (e.g. "1a", "2b").
    public let name: String
    /// RegionID of the DERPRegion that this node belongs to.
    public let regionID: Int
    /// HostName of the DERP node (e.g. "derp1.tailscale.com").
    public let hostName: String
    /// Optional static IPv4 address (e.g. "192.0.2.1").
    public let ipv4: String?
    /// Optional static IPv6 address (e.g. "2001:db8::1").
    public let ipv6: String?
    /// Optional STUN port (defaults to 3478 if omitted or zero).
    public let stunPort: Int?
    /// If true, node only performs STUN, not DERP packet relaying.
    public let stunOnly: Bool?
    /// Port running the DERP HTTPS relay service (defaults to 443 if omitted or zero).
    public let derpPort: Int?
    /// Optional certificate name to check for TLS verification if different from HostName.
    public let certName: String?
    /// If true, certificate validation can be skipped (used in local tests/staging).
    public let insecureForTests: Bool?

    enum CodingKeys: String, CodingKey {
        case name = "Name"
        case regionID = "RegionID"
        case hostName = "HostName"
        case ipv4 = "IPv4"
        case ipv6 = "IPv6"
        case stunPort = "STUNPort"
        case stunOnly = "STUNOnly"
        case derpPort = "DERPPort"
        case certName = "CertName"
        case insecureForTests = "InsecureForTests"
    }

    public init(
        name: String,
        regionID: Int,
        hostName: String,
        ipv4: String? = nil,
        ipv6: String? = nil,
        stunPort: Int? = nil,
        stunOnly: Bool? = nil,
        derpPort: Int? = nil,
        certName: String? = nil,
        insecureForTests: Bool? = nil
    ) {
        self.name = name
        self.regionID = regionID
        self.hostName = hostName
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.stunPort = stunPort
        self.stunOnly = stunOnly
        self.derpPort = derpPort
        self.certName = certName
        self.insecureForTests = insecureForTests
    }

    /// Effective TCP/TLS port for connecting to this DERP node (default 443).
    public var effectiveDERPPort: Int {
        if let p = derpPort, p > 0 { return p }
        return 443
    }

    /// Effective STUN UDP port (default 3478).
    public var effectiveSTUNPort: Int {
        if let p = stunPort, p > 0 { return p }
        return 3478
    }

    /// Server name used for TLS ClientHello SNI and certificate validation.
    /// Prefers `CertName` if set, otherwise falls back to `HostName`.
    public var effectiveServerName: String {
        if let cert = certName, !cert.isEmpty { return cert }
        return hostName
    }

    /// Destination host used when establishing TCP connection (prefers IPv4 if available).
    public var dialHost: String {
        if let v4 = ipv4, !v4.isEmpty { return v4 }
        return hostName
    }

    /// Whether this node can be used as a DERP packet relay (not STUN-only).
    public var isRelayUsable: Bool {
        !(stunOnly ?? false)
    }
}

/// A geographic region running DERP relay node(s).
public struct NCTailscaleDERPRegion: Codable, Equatable, Sendable {
    /// Unique integer for this geographic region (e.g. 1 for NYC, 2 for London).
    public let regionID: Int
    /// Short region code (e.g. "nyc", "lon", "fra", "tok").
    public let regionCode: String
    /// Human-readable region description (e.g. "New York City", "London").
    public let regionName: String?
    /// Whether clients should avoid this region unless specifically configured.
    public let avoid: Bool?
    /// Relay nodes operating within this region.
    public let nodes: [NCTailscaleDERPNode]

    enum CodingKeys: String, CodingKey {
        case regionID = "RegionID"
        case regionCode = "RegionCode"
        case regionName = "RegionName"
        case avoid = "Avoid"
        case nodes = "Nodes"
    }

    public init(
        regionID: Int,
        regionCode: String,
        regionName: String? = nil,
        avoid: Bool? = nil,
        nodes: [NCTailscaleDERPNode] = []
    ) {
        self.regionID = regionID
        self.regionCode = regionCode
        self.regionName = regionName
        self.avoid = avoid
        self.nodes = nodes
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        regionID = try container.decode(Int.self, forKey: .regionID)
        regionCode = try container.decode(String.self, forKey: .regionCode)
        regionName = try container.decodeIfPresent(String.self, forKey: .regionName)
        avoid = try container.decodeIfPresent(Bool.self, forKey: .avoid)
        nodes = try container.decodeIfPresent([NCTailscaleDERPNode].self, forKey: .nodes) ?? []
    }

    /// All nodes in this region capable of DERP packet relaying.
    public var usableNodes: [NCTailscaleDERPNode] {
        nodes.filter { $0.isRelayUsable }
    }
}

/// A complete map of all geographic regions running DERP relay nodes.
public struct NCTailscaleDERPMap: Codable, Equatable, Sendable {
    /// Regions dictionary keyed by RegionID.
    public let regions: [Int: NCTailscaleDERPRegion]
    /// Whether to omit default Tailscale DERP regions.
    public let omitDefaultRegions: Bool?

    enum CodingKeys: String, CodingKey {
        case regions = "Regions"
        case omitDefaultRegions = "OmitDefaultRegions"
    }

    public init(
        regions: [Int: NCTailscaleDERPRegion] = [:],
        omitDefaultRegions: Bool? = nil
    ) {
        self.regions = regions
        self.omitDefaultRegions = omitDefaultRegions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        omitDefaultRegions = try container.decodeIfPresent(Bool.self, forKey: .omitDefaultRegions)

        // Robust decoding: JSON object keys are strings ("1": {...}),
        // Swift JSONDecoder handles [Int: Value] or [String: Value].
        if let direct = try? container.decode([Int: NCTailscaleDERPRegion].self, forKey: .regions) {
            regions = direct
        } else if let stringKeyed = try? container.decode([String: NCTailscaleDERPRegion].self, forKey: .regions) {
            var converted = [Int: NCTailscaleDERPRegion]()
            for (k, v) in stringKeyed {
                if let id = Int(k) {
                    converted[id] = v
                } else {
                    converted[v.regionID] = v
                }
            }
            regions = converted
        } else {
            regions = [:]
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(omitDefaultRegions, forKey: .omitDefaultRegions)

        // Encode as string-keyed dictionary to produce canonical JSON object {"1": {...}}
        var stringKeyed = [String: NCTailscaleDERPRegion]()
        for (k, v) in regions {
            stringKeyed[String(k)] = v
        }
        try container.encode(stringKeyed, forKey: .regions)
    }

    /// Looks up a region by its unique RegionID.
    public func region(id: Int) -> NCTailscaleDERPRegion? {
        regions[id]
    }

    /// List of regions sorted in ascending order of RegionID.
    public var sortedRegions: [NCTailscaleDERPRegion] {
        regions.values.sorted { $0.regionID < $1.regionID }
    }

    /// The first available region suitable for default home selection.
    /// Prefers non-avoid regions with at least one usable relay node.
    public var firstAvailableRegion: NCTailscaleDERPRegion? {
        let sorted = sortedRegions
        if let nonAvoid = sorted.first(where: { !($0.avoid ?? false) && !$0.usableNodes.isEmpty }) {
            return nonAvoid
        }
        return sorted.first(where: { !$0.usableNodes.isEmpty })
    }

    // MARK: - Debug Self-Test Verification

    /// Verifies JSON round-trip decoding against official tailcfg DERPMap format.
    @discardableResult
    public static func selfTest() -> Bool {
        let json = """
        {
          "Regions": {
            "1": {
              "RegionID": 1,
              "RegionCode": "nyc",
              "RegionName": "New York City",
              "Nodes": [
                {
                  "Name": "1a",
                  "RegionID": 1,
                  "HostName": "derp1a.tailscale.com",
                  "CertName": "derp1a.tailscale.com",
                  "IPv4": "198.51.100.1",
                  "DERPPort": 443,
                  "STUNPort": 3478
                }
              ]
            },
            "2": {
              "RegionID": 2,
              "RegionCode": "lon",
              "RegionName": "London",
              "Avoid": true,
              "Nodes": [
                {
                  "Name": "2a",
                  "RegionID": 2,
                  "HostName": "derp2a.tailscale.com",
                  "STUNOnly": true
                }
              ]
            }
          },
          "OmitDefaultRegions": false
        }
        """

        guard let data = json.data(using: .utf8),
              let map = try? JSONDecoder().decode(NCTailscaleDERPMap.self, from: data) else {
            return false
        }

        guard map.regions.count == 2,
              let r1 = map.region(id: 1),
              r1.regionCode == "nyc",
              r1.usableNodes.count == 1,
              r1.usableNodes[0].effectiveDERPPort == 443,
              r1.usableNodes[0].effectiveServerName == "derp1a.tailscale.com",
              r1.usableNodes[0].dialHost == "198.51.100.1" else {
            return false
        }

        guard let r2 = map.region(id: 2),
              r2.avoid == true,
              r2.usableNodes.isEmpty else { // STUNOnly node is not relay usable
            return false
        }

        guard map.firstAvailableRegion?.regionID == 1 else {
            return false
        }

        guard let reencoded = try? JSONEncoder().encode(map),
              let roundtrip = try? JSONDecoder().decode(NCTailscaleDERPMap.self, from: reencoded),
              roundtrip == map else {
            return false
        }

        return true
    }
}

// MARK: - Compatibility Typealiases

public typealias DERPNode = NCTailscaleDERPNode
public typealias DERPRegion = NCTailscaleDERPRegion
public typealias DERPMap = NCTailscaleDERPMap
