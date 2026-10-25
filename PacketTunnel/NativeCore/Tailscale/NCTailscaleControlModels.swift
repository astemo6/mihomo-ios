import CryptoKit
import Foundation

// MARK: - Tailscale Key Text Encoding & Decoding Utilities
//
// Official representation of Curve25519 public and private keys in Tailscale:
// - Machine public key: "mkey:<64 hex digits>"
// - Node public key:    "nodekey:<64 hex digits>"
// - Disco public key:   "discokey:<64 hex digits>"
// - Private key:        "privkey:<64 hex digits>"

public enum NCTailscaleKeyEncoding {
    public static let mkeyPrefix = "mkey:"
    public static let nodekeyPrefix = "nodekey:"
    public static let discokeyPrefix = "discokey:"
    public static let privkeyPrefix = "privkey:"

    public static func encodeMachineKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        mkeyPrefix + hexString(Data(key.rawRepresentation))
    }

    public static func encodeNodeKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        nodekeyPrefix + hexString(Data(key.rawRepresentation))
    }

    public static func encodeDiscoKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        discokeyPrefix + hexString(Data(key.rawRepresentation))
    }

    public static func encodeMachineKey(raw32: Data) -> String {
        mkeyPrefix + hexString(raw32)
    }

    public static func encodeNodeKey(raw32: Data) -> String {
        nodekeyPrefix + hexString(raw32)
    }

    public static func encodeDiscoKey(raw32: Data) -> String {
        discokeyPrefix + hexString(raw32)
    }

    public static func encodePrivateKey(_ key: Curve25519.KeyAgreement.PrivateKey) -> String {
        privkeyPrefix + hexString(Data(key.rawRepresentation))
    }

    /// Strips any known prefix ("mkey:", "nodekey:", "discokey:", "privkey:") or custom prefix,
    /// and decodes the 64-character hexadecimal string into 32 raw bytes.
    public static func decodeKeyHex(_ text: String, expectedPrefix: String? = nil) -> Data? {
        var str = text.trimmingCharacters(in: .whitespacesAndNewlines)

        if let expected = expectedPrefix {
            if str.hasPrefix(expected) {
                str = String(str.dropFirst(expected.count))
            }
        } else {
            let prefixes = [mkeyPrefix, nodekeyPrefix, discokeyPrefix, privkeyPrefix]
            for p in prefixes {
                if str.hasPrefix(p) {
                    str = String(str.dropFirst(p.count))
                    break
                }
            }
        }

        str = str.trimmingCharacters(in: .whitespacesAndNewlines)
        guard str.count == 64 else { return nil }

        var data = Data(capacity: 32)
        var idx = str.startIndex
        while idx < str.endIndex {
            let nextIdx = str.index(idx, offsetBy: 2)
            guard let byte = UInt8(str[idx..<nextIdx], radix: 16) else { return nil }
            data.append(byte)
            idx = nextIdx
        }
        return data
    }

    public static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Control Plane Server Key Response (GET /key?v=106)

public struct NCTailscaleControlKeyResponse: Codable {
    public var publicKey: String

    enum CodingKeys: String, CodingKey {
        case publicKey
        case altPublicKey = "PublicKey"
    }

    public init(publicKey: String) {
        self.publicKey = publicKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let key = try container.decodeIfPresent(String.self, forKey: .publicKey) {
            self.publicKey = key
        } else if let key = try container.decodeIfPresent(String.self, forKey: .altPublicKey) {
            self.publicKey = key
        } else {
            throw DecodingError.keyNotFound(
                CodingKeys.publicKey,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Missing publicKey")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(publicKey, forKey: .publicKey)
    }

    /// Returns the 32 raw Curve25519 public key bytes, stripping "mkey:" if present.
    public var rawKeyBytes: Data? {
        NCTailscaleKeyEncoding.decodeKeyHex(publicKey, expectedPrefix: NCTailscaleKeyEncoding.mkeyPrefix)
    }
}

// MARK: - Hostinfo Model

public struct NCTailscaleHostinfo: Codable, Equatable {
    public var Hostname: String
    public var OS: String?
    public var OSVersion: String?
    public var DeviceModel: String?
    public var GoArch: String?
    public var App: String?

    public init(
        Hostname: String,
        OS: String? = "iOS",
        OSVersion: String? = nil,
        DeviceModel: String? = nil,
        GoArch: String? = nil,
        App: String? = "Tern"
    ) {
        self.Hostname = Hostname
        self.OS = OS
        self.OSVersion = OSVersion
        self.DeviceModel = DeviceModel
        self.GoArch = GoArch
        self.App = App
    }
}

// MARK: - Register Models (POST /machine/register)

public struct NCTailscaleRegisterAuth: Codable, Equatable {
    public var AuthKey: String?

    public init(AuthKey: String? = nil) {
        self.AuthKey = AuthKey
    }
}

public struct NCTailscaleRegisterRequest: Codable, Equatable {
    public var Version: Int
    public var NodeKey: String
    public var OldNodeKey: String?
    public var Auth: NCTailscaleRegisterAuth?
    public var Expiry: String?
    public var Followup: String?
    public var Hostinfo: NCTailscaleHostinfo?
    public var Ephemeral: Bool?

    public init(
        Version: Int = NCTailscaleConsts.capabilityVersion,
        NodeKey: String,
        OldNodeKey: String? = nil,
        Auth: NCTailscaleRegisterAuth? = nil,
        Expiry: String? = nil,
        Followup: String? = nil,
        Hostinfo: NCTailscaleHostinfo? = nil,
        Ephemeral: Bool? = nil
    ) {
        self.Version = Version
        self.NodeKey = NodeKey
        self.OldNodeKey = OldNodeKey
        self.Auth = Auth
        self.Expiry = Expiry
        self.Followup = Followup
        self.Hostinfo = Hostinfo
        self.Ephemeral = Ephemeral
    }
}

public struct NCTailscaleLoginInfo: Codable, Equatable {
    public var ID: Int64?
    public var Provider: String?
    public var LoginName: String?
    public var DisplayName: String?

    public init(ID: Int64? = nil, Provider: String? = nil, LoginName: String? = nil, DisplayName: String? = nil) {
        self.ID = ID
        self.Provider = Provider
        self.LoginName = LoginName
        self.DisplayName = DisplayName
    }
}

public struct NCTailscaleUserInfo: Codable, Equatable {
    public var ID: Int64?
    public var LoginName: String?
    public var DisplayName: String?

    public init(ID: Int64? = nil, LoginName: String? = nil, DisplayName: String? = nil) {
        self.ID = ID
        self.LoginName = LoginName
        self.DisplayName = DisplayName
    }
}

public struct NCTailscaleRegisterResponse: Codable, Equatable {
    public var NodeKeyExpired: Bool?
    public var MachineAuthorized: Bool?
    public var AuthURL: String?
    public var Error: String?
    public var Login: NCTailscaleLoginInfo?
    public var User: NCTailscaleUserInfo?

    public init(
        NodeKeyExpired: Bool? = nil,
        MachineAuthorized: Bool? = nil,
        AuthURL: String? = nil,
        Error: String? = nil,
        Login: NCTailscaleLoginInfo? = nil,
        User: NCTailscaleUserInfo? = nil
    ) {
        self.NodeKeyExpired = NodeKeyExpired
        self.MachineAuthorized = MachineAuthorized
        self.AuthURL = AuthURL
        self.Error = Error
        self.Login = Login
        self.User = User
    }
}

// MARK: - Map Request Model (POST /machine/map)

public struct NCTailscaleMapRequest: Codable, Equatable {
    public var Version: Int
    public var Compress: String
    public var KeepAlive: Bool
    public var NodeKey: String
    public var DiscoKey: String
    public var Stream: Bool
    public var Endpoints: [String]
    public var Hostinfo: NCTailscaleHostinfo?
    public var IncludeIPv6: Bool
    public var OmitCaps: Bool?

    public init(
        Version: Int = NCTailscaleConsts.capabilityVersion,
        Compress: String = "",
        KeepAlive: Bool = true,
        NodeKey: String,
        DiscoKey: String,
        Stream: Bool = true,
        Endpoints: [String] = [],
        Hostinfo: NCTailscaleHostinfo? = nil,
        IncludeIPv6: Bool = true,
        OmitCaps: Bool? = true
    ) {
        self.Version = Version
        self.Compress = Compress
        self.KeepAlive = KeepAlive
        self.NodeKey = NodeKey
        self.DiscoKey = DiscoKey
        self.Stream = Stream
        self.Endpoints = Endpoints
        self.Hostinfo = Hostinfo
        self.IncludeIPv6 = IncludeIPv6
        self.OmitCaps = OmitCaps
    }
}

// MARK: - Map Response & Subordinate Models

public struct NCTailscalePingRequest: Codable, Equatable {
    public var URL: String?
    public var Log: Bool?

    public init(URL: String? = nil, Log: Bool? = nil) {
        self.URL = URL
        self.Log = Log
    }
}

public struct NCTailscaleNode: Codable, Equatable {
    public var ID: Int64
    public var StableID: String?
    public var Name: String?
    public var Key: String
    public var DiscoKey: String?
    public var Addresses: [String]
    public var AllowedIPs: [String]
    public var Endpoints: [String]?
    public var DERP: String?
    public var HomeDERP: Int?
    public var Hostinfo: NCTailscaleHostinfo?
    public var Created: String?
    public var KeyExpiry: String?
    public var Online: Bool?
    public var LastSeen: String?
    public var MachineAuthorized: Bool?

    public init(
        ID: Int64,
        StableID: String? = nil,
        Name: String? = nil,
        Key: String,
        DiscoKey: String? = nil,
        Addresses: [String] = [],
        AllowedIPs: [String] = [],
        Endpoints: [String]? = nil,
        DERP: String? = nil,
        HomeDERP: Int? = nil,
        Hostinfo: NCTailscaleHostinfo? = nil,
        Created: String? = nil,
        KeyExpiry: String? = nil,
        Online: Bool? = nil,
        LastSeen: String? = nil,
        MachineAuthorized: Bool? = nil
    ) {
        self.ID = ID
        self.StableID = StableID
        self.Name = Name
        self.Key = Key
        self.DiscoKey = DiscoKey
        self.Addresses = Addresses
        self.AllowedIPs = AllowedIPs
        self.Endpoints = Endpoints
        self.DERP = DERP
        self.HomeDERP = HomeDERP
        self.Hostinfo = Hostinfo
        self.Created = Created
        self.KeyExpiry = KeyExpiry
        self.Online = Online
        self.LastSeen = LastSeen
        self.MachineAuthorized = MachineAuthorized
    }

    /// Derives the DERP home region ID from either `HomeDERP` (capver 111+) or `DERP` ("127.3.3.40:<port>").
    public var derpRegionID: Int? {
        if let home = HomeDERP, home > 0 {
            return home
        }
        if let derpStr = DERP {
            if let colonIdx = derpStr.lastIndex(of: ":") {
                let portPart = derpStr[derpStr.index(after: colonIdx)...]
                return Int(portPart)
            }
        }
        return nil
    }

    /// Extracts the first IPv4 address from `Addresses`, stripping the CIDR `/mask` if present.
    public var ipv4Address: String? {
        for addr in Addresses {
            let bare = addr.split(separator: "/").first.map(String.init) ?? addr
            if bare.contains(".") && !bare.contains(":") {
                return bare
            }
        }
        return nil
    }

    /// Extracts the first IPv6 address from `Addresses`, stripping the CIDR `/mask` if present.
    public var ipv6Address: String? {
        for addr in Addresses {
            let bare = addr.split(separator: "/").first.map(String.init) ?? addr
            if bare.contains(":") {
                return bare
            }
        }
        return nil
    }
}

public struct NCTailscalePeerChange: Codable, Equatable {
    public var NodeID: Int64
    public var DERPRegion: Int?
    public var Endpoints: [String]?
    public var Key: String?
    public var DiscoKey: String?
    public var Online: Bool?
    public var LastSeen: String?
    public var KeyExpiry: String?

    public init(
        NodeID: Int64,
        DERPRegion: Int? = nil,
        Endpoints: [String]? = nil,
        Key: String? = nil,
        DiscoKey: String? = nil,
        Online: Bool? = nil,
        LastSeen: String? = nil,
        KeyExpiry: String? = nil
    ) {
        self.NodeID = NodeID
        self.DERPRegion = DERPRegion
        self.Endpoints = Endpoints
        self.Key = Key
        self.DiscoKey = DiscoKey
        self.Online = Online
        self.LastSeen = LastSeen
        self.KeyExpiry = KeyExpiry
    }
}

public struct NCTailscaleDERPNode: Codable, Equatable, Sendable {
    public var Name: String
    public var RegionID: Int
    public var HostName: String
    public var CertName: String?
    public var IPv4: String?
    public var IPv6: String?
    public var STUNPort: Int?
    public var STUNOnly: Bool?
    public var DERPPort: Int?
    public var InsecureForTests: Bool?

    enum CodingKeys: String, CodingKey {
        case Name
        case RegionID
        case HostName
        case CertName
        case IPv4
        case IPv6
        case STUNPort
        case STUNOnly
        case DERPPort
        case InsecureForTests
    }

    public init(
        Name: String,
        RegionID: Int,
        HostName: String,
        CertName: String? = nil,
        IPv4: String? = nil,
        IPv6: String? = nil,
        STUNPort: Int? = nil,
        STUNOnly: Bool? = nil,
        DERPPort: Int? = nil,
        InsecureForTests: Bool? = nil
    ) {
        self.Name = Name
        self.RegionID = RegionID
        self.HostName = HostName
        self.CertName = CertName
        self.IPv4 = IPv4
        self.IPv6 = IPv6
        self.STUNPort = STUNPort
        self.STUNOnly = STUNOnly
        self.DERPPort = DERPPort
        self.InsecureForTests = InsecureForTests
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
        self.Name = name
        self.RegionID = regionID
        self.HostName = hostName
        self.CertName = certName
        self.IPv4 = ipv4
        self.IPv6 = ipv6
        self.STUNPort = stunPort
        self.STUNOnly = stunOnly
        self.DERPPort = derpPort
        self.InsecureForTests = insecureForTests
    }

    // Lowercase property accessors for DERP client compatibility
    public var name: String { Name }
    public var regionID: Int { RegionID }
    public var hostName: String { HostName }
    public var certName: String? { CertName }
    public var ipv4: String? { IPv4 }
    public var ipv6: String? { IPv6 }
    public var stunPort: Int? { STUNPort }
    public var stunOnly: Bool? { STUNOnly }
    public var derpPort: Int? { DERPPort }
    public var insecureForTests: Bool? { InsecureForTests }

    /// Effective TCP/TLS port for connecting to this DERP node (default 443).
    public var effectiveDERPPort: Int {
        if let p = DERPPort, p > 0 { return p }
        return 443
    }

    /// Effective STUN UDP port (default 3478).
    public var effectiveSTUNPort: Int {
        if let p = STUNPort, p > 0 { return p }
        return 3478
    }

    /// Server name used for TLS ClientHello SNI and certificate validation.
    /// Prefers `CertName` if set, otherwise falls back to `HostName`.
    public var effectiveServerName: String {
        if let cert = CertName, !cert.isEmpty { return cert }
        return HostName
    }

    /// Destination host used when establishing TCP connection (prefers IPv4 if available).
    public var dialHost: String {
        if let v4 = IPv4, !v4.isEmpty { return v4 }
        return HostName
    }

    /// Whether this node can be used as a DERP packet relay (not STUN-only).
    public var isRelayUsable: Bool {
        !(STUNOnly ?? false)
    }
}

public struct NCTailscaleDERPRegion: Codable, Equatable, Sendable {
    public var RegionID: Int
    public var RegionCode: String
    public var RegionName: String?
    public var Avoid: Bool?
    public var NoMeasureNoHome: Bool?
    public var Nodes: [NCTailscaleDERPNode]?

    enum CodingKeys: String, CodingKey {
        case RegionID
        case RegionCode
        case RegionName
        case Avoid
        case NoMeasureNoHome
        case Nodes
    }

    public init(
        RegionID: Int,
        RegionCode: String,
        RegionName: String? = nil,
        Avoid: Bool? = nil,
        NoMeasureNoHome: Bool? = nil,
        Nodes: [NCTailscaleDERPNode]? = nil
    ) {
        self.RegionID = RegionID
        self.RegionCode = RegionCode
        self.RegionName = RegionName
        self.Avoid = Avoid
        self.NoMeasureNoHome = NoMeasureNoHome
        self.Nodes = Nodes
    }

    public init(
        regionID: Int,
        regionCode: String,
        regionName: String? = nil,
        avoid: Bool? = nil,
        nodes: [NCTailscaleDERPNode] = []
    ) {
        self.RegionID = regionID
        self.RegionCode = regionCode
        self.RegionName = regionName
        self.Avoid = avoid
        self.NoMeasureNoHome = nil
        self.Nodes = nodes
    }

    // Lowercase property accessors for DERP client compatibility
    public var regionID: Int { RegionID }
    public var regionCode: String { RegionCode }
    public var regionName: String? { RegionName }
    public var avoid: Bool? { Avoid }
    public var noMeasureNoHome: Bool? { NoMeasureNoHome }
    public var nodes: [NCTailscaleDERPNode] { Nodes ?? [] }

    /// All nodes in this region capable of DERP packet relaying.
    public var usableNodes: [NCTailscaleDERPNode] {
        nodes.filter { $0.isRelayUsable }
    }
}

public struct NCTailscaleDERPMap: Codable, Equatable, Sendable {
    /// Regions indexed by integer RegionID.
    public var Regions: [Int: NCTailscaleDERPRegion]
    public var OmitDefaultRegions: Bool?

    enum CodingKeys: String, CodingKey {
        case Regions
        case OmitDefaultRegions
        case omitDefaultRegions = "omitDefaultRegions"
    }

    public init(Regions: [Int: NCTailscaleDERPRegion] = [:], OmitDefaultRegions: Bool? = nil) {
        self.Regions = Regions
        self.OmitDefaultRegions = OmitDefaultRegions
    }

    public init(regions: [Int: NCTailscaleDERPRegion] = [:], omitDefaultRegions: Bool? = nil) {
        self.Regions = regions
        self.OmitDefaultRegions = omitDefaultRegions
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.OmitDefaultRegions = (try? container.decodeIfPresent(Bool.self, forKey: .OmitDefaultRegions))
            ?? (try? container.decodeIfPresent(Bool.self, forKey: .omitDefaultRegions))

        if let stringKeyedRegions = try? container.decode([String: NCTailscaleDERPRegion].self, forKey: .Regions) {
            var map: [Int: NCTailscaleDERPRegion] = [:]
            for (key, region) in stringKeyedRegions {
                if let intKey = Int(key) {
                    map[intKey] = region
                }
            }
            self.Regions = map
        } else if let intKeyedRegions = try? container.decode([Int: NCTailscaleDERPRegion].self, forKey: .Regions) {
            self.Regions = intKeyedRegions
        } else {
            self.Regions = [:]
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(OmitDefaultRegions, forKey: .OmitDefaultRegions)

        var stringKeyed: [String: NCTailscaleDERPRegion] = [:]
        for (k, v) in Regions {
            stringKeyed[String(k)] = v
        }
        try container.encode(stringKeyed, forKey: .Regions)
    }

    // Lowercase property accessors for DERP client compatibility
    public var regions: [Int: NCTailscaleDERPRegion] { Regions }
    public var omitDefaultRegions: Bool? { OmitDefaultRegions }

    /// Looks up a region by its unique RegionID.
    public func region(id: Int) -> NCTailscaleDERPRegion? {
        Regions[id]
    }

    /// List of regions sorted in ascending order of RegionID.
    public var sortedRegions: [NCTailscaleDERPRegion] {
        Regions.values.sorted { $0.RegionID < $1.RegionID }
    }

    /// The first available region suitable for default home selection.
    /// Prefers non-avoid regions with at least one usable relay node.
    public var firstAvailableRegion: NCTailscaleDERPRegion? {
        let sorted = sortedRegions
        if let nonAvoid = sorted.first(where: { !($0.Avoid ?? false) && !$0.usableNodes.isEmpty }) {
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
              r2.usableNodes.isEmpty else {
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

public struct NCTailscaleDNSResolver: Codable, Equatable {
    public var Addr: String

    public init(Addr: String) {
        self.Addr = Addr
    }
}

public struct NCTailscaleDNSConfig: Codable, Equatable {
    public var Resolvers: [NCTailscaleDNSResolver]?
    public var Routes: [String: [NCTailscaleDNSResolver]]?
    public var Domains: [String]?
    public var Proxied: Bool?

    public init(
        Resolvers: [NCTailscaleDNSResolver]? = nil,
        Routes: [String: [NCTailscaleDNSResolver]]? = nil,
        Domains: [String]? = nil,
        Proxied: Bool? = nil
    ) {
        self.Resolvers = Resolvers
        self.Routes = Routes
        self.Domains = Domains
        self.Proxied = Proxied
    }
}

public struct NCTailscalePortRange: Codable, Equatable {
    public var First: UInt16
    public var Last: UInt16

    public init(First: UInt16, Last: UInt16) {
        self.First = First
        self.Last = Last
    }
}

/// One destination matcher of a packet filter rule (tailcfg.NetPortRange):
/// `IP` is "*" or an IP/CIDR string, `Bits` an optional prefix that takes
/// precedence over `IP`, `Ports` the destination port range.
public struct NCTailscaleNetPortRange: Codable, Equatable {
    public var IP: String
    public var Bits: String?
    public var Ports: NCTailscalePortRange

    public init(IP: String, Bits: String? = nil, Ports: NCTailscalePortRange) {
        self.IP = IP
        self.Bits = Bits
        self.Ports = Ports
    }
}

/// A capability grant attached to a filter rule (tailcfg.CapGrant).
/// Phase 3 parses but does not enforce capability grants: rules carrying
/// only grants never match as plain allows in the evaluator.
public struct NCTailscaleCapGrant: Codable, Equatable {
    public var Dsts: [String]?
    public var Caps: [String]?

    public init(Dsts: [String]? = nil, Caps: [String]? = nil) {
        self.Dsts = Dsts
        self.Caps = Caps
    }
}

/// tailcfg.PacketFilterRule, field-for-field. The phase-1 model typed
/// `DstPorts` as bare port ranges, which does not match the wire format
/// (each element is a NetPortRange object) and would have failed decoding
/// real MapResponses containing a PacketFilter; fixed in phase 3.
public struct NCTailscalePacketFilterRule: Codable, Equatable {
    public var SrcIPs: [String]?
    public var SrcBits: [String]?
    public var DstPorts: [NCTailscaleNetPortRange]?
    public var IPProto: [Int]?
    public var CapGrant: [NCTailscaleCapGrant]?

    public init(
        SrcIPs: [String]? = nil,
        SrcBits: [String]? = nil,
        DstPorts: [NCTailscaleNetPortRange]? = nil,
        IPProto: [Int]? = nil,
        CapGrant: [NCTailscaleCapGrant]? = nil
    ) {
        self.SrcIPs = SrcIPs
        self.SrcBits = SrcBits
        self.DstPorts = DstPorts
        self.IPProto = IPProto
        self.CapGrant = CapGrant
    }
}

public struct NCTailscaleMapResponse: Codable, Equatable {
    public var MapSessionHandle: String?
    public var Seq: Int64?
    public var KeepAlive: Bool?
    public var PingRequest: NCTailscalePingRequest?
    public var PopBrowserURL: String?
    public var Node: NCTailscaleNode?
    public var DERPMap: NCTailscaleDERPMap?
    public var Peers: [NCTailscaleNode]?
    public var PeersChanged: [NCTailscaleNode]?
    public var PeersRemoved: [Int64]?
    public var PeersChangedPatch: [NCTailscalePeerChange]?
    public var DNSConfig: NCTailscaleDNSConfig?
    public var PacketFilter: [NCTailscalePacketFilterRule]?
    public var ControlTime: String?
    public var NodeKeyExpired: Bool?

    public init(
        MapSessionHandle: String? = nil,
        Seq: Int64? = nil,
        KeepAlive: Bool? = nil,
        PingRequest: NCTailscalePingRequest? = nil,
        PopBrowserURL: String? = nil,
        Node: NCTailscaleNode? = nil,
        DERPMap: NCTailscaleDERPMap? = nil,
        Peers: [NCTailscaleNode]? = nil,
        PeersChanged: [NCTailscaleNode]? = nil,
        PeersRemoved: [Int64]? = nil,
        PeersChangedPatch: [NCTailscalePeerChange]? = nil,
        DNSConfig: NCTailscaleDNSConfig? = nil,
        PacketFilter: [NCTailscalePacketFilterRule]? = nil,
        ControlTime: String? = nil,
        NodeKeyExpired: Bool? = nil
    ) {
        self.MapSessionHandle = MapSessionHandle
        self.Seq = Seq
        self.KeepAlive = KeepAlive
        self.PingRequest = PingRequest
        self.PopBrowserURL = PopBrowserURL
        self.Node = Node
        self.DERPMap = DERPMap
        self.Peers = Peers
        self.PeersChanged = PeersChanged
        self.PeersRemoved = PeersRemoved
        self.PeersChangedPatch = PeersChangedPatch
        self.DNSConfig = DNSConfig
        self.PacketFilter = PacketFilter
        self.ControlTime = ControlTime
        self.NodeKeyExpired = NodeKeyExpired
    }
}
