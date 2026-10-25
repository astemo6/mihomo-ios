import CryptoKit
import Foundation

// MARK: - Tailscale Key Text Encoding & Decoding Utilities
//
// Official representation of Curve25519 public and private keys in Tailscale:
// - Machine public key: "mkey:<64 hex digits>"
// - Node public key:    "nodekey:<64 hex digits>"
// - Disco public key:   "discokey:<64 hex digits>"
// - Private key:        "privkey:<64 hex digits>"

enum NCTailscaleKeyEncoding {
    static let mkeyPrefix = "mkey:"
    static let nodekeyPrefix = "nodekey:"
    static let discokeyPrefix = "discokey:"
    static let privkeyPrefix = "privkey:"

    static func encodeMachineKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        mkeyPrefix + hexString(Data(key.rawRepresentation))
    }

    static func encodeNodeKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        nodekeyPrefix + hexString(Data(key.rawRepresentation))
    }

    static func encodeDiscoKey(_ key: Curve25519.KeyAgreement.PublicKey) -> String {
        discokeyPrefix + hexString(Data(key.rawRepresentation))
    }

    static func encodeMachineKey(raw32: Data) -> String {
        mkeyPrefix + hexString(raw32)
    }

    static func encodeNodeKey(raw32: Data) -> String {
        nodekeyPrefix + hexString(raw32)
    }

    static func encodeDiscoKey(raw32: Data) -> String {
        discokeyPrefix + hexString(raw32)
    }

    static func encodePrivateKey(_ key: Curve25519.KeyAgreement.PrivateKey) -> String {
        privkeyPrefix + hexString(Data(key.rawRepresentation))
    }

    /// Strips any known prefix ("mkey:", "nodekey:", "discokey:", "privkey:") or custom prefix,
    /// and decodes the 64-character hexadecimal string into 32 raw bytes.
    static func decodeKeyHex(_ text: String, expectedPrefix: String? = nil) -> Data? {
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

    /// Decodes a netmap key string ("nodekey:<hex>", "discokey:<hex>", "mkey:<hex>", or bare hex)
    /// into its 32 raw bytes. Returns nil when the text is not a 64-digit hex key.
    static func decodeKey(_ text: String) -> [UInt8]? {
        guard let data = decodeKeyHex(text) else { return nil }
        return [UInt8](data)
    }

    static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Control Plane Server Key Response (GET /key?v=106)

struct NCTailscaleControlKeyResponse: Codable {
    var publicKey: String

    enum CodingKeys: String, CodingKey {
        case publicKey
        case altPublicKey = "PublicKey"
    }

    init(publicKey: String) {
        self.publicKey = publicKey
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(publicKey, forKey: .publicKey)
    }

    /// Returns the 32 raw Curve25519 public key bytes, stripping "mkey:" if present.
    var rawKeyBytes: Data? {
        NCTailscaleKeyEncoding.decodeKeyHex(publicKey, expectedPrefix: NCTailscaleKeyEncoding.mkeyPrefix)
    }
}

// MARK: - Hostinfo Model

struct NCTailscaleHostinfo: Codable, Equatable {
    var Hostname: String
    var OS: String?
    var OSVersion: String?
    var DeviceModel: String?
    var GoArch: String?
    var App: String?

    init(
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

struct NCTailscaleRegisterAuth: Codable, Equatable {
    var AuthKey: String?

    init(AuthKey: String? = nil) {
        self.AuthKey = AuthKey
    }
}

struct NCTailscaleRegisterRequest: Codable, Equatable {
    var Version: Int
    var NodeKey: String
    var OldNodeKey: String?
    var Auth: NCTailscaleRegisterAuth?
    var Expiry: String?
    var Followup: String?
    var Hostinfo: NCTailscaleHostinfo?
    var Ephemeral: Bool?

    init(
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

struct NCTailscaleLoginInfo: Codable, Equatable {
    var ID: Int64?
    var Provider: String?
    var LoginName: String?
    var DisplayName: String?

    init(ID: Int64? = nil, Provider: String? = nil, LoginName: String? = nil, DisplayName: String? = nil) {
        self.ID = ID
        self.Provider = Provider
        self.LoginName = LoginName
        self.DisplayName = DisplayName
    }
}

struct NCTailscaleUserInfo: Codable, Equatable {
    var ID: Int64?
    var LoginName: String?
    var DisplayName: String?

    init(ID: Int64? = nil, LoginName: String? = nil, DisplayName: String? = nil) {
        self.ID = ID
        self.LoginName = LoginName
        self.DisplayName = DisplayName
    }
}

struct NCTailscaleRegisterResponse: Codable, Equatable {
    var NodeKeyExpired: Bool?
    var MachineAuthorized: Bool?
    var AuthURL: String?
    var Error: String?
    var Login: NCTailscaleLoginInfo?
    var User: NCTailscaleUserInfo?

    init(
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

struct NCTailscaleMapRequest: Codable, Equatable {
    var Version: Int
    var Compress: String
    var KeepAlive: Bool
    var NodeKey: String
    var DiscoKey: String
    var Stream: Bool
    var Endpoints: [String]
    var Hostinfo: NCTailscaleHostinfo?
    var IncludeIPv6: Bool
    var OmitCaps: Bool?

    init(
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

struct NCTailscalePingRequest: Codable, Equatable {
    var URL: String?
    var Log: Bool?

    init(URL: String? = nil, Log: Bool? = nil) {
        self.URL = URL
        self.Log = Log
    }
}

struct NCTailscaleNode: Codable, Equatable {
    var ID: Int64
    var StableID: String?
    var Name: String?
    var Key: String
    var DiscoKey: String?
    var Addresses: [String]
    var AllowedIPs: [String]
    var Endpoints: [String]?
    var DERP: String?
    var HomeDERP: Int?
    var Hostinfo: NCTailscaleHostinfo?
    var Created: String?
    var KeyExpiry: String?
    var Online: Bool?
    var LastSeen: String?
    var MachineAuthorized: Bool?

    init(
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
    var derpRegionID: Int? {
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
    var ipv4Address: String? {
        for addr in Addresses {
            let bare = addr.split(separator: "/").first.map(String.init) ?? addr
            if bare.contains(".") && !bare.contains(":") {
                return bare
            }
        }
        return nil
    }

    /// Extracts the first IPv6 address from `Addresses`, stripping the CIDR `/mask` if present.
    var ipv6Address: String? {
        for addr in Addresses {
            let bare = addr.split(separator: "/").first.map(String.init) ?? addr
            if bare.contains(":") {
                return bare
            }
        }
        return nil
    }
}

struct NCTailscalePeerChange: Codable, Equatable {
    var NodeID: Int64
    var DERPRegion: Int?
    var Endpoints: [String]?
    var Key: String?
    var DiscoKey: String?
    var Online: Bool?
    var LastSeen: String?
    var KeyExpiry: String?

    init(
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

struct NCTailscaleDERPNode: Codable, Equatable, Sendable {
    var Name: String
    var RegionID: Int
    var HostName: String
    var CertName: String?
    var IPv4: String?
    var IPv6: String?
    var STUNPort: Int?
    var STUNOnly: Bool?
    var DERPPort: Int?
    var InsecureForTests: Bool?

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

    init(
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

    init(
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
    var name: String { Name }
    var regionID: Int { RegionID }
    var hostName: String { HostName }
    var certName: String? { CertName }
    var ipv4: String? { IPv4 }
    var ipv6: String? { IPv6 }
    var stunPort: Int? { STUNPort }
    var stunOnly: Bool? { STUNOnly }
    var derpPort: Int? { DERPPort }
    var insecureForTests: Bool? { InsecureForTests }

    /// Effective TCP/TLS port for connecting to this DERP node (default 443).
    var effectiveDERPPort: Int {
        if let p = DERPPort, p > 0 { return p }
        return 443
    }

    /// Effective STUN UDP port (default 3478).
    var effectiveSTUNPort: Int {
        if let p = STUNPort, p > 0 { return p }
        return 3478
    }

    /// Server name used for TLS ClientHello SNI and certificate validation.
    /// Prefers `CertName` if set, otherwise falls back to `HostName`.
    var effectiveServerName: String {
        if let cert = CertName, !cert.isEmpty { return cert }
        return HostName
    }

    /// Destination host used when establishing TCP connection (prefers IPv4 if available).
    var dialHost: String {
        if let v4 = IPv4, !v4.isEmpty { return v4 }
        return HostName
    }

    /// Whether this node can be used as a DERP packet relay (not STUN-only).
    var isRelayUsable: Bool {
        !(STUNOnly ?? false)
    }
}

struct NCTailscaleDERPRegion: Codable, Equatable, Sendable {
    var RegionID: Int
    var RegionCode: String
    var RegionName: String?
    var Avoid: Bool?
    var NoMeasureNoHome: Bool?
    var Nodes: [NCTailscaleDERPNode]?

    enum CodingKeys: String, CodingKey {
        case RegionID
        case RegionCode
        case RegionName
        case Avoid
        case NoMeasureNoHome
        case Nodes
    }

    init(
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

    init(
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
    var regionID: Int { RegionID }
    var regionCode: String { RegionCode }
    var regionName: String? { RegionName }
    var avoid: Bool? { Avoid }
    var noMeasureNoHome: Bool? { NoMeasureNoHome }
    var nodes: [NCTailscaleDERPNode] { Nodes ?? [] }

    /// All nodes in this region capable of DERP packet relaying.
    var usableNodes: [NCTailscaleDERPNode] {
        nodes.filter { $0.isRelayUsable }
    }
}

struct NCTailscaleDERPMap: Codable, Equatable, Sendable {
    /// Regions indexed by integer RegionID.
    var Regions: [Int: NCTailscaleDERPRegion]
    var OmitDefaultRegions: Bool?

    enum CodingKeys: String, CodingKey {
        case Regions
        case OmitDefaultRegions
        case omitDefaultRegions = "omitDefaultRegions"
    }

    init(Regions: [Int: NCTailscaleDERPRegion] = [:], OmitDefaultRegions: Bool? = nil) {
        self.Regions = Regions
        self.OmitDefaultRegions = OmitDefaultRegions
    }

    init(regions: [Int: NCTailscaleDERPRegion] = [:], omitDefaultRegions: Bool? = nil) {
        self.Regions = regions
        self.OmitDefaultRegions = omitDefaultRegions
    }

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(OmitDefaultRegions, forKey: .OmitDefaultRegions)

        var stringKeyed: [String: NCTailscaleDERPRegion] = [:]
        for (k, v) in Regions {
            stringKeyed[String(k)] = v
        }
        try container.encode(stringKeyed, forKey: .Regions)
    }

    // Lowercase property accessors for DERP client compatibility
    var regions: [Int: NCTailscaleDERPRegion] { Regions }
    var omitDefaultRegions: Bool? { OmitDefaultRegions }

    /// Looks up a region by its unique RegionID.
    func region(id: Int) -> NCTailscaleDERPRegion? {
        Regions[id]
    }

    /// List of regions sorted in ascending order of RegionID.
    var sortedRegions: [NCTailscaleDERPRegion] {
        Regions.values.sorted { $0.RegionID < $1.RegionID }
    }

    /// The first available region suitable for default home selection.
    /// Prefers non-avoid regions with at least one usable relay node.
    var firstAvailableRegion: NCTailscaleDERPRegion? {
        let sorted = sortedRegions
        if let nonAvoid = sorted.first(where: { !($0.Avoid ?? false) && !$0.usableNodes.isEmpty }) {
            return nonAvoid
        }
        return sorted.first(where: { !$0.usableNodes.isEmpty })
    }

    // MARK: - Debug Self-Test Verification

    /// Verifies JSON round-trip decoding against official tailcfg DERPMap format.
    @discardableResult
    static func selfTest() -> Bool {
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

struct NCTailscaleDNSResolver: Codable, Equatable {
    var Addr: String

    init(Addr: String) {
        self.Addr = Addr
    }
}

struct NCTailscaleDNSConfig: Codable, Equatable {
    var Resolvers: [NCTailscaleDNSResolver]?
    var Routes: [String: [NCTailscaleDNSResolver]]?
    var Domains: [String]?
    var Proxied: Bool?

    init(
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

struct NCTailscalePortRange: Codable, Equatable {
    var First: UInt16
    var Last: UInt16

    init(First: UInt16, Last: UInt16) {
        self.First = First
        self.Last = Last
    }
}

/// One destination matcher of a packet filter rule (tailcfg.NetPortRange):
/// `IP` is "*" or an IP/CIDR string, `Bits` an optional prefix that takes
/// precedence over `IP`, `Ports` the destination port range.
struct NCTailscaleNetPortRange: Codable, Equatable {
    var IP: String
    var Bits: String?
    var Ports: NCTailscalePortRange

    init(IP: String, Bits: String? = nil, Ports: NCTailscalePortRange) {
        self.IP = IP
        self.Bits = Bits
        self.Ports = Ports
    }
}

/// A capability grant attached to a filter rule (tailcfg.CapGrant).
/// Phase 3 parses but does not enforce capability grants: rules carrying
/// only grants never match as plain allows in the evaluator.
struct NCTailscaleCapGrant: Codable, Equatable {
    var Dsts: [String]?
    var Caps: [String]?

    init(Dsts: [String]? = nil, Caps: [String]? = nil) {
        self.Dsts = Dsts
        self.Caps = Caps
    }
}

/// tailcfg.PacketFilterRule, field-for-field. The phase-1 model typed
/// `DstPorts` as bare port ranges, which does not match the wire format
/// (each element is a NetPortRange object) and would have failed decoding
/// real MapResponses containing a PacketFilter; fixed in phase 3.
struct NCTailscalePacketFilterRule: Codable, Equatable {
    var SrcIPs: [String]?
    var SrcBits: [String]?
    var DstPorts: [NCTailscaleNetPortRange]?
    var IPProto: [Int]?
    var CapGrant: [NCTailscaleCapGrant]?

    init(
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

struct NCTailscaleMapResponse: Codable, Equatable {
    var MapSessionHandle: String?
    var Seq: Int64?
    var KeepAlive: Bool?
    var PingRequest: NCTailscalePingRequest?
    var PopBrowserURL: String?
    var Node: NCTailscaleNode?
    var DERPMap: NCTailscaleDERPMap?
    var Peers: [NCTailscaleNode]?
    var PeersChanged: [NCTailscaleNode]?
    var PeersRemoved: [Int64]?
    var PeersChangedPatch: [NCTailscalePeerChange]?
    var DNSConfig: NCTailscaleDNSConfig?
    var PacketFilter: [NCTailscalePacketFilterRule]?
    var ControlTime: String?
    var NodeKeyExpired: Bool?

    init(
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
