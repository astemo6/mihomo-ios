import Foundation

// MARK: - Tailscale Status File Shared Model
//
// Pure Codable model representing the live state of a Tailscale node written by the
// PacketTunnel extension into `<state-dir>/status.json` and read by the App (Stage 4).
// Placed in Shared/NativeCore so it is compiled into both App and PacketTunnel targets.

/// Summary of the local Tailscale node (self node in netmap).
public struct NCTailscaleSelfNodeSummary: Codable, Equatable {
    public var id: Int64?
    public var stableID: String?
    public var name: String?
    public var addresses: [String] = []
    public var allowedIPs: [String] = []
    public var derpHomeRegion: Int?
    public var online: Bool?

    public init(
        id: Int64? = nil,
        stableID: String? = nil,
        name: String? = nil,
        addresses: [String] = [],
        allowedIPs: [String] = [],
        derpHomeRegion: Int? = nil,
        online: Bool? = nil
    ) {
        self.id = id
        self.stableID = stableID
        self.name = name
        self.addresses = addresses
        self.allowedIPs = allowedIPs
        self.derpHomeRegion = derpHomeRegion
        self.online = online
    }
}

/// Peer counts recorded by the Tailscale node.
public struct NCTailscalePeerCounts: Codable, Equatable {
    /// Total number of peers in the netmap.
    public var total: Int
    /// Number of peers reached via direct wire (disco/STUN). Kept at 0 for Stage 1.
    public var direct: Int
    /// Number of peers reached via DERP relays.
    public var relay: Int

    public init(total: Int = 0, direct: Int = 0, relay: Int = 0) {
        self.total = total
        self.direct = direct
        self.relay = relay
    }
}

/// Node state enumeration matching old bridge and UI conventions.
public enum NCTailscaleLoginState: String, Codable {
    case idle = "idle"
    case needsLogin = "needsLogin"
    case starting = "starting"
    case started = "started"
    case refused = "refused"
    case stopped = "stopped"
    case failed = "failed"
}

/// The complete status file contents stored at `<state-dir>/status.json`.
public struct NCTailscaleStatusFile: Codable, Equatable {
    /// Schema version for forwards/backwards compatibility.
    public var version: Int
    /// High-level login / lifecycle state (e.g. "needsLogin", "started", "stopped").
    public var state: String
    /// Interactive login URL when state is "needsLogin".
    public var authURL: String?
    /// Assigned tailnet IPv4 address (e.g. "100.x.y.z").
    public var ipv4: String?
    /// Assigned tailnet IPv6 address (e.g. "fd7a:115c:a1e0:...").
    public var ipv6: String?
    /// Summary of the self node.
    public var selfNode: NCTailscaleSelfNodeSummary?
    /// Current home DERP region ID selected for relaying.
    public var derpHomeRegion: Int?
    /// Peer connectivity breakdown.
    public var peerCounts: NCTailscalePeerCounts
    /// Most recent human-readable error, if any.
    public var lastError: String?
    /// Timestamp of the last status update.
    public var updatedAt: Date

    public init(
        version: Int = 1,
        state: String = NCTailscaleLoginState.idle.rawValue,
        authURL: String? = nil,
        ipv4: String? = nil,
        ipv6: String? = nil,
        selfNode: NCTailscaleSelfNodeSummary? = nil,
        derpHomeRegion: Int? = nil,
        peerCounts: NCTailscalePeerCounts = NCTailscalePeerCounts(),
        lastError: String? = nil,
        updatedAt: Date = Date()
    ) {
        self.version = version
        self.state = state
        self.authURL = authURL
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.selfNode = selfNode
        self.derpHomeRegion = derpHomeRegion
        self.peerCounts = peerCounts
        self.lastError = lastError
        self.updatedAt = updatedAt
    }

    public var isRunning: Bool {
        state == NCTailscaleLoginState.started.rawValue
    }

    public var isStopped: Bool {
        state == NCTailscaleLoginState.stopped.rawValue || state == NCTailscaleLoginState.refused.rawValue
    }

    public var isNeedsLogin: Bool {
        state == NCTailscaleLoginState.needsLogin.rawValue
    }
}
