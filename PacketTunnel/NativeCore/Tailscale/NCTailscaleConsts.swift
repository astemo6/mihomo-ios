import Foundation

/// Central protocol constants, paths, headers, and memory thresholds for Tailscale (ts2021 & DERP).
/// All protocol literals are cross-referenced with official Tailscale client implementations.
enum NCTailscaleConsts {

    // MARK: - Capability Version

    /// The current Tailscale capability version.
    /// Official reference: `tailscale.com/tailcfg.CurrentCapabilityVersion = 106`.
    /// Used in query parameters (e.g. `GET /key?v=106`) and control plane negotiation.
    static let capabilityVersion: Int = 106

    // MARK: - Control Plane Paths & Headers

    /// Default control plane URL used when not specified in configuration.
    /// Official reference: `tailscale.com/ipn.DefaultControlURL = "https://controlplane.tailscale.com"`.
    static let defaultControlURL: String = "https://controlplane.tailscale.com"

    /// Endpoint path to retrieve the control plane public key.
    /// Official reference: `tailscale.com/control/controlhttp/client.go` (`GET /key?v=...`).
    static let keyPath: String = "/key"

    /// Endpoint path to upgrade to ts2021 Noise-encrypted control protocol session.
    /// Official reference: `tailscale.com/control/controlhttp/ts2021.go` (`POST /ts2021`).
    static let ts2021Path: String = "/ts2021"

    /// HTTP Upgrade header value for the ts2021 control protocol session.
    /// Official reference: `tailscale.com/control/controlhttp/ts2021.go` `upgradeHeader = "tailscale-control-protocol"`.
    static let upgradeHeaderValue: String = "tailscale-control-protocol"

    /// HTTP Connection header value for upgrading connections.
    static let connectionUpgradeValue: String = "Upgrade"

    /// Magic prefix header bytes optionally transmitted before the ts2021 Noise handshake.
    /// Official reference: `tailscale.com/control/controlhttp/ts2021.go` `handshakeHeader = []byte("ts2021")`.
    static let ts2021HandshakeHeader: [UInt8] = Array("ts2021".utf8)

    // MARK: - Noise Protocol & Prologue

    /// Noise protocol handshake suite identifier for ts2021.
    /// Official reference: `tailscale.com/control/controlhttp/ts2021.go`.
    /// Pattern: IK (Initiator knows Responder static key in advance).
    /// DH: 25519 (X25519).
    /// Cipher: ChaChaPoly (ChaCha20-Poly1305).
    /// Hash: BLAKE2s (BLAKE2s-256).
    static let noiseProtocolName: String = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

    /// Noise prologue literal mixed into the handshake state at initialization.
    /// Official reference: `tailscale.com/control/controlhttp/ts2021.go` `earlyNoisePrologue = []byte("Tailscale Control Protocol v2021")`.
    static let noisePrologueLiteral: String = "Tailscale Control Protocol v2021"

    // MARK: - DERP (Designated Encrypted Relay for Packets)

    /// HTTP path for upgrading a connection to a DERP relay session.
    /// Official reference: `tailscale.com/derp/derphttp/derphttp_client.go` (`GET /derp`).
    static let derpPath: String = "/derp"

    /// HTTP Upgrade header value for DERP sessions.
    /// Official reference: `tailscale.com/derp/derphttp` `Upgrade: DERP`.
    static let derpUpgradeHeaderValue: String = "DERP"

    /// 4-byte ASCII magic identifier for DERP framing.
    /// Official reference: `tailscale.com/derp` `magic = "DERP"`.
    static let derpMagic: UInt32 = 0x4445_5250 // ASCII "DERP"

    /// Length of a standard DERP frame header (1 byte type + 4 bytes big-endian length).
    /// Official reference: `tailscale.com/derp.frameHeaderLen = 5`.
    static let derpHeaderLength: Int = 5

    /// Official DERP frame type enumeration.
    /// Official reference: `tailscale.com/derp/derp.go` `frameType` definitions.
    enum DERPFrameType: UInt8, CaseIterable {
        /// ServerKey: 8-byte magic + 32-byte server public key. Sent by server upon connect.
        case serverKey = 0x01
        /// ClientInfo: Client's public key (32 bytes) + NaCl box encrypted ClientInfo JSON.
        case clientInfo = 0x02
        /// ServerInfo: NaCl box encrypted ServerInfo JSON from server.
        case serverInfo = 0x03
        /// SendPacket: 32-byte destination public key + raw packet payload.
        case sendPacket = 0x04
        /// ForwardPacket: Internal relay forward frame.
        case forwardPacket = 0x05
        /// RecvPacket: 32-byte source public key + raw packet payload.
        case recvPacket = 0x06
        /// KeepAlive: 0-byte frame payload used to keep the connection alive.
        case keepAlive = 0x07
        /// NotePreferred: 1-byte boolean (0x01 for preferred home, 0x00 otherwise).
        case notePreferred = 0x08
        /// PeerGone: 32-byte peer public key + 1-byte reason.
        case peerGone = 0x09
        /// PeerPresent: 32-byte peer public key.
        case peerPresent = 0x0a
        /// WatchPres: 1-byte boolean for presence notification subscription.
        case watchPres = 0x0b
        /// Ping: 8-byte opaque ping payload.
        case ping = 0x0c
        /// Pong: 8-byte opaque payload echoing the ping payload.
        case pong = 0x0d
        /// Health: UTF-8 formatted error string from the server.
        case health = 0x0e
        /// Restarting: 4-byte reconnect duration (ms) + 4-byte try-for duration (ms).
        case restarting = 0x0f

        public var name: String {
            switch self {
            case .serverKey: return "ServerKey"
            case .clientInfo: return "ClientInfo"
            case .serverInfo: return "ServerInfo"
            case .sendPacket: return "SendPacket"
            case .forwardPacket: return "ForwardPacket"
            case .recvPacket: return "RecvPacket"
            case .keepAlive: return "KeepAlive"
            case .notePreferred: return "NotePreferred"
            case .peerGone: return "PeerGone"
            case .peerPresent: return "PeerPresent"
            case .watchPres: return "WatchPres"
            case .ping: return "Ping"
            case .pong: return "Pong"
            case .health: return "Health"
            case .restarting: return "Restarting"
            }
        }
    }

    // MARK: - Memory Guard Constants

    /// Minimum available bytes in the Network Extension required before starting a Tailscale node.
    /// Below 14 MB (14 << 20), start is refused to protect against iOS Jetsam terminations.
    /// Aligns with Go bridge specification: `tsMinAvailableToStart = 14 << 20`.
    static let minAvailableToStart: Int64 = 14 << 20

    /// If available memory drops below 5 MB (5 << 20) during execution, Tailscale is stopped.
    /// Aligns with Go bridge specification: `tsStopBelowAvailable = 5 << 20`.
    static let stopBelowAvailable: Int64 = 5 << 20

    /// Memory watchdog check interval in seconds.
    /// Aligns with Go bridge specification: `tsWatchInterval = 2 * time.Second`.
    static let watchdogInterval: TimeInterval = 2.0

    /// Target resident memory footprint for Tailscale in bytes (< 8 MB).
    static let targetResidentLimit: Int64 = 8 << 20

    // MARK: - Error Text Formatting (Aligned with GoText / Go Bridge)

    /// Formats the refusal error message when memory is insufficient at startup.
    static func refusalErrorMessage(availableBytes: Int64) -> String {
        let mb = Double(availableBytes) / 1_048_576.0
        let reqMB = Int(minAvailableToStart >> 20)
        return String(
            format: "Tailscale 未启动：隧道扩展只剩 %.1f MB 可用内存（启动至少需要 %d MB，iOS 对 VPN 扩展的上限约 50 MB），继续启动可能让系统直接终止 VPN。可减少规则集 / 模块后重新连接，或在 更多 → 诊断 查看隧道内存",
            mb,
            reqMB
        )
    }

    /// Formats the stop error message when memory drops below safe threshold during operation.
    static func stopErrorMessage(availableBytes: Int64) -> String {
        let mb = Double(availableBytes) / 1_048_576.0
        return String(
            format: "Tailscale 已停止：隧道扩展可用内存降到 %.1f MB，为避免 VPN 被系统终止已关闭 Tailscale。重新连接后可再次使用",
            mb
        )
    }
}
