import Foundation

// MARK: - Tailscale Netmap Snapshot
//
// Read-only snapshot of the active Tailscale network map.
// Emitted whenever a full or delta MapResponse is processed by `NCTailscaleNetmapStore`.

struct NCTailscaleNetmapSnapshot: Equatable {
    /// Local node description (self).
    let selfNode: NCTailscaleNode?
    /// Remote peer nodes currently active in the tailnet, keyed by NodeID.
    let peers: [Int64: NCTailscaleNode]
    /// Available DERP relay regions and nodes.
    let derpMap: NCTailscaleDERPMap?
    /// DNS configuration and MagicDNS routing overlays.
    let dnsConfig: NCTailscaleDNSConfig?
    /// Firewall packet filter rules.
    let packetFilter: [NCTailscalePacketFilterRule]?
    /// Last timestamp reported by the coordination server.
    let controlTime: String?

    init(
        selfNode: NCTailscaleNode? = nil,
        peers: [Int64: NCTailscaleNode] = [:],
        derpMap: NCTailscaleDERPMap? = nil,
        dnsConfig: NCTailscaleDNSConfig? = nil,
        packetFilter: [NCTailscalePacketFilterRule]? = nil,
        controlTime: String? = nil
    ) {
        self.selfNode = selfNode
        self.peers = peers
        self.derpMap = derpMap
        self.dnsConfig = dnsConfig
        self.packetFilter = packetFilter
        self.controlTime = controlTime
    }

    /// The local node's assigned tailnet IPv4 address (e.g. "100.x.y.z"), or nil if not yet assigned.
    var tailnetIPv4: String? {
        selfNode?.ipv4Address
    }

    /// The local node's assigned tailnet IPv6 address, or nil if not yet assigned.
    var tailnetIPv6: String? {
        selfNode?.ipv6Address
    }

    /// Total count of peers present in the network map.
    var peerCount: Int {
        peers.count
    }

    /// Home DERP region ID selected for the self node.
    var derpHomeRegion: Int? {
        selfNode?.derpRegionID
    }

    /// Finds a peer by its unique Node ID.
    func peer(id: Int64) -> NCTailscaleNode? {
        peers[id]
    }

    /// Finds a peer by its WireGuard node key (with or without "nodekey:" prefix).
    func peer(matchingKey keyStr: String) -> NCTailscaleNode? {
        let clean = keyStr.hasPrefix(NCTailscaleKeyEncoding.nodekeyPrefix)
            ? String(keyStr.dropFirst(NCTailscaleKeyEncoding.nodekeyPrefix.count))
            : keyStr
        return peers.values.first { peer in
            let peerClean = peer.Key.hasPrefix(NCTailscaleKeyEncoding.nodekeyPrefix)
                ? String(peer.Key.dropFirst(NCTailscaleKeyEncoding.nodekeyPrefix.count))
                : peer.Key
            return peerClean.caseInsensitiveCompare(clean) == .orderedSame
        }
    }
}

// MARK: - Incremental Netmap Store

/// Thread-safe storage managing the cumulative netmap state across long-poll `MapResponse` streams.
///
/// Follows official Tailscale delta-encoding rules:
/// 1. `Node`: If present, updates `selfNode`. Starting with capver 18, nil means unchanged.
/// 2. `Peers`: If present, replaces the entire peer set. `PeersChanged` and `PeersRemoved` are ignored.
/// 3. `PeersChanged`: Inserts or replaces individual peers by NodeID.
/// 4. `PeersRemoved`: Removes the specified NodeIDs.
/// 5. `PeersChangedPatch`: Performs in-place field updates on existing peer entries.
/// 6. `DERPMap`, `DNSConfig`, `PacketFilter`: Non-nil values replace previous state; nil means unchanged.
final class NCTailscaleNetmapStore {
    private var selfNode: NCTailscaleNode?
    private var peers: [Int64: NCTailscaleNode] = [:]
    private var derpMap: NCTailscaleDERPMap?
    private var dnsConfig: NCTailscaleDNSConfig?
    private var packetFilter: [NCTailscalePacketFilterRule]?
    private var controlTime: String?

    private var cachedSnapshot: NCTailscaleNetmapSnapshot?
    private let lock = NSLock()

    /// Callback fired whenever the netmap snapshot changes.
    var onSnapshotChanged: ((NCTailscaleNetmapSnapshot) -> Void)?

    init() {}

    /// Retrieves the current immutable snapshot of the netmap.
    func currentSnapshot() -> NCTailscaleNetmapSnapshot {
        lock.lock()
        defer { lock.unlock() }

        if let cached = cachedSnapshot {
            return cached
        }

        let snap = NCTailscaleNetmapSnapshot(
            selfNode: selfNode,
            peers: peers,
            derpMap: derpMap,
            dnsConfig: dnsConfig,
            packetFilter: packetFilter,
            controlTime: controlTime
        )
        cachedSnapshot = snap
        return snap
    }

    /// Applies a newly received MapResponse (full or incremental) to the store.
    func apply(mapResponse: NCTailscaleMapResponse) {
        var notifySnapshot: NCTailscaleNetmapSnapshot?

        lock.lock()
        var changed = false

        if let node = mapResponse.Node {
            selfNode = node
            changed = true
        }

        if let dm = mapResponse.DERPMap {
            derpMap = dm
            changed = true
        }

        if let dc = mapResponse.DNSConfig {
            dnsConfig = dc
            changed = true
        }

        if let pf = mapResponse.PacketFilter {
            packetFilter = pf
            changed = true
        }

        if let ct = mapResponse.ControlTime {
            controlTime = ct
            changed = true
        }

        // Peer handling: full replacement vs delta
        if let fullPeers = mapResponse.Peers {
            var newPeers: [Int64: NCTailscaleNode] = [:]
            newPeers.reserveCapacity(fullPeers.count)
            for p in fullPeers {
                newPeers[p.ID] = p
            }
            peers = newPeers
            changed = true
        } else {
            // Delta updates
            if let changedPeers = mapResponse.PeersChanged, !changedPeers.isEmpty {
                for p in changedPeers {
                    peers[p.ID] = p
                }
                changed = true
            }

            if let removedIDs = mapResponse.PeersRemoved, !removedIDs.isEmpty {
                for id in removedIDs {
                    peers.removeValue(forKey: id)
                }
                changed = true
            }

            if let patches = mapResponse.PeersChangedPatch, !patches.isEmpty {
                for patch in patches {
                    guard var existing = peers[patch.NodeID] else { continue }

                    if let r = patch.DERPRegion {
                        existing.HomeDERP = r
                        existing.DERP = "127.3.3.40:\(r)"
                    }
                    if let ep = patch.Endpoints {
                        existing.Endpoints = ep
                    }
                    if let k = patch.Key {
                        existing.Key = k
                    }
                    if let dk = patch.DiscoKey {
                        existing.DiscoKey = dk
                    }
                    if let on = patch.Online {
                        existing.Online = on
                    }
                    if let ls = patch.LastSeen {
                        existing.LastSeen = ls
                    }
                    if let ke = patch.KeyExpiry {
                        existing.KeyExpiry = ke
                    }

                    peers[patch.NodeID] = existing
                    changed = true
                }
            }
        }

        if changed {
            cachedSnapshot = nil
            let snap = NCTailscaleNetmapSnapshot(
                selfNode: selfNode,
                peers: peers,
                derpMap: derpMap,
                dnsConfig: dnsConfig,
                packetFilter: packetFilter,
                controlTime: controlTime
            )
            cachedSnapshot = snap
            notifySnapshot = snap
        }
        lock.unlock()

        if let snap = notifySnapshot {
            onSnapshotChanged?(snap)
        }
    }

    /// Resets the store to an initial empty state.
    func reset() {
        var notifySnapshot: NCTailscaleNetmapSnapshot?

        lock.lock()
        selfNode = nil
        peers.removeAll(keepingCapacity: false)
        derpMap = nil
        dnsConfig = nil
        packetFilter = nil
        controlTime = nil
        cachedSnapshot = nil

        let emptySnap = NCTailscaleNetmapSnapshot()
        cachedSnapshot = emptySnap
        notifySnapshot = emptySnap
        lock.unlock()

        if let snap = notifySnapshot {
            onSnapshotChanged?(snap)
        }
    }
}
