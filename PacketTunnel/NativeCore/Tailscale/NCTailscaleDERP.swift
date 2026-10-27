import CryptoKit
import Foundation

// MARK: - Tailscale DERP Client (Designated Encrypted Relay for Packets)
//
// Manages DERP connections across multiple geographic regions for the WireGuard
// data plane. Provides:
// 1. Persistent connection to the designated Home Region with exponential backoff
//    reconnect and node round-robin failover.
// 2. On-demand connection creation to non-home regions when sending packets to peers
//    located in different DERP regions.
// 3. Packet dispatching, ping/pong latency measurement, and idle session pruning
//    to ensure resident memory footprint remains strictly under the 8 MB target.
//
// Pinned Interfaces:
// - Class: `NCTailscaleDERPClient`
// - Methods: `start(derpMap:homeRegionID:nodeKey:)`, `stop()`, `sendPacket(to:regionID:data:)`
// - Callbacks: `onPacket`, `onPeerGone`, `onHomeStateChange`

final class NCTailscaleDERPClient {

    // MARK: - Callbacks (Pinned Interface)

    /// Inbound WireGuard packet received over DERP.
    /// Parameters: (sourceNodePublicKey: 32 bytes, rawWireGuardPacket: Data)
    var onPacket: ((Data, Data) -> Void)?

    /// Peer departure notification from DERP server.
    /// Parameters: (peerNodePublicKey: 32 bytes)
    var onPeerGone: ((Data) -> Void)?

    /// Home DERP region connection state change notification.
    /// Parameters: (isConnected: Bool, regionID: Int)
    var onHomeStateChange: ((Bool, Int) -> Void)?

    // MARK: - Configuration & Key Material

    private let queue: DispatchQueue
    private var derpMap: NCTailscaleDERPMap?
    private var configuredHomeRegionID: Int = 0
    private(set) var effectiveHomeRegionID: Int = 0
    private var nodeKey: Curve25519.KeyAgreement.PrivateKey?

    // MARK: - Home Region Connection State

    private var homeSession: NCDERPSession?
    private var homeNodeIndex: Int = 0
    private var homeReconnectWorkItem: DispatchWorkItem?
    private var homeBackoffSeconds: TimeInterval = 1.0

    private static let minBackoffSeconds: TimeInterval = 1.0
    private static let maxBackoffSeconds: TimeInterval = 30.0

    // MARK: - Non-Home On-Demand Sessions

    /// Active on-demand sessions for non-home regions: [RegionID: NCDERPSession]
    private var otherSessions = [Int: NCDERPSession]()

    /// Idle session timeout (seconds). Inactive non-home regions are closed to conserve memory.
    private static let nonHomeIdleTimeout: TimeInterval = 90.0

    private var idleSweepTimer: DispatchWorkItem?

    // MARK: - Lifecycle State

    private var isStarted = false
    private var isStopped = false

    // MARK: - Initialization

    /// Marks `queue` so status getters can tell when they already run on it.
    /// The client shares one serial queue between control and DERP, and the
    /// netmap callback reads these getters on that queue: a plain `queue.sync`
    /// there would trap (dispatch_sync on the current queue).
    private let queueKey = DispatchSpecificKey<UInt8>()

    init(queue: DispatchQueue = DispatchQueue(label: "nc.tailscale.derp")) {
        self.queue = queue
        queue.setSpecific(key: queueKey, value: 1)
    }

    private func onQueue<T>(_ body: () -> T) -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            return body()
        }
        return queue.sync(execute: body)
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle Management (Pinned Interface)

    /// Starts the DERP client with the given DERPMap, home region ID, and node identity private key.
    ///
    /// - Parameters:
    ///   - derpMap: Complete geographic DERP map.
    ///   - homeRegionID: Desired home region (0 = automatically select first available region).
    ///   - nodeKey: Curve25519 node private key used as the DERP authentication identity.
    func start(
        derpMap: NCTailscaleDERPMap,
        homeRegionID: Int,
        nodeKey: Curve25519.KeyAgreement.PrivateKey
    ) {
        queue.async { [weak self] in
            guard let self = self, !self.isStarted else { return }
            self.isStarted = true
            self.isStopped = false

            self.derpMap = derpMap
            self.configuredHomeRegionID = homeRegionID
            self.nodeKey = nodeKey

            self.resolveEffectiveHomeRegion()
            self.connectHome()
            self.startIdleSweepTimer()
        }
    }

    /// Stops all active DERP connections, cancels reconnection timers, and releases resources.
    func stop() {
        queue.async { [weak self] in
            guard let self = self, !self.isStopped else { return }
            self.isStopped = true
            self.isStarted = false

            // Cancel home reconnection timer
            self.homeReconnectWorkItem?.cancel()
            self.homeReconnectWorkItem = nil

            // Cancel idle pruner
            self.idleSweepTimer?.cancel()
            self.idleSweepTimer = nil

            // Close home session
            if let home = self.homeSession {
                self.homeSession = nil
                home.close()
                self.onHomeStateChange?(false, self.effectiveHomeRegionID)
            }

            // Close all non-home sessions
            for (_, sess) in self.otherSessions {
                sess.close()
            }
            self.otherSessions.removeAll()
        }
    }

    /// Dynamically updates the DERPMap (e.g. from incremental netmap updates).
    func updateDERPMap(_ newMap: NCTailscaleDERPMap) {
        queue.async { [weak self] in
            guard let self = self, !self.isStopped else { return }
            self.derpMap = newMap

            // If effective home region was 0 or no longer valid, re-resolve
            if self.effectiveHomeRegionID == 0 || newMap.region(id: self.effectiveHomeRegionID) == nil {
                self.resolveEffectiveHomeRegion()
                self.reconnectHomeImmediately()
            }
        }
    }

    // MARK: - Packet Transmission (Pinned Interface)

    /// Sends a WireGuard packet to a destination peer.
    ///
    /// - Parameters:
    ///   - peerKey: 32-byte Curve25519 node public key of the destination peer.
    ///   - regionID: DERP region ID where the peer is currently located (0 = send to home region).
    ///   - data: Raw WireGuard packet payload.
    func sendPacket(to peerKey: Data, regionID: Int, data: Data) {
        queue.async { [weak self] in
            guard let self = self, !self.isStopped else { return }

            guard peerKey.count == 32 else { return }
            guard data.count <= NCDERPFrameCodec.maxPacketSize else { return }

            let targetRegion = (regionID == 0) ? self.effectiveHomeRegionID : regionID

            if targetRegion == self.effectiveHomeRegionID {
                // Route via persistent home region connection
                if let home = self.homeSession {
                    home.sendPacket(destKey: peerKey, data: data)
                }
            } else {
                // Route via on-demand non-home region session
                let session = self.getOrCreateNonHomeSession(regionID: targetRegion)
                session?.sendPacket(destKey: peerKey, data: data)
            }
        }
    }

    // MARK: - Status Queries

    /// Current effective home region ID.
    var currentHomeRegionID: Int {
        onQueue { self.effectiveHomeRegionID }
    }

    /// Whether the home DERP region connection is currently established and ready.
    var isHomeConnected: Bool {
        onQueue { self.homeSession?.state.isReady ?? false }
    }

    // MARK: - Home Region Management & Reconnection

    private func resolveEffectiveHomeRegion() {
        guard let map = derpMap else { return }

        if configuredHomeRegionID > 0, let explicitRegion = map.region(id: configuredHomeRegionID) {
            effectiveHomeRegionID = explicitRegion.regionID
            return
        }

        // Automatic selection: pick first available region in DERPMap order
        if let autoRegion = map.firstAvailableRegion {
            effectiveHomeRegionID = autoRegion.regionID
        } else if let first = map.sortedRegions.first {
            effectiveHomeRegionID = first.regionID
        } else {
            effectiveHomeRegionID = 0
        }
    }

    private func connectHome() {
        guard !isStopped, let map = derpMap, let key = nodeKey else { return }
        guard effectiveHomeRegionID > 0, let region = map.region(id: effectiveHomeRegionID) else { return }

        let nodes = region.usableNodes
        guard !nodes.isEmpty else { return }

        // Round-robin over usable nodes within the home region
        let node = nodes[homeNodeIndex % nodes.count]

        let session = NCDERPSession(
            regionID: effectiveHomeRegionID,
            isHome: true,
            node: node,
            nodeKey: key,
            queue: queue
        )
        homeSession = session

        session.onConnected = { [weak self, weak session] in
            guard let self = self, self.homeSession === session else { return }
            self.homeBackoffSeconds = Self.minBackoffSeconds
            self.onHomeStateChange?(true, self.effectiveHomeRegionID)
        }

        session.onClosed = { [weak self, weak session] _ in
            guard let self = self, self.homeSession === session else { return }
            self.homeSession = nil
            self.onHomeStateChange?(false, self.effectiveHomeRegionID)
            self.scheduleHomeReconnect()
        }

        session.onPacket = { [weak self] srcKey, packet in
            self?.onPacket?(srcKey, packet)
        }

        session.onPeerGone = { [weak self] peerKey, _ in
            self?.onPeerGone?(peerKey)
        }

        session.start()
    }

    private func scheduleHomeReconnect() {
        guard !isStopped, homeReconnectWorkItem == nil else { return }

        homeNodeIndex &+= 1
        let delay = homeBackoffSeconds
        homeBackoffSeconds = min(homeBackoffSeconds * 2.0, Self.maxBackoffSeconds)

        let item = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.homeReconnectWorkItem = nil
            self.connectHome()
        }
        homeReconnectWorkItem = item
        queue.asyncAfter(deadline: .now() + delay, execute: item)
    }

    private func reconnectHomeImmediately() {
        homeReconnectWorkItem?.cancel()
        homeReconnectWorkItem = nil

        if let old = homeSession {
            homeSession = nil
            old.close()
            onHomeStateChange?(false, effectiveHomeRegionID)
        }

        homeBackoffSeconds = Self.minBackoffSeconds
        connectHome()
    }

    // MARK: - On-Demand Non-Home Region Management

    private func getOrCreateNonHomeSession(regionID: Int) -> NCDERPSession? {
        if let existing = otherSessions[regionID] {
            return existing
        }

        guard let map = derpMap, let key = nodeKey,
              let region = map.region(id: regionID) else {
            return nil
        }

        let nodes = region.usableNodes
        guard let node = nodes.first else { return nil }

        let session = NCDERPSession(
            regionID: regionID,
            isHome: false,
            node: node,
            nodeKey: key,
            queue: queue
        )

        session.onPacket = { [weak self] srcKey, packet in
            self?.onPacket?(srcKey, packet)
        }

        session.onPeerGone = { [weak self] peerKey, _ in
            self?.onPeerGone?(peerKey)
        }

        session.onClosed = { [weak self, weak session] _ in
            guard let self = self else { return }
            if self.otherSessions[regionID] === session {
                self.otherSessions.removeValue(forKey: regionID)
            }
        }

        otherSessions[regionID] = session
        session.start()
        return session
    }

    // MARK: - Memory Governor: Idle Non-Home Session Pruning

    private func startIdleSweepTimer() {
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, !self.isStopped else { return }
            self.pruneIdleNonHomeSessions()
            self.startIdleSweepTimer()
        }
        idleSweepTimer = item
        queue.asyncAfter(deadline: .now() + 30.0, execute: item)
    }

    private func pruneIdleNonHomeSessions() {
        let now = Date()
        var toPrune = [Int]()

        for (regID, sess) in otherSessions {
            if now.timeIntervalSince(sess.lastActivity) > Self.nonHomeIdleTimeout {
                toPrune.append(regID)
            }
        }

        for regID in toPrune {
            if let sess = otherSessions.removeValue(forKey: regID) {
                sess.close()
            }
        }
    }
}
