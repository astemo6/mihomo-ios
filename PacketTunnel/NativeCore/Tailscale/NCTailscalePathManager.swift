import CryptoKit
import Foundation
import Network

// MARK: - disco path manager (phase 2: direct paths with DERP fallback)
//
// Owns the shared UDP socket and decides, per peer, whether WireGuard
// packets travel direct (UDP to a disco-discovered endpoint) or relayed
// (DERP, via the client's existing send path).
//
// Model (simplified magicsock):
// - Endpoints are learned from the netmap (Node.Endpoints), from disco
//   CallMeMaybe messages, and as sources of disco/WireGuard packets.
// - disco Pings probe candidates; the lowest-RTT endpoint that answered
//   becomes the direct path. Any packet received from a peer's endpoint
//   counts as liveness for that path.
// - If the direct path sees no inbound activity for `directExpiry`
//   seconds it is abandoned and traffic falls back to DERP, while a
//   CallMeMaybe over DERP (throttled) asks the peer to re-punch.
// - STUN rounds keep our own reflexive endpoint fresh; changes are
//   reported via onEndpointsChanged so the client re-issues the map
//   request with MapRequest.Endpoints. NWPathMonitor path changes force
//   a full re-probe (new STUN round, all peers back to DERP).

public final class NCTailscalePathManager {
    private static let pingInterval: TimeInterval = 25
    private static let directExpiry: TimeInterval = 45
    private static let callMeMaybeThrottle: TimeInterval = 10
    private static let activeTrafficWindow: TimeInterval = 120

    private let queue: DispatchQueue
    private let socket = NCTailscaleUDPSocket()

    private var discoPrivate: Curve25519.KeyAgreement.PrivateKey?
    private var discoPublic: Data?
    private var myNodeKey: Data?

    private struct PeerPath {
        var nodeKey: Data
        var discoKey: Data
        var candidates: [String] = []
        var bestEndpoint: String?
        var bestLatency: TimeInterval?
        var lastInbound: Date?          // any packet from bestEndpoint
        var lastTraffic: Date?          // last outbound WG packet
        var lastCallMeMaybe: Date?
        var pendingPings: [Data: (endpoint: String, sentAt: Date)] = [:]
        var usingDirect = false
    }

    private var peers: [Data: PeerPath] = [:]          // by node key
    private var nodeKeyByDisco: [Data: Data] = [:]
    private var nodeKeyByEndpoint: [String: Data] = [:]

    private var stunServers: [String] = []
    private var pendingSTUN: [Data: Bool] = [:]
    private var reflexiveEndpoints: [String] = []

    private var heartbeat: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String?

    // MARK: Callbacks into the client

    /// Attributed inbound WireGuard packet received on the direct path.
    public var onWGDirectPacket: ((Data, Data) -> Void)?
    /// Relay send (DERP) for WG payloads and disco-over-DERP messages.
    public var sendViaDERP: ((Data, Data) -> Void)?
    /// Our advertised endpoint set changed; re-issue the map request.
    public var onEndpointsChanged: (() -> Void)?
    /// A peer's direct/relay classification changed (status counts).
    public var onPathChanged: (() -> Void)?

    public init(queue: DispatchQueue) {
        self.queue = queue
    }

    // MARK: Lifecycle

    public func start(discoPrivate: Curve25519.KeyAgreement.PrivateKey, nodeKey: Data, derpMap: NCTailscaleDERPMap?) {
        self.discoPrivate = discoPrivate
        self.discoPublic = discoPrivate.publicKey.rawRepresentation
        self.myNodeKey = nodeKey
        socket.onPacket = { [weak self] data, src in
            self?.handleSocketPacket(data, from: src)
        }
        if !socket.isOpen {
            socket.start(queue: queue)
        }
        updateSTUNServers(derpMap: derpMap)
        runSTUNRound()
        startHeartbeat()
        startPathMonitor()
    }

    public func stop() {
        heartbeat?.cancel()
        heartbeat = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        socket.stop()
        peers.removeAll()
        nodeKeyByDisco.removeAll()
        nodeKeyByEndpoint.removeAll()
    }

    // MARK: Netmap-driven peer table

    public func updatePeers(nodes: [NCTailscaleNode]) {
        var seen = Set<Data>()
        for node in nodes {
            guard let nodeKeyBytes = NCTailscaleKeyEncoding.decodeKey(node.Key), nodeKeyBytes.count == 32,
                  let discoKeyBytes = node.DiscoKey.flatMap({ NCTailscaleKeyEncoding.decodeKey($0) }),
                  discoKeyBytes.count == 32 else { continue }
            let nodeKey = Data(nodeKeyBytes)
            let discoKey = Data(discoKeyBytes)
            seen.insert(nodeKey)
            nodeKeyByDisco[discoKey] = nodeKey
            var path = peers[nodeKey] ?? PeerPath(nodeKey: nodeKey, discoKey: discoKey)
            path.discoKey = discoKey
            for ep in node.Endpoints ?? [] where !path.candidates.contains(ep) {
                path.candidates.append(ep)
                nodeKeyByEndpoint[ep] = nodeKey
            }
            peers[nodeKey] = path
        }
        for key in peers.keys where !seen.contains(key) {
            peers.removeValue(forKey: key)
        }
    }

    public func updateDERPMap(_ derpMap: NCTailscaleDERPMap?) {
        updateSTUNServers(derpMap: derpMap)
    }

    // MARK: Advertised endpoints

    public func currentEndpoints() -> [String] {
        var out = reflexiveEndpoints
        for ep in socket.localEndpoints() where !out.contains(ep) {
            out.append(ep)
        }
        return out
    }

    public var directPeerCount: Int {
        peers.values.filter { $0.usingDirect }.count
    }

    // MARK: Sending WG packets

    public func send(nodeKey: Data, packet: Data) {
        guard var path = peers[nodeKey] else {
            sendViaDERP?(nodeKey, packet)
            return
        }
        path.lastTraffic = Date()
        peers[nodeKey] = path
        if path.usingDirect, let ep = path.bestEndpoint {
            socket.send(packet, to: ep)
            return
        }
        sendViaDERP?(nodeKey, packet)
        // Try to establish a direct path in the background.
        maybeInitiateDirect(&path)
    }

    private func maybeInitiateDirect(_ path: inout PeerPath) {
        let now = Date()
        if let last = path.lastCallMeMaybe, now.timeIntervalSince(last) < Self.callMeMaybeThrottle {
            peers[path.nodeKey] = path
            return
        }
        path.lastCallMeMaybe = now
        peers[path.nodeKey] = path
        // Ask the peer (over DERP) to punch toward our endpoints, and probe
        // its known endpoints directly at the same time.
        if let discoPrivate, let discoPublic,
           let packet = NCTailscaleDisco.seal(
               .callMeMaybe(endpoints: currentEndpoints()),
               senderPrivate: discoPrivate, senderPublic: discoPublic,
               recipientPublic: path.discoKey) {
            sendViaDERP?(path.nodeKey, packet)
        }
        for ep in path.candidates {
            sendPing(to: path, endpoint: ep)
        }
    }

    // MARK: Receiving

    /// Demultiplexes a packet that arrived over DERP. Returns true when it
    /// was a disco message (consumed); false means it is a WG packet.
    public func handleDERPPacket(_ data: Data, fromNodeKey: Data) -> Bool {
        guard NCTailscaleDisco.isDisco(data) else { return false }
        handleDisco(data, fromNodeKey: fromNodeKey, sourceEndpoint: nil)
        return true
    }

    private func handleSocketPacket(_ data: Data, from src: String) {
        let bytes = [UInt8](data)
        if NCTailscaleSTUN.isSTUNResponse(bytes) {
            for txid in Array(pendingSTUN.keys) {
                if let ep = NCTailscaleSTUN.parseBindingResponse(bytes, txid: [UInt8](txid)) {
                    pendingSTUN.removeValue(forKey: txid)
                    if !reflexiveEndpoints.contains(ep) {
                        reflexiveEndpoints = [ep]
                        onEndpointsChanged?()
                    }
                    return
                }
            }
            return
        }
        if NCTailscaleDisco.isDisco(data) {
            handleDisco(data, fromNodeKey: nil, sourceEndpoint: src)
            return
        }
        // WireGuard packet: attribute by source endpoint.
        if let nodeKey = nodeKeyByEndpoint[src] {
            noteInbound(nodeKey: nodeKey, endpoint: src)
            onWGDirectPacket?(nodeKey, data)
        }
        // Unattributed direct packets are dropped: without a disco-learned
        // or netmap-advertised endpoint we cannot know which peer sent
        // them, and the WG layer would reject them anyway.
    }

    private func handleDisco(_ data: Data, fromNodeKey: Data?, sourceEndpoint: String?) {
        guard let discoPrivate,
              let (senderDisco, message) = NCTailscaleDisco.open(data, recipientPrivate: discoPrivate)
        else { return }
        let senderNode = fromNodeKey ?? nodeKeyByDisco[senderDisco]
        guard let nodeKey = senderNode, var path = peers[nodeKey] else { return }

        switch message {
        case .ping(let txid, _):
            if let ep = sourceEndpoint {
                learnEndpoint(&path, endpoint: ep)
            }
            // Pong goes back over the channel the ping arrived on.
            let pong = NCTailscaleDisco.Message.pong(txid: txid, src: sourceEndpoint ?? currentEndpoints().first ?? "")
            if let discoPublic,
               let packet = NCTailscaleDisco.seal(pong, senderPrivate: discoPrivate,
                                                  senderPublic: discoPublic,
                                                  recipientPublic: path.discoKey) {
                if let ep = sourceEndpoint {
                    socket.send(packet, to: ep)
                } else {
                    sendViaDERP?(nodeKey, packet)
                }
            }
            peers[nodeKey] = path

        case .pong(let txid, _):
            guard let pending = path.pendingPings[txid] else { return }
            path.pendingPings.removeValue(forKey: txid)
            let rtt = Date().timeIntervalSince(pending.sentAt)
            if path.bestLatency == nil || rtt <= (path.bestLatency ?? .infinity)
                || path.bestEndpoint == pending.endpoint {
                path.bestLatency = rtt
                path.bestEndpoint = pending.endpoint
            }
            if let ep = sourceEndpoint { learnEndpoint(&path, endpoint: ep) }
            setDirect(&path, true)
            path.lastInbound = Date()
            peers[nodeKey] = path

        case .callMeMaybe(let endpoints):
            for ep in endpoints { learnEndpoint(&path, endpoint: ep) }
            peers[nodeKey] = path
            // Punch back immediately: ping every advertised endpoint.
            for ep in endpoints {
                sendPing(to: path, endpoint: ep)
            }
        }
    }

    // MARK: Path bookkeeping

    private func learnEndpoint(_ path: inout PeerPath, endpoint: String) {
        if !path.candidates.contains(endpoint) {
            path.candidates.append(endpoint)
        }
        nodeKeyByEndpoint[endpoint] = path.nodeKey
    }

    private func noteInbound(nodeKey: Data, endpoint: String) {
        guard var path = peers[nodeKey] else { return }
        learnEndpoint(&path, endpoint: endpoint)
        if path.bestEndpoint == nil { path.bestEndpoint = endpoint }
        if endpoint == path.bestEndpoint {
            path.lastInbound = Date()
            setDirect(&path, true)
        }
        peers[nodeKey] = path
    }

    private func setDirect(_ path: inout PeerPath, _ direct: Bool) {
        if path.usingDirect != direct {
            path.usingDirect = direct
            onPathChanged?()
        }
    }

    private func sendPing(to path: PeerPath, endpoint: String) {
        guard let discoPrivate, let discoPublic else { return }
        let txid = NCTailscaleDiscoRandom.data(count: 12)
        var updated = path
        updated.pendingPings[txid] = (endpoint, Date())
        peers[path.nodeKey] = updated
        if let packet = NCTailscaleDisco.seal(
            .ping(txid: txid, nodeKey: myNodeKey),
            senderPrivate: discoPrivate, senderPublic: discoPublic,
            recipientPublic: path.discoKey) {
            socket.send(packet, to: endpoint)
        }
    }

    // MARK: STUN

    private func updateSTUNServers(derpMap: NCTailscaleDERPMap?) {
        guard let derpMap else { return }
        var servers: [String] = []
        for region in derpMap.sortedRegions {
            for node in region.nodes where node.stunPort != nil || node.stunOnly == true {
                // Prefer the node's advertised IPv4 (no DNS needed); fall
                // back to its hostname, resolved at probe time.
                let host = node.ipv4 ?? node.hostName
                let port = node.stunPort ?? NCTailscaleSTUN.defaultPort
                if !host.isEmpty { servers.append("\(host):\(port)") }
            }
        }
        stunServers = Array(servers.prefix(4))
    }

    private func runSTUNRound() {
        guard !stunServers.isEmpty else { return }
        for server in stunServers {
            let (packet, txid) = NCTailscaleSTUN.makeBindingRequest()
            pendingSTUN[Data(txid)] = true
            if NCTailscaleDisco.parseEndpoint(server) != nil {
                socket.send(Data(packet), to: server)
                continue
            }
            // Hostname server (the common case for official DERP): resolve
            // off-queue, then send from the manager queue.
            guard let (host, port) = Self.splitHostPort(server) else { continue }
            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self, let ip = Self.resolveFirstIP(host) else { return }
                self.queue.async {
                    let endpoint = ip.contains(":") ? "[\(ip)]:\(port)" : "\(ip):\(port)"
                    self.socket.send(Data(packet), to: endpoint)
                }
            }
        }
    }

    private static func splitHostPort(_ s: String) -> (String, UInt16)? {
        if let parsed = NCTailscaleDisco.parseEndpoint(s) {
            return (parsed.0.string, parsed.1)
        }
        guard let colon = s.lastIndex(of: ":") else { return nil }
        let host = String(s[..<colon])
        guard let port = UInt16(s[s.index(after: colon)...]) else { return nil }
        return (host, port)
    }

    private static func resolveFirstIP(_ host: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(first) }
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let cur = node {
            if let sa = cur.pointee.ai_addr {
                var storage = sockaddr_storage()
                memcpy(&storage, sa, Int(cur.pointee.ai_addrlen))
                if let ep = NCTailscaleUDPSocket.endpointString(from: storage) {
                    // strip the :0 port suffix endpointString adds
                    if let parsed = NCTailscaleDisco.parseEndpoint(ep) {
                        return parsed.0.string
                    }
                    return ep
                }
            }
            node = cur.pointee.ai_next
        }
        return nil
    }

    // MARK: Heartbeat & network changes

    private func startHeartbeat() {
        heartbeat?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
        heartbeat = timer
    }

    private func tick() {
        let now = Date()
        // Iterate a snapshot: the helpers below write back into `peers`.
        for (key, var path) in Array(peers) {
            // Expire stale direct paths.
            if path.usingDirect {
                let last = path.lastInbound ?? .distantPast
                if now.timeIntervalSince(last) > Self.directExpiry {
                    setDirect(&path, false)
                    path.bestLatency = nil
                    peers[key] = path
                    maybeInitiateDirect(&path)
                    continue
                }
            }
            // Keep NAT mappings warm for peers with recent traffic.
            let active = path.lastTraffic.map { now.timeIntervalSince($0) < Self.activeTrafficWindow } ?? false
            if active || path.usingDirect {
                if let ep = path.bestEndpoint ?? path.candidates.first {
                    // Throttle pings to the global ping cadence by checking
                    // the oldest outstanding ping time.
                    let lastPing = path.pendingPings.values.map(\.sentAt).max()
                    if lastPing == nil || now.timeIntervalSince(lastPing!) > Self.pingInterval {
                        sendPing(to: path, endpoint: ep)
                    }
                } else if !path.usingDirect {
                    maybeInitiateDirect(&path)
                }
            }
        }
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let signature = path.availableInterfaces.map { "\($0.name)" }.joined(separator: ",")
            self.queue.async {
                if let last = self.lastPathSignature, last != signature {
                    // Network changed: re-probe everything.
                    for (key, var p) in self.peers {
                        self.setDirect(&p, false)
                        p.bestLatency = nil
                        p.lastInbound = nil
                        self.peers[key] = p
                    }
                    self.reflexiveEndpoints = []
                    self.runSTUNRound()
                    self.onEndpointsChanged?()
                }
                self.lastPathSignature = signature
            }
        }
        monitor.start(queue: queue)
    }
}
