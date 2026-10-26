import CryptoKit
import Foundation
import Network

// MARK: - Tailscale Node Orchestrator & Client
//
// Manages the complete lifecycle of one Tailscale node inside the Network Extension:
// 1. Singleton/Cached instance per node name + state directory.
// 2. Memory guard on startup (< 14 MB available refuses with localized error).
// 3. Periodic memory watchdog (< 5 MB available stops client and tears down device).
// 4. Coordinates S2 Control Client (ts2021 + register + long polling netmap).
// 5. Coordinates S3a DERP Client (home region + multi-region relay).
// 6. Configures and drives NCWGDevice userspace WireGuard / lwIP network interface.
// 7. Manages packet routing: WG output -> DERP sendPacket; DERP onPacket -> WG input.
// 8. Performs inbound AllowedIPs filtering.
// 9. Dials TCP streams via userspace lwIP stack for destinations inside tailnet routes.
// 10. Persists status.json and exports guard status snapshot for memoryStats & tailscaleInfo.

final class NCTailscaleClient {
    // MARK: - Instance Cache

    private static let cacheLock = NSLock()
    private static var cachedClients: [String: NCTailscaleClient] = [:]

    /// Returns the cached client for `proxy`, or initializes a new one.
    static func client(for proxy: NCProxy) -> NCTailscaleClient? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return clientUnlocked(for: proxy)
    }

    private static func clientUnlocked(for proxy: NCProxy) -> NCTailscaleClient? {
        let name = proxy.name
        let rawStateDir = proxy.fields["state-dir"]?.string ?? ""
        let stateDir = rawStateDir.isEmpty ? defaultStateDir(name: name) : rawStateDir
        let cacheKey = "\(name):\(stateDir)"

        if let existing = cachedClients[cacheKey] {
            return existing
        }

        let homePath = AppShared.homeURL.path
        guard let stateDirURL = try? NCTailscalePath.resolveStateDir(home: homePath, stateDir: stateDir) else {
            return nil
        }

        let client = NCTailscaleClient(
            proxy: proxy,
            name: name,
            stateDir: stateDir,
            stateDirURL: stateDirURL,
            homePath: homePath
        )
        cachedClients[cacheKey] = client
        return client
    }

    /// Returns all managed Tailscale clients, discovering any configured nodes from the loaded engine.
    static func allClients() -> [NCTailscaleClient] {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        if let proxies = NativeTunnelCore.shared.engine?.withGroups({ cfg, _ in
            cfg.proxies.filter { $0.type.lowercased() == "tailscale" }
        }) {
            for p in proxies {
                _ = clientUnlocked(for: p)
            }
        }

        return Array(cachedClients.values)
    }

    /// Stops all running Tailscale clients and cleans up resources.
    static func stopAll() {
        let clients = allClients()
        for client in clients {
            client.stop()
        }
    }

    /// bridge tailscaleStateDir default calculation: "tailscale/<sanitized>-<sha1_8>".
    private static func defaultStateDir(name: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data(name.utf8))
        let hash8 = digest.ncHex.prefix(8)
        var base = ""
        var inUnsafeRun = false
        for ch in name {
            if ch.isASCII && (ch.isLetter || ch.isNumber || ch == "." || ch == "_" || ch == "-") {
                base.append(ch)
                inUnsafeRun = false
            } else if !inUnsafeRun {
                base.append("_")
                inUnsafeRun = true
            }
        }
        base = base.trimmingCharacters(in: CharacterSet(charactersIn: "_."))
        if base.count > 24 { base = String(base.prefix(24)) }
        if base.isEmpty { base = "node" }
        return "tailscale/" + base + "-" + hash8
    }

    // MARK: - Properties

    let proxy: NCProxy
    let name: String
    let stateDir: String
    let stateDirURL: URL
    let homePath: String
    let queue: DispatchQueue

    // Subsystems
    let control: NCTailscaleControl
    let derp: NCTailscaleDERPClient
    private(set) var device: NCWGDevice?

    // Phase 3: routing policy, MagicDNS, PacketFilter state
    let routeConfig: NCTailscaleRouteConfig
    let magicDNS = NCTailscaleMagicDNS()
    private(set) var routingError: String?
    private var packetFilterRules: [NCTailscalePacketFilterRule]?
    private var dnsProviderInstalled = false

    private func currentPacketFilterRules() -> [NCTailscalePacketFilterRule]? {
        clientLock.lock()
        defer { clientLock.unlock() }
        return packetFilterRules
    }
    // Phase 2: disco direct-path manager (created on first netmap snapshot)
    private(set) var pathManager: NCTailscalePathManager?

    // Threading & State Locks
    private let clientLock = NSLock()
    private var peerRegionMap: [Data: Int] = [:]
    private var pendingDialCompletions: [(Error?) -> Void] = []
    private var watchdogTimer: DispatchSourceTimer?
    private var isStarting = false

    // Observability & Guard Metrics (TailscaleGuardStatus shape)
    private(set) var state: String = NCTailscaleLoginState.idle.rawValue
    private(set) var startedAt: Int64?
    private(set) var footprintBefore: Int64?
    private(set) var availableBefore: Int64?
    private(set) var footprintAfter: Int64?
    private(set) var startMillis: Int64?
    private(set) var peakSinceStart: Int64?
    private(set) var refusedAvailable: Int64?
    private(set) var refusedAt: Int64?
    private(set) var stoppedAvailable: Int64?
    private(set) var stoppedAt: Int64?
    private(set) var lastError: String?
    private(set) var authURL: String?
    private(set) var ipv4: String?
    private(set) var ipv6: String?
    private(set) var derpHomeRegion: Int?
    private(set) var peerCounts: NCTailscalePeerCounts = NCTailscalePeerCounts()

    // MARK: - Initialization

    private init(proxy: NCProxy, name: String, stateDir: String, stateDirURL: URL, homePath: String) {
        self.proxy = proxy
        self.name = name
        self.stateDir = stateDir
        self.stateDirURL = stateDirURL
        self.homePath = homePath
        let q = DispatchQueue(label: "com.tern.tailscale.client.\(name)")
        self.queue = q

        let controlURL = proxy.fields["control-url"]?.string ?? proxy.server ?? ""
        let authKey = proxy.fields["auth-key"]?.string ?? proxy.password
        let hostname = proxy.fields["hostname"]?.string ?? "mihomo-ios"
        let ephemeral = proxy.fields["ephemeral"]?.bool ?? false

        let controlConfig = NCTailscaleControlConfig(
            name: name,
            controlURL: controlURL,
            authKey: authKey,
            hostname: hostname,
            stateDir: stateDir,
            homePath: homePath,
            ephemeral: ephemeral,
            queue: q
        )
        self.control = NCTailscaleControl(config: controlConfig)
        self.derp = NCTailscaleDERPClient(queue: q)
        self.routeConfig = NCTailscaleRouteConfig(proxy: proxy)

        // Attempt loading prior state if present
        if let saved = NCTailscaleStatusStore.load(stateDirURL: stateDirURL) {
            self.ipv4 = saved.ipv4
            self.ipv6 = saved.ipv6
            self.derpHomeRegion = saved.derpHomeRegion
            self.peerCounts = saved.peerCounts
            self.authURL = saved.authURL
        }
    }

    // MARK: - Lifecycle & Memory Guard

    /// Lazily starts the Tailscale client (called on first dial).
    func startIfNeeded(completion: @escaping (Error?) -> Void) {
        clientLock.lock()
        if state == NCTailscaleLoginState.started.rawValue && device?.alive == true {
            clientLock.unlock()
            completion(nil)
            return
        }
        if state == NCTailscaleLoginState.refused.rawValue {
            let err = lastError ?? NCTailscaleConsts.refusalErrorMessage(availableBytes: refusedAvailable ?? 0)
            clientLock.unlock()
            completion(NCConnector.Failure.handshake(err))
            return
        }
        if state == NCTailscaleLoginState.stopped.rawValue {
            let err = lastError ?? NCTailscaleConsts.stopErrorMessage(availableBytes: stoppedAvailable ?? 0)
            clientLock.unlock()
            completion(NCConnector.Failure.handshake(err))
            return
        }
        if isStarting {
            pendingDialCompletions.append(completion)
            clientLock.unlock()
            return
        }
        isStarting = true
        pendingDialCompletions.append(completion)
        clientLock.unlock()

        // 1. Guard check: Available memory BEFORE start
        let avail = Int64(ProcessMemory.availableBytes())
        let fp = Int64(ProcessMemory.footprintBytes())
        if avail < NCTailscaleConsts.minAvailableToStart {
            clientLock.lock()
            refusedAvailable = avail
            refusedAt = Int64(Date().timeIntervalSince1970)
            state = NCTailscaleLoginState.refused.rawValue
            let errStr = NCTailscaleConsts.refusalErrorMessage(availableBytes: avail)
            lastError = errStr
            isStarting = false
            let waiters = pendingDialCompletions
            pendingDialCompletions.removeAll()
            clientLock.unlock()

            writeStatusFile()
            let err = NCConnector.Failure.handshake(errStr)
            waiters.forEach { $0(err) }
            return
        }

        // 2. Record starting footprint & available
        let startBegan = Date()
        clientLock.lock()
        footprintBefore = fp
        availableBefore = avail
        peakSinceStart = fp
        state = NCTailscaleLoginState.starting.rawValue
        lastError = nil
        clientLock.unlock()
        writeStatusFile()

        // 3. Start periodic memory watchdog (2-second interval)
        startWatchdog()

        // 4. Hook control plane callbacks and start control client
        control.onSnapshotChanged = { [weak self] snapshot in
            self?.handleSnapshotChanged(snapshot)
        }
        control.onStatusChanged = { [weak self] statusFile in
            self?.handleControlStatusChanged(statusFile)
        }
        control.endpointsProvider = { [weak self] in
            self?.pathManager?.currentEndpoints() ?? []
        }

        control.start()

        // 5. Record footprint after startup trigger
        let fpAfter = Int64(ProcessMemory.footprintBytes())
        clientLock.lock()
        footprintAfter = fpAfter
        peakSinceStart = max(peakSinceStart ?? 0, fpAfter)
        startMillis = Int64(Date().timeIntervalSince(startBegan) * 1000)
        startedAt = Int64(startBegan.timeIntervalSince1970)
        clientLock.unlock()
    }

    private func startWatchdog() {
        watchdogTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + NCTailscaleConsts.watchdogInterval, repeating: NCTailscaleConsts.watchdogInterval)
        timer.setEventHandler { [weak self] in
            self?.checkMemoryWatchdog()
        }
        timer.resume()
        watchdogTimer = timer
    }

    private func checkMemoryWatchdog() {
        let curAvail = Int64(ProcessMemory.availableBytes())
        let curFP = Int64(ProcessMemory.footprintBytes())
        clientLock.lock()
        peakSinceStart = max(peakSinceStart ?? 0, curFP)
        if curAvail < NCTailscaleConsts.stopBelowAvailable {
            clientLock.unlock()
            stopDueToMemory(availableBytes: curAvail)
        } else {
            clientLock.unlock()
        }
    }

    private func stopDueToMemory(availableBytes: Int64) {
        clientLock.lock()
        stoppedAvailable = availableBytes
        stoppedAt = Int64(Date().timeIntervalSince1970)
        state = NCTailscaleLoginState.stopped.rawValue
        let errStr = NCTailscaleConsts.stopErrorMessage(availableBytes: availableBytes)
        lastError = errStr
        clientLock.unlock()

        stopInternal()
        writeStatusFile()
    }

    func stop() {
        clientLock.lock()
        state = NCTailscaleLoginState.stopped.rawValue
        clientLock.unlock()

        stopInternal()
        writeStatusFile()
    }

    private func installDNSProviderIfNeeded() {
        guard !dnsProviderInstalled else { return }
        dnsProviderInstalled = true
        NCDNSPolicy.tailscaleHostsProvider = { [weak self] name in
            self?.magicDNS.lookup(name) ?? []
        }
    }

    private func stopInternal() {
        watchdogTimer?.cancel()
        watchdogTimer = nil
        if dnsProviderInstalled {
            dnsProviderInstalled = false
            NCDNSPolicy.tailscaleHostsProvider = nil
        }
        pathManager?.stop()
        pathManager = nil
        control.stop()
        derp.stop()
        NCLwIP.queue.async { [weak self] in
            guard let self, let dev = self.device else { return }
            NCWGStack.shared.unregisterDevice(dev)
            dev.teardown()
            self.device = nil
        }
    }

    // MARK: - Control Plane & Netmap Coordination

    private func handleControlStatusChanged(_ statusFile: NCTailscaleStatusFile) {
        clientLock.lock()
        if statusFile.state == NCTailscaleLoginState.needsLogin.rawValue {
            self.state = NCTailscaleLoginState.needsLogin.rawValue
            self.authURL = statusFile.authURL
        } else if statusFile.state == NCTailscaleLoginState.failed.rawValue {
            self.state = NCTailscaleLoginState.failed.rawValue
            self.lastError = statusFile.lastError
            let waiters = self.pendingDialCompletions
            self.pendingDialCompletions.removeAll()
            self.isStarting = false
            clientLock.unlock()
            writeStatusFile()
            waiters.forEach { $0(NCConnector.Failure.handshake(statusFile.lastError ?? "Tailscale 控制面连接失败")) }
            return
        }
        clientLock.unlock()
        writeStatusFile()
    }

    private func handleSnapshotChanged(_ snapshot: NCTailscaleNetmapSnapshot) {
        clientLock.lock()
        ipv4 = snapshot.tailnetIPv4
        ipv6 = snapshot.tailnetIPv6

        // Resolve home region: prefer selfNode.derpRegionID, then snapshot.derpHomeRegion, then first available in DERPMap
        let homeRegion = snapshot.selfNode?.derpRegionID
            ?? snapshot.derpHomeRegion
            ?? snapshot.derpMap?.firstAvailableRegion?.regionID
            ?? snapshot.derpMap?.sortedRegions.first?.regionID
            ?? 0
        derpHomeRegion = homeRegion

        // Tailnet Lock detection heuristic:
        // When Tailnet Lock is active, nodes without a valid TKA signature or authorization cannot participate.
        if snapshot.selfNode?.MachineAuthorized == false {
            state = NCTailscaleLoginState.failed.rawValue
            lastError = "Tailscale 节点未获得 Tailnet Lock 授权（机器未通过管理员验证）"
            let waiters = pendingDialCompletions
            pendingDialCompletions.removeAll()
            isStarting = false
            clientLock.unlock()
            writeStatusFile()
            waiters.forEach { $0(NCConnector.Failure.handshake(self.lastError ?? "Tailnet Lock 未通过")) }
            return
        }

        clientLock.unlock()

        // Start or update DERP client
        guard let nodeKey = control.keys?.nodeKey else { return }
        if let derpMap = snapshot.derpMap {
            if !derp.isHomeConnected && derp.currentHomeRegionID == 0 {
                derp.onPacket = { [weak self] srcPubkey, wgPacket in
                    guard let self else { return }
                    if let pm = self.pathManager,
                       pm.handleDERPPacket(wgPacket, fromNodeKey: srcPubkey) {
                        return // disco message consumed by the path manager
                    }
                    self.handleDERPPacket(srcPubkey: srcPubkey, packet: wgPacket)
                }
                derp.onHomeStateChange = { [weak self] connected, region in
                    self?.handleDERPHomeChange(connected: connected, region: region)
                }
                derp.start(derpMap: derpMap, homeRegionID: homeRegion, nodeKey: nodeKey)
            } else {
                derp.updateDERPMap(derpMap)
            }
        }

        // Phase 3: MagicDNS table, PacketFilter rules, exit-node resolution
        magicDNS.rebuild(snapshot: snapshot)
        installDNSProviderIfNeeded()
        let exitPeerKey: Data?
        if let query = routeConfig.exitNodeQuery {
            if let exitNode = NCTailscaleRouting.resolveExitNode(query: query, peers: Array(snapshot.peers.values)),
               let keyBytes = NCTailscaleKeyEncoding.decodeKey(exitNode.Key), keyBytes.count == 32 {
                exitPeerKey = Data(keyBytes)
                clientLock.lock(); routingError = nil; clientLock.unlock()
            } else {
                exitPeerKey = nil
                clientLock.lock()
                routingError = "Tailscale 出口节点「\(query)」在当前 tailnet 中未找到，已按无出口节点运行"
                clientLock.unlock()
            }
        } else {
            exitPeerKey = nil
        }
        clientLock.lock()
        packetFilterRules = snapshot.packetFilter
        clientLock.unlock()
        // Phase 2: disco path manager (direct paths with DERP fallback)
        if let keys = control.keys {
            let pm: NCTailscalePathManager
            if let existing = pathManager {
                pm = existing
                pm.updateDERPMap(snapshot.derpMap)
            } else {
                pm = NCTailscalePathManager(queue: queue)
                pm.sendViaDERP = { [weak self] nodeKey, data in
                    self?.sendPacketViaDERP(peerKey: [UInt8](nodeKey), data: [UInt8](data))
                }
                pm.onWGDirectPacket = { [weak self] nodeKey, data in
                    self?.handleDERPPacket(srcPubkey: nodeKey, packet: data)
                }
                pm.onEndpointsChanged = { [weak self] in
                    self?.control.refreshEndpoints()
                }
                pm.onPathChanged = { [weak self] in
                    self?.writeStatusFile()
                }
                pathManager = pm
                pm.start(discoPrivate: keys.discoKey,
                         nodeKey: Data(keys.nodeKey.publicKey.rawRepresentation),
                         derpMap: snapshot.derpMap)
            }
            pm.updatePeers(nodes: Array(snapshot.peers.values))
        }

        // Build peer list from netmap
        var newPeers: [NCWGConfig.Peer] = []
        var newRegionMap: [Data: Int] = [:]
        for peerNode in snapshot.peers.values {
            guard let pubKeyBytes = NCTailscaleKeyEncoding.decodeKey(peerNode.Key), pubKeyBytes.count == 32 else {
                continue
            }
            let keyData = Data(pubKeyBytes)
            let pRegion = peerNode.derpRegionID ?? homeRegion
            newRegionMap[keyData] = pRegion
            let effective = NCTailscaleRouting.effectiveAllowedIPs(
                for: peerNode, isExitNode: exitPeerKey == keyData, config: routeConfig)
            let cidrs = effective.compactMap { NCCIDR($0.trimmingCharacters(in: .whitespaces)) }
            guard !cidrs.isEmpty else { continue }
            newPeers.append(NCWGConfig.Peer(
                server: "",
                port: 0,
                publicKey: pubKeyBytes,
                preSharedKey: [UInt8](repeating: 0, count: 32),
                reserved: nil,
                allowed: cidrs
            ))
        }

        clientLock.lock()
        peerRegionMap = newRegionMap
        clientLock.unlock()

        // Configure or update NCWGDevice on NCLwIP.queue
        NCLwIP.queue.async { [weak self] in
            guard let self else { return }
            if let dev = self.device, dev.alive {
                dev.updatePeers(newPeers) { [weak self] peer, rawBytes in
                    self?.sendPacketViaPath(peerKey: peer.cfg.publicKey, data: rawBytes)
                }
            } else {
                let wgCfg = NCWGConfig(
                    privateKey: [UInt8](nodeKey.rawRepresentation),
                    ip4: snapshot.tailnetIPv4,
                    ip6: snapshot.tailnetIPv6,
                    mtu: 1280,
                    keepalive: 25,
                    peers: newPeers,
                    dns: [],
                    remoteDNS: false,
                    amnezia: nil
                )
                guard let dev = NCWGDevice(key: self.name, name: self.name, cfg: wgCfg) else {
                    self.clientLock.lock()
                    self.state = NCTailscaleLoginState.failed.rawValue
                    self.lastError = "Tailscale WireGuard 接口创建失败（lwIP netif）"
                    let waiters = self.pendingDialCompletions
                    self.pendingDialCompletions.removeAll()
                    self.isStarting = false
                    self.clientLock.unlock()
                    self.writeStatusFile()
                    waiters.forEach { $0(NCConnector.Failure.handshake("WireGuard 接口创建失败")) }
                    return
                }
                NCWGStack.shared.registerDevice(dev)
                for p in dev.peers {
                    p.customSender = { [weak self, weak p] bytes in
                        guard let self, let p else { return }
                        self.sendPacketViaPath(peerKey: p.cfg.publicKey, data: bytes)
                    }
                }
                self.device = dev
            }

            // Phase 3: enforce the netmap PacketFilter on inbound packets
            if let dev = self.device {
                dev.inboundPacketHook = { [weak self] pkt in
                    guard let self else { return true }
                    return NCTailscalePacketFilter.allows(packet: pkt, rules: self.currentPacketFilterRules())
                }
            }

            self.clientLock.lock()
            self.state = NCTailscaleLoginState.started.rawValue
            self.isStarting = false
            let waiters = self.pendingDialCompletions
            self.pendingDialCompletions.removeAll()
            self.clientLock.unlock()

            self.writeStatusFile()
            waiters.forEach { $0(nil) }
        }
    }

    // MARK: - Packet Routing (WG <-> DERP)

    /// WG device output: direct disco path when one is live, else DERP relay.
    private func sendPacketViaPath(peerKey: [UInt8], data: [UInt8]) {
        if let pm = pathManager {
            pm.send(nodeKey: Data(peerKey), packet: Data(data))
        } else {
            sendPacketViaDERP(peerKey: peerKey, data: data)
        }
    }

    /// WG device output -> DERP sendPacket.
    private func sendPacketViaDERP(peerKey: [UInt8], data: [UInt8]) {
        let keyData = Data(peerKey)
        clientLock.lock()
        let regionID = peerRegionMap[keyData] ?? derpHomeRegion ?? 0
        clientLock.unlock()
        derp.sendPacket(to: keyData, regionID: regionID, data: Data(data))
    }

    /// DERP onPacket -> WG device input.
    /// Minimum inbound filter: packets whose decrypted source IP is not in the peer's AllowedIPs
    /// are dropped inside NCWGDevice.input.
    private func handleDERPPacket(srcPubkey: Data, packet: Data) {
        let pubKeyBytes = [UInt8](srcPubkey)
        let packetBytes = [UInt8](packet)
        NCLwIP.queue.async { [weak self] in
            guard let self, let dev = self.device, dev.alive else { return }
            dev.handleIncomingPacket(from: pubKeyBytes, data: packetBytes)
        }
    }

    private func handleDERPHomeChange(connected: Bool, region: Int) {
        clientLock.lock()
        derpHomeRegion = region
        clientLock.unlock()
        writeStatusFile()
    }

    // MARK: - Dial (Connector Integration)

    /// Static entrypoint invoked by `NCConnector.tailscaleDialer`.
    static func dial(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                            completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let client = client(for: proxy) else {
            queue.async {
                completion(nil, NCConnector.Failure.unsupported("Tailscale 节点「\(proxy.name)」客户端初始化失败"))
            }
            return
        }
        client.dial(target: target, queue: queue, completion: completion)
    }

    /// Dials a destination target through the Tailscale node's userspace lwIP stack.
    func dial(target: NCTarget, queue: DispatchQueue,
                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        startIfNeeded { [weak self] err in
            if let err {
                queue.async { completion(nil, err) }
                return
            }
            guard let self else {
                queue.async { completion(nil, NCConnector.Failure.handshake("Tailscale client deallocated")) }
                return
            }

            NCLwIP.queue.async {
                guard let dev = self.device, dev.alive else {
                    queue.async { completion(nil, NCConnector.Failure.handshake("Tailscale WireGuard device unavailable")) }
                    return
                }

                dev.retain()
                let proceed: ([NCIP]) -> Void = { ips in
                    guard dev.alive else {
                        dev.release()
                        queue.async { completion(nil, NCConnector.Failure.handshake("Tailscale device closed during resolve")) }
                        return
                    }

                    // Cryptokey routing check: target IP must match a peer's
                    // effective AllowedIPs (phase-3 routing policy included)
                    var matchedIP: NCIP?
                    for ip in ips {
                        if dev.peer(for: ip) != nil {
                            matchedIP = ip
                            break
                        }
                    }

                    guard let targetIP = matchedIP else {
                        dev.release()
                        let msg = self.dialRouteError(target: target, candidates: ips)
                        queue.async { completion(nil, NCConnector.Failure.handshake(msg)) }
                        return
                    }

                    // Open TCP stream via userspace lwIP PCB
                    let s = NCWGTCPStream(device: dev, callerQueue: queue)
                    s.start(ip: targetIP, port: target.port) { err in
                        completion(err == nil ? s : nil, err)
                    }
                }

                // MagicDNS first: tailnet names resolve from the netmap
                // table without a DNS round-trip
                let magic = self.magicDNS.lookup(target.host)
                if !magic.isEmpty {
                    proceed(magic)
                } else {
                    dev.resolve(target.host) { ips in proceed(ips) }
                }
            }
        }
    }

    /// Explains why a dial target has no route, preferring the most
    /// specific cause: unresolved exit node, LAN carved out of the exit
    /// route by allow-lan-access, or an unknown tailnet name.
    private func dialRouteError(target: NCTarget, candidates: [NCIP]) -> String {
        clientLock.lock()
        let rErr = routingError
        clientLock.unlock()
        if let rErr { return rErr }
        if routeConfig.exitNodeQuery != nil, routeConfig.allowLanAccess,
           candidates.contains(where: { NCTailscaleRouting.isLANOrTailnet($0) }) {
            return "目标 \(target.host) 是局域网/tailnet 地址：按 exit-node-allow-lan-access 不经出口节点转发，且没有子网路由覆盖它"
        }
        if magicDNS.isTailnetName(target.host) {
            return "目标 \(target.host) 是 tailnet 名称，但当前 netmap 中没有这台设备"
        }
        return "目标 \(target.host) 不在 tailnet 路由内"
    }

    // MARK: - Status File Persistence

    private func writeStatusFile() {
        clientLock.lock()
        let curState = state
        let curAuthURL = authURL
        let curIPv4 = ipv4
        let curIPv6 = ipv6
        let curRegion = derpHomeRegion
        let curError = lastError
        let totalPeers = control.currentSnapshot.peers.count
        clientLock.unlock()

        let sessions = device?.activeRelayCount ?? 0
        let directPeers = pathManager?.directPeerCount ?? 0
        let counts = NCTailscalePeerCounts(total: totalPeers, direct: directPeers,
                                           relay: max(0, sessions - directPeers))

        let selfSummary = NCTailscaleSelfNodeSummary(
            id: control.currentSnapshot.selfNode?.ID,
            stableID: control.currentSnapshot.selfNode?.StableID,
            name: control.currentSnapshot.selfNode?.Name,
            addresses: control.currentSnapshot.selfNode?.Addresses ?? [],
            allowedIPs: control.currentSnapshot.selfNode?.AllowedIPs ?? [],
            derpHomeRegion: curRegion,
            online: curState == NCTailscaleLoginState.started.rawValue
        )

        let statusFile = NCTailscaleStatusFile(
            version: 1,
            state: curState,
            authURL: curAuthURL,
            ipv4: curIPv4,
            ipv6: curIPv6,
            selfNode: selfSummary,
            derpHomeRegion: curRegion,
            peerCounts: counts,
            lastError: curError,
            updatedAt: Date()
        )

        try? NCTailscaleStatusStore.save(status: statusFile, stateDirURL: stateDirURL)
    }

    // MARK: - Observability Snapshots (for Task 5)

    /// Builds a dictionary strictly aligned with App's `TailscaleGuardStatus` for `NativeTunnelCore.memorySnapshot`.
    static func guardStatusSnapshot() -> [String: Any]? {
        let clients = allClients()
        guard !clients.isEmpty else { return nil }

        // Selection rule for multiple nodes:
        // Report the first node in error state (refused/stopped/failed),
        // or the first active node (started/starting), or the first node.
        let selected: NCTailscaleClient = {
            if let errored = clients.first(where: {
                $0.state == NCTailscaleLoginState.refused.rawValue ||
                $0.state == NCTailscaleLoginState.stopped.rawValue ||
                $0.state == NCTailscaleLoginState.failed.rawValue ||
                $0.lastError != nil
            }) {
                return errored
            }
            if let active = clients.first(where: {
                $0.state == NCTailscaleLoginState.started.rawValue ||
                $0.state == NCTailscaleLoginState.starting.rawValue
            }) {
                return active
            }
            return clients[0]
        }()

        selected.clientLock.lock()
        defer { selected.clientLock.unlock() }

        var dict: [String: Any] = [
            "nodes": clients.count,
            "state": selected.state,
            "minAvailableToStart": NCTailscaleConsts.minAvailableToStart,
            "stopBelowAvailable": NCTailscaleConsts.stopBelowAvailable
        ]
        dict["node"] = selected.name
        if let v = selected.startedAt { dict["startedAt"] = v }
        if let v = selected.footprintBefore { dict["footprintBefore"] = v }
        if let v = selected.availableBefore { dict["availableBefore"] = v }
        if let v = selected.footprintAfter { dict["footprintAfter"] = v }
        if let v = selected.startMillis { dict["startMillis"] = v }
        if let v = selected.peakSinceStart { dict["peakSinceStart"] = v }
        if let v = selected.refusedAvailable { dict["refusedAvailable"] = v }
        if let v = selected.refusedAt { dict["refusedAt"] = v }
        if let v = selected.stoppedAvailable { dict["stoppedAvailable"] = v }
        if let v = selected.stoppedAt { dict["stoppedAt"] = v }
        if let v = selected.lastError { dict["error"] = v }
        if let v = selected.routingError { dict["routingError"] = v }
        if let v = selected.authURL { dict["authURL"] = v }
        return dict
    }

    /// Builds the list of nodes for `.tailscaleInfo` App message (matches App's `TailnetNodeInfo`).
    static func tailscaleNodeInfos() -> [[String: Any]] {
        let clients = allClients()
        return clients.map { client in
            client.clientLock.lock()
            defer { client.clientLock.unlock() }
            var info: [String: Any] = [
                "name": client.name,
                "started": client.state == NCTailscaleLoginState.started.rawValue,
                "stopped": client.state == NCTailscaleLoginState.stopped.rawValue ||
                           client.state == NCTailscaleLoginState.refused.rawValue
            ]
            if let v4 = client.ipv4 { info["ipv4"] = v4 }
            if let v6 = client.ipv6 { info["ipv6"] = v6 }
            return info
        }
    }
}
