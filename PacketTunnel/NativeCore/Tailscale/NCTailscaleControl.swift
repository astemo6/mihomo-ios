// NOTE: Stage 1/2 implementation supports HTTPS control plane connections only (default port 443
// or custom HTTPS port). Plaintext HTTP port 80 with early-noise fallback is not supported in
// this phase and will be rejected or upgraded to HTTPS.

import CryptoKit
import Foundation
import Network

// MARK: - Control Plane Client Configuration

struct NCTailscaleControlConfig {
    /// Proxy/node identifier in configuration (e.g. "tailscale-node").
    var name: String
    /// Control plane URL (e.g. "https://controlplane.tailscale.com" or Headscale endpoint). Empty string falls back to official default.
    var controlURL: String
    /// Pre-authentication key (never logged).
    var authKey: String?
    /// Hostname advertised to the tailnet (defaults to "tern").
    var hostname: String
    /// Relative state directory under home container (e.g. "tailscale/node-sha1").
    var stateDir: String
    /// Path to App Group container home.
    var homePath: String
    /// Whether this node should be treated as ephemeral.
    var ephemeral: Bool
    /// Serial dispatch queue for network and state orchestration.
    var queue: DispatchQueue?

    init(
        name: String,
        controlURL: String = "",
        authKey: String? = nil,
        hostname: String = "tern",
        stateDir: String,
        homePath: String,
        ephemeral: Bool = false,
        queue: DispatchQueue? = nil
    ) {
        self.name = name
        self.controlURL = controlURL
        self.authKey = authKey
        self.hostname = hostname.isEmpty ? "tern" : hostname
        self.stateDir = stateDir
        self.homePath = homePath
        self.ephemeral = ephemeral
        self.queue = queue
    }
}

// MARK: - Tailscale Control Plane Client (ts2021 + Register + Netmap Long-Polling)

/// Controls the complete lifecycle of a Tailscale node's control plane connection:
/// 1. Resolves and validates the node's state directory and key material (`machine.key`, `node.key`, `disco.key`).
/// 2. Performs TLS handshake over NWConnection.
/// 3. Retrieves the server's static machine public key via `GET /key?v=106`.
/// 4. Upgrades to `ts2021` Noise IK (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) via `POST /ts2021`.
/// 5. Establishes an HTTP/2 session (`NCH2ClientCore`) inside the encrypted Noise transport stream.
/// 6. Registers the node via `POST /machine/register`. Handles pre-auth keys and interactive `AuthURL` login.
/// 7. Maintains an incremental network map stream via `POST /machine/map` long-polling with exponential backoff.
/// 8. Persists live state and coordinates cleanly with Stage 3 data plane & memory guards.
final class NCTailscaleControl {
    let config: NCTailscaleControlConfig
    let netmapStore: NCTailscaleNetmapStore
    let queue: DispatchQueue

    // State & Keys
    private(set) var stateDirURL: URL?
    private(set) var keys: NCTailscaleKeys?
    private(set) var currentStatus: NCTailscaleStatusFile
    private(set) var isRunning: Bool = false

    // Cached Control Plane Machine Public Key (32 bytes)
    private var cachedServerControlKey: Data?

    // Active Transport State
    private var activeStream: NCStream?
    private var activeTLSStream: NCTLSClientStream?
    private var activeH2: NCH2ClientCore?
    private var activeCipher: NCTransportCipher?

    // Receive Buffers & Parsers
    private var encryptedRecvBuf = Data()
    private var earlyPayloadChecked = false
    private let mapResponseScanner = NCTailscaleMapResponseScanner()

    // Timers & Reconnection
    private var retryWorkItem: DispatchWorkItem?
    private var retryBackoff: TimeInterval = 1.0
    private var watchdogItem: DispatchWorkItem?

    // Callbacks for Stage 3 & UI consumption
    var onSnapshotChanged: ((NCTailscaleNetmapSnapshot) -> Void)?
    var onStatusChanged: ((NCTailscaleStatusFile) -> Void)?

    /// Phase 2: supplies the MapRequest `Endpoints` (our advertised UDP
    /// endpoints from STUN + local interfaces) at request-build time.
    var endpointsProvider: (() -> [String])?

    /// Phase 2: re-runs the session so the next MapRequest carries fresh
    /// endpoints. Unlike scheduleReconnect this is not an error path: no
    /// backoff, and no error is written to the status file.
    func refreshEndpoints() {
        guard isRunning else { return }
        queue.async { [weak self] in
            guard let self, self.isRunning else { return }
            self.retryWorkItem?.cancel()
            self.cancelCurrentConnection()
            self.runSession()
        }
    }

    private let statusLock = NSLock()

    init(config: NCTailscaleControlConfig) {
        self.config = config
        self.netmapStore = NCTailscaleNetmapStore()
        self.queue = config.queue ?? DispatchQueue(label: "com.tern.tailscale.control.\(config.name)")
        self.currentStatus = NCTailscaleStatusFile(
            version: 1,
            state: NCTailscaleLoginState.idle.rawValue,
            updatedAt: Date()
        )

        // Forward netmap updates to outer callback
        self.netmapStore.onSnapshotChanged = { [weak self] snapshot in
            self?.onSnapshotChanged?(snapshot)
        }
    }

    /// Latest immutable snapshot of the netmap.
    var currentSnapshot: NCTailscaleNetmapSnapshot {
        netmapStore.currentSnapshot()
    }

    // MARK: - Lifecycle

    /// Starts the Tailscale control client. Idempotent if already running.
    func start() {
        queue.async { [weak self] in
            guard let self = self, !self.isRunning else { return }
            self.isRunning = true
            self.retryBackoff = 1.0

            self.updateStatus { status in
                status.state = NCTailscaleLoginState.starting.rawValue
                status.lastError = nil
                status.updatedAt = Date()
            }

            do {
                let dir = try NCTailscalePath.resolveStateDir(home: self.config.homePath, stateDir: self.config.stateDir)
                self.stateDirURL = dir
                self.keys = try NCTailscaleKeyStore.loadOrCreate(in: dir)
                self.runSession()
            } catch {
                self.handleFatalError(error)
            }
        }
    }

    /// Stops the Tailscale control client immediately, closing connections, cancelling timers, and resetting state.
    func stop() {
        queue.async { [weak self] in
            guard let self = self, self.isRunning else { return }
            self.isRunning = false

            self.cancelCurrentConnection()
            self.retryWorkItem?.cancel()
            self.retryWorkItem = nil
            self.watchdogItem?.cancel()
            self.watchdogItem = nil

            self.netmapStore.reset()
            self.mapResponseScanner.reset()
            self.encryptedRecvBuf.removeAll(keepingCapacity: false)

            self.updateStatus { status in
                status.state = NCTailscaleLoginState.stopped.rawValue
                status.updatedAt = Date()
            }
        }
    }

    // MARK: - Orchestration Loop

    private func runSession() {
        guard isRunning else { return }

        cancelCurrentConnection()

        guard let target = resolveEndpoint() else {
            handleFatalError(NCTailscaleTransportError.invalidHTTPResponse("Invalid control URL: \(config.controlURL)"))
            return
        }

        // Step 1: Ensure server machine public key is known (GET /key?v=106)
        if let controlKey = cachedServerControlKey {
            startRegisterSession(target: target, serverKey: controlKey)
        } else {
            fetchServerKey(target: target) { [weak self] result in
                guard let self = self, self.isRunning else { return }
                switch result {
                case .success(let key):
                    self.cachedServerControlKey = key
                    self.startRegisterSession(target: target, serverKey: key)
                case .failure(let error):
                    self.scheduleReconnect(error: error)
                }
            }
        }
    }

    // MARK: - Step 1: GET /key?v=106

    private func fetchServerKey(target: (host: String, port: Int, authority: String), completion: @escaping (Result<Data, Error>) -> Void) {
        dialTLS(host: target.host, port: target.port) { [weak self] result in
            guard let self = self, self.isRunning else { return }
            switch result {
            case .failure(let err):
                completion(.failure(err))
            case .success(let stream):
                self.activeTLSStream = stream
                let req = "GET \(NCTailscaleConsts.keyPath)?v=\(NCTailscaleConsts.capabilityVersion) HTTP/1.1\r\n" +
                          "Host: \(target.authority)\r\n" +
                          "User-Agent: Tailscale\r\n" +
                          "Accept: application/json\r\n" +
                          "Connection: close\r\n\r\n"

                stream.send(Data(req.utf8))

                let parser = NCHTTP1ResponseParser()
                self.readHTTP1Response(stream: stream, parser: parser) { parseResult in
                    stream.cancel()
                    switch parseResult {
                    case .failure(let err):
                        completion(.failure(err))
                    case .success:
                        guard parser.statusCode == 200 else {
                            completion(.failure(NCTailscaleTransportError.unexpectedHTTPStatus(parser.statusCode, parser.statusText)))
                            return
                        }
                        do {
                            let keyResp = try JSONDecoder().decode(NCTailscaleControlKeyResponse.self, from: parser.body)
                            guard let rawKey = keyResp.rawKeyBytes else {
                                completion(.failure(NCTailscaleTransportError.invalidHandshakeFrame("Invalid server machine key format: \(keyResp.publicKey)")))
                                return
                            }
                            completion(.success(rawKey))
                        } catch {
                            completion(.failure(error))
                        }
                    }
                }
            }
        }
    }

    // MARK: - Step 2: Register (POST /machine/register)

    private func startRegisterSession(target: (host: String, port: Int, authority: String), serverKey: Data) {
        guard let keys = self.keys else { return }

        upgradeToNoiseTS2021(target: target, serverKey: serverKey) { [weak self] result in
            guard let self = self, self.isRunning else { return }
            switch result {
            case .failure(let err):
                self.scheduleReconnect(error: err)
            case .success(let session):
                self.executeRegisterRequest(target: target, session: session, keys: keys)
            }
        }
    }

    private func executeRegisterRequest(
        target: (host: String, port: Int, authority: String),
        session: (tlsStream: NCTLSClientStream, cipher: NCTransportCipher),
        keys: NCTailscaleKeys
    ) {
        let h2 = NCH2ClientCore()
        self.activeH2 = h2
        self.activeCipher = session.cipher
        self.activeTLSStream = session.tlsStream

        let headers: [(String, String)] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/machine/register"),
            (":authority", target.authority),
            ("content-type", "application/json"),
            ("accept", "application/json")
        ]

        let authModel = config.authKey.map { NCTailscaleRegisterAuth(AuthKey: $0) }
        let regRequest = NCTailscaleRegisterRequest(
            Version: NCTailscaleConsts.capabilityVersion,
            NodeKey: NCTailscaleKeyEncoding.encodeNodeKey(keys.nodeKey.publicKey),
            Auth: authModel,
            Hostinfo: NCTailscaleHostinfo(Hostname: config.hostname),
            Ephemeral: config.ephemeral ? true : nil
        )

        do {
            let bodyData = try JSONEncoder().encode(regRequest)
            let startFrames = h2.start(headers: headers)
            let dataFrame = NCH2ClientCore.frame(type: 0x0, flags: 0x1, streamID: 1, payload: bodyData)
            let plaintext = startFrames + dataFrame
            let recordData = try NCTailscaleControlFraming.makeRecordFrames(plaintext: plaintext, cipher: session.cipher)
            session.tlsStream.send(recordData)
        } catch {
            session.tlsStream.cancel()
            scheduleReconnect(error: error)
            return
        }

        var responseBody = Data()
        var streamFinished = false

        func pump() {
            session.tlsStream.receive { [weak self] data, error in
                guard let self = self, self.isRunning else { return }
                guard let data = data else {
                    if !streamFinished {
                        session.tlsStream.cancel()
                        self.scheduleReconnect(error: error ?? NCTailscaleTransportError.streamClosed)
                    }
                    return
                }

                do {
                    self.encryptedRecvBuf.append(data)
                    let chunks = try NCTailscaleControlFraming.parseRecordFrames(
                        from: &self.encryptedRecvBuf,
                        cipher: session.cipher
                    )

                    for var chunk in chunks {
                        _ = NCTailscaleControlFraming.filterEarlyPayload(from: &chunk, checked: &self.earlyPayloadChecked)
                        guard !chunk.isEmpty else { continue }

                        let feedResult = h2.feed(chunk)
                        if !feedResult.outbound.isEmpty {
                            let encOut = try NCTailscaleControlFraming.makeRecordFrames(
                                plaintext: feedResult.outbound,
                                cipher: session.cipher
                            )
                            session.tlsStream.send(encOut)
                        }

                        for payload in feedResult.payloads {
                            responseBody.append(payload)
                        }

                        if h2.streamClosed {
                            streamFinished = true
                            session.tlsStream.cancel()
                            self.handleRegisterResponse(
                                target: target,
                                responseData: responseBody,
                                serverKey: self.cachedServerControlKey
                            )
                            return
                        }
                    }

                    pump()
                } catch {
                    session.tlsStream.cancel()
                    self.scheduleReconnect(error: error)
                }
            }
        }

        pump()
    }

    private func handleRegisterResponse(
        target: (host: String, port: Int, authority: String),
        responseData: Data,
        serverKey: Data?
    ) {
        guard let serverKey = serverKey else { return }

        do {
            let resp = try JSONDecoder().decode(NCTailscaleRegisterResponse.self, from: responseData)

            if resp.NodeKeyExpired == true {
                // Key expired: rotate node key and re-register
                try rotateNodeKey()
                startRegisterSession(target: target, serverKey: serverKey)
                return
            }

            if let authURL = resp.AuthURL, !authURL.isEmpty {
                // Interactive login required
                updateStatus { status in
                    status.state = NCTailscaleLoginState.needsLogin.rawValue
                    status.authURL = authURL
                    status.updatedAt = Date()
                }
                // Schedule poll retry to check if user authorized
                let item = DispatchWorkItem { [weak self] in
                    self?.startRegisterSession(target: target, serverKey: serverKey)
                }
                self.retryWorkItem = item
                self.queue.asyncAfter(deadline: .now() + 5.0, execute: item)
                return
            }

            // Successfully registered; transition to Map long-polling
            updateStatus { status in
                status.state = NCTailscaleLoginState.starting.rawValue
                status.authURL = nil
                status.updatedAt = Date()
            }

            startMapSession(target: target, serverKey: serverKey)
        } catch {
            scheduleReconnect(error: error)
        }
    }

    // MARK: - Step 3: Map Long-Polling (POST /machine/map)

    private func startMapSession(target: (host: String, port: Int, authority: String), serverKey: Data) {
        guard let keys = self.keys else { return }

        upgradeToNoiseTS2021(target: target, serverKey: serverKey) { [weak self] result in
            guard let self = self, self.isRunning else { return }
            switch result {
            case .failure(let err):
                self.scheduleReconnect(error: err)
            case .success(let session):
                self.executeMapRequest(target: target, session: session, keys: keys)
            }
        }
    }

    private func executeMapRequest(
        target: (host: String, port: Int, authority: String),
        session: (tlsStream: NCTLSClientStream, cipher: NCTransportCipher),
        keys: NCTailscaleKeys
    ) {
        let h2 = NCH2ClientCore()
        self.activeH2 = h2
        self.activeCipher = session.cipher
        self.activeTLSStream = session.tlsStream
        self.mapResponseScanner.reset()

        let headers: [(String, String)] = [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/machine/map"),
            (":authority", target.authority),
            ("content-type", "application/json"),
            ("accept", "application/json")
        ]

        let mapReq = NCTailscaleMapRequest(
            Version: NCTailscaleConsts.capabilityVersion,
            Compress: "", // Specification requires uncompressed
            KeepAlive: true,
            NodeKey: NCTailscaleKeyEncoding.encodeNodeKey(keys.nodeKey.publicKey),
            DiscoKey: NCTailscaleKeyEncoding.encodeDiscoKey(keys.discoKey.publicKey),
            Stream: true,
            Endpoints: endpointsProvider?() ?? [],
            Hostinfo: NCTailscaleHostinfo(Hostname: config.hostname),
            IncludeIPv6: true,
            OmitCaps: true
        )

        do {
            let bodyData = try JSONEncoder().encode(mapReq)
            let startFrames = h2.start(headers: headers)
            let dataFrame = NCH2ClientCore.frame(type: 0x0, flags: 0x1, streamID: 1, payload: bodyData)
            let plaintext = startFrames + dataFrame
            let recordData = try NCTailscaleControlFraming.makeRecordFrames(plaintext: plaintext, cipher: session.cipher)
            session.tlsStream.send(recordData)
        } catch {
            session.tlsStream.cancel()
            scheduleReconnect(error: error)
            return
        }

        self.armWatchdog(session: session.tlsStream)
        self.pumpMapStream(session: session, h2: h2, target: target)
    }

    private func pumpMapStream(
        session: (tlsStream: NCTLSClientStream, cipher: NCTransportCipher),
        h2: NCH2ClientCore,
        target: (host: String, port: Int, authority: String)
    ) {
        session.tlsStream.receive { [weak self] data, error in
            guard let self = self, self.isRunning else { return }

            guard let data = data else {
                session.tlsStream.cancel()
                self.scheduleReconnect(error: error ?? NCTailscaleTransportError.streamClosed)
                return
            }

            self.armWatchdog(session: session.tlsStream)

            do {
                self.encryptedRecvBuf.append(data)
                let chunks = try NCTailscaleControlFraming.parseRecordFrames(
                    from: &self.encryptedRecvBuf,
                    cipher: session.cipher
                )

                for var chunk in chunks {
                    _ = NCTailscaleControlFraming.filterEarlyPayload(from: &chunk, checked: &self.earlyPayloadChecked)
                    guard !chunk.isEmpty else { continue }

                    let feedResult = h2.feed(chunk)

                    if !feedResult.outbound.isEmpty {
                        let encOut = try NCTailscaleControlFraming.makeRecordFrames(
                            plaintext: feedResult.outbound,
                            cipher: session.cipher
                        )
                        session.tlsStream.send(encOut)
                    }

                    for payload in feedResult.payloads {
                        self.mapResponseScanner.append(payload)
                        self.drainMapResponses(target: target, session: session.tlsStream)
                    }

                    if h2.streamClosed {
                        session.tlsStream.cancel()
                        self.scheduleReconnect(error: NCTailscaleTransportError.streamClosed)
                        return
                    }
                }

                self.pumpMapStream(session: session, h2: h2, target: target)
            } catch {
                session.tlsStream.cancel()
                self.scheduleReconnect(error: error)
            }
        }
    }

    private func drainMapResponses(
        target: (host: String, port: Int, authority: String),
        session: NCTLSClientStream
    ) {
        while let responseData = mapResponseScanner.nextResponseData() {
            do {
                let mapResp = try JSONDecoder().decode(NCTailscaleMapResponse.self, from: responseData)

                if mapResp.NodeKeyExpired == true {
                    session.cancel()
                    try rotateNodeKey()
                    if let key = cachedServerControlKey {
                        startRegisterSession(target: target, serverKey: key)
                    } else {
                        runSession()
                    }
                    return
                }

                // Apply update to cumulative netmap
                netmapStore.apply(mapResponse: mapResp)
                let snap = netmapStore.currentSnapshot()

                // Reset exponential backoff on successful update
                retryBackoff = 1.0

                updateStatus { status in
                    status.state = NCTailscaleLoginState.started.rawValue
                    if let pop = mapResp.PopBrowserURL, !pop.isEmpty {
                        status.authURL = pop
                    }
                    status.ipv4 = snap.tailnetIPv4 ?? status.ipv4
                    status.ipv6 = snap.tailnetIPv6 ?? status.ipv6
                    status.derpHomeRegion = snap.derpHomeRegion ?? status.derpHomeRegion
                    status.peerCounts = NCTailscalePeerCounts(
                        total: snap.peerCount,
                        direct: 0,
                        relay: snap.peerCount
                    )
                    if let sNode = snap.selfNode {
                        status.selfNode = NCTailscaleSelfNodeSummary(
                            id: sNode.ID,
                            stableID: sNode.StableID,
                            name: sNode.Name,
                            addresses: sNode.Addresses,
                            allowedIPs: sNode.AllowedIPs,
                            derpHomeRegion: sNode.derpRegionID,
                            online: sNode.Online
                        )
                    }
                    status.lastError = nil
                    status.updatedAt = Date()
                }
            } catch {
                // Non-fatal parse warning for unknown/future extensions
            }
        }
    }

    // MARK: - ts2021 Noise IK Handshake Helper

    private func upgradeToNoiseTS2021(
        target: (host: String, port: Int, authority: String),
        serverKey: Data,
        completion: @escaping (Result<(tlsStream: NCTLSClientStream, cipher: NCTransportCipher), Error>) -> Void
    ) {
        guard let keys = self.keys else {
            completion(.failure(NCTailscaleTransportError.invalidHandshakeFrame("Keys not loaded")))
            return
        }

        dialTLS(host: target.host, port: target.port) { [weak self] result in
            guard let self = self, self.isRunning else { return }
            switch result {
            case .failure(let err):
                completion(.failure(err))
            case .success(let stream):
                self.activeTLSStream = stream
                do {
                    // Handshake pattern: Noise_IK_25519_ChaChaPoly_BLAKE2s
                    // Prologue: "Tailscale Control Protocol v" + capver (or "Tailscale Control Protocol v2021")
                    let prologueStr = "Tailscale Control Protocol v\(NCTailscaleConsts.capabilityVersion)"
                    let initiator = try NCNoiseIKInitiator(
                        staticPrivateKey: keys.machineKey,
                        responderStaticPublicKey: [UInt8](serverKey),
                        prologue: Array(prologueStr.utf8)
                    )

                    let noiseMsg1 = try initiator.writeMessage1(payload: Data())
                    let initFrame = NCTailscaleControlFraming.makeInitiationFrame(
                        protocolVersion: UInt16(NCTailscaleConsts.capabilityVersion),
                        noiseMsg1: noiseMsg1
                    )
                    let initB64 = initFrame.base64EncodedString()

                    var upgradeReq = "POST \(NCTailscaleConsts.ts2021Path) HTTP/1.1\r\n"
                    upgradeReq += "Host: \(target.authority)\r\n"
                    upgradeReq += "User-Agent: Tailscale\r\n"
                    upgradeReq += "Connection: Upgrade\r\n"
                    upgradeReq += "Upgrade: \(NCTailscaleConsts.upgradeHeaderValue)\r\n"
                    upgradeReq += "X-Tailscale-Handshake: \(initB64)\r\n"
                    upgradeReq += "Content-Length: 0\r\n\r\n"

                    stream.send(Data(upgradeReq.utf8))

                    let parser = NCHTTP1ResponseParser()
                    self.readHTTP1Response(stream: stream, parser: parser) { parseResult in
                        switch parseResult {
                        case .failure(let err):
                            stream.cancel()
                            completion(.failure(err))
                        case .success:
                            guard parser.statusCode == 101 else {
                                stream.cancel()
                                completion(.failure(NCTailscaleTransportError.unexpectedHTTPStatus(parser.statusCode, parser.statusText)))
                                return
                            }

                            // 101 Switching Protocols confirmed; complete Noise handshake with Message 2
                            let handshakeBuf = parser.trailingData
                            self.encryptedRecvBuf.removeAll(keepingCapacity: false)
                            self.earlyPayloadChecked = false

                            self.readNoiseMessage2(stream: stream, buffer: handshakeBuf) { msg2Result in
                                switch msg2Result {
                                case .failure(let err):
                                    stream.cancel()
                                    completion(.failure(err))
                                case .success(let msg2):
                                    do {
                                        let (_, transportCipher) = try initiator.readMessage2(msg2.message)
                                        // Bytes after message 2 are the first transport records.
                                        self.encryptedRecvBuf = msg2.remaining
                                        completion(.success((tlsStream: stream, cipher: transportCipher)))
                                    } catch {
                                        stream.cancel()
                                        completion(.failure(error))
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    stream.cancel()
                    completion(.failure(error))
                }
            }
        }
    }

    /// Reads the Noise message 2 frame. The buffer is passed by value (an escaping
    /// receive callback cannot capture an `inout` parameter); the bytes left after
    /// the frame are handed back as `remaining`.
    private func readNoiseMessage2(
        stream: NCTLSClientStream,
        buffer: Data,
        completion: @escaping (Result<(message: Data, remaining: Data), Error>) -> Void
    ) {
        var working = buffer
        do {
            if let msg2 = try NCTailscaleControlFraming.parseResponseMessage(from: &working) {
                completion(.success((message: msg2, remaining: working)))
                return
            }
        } catch {
            completion(.failure(error))
            return
        }

        let pending = working
        stream.receive { [weak self] data, error in
            guard let self = self, self.isRunning else { return }
            guard let data = data else {
                completion(.failure(error ?? NCTailscaleTransportError.streamClosed))
                return
            }
            var next = pending
            next.append(data)
            self.readNoiseMessage2(stream: stream, buffer: next, completion: completion)
        }
    }

    // MARK: - TLS Dialing & HTTP/1.1 Helpers

    private func dialTLS(host: String, port: Int, completion: @escaping (Result<NCTLSClientStream, Error>) -> Void) {
        let tcpStream = NCStream(to: host, port: port, tls: false, queue: queue)
        self.activeStream = tcpStream

        tcpStream.start { [weak self] error in
            guard let self = self, self.isRunning else {
                tcpStream.cancel()
                return
            }
            if let error = error {
                completion(.failure(error))
                return
            }

            var tlsConfig = NCTLSClientStream.Config(serverName: host)
            tlsConfig.alpn = ["http/1.1"]
            tlsConfig.allowInsecure = true // Noise IK provides authenticated endpoint security

            let tlsStream = NCTLSClientStream(raw: tcpStream, config: tlsConfig, queue: self.queue)
            tlsStream.startHandshake { [weak self] tlsError in
                guard let self = self, self.isRunning else {
                    tlsStream.cancel()
                    return
                }
                if let tlsError = tlsError {
                    completion(.failure(tlsError))
                    return
                }
                completion(.success(tlsStream))
            }
        }
    }

    private func readHTTP1Response(
        stream: NCTLSClientStream,
        parser: NCHTTP1ResponseParser,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        stream.receive { [weak self] data, error in
            guard let self = self, self.isRunning else { return }
            guard let data = data else {
                completion(.failure(error ?? NCTailscaleTransportError.streamClosed))
                return
            }

            do {
                if try parser.feed(data) {
                    completion(.success(()))
                } else {
                    self.readHTTP1Response(stream: stream, parser: parser, completion: completion)
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    // MARK: - Reconnection & Watchdog

    private func scheduleReconnect(error: Error) {
        guard isRunning else { return }

        cancelCurrentConnection()

        updateStatus { status in
            status.lastError = error.localizedDescription
            status.updatedAt = Date()
        }

        let delay = retryBackoff
        retryBackoff = min(retryBackoff * 2.0, 30.0)

        let item = DispatchWorkItem { [weak self] in
            self?.runSession()
        }
        self.retryWorkItem = item
        self.queue.asyncAfter(deadline: .now() + delay, execute: item)
    }

    private func armWatchdog(session: NCTLSClientStream) {
        watchdogItem?.cancel()
        let item = DispatchWorkItem { [weak self, weak session] in
            guard let self = self, self.isRunning else { return }
            session?.cancel()
            self.scheduleReconnect(error: NCTailscaleTransportError.streamClosed)
        }
        self.watchdogItem = item
        // 120-second inactivity watchdog for map poll streams
        self.queue.asyncAfter(deadline: .now() + 120.0, execute: item)
    }

    private func cancelCurrentConnection() {
        watchdogItem?.cancel()
        watchdogItem = nil
        activeTLSStream?.cancel()
        activeTLSStream = nil
        activeStream?.cancel()
        activeStream = nil
        activeH2 = nil
        activeCipher = nil
    }

    private func handleFatalError(_ error: Error) {
        cancelCurrentConnection()
        updateStatus { status in
            status.state = NCTailscaleLoginState.failed.rawValue
            status.lastError = error.localizedDescription
            status.updatedAt = Date()
        }
    }

    // MARK: - Key Rotation & Persistence Helpers

    private func rotateNodeKey() throws {
        guard let dir = stateDirURL else { return }
        let newKey = Curve25519.KeyAgreement.PrivateKey()
        let data = NCTailscaleKeyStore.formatKey(newKey)
        try NCTailscaleKeyStore.atomicWrite(data: data, to: dir.appendingPathComponent("node.key"))
        self.keys = try NCTailscaleKeyStore.loadOrCreate(in: dir)
    }

    private func updateStatus(_ modifier: (inout NCTailscaleStatusFile) -> Void) {
        statusLock.lock()
        var st = currentStatus
        modifier(&st)
        currentStatus = st
        if let dir = stateDirURL {
            try? NCTailscaleStatusStore.save(status: st, stateDirURL: dir)
        }
        statusLock.unlock()

        onStatusChanged?(st)
    }

    private func resolveEndpoint() -> (host: String, port: Int, authority: String)? {
        let raw = config.controlURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let effective = raw.isEmpty ? NCTailscaleConsts.defaultControlURL : raw

        guard let url = URL(string: effective), let host = url.host, !host.isEmpty else {
            return nil
        }

        let scheme = url.scheme?.lowercased() ?? "https"
        let defaultPort = (scheme == "http") ? 80 : 443
        let port = url.port ?? defaultPort
        let authority = (port == defaultPort) ? host : "\(host):\(port)"
        return (host: host, port: port, authority: authority)
    }
}
