import CryptoKit
import Foundation
import Network
import Security

// MARK: - DERP Region Single Session
//
// Manages a single TCP/TLS/HTTP Upgrade connection to a DERP relay node.
// Handles the complete handshake lifecycle:
// 1. TCP dial via NCStream (bound via NCOutboundBinding.params to physical interface)
// 2. TLS handshake via NCTLSClientStream (SNI set to CertName ?? HostName)
// 3. HTTP Upgrade: `GET /derp HTTP/1.1` with `Upgrade: DERP` and `Connection: Upgrade`
// 4. Receives HTTP `101 Switching Protocols`
// 5. Reads `ServerKey` frame (extracts 32-byte server public key)
// 6. Sends `ClientInfo` frame (node key as identity key, encrypted JSON `{"Version": 2}`)
// 7. Reads `ServerInfo` frame (verifies server response box)
// 8. Sends `NotePreferred` frame (0x01 for home region, 0x00 otherwise)
// 9. Enters steady state: packet relaying, ping/pong echo, keepalive, and peer notifications.

final class NCDERPSession {

    enum State: Equatable {
        case idle
        case connectingTCP
        case tlsHandshake
        case httpUpgrade
        case waitingServerKey
        case waitingServerInfo
        case ready
        case closed(String?)

        var isReady: Bool {
            if case .ready = self { return true }
            return false
        }
    }

    // MARK: - Configuration

    let regionID: Int
    let isHome: Bool
    let node: NCTailscaleDERPNode
    private let nodeKey: Curve25519.KeyAgreement.PrivateKey
    private let queue: DispatchQueue

    // MARK: - Callbacks

    var onConnected: (() -> Void)?
    var onClosed: ((Error?) -> Void)?
    var onPacket: ((Data, Data) -> Void)?
    var onPeerGone: ((Data, UInt8) -> Void)?
    var onPeerPresent: ((Data) -> Void)?

    // MARK: - Connection & Framing State

    private(set) var state: State = .idle
    private var rawStream: NCStream?
    private var tlsStream: NCTLSClientStream?
    private let decoder = NCDERPFrameDecoder()

    private var serverDERPPublicKey: Data?
    private var httpUpgradeBuffer = Data()
    private var httpUpgradeComplete = false

    /// Outgoing packet queue buffered while connecting or under backpressure.
    private var sendQueue: [(destKey: Data, data: Data)] = []
    static let maxSendQueueSize: Int = 256
    private(set) var droppedPacketsCount: Int = 0

    /// Liveness timestamp for idle tracking.
    private(set) var lastActivity: Date = Date()

    private var isCancelled = false

    // MARK: - Initialization

    init(
        regionID: Int,
        isHome: Bool,
        node: NCTailscaleDERPNode,
        nodeKey: Curve25519.KeyAgreement.PrivateKey,
        queue: DispatchQueue
    ) {
        self.regionID = regionID
        self.isHome = isHome
        self.node = node
        self.nodeKey = nodeKey
        self.queue = queue
    }

    // MARK: - Connection Lifecycle

    /// Begins establishing connection and DERP handshake.
    func start() {
        queue.async { [weak self] in
            guard let self = self, self.state == .idle, !self.isCancelled else { return }
            self.connectTCP()
        }
    }

    /// Closes the session and tears down underlying network resources.
    func close(error: Error? = nil) {
        queue.async { [weak self] in
            guard let self = self, !self.isCancelled else { return }
            self.teardown(error: error)
        }
    }

    private func teardown(error: Error?) {
        isCancelled = true
        state = .closed(error?.localizedDescription)

        tlsStream?.cancel()
        tlsStream = nil

        rawStream?.cancel()
        rawStream = nil

        decoder.reset()
        httpUpgradeBuffer.removeAll()
        sendQueue.removeAll()

        onClosed?(error)
    }

    // MARK: - 1. TCP Connection

    private func connectTCP() {
        state = .connectingTCP
        let dialHost = node.dialHost
        let port = node.effectiveDERPPort

        let stream = NCStream(to: dialHost, port: port, queue: queue)
        rawStream = stream

        stream.start { [weak self] error in
            guard let self = self, !self.isCancelled else { return }
            if let error = error {
                self.fail(error: error, stage: "TCP connect")
                return
            }
            self.startTLS(raw: stream)
        }
    }

    // MARK: - 2. TLS Handshake

    private func startTLS(raw: NCStream) {
        state = .tlsHandshake
        let sni = node.effectiveServerName
        let allowInsecure = node.insecureForTests ?? false

        let config = NCTLSClientStream.Config(
            serverName: sni,
            alpn: ["http/1.1"],
            allowInsecure: allowInsecure
        )

        let tls = NCTLSClientStream(raw: raw, config: config, queue: queue)
        tlsStream = tls

        tls.startHandshake { [weak self] error in
            guard let self = self, !self.isCancelled else { return }
            if let error = error {
                self.fail(error: error, stage: "TLS handshake")
                return
            }
            self.sendHTTPUpgrade(tls: tls)
        }
    }

    // MARK: - 3. HTTP Upgrade (GET /derp, Upgrade: DERP)

    private func sendHTTPUpgrade(tls: NCTLSClientStream) {
        state = .httpUpgrade
        let hostHeader = node.effectiveServerName
        let path = NCTailscaleConsts.derpPath // "/derp"
        let upgradeHeader = NCTailscaleConsts.derpUpgradeHeaderValue // "DERP"

        // DERP protocol specifies standard HTTP/1.1 GET with Upgrade: DERP
        let req = "GET \(path) HTTP/1.1\r\n" +
            "Host: \(hostHeader)\r\n" +
            "Upgrade: \(upgradeHeader)\r\n" +
            "Connection: Upgrade\r\n\r\n"

        tls.send(Data(req.utf8))
        receiveLoop(tls: tls)
    }

    // MARK: - 4. Stream Receive Loop

    private func receiveLoop(tls: NCTLSClientStream) {
        tls.receive { [weak self] data, error in
            guard let self = self, !self.isCancelled else { return }

            if let error = error {
                self.fail(error: error, stage: "receive")
                return
            }

            guard let data = data, !data.isEmpty else {
                // EOF from server
                self.fail(
                    error: NSError(domain: "NCDERPSession", code: -1, userInfo: [NSLocalizedDescriptionKey: "Server closed stream (EOF)"]),
                    stage: "receive EOF"
                )
                return
            }

            self.lastActivity = Date()

            if !self.httpUpgradeComplete {
                self.handleHTTPUpgradeResponse(data: data, tls: tls)
            } else {
                self.handleDERPStreamBytes(data: data, tls: tls)
            }

            // Continue receive loop if not cancelled/closed
            if !self.isCancelled, case .closed = self.state {
                // Stopped
            } else if !self.isCancelled {
                self.receiveLoop(tls: tls)
            }
        }
    }

    // MARK: - HTTP Upgrade Parser

    private func handleHTTPUpgradeResponse(data: Data, tls: NCTLSClientStream) {
        httpUpgradeBuffer.append(data)

        // Safety limit: HTTP 101 header should never exceed 8 KB
        if httpUpgradeBuffer.count > 8192 {
            fail(
                error: NSError(domain: "NCDERPSession", code: -2, userInfo: [NSLocalizedDescriptionKey: "HTTP upgrade response too large"]),
                stage: "HTTP upgrade"
            )
            return
        }

        // Search for end of HTTP headers: CRLF CRLF
        let crlfcrlf = Data([0x0d, 0x0a, 0x0d, 0x0a])
        guard let range = httpUpgradeBuffer.range(of: crlfcrlf) else {
            // Wait for more header bytes
            return
        }

        let headerData = httpUpgradeBuffer.subdata(in: 0..<range.lowerBound)
        let trailingData = httpUpgradeBuffer.subdata(in: range.upperBound..<httpUpgradeBuffer.count)
        httpUpgradeBuffer.removeAll()
        httpUpgradeComplete = true

        guard let headerString = String(data: headerData, encoding: .utf8) else {
            fail(
                error: NSError(domain: "NCDERPSession", code: -3, userInfo: [NSLocalizedDescriptionKey: "Invalid UTF-8 in HTTP response"]),
                stage: "HTTP upgrade"
            )
            return
        }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let statusLine = lines.first,
              statusLine.contains(" 101 ") || statusLine.hasPrefix("HTTP/1.1 101") || statusLine.hasPrefix("HTTP/1.0 101") else {
            fail(
                error: NSError(
                    domain: "NCDERPSession",
                    code: -4,
                    userInfo: [NSLocalizedDescriptionKey: "DERP HTTP upgrade rejected: \(lines.first ?? "")"]
                ),
                stage: "HTTP upgrade"
            )
            return
        }

        // Advance to DERP handshake
        state = .waitingServerKey

        // Feed any bytes received after \r\n\r\n into the DERP frame decoder
        if !trailingData.isEmpty {
            handleDERPStreamBytes(data: trailingData, tls: tls)
        }
    }

    // MARK: - DERP Framing & Handshake State Machine

    private func handleDERPStreamBytes(data: Data, tls: NCTLSClientStream) {
        let frames: [NCDERPFrame]
        do {
            frames = try decoder.feed(data)
        } catch {
            fail(error: error, stage: "frame decoder")
            return
        }

        for frame in frames {
            processFrame(frame, tls: tls)
            if isCancelled { break }
        }
    }

    private func processFrame(_ frame: NCDERPFrame, tls: NCTLSClientStream) {
        switch state {
        case .waitingServerKey:
            guard case .serverKey(_, let serverKey) = frame else {
                fail(
                    error: NSError(domain: "NCDERPSession", code: -5, userInfo: [NSLocalizedDescriptionKey: "Expected ServerKey frame"]),
                    stage: "handshake"
                )
                return
            }
            guard serverKey.count == 32 else {
                fail(
                    error: NSError(domain: "NCDERPSession", code: -6, userInfo: [NSLocalizedDescriptionKey: "Invalid ServerKey length"]),
                    stage: "handshake"
                )
                return
            }

            serverDERPPublicKey = serverKey
            sendClientInfo(tls: tls, serverKey: serverKey)

        case .waitingServerInfo:
            guard case .serverInfo(let nonce, let boxedData) = frame else {
                fail(
                    error: NSError(domain: "NCDERPSession", code: -7, userInfo: [NSLocalizedDescriptionKey: "Expected ServerInfo frame"]),
                    stage: "handshake"
                )
                return
            }

            guard let serverPub = serverDERPPublicKey else {
                fail(
                    error: NSError(domain: "NCDERPSession", code: -8, userInfo: [NSLocalizedDescriptionKey: "Missing ServerKey for ServerInfo"]),
                    stage: "handshake"
                )
                return
            }

            // Open NaCl box from server to verify mutual authentication
            guard NCNaClBox.Box.open(
                box: boxedData,
                nonce24: nonce,
                senderPublicKey: serverPub,
                recipientPrivateKey: nodeKey
            ) != nil else {
                fail(
                    error: NSError(domain: "NCDERPSession", code: -9, userInfo: [NSLocalizedDescriptionKey: "Failed to open ServerInfo NaCl box"]),
                    stage: "handshake"
                )
                return
            }

            // Handshake authenticated! Send NotePreferred and transition to ready
            let prefFrame = NCDERPFrameCodec.encodeNotePreferred(preferred: isHome)
            tls.send(prefFrame)

            state = .ready
            onConnected?()

            // Flush any packets queued while handshake was in flight
            flushSendQueue(tls: tls)

        case .ready:
            handleReadyFrame(frame, tls: tls)

        default:
            break
        }
    }

    private func sendClientInfo(tls: NCTLSClientStream, serverKey: Data) {
        state = .waitingServerInfo

        // ClientInfo JSON: official protocol version 2
        // Reference: `derp_client.go`: ClientInfo{Version: 2, CanAckPings: true}
        let jsonStr = "{\"Version\":2,\"CanAckPings\":true}"
        let jsonBytes = Data(jsonStr.utf8)

        // Generate 24-byte cryptographically secure random nonce
        var nonce = Data(count: 24)
        let status = nonce.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 24, buf.baseAddress!)
        }
        guard status == errSecSuccess else {
            fail(
                error: NSError(domain: "NCDERPSession", code: -10, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed"]),
                stage: "ClientInfo nonce"
            )
            return
        }

        // Encrypt ClientInfo JSON with NaCl box (Curve25519 DH + XSalsa20 + Poly1305)
        guard let boxed = NCNaClBox.Box.seal(
            message: jsonBytes,
            nonce24: nonce,
            recipientPublicKey: serverKey,
            senderPrivateKey: nodeKey
        ) else {
            fail(
                error: NSError(domain: "NCDERPSession", code: -11, userInfo: [NSLocalizedDescriptionKey: "Failed to seal ClientInfo box"]),
                stage: "ClientInfo box"
            )
            return
        }

        let clientPub = Data(nodeKey.publicKey.rawRepresentation)
        let frameData = NCDERPFrameCodec.encodeClientInfo(clientKey: clientPub, nonce: nonce, boxedData: boxed)
        tls.send(frameData)
    }

    private func handleReadyFrame(_ frame: NCDERPFrame, tls: NCTLSClientStream) {
        switch frame {
        case .ping(let pingData):
            // DERP protocol: echo the 8-byte ping challenge in a pong frame
            let pongFrame = NCDERPFrameCodec.encodePong(data: pingData)
            tls.send(pongFrame)

        case .pong:
            // Ping response from server, updates liveness
            break

        case .keepAlive:
            // Liveness keep-alive frame, no payload
            break

        case .recvPacket(let srcKey, let packetData):
            // Incoming WireGuard packet from peer: forward to upstream engine
            onPacket?(srcKey, packetData)

        case .peerGone(let peerKey, let reason):
            // Server signals peer is no longer connected
            onPeerGone?(peerKey, reason)

        case .peerPresent(let peerKey, _):
            onPeerPresent?(peerKey)

        case .health:
            // Health diagnostic frame from server
            break

        case .restarting(let recMs, _):
            // Server announced scheduled restart: reconnect
            fail(
                error: NSError(
                    domain: "NCDERPSession",
                    code: -12,
                    userInfo: [NSLocalizedDescriptionKey: "Server restarting (reconnect in \(recMs)ms)"]
                ),
                stage: "server restarting"
            )

        default:
            break
        }
    }

    // MARK: - Packet Transmission & Queue Management

    /// Queues or immediately sends a WireGuard packet to `destKey`.
    ///
    /// - Parameters:
    ///   - destKey: 32-byte Curve25519 public key of destination node.
    ///   - data: Raw WireGuard packet.
    func sendPacket(destKey: Data, data: Data) {
        queue.async { [weak self] in
            guard let self = self, !self.isCancelled else { return }

            guard destKey.count == 32 else { return }
            guard data.count <= NCDERPFrameCodec.maxPacketSize else { return }

            if self.state == .ready, let tls = self.tlsStream {
                let wire = NCDERPFrameCodec.encodeSendPacket(destKey: destKey, data: data)
                tls.send(wire)
            } else {
                // Queue packet while connecting/handshaking
                if self.sendQueue.count >= Self.maxSendQueueSize {
                    // Drop oldest queued packet to prevent unbounded memory growth
                    self.sendQueue.removeFirst()
                    self.droppedPacketsCount += 1
                }
                self.sendQueue.append((destKey: destKey, data: data))
            }
        }
    }

    /// Sends a ping probe frame to test latency or keep connection alive.
    func sendPing(opaque: Data = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])) {
        queue.async { [weak self] in
            guard let self = self, self.state == .ready, let tls = self.tlsStream else { return }
            let frame = NCDERPFrameCodec.encodePing(data: opaque)
            tls.send(frame)
        }
    }

    private func flushSendQueue(tls: NCTLSClientStream) {
        guard !sendQueue.isEmpty else { return }
        for item in sendQueue {
            let wire = NCDERPFrameCodec.encodeSendPacket(destKey: item.destKey, data: item.data)
            tls.send(wire)
        }
        sendQueue.removeAll()
    }

    private func fail(error: Error, stage: String) {
        teardown(error: error)
    }
}
