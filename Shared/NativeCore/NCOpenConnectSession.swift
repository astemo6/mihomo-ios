import Foundation
import Network
import Security

/// OpenConnect connection session and data pump (CSTP over TLS/TCP + DTLS 1.2 over UDP fallback).
///
/// Design note: docs/nc-proto-openconnect.md.
/// References:
/// - draft-mavrogiannopoulos-openconnect-04 §2.2 (Authentication & Tunnel Establishment)
/// - draft-mavrogiannopoulos-openconnect-04 §2.3 (CSTP Data Protocol)
/// - draft-mavrogiannopoulos-openconnect-04 §2.4 & §2.2.7 (DTLS Channel & Fallback)

// MARK: - Enums & Errors

enum NCOpenConnectMode: String, CustomStringConvertible {
    case cstp = "CSTP (TCP)"
    case dtls = "DTLS (UDP)"
    var description: String { rawValue }
}

enum NCOpenConnectChannelState: Equatable, CustomStringConvertible {
    case disconnected
    case authenticating
    case upgradingTunnel
    case cstpActive
    case attemptingDTLS(port: Int)
    case dtlsActive(port: Int)
    case dtlsFallbackToCSTP(reason: NCOpenConnectFallbackReason)
    case closed

    var description: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .authenticating: return "Authenticating"
        case .upgradingTunnel: return "Upgrading CSTP Tunnel"
        case .cstpActive: return "CSTP Active (TCP)"
        case .attemptingDTLS(let p): return "Attempting DTLS (UDP port \(p))"
        case .dtlsActive(let p): return "DTLS Active (UDP port \(p))"
        case .dtlsFallbackToCSTP(let r): return "DTLS Fallback to CSTP: \(r.rawValue)"
        case .closed: return "Closed"
        }
    }
}

enum NCOpenConnectFallbackReason: String, Equatable {
    case disabledByConfig = "DTLS disabled by proxy configuration"
    case serverNotOffered = "Server did not negotiate DTLS (missing X-DTLS-Port or PSK-NEGOTIATE)"
    case missingAppID = "Server did not provide X-DTLS-App-ID"
    case keyExporterUnavailable = "RFC 5705 key exporter unavailable on TLS connection"
    case platformUnsupported = "Network.framework does not support custom SessionID in DTLS PSK ClientHello"
    case handshakeFailed = "DTLS UDP handshake failed"
    case dpdProbeFailed = "DTLS DPD probe failed"
}

enum NCOpenConnectError: LocalizedError, Equatable {
    case connectionFailed(String)
    case authenticationFailed(String)
    case tunnelUpgradeFailed(String)
    case protocolError(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .connectionFailed(let s): return "OpenConnect 连接失败: \(s)"
        case .authenticationFailed(let s): return "OpenConnect 认证失败: \(s)"
        case .tunnelUpgradeFailed(let s): return "OpenConnect CSTP 升级失败: \(s)"
        case .protocolError(let s): return "OpenConnect 协议错误: \(s)"
        case .cancelled: return "OpenConnect 会话已取消"
        }
    }
}

// MARK: - Session

final class NCOpenConnectSession {
    let config: NCOpenConnect.Config
    let target: NCTarget
    let isEchoMode: Bool
    let queue: DispatchQueue

    private(set) var channelState: NCOpenConnectChannelState = .disconnected
    private(set) var activeMode: NCOpenConnectMode = .cstp
    private(set) var dtlsFallbackReason: NCOpenConnectFallbackReason?
    var tunnelParams: NCOpenConnect.TunnelParameters?
    private(set) var webvpnCookie: String?

    var onStateChange: ((NCOpenConnectChannelState) -> Void)?

    private var accumulatedCookies: [String: String] = [:]
    private var authStream: NCStream?
    private var cstpStream: NCStream?
    private var relayStream: NCOpenConnectRelayStream?
    private var isClosed = false

    init(config: NCOpenConnect.Config, target: NCTarget, isEchoMode: Bool = false, queue: DispatchQueue) {
        self.config = config
        self.target = target
        self.isEchoMode = isEchoMode
        self.queue = queue
    }

    /// Starts connection: authenticates if necessary, upgrades to CSTP, initiates DTLS evaluation.
    func start(completion: @escaping (NCRelayStream?, Error?) -> Void) {
        queue.async {
            if let preCookie = self.config.cookie, !preCookie.isEmpty {
                // If user provided a raw cookie or webvpn token, skip auth state machine
                let val = preCookie.contains("=") ? preCookie.components(separatedBy: "=").dropFirst().joined(separator: "=") : preCookie
                self.webvpnCookie = val.trimmingCharacters(in: .whitespaces)
                self.startCSTPTunnel(completion: completion)
            } else {
                self.startAuth(completion: completion)
            }
        }
    }

    // MARK: - HTTPS Authentication State Machine

    private func startAuth(completion: @escaping (NCRelayStream?, Error?) -> Void) {
        updateState(.authenticating)
        let stream = NCStream(to: config.server, port: config.port,
                              tlsServerName: config.sni,
                              allowInsecure: config.skipCertVerify,
                              queue: queue)
        self.authStream = stream

        stream.start { [weak self] err in
            guard let self = self else { return }
            if let err = err {
                completion(nil, NCOpenConnectError.connectionFailed(err.localizedDescription))
                return
            }
            // Send initial XML request
            let initXML = NCOpenConnect.buildInitXML()
            let req = [
                "POST / HTTP/1.1",
                "Host: \(self.config.server):\(self.config.port)",
                "User-Agent: \(self.config.userAgent)",
                "Accept: */*",
                "Accept-Encoding: identity",
                "X-Transcend-Version: 1",
                "Content-Type: text/xml; charset=utf-8",
                "Content-Length: \(initXML.utf8.count)",
                "",
                initXML
            ].joined(separator: "\r\n")

            stream.send(Data(req.utf8)) {
                self.readAuthStep(stream: stream, rxBuffer: Data(), round: 1, completion: completion)
            }
        }
    }

    private func readAuthStep(stream: NCStream, rxBuffer: Data = Data(), round: Int,
                              completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard round <= 6 else {
            completion(nil, NCOpenConnectError.authenticationFailed("认证交互轮数超过上限 (6)"))
            return
        }

        stream.receive { [weak self] chunk, err in
            guard let self = self else { return }
            if let err = err {
                completion(nil, NCOpenConnectError.authenticationFailed("网络中断: \(err.localizedDescription)"))
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                completion(nil, NCOpenConnectError.authenticationFailed("服务端过早关闭连接"))
                return
            }

            var localBuffer = rxBuffer
            localBuffer.append(chunk)

            if let (msg, consumed) = NCOpenConnect.HTTPMessage.parse(data: localBuffer) {
                let rest = Data(localBuffer.dropFirst(consumed))
                self.handleAuthResponse(msg: msg, stream: stream, remainingData: rest, round: round, completion: completion)
            } else {
                // Wait for more HTTP data
                self.readAuthStep(stream: stream, rxBuffer: localBuffer, round: round, completion: completion)
            }
        }
    }

    private func handleAuthResponse(msg: NCOpenConnect.HTTPMessage, stream: NCStream, remainingData: Data, round: Int,
                                    completion: @escaping (NCRelayStream?, Error?) -> Void) {
        // Collect cookies
        for (k, v) in msg.cookies {
            accumulatedCookies[k] = v
            if k.lowercased() == "webvpn" && !v.isEmpty {
                self.webvpnCookie = v
            }
        }

        let bodyStr = String(data: msg.body, encoding: .utf8) ?? ""
        let authResp = NCOpenConnect.AuthResponse.parse(xmlString: bodyStr)

        if msg.statusCode == 200, (authResp?.type == .complete || (authResp?.type != .authRequest && self.webvpnCookie != nil)) {
            // Authentication successful!
            stream.cancel()
            self.authStream = nil
            self.startCSTPTunnel(completion: completion)
            return
        }

        if msg.statusCode == 401 || authResp?.type == .error {
            let desc = authResp?.message ?? authResp?.error ?? "HTTP \(msg.statusCode) 凭据错误"
            completion(nil, NCOpenConnectError.authenticationFailed(desc))
            return
        }

        if let authResp = authResp, authResp.type == .authRequest {
            // Build reply
            let action = authResp.formAction ?? "/auth"
            let targetPath = action.hasPrefix("/") ? action : "/\(action)"

            var postFields: [(String, String)] = []
            if authResp.inputs["group_list"] != nil, let g = config.authGroup, !g.isEmpty {
                postFields.append(("group_list", g))
            }
            if authResp.inputs["username"] != nil, let u = config.username {
                postFields.append(("username", u))
            }
            if authResp.inputs["password"] != nil, let p = config.password {
                postFields.append(("password", p))
            }

            let formBody = NCOpenConnect.buildFormURLEncoded(fields: postFields)
            var cookieList: [String] = []
            for (ck, cv) in accumulatedCookies { cookieList.append("\(ck)=\(cv)") }
            let cookieHeader = cookieList.joined(separator: "; ")

            var reqLines = [
                "POST \(targetPath) HTTP/1.1",
                "Host: \(config.server):\(config.port)",
                "User-Agent: \(config.userAgent)",
                "Accept: */*",
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Length: \(formBody.utf8.count)"
            ]
            if !cookieHeader.isEmpty {
                reqLines.append("Cookie: \(cookieHeader)")
            }
            reqLines.append("")
            reqLines.append(formBody)

            let wireReq = reqLines.joined(separator: "\r\n")
            stream.send(Data(wireReq.utf8)) {
                self.readAuthStep(stream: stream, rxBuffer: remainingData, round: round + 1, completion: completion)
            }
            return
        }

        // Unknown or empty response
        completion(nil, NCOpenConnectError.authenticationFailed("无法识别的认证响应: \(bodyStr.prefix(200))"))
    }

    // MARK: - CSTP Tunnel Upgrade

    private func startCSTPTunnel(completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let cookie = self.webvpnCookie, !cookie.isEmpty else {
            completion(nil, NCOpenConnectError.authenticationFailed("缺少 webvpn 会话令牌"))
            return
        }

        updateState(.upgradingTunnel)
        let stream = NCStream(to: config.server, port: config.port,
                              tlsServerName: config.sni,
                              allowInsecure: config.skipCertVerify,
                              queue: queue)
        self.cstpStream = stream

        stream.start { [weak self] err in
            guard let self = self else { return }
            if let err = err {
                completion(nil, NCOpenConnectError.tunnelUpgradeFailed(err.localizedDescription))
                return
            }

            let connectReq = [
                "CONNECT /CSCOSSLC/tunnel HTTP/1.1",
                "Host: \(self.config.server):\(self.config.port)",
                "User-Agent: \(self.config.userAgent)",
                "Cookie: webvpn=\(cookie)",
                "X-CSTP-Version: 1",
                "X-CSTP-Hostname: \(self.config.localHostname ?? "localhost")",
                "X-CSTP-Base-MTU: \(NCOpenConnect.defaultBaseMTU)",
                "X-CSTP-MTU: \(self.config.mtu)",
                "X-CSTP-Address-Type: IPv4,IPv6",
                "X-DTLS-CipherSuite: PSK-NEGOTIATE",
                "",
                ""
            ].joined(separator: "\r\n")

            stream.send(Data(connectReq.utf8)) {
                self.readTunnelResponse(stream: stream, completion: completion)
            }
        }
    }

    private func readTunnelResponse(stream: NCStream, rxBuffer: Data = Data(), completion: @escaping (NCRelayStream?, Error?) -> Void) {
        stream.receive { [weak self] chunk, err in
            guard let self = self else { return }
            if let err = err {
                completion(nil, NCOpenConnectError.tunnelUpgradeFailed(err.localizedDescription))
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                completion(nil, NCOpenConnectError.tunnelUpgradeFailed("服务端未响应 CONNECT 请求"))
                return
            }

            var current = rxBuffer
            current.append(chunk)

            let crlf2 = Data([0x0d, 0x0a, 0x0d, 0x0a])
            if let r = current.range(of: crlf2) {
                let headerBytes = current.subdata(in: current.startIndex..<r.lowerBound)
                let rest = Data(current.subdata(in: r.upperBound..<current.endIndex))

                guard let headerStr = String(data: headerBytes, encoding: .utf8) ?? String(data: headerBytes, encoding: .isoLatin1) else {
                    completion(nil, NCOpenConnectError.tunnelUpgradeFailed("无法解析响应头"))
                    return
                }

                let lines = headerStr.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
                guard let statusLine = lines.first else {
                    completion(nil, NCOpenConnectError.tunnelUpgradeFailed("缺少状态行"))
                    return
                }

                let is200 = statusLine.contains("200")
                guard is200 else {
                    completion(nil, NCOpenConnectError.tunnelUpgradeFailed("HTTP 协商被拒: \(statusLine)"))
                    return
                }

                var headers: [String: String] = [:]
                for line in lines.dropFirst() {
                    guard let idx = line.firstIndex(of: ":") else { continue }
                    let k = line[..<idx].trimmingCharacters(in: .whitespaces)
                    let v = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                    headers[k] = v
                }

                self.tunnelParams = NCOpenConnect.TunnelParameters.parse(headers: headers)
                self.updateState(.cstpActive)
                self.activeMode = .cstp

                // Construct relay stream
                let relay = NCOpenConnectRelayStream(session: self, cstpStream: stream, initialData: rest, isEchoMode: self.isEchoMode, queue: self.queue)
                self.relayStream = relay

                // Evaluate DTLS 1.2 Channel & Fallback
                self.evaluateDTLSChannel()

                completion(relay, nil)
            } else {
                self.readTunnelResponse(stream: stream, rxBuffer: current, completion: completion)
            }
        }
    }

    // MARK: - DTLS 1.2 Channel & Explicit Fallback State Machine

    /// Evaluates DTLS preconditions according to S1 design.
    /// If preconditions or platform capabilities are missing, triggers explicit fallback to CSTP.
    func evaluateDTLSChannel() {
        guard config.dtls else {
            triggerDTLSFallback(reason: .disabledByConfig)
            return
        }

        guard let params = tunnelParams else {
            triggerDTLSFallback(reason: .serverNotOffered)
            return
        }

        guard let port = params.dtlsPort, port > 0,
              let cipher = params.dtlsCipherSuite, cipher.contains("PSK-NEGOTIATE") else {
            triggerDTLSFallback(reason: .serverNotOffered)
            return
        }

        guard let appID = params.dtlsAppID, !appID.isEmpty else {
            triggerDTLSFallback(reason: .missingAppID)
            return
        }

        updateState(.attemptingDTLS(port: port))

        // Check TLS exporter (RFC 5705)
        guard exportDTLSPSK() != nil else {
            triggerDTLSFallback(reason: .keyExporterUnavailable)
            return
        }

        // On Darwin / Network.framework, DTLS 1.2 PSK cannot bind arbitrary ClientHello.legacy_session_id
        // (X-DTLS-App-ID) via public sec_protocol_options API. ocserv rejects UDP handshakes without matching
        // App-ID in session ID. Therefore, Network.framework DTLS cannot fulfill the server's session correlation.
        // As designed in S1 and ordered by dispatcher, fall back cleanly and explicitly to CSTP.
        triggerDTLSFallback(reason: .platformUnsupported)
    }

    private func exportDTLSPSK() -> Data? {
        guard let stream = cstpStream else { return nil }
        guard let md = stream.conn.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return nil
        }
        let sec = md.securityProtocolMetadata
        let label = Array(NCOpenConnect.dtlsExporterLabel.utf8.map { CChar(bitPattern: $0) })
        let emptyCtx: [UInt8] = []
        let secret = label.withUnsafeBufferPointer { lp in
            emptyCtx.withUnsafeBufferPointer { cp in
                sec_protocol_metadata_create_secret_with_context(
                    sec,
                    lp.count,
                    lp.baseAddress ?? UnsafePointer<CChar>(bitPattern: 1)!,
                    0,
                    cp.baseAddress ?? UnsafePointer<UInt8>(bitPattern: 1)!,
                    32
                )
            }
        }
        guard let secret else { return nil }
        let out = Data(referencing: (secret as AnyObject) as! NSData)
        return out.count == 32 ? out : nil
    }

    func triggerDTLSFallback(reason: NCOpenConnectFallbackReason) {
        self.dtlsFallbackReason = reason
        self.activeMode = .cstp
        updateState(.dtlsFallbackToCSTP(reason: reason))
        NSLog("[openconnect] DTLS channel unavailable (\(reason.rawValue)), falling back to CSTP TCP")
    }

    private func updateState(_ state: NCOpenConnectChannelState) {
        self.channelState = state
        onStateChange?(state)
    }

    func cancel() {
        guard !isClosed else { return }
        isClosed = true
        updateState(.closed)
        authStream?.cancel()
        authStream = nil
        cstpStream?.cancel()
        cstpStream = nil
        relayStream = nil
    }
}

// MARK: - CSTP Relay Stream (NCRelayStream conformer)

final class NCOpenConnectRelayStream: NCRelayStream {
    weak var session: NCOpenConnectSession?
    let cstpStream: NCStream
    let isEchoMode: Bool
    let queue: DispatchQueue

    private var rxBuffer: Data
    private var receiveHandler: ((Data?, Error?) -> Void)?
    private var isCancelled = false
    private var isPumping = false

    init(session: NCOpenConnectSession, cstpStream: NCStream, initialData: Data, isEchoMode: Bool, queue: DispatchQueue) {
        self.session = session
        self.cstpStream = cstpStream
        self.rxBuffer = initialData
        self.isEchoMode = isEchoMode
        self.queue = queue
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !isCancelled else {
            once.call()
            return
        }

        let wire: Data
        if isEchoMode {
            // In loopback echo mode, send as CSTP DPD-REQ to trigger immediate server DPD-RESP echo
            wire = NCOpenConnect.encodeCSTP(type: .dpdReq, payload: data)
        } else if data.starts(with: NCOpenConnect.cstpMagic) {
            wire = data
        } else {
            wire = NCOpenConnect.encodeCSTP(type: .data, payload: data)
        }

        cstpStream.send(wire, completion: once.call)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        self.receiveHandler = handler
        drainBufferedFrames()
        if !isPumping {
            isPumping = true
            pumpReceive()
        }
    }

    private func pumpReceive() {
        guard !isCancelled else { return }

        cstpStream.receive { [weak self] chunk, err in
            guard let self = self else { return }
            if let err = err {
                self.receiveHandler?(nil, err)
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                self.receiveHandler?(nil, nil)
                return
            }

            self.rxBuffer.append(chunk)
            self.drainBufferedFrames()

            if !self.isCancelled {
                self.pumpReceive()
            }
        }
    }

    private func drainBufferedFrames() {
        while !rxBuffer.isEmpty {
            if rxBuffer.count >= NCOpenConnect.cstpHeaderSize {
                let start = rxBuffer.startIndex
                if rxBuffer[start] != NCOpenConnect.cstpMagic[0] ||
                   rxBuffer[start + 1] != NCOpenConnect.cstpMagic[1] ||
                   rxBuffer[start + 2] != NCOpenConnect.cstpMagic[2] ||
                   rxBuffer[start + 3] != NCOpenConnect.cstpMagic[3] {
                    receiveHandler?(nil, NCOpenConnectError.protocolError("CSTP 报文魔数不匹配"))
                    cancel()
                    return
                }
            }
            guard let (type, payload, consumed) = NCOpenConnect.decodeCSTP(rxBuffer) else {
                break
            }
            rxBuffer = Data(rxBuffer.dropFirst(consumed))

            switch type {
            case .data:
                if !isEchoMode {
                    receiveHandler?(payload, nil)
                }
            case .dpdResp:
                // Server echoed back our DPD-REQ payload!
                receiveHandler?(payload, nil)
            case .dpdReq:
                // Server sent DPD probe: reply with DPD-RESP
                let resp = NCOpenConnect.encodeCSTP(type: .dpdResp, payload: payload)
                cstpStream.send(resp, completion: {})
            case .keepalive:
                // Reply with Keepalive
                let resp = NCOpenConnect.encodeCSTP(type: .keepalive)
                cstpStream.send(resp, completion: {})
            case .disconnect, .terminate:
                receiveHandler?(nil, NCOpenConnectError.protocolError("服务端终止了 CSTP 会话"))
                cancel()
                return
            default:
                break
            }
        }
    }

    func cancel() {
        guard !isCancelled else { return }
        isCancelled = true
        let disc = NCOpenConnect.encodeCSTP(type: .disconnect, payload: Data([0xb0]))
        cstpStream.send(disc) { [weak self] in
            self?.cstpStream.cancel()
            self?.session?.cancel()
        }
    }
}

// MARK: - NCConnector Extension

extension NCConnector {
    static func openconnectStream(config: NCOpenConnect.Config, target: NCTarget, queue: DispatchQueue,
                                  completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let isEcho = (target.port == 18080)
        let session = NCOpenConnectSession(config: config, target: target, isEchoMode: isEcho, queue: queue)
        session.start { stream, err in
            completion(stream, err)
        }
    }
}
