import Foundation
import Network
import Security

/// OpenConnect control plane: HTTPS auth (XML / form) and the CSTP `CONNECT /CSCOSSLC/tunnel` upgrade. The
/// upgraded TLS stream carries IP packets, so the data plane is a lwIP netif inside the packet tunnel
/// (PacketTunnel/NativeCore/NCOpenConnectNetif.swift, fix/nc-openconnect-dp); this file only hands it the stream,
/// the tunnel parameters (X-CSTP-Address / -MTU / -DNS …) and any bytes read past the response header.
/// Auth state machine and framing from astemo6's PR #159 (feat/nc-openconnect).
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

/// An established CSTP channel: the TLS stream (CSTP frames from here on), the server's tunnel parameters and the
/// bytes that arrived right behind the CONNECT response header (already CSTP frames).
struct NCOpenConnectTunnel {
    let stream: NCStream
    let params: NCOpenConnect.TunnelParameters
    let leftover: Data
}

final class NCOpenConnectSession {
    let config: NCOpenConnect.Config
    let queue: DispatchQueue

    private(set) var channelState: NCOpenConnectChannelState = .disconnected
    private(set) var activeMode: NCOpenConnectMode = .cstp
    private(set) var dtlsFallbackReason: NCOpenConnectFallbackReason?
    var tunnelParams: NCOpenConnect.TunnelParameters?
    /// The session cookie (webvpn). Kept for reconnects: ocserv / ASA accept a fresh CONNECT with it until the
    /// server's cookie timeout, and hand back the same address, so lwIP flows survive a dropped TCP channel.
    private(set) var webvpnCookie: String?

    var onStateChange: ((NCOpenConnectChannelState) -> Void)?

    private var accumulatedCookies: [String: String] = [:]
    private var authStream: NCStream?
    private var cstpStream: NCStream?
    private var isClosed = false
    /// Bumped by cancel() and every start/reconnect: a late callback of an abandoned attempt is dropped.
    private var generation = 0

    init(config: NCOpenConnect.Config, target: NCTarget? = nil, queue: DispatchQueue) {
        self.config = config
        self.queue = queue
    }

    /// Authenticates (unless a cookie is configured) and upgrades to CSTP. Completion on `queue`, exactly once.
    func start(completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        queue.async {
            self.isClosed = false
            self.generation += 1
            let gen = self.generation
            let done = self.once(gen, completion)
            if let preCookie = self.config.cookie, !preCookie.isEmpty {
                self.webvpnCookie = NCOpenConnect.cookieValue(preCookie)
                self.startCSTPTunnel(gen: gen, completion: done)
            } else {
                self.startAuth(gen: gen, completion: done)
            }
        }
    }

    /// A new CSTP channel for the same session (dead TCP / DPD timeout). Tries the kept cookie first; when the
    /// server refuses it (expired) and credentials exist, authenticates again. Completion on `queue`, exactly once.
    func reconnect(completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        queue.async {
            self.isClosed = false
            self.generation += 1
            let gen = self.generation
            let done = self.once(gen, completion)
            self.cstpStream?.cancel()
            self.cstpStream = nil
            guard self.webvpnCookie != nil else { self.startAuth(gen: gen, completion: done); return }
            self.startCSTPTunnel(gen: gen) { [weak self] r in
                guard let self else { return }
                if case .failure(let e) = r, case NCOpenConnectError.tunnelUpgradeFailed(let why) = e,
                   why.contains("401") || why.contains("403"),
                   self.config.cookie == nil || self.config.cookie?.isEmpty == true,
                   let u = self.config.username, !u.isEmpty, self.config.password != nil {
                    self.webvpnCookie = nil
                    self.accumulatedCookies.removeAll()
                    self.startAuth(gen: gen, completion: done)
                    return
                }
                done(r)
            }
        }
    }

    /// Exactly-once, generation-checked completion (an attempt abandoned by cancel / a newer attempt never reports).
    private func once(_ gen: Int, _ completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void)
        -> (Result<NCOpenConnectTunnel, Error>) -> Void {
        var fired = false
        return { [weak self] r in
            guard !fired else { return }
            fired = true
            guard let self, !self.isClosed, self.generation == gen else {
                if case .success(let t) = r { t.stream.cancel() }
                completion(.failure(NCOpenConnectError.cancelled))
                return
            }
            completion(r)
        }
    }

    // MARK: - HTTPS Authentication State Machine

    private func startAuth(gen: Int, completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        updateState(.authenticating)
        let stream = NCStream(to: config.server, port: config.port,
                              tlsServerName: config.sni,
                              allowInsecure: config.skipCertVerify,
                              queue: queue)
        self.authStream = stream

        stream.start { [weak self] err in
            guard let self = self, self.generation == gen else { stream.cancel(); return }
            if let err = err {
                completion(.failure(NCOpenConnectError.connectionFailed(err.localizedDescription)))
                return
            }
            // Send initial XML request
            let initXML = NCOpenConnect.buildInitXML()
            let req = [
                "POST / HTTP/1.1",
                "Host: \(self.hostHeader)",
                "User-Agent: \(self.config.userAgent)",
                "Accept: */*",
                "Accept-Encoding: identity",
                "X-Transcend-Version: 1",
                "X-Aggregate-Auth: 1",
                "Content-Type: text/xml; charset=utf-8",
                "Content-Length: \(initXML.utf8.count)",
                "",
                initXML
            ].joined(separator: "\r\n")

            stream.send(Data(req.utf8))
            self.readAuthStep(stream: stream, rxBuffer: Data(), round: 1, gen: gen, completion: completion)
        }
    }

    private var hostHeader: String {
        let h = config.server.contains(":") && !config.server.hasPrefix("[") ? "[\(config.server)]" : config.server
        return config.port == 443 ? h : "\(h):\(config.port)"
    }

    private func readAuthStep(stream: NCStream, rxBuffer: Data = Data(), round: Int, gen: Int,
                              completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        guard round <= 6 else {
            completion(.failure(NCOpenConnectError.authenticationFailed("认证交互轮数超过上限 (6)")))
            return
        }
        guard rxBuffer.count < 256 * 1024 else {
            completion(.failure(NCOpenConnectError.authenticationFailed("认证响应过大")))
            return
        }

        stream.receive { [weak self] chunk, err in
            guard let self = self, self.generation == gen else { return }
            if let err = err {
                completion(.failure(NCOpenConnectError.authenticationFailed("网络中断: \(err.localizedDescription)")))
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                completion(.failure(NCOpenConnectError.authenticationFailed("服务端过早关闭连接")))
                return
            }

            var localBuffer = rxBuffer
            localBuffer.append(chunk)

            if let (msg, consumed) = NCOpenConnect.HTTPMessage.parse(data: localBuffer) {
                let rest = Data(localBuffer.dropFirst(consumed))
                self.handleAuthResponse(msg: msg, stream: stream, remainingData: rest, round: round, gen: gen,
                                        completion: completion)
            } else {
                // Wait for more HTTP data
                self.readAuthStep(stream: stream, rxBuffer: localBuffer, round: round, gen: gen, completion: completion)
            }
        }
    }

    private func handleAuthResponse(msg: NCOpenConnect.HTTPMessage, stream: NCStream, remainingData: Data, round: Int,
                                    gen: Int, completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
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
            self.startCSTPTunnel(gen: gen, completion: completion)
            return
        }

        if msg.statusCode == 401 || authResp?.type == .error {
            let desc = authResp?.message ?? authResp?.error ?? "HTTP \(msg.statusCode) 凭据错误"
            completion(.failure(NCOpenConnectError.authenticationFailed(desc)))
            return
        }

        if let authResp = authResp, authResp.type == .authRequest {
            // A second form after the password (OTP, new-password, …) cannot be answered from a static node.
            if round > 1, authResp.inputs["password"] != nil || authResp.inputs.isEmpty {
                let desc = authResp.error ?? authResp.message ?? "服务端再次要求输入凭据"
                completion(.failure(NCOpenConnectError.authenticationFailed(desc)))
                return
            }
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
            for (ck, cv) in accumulatedCookies.sorted(by: { $0.key < $1.key }) { cookieList.append("\(ck)=\(cv)") }
            let cookieHeader = cookieList.joined(separator: "; ")

            var reqLines = [
                "POST \(targetPath) HTTP/1.1",
                "Host: \(hostHeader)",
                "User-Agent: \(config.userAgent)",
                "Accept: */*",
                "X-Transcend-Version: 1",
                "X-Aggregate-Auth: 1",
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Length: \(formBody.utf8.count)"
            ]
            if !cookieHeader.isEmpty {
                reqLines.append("Cookie: \(cookieHeader)")
            }
            reqLines.append("")
            reqLines.append(formBody)

            let wireReq = reqLines.joined(separator: "\r\n")
            stream.send(Data(wireReq.utf8))
            self.readAuthStep(stream: stream, rxBuffer: remainingData, round: round + 1, gen: gen, completion: completion)
            return
        }

        // Unknown or empty response
        completion(.failure(NCOpenConnectError.authenticationFailed("无法识别的认证响应: \(bodyStr.prefix(200))")))
    }

    // MARK: - CSTP Tunnel Upgrade

    private func startCSTPTunnel(gen: Int, completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        guard let cookie = self.webvpnCookie, !cookie.isEmpty else {
            completion(.failure(NCOpenConnectError.authenticationFailed("缺少 webvpn 会话令牌")))
            return
        }

        updateState(.upgradingTunnel)
        let stream = NCStream(to: config.server, port: config.port,
                              tlsServerName: config.sni,
                              allowInsecure: config.skipCertVerify,
                              queue: queue)
        self.cstpStream = stream

        stream.start { [weak self] err in
            guard let self = self, self.generation == gen else { stream.cancel(); return }
            if let err = err {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed(err.localizedDescription)))
                return
            }

            var lines = [
                "CONNECT /CSCOSSLC/tunnel HTTP/1.1",
                "Host: \(self.hostHeader)",
                "User-Agent: \(self.config.userAgent)",
                "Cookie: webvpn=\(cookie)",
                "X-CSTP-Version: 1",
                "X-CSTP-Hostname: \(self.config.localHostname ?? "localhost")",
                "X-CSTP-Base-MTU: \(NCOpenConnect.defaultBaseMTU)",
                "X-CSTP-MTU: \(self.config.mtu)",
                "X-CSTP-Address-Type: IPv6,IPv4",
                "X-CSTP-Full-IPv6-Capability: true",
            ]
            // Only offer DTLS when the node allows it; the data plane runs over CSTP either way (fallback below).
            if self.config.dtls { lines.append("X-DTLS-CipherSuite: PSK-NEGOTIATE") }
            lines += ["", ""]
            stream.send(Data(lines.joined(separator: "\r\n").utf8))
            self.readTunnelResponse(stream: stream, gen: gen, completion: completion)
        }
    }

    private func readTunnelResponse(stream: NCStream, rxBuffer: Data = Data(), gen: Int,
                                    completion: @escaping (Result<NCOpenConnectTunnel, Error>) -> Void) {
        stream.receive { [weak self] chunk, err in
            guard let self = self, self.generation == gen else { return }
            if let err = err {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed(err.localizedDescription)))
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("服务端未响应 CONNECT 请求")))
                return
            }

            var current = rxBuffer
            current.append(chunk)
            guard current.count < 64 * 1024 else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("CONNECT 响应头过大")))
                return
            }

            let crlf2 = Data([0x0d, 0x0a, 0x0d, 0x0a])
            guard let r = current.range(of: crlf2) else {
                self.readTunnelResponse(stream: stream, rxBuffer: current, gen: gen, completion: completion)
                return
            }
            let headerBytes = current.subdata(in: current.startIndex..<r.lowerBound)
            let rest = Data(current.subdata(in: r.upperBound..<current.endIndex))

            guard let headerStr = String(data: headerBytes, encoding: .utf8) ?? String(data: headerBytes, encoding: .isoLatin1) else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("无法解析响应头")))
                return
            }

            let lines = headerStr.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            guard let statusLine = lines.first else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("缺少状态行")))
                return
            }
            let parts = statusLine.split(separator: " ", maxSplits: 2)
            guard parts.count >= 2, parts[1] == "200" else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("HTTP 协商被拒: \(statusLine)")))
                return
            }

            // Repeated headers (X-CSTP-DNS, X-CSTP-Split-Include, …) are kept in order.
            var headers: [(String, String)] = []
            for line in lines.dropFirst() {
                guard let idx = line.firstIndex(of: ":") else { continue }
                let k = line[..<idx].trimmingCharacters(in: .whitespaces)
                let v = line[line.index(after: idx)...].trimmingCharacters(in: .whitespaces)
                headers.append((k, v))
            }

            let params = NCOpenConnect.TunnelParameters.parse(headerList: headers)
            guard params.assignedIPv4 != nil || params.assignedIPv6 != nil else {
                completion(.failure(NCOpenConnectError.tunnelUpgradeFailed("服务端未分配隧道地址 (X-CSTP-Address)")))
                return
            }
            self.tunnelParams = params
            self.updateState(.cstpActive)
            self.activeMode = .cstp

            // DTLS 1.2 channel evaluation (falls back to CSTP explicitly; see evaluateDTLSChannel).
            self.evaluateDTLSChannel()

            completion(.success(NCOpenConnectTunnel(stream: stream, params: params, leftover: rest)))
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

        // On Darwin / Network.framework, DTLS 1.2 PSK cannot bind arbitrary ClientHello.legacy_session_id
        // (X-DTLS-App-ID) via public sec_protocol_options API. ocserv rejects UDP handshakes without matching
        // App-ID in session ID. Therefore, Network.framework DTLS cannot fulfill the server's session correlation.
        // As designed in S1 and ordered by dispatcher, fall back cleanly and explicitly to CSTP.
        triggerDTLSFallback(reason: .platformUnsupported)
    }

    func triggerDTLSFallback(reason: NCOpenConnectFallbackReason) {
        self.dtlsFallbackReason = reason
        self.activeMode = .cstp
        updateState(.dtlsFallbackToCSTP(reason: reason))
    }

    private func updateState(_ state: NCOpenConnectChannelState) {
        self.channelState = state
        onStateChange?(state)
    }

    /// The data plane took over the CSTP stream (NCOCDevice owns and closes it from now on); cancel() / reconnect()
    /// must no longer touch it.
    func releaseTunnelStream() {
        cstpStream = nil
    }

    func cancel() {
        guard !isClosed else { return }
        isClosed = true
        generation += 1
        updateState(.closed)
        authStream?.cancel()
        authStream = nil
        cstpStream?.cancel()
        cstpStream = nil
    }

    /// The CSTP stream now belongs to the data plane (it cancels it); the session forgets it.
    func releaseTunnelStream() {
        cstpStream = nil
    }
}
