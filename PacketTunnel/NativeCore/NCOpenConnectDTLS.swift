import Foundation
import Network

// fix/nc-oc-dtls: the OpenConnect DTLS data channel (ocserv "PSK-NEGOTIATE").
//
// After CONNECT the CSTP channel is up and carries traffic at once; in parallel the device opens one UDP flow to
// X-DTLS-Port and runs NCDTLS12PSK (PSK = TLS exporter of the CSTP session, session id = X-DTLS-App-ID). Once the
// handshake finishes, uplink IP packets that fit X-DTLS-MTU go as DTLS records ([type][packet]); ocserv switches its
// downlink to DTLS as well. CSTP stays open (control, DPD, oversized packets, and the fallback):
//   • handshake not done within 6 s (UDP blocked / filtered / refused) → closed, CSTP only ("fallback");
//   • DTLS dead (no answer to DTLS DPD within 2×X-DTLS-DPD + 5 s) or alert → closed, CSTP only;
//   • a CSTP reconnect starts a fresh DTLS attempt with the new App-ID.
// Memory: one NWConnection + the record state; datagrams are processed as they arrive (no queue).
// NCLwIP.queue only.

final class NCOCDTLSChannel {
    enum Phase: Equatable { case handshaking, up, closed }

    private(set) var phase: Phase = .handshaking
    private let conn: NWConnection
    private let dtls: NCDTLS12PSK
    private let dpd: TimeInterval
    private let keepalive: TimeInterval
    private var started = Date()
    private var lastRetransmit = Date()
    private var lastRx = Date()
    private var lastTx = Date()
    private var lastDPD = Date.distantPast
    private(set) var packetsOut = 0
    private(set) var packetsIn = 0
    private(set) var dpdResponses = 0

    /// A DATA payload (IP packet) from the server; valid only during the call.
    var onData: ((Data) -> Void)?
    var onUp: (() -> Void)?
    /// The channel ended (reason); the device falls back to CSTP.
    var onClosed: ((String) -> Void)?

    static let handshakeTimeout: TimeInterval = 6

    init(host: String, port: Int, psk: Data, sessionID: Data, dpd: Int, keepalive: Int) {
        dtls = NCDTLS12PSK(psk: psk, sessionID: sessionID)
        self.dpd = TimeInterval(max(dpd, 5))
        self.keepalive = TimeInterval(max(keepalive, 0))
        let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? 443)
        conn = NWConnection(to: ep, using: NCOutboundBinding.params(.udp, host: host))
    }

    func start() {
        started = Date()
        conn.stateUpdateHandler = { [weak self] st in
            guard let self, self.phase != .closed else { return }
            switch st {
            case .ready:
                self.lastRetransmit = Date()
                self.transmit(self.dtls.start())
                self.receive()
            case .failed(let e):
                self.close("UDP \(e.localizedDescription)")
            case .waiting(let e):
                // UDP "waiting" (no route / ICMP unreachable): the handshake timer decides; note it only.
                StartupLog.write("openconnect: DTLS waiting (\(e.localizedDescription))")
            default:
                break
            }
        }
        conn.start(queue: NCLwIP.queue)
    }

    private func receive() {
        conn.receiveMessage { [weak self] data, _, _, err in
            guard let self, self.phase != .closed else { return }
            if let data, !data.isEmpty { self.handle(data) }
            if let err {
                // ICMP port unreachable surfaces here (ECONNREFUSED): blocked → fallback.
                self.close("UDP \(err.localizedDescription)")
                return
            }
            if self.phase != .closed { self.receive() }
        }
    }

    private func handle(_ datagram: Data) {
        let (out, app) = dtls.receive(datagram)
        transmit(out)
        if case .failed(let why) = dtls.state {
            close(why)
            return
        }
        if phase == .handshaking, dtls.state == .established {
            phase = .up
            lastRx = Date()
            lastTx = Date()
            onUp?()
        }
        guard phase == .up else { return }
        if !app.isEmpty { lastRx = Date() }
        for rec in app {
            guard let t = rec.first else { continue }
            switch t {
            case NCOpenConnect.PayloadType.data.rawValue:
                packetsIn += 1
                onData?(rec.dropFirst())
            case NCOpenConnect.PayloadType.dpdReq.rawValue:
                sendControl(.dpdResp, Data(rec.dropFirst()))
            case NCOpenConnect.PayloadType.dpdResp.rawValue:
                dpdResponses += 1
            case NCOpenConnect.PayloadType.disconnect.rawValue, NCOpenConnect.PayloadType.terminate.rawValue:
                close("server DTLS disconnect")
                return
            default:
                break // KEEPALIVE, unknown
            }
        }
    }

    private func transmit(_ datagrams: [Data]) {
        for d in datagrams where !d.isEmpty {
            conn.send(content: d, completion: .idempotent)
        }
    }

    /// One IP packet as a DTLS DATA record. false when the channel is not up (caller uses CSTP).
    func sendPacket(_ pkt: UnsafeBufferPointer<UInt8>) -> Bool {
        guard phase == .up, let base = pkt.baseAddress else { return false }
        var payload = Data(capacity: 1 + pkt.count)
        payload.append(NCOpenConnect.PayloadType.data.rawValue)
        payload.append(base, count: pkt.count)
        guard let rec = dtls.seal(payload) else { return false }
        packetsOut += 1
        lastTx = Date()
        conn.send(content: rec, completion: .contentProcessed { [weak self] err in
            if let err, let self { self.close("send: \(err.localizedDescription)") }
        })
        return true
    }

    private func sendControl(_ t: NCOpenConnect.PayloadType, _ payload: Data = Data()) {
        guard let rec = dtls.seal(Data([t.rawValue]) + payload) else { return }
        lastTx = Date()
        conn.send(content: rec, completion: .idempotent)
    }

    /// Called from the device's timer (every 0.25–1 s).
    func tick(_ now: Date) {
        switch phase {
        case .handshaking:
            if now.timeIntervalSince(started) > Self.handshakeTimeout {
                close("DTLS handshake timeout (\(Int(Self.handshakeTimeout)) s, UDP blocked?)")
            } else if now.timeIntervalSince(lastRetransmit) >= 1 {
                lastRetransmit = now
                transmit(dtls.retransmit())
            }
        case .up:
            let idle = now.timeIntervalSince(lastRx)
            if idle > 2 * dpd + 5 {
                close("DTLS DPD timeout (\(Int(idle)) s)")
            } else if idle > dpd, now.timeIntervalSince(lastDPD) > dpd {
                lastDPD = now
                sendControl(.dpdReq)
            } else if keepalive > 0, now.timeIntervalSince(lastTx) > keepalive {
                sendControl(.keepalive)
            }
        case .closed:
            break
        }
    }

    /// Sends one DTLS DPD request now (tests).
    func debugSendDPD() {
        lastDPD = Date()
        sendControl(.dpdReq)
    }

    func close(_ why: String) {
        guard phase != .closed else { return }
        let wasUp = phase == .up
        phase = .closed
        if wasUp, let bye = dtls.closeNotify() { conn.send(content: bye, completion: .idempotent) }
        conn.stateUpdateHandler = nil
        conn.cancel()
        let cb = onClosed
        onClosed = nil
        onUp = nil
        onData = nil
        cb?(why)
    }

    /// RFC 5705 exporter "EXPORTER-openconnect-psk" (no context, 32 bytes) of the CSTP TLS connection.
    static func exportPSK(_ tls: NWConnection) -> Data? {
        guard let md = tls.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else { return nil }
        let sec = md.securityProtocolMetadata
        let label = Array(NCDTLS12PSK.exporterLabel.utf8CString.dropLast()) // no NUL
        let secret = label.withUnsafeBufferPointer { lp in
            sec_protocol_metadata_create_secret(sec, lp.count, lp.baseAddress!, 32)
        }
        guard let secret else { return nil }
        let out = Data(referencing: (secret as AnyObject) as! NSData)
        return out.count == 32 ? out : nil
    }
}
