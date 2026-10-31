import CryptoKit
import Foundation
import Network

// feat/nc-wg (based on astemo6/Muse NativeCore): WireGuard outbound for the native-only tunnel.
//
// docs/nc-proto-wireguard-tuic-udp.md §2, option (a): each WireGuard node is an extra lwIP netif (lwip/nc_wg.c)
// in the same lwIP instance as the TUN. NativeCore opens TCP / UDP client PCBs bound to that netif; the netif's
// IP packets are encrypted here (Noise_IKpsk2, ChaCha20-Poly1305, X25519, BLAKE2s — NCWireGuardCrypto.swift) and
// sent to the peer over one UDP NWConnection per peer. Initiator only (a client never answers handshakes).
//
// Covered: several peers (allowed-ips, longest prefix), pre-shared keys, `reserved` (WARP), mtu,
// persistent-keepalive, cookie replies (mac2), rekey / expiry / retry timers, replay window, AmneziaWG 1.0
// (jc / jmin / jmax junk, s1 / s2 padding, h1–h4 headers) and 2.0 (h1–h4 header ranges, s3 / s4 padding;
// i1–i5 signature packets are not implemented), remote-dns-resolve over the tunnel.
//
// Threading: everything here (and every nc_wg_* call) runs on NCLwIP.queue, the queue the TUN data plane also
// uses — lwIP is single-threaded. Callers on other queues get their completions on their own queue.

/// The one queue lwIP runs on (TUN data plane + WireGuard devices).
enum NCLwIP {
    static let queue = DispatchQueue(label: "nc.dataplane", qos: .userInitiated)
}

/// fix/nc-openconnect-dp: one extra lwIP netif (nc_wg.c) whatever carries its IP packets — WireGuard peers
/// (NCWGDevice) or an OpenConnect CSTP channel (NCOCDevice, NCOpenConnectNetif.swift). NCWGTCPStream and
/// NCUDPWireGuardSession only need this much, so both protocols share them (and the C bridge). NCLwIP.queue only.
protocol NCLwIPDevice: AnyObject {
    var devID: Int32 { get }
    var alive: Bool { get }
    var has4: Bool { get }
    var has6: Bool { get }
    var lastUse: Date { get set }
    func retain()
    func release()
    /// Name -> addresses for flows from this netif; `done` on NCLwIP.queue.
    func resolve(_ host: String, _ done: @escaping ([NCIP]) -> Void)
    /// An IP packet lwIP emits on this netif (valid only during the call).
    func lwipOutput(_ pkt: UnsafeBufferPointer<UInt8>)
    /// Error-message prefix for flows on this netif ("wireguard", "openconnect"). fix/nc-oc-dtls.
    var label: String { get }
}

extension NCLwIPDevice {
    var label: String { "wireguard" }

    /// The address family to dial for this device: v4 when the interface has one.
    func pick(_ ips: [NCIP]) -> NCIP? {
        if has4, let v4 = ips.first(where: { $0.isV4 }) { return v4 }
        if has6, let v6 = ips.first(where: { !$0.isV4 }) { return v6 }
        return nil
    }

    /// A/AAAA over UDP through this netif (plain / udp:// server IPs; others are skipped). NCLwIP.queue.
    func dnsOverTunnel(_ host: String, servers: [String], _ done: @escaping ([NCIP]) -> Void) {
        let ips: [NCIP] = servers.compactMap { s in
            var t = s.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("udp://") { t = String(t.dropFirst(6)) }
            if t.contains("://") { return nil }
            if let ip = NCIP(t) { return ip }
            if t.hasPrefix("["), let close = t.firstIndex(of: "]") { return NCIP(String(t[t.index(after: t.startIndex)..<close])) }
            if let colon = t.lastIndex(of: ":"), t.filter({ $0 == ":" }).count == 1 { return NCIP(String(t[..<colon])) }
            return nil
        }.filter { $0.isV4 ? has4 : has6 }
        let qtype: UInt16 = has4 ? 1 : 28
        retain()
        func attempt(_ i: Int) {
            guard alive, i < ips.count else { release(); done([]); return }
            let server = ips[i]
            let sock = nc_wg_udp_open(devID, server.isV4 ? 0 : 1)
            guard sock != 0 else { attempt(i + 1); return }
            let qid = UInt16.random(in: 0...UInt16.max)
            var q: [UInt8] = [UInt8(qid >> 8), UInt8(qid & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
            for label in host.split(separator: ".") {
                let b = Array(label.utf8).prefix(63)
                q.append(UInt8(b.count))
                q += b
            }
            q += [0, UInt8(qtype >> 8), UInt8(qtype & 0xff), 0, 1]
            var finished = false
            let finishOnce: ([NCIP]?) -> Void = { [weak self] result in
                guard !finished else { return }
                finished = true
                NCWGStack.shared.udp.removeValue(forKey: sock)
                nc_wg_udp_close(sock)
                if let result, !result.isEmpty {
                    self?.release()
                    done(result)
                } else {
                    attempt(i + 1)
                }
            }
            NCWGStack.shared.udp[sock] = { _, _, data in
                guard let r = NCWGDevice.parseDNS(data, id: qid, qtype: qtype) else { return }
                finishOnce(r)
            }
            let b = server.bytes + [UInt8](repeating: 0, count: 16 - server.bytes.count)
            _ = b.withUnsafeBufferPointer { bp in
                q.withUnsafeBufferPointer { qp in
                    nc_wg_udp_send(sock, bp.baseAddress, server.isV4 ? 0 : 1, 53, qp.baseAddress, UInt32(qp.count))
                }
            }
            NCLwIP.queue.asyncAfter(deadline: .now() + 2.5) { finishOnce(nil) }
        }
        attempt(0)
    }
}

// MARK: - Config

struct NCWGConfig {
    struct Peer {
        let server: String
        let port: Int
        let publicKey: [UInt8]
        let preSharedKey: [UInt8]
        let reserved: [UInt8]?
        let allowed: [NCCIDR]
    }

    struct Amnezia {
        /// AmneziaWG magic header (h1–h4): a single value, or — AWG 2.0 — an inclusive range the
        /// sender picks a fresh value from for every packet; the receiver accepts any value in range.
        struct Header {
            let lo: UInt32, hi: UInt32
            func pick() -> UInt32 { lo == hi ? lo : UInt32.random(in: lo...hi) }
            func contains(_ v: UInt32) -> Bool { v >= lo && v <= hi }
            func isSingle(_ v: UInt32) -> Bool { lo == hi && lo == v }
        }
        let jc: Int, jmin: Int, jmax: Int
        /// Random-prefix lengths: s1 initiation, s2 response, s3 cookie reply, s4 transport (AWG 2.0).
        let s1: Int, s2: Int, s3: Int, s4: Int
        let h1: Header, h2: Header, h3: Header, h4: Header
    }

    let privateKey: [UInt8]
    let ip4: String?
    let ip6: String?
    let mtu: Int
    let keepalive: Int
    let peers: [Peer]
    let dns: [String]
    let remoteDNS: Bool
    let amnezia: Amnezia?

    static func stripPrefix(_ s: String?) -> String? {
        guard var s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        if s.hasPrefix("["), s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        return s
    }

    static func reserved(_ v: NCJSONValue?) -> [UInt8]? {
        guard let v else { return nil }
        var out: [UInt8] = []
        if let a = v.array {
            out = a.compactMap { $0.int }.map { UInt8(clamping: $0) }
        } else if let s = v.string?.trimmingCharacters(in: .whitespaces), !s.isEmpty {
            if s.contains(",") {
                out = s.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
                    .map { UInt8(clamping: $0) }
            } else {
                var b64 = s
                while b64.count % 4 != 0 { b64.append("=") }
                if let d = Data(base64Encoded: b64) { out = [UInt8](d) }
            }
        }
        guard out.count == 3 else { return nil }
        return out.allSatisfy({ $0 == 0 }) ? nil : out
    }

    static func cidrs(_ v: NCJSONValue?) -> [NCCIDR] {
        let list = v?.array?.compactMap { $0.string } ?? []
        let out = list.compactMap { NCCIDR($0.trimmingCharacters(in: .whitespaces)) }
        return out.isEmpty ? [NCCIDR("0.0.0.0/0")!, NCCIDR("::/0")!] : out
    }

    /// nil config + reason when the node cannot run (mirrors NCSupport.wireguardUnsupported).
    static func parse(_ p: NCProxy) -> (NCWGConfig?, String?) {
        let f = p.fields
        guard let priv = NCWGCrypto.key(f["private-key"]?.string) else { return (nil, "WireGuard private-key 无效") }
        let ip4 = stripPrefix(f["ip"]?.string)
        let ip6 = stripPrefix(f["ipv6"]?.string)
        if ip4 == nil && ip6 == nil { return (nil, "WireGuard 缺少 ip / ipv6") }
        if let ip4, NCIP.parseV4(ip4) == nil { return (nil, "WireGuard ip \(ip4) 无效") }
        if let ip6, NCIP.parseV6(ip6) == nil { return (nil, "WireGuard ipv6 \(ip6) 无效") }
        var peers: [Peer] = []
        if let list = f["peers"]?.array, !list.isEmpty {
            for (i, pv) in list.enumerated() {
                guard let o = pv.object, let server = o["server"]?.string, !server.isEmpty,
                      let port = o["port"]?.int, port > 0, port < 65536,
                      let pub = NCWGCrypto.key(o["public-key"]?.string) else {
                    return (nil, "WireGuard peers[\(i)] 缺少 server / port / public-key")
                }
                let psk = NCWGCrypto.key(o["pre-shared-key"]?.string) ?? [UInt8](repeating: 0, count: 32)
                peers.append(Peer(server: server, port: port, publicKey: pub, preSharedKey: psk,
                                  reserved: reserved(o["reserved"]) ?? reserved(f["reserved"]),
                                  allowed: cidrs(o["allowed-ips"])))
            }
        } else {
            guard let server = p.server, !server.isEmpty, let port = p.port, port > 0, port < 65536,
                  let pub = NCWGCrypto.key(f["public-key"]?.string) else {
                return (nil, "WireGuard 缺少 server / port / public-key")
            }
            let psk = NCWGCrypto.key(f["pre-shared-key"]?.string) ?? [UInt8](repeating: 0, count: 32)
            peers.append(Peer(server: server, port: port, publicKey: pub, preSharedKey: psk,
                              reserved: reserved(f["reserved"]), allowed: cidrs(f["allowed-ips"])))
        }
        var awg: Amnezia?
        if let o = f["amnezia-wg-option"]?.object {
            let jc = max(0, min(o["jc"]?.int ?? 0, 128))
            let jmin = max(0, min(o["jmin"]?.int ?? 0, 1280))
            let jmax = max(jmin, min(o["jmax"]?.int ?? 0, 1280))
            let s1 = max(0, min(o["s1"]?.int ?? 0, 1132))
            let s2 = max(0, min(o["s2"]?.int ?? 0, 1188))
            let s3 = max(0, min(o["s3"]?.int ?? 0, 1216))
            let s4 = max(0, min(o["s4"]?.int ?? 0, 32))
            // h1–h4: a number / numeric string is a single value; "lo-hi" is an AWG 2.0 range.
            // 0 (or an unparseable value) keeps the standard WireGuard header, as before.
            func h(_ k: String, _ d: UInt32) -> Amnezia.Header {
                let single = Amnezia.Header(lo: d, hi: d)
                guard let v = o[k] else { return single }
                if let n = v.number, n > 0, n <= Double(UInt32.max) {
                    let x = UInt32(n); return Amnezia.Header(lo: x, hi: x)
                }
                guard let s = v.string?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return single }
                if let x = UInt32(s) { return x == 0 ? single : Amnezia.Header(lo: x, hi: x) }
                let parts = s.split(separator: "-", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count == 2, let lo = UInt32(parts[0]), let hi = UInt32(parts[1]), lo > 0, lo <= hi {
                    return Amnezia.Header(lo: lo, hi: hi)
                }
                return single
            }
            let a = Amnezia(jc: jc, jmin: jmin, jmax: jmax, s1: s1, s2: s2, s3: s3, s4: s4,
                            h1: h("h1", 1), h2: h("h2", 2), h3: h("h3", 3), h4: h("h4", 4))
            let standard = a.jc == 0 && a.s1 == 0 && a.s2 == 0 && a.s3 == 0 && a.s4 == 0
                && a.h1.isSingle(1) && a.h2.isSingle(2) && a.h3.isSingle(3) && a.h4.isSingle(4)
            awg = standard ? nil : a
        }
        let mtu = f["mtu"]?.int ?? 1408
        let dns = (f["dns"]?.array?.compactMap { $0.string }) ?? []
        return (NCWGConfig(privateKey: priv, ip4: ip4, ip6: ip6, mtu: max(576, min(mtu, 4000)),
                           keepalive: max(0, f["persistent-keepalive"]?.int ?? 0), peers: peers, dns: dns,
                           remoteDNS: f["remote-dns-resolve"]?.bool ?? false, amnezia: awg), nil)
    }

    /// Stable identity of a node's settings (device registry key): a changed node gets a new device.
    static func identity(_ p: NCProxy) -> String {
        func canon(_ v: NCJSONValue) -> String {
            switch v {
            case .null: return "null"
            case .bool(let b): return b ? "true" : "false"
            case .number(let n): return String(n)
            case .string(let s): return "\"\(s)\""
            case .array(let a): return "[" + a.map(canon).joined(separator: ",") + "]"
            case .object(let o): return "{" + o.keys.sorted().map { "\($0):\(canon(o[$0]!))" }.joined(separator: ",") + "}"
            }
        }
        return p.name + "|" + canon(.object(p.fields))
    }
}

// MARK: - Byte helpers

@inline(__always) private func le32(_ b: [UInt8], _ o: Int) -> UInt32 {
    UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
}

@inline(__always) private func le64(_ b: [UInt8], _ o: Int) -> UInt64 {
    UInt64(le32(b, o)) | UInt64(le32(b, o + 4)) << 32
}

@inline(__always) private func putLE32(_ b: inout [UInt8], _ o: Int, _ v: UInt32) {
    for i in 0..<4 { b[o + i] = UInt8((v >> (8 * UInt32(i))) & 0xff) }
}

@inline(__always) private func putLE64(_ b: inout [UInt8], _ o: Int, _ v: UInt64) {
    for i in 0..<8 { b[o + i] = UInt8((v >> (8 * UInt64(i))) & 0xff) }
}

private func randomBytes(_ n: Int) -> [UInt8] {
    (0..<n).map { _ in UInt8.random(in: 0...255) }
}

// MARK: - Stack (C bridge)

/// Owns the nc_wg callbacks and the handle → object maps. NCLwIP.queue only.
final class NCWGStack {
    static let shared = NCWGStack()

    private var installed = false
    private var devices: [String: NCWGDevice] = [:]
    fileprivate var byDev: [Int32: NCWGDevice] = [:]
    /// fix/nc-openconnect-dp: non-WireGuard netifs (OpenConnect) by device id.
    fileprivate var others: [Int32: NCLwIPDevice] = [:]
    fileprivate var tcp: [UInt32: NCWGTCPStream] = [:]
    var udp: [UInt32: (NCIP, Int, [UInt8]) -> Void] = [:]

    func install() {
        guard !installed else { return }
        var cbs = nc_wg_callbacks()
        cbs.output = ncwgOnOutput
        cbs.tcp_connected = ncwgOnConnected
        cbs.tcp_recv = ncwgOnRecv
        cbs.tcp_sent = ncwgOnSent
        cbs.tcp_err = ncwgOnErr
        cbs.udp_recv = ncwgOnUDP
        nc_wg_set_callbacks(&cbs, nil)
        installed = true
    }

    /// nc-lifecycle: tear down every device (tunnel stop / plane teardown).
    /// Caller holds NCLwIP.queue, like device(for:). Each device's timers,
    /// peer connections and lwIP-side registration live until teardown()
    /// runs; the udp handler map is dropped with them.
    func teardownAll() {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        let all = Array(devices.values)
        devices.removeAll()
        udp.removeAll()
        for d in all { d.teardown() }
    }

    /// The shared device for a node (created on first use). NCLwIP.queue.
    func device(for proxy: NCProxy) -> (NCWGDevice?, String?) {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        install()
        let key = NCWGConfig.identity(proxy)
        if let d = devices[key], d.alive { return (d, nil) }
        let (cfg, why) = NCWGConfig.parse(proxy)
        guard let cfg else { return (nil, why) }
        guard let d = NCWGDevice(key: key, name: proxy.name, cfg: cfg) else {
            return (nil, "WireGuard 接口创建失败（lwIP netif）")
        }
        devices[key] = d
        byDev[d.devID] = d
        StartupLog.write("wireguard: \(proxy.name) up — \(cfg.peers.count) peer(s), mtu \(cfg.mtu)"
            + (cfg.amnezia != nil ? ", amnezia" : "") + (cfg.peers.contains { $0.reserved != nil } ? ", reserved" : ""))
        return (d, nil)
    }

    fileprivate func forget(_ d: NCWGDevice) {
        if devices[d.key] === d { devices.removeValue(forKey: d.key) }
        byDev.removeValue(forKey: d.devID)
    }

    func registerDevice(_ d: NCWGDevice) {
        install()
        byDev[d.devID] = d
    }

    func unregisterDevice(_ d: NCWGDevice) {
        byDev.removeValue(forKey: d.devID)
    }

    /// fix/nc-openconnect-dp: an OpenConnect netif (its packets go to lwipOutput). NCLwIP.queue.
    func registerOther(_ d: NCLwIPDevice) {
        install()
        others[d.devID] = d
    }

    func unregisterOther(_ d: NCLwIPDevice) {
        if others[d.devID] === d { others.removeValue(forKey: d.devID) }
    }
}

@_cdecl("ncwgOnOutput")
func ncwgOnOutput(_ ctx: UnsafeMutableRawPointer?, _ dev: Int32, _ pkt: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let pkt else { return }
    if let d = NCWGStack.shared.byDev[dev] {
        d.output([UInt8](UnsafeBufferPointer(start: pkt, count: Int(len))))
    } else if let o = NCWGStack.shared.others[dev] {
        // fix/nc-openconnect-dp: framed straight from lwIP's buffer (no intermediate copy).
        o.lwipOutput(UnsafeBufferPointer(start: pkt, count: Int(len)))
    }
}

@_cdecl("ncwgOnConnected")
func ncwgOnConnected(_ ctx: UnsafeMutableRawPointer?, _ conn: UInt32, _ err: Int32) {
    NCWGStack.shared.tcp[conn]?.lwipConnected()
}

@_cdecl("ncwgOnRecv")
func ncwgOnRecv(_ ctx: UnsafeMutableRawPointer?, _ conn: UInt32, _ data: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let s = NCWGStack.shared.tcp[conn] else { return }
    if let data { s.lwipData(Data(bytes: data, count: Int(len))) } else { s.lwipFIN() }
}

@_cdecl("ncwgOnSent")
func ncwgOnSent(_ ctx: UnsafeMutableRawPointer?, _ conn: UInt32, _ len: UInt32) {
    NCWGStack.shared.tcp[conn]?.lwipSent(Int(len))
}

@_cdecl("ncwgOnErr")
func ncwgOnErr(_ ctx: UnsafeMutableRawPointer?, _ conn: UInt32, _ err: Int32) {
    guard let s = NCWGStack.shared.tcp.removeValue(forKey: conn) else { return }
    s.lwipError(err)
}

@_cdecl("ncwgOnUDP")
func ncwgOnUDP(_ ctx: UnsafeMutableRawPointer?, _ sock: UInt32, _ src: UnsafePointer<UInt8>?, _ srcPort: UInt16,
               _ is6: Int32, _ data: UnsafePointer<UInt8>?, _ len: UInt32) {
    guard let src, let data, let h = NCWGStack.shared.udp[sock] else { return }
    let ip: NCIP = is6 != 0 ? .v6((0..<16).map { src[$0] })
        : .v4(UInt32(src[0]) << 24 | UInt32(src[1]) << 16 | UInt32(src[2]) << 8 | UInt32(src[3]))
    h(ip, Int(srcPort), [UInt8](UnsafeBufferPointer(start: data, count: Int(len))))
}

// MARK: - Device

/// One WireGuard interface (node): lwIP netif + peers + timers. NCLwIP.queue only.
final class NCWGDevice: NCLwIPDevice {
    let key: String
    let name: String
    let cfg: NCWGConfig
    let devID: Int32
    let staticPriv: Curve25519.KeyAgreement.PrivateKey
    let staticPub: [UInt8]
    private(set) var peers: [NCWGPeer] = []
    private var routes: [(NCCIDR, NCWGPeer)] = []
    private var timer: DispatchSourceTimer?
    private(set) var alive = true
    private var users = 0
    var lastUse = Date()
    private var dnsCache: [String: ([NCIP], Date)] = [:]

    var has4: Bool { cfg.ip4 != nil }
    var has6: Bool { cfg.ip6 != nil }

    init?(key: String, name: String, cfg: NCWGConfig) {
        guard let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: cfg.privateKey) else { return nil }
        let m = UInt16(clamping: cfg.mtu)
        let id: Int32
        switch (cfg.ip4, cfg.ip6) {
        case let (a?, b?): id = a.withCString { pa in b.withCString { pb in nc_wg_dev_add(pa, pb, m) } }
        case let (a?, nil): id = a.withCString { pa in nc_wg_dev_add(pa, nil, m) }
        case let (nil, b?): id = b.withCString { pb in nc_wg_dev_add(nil, pb, m) }
        default: return nil
        }
        guard id > 0 else { return nil }
        self.key = key
        self.name = name
        self.cfg = cfg
        self.devID = id
        staticPriv = priv
        staticPub = [UInt8](priv.publicKey.rawRepresentation)
        peers = cfg.peers.map { NCWGPeer(device: self, cfg: $0) }
        for p in peers { for c in p.cfg.allowed { routes.append((c, p)) } }
        routes.sort { $0.0.bits > $1.0.bits }
        let t = DispatchSource.makeTimerSource(queue: NCLwIP.queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    func retain() {
        users += 1
        lastUse = Date()
        setTickFast(true)
    }

    // Power (2026-10-25 merge review): 250 ms only while a stream / UDP session uses the device; an unused device
    // (lingering up to 180 s before teardown) ticks once a second — rekey / keepalive / lwIP close timers are all
    // second-scale, and the next flow restores 250 ms at once via retain().
    private var tickFast = true

    private func setTickFast(_ fast: Bool) {
        guard fast != tickFast, let timer else { return }
        tickFast = fast
        let interval: DispatchTimeInterval = fast ? .milliseconds(250) : .seconds(1)
        timer.schedule(deadline: .now() + interval, repeating: interval,
                       leeway: fast ? .milliseconds(25) : .milliseconds(200))
    }

    func release() {
        users = max(0, users - 1)
        lastUse = Date()
    }

    /// An IP packet from the netif toward the peers (cryptokey routing by destination).
    fileprivate func output(_ pkt: [UInt8]) {
        guard alive, let dst = NCWGDevice.address(pkt, source: false) else { return }
        guard let peer = routes.first(where: { $0.0.contains(dst) })?.1 else { return }
        peer.sendPacket(pkt)
    }

    /// Optional extra inbound filter, consulted after the cryptokey source
    /// check in `input(_:from:)`. The Tailscale client installs it to enforce
    /// the control-delivered PacketFilter ACLs; returning false drops the
    /// packet. Nil means no extra filtering (plain WireGuard behavior).
    var inboundPacketHook: (([UInt8]) -> Bool)?

    /// A decrypted packet from `peer`: accepted only when its source is in the peer's allowed-ips.
    fileprivate func input(_ pkt: [UInt8], from peer: NCWGPeer) {
        guard alive, let src = NCWGDevice.address(pkt, source: true),
              routes.first(where: { $0.0.contains(src) })?.1 === peer else { return }
        if let hook = inboundPacketHook, !hook(pkt) { return }
        pkt.withUnsafeBufferPointer { nc_wg_input(devID, $0.baseAddress, UInt32($0.count)) }
    }

    /// Finds peer whose AllowedIPs contains destination IP.
    func peer(for ip: NCIP) -> NCWGPeer? {
        routes.first(where: { $0.0.contains(ip) })?.1
    }

    /// Feeds incoming raw WireGuard packet (e.g. from DERP) into the peer matching public key.
    func handleIncomingPacket(from peerPublicKey: [UInt8], data: [UInt8]) {
        guard alive else { return }
        guard let peer = peers.first(where: { $0.cfg.publicKey == peerPublicKey }) else { return }
        peer.handleIncomingPacket(data)
    }

    /// Count of peers that currently have an active WireGuard session.
    var activeRelayCount: Int {
        peers.filter { $0.hasSession }.count
    }

    /// Dynamically update peers (for Tailscale netmap updates). Runs on NCLwIP.queue.
    func updatePeers(_ newPeers: [NCWGConfig.Peer], customSender: ((NCWGPeer, [UInt8]) -> Void)? = nil) {
        dispatchPrecondition(condition: .onQueue(NCLwIP.queue))
        guard alive else { return }
        let newKeys = Set(newPeers.map { $0.publicKey })
        for p in peers where !newKeys.contains(p.cfg.publicKey) {
            p.close()
        }
        var updated: [NCWGPeer] = []
        for pcfg in newPeers {
            if let existing = peers.first(where: { $0.cfg.publicKey == pcfg.publicKey }) {
                updated.append(existing)
            } else {
                let p = NCWGPeer(device: self, cfg: pcfg)
                if let customSender {
                    p.customSender = { [weak p] bytes in
                        guard let p else { return }
                        customSender(p, bytes)
                    }
                }
                updated.append(p)
            }
        }
        self.peers = updated
        var newRoutes: [(NCCIDR, NCWGPeer)] = []
        for p in peers { for c in p.cfg.allowed { newRoutes.append((c, p)) } }
        newRoutes.sort { $0.0.bits > $1.0.bits }
        self.routes = newRoutes
    }

    static func address(_ p: [UInt8], source: Bool) -> NCIP? {
        guard let first = p.first else { return nil }
        switch first >> 4 {
        case 4:
            guard p.count >= 20 else { return nil }
            let o = source ? 12 : 16
            return .v4(UInt32(p[o]) << 24 | UInt32(p[o + 1]) << 16 | UInt32(p[o + 2]) << 8 | UInt32(p[o + 3]))
        case 6:
            guard p.count >= 40 else { return nil }
            let o = source ? 8 : 24
            return .v6(Array(p[o..<(o + 16)]))
        default:
            return nil
        }
    }

    private func tick() {
        guard alive else { return }
        nc_wg_poll()
        let now = Date()
        for p in peers { p.tick(now) }
        // Memory first: an unused device (no stream / UDP session for 3 min) is torn down; the next flow
        // re-creates it with a fresh handshake.
        if users == 0, now.timeIntervalSince(lastUse) > 180 { teardown(); return }
        setTickFast(users > 0)
    }

    func teardown() {
        guard alive else { return }
        alive = false
        timer?.cancel()
        timer = nil
        for p in peers { p.close() }
        NCWGStack.shared.forget(self)
        nc_wg_dev_remove(devID) // fires tcp_err for anything still open
        StartupLog.write("wireguard: \(name) idle, interface removed")
    }

    /// NCLwIPDevice: WireGuard routes by cryptokey (output(_:) copies once for the peer's encryption).
    func lwipOutput(_ pkt: UnsafeBufferPointer<UInt8>) { output([UInt8](pkt)) }

    // MARK: Name resolution

    private static let fakeV4 = NCCIDR("198.18.0.0/15")!
    private static let fakeV6 = NCCIDR("fdfe:dcba:9876::/48")!

    func resolve(_ host0: String, _ done: @escaping ([NCIP]) -> Void) {
        let host = host0.hasPrefix("[") && host0.hasSuffix("]") ? String(host0.dropFirst().dropLast()) : host0
        if let ip = NCIP(host) { done([ip]); return }
        let key = host.lowercased()
        if let hit = dnsCache[key], hit.1 > Date() { done(hit.0); return }
        let finish: ([NCIP]) -> Void = { [weak self] ips in
            if let self, !ips.isEmpty {
                if self.dnsCache.count > 128 { self.dnsCache.removeAll() }
                self.dnsCache[key] = (ips, Date().addingTimeInterval(120))
            }
            done(ips)
        }
        let servers = cfg.dns
        if cfg.remoteDNS && !servers.isEmpty {
            dnsOverTunnel(host, servers: servers, finish)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let sys = NCWGDevice.systemResolve(host)
            NCLwIP.queue.async { [weak self] in
                guard let self else { done([]); return }
                let real = sys.filter { !NCWGDevice.fakeV4.contains($0) && !NCWGDevice.fakeV6.contains($0) }
                if !real.isEmpty { finish(real); return }
                // The process resolver answered with a fake IP (includeAllNetworks routes our own lookups into
                // the tunnel) or failed: ask through the WireGuard tunnel instead.
                let fallback = servers.isEmpty ? (self.has4 ? ["1.1.1.1", "8.8.8.8"] : ["2606:4700:4700::1111"]) : servers
                self.dnsOverTunnel(host, servers: fallback, finish)
            }
        }
    }

    static func systemResolve(_ host: String) -> [NCIP] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0 else { return [] }
        defer { freeaddrinfo(res) }
        var out: [NCIP] = []
        var p = res
        while let ai = p {
            if let sa = ai.pointee.ai_addr {
                if ai.pointee.ai_family == AF_INET {
                    sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                        out.append(.v4(UInt32(bigEndian: sin.pointee.sin_addr.s_addr)))
                    }
                } else if ai.pointee.ai_family == AF_INET6 {
                    sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                        var a = sin6.pointee.sin6_addr
                        out.append(.v6(withUnsafeBytes(of: &a) { [UInt8]($0) }))
                    }
                }
            }
            p = ai.pointee.ai_next
        }
        return out
    }

    static func parseDNS(_ d: [UInt8], id: UInt16, qtype: UInt16) -> [NCIP]? {
        guard d.count >= 12, UInt16(d[0]) << 8 | UInt16(d[1]) == id, d[2] & 0x80 != 0 else { return nil }
        if d[3] & 0x0f != 0 { return [] }
        let qd = Int(d[4]) << 8 | Int(d[5])
        let an = Int(d[6]) << 8 | Int(d[7])
        var off = 12
        func skipName() -> Bool {
            while off < d.count {
                let l = Int(d[off])
                if l == 0 { off += 1; return true }
                if l & 0xC0 == 0xC0 { off += 2; return off <= d.count }
                off += l + 1
            }
            return false
        }
        for _ in 0..<qd {
            guard skipName(), off + 4 <= d.count else { return [] }
            off += 4
        }
        var out: [NCIP] = []
        for _ in 0..<an {
            guard skipName(), off + 10 <= d.count else { break }
            let type = UInt16(d[off]) << 8 | UInt16(d[off + 1])
            let rdlen = Int(d[off + 8]) << 8 | Int(d[off + 9])
            off += 10
            guard off + rdlen <= d.count else { break }
            if type == qtype, type == 1, rdlen == 4 {
                out.append(.v4(UInt32(d[off]) << 24 | UInt32(d[off + 1]) << 16 | UInt32(d[off + 2]) << 8 | UInt32(d[off + 3])))
            } else if type == qtype, type == 28, rdlen == 16 {
                out.append(.v6(Array(d[off..<(off + 16)])))
            }
            off += rdlen
        }
        return out
    }
}

// MARK: - Peer (Noise IKpsk2 initiator, sessions, timers)

final class NCWGPeer {
    private static let rekeyAfterTime: TimeInterval = 120
    private static let rejectAfterTime: TimeInterval = 180
    private static let rekeyAttemptTime: TimeInterval = 90
    private static let rekeyTimeout: TimeInterval = 5
    private static let keepaliveTimeout: TimeInterval = 10
    private static let rekeyAfterMessages: UInt64 = 1 << 60
    private static let rejectAfterMessages: UInt64 = UInt64.max - (1 << 13)
    private static let maxQueued = 128

    unowned let device: NCWGDevice
    let cfg: NCWGConfig.Peer
    private let mac1Key: [UInt8]
    private let cookieKey: [UInt8]
    private let staticDH: [UInt8]?

    private struct Handshake {
        let localIndex: UInt32
        let ephemeral: Curve25519.KeyAgreement.PrivateKey
        let chainKey: [UInt8]
        let hash: [UInt8]
        let mac1: [UInt8]
    }

    private final class Keypair {
        let send: SymmetricKey
        let recv: SymmetricKey
        let localIndex: UInt32
        let remoteIndex: UInt32
        let created = Date()
        var sendCounter: UInt64 = 0
        var replay = NCWGReplayWindow()
        init(send: [UInt8], recv: [UInt8], localIndex: UInt32, remoteIndex: UInt32) {
            self.send = SymmetricKey(data: send)
            self.recv = SymmetricKey(data: recv)
            self.localIndex = localIndex
            self.remoteIndex = remoteIndex
        }
    }

    private var conn: NWConnection?
    private var handshake: Handshake?
    private var attemptStarted: Date?
    private var lastInitiation = Date.distantPast
    private var retryJitter: TimeInterval = 0
    private var current: Keypair?
    private var previous: Keypair?
    private var queued: [[UInt8]] = []
    private var cookie: [UInt8]?
    private var cookieAt = Date.distantPast
    private var lastSentAny = Date.distantPast
    private var lastSentData = Date.distantPast
    private var lastRecvAny = Date.distantPast
    private var lastRecvData = Date.distantPast
    var customSender: (([UInt8]) -> Void)?

    var hasSession: Bool {
        usable(current) != nil
    }

    func handleIncomingPacket(_ d0: [UInt8]) {
        received(d0)
    }

    init(device: NCWGDevice, cfg: NCWGConfig.Peer) {
        self.device = device
        self.cfg = cfg
        mac1Key = NCBlake2s.hash(NCWGCrypto.labelMAC1, cfg.publicKey)
        cookieKey = NCBlake2s.hash(NCWGCrypto.labelCookie, cfg.publicKey)
        staticDH = NCWGCrypto.dh(device.staticPriv, cfg.publicKey)
    }

    private var amnezia: NCWGConfig.Amnezia? { device.cfg.amnezia }

    private func usable(_ k: Keypair?, _ now: Date = Date()) -> Keypair? {
        guard let k, now.timeIntervalSince(k.created) < NCWGPeer.rejectAfterTime,
              k.sendCounter < NCWGPeer.rejectAfterMessages else { return nil }
        return k
    }

    // MARK: Sending

    func sendPacket(_ pkt: [UInt8]) {
        let now = Date()
        lastSentData = now
        device.lastUse = now
        if let k = usable(current, now) {
            sendTransport(k, pkt)
            if handshake == nil,
               now.timeIntervalSince(k.created) > NCWGPeer.rekeyAfterTime || k.sendCounter > NCWGPeer.rekeyAfterMessages {
                initiate()
            }
            return
        }
        if queued.count >= NCWGPeer.maxQueued { queued.removeFirst() }
        queued.append(pkt)
        if handshake == nil { initiate() }
    }

    private func sendKeepalive() {
        guard let k = usable(current) else { return }
        sendTransport(k, [])
    }

    private func sendTransport(_ k: Keypair, _ pkt: [UInt8]) {
        let mtu = device.cfg.mtu
        var plain = pkt
        if !plain.isEmpty {
            var padded = (plain.count + 15) & ~15
            if padded > mtu { padded = max(plain.count, mtu) }
            if padded > plain.count { plain += [UInt8](repeating: 0, count: padded - plain.count) }
        }
        let counter = k.sendCounter
        k.sendCounter += 1
        guard let sealed = NCWGCrypto.seal(key: k.send, counter: counter, plain, aad: []) else { return }
        var msg = [UInt8](repeating: 0, count: 16)
        if let a = amnezia { putLE32(&msg, 0, a.h4.pick()) } else { msg[0] = 4 }
        putLE32(&msg, 4, k.remoteIndex)
        putLE64(&msg, 8, counter)
        msg += sealed
        applyReserved(&msg)
        if let a = amnezia, a.s4 > 0 { msg = randomBytes(a.s4) + msg } // AWG 2.0 transport prefix
        sendRaw(msg)
        lastSentAny = Date()
    }

    /// WARP-style `reserved`: bytes 1–3 of every message we send (after the MACs, as Clash.Meta / sing-box do).
    private func applyReserved(_ msg: inout [UInt8]) {
        guard amnezia == nil, let r = cfg.reserved, msg.count >= 4 else { return }
        msg[1] = r[0]; msg[2] = r[1]; msg[3] = r[2]
    }

    private func initiate() {
        let now = Date()
        if handshake != nil, now.timeIntervalSince(lastInitiation) < NCWGPeer.rekeyTimeout { return }
        guard let staticDH else { return }
        if attemptStarted == nil { attemptStarted = now }
        lastInitiation = now
        retryJitter = Double.random(in: 0...0.333)

        let eph = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = [UInt8](eph.publicKey.rawRepresentation)
        var c = NCBlake2s.hash(NCWGCrypto.construction)
        var h = NCBlake2s.hash(c, NCWGCrypto.identifier)
        h = NCBlake2s.hash(h, cfg.publicKey)
        c = NCWGCrypto.kdf(1, key: c, input: ephPub)[0]
        h = NCBlake2s.hash(h, ephPub)
        guard let es = NCWGCrypto.dh(eph, cfg.publicKey) else { return }
        var kk = NCWGCrypto.kdf(2, key: c, input: es)
        c = kk[0]
        guard let encStatic = NCWGCrypto.seal(key: SymmetricKey(data: kk[1]), counter: 0, device.staticPub, aad: h) else { return }
        h = NCBlake2s.hash(h, encStatic)
        kk = NCWGCrypto.kdf(2, key: c, input: staticDH)
        c = kk[0]
        guard let encTS = NCWGCrypto.seal(key: SymmetricKey(data: kk[1]), counter: 0, NCWGCrypto.tai64n(now), aad: h) else { return }
        h = NCBlake2s.hash(h, encTS)

        var local = UInt32.random(in: 1...UInt32.max)
        while local == current?.localIndex || local == previous?.localIndex { local = UInt32.random(in: 1...UInt32.max) }
        var msg = [UInt8](repeating: 0, count: 148)
        if let a = amnezia { putLE32(&msg, 0, a.h1.pick()) } else { msg[0] = 1 }
        putLE32(&msg, 4, local)
        msg.replaceSubrange(8..<40, with: ephPub)
        msg.replaceSubrange(40..<88, with: encStatic)
        msg.replaceSubrange(88..<116, with: encTS)
        let mac1 = NCBlake2s.mac(key: mac1Key, Array(msg[0..<116]))
        msg.replaceSubrange(116..<132, with: mac1)
        if let cookie, now.timeIntervalSince(cookieAt) < 120 - 5 {
            msg.replaceSubrange(132..<148, with: NCBlake2s.mac(key: cookie, Array(msg[0..<132])))
        }
        handshake = Handshake(localIndex: local, ephemeral: eph, chainKey: c, hash: h, mac1: mac1)
        applyReserved(&msg)
        if let a = amnezia {
            // AmneziaWG 1.0: jc junk datagrams of jmin…jmax random bytes, then the initiation behind s1 random bytes.
            for _ in 0..<a.jc {
                let n = a.jmax > a.jmin ? Int.random(in: a.jmin...a.jmax) : a.jmin
                if n > 0 { sendRaw(randomBytes(n)) }
            }
            if a.s1 > 0 { msg = randomBytes(a.s1) + msg }
        }
        sendRaw(msg)
        lastSentAny = now
    }

    // MARK: Receiving

    private func received(_ d0: [UInt8]) {
        dbgRecvTotal += 1
        NSLog("[wg-prod] recv #%d: %d B type=%d from %@:%d", dbgRecvTotal, d0.count,
              d0.count >= 4 ? Int(d0[0]) : -1, cfg.server, cfg.port)
        var d = d0
        if let a = amnezia {
            // AWG 2.0: the header value only has to fall inside the configured range, and the
            // cookie / transport messages carry their own s3 / s4 random prefixes.
            if d.count == 92 + a.s2, a.h2.contains(le32(d, a.s2)) {
                handleResponse(Array(d[a.s2...]))
            } else if d.count == 64 + a.s3, a.h3.contains(le32(d, a.s3)) {
                handleCookie(Array(d[a.s3...]))
            } else if d.count >= 32 + a.s4, a.h4.contains(le32(d, a.s4)) {
                handleTransport(Array(d[a.s4...]))
            }
            return
        }
        guard d.count >= 4 else { return }
        d[1] = 0; d[2] = 0; d[3] = 0 // reserved bytes (WARP) are not part of the type
        switch d[0] {
        case 2 where d.count == 92: handleResponse(d)
        case 3 where d.count == 64: handleCookie(d)
        case 4 where d.count >= 32: handleTransport(d)
        default: break
        }
    }

    private func handleResponse(_ m: [UInt8]) {
        guard let hs = handshake, le32(m, 8) == hs.localIndex else {
            NSLog("[wg-prod] response DROPPED: handshake=%@ receiverIndex=%d localIndex=%d",
                  handshake == nil ? "nil" : "pending", m.count >= 12 ? Int(le32(m, 8)) : -1,
                  handshake.map { Int($0.localIndex) } ?? -1)
            return
        }
        // mac1 is not checked: it is the responder's DoS cookie; the AEAD below authenticates the message.
        let remote = le32(m, 4)
        let erPub = Array(m[12..<44])
        let empty = Array(m[44..<60])
        var c = NCWGCrypto.kdf(1, key: hs.chainKey, input: erPub)[0]
        var h = NCBlake2s.hash(hs.hash, erPub)
        guard let ee = NCWGCrypto.dh(hs.ephemeral, erPub), let se = NCWGCrypto.dh(device.staticPriv, erPub) else { return }
        c = NCWGCrypto.kdf(1, key: c, input: ee)[0]
        c = NCWGCrypto.kdf(1, key: c, input: se)[0]
        let k3 = NCWGCrypto.kdf(3, key: c, input: cfg.preSharedKey)
        c = k3[0]
        h = NCBlake2s.hash(h, k3[1])
        guard NCWGCrypto.open(key: SymmetricKey(data: k3[2]), counter: 0, empty, aad: h) != nil else {
            NSLog("[wg-prod] response DROPPED: empty-message AEAD open failed")
            return
        }
        NSLog("[wg-prod] handshake response ACCEPTED — session keys derived")
        let keys = NCWGCrypto.kdf(2, key: c, input: [])
        let kp = Keypair(send: keys[0], recv: keys[1], localIndex: hs.localIndex, remoteIndex: remote)
        previous = current
        current = kp
        handshake = nil
        attemptStarted = nil
        let now = Date()
        lastRecvAny = now
        let backlog = queued
        queued.removeAll()
        if backlog.isEmpty {
            sendTransport(kp, []) // confirms the session to the responder
        } else {
            for p in backlog { sendTransport(kp, p) }
        }
    }

    private func handleCookie(_ m: [UInt8]) {
        guard let hs = handshake, le32(m, 4) == hs.localIndex,
              let c = NCWGCrypto.xopen(key: cookieKey, nonce24: Array(m[8..<32]), Array(m[32..<64]), aad: hs.mac1),
              c.count == 16 else { return }
        cookie = c
        cookieAt = Date()
    }

    private func handleTransport(_ m: [UInt8]) {
        let idx = le32(m, 4)
        let counter = le64(m, 8)
        let kp: Keypair
        if let c = current, c.localIndex == idx { kp = c }
        else if let p = previous, p.localIndex == idx { kp = p }
        else { return }
        let now = Date()
        guard now.timeIntervalSince(kp.created) < NCWGPeer.rejectAfterTime, counter < NCWGPeer.rejectAfterMessages,
              let plain = NCWGCrypto.open(key: kp.recv, counter: counter, Array(m[16...]), aad: []),
              kp.replay.accept(counter) else { return }
        lastRecvAny = now
        guard !plain.isEmpty else { return } // keepalive
        var pkt = plain
        switch pkt[0] >> 4 {
        case 4 where pkt.count >= 20:
            let total = Int(pkt[2]) << 8 | Int(pkt[3])
            guard total >= 20, total <= pkt.count else { return }
            pkt.removeSubrange(total...)
        case 6 where pkt.count >= 40:
            let total = 40 + (Int(pkt[4]) << 8 | Int(pkt[5]))
            guard total <= pkt.count else { return }
            pkt.removeSubrange(total...)
        default:
            return
        }
        lastRecvData = now
        device.input(pkt, from: self)
    }

    // MARK: Timers

    func tick(_ now: Date) {
        if handshake != nil, now.timeIntervalSince(lastInitiation) >= NCWGPeer.rekeyTimeout + retryJitter {
            if let started = attemptStarted, now.timeIntervalSince(started) > NCWGPeer.rekeyAttemptTime {
                // Give up until new traffic asks again.
                NSLog("[wg-prod] handshake GIVE UP after %.0f s: sent %d initiation(s), received %d packet(s) total",
                      now.timeIntervalSince(started), dbgSentInit, dbgRecvTotal)
                handshake = nil
                attemptStarted = nil
                queued.removeAll()
                lastSentData = .distantPast
            } else {
                initiate()
            }
        }
        if let c = current, now.timeIntervalSince(c.created) >= NCWGPeer.rejectAfterTime { current = nil }
        if let p = previous, now.timeIntervalSince(p.created) >= NCWGPeer.rejectAfterTime { previous = nil }
        let live = usable(current, now) != nil
        let ka = TimeInterval(device.cfg.keepalive)
        if ka > 0, now.timeIntervalSince(lastSentAny) >= ka {
            if live { sendKeepalive() } else if handshake == nil, !queued.isEmpty { initiate() }
        }
        // Passive keepalive: data came in and we had nothing to send for 10 s.
        if live, lastRecvData > lastSentAny, now.timeIntervalSince(lastRecvData) >= NCWGPeer.keepaliveTimeout {
            sendKeepalive()
        }
        // Data went out but nothing came back for 15 s: the session may be dead — new handshake.
        if handshake == nil, lastSentData > lastRecvAny,
           now.timeIntervalSince(lastSentData) >= NCWGPeer.keepaliveTimeout + NCWGPeer.rekeyTimeout {
            lastSentData = now // one attempt per silent period
            initiate()
        }
    }

    // MARK: UDP to the endpoint

    // fix/kit-wireguard-prod probe counters (NSLog only; no behavior change).
    private var dbgSentInit = 0
    private var dbgSentTotal = 0
    private var dbgRecvTotal = 0

    private func sendRaw(_ bytes: [UInt8]) {
        if let customSender {
            customSender(bytes)
            return
        }
        dbgSentTotal += 1
        if bytes.first == 1 {
            dbgSentInit += 1
            NSLog("[wg-prod] send initiation #%d (%d B) to %@:%d conn=%@", dbgSentInit, bytes.count,
                  cfg.server, cfg.port, conn == nil ? "opening" : "open")
        }
        if conn == nil { openConnection() }
        conn?.send(content: Data(bytes), completion: .idempotent)
    }

    private func openConnection() {
        let port = NWEndpoint.Port(rawValue: UInt16(clamping: cfg.port)) ?? .any
        let c = NWConnection(host: NWEndpoint.Host(cfg.server), port: port,
                             using: NCOutboundBinding.params(.udp, host: cfg.server))
        c.stateUpdateHandler = { [weak self, weak c] state in
            guard let self, let c, self.conn === c else { return }
            switch state {
            case .ready:
                NSLog("[wg-prod] endpoint conn ready -> %@", String(describing: c.endpoint))
                self.receiveLoop(c)
            case .waiting(let e):
                NSLog("[wg-prod] endpoint conn waiting: %@", e.localizedDescription)
            case .failed(let e):
                NSLog("[wg-prod] endpoint conn FAILED: %@", e.localizedDescription)
                self.conn = nil
            case .cancelled:
                NSLog("[wg-prod] endpoint conn cancelled")
                self.conn = nil
            default:
                break
            }
        }
        conn = c
        c.start(queue: NCLwIP.queue)
    }

    private func receiveLoop(_ c: NWConnection) {
        c.receiveMessage { [weak self, weak c] data, _, _, error in
            guard let self, let c, self.conn === c else { return }
            if let data, !data.isEmpty { self.received([UInt8](data)) }
            if error == nil { self.receiveLoop(c) }
        }
    }

    func close() {
        conn?.cancel()
        conn = nil
        handshake = nil
        current = nil
        previous = nil
        queued.removeAll()
    }
}

// MARK: - TCP relay

/// A TCP connection originated from the WireGuard netif. NCRelayStream calls may come from any queue; state lives
/// on NCLwIP.queue; completions go to `callerQueue`. Receive-side backpressure: the lwIP window is reopened only
/// for bytes handed to a receive handler.
final class NCWGTCPStream: NCRelayStream {
    private let device: NCLwIPDevice
    private let callerQueue: DispatchQueue
    private var connID: UInt32 = 0
    private var connected = false
    private var released = false
    private var closed = false
    private var fin = false
    private var failure: Error?
    private var inbox = Data()
    private var outbox = Data()
    /// nc-sessions-flow (approximation): send completions by cumulative offset. WireGuard gives no
    /// per-send completion signal, so a completion fires once its bytes were written into the lwIP
    /// send buffer AND the in-flight (written, not yet tcp_sent-acked) total is below 64 KB; above
    /// that it waits for acks to drain. Fired on callerQueue like this stream's other completions.
    private var sendWaiters: [(end: Int, once: NCCallOnce)] = []
    private var appendedTotal = 0
    private var writtenTotal = 0
    private var ackedTotal = 0
    private var handler: ((Data?, Error?) -> Void)?
    private var onConnect: ((Error?) -> Void)?

    init(device: NCLwIPDevice, callerQueue: DispatchQueue) {
        self.device = device
        self.callerQueue = callerQueue
    }

    /// NCLwIP.queue. The device was retained by the caller; this stream releases it once.
    func start(ip: NCIP, port: Int, completion: @escaping (Error?) -> Void) {
        onConnect = completion
        let b = ip.bytes
        connID = b.withUnsafeBufferPointer { nc_wg_tcp_connect(device.devID, $0.baseAddress, ip.isV4 ? 0 : 1, UInt16(clamping: port)) }
        guard connID != 0 else {
            finishConnect(NCConnector.Failure.handshake("\(device.label): no lwIP PCB for \(ip.string):\(port)"))
            releaseDevice()
            return
        }
        NCWGStack.shared.tcp[connID] = self
        NCLwIP.queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, !self.connected, !self.closed, self.connID != 0 else { return }
            NCWGStack.shared.tcp.removeValue(forKey: self.connID)
            nc_wg_tcp_abort(self.connID)
            self.connID = 0
            self.closed = true
            self.finishConnect(NCConnector.Failure.handshake("\(self.device.label): connect timeout (no handshake / no answer)"))
            self.releaseDevice()
        }
    }

    private func finishConnect(_ err: Error?) {
        guard let cb = onConnect else { return }
        onConnect = nil
        callerQueue.async { cb(err) }
    }

    private func releaseDevice() {
        guard !released else { return }
        released = true
        device.release()
    }

    // lwIP callbacks (NCLwIP.queue)

    fileprivate func lwipConnected() {
        connected = true
        finishConnect(nil)
        flush()
    }

    fileprivate func lwipData(_ d: Data) {
        inbox.append(d)
        device.lastUse = Date()
        if let h = handler {
            handler = nil
            deliver(h)
        }
    }

    fileprivate func lwipFIN() {
        fin = true
        if inbox.isEmpty, let h = handler {
            handler = nil
            callerQueue.async { h(nil, nil) }
        }
    }

    fileprivate func lwipError(_ err: Int32) {
        connID = 0
        drainSendWaiters()
        let e = NCConnector.Failure.handshake("\(device.label): connection reset (lwIP \(err))")
        if !connected {
            closed = true
            finishConnect(e)
        } else {
            failure = e
            if inbox.isEmpty, let h = handler {
                handler = nil
                callerQueue.async { h(nil, e) }
            }
        }
        releaseDevice()
    }

    fileprivate func flush() {
        guard connected, connID != 0, !outbox.isEmpty else { return }
        let before = outbox.count
        defer {
            writtenTotal += before - outbox.count
            checkSendWaiters()
        }
        // nc-perf: write from a running offset instead of copying the remainder per partial
        // write (a Data(dropFirst) per tcp_write is O(n^2) for a large outbox); compact once.
        var off = 0
        while off < outbox.count {
            let n = outbox.withUnsafeBytes { raw -> Int32 in
                nc_wg_tcp_write(connID, raw.bindMemory(to: UInt8.self).baseAddress?.advanced(by: off), UInt32(raw.count - off))
            }
            if n < 0 { outbox.removeAll(); return }
            if n == 0 { break } // send buffer full: the next tcp_sent continues
            off += Int(n)
        }
        if off == outbox.count { outbox = Data() }
        else if off > 0 { outbox = Data(outbox.dropFirst(off)) }
    }

    private func deliver(_ h: @escaping (Data?, Error?) -> Void) {
        if !inbox.isEmpty {
            let d = inbox
            inbox = Data()
            if connID != 0 { nc_wg_tcp_recved(connID, UInt32(d.count)) }
            callerQueue.async { h(d, nil) }
        } else if let f = failure {
            callerQueue.async { h(nil, f) }
        } else if fin || closed {
            callerQueue.async { h(nil, nil) }
        } else {
            handler = h
        }
    }

    /// NCLwIP.queue: the peer acked `len` more bytes (the C tcp_sent callback).
    fileprivate func lwipSent(_ len: Int) {
        ackedTotal += len
        flush()
        checkSendWaiters()
    }

    /// NCLwIP.queue.
    private func checkSendWaiters() {
        let inflight = writtenTotal - ackedTotal
        let due = sendWaiters.filter { $0.end <= writtenTotal && (inflight < 65536 || $0.end <= ackedTotal) }
        guard !due.isEmpty else { return }
        sendWaiters.removeAll { w in due.contains { $0.end == w.end && $0.once === w.once } }
        callerQueue.async { due.forEach { $0.once.call() } }
    }

    /// NCLwIP.queue: fire every pending send completion (teardown: the bytes will never be acked,
    /// but no sender may be left waiting).
    private func drainSendWaiters() {
        let all = sendWaiters
        sendWaiters = []
        if !all.isEmpty { callerQueue.async { all.forEach { $0.once.call() } } }
    }

    // NCRelayStream

    func send(_ data: Data) {
        NCLwIP.queue.async { [self] in
            guard !closed, !data.isEmpty else { return }
            device.lastUse = Date()
            outbox.append(data)
            flush()
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        NCLwIP.queue.async { [self] in
            guard !closed, !data.isEmpty else {
                callerQueue.async { once.call() }
                return
            }
            device.lastUse = Date()
            appendedTotal += data.count
            sendWaiters.append((appendedTotal, once))
            outbox.append(data)
            flush()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        NCLwIP.queue.async { [self] in deliver(handler) }
    }

    func cancel() {
        NCLwIP.queue.async { [self] in
            guard !closed else { return }
            closed = true
            drainSendWaiters()
            if connID != 0 {
                NCWGStack.shared.tcp.removeValue(forKey: connID)
                nc_wg_tcp_close(connID)
                connID = 0
            }
            outbox = Data()
            inbox = Data()
            if let h = handler {
                handler = nil
                callerQueue.async { h(nil, nil) }
            }
            finishConnect(NCConnector.Failure.handshake("\(device.label): cancelled"))
            releaseDevice()
        }
    }
}

// MARK: - UDP session

/// UDP through a WireGuard node for one TUN session: a lwIP UDP socket per address family on the WG netif.
final class NCUDPWireGuardSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let queue: DispatchQueue
    private var device: NCLwIPDevice?
    private var sock4: UInt32 = 0
    private var sock6: UInt32 = 0
    private var cancelled = false

    /// `acquire` (NCLwIP.queue) yields the node's netif device: WireGuard by default; fix/nc-openconnect-dp passes
    /// NCOCStack's for OpenConnect, whose device may still be connecting (its resolve waits for the tunnel).
    init(proxy: NCProxy, queue: DispatchQueue,
         acquire: ((NCProxy) -> (NCLwIPDevice?, String?))? = nil) {
        self.queue = queue
        NCLwIP.queue.async { [self] in
            guard !cancelled else { return }
            let d: NCLwIPDevice?
            let why: String?
            if let acquire {
                let r = acquire(proxy)
                d = r.0
                why = r.1
            } else {
                let r = NCWGStack.shared.device(for: proxy)
                d = r.0
                why = r.1
            }
            if let d { d.retain(); device = d }
            else { StartupLog.write("\(proxy.type): \(proxy.name) UDP unavailable: \(why ?? "-")") }
        }
    }

    private func socket(v4: Bool) -> UInt32 {
        guard let d = device else { return 0 }
        if v4, sock4 != 0 { return sock4 }
        if !v4, sock6 != 0 { return sock6 }
        let s = nc_wg_udp_open(d.devID, v4 ? 0 : 1)
        guard s != 0 else { return 0 }
        NCWGStack.shared.udp[s] = { [weak self] _, _, data in
            guard let self, !self.cancelled else { return }
            let payload = Data(data)
            self.queue.async { self.onReply(payload) }
        }
        if v4 { sock4 = s } else { sock6 = s }
        return s
    }

    func send(_ data: Data, to target: NCTarget) {
        NCLwIP.queue.async { [self] in
            guard !cancelled, let d = device, d.alive else { return }
            d.lastUse = Date()
            d.resolve(target.host) { [weak self] ips in
                guard let self, !self.cancelled, let ip = d.pick(ips) else { return }
                let s = self.socket(v4: ip.isV4)
                guard s != 0 else { return }
                let b = ip.bytes
                _ = b.withUnsafeBufferPointer { bp in
                    data.withUnsafeBytes { raw in
                        nc_wg_udp_send(s, bp.baseAddress, ip.isV4 ? 0 : 1, UInt16(clamping: target.port),
                                       raw.bindMemory(to: UInt8.self).baseAddress, UInt32(raw.count))
                    }
                }
            }
        }
    }

    func cancel() {
        NCLwIP.queue.async { [self] in
            guard !cancelled else { return }
            cancelled = true
            for s in [sock4, sock6] where s != 0 {
                NCWGStack.shared.udp.removeValue(forKey: s)
                if device?.alive == true { nc_wg_udp_close(s) }
            }
            sock4 = 0
            sock6 = 0
            device?.release()
            device = nil
        }
    }
}

// MARK: - Connector entry

extension NCConnector {
    /// Hooks wireguardStream into the shared connector (NCConnector lives in Shared/, compiled into the App too).
    static func installWireGuardDialer() {
        wireguardDialer = { proxy, target, queue, completion in
            wireguardStream(proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    /// Hooks tailscaleStream into the shared connector.
    static func installTailscaleDialer() {
        tailscaleDialer = { proxy, target, queue, completion in
            NCTailscaleClient.dial(proxy: proxy, target: target, queue: queue, completion: completion)
        }
    }

    /// TCP through a WireGuard node (feat/nc-wg). Completion on `queue`, exactly once.
    static func wireguardStream(proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        NCLwIP.queue.async {
            let (dev, why) = NCWGStack.shared.device(for: proxy)
            guard let dev else {
                queue.async { completion(nil, Failure.unsupported(why ?? "wireguard")) }
                return
            }
            dev.retain()
            dev.resolve(target.host) { ips in
                guard dev.alive, let ip = dev.pick(ips) else {
                    dev.release()
                    queue.async { completion(nil, Failure.handshake("wireguard: cannot resolve \(target.host)")) }
                    return
                }
                let s = NCWGTCPStream(device: dev, callerQueue: queue)
                s.start(ip: ip, port: target.port) { err in completion(err == nil ? s : nil, err) }
            }
        }
    }
}
