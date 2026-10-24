import Darwin
import Foundation
import NetworkExtension

/// Moves IP packets between `NEPacketTunnelFlow` (public NetworkExtension API) and the mihomo core.
///
/// The core gets one end of an `AF_UNIX`/`SOCK_DGRAM` socket pair as its tun "file descriptor"; every
/// datagram is utun-framed (4-byte big-endian address family + IP packet), which is what sing-tun's
/// darwin reader expects. No private utun descriptor scanning is involved.
///
/// Design follows Hako-Adapter's PacketFlowBridge (TokenPLS/Hako-Adapter, now ProjectClash/Clash-Adapter,
/// GPL-3.0): non-blocking socket pair with enlarged buffers, a bounded queue toward the core with a
/// write source for back-pressure, batched drains toward the system, and short back-off on ENOBUFS.
/// This is an independent, smaller implementation for this project (also GPL-3.0).
final class PacketFlowBridge {
    private static let headerSize = PacketFraming.headerSize
    private static let maxPacket = 65_535
    private static let socketBuffer: Int32 = 1 << 20
    private static let maxDrainBatch = 64
    private static let queueKey = DispatchSpecificKey<UInt8>()

    private let flow: NEPacketTunnelFlow
    private let queue = DispatchQueue(label: "mihomo.packetflow", qos: .userInitiated)
    private let maxPendingPackets = 512
    private let maxPendingBytes = 2 << 20

    private var flowFD: Int32 = -1
    private var coreFD: Int32 = -1
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceResumed = false
    private var running = false
    private var generation: UInt64 = 0
    private var readOutstanding = false
    private var backoffScheduled = false
    private var backoffSteps = 0

    /// Packets read from the system, waiting to be sent to the core. E 线 #2: kept as the system's own
    /// `Data` plus its family and framed only at send time (`PacketFraming.send`, two iovecs), instead
    /// of a new header + copy `Data` per packet.
    private struct Outbound {
        let packet: Data
        let family: Int32
        var size: Int { PacketFraming.headerSize + packet.count }
    }
    private var pending: [Outbound] = []
    private var pendingHead = 0
    private var pendingBytes = 0
    private var recvBuffer = [UInt8](repeating: 0, count: PacketFlowBridge.maxPacket + PacketFlowBridge.headerSize)

    private(set) var packetsIn: UInt64 = 0
    private(set) var packetsOut: UInt64 = 0
    private(set) var dropped: UInt64 = 0

    var onFailure: ((String) -> Void)?

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
        queue.setSpecific(key: Self.queueKey, value: 1)
    }

    deinit { stop() }

    /// Creates the socket pair and starts pumping. Returns a descriptor for the core (a dup the core owns
    /// and closes on shutdown; the bridge keeps its own copy).
    func start() throws -> Int32 {
        try queue.sync { () throws -> Int32 in
            if running { return dup(coreFD) }
            var fds: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else { throw Self.posix("socketpair") }
            flowFD = fds[0]
            coreFD = fds[1]
            for fd in [flowFD, coreFD] {
                let fl = fcntl(fd, F_GETFL)
                _ = fcntl(fd, F_SETFL, fl | O_NONBLOCK)
                _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
                var size = Self.socketBuffer
                _ = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
                size = Self.socketBuffer
                _ = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
            }
            running = true
            generation &+= 1
            installSources()
            readFromSystem()
            let handed = dup(coreFD)
            guard handed >= 0 else { throw Self.posix("dup") }
            return handed
        }
    }

    func stop() {
        if DispatchQueue.getSpecific(key: Self.queueKey) != nil {
            stopOnQueue()
        } else {
            queue.sync { stopOnQueue() }
        }
    }

    private func stopOnQueue() {
        guard running || flowFD >= 0 else { return }
        running = false
        generation &+= 1
        pending.removeAll(keepingCapacity: false)
        pendingHead = 0
        pendingBytes = 0
        if let ws = writeSource {
            if !writeSourceResumed { ws.resume() }
            ws.cancel()
            writeSource = nil
            writeSourceResumed = false
        }
        if let rs = readSource {
            rs.cancel() // cancel handler closes the flow end
            readSource = nil
        } else if flowFD >= 0 {
            close(flowFD)
        }
        flowFD = -1
        if coreFD >= 0 { close(coreFD); coreFD = -1 }
    }

    var stats: String { "packets in \(packetsIn), out \(packetsOut), dropped \(dropped)" }

    // MARK: - system → core

    private func readFromSystem() {
        guard running, !readOutstanding else { return }
        readOutstanding = true
        let gen = generation
        flow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.queue.async {
                guard self.running, self.generation == gen else { return }
                self.readOutstanding = false
                for (i, p) in packets.enumerated() {
                    let family = i < protocols.count ? protocols[i].int32Value : PacketFraming.family(of: p)
                    self.enqueue(Outbound(packet: p, family: family))
                }
                self.packetsIn &+= UInt64(packets.count)
                self.flushToCore()
                self.readFromSystem()
            }
        }
    }

    private func enqueue(_ out: Outbound) {
        let size = out.size
        guard pending.count - pendingHead < maxPendingPackets, pendingBytes + size <= maxPendingBytes else {
            dropped &+= 1
            return
        }
        pending.append(out)
        pendingBytes += size
    }

    private func flushToCore() {
        guard running, !backoffScheduled else { return }
        while pendingHead < pending.count {
            let out = pending[pendingHead]
            let size = out.size
            let n = PacketFraming.send(fd: flowFD, family: out.family, packet: out.packet)
            if n == size {
                pendingHead += 1
                pendingBytes -= size
                continue
            }
            let e = errno
            if n < 0 && e == EINTR { continue }
            if n < 0 && (e == EAGAIN || e == EWOULDBLOCK) {
                compact()
                resumeWriteSource()
                return
            }
            if n < 0 && (e == ENOBUFS || e == ENOMEM) {
                compact()
                scheduleBackoff()
                return
            }
            // Oversized or broken datagram: drop it rather than wedge the queue.
            dropped &+= 1
            pendingHead += 1
            pendingBytes -= size
            if n < 0 && (e == EPIPE || e == EBADF || e == ECONNRESET) {
                fail("send errno \(e)")
                return
            }
        }
        pending.removeAll(keepingCapacity: true)
        pendingHead = 0
        pendingBytes = 0
        backoffSteps = 0
        suspendWriteSource()
    }

    private func compact() {
        guard pendingHead > 0, pendingHead >= 128 || pendingHead * 2 >= pending.count else { return }
        pending.removeFirst(pendingHead)
        pendingHead = 0
    }

    private func scheduleBackoff() {
        suspendWriteSource()
        guard !backoffScheduled else { return }
        backoffScheduled = true
        backoffSteps = min(backoffSteps + 1, 6)
        let delayMs = 1 << (backoffSteps - 1) // 1, 2, 4 … 32 ms
        let gen = generation
        queue.asyncAfter(deadline: .now() + .milliseconds(delayMs)) { [weak self] in
            guard let self, self.running, self.generation == gen else { return }
            self.backoffScheduled = false
            self.flushToCore()
        }
    }

    // MARK: - core → system

    private func drainFromCore() {
        guard running else { return }
        let fd = flowFD
        var rounds = 0
        while rounds < 8 {
            rounds += 1
            var packets: [Data] = []
            var protocols: [NSNumber] = []
            packets.reserveCapacity(Self.maxDrainBatch)
            protocols.reserveCapacity(Self.maxDrainBatch)
            while packets.count < Self.maxDrainBatch {
                let n = recvBuffer.withUnsafeMutableBytes { buf -> Int in recv(fd, buf.baseAddress, buf.count, MSG_DONTWAIT) }
                if n < 0 {
                    let e = errno
                    if e == EINTR { continue }
                    if e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS || e == ENOMEM { break }
                    fail("recv errno \(e)")
                    return
                }
                guard n > Self.headerSize else { continue }
                let (family, packet) = recvBuffer.withUnsafeBytes { raw -> (Int32, Data) in
                    let f = UInt32(raw[0]) << 24 | UInt32(raw[1]) << 16 | UInt32(raw[2]) << 8 | UInt32(raw[3])
                    return (Int32(bitPattern: f), Data(bytes: raw.baseAddress! + Self.headerSize, count: n - Self.headerSize))
                }
                guard family == AF_INET || family == AF_INET6 else { dropped &+= 1; continue }
                packets.append(packet)
                protocols.append(NSNumber(value: family))
            }
            if packets.isEmpty { return }
            if flow.writePackets(packets, withProtocols: protocols) {
                packetsOut &+= UInt64(packets.count)
            } else {
                dropped &+= UInt64(packets.count)
            }
            if packets.count < Self.maxDrainBatch { return }
        }
        // Still more queued: yield the queue to the other direction, then continue.
        queue.async { [weak self] in self?.drainFromCore() }
    }

    // MARK: - sources

    private func installSources() {
        let fd = flowFD
        let rs = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        rs.setEventHandler { [weak self] in self?.drainFromCore() }
        rs.setCancelHandler { close(fd) }
        readSource = rs
        rs.resume()
        let ws = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
        ws.setEventHandler { [weak self] in self?.flushToCore() }
        writeSource = ws // created suspended
        writeSourceResumed = false
    }

    private func resumeWriteSource() {
        guard let ws = writeSource, !writeSourceResumed else { return }
        writeSourceResumed = true
        ws.resume()
    }

    private func suspendWriteSource() {
        guard let ws = writeSource, writeSourceResumed else { return }
        ws.suspend()
        writeSourceResumed = false
    }

    private func fail(_ why: String) {
        guard running else { return }
        StartupLog.write("packet bridge failed: \(why)")
        stopOnQueue()
        onFailure?(why)
    }

    // MARK: - framing

    static func posix(_ call: String) -> NSError {
        let code = errno
        return NSError(domain: NSPOSIXErrorDomain, code: Int(code), userInfo: [NSLocalizedDescriptionKey: "\(call) 失败（errno \(code)）"])
    }
}
