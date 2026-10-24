import Darwin
import Foundation

/// utun framing for the PacketFlowBridge socket pair: every datagram is a 4-byte big-endian address
/// family followed by the IP packet (what sing-tun's darwin reader expects).
///
/// E 线 #2: the bridge used to build a new `Data` per outbound packet (4-byte header + a copy of the
/// packet) before `send`. `send(fd:family:packet:)` hands the header and the packet's own bytes to
/// `sendmsg` as two iovecs instead, so the packet `NEPacketTunnelFlow` gave us is sent without an
/// allocation or a copy. On an `AF_UNIX`/`SOCK_DGRAM` socket the two iovecs form one datagram.
/// Lives in Shared so the unit tests (hosted in the app) can exercise it on a real socket pair.
enum PacketFraming {
    static let headerSize = 4

    /// Sends one framed datagram without blocking. Returns `sendmsg`'s result: the bytes sent
    /// (`headerSize + packet.count` when the whole datagram went out) or -1 with `errno` set.
    static func send(fd: Int32, family: Int32, packet: Data) -> Int {
        var header = UInt32(bitPattern: family).bigEndian
        return withUnsafeMutableBytes(of: &header) { hdr -> Int in
            packet.withUnsafeBytes { body -> Int in
                // A homogeneous tuple is laid out contiguously: two iovecs without a heap-allocated array.
                var iov = (
                    iovec(iov_base: hdr.baseAddress, iov_len: headerSize),
                    iovec(iov_base: UnsafeMutableRawPointer(mutating: body.baseAddress), iov_len: body.count)
                )
                return withUnsafeMutablePointer(to: &iov) { pair -> Int in
                    pair.withMemoryRebound(to: iovec.self, capacity: 2) { vec -> Int in
                        var msg = msghdr()
                        msg.msg_iov = vec
                        msg.msg_iovlen = 2
                        return sendmsg(fd, &msg, MSG_DONTWAIT)
                    }
                }
            }
        }
    }

    /// The datagram size `send` produces for a packet.
    static func framedSize(_ packet: Data) -> Int { headerSize + packet.count }

    /// The address family of a raw IP packet (version nibble), for packets the system gave without one.
    static func family(of packet: Data) -> Int32 {
        guard let first = packet.first else { return AF_INET }
        return (first >> 4) == 6 ? AF_INET6 : AF_INET
    }
}
