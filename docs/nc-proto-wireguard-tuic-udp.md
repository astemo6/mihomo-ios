# NativeCore: WireGuard and TUIC UDP — design note (feat/nc-proto, based on astemo6/Muse NativeCore)

Status 2026-10-25: TUIC v5/v4 **TCP** is implemented (PacketTunnel/NativeCore/NCTUIC.swift) on Network.framework
QUIC — no third-party QUIC library is needed for it. WireGuard and TUIC **UDP** are not implemented; this note is
the plan.

## 1. TUIC UDP

| relay mode | transport | Network.framework support | plan |
|---|---|---|---|
| `quic` | client→server Packet commands on unidirectional streams, server→client on server-opened uni streams | uni streams: yes (`NWProtocolQUIC.Options.direction = .unidirectional`, `group.newConnectionHandler` for incoming) | implement first: `Packet{ver,type=2,assoc_id u16,pkt_id u16,frag_total u8,frag_id u8,size u16,addr}` + payload per uni stream; reassembly per (assoc_id,pkt_id) with a 16-entry cap; Dissociate on session close |
| `native` (default) | QUIC DATAGRAM frames (RFC 9221) | datagram flows exist (`NWProtocolQUIC.Options.isDatagram`, `maxDatagramFrameSize`, iOS 16+) but are undocumented for NWConnectionGroup; NCHysteria2 already tries the same binding | reuse NCHysteria2's datagram channel once it is device-verified; fall back to `quic` mode when no datagram arrives within 3 s |

Heartbeat (v5 `Heartbeat` datagram every 10 s) needs the same datagram channel; until then an idle session is
closed by the QUIC idle timeout and the next flow reconnects (implemented).

**No embedded QUIC library is required.** If Network.framework datagrams turn out unusable on a device, the
fallback is quic-mode only (still no library). Embedding a QUIC stack only makes sense for Brutal/BBR congestion
control (Hysteria v1/v2 `up`/`down`, TUIC `congestion-controller`): candidates and costs —

| library | language | binary (arm64, release) | per-connection memory | notes |
|---|---|---|---|---|
| quiche (Cloudflare) | Rust + BoringSSL | ~2.0–2.5 MB (+BoringSSL ~1 MB if not shared) | ~150–300 KB (stream buffers configurable) | C API, pluggable CC (cubic/reno/bbr2), datagrams, exporter; needs a UDP socket loop of our own (NWConnection UDP) |
| ngtcp2 + nghttp3 | C (+ picotls / wolfSSL for TLS) | ~0.6 MB + TLS ~0.4–0.8 MB | ~100–200 KB | smallest; we bring the TLS backend and the timer loop |
| MsQuic | C | ~1.5 MB + OpenSSL/Schannel | higher (worker threads) | thread model fights the extension's single-queue design |

Recommendation if ever needed: ngtcp2 + picotls (≈1.2 MB, smallest memory), driven from the engine queue. The
extension budget (50 MB jetsam, today ~3.3 MB binary) can afford it, but it is not needed for any protocol in A1–A6.

## 2. WireGuard

Pieces and where they live:

1. **Crypto (pure Swift, ~350 lines)**: Curve25519 (CryptoKit), ChaCha20-Poly1305 (CryptoKit `ChaChaPoly`, nonce =
   4 zero bytes ‖ counter LE64), XChaCha20-Poly1305 for cookies (HChaCha20 + ChaChaPoly), BLAKE2s-256 + keyed
   BLAKE2s/HMAC-BLAKE2s (new, ~120 lines), TAI64N timestamps.
2. **Noise_IKpsk2 handshake + timers (~400 lines)**: initiation / response / cookie reply, rekey after 120 s or
   2^60 messages, keepalive (`persistent-keepalive`), replay window (2048-bit bitmap), `reserved` bytes (mihomo's
   `reserved: [a,b,c]` for Cloudflare WARP) written into bytes 1–3 of every message. One `NWConnection` UDP socket
   per peer; `amnezia-wg-option` (junk packets / header obfuscation) as a later extension.
3. **IP stack for the tunnel side**: WireGuard carries IP packets, so TCP/UDP flows from NativeCore must be
   originated by a userspace stack on the WG interface. Options:
   - (a) **Second netif in the existing lwIP** (recommended): turn off `LWIP_SINGLE_NETIF`, add `nc_wg_netif_add
     (ip4, ip6, mtu, output_cb)` in nc_stack.c; client PCBs are created with `tcp_new` + `tcp_bind_netif(pcb,
     wg_netif)` + `tcp_connect` (lwIP ≥ 2.1 has `tcp_bind_netif`), UDP with `udp_bind_netif`. The TUN netif keeps
     the listener-per-destination trick; the WG netif only sees packets that WireGuard decrypted (`netif->input`).
     A route hook (`LWIP_HOOK_IP4_ROUTE_SRC`) picks the WG netif for PCBs bound to its address. Memory: shares the
     existing MEM_SIZE 384 KB / 96 PCBs; raise `MEMP_NUM_TCP_PCB` to 128 and `MEM_SIZE` to 512 KB when a WG node is
     configured (+128 KB).
   - (b) A second, symbol-prefixed copy of lwIP (separate instance, ~280 KB more binary, its own MEM_SIZE): simpler
     isolation, more memory; only if (a) hits lwIP global-state limits.
   - (c) A Swift userspace TCP client (no listen, no reassembly of out-of-order beyond a small window): smallest
     code footprint but the most risk; not recommended.
4. **Connector glue**: `NCWireGuardDevice` (one per node, shared) exposes `openTCP(target) -> NCRelayStream`
   (lwIP client PCB on the WG netif) and `openUDP`; DNS for domain targets uses the node's `dns` servers through
   the same netif when `remote-dns-resolve` is set, otherwise the tunnel resolver.

Estimate: crypto + handshake + timers ~1 day, lwIP second netif + connector glue ~1 day, device validation against
a WARP and a plain wg-quick server ~0.5 day. Binary +~120 KB (option a), memory +~150 KB per active WG device.
