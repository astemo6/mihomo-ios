# Shadowsocks `plugin: kcptun` — native core implementation (feat/nc-ss-cloak-kcptun)

Status: **Implemented natively in pure Swift** (removed from `NCSupport.ssPluginUnsupported`).
Reference: mihomo v1.19.33 `transport/kcptun` (client.go / common.go / comp.go) on top of
`metacubex/kcp-go`, `metacubex/smux`, `golang/snappy`, `klauspost/reedsolomon`.

## Implementation Layer Summary

| Layer | mihomo default | Native Implementation (Pure Swift) | Status |
|---|---|---|---|
| UDP socket | `listenPacketContext`, sockbuf 4 MiB | NWConnection UDP per session; physical-interface binding via `NCOutboundBinding.params(.udp)` | Implemented (`NCKcptunSmux.swift`) |
| Packet crypto | `crypt: aes` = AES-256-CFB over every datagram with 16-byte random nonce + CRC32 header; also aes-128, aes-128-gcm, salsa20, none; key = PBKDF2-SHA1(key, "kcp-go", 4096, keyLen) | `NCKcptunBlockCrypt` in `NCKcptunCrypt.swift`: PBKDF2-SHA1, CFB128 via `NCAES`, AES-128-GCM via CryptoKit, Salsa20, and plaintext none/null. | Implemented |
| FEC | datashard 10, parityshard 3 (Reed-Solomon GF(2^8), kcp-go fecEncoder/fecDecoder with shard groups) | `NCReedSolomon` & `NCKcptunFEC` in `NCKcptunCrypt.swift`: GF(2^8) with poly 29, Vandermonde matrix inversion via Gaussian elimination, FEC headers (seqid:4 LE, flag:2 LE), bounded cache (`maxShardSets = 3`). | Implemented |
| KCP ARQ | ikcp: conv, una/ack lists, RTO, fast-resend, congestion window, MTU 1350, nodelay/interval/resend/nc presets per `mode` (fast = 0/30/2/1), stream mode on | `NCKCP` in `NCKcptunARQ.swift`: full Skywind3000/kcp-go ARQ state machine, sliding window, fast retransmit, window probing, 10–50 ms DispatchSourceTimer. | Implemented |
| Compression | on by default (`nocomp: false`): snappy *framed stream* (chunk headers + CRC32C) both ways | `NCSnappyFramedStream` in `NCKcptunARQ.swift`: snappy block compression / decompression + RFC framing format + Castagnoli CRC32C checksum. | Implemented |
| Mux | smux v1 / v2 multi-stream session; every SS TCP connection is one smux stream; shared across connections | `NCKcptunSmuxSession` & `NCKcptunSessionPool` in `NCKcptunSmux.swift`: long-lived shared UDP session per node with autoexpire rotation and reload teardown. | Implemented |

## Memory Discipline & Constants (Network Extension Budget)

To comply with the Network Extension ~50MiB memory ceiling while preserving interoperability with standard kcptun servers:

| Parameter | mihomo Default | Native Core Constant | Rationale / Divergence |
|---|---|---|---|
| `rcvwnd` | 512 segments (~700 KiB) | `NCKcptunOptions.defaultRcvWnd = 128` (~170 KiB) | Caps peak segment buffer memory per active kcptun node by 75% |
| `sndwnd` | 128 segments (~170 KiB) | `NCKcptunOptions.defaultSndWnd = 128` | Matches mihomo default |
| `smuxbuf` (MaxReceiveBuffer) | 4 MiB | `NCKcptunOptions.defaultSmuxBuf = 524288` (512 KiB) | Avoids multi-megabyte window bloat from aggressive servers |
| `streambuf` (MaxStreamBuffer) | 2 MiB | `NCKcptunOptions.defaultStreamBuf = 262144` (256 KiB) | Bounded per-stream receive buffer |
| `maxShardSets` | unbounded / timed | `NCKcptunFEC.maxShardSets = 3` | Strictly limits FEC reconstruction shard cache to 3 sets (~50 KiB) |

## DIVERGENCES

1. **`rcvwnd` cap**: Capped at 128 segments (mihomo defaults to 512). Reason: 512 segments of 1350 bytes consume ~700 KiB in queue plus duplicate segments; 128 segments gives smooth throughput on mobile while keeping memory under 200 KiB.
2. **`smuxbuf` and `streambuf` caps**: Capped at 512 KiB and 256 KiB respectively (mihomo defaults to 4 MiB and 2 MiB). Reason: A 4 MiB buffer easily triggers memory pressure warnings or jetsam in iOS Network Extensions.
3. **Ciphers**: Supported: `aes` (AES-256-CFB128, default; unknown names fall back to it like mihomo), `aes-128`, `aes-128-gcm`, `salsa20`, `none` (nonce + CRC header, no cipher), `null` (no header). `tea`, `xor`, `sm4`, `blowfish`, `twofish`, `cast5`, `3des`, `xtea`, `aes-192` are reported unsupported by `NCKcptunOptions.parse` (never silently keyed as AES).
4. **Session sharing & pooling**: `NCKcptunSessionPool` maintains one shared `NCKcptunSession` per unique node endpoint (`server:port:cacheKey`). Multiple SS connections reuse this single session via separate smux streams, matching mihomo's mux architecture.
5. **Flow control / lifecycle (helper-PR CI pass, 2026-10-25)**: all KCP/FEC/smux state lives on one serial session queue; stream callbacks return on the opener's queue. Receive stops pulling from KCP while `smuxbuf` bytes are unread (KCP window closes → server backs off); smux v2 sends cmdUPD per consumed bytes. Send completions are held while KCP queues more than `max(64, 2 × sndwnd)` segments. Idle sessions (no streams, nothing in flight) close after 60 s; dead-link (20 retransmits) closes the session; tunnel stop closes every session via `NCConnector.closeAllSharedSessions` (`kcptun` registry count).
