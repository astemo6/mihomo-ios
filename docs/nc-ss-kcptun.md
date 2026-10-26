# Shadowsocks `plugin: kcptun` — native core decision (feat/nc-ss-plugins2)

Status: **not implemented, stays unsupported** (`NCSupport.ssPluginUnsupported` → "kcptun（KCP/UDP 插件）").
Reference: mihomo v1.19.33 `transport/kcptun` (client.go / common.go / comp.go) on top of
`metacubex/kcp-go`, `metacubex/smux`, `golang/snappy`, `klauspost/reedsolomon`.

## What mihomo actually runs for one kcptun node

| Layer | mihomo default | Native work needed (Swift, no Go) |
|---|---|---|
| UDP socket | `listenPacketContext`, sockbuf 4 MiB | NWConnection UDP per session; physical-interface binding like NCHysteria |
| Packet crypto | `crypt: aes` = AES-256-CFB over every datagram with 16-byte random nonce + CRC32 header; also tea, xor, none, null, aes-128, aes-192, blowfish, twofish, cast5, 3des, xtea, salsa20, aes-128-gcm; key = PBKDF2-SHA1(key, "kcp-go", 4096, 32) | ~13 block modes. CommonCrypto covers AES/CAST/Blowfish/3DES; twofish, xtea, tea, salsa20 hand-written (~450 lines) |
| FEC | **on by default**: datashard 10, parityshard 3 (Reed-Solomon GF(2^8), kcp-go fecEncoder/fecDecoder with shard groups, auto-tune) | RS encode + matrix-inverse decode + kcp-go FEC header/group bookkeeping (~500 lines) |
| KCP ARQ | ikcp: conv, una/ack lists, RTO, fast-resend, congestion window, sndwnd 128 / rcvwnd 512 segments, MTU 1350, nodelay/interval/resend/nc presets per `mode` (fast = 0/30/2/1), stream mode on | ikcp port (~900 lines) + a 10–50 ms update timer per session |
| Compression | **on by default** (`nocomp: false`): snappy *framed stream* (chunk headers + CRC32C) both ways | snappy block codec + framing format (~400 lines) |
| Mux | smux v1 or v2 **session** (MaxReceiveBuffer 4 MiB, MaxStreamBuffer 2 MiB, frame 8 KiB, keep-alive 10 s, v2 per-stream window updates); every SS TCP connection of the node is one stream; `conn` sessions round-robin; `autoexpire` / `scavengettl` rotation | full multi-stream smux session shared across connections (~600 lines) — gost-plugin's single-stream NCGostSmuxStream is not enough |

Estimate: **~3,000–3,500 lines of new Swift** + a shared-session lifecycle (one long-lived UDP KCP session per
node serving many relays, rotation, teardown on reload), i.e. roughly the size of the TUIC + Hysteria UDP stack
combined. No interop server in CI: sing-box has no kcptun inbound, and the loopback harness must stay Go-free on
the app side, so correctness would rest on hand-derived vectors only.

## Memory / power cost (Network Extension budget)

Per active node session, worst case with mihomo defaults:
- KCP receive window 512 × 1350 B ≈ 0.7 MiB, send window 128 × 1350 B ≈ 0.17 MiB, plus retransmit copies;
- FEC shard cache (≥ 3 groups × 13 shards × MTU) ≈ 50 KiB;
- smux session receive buffer up to 4 MiB (bounded by v2 flow control; v1 has none — server can push up to it);
- snappy framing buffers ≈ 64 KiB each direction;
- a 30 ms timer that never sleeps while the session is open (radio + CPU wake-ups).

That is 1–5 MiB per kcptun node against the ~50 MiB extension limit, and a permanent wake-up timer —
against the native core's "memory first" rule, for a plugin that is rare in subscriptions.

## Revisit when

- users report real kcptun subscriptions, **and**
- we accept capping `rcvwnd`/`smuxbuf` below mihomo defaults (diverging from mihomo), and
- a kcptun server can run in CI (e.g. a prebuilt `xtaci/kcptun` server binary in tools/loopback).
