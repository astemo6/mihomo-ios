# NativeCore: Sudoku — design note (feat/nc-sudoku, baseline 6fd4bab)

> **Status (fix/nc-sudoku-interop, 2026-10-27):** the data plane is wire-compatible with the official server v0.5.2.0
> (`NCSudokuWire.swift` + `NCSudokuSession.swift`): per-direction HKDF handshake keys, X25519 rekey, the reference
> server's legacy PRNG table seed (additive lagged Fibonacci, seeded table — `NCLaggedFibRand` / `NCLaggedFibSeedTable`),
> client key normalisation (private key → master public key), padding-aware streaming decode (classic + packed
> downlink), aead none passthrough, custom-table rotation hint. Verified by `NativeCoreLoopbackTests` against the
> official binary built from source in proto-loopback.yml (:18090–:18094, HTTP origin :18095); with that loopback
> green the node is **available** (NCSupport / NCConnector dial it). Not implemented (explicit markers, never a
> timeout): HTTP tunnel modes stream / poll / auto / ws, `multiplex: on`.

Status 2026-10-26 (S2 complete): parsing layer (S1) plus pure-Swift data plane,
connector wiring, unit vectors/boundary tests, and the loopback harness wired to
the official `SUDOKU-ASCII/sudoku` server as a black-box peer (127.0.0.1:18015).
Static interop analysis against upstream v0.5.2 (§2.6) shows the handshake cannot
complete yet — the loopback echo verdict is **pending CI** (§7), with the S3
remediation list in §8. Clean-room basis is documented in §6.

---

## 1. Protocol Research & Specification Availability

### 1.1 Specification Availability Determination
**Verdict: 规范完全公开且开源 (Specification is public and open source).**

- **Official Upstream Repository**: `SUDOKU-ASCII/sudoku` (GitHub: `https://github.com/SUDOKU-ASCII/sudoku`)
- **License**: GNU General Public License v3.0 (`GPL-3.0`)
- **Primary Author**: `saba` / `saba-futai`
- **Upstream release used for the loopback black-box peer**: `v0.5.2.0` (tag on GitHub Releases; assets `sudoku-darwin-arm64.tar.gz` / `sudoku-linux-{amd64,arm64}.tar.gz` / …, flat tarballs containing the `sudoku` binary)
- **Reference Implementations**:
  - **Go**:
    - `SUDOKU-ASCII/sudoku` (official tunnel core, server, and CLI tools)
    - `MetaCubeX/mihomo` (PR #2397 merged on 2025-11-28, adding native outbound and inbound listener support in v1.19.21+)
    - `SUDOKU-ASCII/sudoku-sing-box` (official sing-box integration branch)
  - **Swift**:
    - `NodePassProject/Anywhere` (`https://github.com/NodePassProject/Anywhere`, App Store: Anywhere Proxy): open-source Swift implementation of the Sudoku protocol for iOS/macOS/tvOS by `saba-futai` and the NodePassProject team.
- **Client Ecosystem Support**:
  - **Shadowrocket**: officially supported since version `2.2.92` (changelog: *"feat(protocol): 新增 Sudoku 代理协议支持，并深度优化其数据转发路径以减少内存分配与拷贝"*).
  - **Clash.Meta**: outbound and inbound support since `v1.19.21`.
  - **Anywhere Proxy (iOS)**: pure Swift native implementation.
  - **Quantumult X**: no native Sudoku support in QuanX (we still parse QX-style node lines).

---

## 2. Protocol Design & Wire Format (as verified against upstream v0.5.2)

Sudoku is a traffic obfuscation proxy protocol based on constructing and solving 4×4 Sudoku puzzles. It maps arbitrary data streams (where each byte has 256 possibilities) into 4×4 Sudoku puzzles (which have 288 non-isomorphic variants) defined by 4 clues. Because each puzzle has at least one valid clue-setting configuration, the clue selection creates stochastic variation, rendering the observable byte stream indistinguishable from printable ASCII or low-entropy traffic.

### 2.1 Obfuscation Layer (Sudoku Encoding)
- **Table generation**: both peers derive the byte→puzzle mapping from the shared
  key string. Upstream (`pkg/obfs/sudoku/grid.go`):
  - All valid 4×4 grids are enumerated by fixed-order backtracking — 288 grids;
    "the order is part of the table-seeding contract" (`grid.go:26`).
  - `shuffledGrids(key)` seeds `math/rand` **v1** with `int64(BE(SHA256(key)[0..8]))`
    and Fisher-Yates-shuffles the 288 grids; position k in the result is the grid
    of plaintext byte k, the 32 trailing grids encode nothing (`grid.go:80-89`).
    The comment states "The math/rand v1 stream is part of the wire contract."
  - The client normalizes its key first (§2.6 row 2), so both sides seed from the
    **master public key hex string**.
- **4×4 clue mapping**: each byte is encoded as a uniquely solvable puzzle of 4
  clues; the encoder picks among valid clue sets stochastically
  (`classic_encode.go pickPuzzle`).
- **True Arbitrary Dynamic Padding**: padding bytes from the layout's padding pool
  can be inserted *before each clue byte and before each clue group*
  (`classic_encode.go:57-69 padSlot`), driven by `padding_min`/`padding_max`
  probabilities. The decoder keeps a streaming hint buffer and skips non-clue
  bytes anywhere between clue bytes (`classic_decode.go:7-35`) — no padding length
  is ever negotiated.
- **ASCII & Entropy Profiles**: `prefer_ascii` (printable ASCII layout),
  `prefer_entropy` (low-Hamming-weight layout), directional
  `up_ascii_down_entropy` / `up_entropy_down_ascii`, and custom 8-character XVP
  layouts (2×`x`, 2×`p`, 4×`v`, e.g. `xpxvvpvv`; 420 valid permutations).
  ASCII preference wins over custom patterns (`layout.go:70-74`).

### 2.2 Downlink Modes
- **Pure Sudoku Downlink (`enable_pure_downlink: true`, default)**: both directions use classic 4×4 Sudoku clue encoding.
- **Bandwidth-Optimized Downlink (`enable_pure_downlink: false`)**: downlink splits the byte stream into 6-bit chunks and reuses the padding pool (`pkg/obfs/sudoku/packed*.go`).

### 2.3 HTTP Masking Layer (`httpmask`)
- `mode: "legacy"`: one fake HTTP/1.1 request head, then raw Sudoku stream.
- `mode: "stream" / "poll" / "auto"`: HTTP tunnel modes (CDN/reverse-proxy friendly).
- `mode: "ws"`: WebSocket tunneling (subprotocol `sudoku-tcp-v1`).
- `tls: true` (client tunnel modes): outer TLS; `host`: Host/SNI override; `path-root`: path prefix shared by both ends.
- `multiplex: off/auto/on`: `on` enables session mux over raw TCP or HTTPMask (`auto` = transport reuse only).

### 2.4 AEAD Record Layer (Encryption)
When `aead` is not `none` (`pkg/crypto/record_conn.go`):
- **Record framing** (matches our implementation byte-for-byte):
  | Field | Size | Encoding | Description |
  |---|---:|---|---|
  | `body_len` | 2 bytes | uint16 BE | Length of `header` + `ciphertext` (incl. tag) |
  | `header` | 12 bytes | Plaintext | `epoch` (uint32 BE) + `seq` (uint64 BE) |
  | `ciphertext+tag` | `body_len - 12` | AEAD | `AEAD.Seal(nonce=header, plaintext, aad=header)` |
  The 12-byte header serves as framing, nonce, and AAD (`record_conn.go:36-41`).
- **Key schedule** (official; *not* matched by the current clean-room client, see §2.6):
  1. PSK handshake bases: `HKDF-Expand(SHA256(key-string), "sudoku-psk-c2s" | "sudoku-psk-s2c", 32)` — directional; ClientHello/ServerHello records are sealed with these (`session_keys.go:16-21`, `handshake_client.go:71-72`).
  2. After ServerHello both sides **Rekey** to session bases: `prk = HKDF-Extract(salt=SHA256(key-string), ikm=X25519(ephemeral, server_pub) ‖ nonce)`, then `HKDF-Expand(prk, "sudoku-session-c2s" | "sudoku-session-s2c", 32)` (`session_keys.go:25-47`, `kip_hello.go deriveClientSession`, `handshake_server.go:152`).
  3. Per-epoch AEAD key: `HMAC-SHA256(base, "sudoku-record:" ‖ method ‖ epoch_be32)`; rotation every 32 MiB plaintext per direction (`record_conn.go:270-280`, `KeyUpdateAfterBytes`).
  4. Receive path enforces strict in-order `seq` (replay protection).
- **Ciphers**: `chacha20-poly1305` (default) or `aes-128-gcm`. `none` = raw
  passthrough with **no framing at all** (`record_conn.go` `Write`, `method == "none"` branch).

### 2.5 Control Plane (KIP Framing)
All control messages are wrapped in KIP frames:
| Field | Size | Encoding | Description |
|---|---:|---|---|
| `magic` | 3 bytes | ASCII | `"kip"` |
| `type` | 1 byte | uint8 | 0x01 ClientHello, 0x02 ServerHello, 0x10 OpenTCP, 0x11 StartMux, 0x12 StartUoT, 0x14 KeepAlive |
| `payload_len` | 2 bytes | uint16 BE | Length of payload |
| `payload` | variable | bytes | Message body |

- **ClientHello (0x01)** (`internal/tunnel/kip.go:173`): `timestamp` (uint64 BE unix seconds) + `user_hash` (8 bytes = `SHA256(private-key-bytes)[:8]`, `kip.go:157`) + `nonce` (16 random bytes) + `client_pub` (32 X25519 ephemeral) + `features` (uint32 BE) — 68 bytes, plus an *optional* trailing 4-byte table hint (decoded when present, `kip.go:192-219`). The server tolerates ±60 s clock skew and rejects nonce replay (`kip_hello.go:24`, `acceptClientHello`).
- **ServerHello (0x02)** (`kip.go:246`): `nonce` (16, exact echo) + `server_pub` (32 X25519 ephemeral) + `selected_features` (uint32 BE) — exactly 52 bytes.
- **OpenTCP (0x10)**: SOCKS5-style address: `atyp` (0x01 IPv4 / 0x03 domain / 0x04 IPv6) + address bytes + port (uint16 BE).
- **UoT (0x12)**: UDP-over-TCP inside the tunnel (feat/nc-sudoku-udp, `NCSudokuUoT.swift`). The client sends
  StartUoT with an empty payload right after the rekey (instead of OpenTCP); afterwards both directions carry
  datagram frames `addrLen u16 BE ‖ payloadLen u16 BE ‖ address ‖ payload`, where `address` is the SOCKS5-style
  encoding (uplink: destination, domains resolved by the server; downlink: the peer IP). `addrLen = 0` ends the
  session; an undecodable address skips that datagram. One tunnel per UDP association (as the official client and
  Clash.Meta do); each frame is written as one record. Verified against the official server v0.5.2.0 in
  NativeCoreLoopbackTests (`testSudokuUDP*`).

### 2.6 Interoperability Status vs Upstream v0.5.2 (实现现状对照)

Static comparison of `Shared/NativeCore/NCSudokuSession.swift` (commit 2041932,
frozen this round) against the upstream source. **Layer-by-layer verdict**:

| # | Layer | Official v0.5.2 (evidence) | Our clean-room data plane | Interop |
|---|---|---|---|---|
| 1 | KIP frame layout | `"kip"` + type + u16 BE len + payload (`apis/codec.go`, `tunnel/kip.go`) | identical (`NCSudokuKIP`) | ✅ |
| 2 | Key normalization | client rewrites `cfg.Key` to master-public-key hex for PSK + table seed, keeps raw private bytes for `user_hash` (`internal/app/client.go normalizeClientKey`) | absent — key used as given | ❌ (affects PSK + table seed for split-key configs) |
| 3 | `user_hash` | `SHA256(private-key-bytes)[:8]`; 64/128-hex decoded; fallback `SHA256(trim(key-string))` (`kip.go:157`) | same for 64/128-hex; fallback does not trim | ✅ (trim nit) |
| 4 | ClientHello payload | 8+8+16+32+4 (+optional 4B table hint) (`kip.go:173,192`) | identical without the hint (server tolerates absence) | ✅ |
| 5 | ServerHello payload | nonce 16 + pub 32 + feats 4, exact-52 (`kip.go:246`) | identical | ✅ |
| 6 | Record framing | u16 `body_len` + header 12 B = epoch‖seq as nonce+AAD (`record_conn.go:36`) | identical (`NCSudokuAEAD.seal/unseal`) | ✅ |
| 7 | Handshake record keys | directional `HKDF-Expand(SHA256(key-string), "sudoku-psk-c2s"/"-s2c")` (`session_keys.go:16`) | single `SHA256(key-bytes)` both directions | ❌ |
| 8 | Post-ServerHello rekey | X25519 ECDH + HKDF session bases + `Rekey` (`session_keys.go:25`, `kip_hello.go`) | absent — no ECDH mixing, no rekey | ❌ |
| 9 | Per-epoch key | `HMAC-SHA256(base, "sudoku-record:"+method+epoch)`, 32 MiB rotation, strict recv `seq` (`record_conn.go:270,30`) | fixed key, no rotation, no seq check | ❌ |
| 10 | `aead=none` framing | raw passthrough, no framing (`record_conn.go` Write) | u16-len framed plaintext | ❌ |
| 11 | Grid enumeration | fixed-order backtracking, 288 grids (`grid.go:26`) | identical enumeration (`generate288Grids`) | ✅ |
| 12 | Table shuffle | seed `int64(BE(SHA256(key-string)[:8]))` → `math/rand` v1 → Fisher-Yates; first 256 slots = bytes, 32 trailing unused; "the math/rand v1 stream is part of the wire contract" (`grid.go:80-89`) | homemade xorshift PRNG over `SHA256(key-bytes)`, all 288 slots indexed 0…255 | ❌ |
| 13 | Uplink padding | per-clue interleaved padding from layout pool, probability-driven (`classic_encode.go:57-69`) | none emitted (`paddingMin/Max` parsed but unused) | ⚠️ subset (valid-but-minimal; server accepts) |
| 14 | Decode padding tolerance | streaming hint buffer; padding allowed between clue bytes (`classic_decode.go`) | fixed 4-byte aligned groups; only whole garbage groups dropped | ❌ (server-padded downlink misparses) |
| 15 | Packed downlink | 6-bit chunk mode when `enable_pure_downlink=false` (`packed*.go`) | not implemented (pure mode only) | ❌ (loopback config pins pure mode) |

**Consequence**: rows 7/8/12 alone make the handshake impossible — the official
server cannot decrypt our ClientHello record, and even with `aead=none` it would
read our table-encoded bytes through a different table. Predicted CI outcome for
`testSudokuTCPEcho` (§7): the server treats the garbled ClientHello as illegal
traffic, `suspicious_action: fallback` replays the already-read prefix to the
18080 echo backend, the echo reflects it, and the client errors out — most likely
`Invalid ServerHello message` (the reflected ClientHello unseals successfully
under our own key but carries KIP type 0x01, not 0x02). This is a *prediction*;
the CI run is the verdict. `testSudokuWrongKeyRejected` passes regardless: a
wrong key must never yield a stream.

---

## 3. Supported Fields & Alignment Matrix

Parsing (S1) is unchanged; the S2 notes column records what the data plane
actually does with each field.

| Canonical Field | Clash.Meta YAML | Shortlink JSON (`sudoku://`) | Surge / Shadowrocket `.conf` | Quantumult X | Type | Default | S2 data-plane note |
|---|---|---|---|---|---|---|---|
| Server address | `server` | `h` | 2nd positional | Host in `server:port` | String | (Required) | dialed via `NCStream` |
| Server port | `port` | `p` | 3rd positional | Port in `server:port` | Int | (Required) | dialed via `NCStream` |
| Secret key | `key` | `k` | `key=` / `password=` | `key=` / `password=` | String | (Required) | AEAD key + table seed + user hash (divergences: §2.6 rows 2/7/12) |
| Node name | `name` | `n` | Line key `Name =` | `tag=` | String | (Derived) | display only |
| AEAD method | `aead-method` / `aead` | `e` | `aead-method=` / `aead=` | `aead-method=` / `aead=` | String | `"chacha20-poly1305"` | both ciphers live; `none` framing differs (row 10) |
| Table / ASCII mode | `table-type` / `ascii` | `a` | `table-type=` / `ascii=` | `table-type=` / `ascii=` | String | `"prefer_entropy"` | layouts live (self-consistent); table seed diverges (row 12) |
| Padding min | `padding-min` / `padding_min` | — | `padding-min=` | `padding-min=` | Int | `5` / `2` | parsed + validated; **encoder emits no padding yet** |
| Padding max | `padding-max` / `padding_max` | — | `padding-max=` | `padding-max=` | Int | `15` / `7` | parsed + validated; **encoder emits no padding yet** |
| Custom table | `custom-table` / `table` | `t` | `custom-table=` / `table=` | `custom-table=` / `table=` | String | `nil` | XVP pack/unpack live (self-consistent) |
| Custom tables rotation | `custom-tables` | `ts` | — | — | [String] | `[]` | parsed + validated; no rotation in data plane |
| Pure downlink | `enable-pure-downlink` | `x` (inverted: `x:true` = packed) | `enable-pure-downlink=` | `enable-pure-downlink=` | Bool | `true` | pure encoding used; packed downlink not implemented (row 15) |
| Multiplex mode | `multiplex` | `hx` | `multiplex=` | `multiplex=` | String | `"off"` | parsed + validated; muxless one-connection-per-dial (protocol-valid, `features=0`) |
| HTTP mask disable | `httpmask.disable` | `hd` | `httpmask-disable=` | `httpmask-disable=` | Bool | `false` | honored |
| HTTP mask mode | `httpmask.mode` | `hm` | `httpmask-mode=` | `httpmask-mode=` | String | `"legacy"` | only `legacy` (fake head) / disabled; `stream/poll/auto/ws` tunnels not implemented |
| HTTP mask TLS | `httpmask.tls` | `ht` | `httpmask-tls=` | `httpmask-tls=` | Bool | `false` | parsed; no TLS wrapping in data plane |
| HTTP mask Host | `httpmask.host` | `hh` | `httpmask-host=` | `httpmask-host=` | String | `""` | used for the legacy fake head |
| HTTP mask Path | `httpmask.path-root` | `hy` | `httpmask-path=` | `httpmask-path=` | String | `""` | used for the legacy fake head |
| UDP forwarding | `udp` | — | `udp=` / `udp-relay=` | `udp-relay=` | Bool | `false` | UoT (0x12) inside the tunnel, always available like Clash.Meta's Sudoku outbound (the protocol has no UDP switch; the flag is not consulted) — NCDataPlane `sudoku` case → NCSudokuUDPSession |

## 4. Unsupported Fields & Explicit Markers

Unchanged from S1 — any unsupported or invalid parameter is surfaced through
`NCSupport.unsupportedReason(proxy)` without silent drops:

| Field / Feature | Condition | Explicit `unsupportedReason` String | Rationale |
|---|---|---|---|
| Missing Key | `key` is empty | `"Sudoku 缺少 key"` | Key is essential for table generation and AEAD key derivation |
| Missing Server | `server` is empty | `"Sudoku 缺少 server"` | Dial destination host required |
| Invalid Port | `port <= 0` or `> 65535` | `"Sudoku 缺少有效 port"` | Port out of range |
| Unsupported AEAD | Not in `chacha20-poly1305`, `aes-128-gcm`, `none` | `"Sudoku 不支持的 aead-method: \(aead)"` | Protocol only specifies these three ciphers |
| Unsupported Table Type | Not in `prefer_ascii`, `prefer_entropy`, directional modes | `"Sudoku 不支持的 table-type: \(table)"` | Protocol defines only these steganographic modes |
| Invalid Padding | `pmin < 0`, `pmax < pmin`, or `pmax > 100` | `"Sudoku padding 范围无效: \(min)-\(max) (须 0 <= min <= max <= 100)"` | Padding percentages must satisfy `0 <= min <= max <= 100` |
| Invalid Custom Table | Length ≠ 8 or characters ≠ 2x, 2p, 4v | `"Sudoku custom-table 无效: 须由 2个x、2个p、4个v 组成的8字符 (如 xpxvvpvv)"` | Strict structural rule for 4×4 Sudoku clue table permutation |
| Unsupported HTTPMask Mode | Mode not in `legacy`, `stream`, `poll`, `auto`, `ws` | `"Sudoku httpmask mode 不支持: \(mode)"` | HTTP disguise supports only standard documented modes |
| Reverse Proxy | `reverse` block configured | `"Sudoku reverse (反向代理) 尚未接入"` | Reverse proxy exposes client local services; out of scope for outbound dialer |
| Users Whitelist | `users` list configured | `"Sudoku users (服务端白名单) 仅用于服务端"` | Server-side user metering and whitelist |

Known data-plane gap that is *not* yet an explicit marker: a node with
`httpmask.mode: stream/poll/auto/ws` or `multiplex: on` passes validation
(the modes are protocol-defined) but the S2 data plane neither tunnels nor
multiplexes — such nodes fail at connect with a handshake error instead of a
curated `unsupportedReason`. Listing them as explicit markers is queued with
the S3 data-plane work so the App shows a precise reason (see §8).

---

## 5. S2 Data Plane Implementation (as shipped, commit 2041932)

`Shared/NativeCore/NCSudokuSession.swift` (~815 lines, pure Swift + CryptoKit):

1. **`NCSudokuKIP`** — KIP framing, ClientHello builder, ServerHello parser,
   OpenTCP (SOCKS5-style) encoder. Layout matches upstream (§2.6 rows 1/4/5).
2. **`NCSudokuAEAD`** — record framing (`seal`/`unseal`) with CryptoKit
   `ChaChaPoly` / `AES.GCM`; key = `SHA256(key-bytes)`; none-mode = u16-len
   framed plaintext (divergences: rows 7/9/10).
3. **`NCSudokuCodec`** — 288-grid enumeration (identical to upstream), key-seeded
   shuffle via homemade xorshift PRNG (divergence: row 12), 4-clue hint search,
   XVP bit packing for entropy/custom layouts, printable-ASCII band for
   `prefer_ascii`, fixed-group decode with garbage-group filtering (divergence:
   rows 13/14).
4. **`NCSudokuHTTPMask`** — legacy fake HTTP/1.1 head generator.
5. **`NCSudokuRelay`** — `NCRelayStream` over the raw TCP stream: legacy-mask +
   ClientHello → ServerHello (nonce-echo validation) → OpenTCP, then
   AEAD+table-framed relay. No ECDH mixing / rekey (divergence: row 8).
6. **Connector** (`NCConnector.sudokuStream`, commit 2041932): `case "sudoku"`
   dials `NCStream(to:port:)` and hands the raw stream to
   `NCSudokuSession.connect`; pre-dial `NCSupport` validation retained from S1.

Memory & concurrency: per-connection objects only, incremental
`wireBuffer`/`plainBuffer` slices (no whole-stream buffers), single serial
`DispatchQueue` per connection — consistent with the NativeCore memory red-line.

---

## 6. Clean-Room Basis (净室依据)

1. **What the implementation was written from.** `NCSudoku.swift` (S1 parsing)
   and `NCSudokuSession.swift` (S2 data plane, commit 2041932) were authored
   against the upstream *documentation* only — `doc/README.md` (protocol layers,
   wire formats, KIP messages, address encoding, padding principle) and
   `configs/README.md` (field semantics) — as listed in the reference header of
   `NCSudokuSession.swift`. No upstream Go code was copied or mechanically
   translated.
2. **Why the divergences exist.** The public docs specify the *shapes* (framing,
   payload layouts, padding principle, table concept) but not the exact PRNG
   stream (`math/rand` v1 internal state machine), the HKDF label schedule, or
   the epoch-HMAC KDF. The clean-room implementation filled those gaps with
   spec-compatible-but-independent choices (§2.6 rows 7–12). This is precisely
   what the loopback interop test is designed to expose.
3. **What S2 read upstream source for.** This round read the upstream repository
   (tag `v0.5.2.0`) read-only, solely to (a) operate the official server as a
   black-box peer (release assets, `configs/server.config.json` template,
   `configs/README.md` field guide) and (b) produce the §2.6 divergence analysis
   and the §8 remediation list. Files consulted: `internal/app/client.go`,
   `internal/app/client_runtime.go`, `internal/tunnel/{kip,kip_hello,session_keys,handshake_client,handshake_server}.go`,
   `pkg/crypto/record_conn.go`, `pkg/crypto/keypair.go`, `pkg/obfs/sudoku/{grid,table,rand,layout,ascii_mode,classic_encode,classic_decode}.go`,
   `internal/config/{config,defaults}.go`, `cmd/sudoku-tunnel/main.go`,
   `.github/workflows/release.yml`, `configs/*.json`. No code from these files
   was incorporated into this repository in this round.
4. **License note.** Upstream is GPL-3.0. The S3 remediation (§8) must close the
   divergences by *re-implementing from documented behavior* (e.g. porting the
   `math/rand` v1 stream and HKDF/HMAC schedules as algorithms, not by copying
   Go source), keeping the clean-room posture and respecting GPL-3.0
   obligations for anything that ends up derived from upstream code.
5. **Test vectors.** The SHA-256 user-hash vectors and the RFC 7748 §6.1 X25519
   vectors pinned in `UnitTests/NativeCoreSudokuTests.swift` come from public
   standards and independently computed hashes (RFC 8032/7748, hashlib), not
   from upstream test files. The loopback keypair is generated for this repo
   only (RFC 8032 reference math, self-checked against RFC 8032 test vector 1).

---

## 7. Loopback Test Harness (wired; results pending CI)

Official server as black-box peer (sing-box has no sudoku inbound):

- **Server**: pinned upstream release `v0.5.2.0`, binary downloaded by
  `tools/loopback/start-servers.sh` (`SUDOKU_VERSION` / `SUDOKU_BIN` overrides),
  config `tools/loopback/sudoku-config.json` → `local_port: 18015`,
  `aead: chacha20-poly1305`, `ascii: prefer_ascii`, `padding_min/max: 0` (no
  server-side padding — fewest confounders), `enable_pure_downlink: true`,
  `httpmask.disable: true`, `multiplex: off`, `suspicious_action: fallback`
  with `fallback_address: 127.0.0.1:18080` (the existing echo backend, so a
  failed handshake is reflected back instead of hanging).
- **Keys**: the server holds the master public key
  `3388f6b59b225f4e41cd14f445b73b6568711ce536832217b15649253612451d`; the test
  node uses the matching split ("available") private key
  `e2eac3d4…7b60b` (128 hex chars) — generated for this repo via RFC 8032
  reference math, loopback-only values.
- **Tests** (`UnitTests/NativeCoreLoopbackTests.swift`):
  - `testSudokuTCPEcho` — full-stack echo through `NCConnector` → official
    server → echo backend; **the interop verdict, expected to fail until §8
    lands** (prediction in §2.6).
  - `testSudokuWrongKeyRejected` — corrupted key must error, never return a
    stream; passes regardless of interop state.
  - 18015 added to `testServerPortsReachable`.
- **Unit tests** (`UnitTests/NativeCoreSudokuTests.swift`): key-negotiation
  vectors (user-hash SHA-256 vectors, RFC 7748 X25519, ClientHello/ServerHello/
  OpenTCP byte layouts, KIP frame round-trip), codec boundaries (all-256 round
  trip per layout, printable band, padding/tail handling, XVP exhaustive +
  non-one-hot rejection, key sensitivity, no-padding-yet pin), AEAD negatives
  (wrong key, flipped tag, truncated record, bad `body_len`, none-mode framing).
- **CI**: `.github/workflows/proto-loopback.yml` starts the whole fleet
  (sing-box + sudoku + echo) and collects `sudoku.log`. **No loopback result
  exists yet — 本轮回环实测待 CI**（本机无 Xcode；本轮提交均带 `[skip ci]`，未触发任何工作流）。

## 8. S3 Remediation Plan (data plane; ordered by dependency)

1. Key normalization: derive master public key from split/master private key
   (Ed25519 scalar math, pure Swift) for PSK + table seed; keep raw private
   bytes for `user_hash` (§2.6 rows 2/3).
2. PSK directional handshake keys: `HKDF-Expand(SHA256(key-string), …)` with the
   upstream labels (CryptoKit `HKDF<SHA256>`) (row 7).
3. Table shuffle: port the `math/rand` v1 stream (seeded lagged-Fibonacci
   `rngSource` + `Int31n`/`Shuffle` semantics) as an algorithm — documented
   wire contract, `grid.go:80-89` (row 12).
4. Session rekey: X25519 (CryptoKit, RFC 7748 vector already pinned) +
   `HKDF-Extract/Expand` session bases applied after ServerHello (row 8).
5. Per-epoch keys `HMAC-SHA256(base, "sudoku-record:"+method+epoch)` + optional
   32 MiB rotation + strict recv-seq (row 9).
6. Streaming decoder with a hint buffer (padding between clue bytes) (row 14).
7. Decide `aead=none` framing: upstream passes through unframed — align or
   document the delta (row 10).
8. Optional: packed downlink (row 15), UoT/UDP, mux, httpmask tunnel modes;
   extend `NCSupport` explicit markers for not-yet-implemented-but-valid fields
   (§4 gap note).
