# NativeCore: Sudoku — design note (feat/nc-sudoku, baseline 6fd4bab)

Status 2026-10-26 (S1 complete): Protocol specification confirmed public and open-source (GPL-3.0). Canonical model extended, three-format parsing (Clash/mihomo YAML, official `sudoku://` short links, and Surge/Shadowrocket `.conf` / QX formats) implemented, and unsupported field detection integrated into `NCSupport`. Comprehensive unit tests added. Connector data plane and loopback test harness planned for S2.

---

## 1. Protocol Research & Specification Availability

### 1.1 Specification Availability Determination
**Verdict: 规范完全公开且开源 (Specification is public and open source).**

- **Official Upstream Repository**: `SUDOKU-ASCII/sudoku` (GitHub: `https://github.com/SUDOKU-ASCII/sudoku`)
- **License**: GNU General Public License v3.0 (`GPL-3.0`)
- **Primary Author**: `saba-futai` / `saba`
- **Recent Activity**: Repository initiated in November 2025; active continuous releases and optimizations throughout 2025–2026.
- **Reference Implementations**:
  - **Go**:
    - `SUDOKU-ASCII/sudoku` (official tunnel client, server, and CLI tools)
    - `MetaCubeX/mihomo` (PR #2397 merged on 2025-11-28, adding native outbound and inbound listener support in v1.19.21+)
    - `SUDOKU-ASCII/sudoku-sing-box` (official sing-box integration branch)
  - **Swift**:
    - `NodePassProject/Anywhere` (`https://github.com/NodePassProject/Anywhere`, App Store: Anywhere Proxy): Open-source Swift implementation of the Sudoku protocol for iOS/macOS/tvOS by `saba-futai` and the NodePassProject team.
- **Client Ecosystem Support**:
  - **Shadowrocket**: Officially supported since version `2.2.92` (changelog: *"feat(protocol): 新增 Sudoku 代理协议支持，并深度优化其数据转发路径以减少内存分配与拷贝"*).
  - **Mihomo / ClashMeta**: Outbound and inbound support since `v1.19.21`.
  - **Anywhere Proxy (iOS)**: Pure Swift native implementation.
  - **Quantumult X**: No native Sudoku support in QuanX.

---

## 2. Protocol Design & Wire Format

Sudoku is a traffic obfuscation proxy protocol based on constructing and solving 4×4 Sudoku puzzles. It maps arbitrary data streams (where each byte has 256 possibilities) into 4×4 Sudoku puzzles (which have 288 non-isomorphic variants) defined by 4 clues. Because each puzzle has at least one valid clue-setting configuration, the clue selection creates stochastic variation, rendering the observable byte stream indistinguishable from printable ASCII or low-entropy traffic.

### 2.1 Obfuscation Layer (Sudoku Encoding)
- **Table Generation**: Both client and server deterministically derive an identical Sudoku mapping table from the shared `key` (and optional `custom_table`).
- **4×4 Clue Mapping**: Each byte is mapped to a uniquely solvable 4×4 Sudoku puzzle hint consisting of 4 clues.
- **True Arbitrary Dynamic Padding**: Traditional protocols negotiate a padding length prefix. Sudoku filters out invalid or unsolvable Sudoku states without prior length negotiation. Any byte sequence that does not decode into a valid unique puzzle is discarded by the receiver as padding.
- **ASCII & Entropy Profiles**:
  - `prefer_ascii`: Maps puzzles to printable ASCII characters (>98% printable ASCII, Hamming weight ≈ 4.0).
  - `prefer_entropy`: Low-entropy byte layout with byte Hamming weight ≈ 3.0 (below typical censorship detection thresholds).
  - Directional modes: `up_ascii_down_entropy` and `up_entropy_down_ascii`.
  - Custom tables: 8-character layout string consisting of two `x`, two `p`, and four `v` characters (e.g. `xpxvvpvv`, 420 valid permutations).

### 2.2 Downlink Modes
- **Pure Sudoku Downlink (`enable-pure-downlink: true`, default)**: Both uplink and downlink use classic 4×4 Sudoku clue encoding.
- **Bandwidth-Optimized Downlink (`enable-pure-downlink: false`)**: Downlink splits the byte stream into 6-bit chunks and reuses the existing padding pool to reduce downlink overhead while preserving fingerprint alignment with uplink.

### 2.3 HTTP Masking Layer (`httpmask`)
Before or alongside Sudoku obfuscation, an optional HTTP disguise layer operates over raw TCP:
- `mode: "legacy"`: Emits a randomized HTTP/1.1 request header upon connection establishment, then immediately transitions into the raw Sudoku stream (suitable for direct connections, not CDN-friendly).
- `mode: "stream" / "poll" / "auto"`: HTTP tunnel modes compatible with reverse proxies and Cloudflare CDN.
- `mode: "ws"`: WebSocket tunneling mode (subprotocol `sudoku-tcp-v1`).
- `tls: true`: Wraps the outer transport in TLS.
- `host`: Overrides the HTTP `Host` header and TLS SNI.
- `path-root`: Custom path prefix for HTTP routes.

### 2.4 AEAD Record Layer (Encryption)
When `aead` is not `none`:
- **Cipher**: `chacha20-poly1305` (default) or `aes-128-gcm`. Key derived via `SHA256(key)`.
- **Framing**:
  | Field | Size | Encoding | Description |
  |---|---:|---|---|
  | `body_len` | 2 bytes | uint16 BE | Length of `header` + `ciphertext` |
  | `header` | 12 bytes | Plaintext | `epoch` (uint32 BE, key rotation) + `seq` (uint64 BE, message counter) |
  | `ciphertext` | `body_len - 12` | Bytes | `AEAD.Seal(nonce=header, plaintext, aad=header)` |
  The 12-byte `header` serves as both plaintext framing, nonce, and authenticated additional data (AAD).

### 2.5 Control Plane (KIP Framing)
All control messages are wrapped in KIP frames:
| Field | Size | Encoding | Description |
|---|---:|---|---|
| `magic` | 3 bytes | ASCII | `"kip"` |
| `type` | 1 byte | uint8 | Message type (0x01 ClientHello, 0x02 ServerHello, 0x10 OpenTCP, 0x11 StartMux, 0x12 StartUoT, 0x14 KeepAlive) |
| `payload_len` | 2 bytes | uint16 BE | Length of payload |
| `payload` | variable | bytes | Message body |

- **ClientHello (0x01)**: `timestamp` (uint64 BE) + `user_hash` (8 bytes, `SHA256(private_key)[:8]`) + `nonce` (16 bytes random) + `client_pub` (32 bytes X25519) + `features` (uint32 BE).
- **ServerHello (0x02)**: `nonce` (16 bytes matching client) + `server_pub` (32 bytes X25519) + `selected_features` (uint32 BE).
- **OpenTCP (0x10)**: SOCKS5-style address: `atyp` (0x01 IPv4 / 0x03 Domain / 0x04 IPv6) + address bytes + port (uint16 BE).
- **UoT (UDP-over-TCP, 0x12)**: Datagram framing with `addr_len` (uint16 BE) + `payload_len` (uint16 BE) + `addr` + `payload`.

---

## 3. Supported Fields & Alignment Matrix

| Canonical Field | Clash / mihomo YAML | Shortlink JSON (`sudoku://`) | Surge / Shadowrocket `.conf` | Quantumult X | Type | Default | Support Status |
|---|---|---|---|---|---|---|---|
| Server address | `server` | `h` | 2nd positional | Host in `server:port` | String | (Required) | Supported |
| Server port | `port` | `p` | 3rd positional | Port in `server:port` | Int | (Required) | Supported |
| Secret key | `key` | `k` | `key=` / `password=` | `key=` / `password=` | String | (Required) | Supported |
| Node name | `name` | `n` | Line key `Name =` | `tag=` | String | (Derived) | Supported |
| AEAD method | `aead-method` / `aead` | `e` | `aead-method=` / `aead=` | `aead-method=` / `aead=` | String | `"chacha20-poly1305"` | Supported (`chacha20-poly1305`, `aes-128-gcm`, `none`) |
| Table / ASCII mode | `table-type` / `ascii` | `a` | `table-type=` / `ascii=` | `table-type=` / `ascii=` | String | `"prefer_entropy"` | Supported (`prefer_ascii`, `prefer_entropy`, directional) |
| Padding min | `padding-min` / `padding_min` | — | `padding-min=` | `padding-min=` | Int | `5` (shortlink) / `2` (yaml) | Supported (0–100) |
| Padding max | `padding-max` / `padding_max` | — | `padding-max=` | `padding-max=` | Int | `15` (shortlink) / `7` (yaml) | Supported (0–100, ≥ min) |
| Custom table | `custom-table` / `table` | `t` | `custom-table=` / `table=` | `custom-table=` / `table=` | String | `nil` | Supported (8 chars: 2x, 2p, 4v) |
| Custom tables rotation | `custom-tables` | `ts` | — | — | [String] | `[]` | Supported |
| Pure downlink | `enable-pure-downlink` | `x` (inverted: `x:true` = packed) | `enable-pure-downlink=` | `enable-pure-downlink=` | Bool | `true` | Supported |
| Multiplex mode | `multiplex` | `hx` | `multiplex=` | `multiplex=` | String | `"off"` | Supported (`"off"`, `"auto"`, `"on"`) |
| HTTP mask disable | `httpmask.disable` | `hd` | `httpmask-disable=` | `httpmask-disable=` | Bool | `false` | Supported |
| HTTP mask mode | `httpmask.mode` | `hm` | `httpmask-mode=` | `httpmask-mode=` | String | `"legacy"` | Supported (`"legacy"`, `"stream"`, `"poll"`, `"auto"`, `"ws"`) |
| HTTP mask TLS | `httpmask.tls` | `ht` | `httpmask-tls=` | `httpmask-tls=` | Bool | `false` | Supported |
| HTTP mask Host | `httpmask.host` | `hh` | `httpmask-host=` | `httpmask-host=` | String | `""` | Supported |
| HTTP mask Path | `httpmask.path-root` | `hy` | `httpmask-path=` | `httpmask-path=` | String | `""` | Supported |
| UDP forwarding | `udp` | — | `udp=` / `udp-relay=` | `udp-relay=` | Bool | `false` | Supported via UoT in S2 |

---

## 4. Unsupported Fields & Explicit Markers

Under NativeCore red-line rules, any unsupported or invalid parameter must be explicitly detected and surfaced to the UI via `NCSupport.unsupportedReason(proxy)` without silent drops:

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

---

## 5. S2 Data Plane & Connector Implementation Plan

In S2, the complete pure-Swift data plane will be implemented in `Shared/NativeCore/NCSudokuSession.swift` and wired to `NCConnector`:

1. **Table Generation (`NCSudokuTable`)**:
   - Pure Swift implementation of the 4×4 Sudoku table builder.
   - Deterministic seed generation via SHA-256 of the shared `key`.
   - Precomputation of the 288 non-isomorphic 4×4 puzzle mappings into compact lookup tables (O(1) encode/decode, memory budget < 64 KB).
2. **Codec & Framing**:
   - `NCSudokuEncoder`: Slices plaintext into byte stream, maps to 4-clue Sudoku puzzles, inserts dynamic padding based on `paddingMin` / `paddingMax`.
   - `NCSudokuDecoder`: Validates puzzle solvability, discards invalid/non-unique padding, maps clues back to original bytes.
   - `NCSudokuRecordStream`: Implements the 12-byte AEAD record framing (`body_len` + `epoch`/`seq` + sealed ciphertext) using CryptoKit (`ChaChaPoly` / `AES.GCM`).
3. **HTTP Masking & Handshake**:
   - Randomized HTTP/1.1 request head generation for `legacy` mode.
   - KIP ClientHello (timestamp + user hash + ephemeral X25519) and ServerHello validation.
   - Target address encoding in SOCKS5 format.
4. **Multiplex & UoT**:
   - Sub-stream framing for multiplexed sessions.
   - UDP datagram encapsulation for UoT relay.
5. **Memory & Concurrency Budget**:
   - Single-queue asynchronous event loop using `DispatchQueue`.
   - Direct buffer slicing to prevent heap copies and stay comfortably under the 50 MB Network Extension jetsam limit.

---

## 6. S2 Loopback Test Plan

An open-source server is available to execute end-to-end loopback tests:
1. **Server Candidates**:
   - **Option A (Primary)**: `SUDOKU-ASCII/sudoku` standalone binary or Docker container (`docker run -p 8443:8443 sudoku:local`).
   - **Option B (Alternative)**: `MetaCubeX/mihomo` with `type: sudoku` inbound listener configured in `tools/loopback/`.
2. **Loopback Server Configuration (`tools/loopback/start-servers.sh`)**:
   - Add Sudoku server startup step on port `18443` (TCP).
   - Server config:
     ```json
     {
       "mode": "server",
       "local_port": 18443,
       "fallback_address": "127.0.0.1:80",
       "key": "6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b",
       "aead": "chacha20-poly1305",
       "table-type": "prefer_ascii",
       "padding_min": 2,
       "padding_max": 7
     }
     ```
3. **Loopback Unit Tests (`UnitTests/NativeCoreLoopbackTests.swift`)**:
   - Add test case `testSudokuTCPPing` connecting through `127.0.0.1:18443` to local HTTP echo server.
   - Add test case `testSudokuUoT` querying DNS `8.8.8.8:53` via Sudoku UoT channel.
4. **CI Workflow (`.github/workflows/proto-loopback.yml`)**:
   - Install `sudoku` Go binary or run via pre-built runner artifact.
   - Execute loopback test suite under GitHub Actions.
