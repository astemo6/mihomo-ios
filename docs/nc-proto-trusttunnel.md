# NativeCore: TrustTunnel (AdGuard) — design note (feat/nc-trusttunnel, based on astemo6/mihomo-ios @ 6fd4bab)

Status 2026-10-26 (S2 completed):
- Public specification and official implementation surveyed (AdGuard TrustTunnel v1.0, Apache 2.0).
- Session and connector layer landed in `Shared/NativeCore/NCTrustTunnelSession.swift` and `Shared/NativeCore/NCConnector.swift`.
- Both HTTP/2 (Track A via `NCTrustTunnelH2Session` with multi-stream multiplexing over TLS) and HTTP/3 (Track B via `NCTrustTunnelH3Session` with QUIC bidirectional streams and QPACK CONNECT headers) fully supported.
- HTTP Basic Authentication per TrustTunnel §5.1 / §9.1 enforced on every CONNECT request; 407 Proxy Authentication Required explicitly handled.
- App availability promoted in NCConnector; unsupported fields (`anti-dpi`, `client-random-prefix`, `client-random-auth-key`, `icmp`) explicitly rejected with clear diagnostics.
- Official server `trusttunnel_endpoint` (v1.1.0 pinned) integrated into `tools/loopback/start-servers.sh` on port 18013 (dual TCP for H2 and UDP for H3).
- Loopback test cases added to `UnitTests/NativeCoreLoopbackTests.swift` (`testTrustTunnelH2TCPEcho`, `testTrustTunnelH3TCPEcho`, `testTrustTunnelAuthFailure`).
- Unit tests reinforced in `UnitTests/NativeCoreTrustTunnelTests.swift` covering frame codec boundaries (truncated data, varint boundaries, IP padding, appName overflow) and authentication failure handling (407).
- Local verification: Linux x86_64 server startup and HTTP/2 CONNECT handshake verified; Xcode test execution: 待 CI.

---

## 1. Protocol Background & Ecosystem

### 1.1 Origins & Licensing

TrustTunnel is a modern VPN protocol originally developed by AdGuard VPN to tunnel TCP, UDP, and ICMP network traffic through standard HTTP/2 and HTTP/3 (QUIC) connections. By leveraging standard web application protocols, TrustTunnel traffic is indistinguishable from standard HTTPS traffic, bypassing deep packet inspection (DPI) and protocol fingerprinting.

- **Official Repository**: [TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) (formerly AdguardTeam/TrustTunnel)
- **Official Specification**: `PROTOCOL.md` (v1.0, Dec 24, 2025) and `DEEP_LINK.md` (v2) in the repository
- **License**: Apache License 2.0 (fully open source for server, client library, and tools)
- **Official Server Implementation**: Written in Rust, single standalone binary `trusttunnel_endpoint`. Prebuilt releases are provided for `linux-x86_64`, `linux-aarch64`, and `macos-universal`.

### 1.2 Ecosystem Support

| Client / Tool | Support Level | Share & Configuration Format |
|---|---|---|
| **Official Clients** | Full (H2, H3, UDP, ICMP) | Deep link `tt://?<base64url>` (v2), TOML config, HTTPS subscription endpoint (`https://user:pass@host/path`) |
| **Shadowrocket** | Full (H2, H3, DeepLink, .conf) | Imports `tt://?<base64url>` deep links; supports Surge-style `trust-tunnel` lines in `.conf` |
| **Surge** (Mac 6.4.4+, iOS 5.22.0+) | Partial (TCP over H2/H3; no UDP) | `[Proxy]` line: `Proxy = trust-tunnel, server, port, username=..., password=..., [h3=true], [max-streams=...]` |
| **Stash** (iOS 3.4.0+, macOS 4.2.0+) | Full (H2, H3, UDP) | YAML: `type: trusttunnel`, `quic: true/false`, `server`, `port`, `username`, `password` |
| **Clash / Mihomo** (v1.19.21+) | Full (H2, H3, UDP) | YAML: `type: trusttunnel`, `server`, `port`, `username`, `password`, `quic: true/false`, `udp: true` |
| **Quantumult X** | None | No public specification or format exists; parser explicitly marks it unavailable with diagnostic warning |

---

## 2. Architecture & Design

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          NativeCore Outbound                           │
├────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────┐            ┌───────────────────────────┐  │
│  │   TCP Stream (Per-Flow) │            │   UDP Stream (Multiplexed)│  │
│  │   CONNECT host:port     │            │   CONNECT _udp2           │  │
│  └────────────┬────────────┘            └─────────────┬─────────────┘  │
│               │                                       │                │
│               └───────────────────┬───────────────────┘                │
│                                   │                                    │
│                 ┌─────────────────▼─────────────────┐                  │
│                 │      NCTrustTunnelSession         │                  │
│                 │   (HTTP/2 or HTTP/3 Multiplexer)  │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   │                                    │
│         ┌─────────────────────────┴─────────────────────────┐          │
│         ▼                                                   ▼          │
│  ┌──────────────┐                                    ┌──────────────┐  │
│  │ HTTP/2 Track │ (quic=false)                       │ HTTP/3 Track │  │ (quic=true)
│  │ TLS 1.2/1.3  │                                    │ QUIC (RFC9000│  │
│  │ ALPN: h2     │                                    │ ALPN: h3     │  │
│  │ NCH2ClientCore                                    │ NWProtocolQUIC  │
│  └──────┬───────┘                                    └──────┬───────┘  │
└─────────┼───────────────────────────────────────────────────┼──────────┘
          │ (TCP:443)                                         │ (UDP:443)
          ▼                                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        TrustTunnel Endpoint Server                     │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Transport Layer: Two Parallel Tracks

TrustTunnel defines two distinct transport tracks configured via `quic: false` (HTTP/2) or `quic: true` (HTTP/3):

#### Track A: HTTP/2 over TLS (`quic: false`)
1. **Underlay**: TCP connection to the endpoint host/port wrapped in TLS (TLS 1.2 or 1.3) with ALPN negotiation selecting `h2`.
2. **Initial Parameters**: HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), empty SETTINGS frame, and initial stream window set to **131072 bytes** (RFC 7540 / Chrome default).
3. **TCP Flow Tunneling**: Each outgoing TCP connection allocates a new client stream ID (1, 3, 5, ...). A HEADERS frame with `:method: CONNECT`, `:authority: <target_host>:<target_port>`, and Basic Auth header is sent. Once the server returns `200 OK`, raw bidirectional bytes flow inside HTTP/2 DATA frames.
4. **UDP Flow Multiplexing**: A single dedicated stream is established using `CONNECT _udp2 HTTP/2`. All UDP datagrams are framed with TrustTunnel's UDP packet format and multiplexed over this single stream.
5. **Stream Termination**: Graceful closure uses `END_STREAM` (flag 0x01 on DATA or HEADERS); abrupt reset uses `RST_STREAM`.

#### Track B: HTTP/3 over QUIC (`quic: true`)
1. **Underlay**: QUIC connection (RFC 9000, version `0x00000001`) to endpoint host/port with ALPN negotiation selecting `h3`.
2. **Session Idle Timeout**: Configured as `2 * (connection_timeout + health_check_timeout)`.
3. **HTTP/3 Semantics**: Conforms to RFC 9114.
   - Client opens bidirectional stream.
   - Sends QPACK-encoded HEADERS frame (frame type `0x01`): `:method: CONNECT`, `:authority: <target>`, `proxy-authorization: Basic ...`.
   - Upon receiving `200 OK`, the stream transitions to transparent byte relay.
4. **UDP & ICMP**: Uses the same reserved pseudo-hosts (`_udp2` and `_icmp`) over a single bidirectional stream.

### 2.2 Reuse Points and Gaps with Existing NativeCore Code

| Component | Existing NativeCore Module | Reuse Status | Gaps to Address in S2 |
|---|---|---|---|
| **H2 Framing & State Machine** | `Shared/NativeCore/NCH2.swift` (`NCH2ClientCore`) | **Direct Reuse**: `start()`, `frame()`, `feed()`, `rstStream()`, `makeData()` and flow control | Current `NCH2ClientCore` only tracks a single active stream (streamID 1 for VMess/VLESS gRPC). TrustTunnel multiplexes multiple streams (1, 3, 5, ...); needs multi-stream ID dispatch table in `NCTrustTunnelH2Session`. |
| **HPACK Encoding/Decoding** | `Shared/NativeCore/NCHPACK.swift` | **Direct Reuse**: Static and literal header encoding | None. Full static table and integer encoding already present. |
| **QUIC Connection & Options** | `Shared/NativeCore/NCQUIC.swift`, `PacketTunnel/NativeCore/NCTUIC.swift` | **Direct Reuse**: `NWProtocolQUIC.Options` with ALPN negotiation | Needs ALPN set to `["h3"]` and QUIC bidirectional stream handler for CONNECT. |
| **HTTP/3 Frame & QPACK Decoding** | `Shared/NativeCore/NCHysteria2.swift` (`NCHy2`) | **Direct Reuse**: `http3Frame()`, `http3SettingsFrame()`, `http3HeadersFrame()`, `qpackDecodeFieldSection()` | Need minimal QPACK literal encoder for outgoing request headers (compact ~25 lines of Swift). |
| **Backpressure Contract** | `Shared/NativeCore/NCConnector.swift` (`NCRelayStream`) | **Direct Reuse**: `send(_:completion:)` with `NCCallOnce` | Enforce flow-control window checks before firing completion, exactly as in `NCH2TunnelStream`. |
| **Session Queues & Threading** | `Shared/NativeCore/NCSessionQueues.swift` | **Direct Reuse**: Serial queue per session + `callerQueue` hopping pattern | Conforms to #116 thread-safety standard. |

### 2.3 Authentication Model

TrustTunnel strictly uses HTTP Basic Authentication on every CONNECT request:
- Header: `proxy-authorization: Basic <base64(username + ":" + password)>`
- Endpoint status responses:
  - `200 OK`: Successful authorization and tunnel connection. Plaintext data begins immediately.
  - `407 Proxy Authentication Required`: Credentials invalid or expired (custom HTTP/2 error code `0x1F`). Client MUST terminate session and request re-authentication.
  - Other 4xx/5xx: Server errors; treated as connection failure.
- Health Check: Periodic probe to reserved pseudo-host `_check` with Basic Auth. `200 OK` confirms session health. Default timeout: 7000 ms.

### 2.4 Wire Formats

#### UDP Datagram Framing (Over `CONNECT _udp2`)

- **Client → Endpoint (Outgoing)**:
  ```text
  +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
  |  Length  | Source Address | Source Port | Destination Address | Destination Port | App Name Len (L) | App Name | Payload |
  | 4 bytes  |    16 bytes    |   2 bytes   |      16 bytes       |     2 bytes      |      1 byte      | L bytes  | N bytes |
  +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
  ```
  - `Length`: 32-bit big-endian unsigned integer (total byte length excluding this 4-byte field).
  - `Source Address`: 16 bytes. IPv4 addresses are zero-padded to 16 bytes with 12 leading zero bytes:
    `00 00 00 00 00 00 00 00 00 00 00 00 [4 bytes IPv4]`
  - `Source Port`: 16-bit big-endian port.
  - `Destination Address`: 16 bytes (zero-padded for IPv4).
  - `Destination Port`: 16-bit big-endian port.
  - `App Name Length`: 1 byte (0–255).
  - `App Name`: UTF-8 bundle identifier / executable name.
  - `Payload`: Raw UDP datagram bytes.

- **Endpoint → Client (Incoming)**:
  ```text
  +----------+----------------+-------------+---------------------+------------------+---------+
  |  Length  | Source Address | Source Port | Destination Address | Destination Port | Payload |
  | 4 bytes  |    16 bytes    |   2 bytes   |      16 bytes       |     2 bytes      | N bytes |
  +----------+----------------+-------------+---------------------+------------------+---------+
  ```
  Note: Incoming packets omit the `App Name Length` and `App Name` fields.

#### Reserved Pseudo-Hosts

| Pseudo-Host | Port | Purpose |
|---|---|---|
| `_udp2` | 0 | Multiplexed UDP datagrams stream |
| `_icmp` | 0 | Multiplexed ICMP echo stream |
| `_check` | 0 | Health check probe stream |

### 2.5 Memory & Jetsam Considerations

iOS NetworkExtension PacketTunnel Provider enforces a hard 50 MB jetsam memory limit:
1. **Zero Large Intermediate Buffers**: Parsing uses byte offset walks (`off`) followed by a single buffer compaction (`Data(buffer[off...])`) per feed chunk, avoiding quadratic memory reallocation.
2. **Strict Queue Caps**:
   - `maxPendingSend`: 256 KB per stream.
   - `maxQueuedInbound`: 256 KB per stream.
   If peer windows stall or uplink queue overflows, the stream fails cleanly with RST rather than causing jetsam kill.
3. **Uplink Backpressure**: All `send(_:completion:)` completions wait until bytes are window-accepted by the H2/H3 core and accepted by the underlay socket, preventing the TUN device from flooding memory.
4. **Connection Pooling**: Default `max-streams` capped at 12 (matching Surge/Mihomo recommendation); connection pool capped at 8 connections.

---

## 3. Supported Fields Table

| Canonical Field | Clash / Mihomo YAML | Surge / Loon `.conf` | Deep Link `tt://?` (TLV Tag) | Type | Default | Description |
|---|---|---|---|---|---|---|
| `server` | `server` | Positional 1 | `0x02` `addresses` | String | Required | Endpoint server hostname or IP address |
| `port` | `port` | Positional 2 | `0x02` `addresses` | Int | 443 | Endpoint port |
| `username` | `username` | `username` | `0x05` `username` | String | Required* | Basic Auth username (*optional if subscription_url present) |
| `password` | `password` | `password` | `0x06` `password` | String | Required* | Basic Auth password (*optional if subscription_url present) |
| `quic` | `quic` | `h3` / `quic` | `0x09` `upstream_protocol` | Bool | `false` | Transport selection: `false` = HTTP/2 over TLS, `true` = HTTP/3 over QUIC |
| `network` | `network` | - | `0x09` (derived) | String | `"h2"` / `"h3"` | Stream transport identifier |
| `sni` / `servername` | `sni` | `sni` | `0x03` `custom_sni` / `0x01` `hostname` | String | `server` | TLS SNI hostname override |
| `skip-cert-verify` | `skip-cert-verify` | `skip-cert-verify` | `0x07` `skip_verification` | Bool | `false` | Bypass TLS certificate verification |
| `alpn` | `alpn` | `alpn` | - | [String] / String | `["h2"]` / `["h3"]` | Custom TLS ALPN list |
| `udp` | `udp` | - | - | Bool | `true` | Enable UDP forwarding over `_udp2` stream |
| `name` | `name` | Section key | `0x0c` `name` | String | `server` | Human-readable node display name |
| `max-streams` | `max-streams` | `max-streams` | - | Int | 12 | Maximum multiplexed streams per connection |
| `headers` | - | `headers` | - | String | nil | Custom HTTP handshake headers (Surge format) |
| `dns-upstreams` | - | - | `0x0d` `dns_upstreams` | [String] | `[]` | Upstream DNS servers for node |
| `subscription-url` | - | - | `0x0e` `subscription_url` | String | nil | Remote HTTPS subscription URL for auto-update |
| `has-ipv6` | - | - | `0x04` `has_ipv6` | Bool | `true` | IPv6 routing support flag |

---

## 4. Unsupported Fields & Technical Reasons

| Unsupported Field | Source Dialect | Unsupported Reason (Shown in 诊断 / Log) | Detailed Technical Reason |
|---|---|---|---|
| `anti-dpi` | Deep Link (Tag `0x0a`) | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | Anti-DPI alters TLS ClientHello handshake records. iOS Network.framework manages TLS handshakes internally and does not expose raw ClientHello record mutation. |
| `client-random-prefix` | Deep Link (Tag `0x0b`) | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | Injects custom prefix/mask into TLS ClientHello `random` bytes. Network.framework provides no API to inject custom client random entropy. |
| `client-random-auth-key` | Deep Link (Tag `0x0f`) | `TrustTunnel client-random-auth-key 尚未接入` | Derives TLS ClientHello random bytes from an auth key and SNI. Requires custom userspace TLS engine, unsupported on Network.framework. |
| `icmp` | Official Spec (§7) | `TrustTunnel icmp 尚未接入` | iOS NetworkExtension does not route arbitrary ICMP echo ping traffic via proxy streams; only TCP and UDP IP packets are forwarded. |
| `congestion-controller` / `bbr-profile` | Mihomo YAML | Evaluated by kernel; ignored without fatal error | iOS `NWProtocolQUIC` uses kernel-managed BBR/Cubic congestion control; custom user-pluggable algorithms are unavailable. |
| **Quantumult X format** | `[server_local]` | `quantumultx [server_local]: trusttunnel has no Quantumult X format specification; explicitly unavailable` | Quantumult X has never specified or implemented a `trusttunnel` proxy format. Attempted lines are explicitly rejected with warnings and not silently dropped. |

---

## 5. S2 Loopback Implementation & Verification

### 5.1 Official Server Feasibility & Port Allocation

The official server [TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) is written in Rust and licensed under Apache-2.0. Prebuilt standalone binary releases (`trusttunnel_endpoint`) are published for `linux-x86_64`, `linux-aarch64`, and `macos-universal` (Mach-O dual slice x86_64 + arm64).

- **Port Allocation**: Allocated to **18013** (per project port assignments, preserving 18015 for Sudoku). A single port 18013 serves both HTTP/2 (TCP) and HTTP/3 (UDP).
- **Local Execution**: The server runs locally in background:
  ```sh
  trusttunnel_endpoint tt-settings.toml tt-hosts.toml
  ```
- **Configuration Layout**:
  - `tt-settings.toml`:
    ```toml
    listen_address = "127.0.0.1:18013"
    credentials_file = "/tmp/nc-loopback/tt-credentials.toml"
    allow_private_network_connections = true

    [listen_protocols.http2]

    [listen_protocols.quic]

    [forward_protocol.direct]
    ```
  - `tt-hosts.toml`:
    ```toml
    [[main_hosts]]
    hostname = "localhost"
    cert_chain_path = "/tmp/nc-loopback/cert.pem"
    private_key_path = "/tmp/nc-loopback/key.pem"
    ```
  - `tt-credentials.toml`:
    ```toml
    [[client]]
    username = "nc-loop-tt-user"
    password = "nc-loop-tt-pw"
    ```

### 5.2 Integration into `tools/loopback/`

1. **`start-servers.sh`**:
   - Downloads pinned `trusttunnel_endpoint` v1.1.0 (`macos-universal` on macOS runner, `linux-x86_64`/`linux-aarch64` on Linux).
   - Dynamically renders `tt-settings.toml`, `tt-hosts.toml`, and `tt-credentials.toml` into `$NC_LOOPBACK_DIR`.
   - Starts `trusttunnel_endpoint` in background with PID written to `$NC_LOOPBACK_DIR/trusttunnel.pid`.
   - Verifies readiness with `wait_tcp 18013`.
   - Integrated into `status` and `stop` commands.
2. **`README.md`**:
   - Documented port 18013 in Topology table and coverage notes.

### 5.3 Loopback Test Cases (`NativeCoreLoopbackTests.swift`)

- `testTrustTunnelH2TCPEcho`: Dials `127.0.0.1:18080` (echo backend) via TrustTunnel H2 proxy on port 18013, sends 8192-byte test payload, validates byte-for-byte exact echo response.
- `testTrustTunnelH3TCPEcho`: Dials `127.0.0.1:18080` via TrustTunnel H3 (QUIC) proxy on port 18013, validates byte-for-byte exact echo response.
- `testTrustTunnelAuthFailure`: Connects using wrong password, verifies client rejects connection and returns authentication failure.

### 5.4 Test Results

- **Local Server Lifecycle**: Verified on Linux x86_64 (`start-servers.sh start`, `status`, `stop` all passed cleanly).
- **Local Protocol Handshake**: Verified with curl through `trusttunnel_endpoint` (`CONNECT 127.0.0.1:18080 HTTP/2` returned `200 OK`).
- **iOS Simulator Loopback Tests**: 待 CI（本机无 Xcode 环境，由 GitHub Actions `proto-loopback.yml` CI 验证）。
