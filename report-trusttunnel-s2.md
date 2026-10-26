# TrustTunnel（AdGuard）S2 交付报告

- **分支**: `feat/nc-trusttunnel`
- **基线**: `6fd4bab` (`xcstrings: ja/ko self-check titles use canonical terms`)
- **工作区**: `/home/hatch/mihomo-ios-test/repo-tt`
- **阶段**: S2（connector / 会话层 H2+H3 + 回环接入 + 单测补强 + 文档修订）

---

## 1. 交付文件清单

| 文件路径 | 状态 | 职责说明 |
|---|---|---|
| `Shared/NativeCore/NCTrustTunnelSession.swift` | **新增** | 会话层核心：`NCTrustTunnelSessionManager` 连接池调度；`NCTrustTunnelH2Session` / `NCTrustTunnelH2Stream`（基于 TLS+ALPN h2，多路复用流 1, 3, 5...，流控与 backpressure，Basic 认证）；`NCTrustTunnelH3Session` / `NCTrustTunnelH3Stream`（基于 NWConnectionGroup + QUIC ALPN h3，QPACK CONNECT 头封装与响应解析，透明 byte relay） |
| `Shared/NativeCore/NCConnector.swift` | **修改** | 将 S1 占位分支替换为正式分发：校验不支持字段（`trusttunnelUnsupported`），转正至 `NCTrustTunnelSessionManager.connect`，App 可用性转正 |
| `Shared/NativeCore/NCStream.swift` | **修改** | TLS 初始化方法增加可选 `alpn: [String]? = nil` 支持，使用 Apple Security 规范 API `sec_protocol_options_add_tls_application_protocol` 协商 ALPN |
| `Shared/NativeCore/NCMux.swift` | **修改** | `NCH2MuxCore.openStream` 扩展支持传入自定义 `headers: [(String, String)]? = nil`，无缝复用多流 H2 帧解码与流控核心 |
| `Shared/NativeCore/NCTrustTunnel.swift` | **修改** | `NCTrustTunnelWire` 增加 `qpackConnectHeaders`，按 RFC 9204 / RFC 9220 规范输出 HTTP/3 CONNECT 请求头部字段块 |
| `tools/loopback/start-servers.sh` | **修改** | 官方服务端接入：增加 `trusttunnel_endpoint` v1.1.0 自动拉取（macOS universal 双架构 / Linux 多架构），动态生成 `tt-settings.toml`、`tt-hosts.toml`、`tt-credentials.toml`，在端口 `18013` 启动管理，生命周期并入 start/stop/status |
| `tools/loopback/README.md` | **修改** | 拓扑表与覆盖说明增加端口 `18013` `trusttunnel_endpoint`（H2 TCP 与 H3 UDP 双栈）及 echo 覆盖记录 |
| `UnitTests/NativeCoreLoopbackTests.swift` | **修改** | 回环用例接入：端口 `18013` 探活检查，增加 `testTrustTunnelH2TCPEcho`、`testTrustTunnelH3TCPEcho` 与 `testTrustTunnelAuthFailure` |
| `UnitTests/NativeCoreTrustTunnelTests.swift` | **修改** | 单测补强：增加 `testFrameCodecBoundaries`（截断数据、长度越界、VarInt 边界、IP 填充校验）、`testQPACKConnectHeadersRoundtrip`、`testAuthenticationFailurePaths`（407 认证失败路径提取） |
| `docs/nc-proto-trusttunnel.md` | **修改** | 更新 S2 实现现状、回环服务端真实配置、端口分配与测试记录 |
| `report-trusttunnel-s2.md` | **新增** | 本报告 |

---

## 2. 回环端口分配确认

在接入前严格核对 `tools/loopback/` 现有分配：
- `18001`: Shadowsocks (`aes-256-gcm`)
- `18002`: Shadowsocks 2022 (`2022-blake3-aes-128-gcm`)
- `18003`: VMess
- `18004`: VLESS
- `18005`: Trojan
- `18006`: Hysteria2
- `18007`: TUIC
- `18008`: WireGuard
- `18013`: **TrustTunnel (`trusttunnel_endpoint`)**（TCP 供 H2 监听，UDP 供 QUIC/H3 监听，同端口双协议）
- `18015`: 预留 Sudoku（未占用、绝不越界）
- `18080` / `18081` / `18082` / `18083`: Echo / Blackhole / Control 后端

**结论**: `tools/loopback/start-servers.sh`、`tools/loopback/README.md`、`UnitTests/NativeCoreLoopbackTests.swift`、`docs/nc-proto-trusttunnel.md` 全部统一为 **18013**。

---

## 3. 官方服务端可行性与验证证据

### 3.1 官方服务端发布与架构兼容性
- 官方仓库：`TrustTunnel/TrustTunnel`（Version 1.1.0 锁定）。
- CI 平台 `macos-15`（Apple Silicon）：官方 Release 提供 `trusttunnel-v1.1.0-macos-universal.tar.gz`，解包验证二进制 `trusttunnel_endpoint` 为 Mach-O Universal 格式，包含 `arm64` 与 `x86_64` 双架构切片，可直接在 GitHub Actions `macos-15` runner 原生运行。
- Linux（x86_64 / aarch64）：官方 Release 提供原生静态编译包。

### 3.2 本地运行与协议握手实测证据
在本地测试环境配置 `start-servers.sh` 后运行实测：
1. **服务启动与探针验证**:
   ```text
   [loopback] downloading trusttunnel_endpoint 1.1.0 (trusttunnel-v1.1.0-linux-x86_64)
   [loopback] sing-box check
   [loopback] starting echo_server.py
   [loopback] starting sing-box sing-box version 1.12.24
   [loopback] starting trusttunnel_endpoint 1.1.0
   [loopback] ready: ss :18001 ss2022 :18002 vmess :18003 vless :18004 trojan :18005 hy2 :18006 tuic :18007 wg :18008 tt :18013 echo :18080/:18081 blackhole :18082
   ```
2. **服务端双协议监听日志**:
   ```text
   [INFO] [trusttunnel::core] Listening to TCP 127.0.0.1:18013
   [INFO] [trusttunnel::core] Listening to UDP 127.0.0.1:18013
   ```
3. **HTTP/2 CONNECT 握手实测（通过 curl 代理通道验证）**:
   ```text
   * Establish HTTP/2 proxy tunnel to 127.0.0.1:18080
   * Proxy auth using Basic with user 'nc-loop-tt-user'
   * CONNECT tunnel established, response 200
   * CONNECT phase completed
   ```
   服务端日志：
   ```text
   [DEBUG] [trusttunnel::core] [CLIENT=0] New TCP client: 127.0.0.1:54558
   [TRACE] [trusttunnel::core] [CLIENT=0] Starting TLS handshake
   [TRACE] [trusttunnel::tunnel] [CLIENT=0/TUN=0/CONN=0] Authentication complete, promoting request
   [TRACE] [trusttunnel::tunnel] [CLIENT=0/TUN=0/CONN=0] TCP connect: connecting to peer: 127.0.0.1:18080
   [DEBUG] [trusttunnel::tunnel] [CLIENT=0/TUN=0/CONN=0] Successfully connected to TcpConnectionMeta { client_address: 127.0.0.1, destination: Address(127.0.0.1:18080), auth: Some(ProxyBasic(__stripped__)), tls_domain: "localhost", user_agent: Some("curl/8.5.0") }
   ```

---

## 4. 字段表现状与不支持标记

### 4.1 支持字段

| 字段 | 来源格式 | 类型 | 默认值 | 会话与数据面实现说明 |
|---|---|---|---|---|
| `server` | 全部 | String | 必填 | 远端服务器主机名或 IP |
| `port` | 全部 | Int | 443 | 远端服务器端口 |
| `username` | 全部 | String | 必填* | 每条 CONNECT 请求携带 `proxy-authorization: Basic <base64>` |
| `password` | 全部 | String | 必填* | Basic Auth 认证密码 |
| `quic` / `network` | YAML / Conf / DeepLink | Bool / String | `false` / `h2` | 传输路由：`false` / `"h2"` 走 `NCTrustTunnelH2Session`；`true` / `"h3"` 走 `NCTrustTunnelH3Session` |
| `sni` / `servername` | 全部 | String | `server` | TLS SNI 主机名覆盖 |
| `skip-cert-verify` | 全部 | Bool | `false` | 自签名证书验证绕过（跳过服务端证书链校验） |
| `max-streams` | YAML / Conf / URI | Int | 12 | H2 会话单连接最大并发流上限，超限自动建立新连接或返回错误 |
| `alpn` | YAML / Conf / URI | [String] | `["h2"]`/`["h3"]` | 自定义 TLS ALPN 列表 |
| `udp` | YAML | Bool | `true` | UDP 多路复用开关（经 `_udp2` 伪主机单流传输） |
| `name` | 全部 | String | `server` | 节点展示名称 |

### 4.2 不支持字段及显式标记（绝不静默丢弃）

| 字段 | 诊断日志中文提示 | 技术原因与断言依据 |
|---|---|---|
| `anti-dpi` | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | iOS Network.framework 由内核驱动 TLS 握手，不暴露 raw ClientHello 帧修改能力 |
| `client-random-prefix` | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | Network.framework 不提供注入自定义 ClientHello random entropy 的 API |
| `client-random-auth-key` | `TrustTunnel client-random-auth-key 尚未接入` | 基于 SNI 与 auth key 派生 ClientHello 随机数，受限于系统 TLS 黑盒机制 |
| `icmp` | `TrustTunnel icmp 尚未接入` | iOS NetworkExtension 不支持在代理流上暴露原生 ICMP echo 链路 |
| **Quantumult X 节点** | `quantumultx [server_local]: trusttunnel has no Quantumult X format specification; explicitly unavailable` | Quantumult X 官方从未发布 TrustTunnel 规范；显式打回并记录 warning |

---

## 5. 测试与 CI 状态

- **单元测试 (`UnitTests/NativeCoreTrustTunnelTests.swift`)**:
  - `testFrameCodecBoundaries`: 覆盖小于 4 字节截断、长度字段溢出、小于 36 字节头部、AppName 变长字段越界截断、非法 IP 填充、8 组 VarInt 边界值（0, 63, 64, 16383, 16384, $2^{30}-1$, $2^{30}$, $2^{62}-1$）及 3 组各前缀级别截断异常。
  - `testQPACKConnectHeadersRoundtrip`: 覆盖 RFC 9204 / RFC 9220 CONNECT 头部编码与 `NCHy2.qpackDecodeFieldSection` 解码字段一致性。
  - `testAuthenticationFailurePaths`: 覆盖 H2 407 响应解析与 H3 407 QPACK 响应解析。
- **回环测试 (`UnitTests/NativeCoreLoopbackTests.swift`)**:
  - `testTrustTunnelH2TCPEcho`: H2 隧道端到端 8192 字节 echo 验证。
  - `testTrustTunnelH3TCPEcho`: H3 隧道端到端 8192 字节 echo 验证。
  - `testTrustTunnelAuthFailure`: 认证失败路径验证（错误凭据拦截并返回 407/Auth 错误）。
  - 本机无 Xcode 环境，回环执行结论写为 **“待 CI”**。

---

## 6. 红线核验

- [x] 仅在 `~/mihomo-ios-test/repo-tt` 的 `feat/nc-trusttunnel` 分支工作；
- [x] 绝未触动 `main` 和 `feat/nc-kernel` 分支；
- [x] 未开 PR、未触发 CI（commit 带 `[skip ci]`）；
- [x] 纯 Swift 代码，零 Go 代码，零新增第三方依赖；
- [x] 节奏调整：核心代码在第一提交已提前落盘并 push，本轮完成回环设施、单测补强与文档并做第二提交 push；
- [x] 括号配平、静态自洽，所有符号引用真实存在；
- [x] 字段与端口分配完整统一。
