# NativeCore: MASQUE (RFC 9298 / RFC 9484) — design note (feat/nc-masque, based on 6fd4bab)

> **Status (fix/nc-masque-ip, 2026-10-27):** RFC 9484 **CONNECT-IP** over HTTP/3 is implemented as an L3 data plane:
> `NCMASQUEIPTunnel` (Shared/NativeCore/NCMASQUEIP.swift — Extended CONNECT `:protocol = connect-ip`, ADDRESS_ASSIGN /
> ROUTE_ADVERTISEMENT / DATAGRAM capsules, IP packets as HTTP Datagrams with context id 0) feeding a per-node lwIP netif
> (`NCMQIPDevice`, PacketTunnel/NativeCore/NCMASQUEIPNetif.swift, `NCLwIPDevice` like WireGuard / OpenConnect). TCP flows go
> through `NCConnector.masqueIPDialer` (NCWGTCPStream on the netif), UDP through `NCUDPWireGuardSession` with the CONNECT-IP
> device, names through the node's `dns` over the tunnel. A generic node is `mode: connect-ip` + `uri` (absolute template;
> `{target}` / `{ipproto}` expand to `*`; `:authority` comes from the template host), credentials optional.
> Generic CONNECT-IP nodes are **available** (`NCMASQUE.connectIPVerified = true`) after the real loopback went green —
> proto-loopback.yml job `masque-ip`, upstream connect-ip-go integration proxy in an Alpine VM under QEMU
> (tools/loopback/connectip): 1 MiB TCP echo byte-exact, UDP echo, UDP DNS, tunnel DNS by name, HTTP 304000 B, routes,
> redial, 404 refusal (8/8, mirror runs 40464266033 and 40468656765). Netif MTU ≤ 1193 (QUIC DATAGRAM room); nc_wg clamps
> each connected PCB's MSS to its device MTU.
> Still not wired: **Cloudflare WARP** profiles (key pair → Cloudflare's `cf-connect-ip` protocol + an mTLS client identity
> built from the WARP private key + server-key pinning; shown as `NCMASQUE.warpUnavailable`), CONNECT-IP over HTTP/2,
> CONNECT-TCP / `h3-l4proxy`, IP flow forwarding (scoped `{target}` templates), reconnect keeping flows (a lost tunnel tears
> the netif down; the next flow redials).
>
> WARP profile format (for the follow-up; documented from public client implementations, not verified here): Clash-style
> `type: masque` with `private-key` (base64 / PEM ECDSA P-256 — the client certificate key), `public-key` (Cloudflare's
> endpoint P-256 key, pinned), `ip` / `ipv6` (addresses from WARP registration; the server does not need to assign),
> `server` 162.159.198.x / `port` 443, `sni` consumer-masque.cloudflareclient.com, `uri` https://cloudflareaccess.com,
> `mtu` 1280. The request uses `:protocol = cf-connect-ip` and HTTP/3 SETTINGS including H3_DATAGRAM_00 (0x276).

> **Status (fix/nc-proto-masque-int, 2026-10-27):** RFC 9298 CONNECT-UDP over HTTP/3 is wired for **UDP flows**
> (NCUDPMASQUESession) and loopback-verified against masque-go. TCP flows through a MASQUE node are refused
> (CONNECT-UDP carries datagrams only); WARP / CONNECT-IP and h3-l4proxy nodes are parsed but shown unavailable.

Status 2026-10-26 (S2 Deliverable): Data plane connector implemented (`Shared/NativeCore/NCMASQUESession.swift`), RFC 9298 Extended CONNECT negotiation, Quarter Stream ID multiplexing, HTTP/3 Datagram (RFC 9297) forwarding, and Capsule Protocol fallback completed. NCConnector integrated with real dispatch. CONNECT-IP explicitly guarded at connector with descriptive error (requiring PacketTunnel lwIP L3 integration). Loopback server (`masque-proxy`, MIT) integrated into `tools/loopback` on port 18012 (avoiding WG/OpenConnect collisions). Loopback echo test added in `UnitTests/NativeCoreLoopbackTests.swift`. Unit tests hardened with boundary and failure path coverage.

---

## 1. 协议规范与调研背景

MASQUE（Multiplexed Application Substrate over QUIC Encryption）是 IETF MASQUE 工作组制订的一套基于 HTTP/3 与 HTTP/2 的现代化代理与安全组网隧道标准体系。本实现以 IETF 正式发布的标准 RFC 与主流客户端（Shadowrocket 2.2.90+、Clash.Meta Alpha、Surge 5.22.0+）的生产实现为基准。

### 1.1 核心 RFC 规范

1. **RFC 9298 — Proxying UDP in HTTP (CONNECT-UDP)**:
   - **升级标识符**: `:protocol = connect-udp`
   - **请求方法**: HTTP/3 与 HTTP/2 下采用 Extended CONNECT 方法（`:method = CONNECT`），包含 `:scheme = https`、`:authority = <proxy_host>`、`:path = <expanded_uri_template>`。
   - **默认 URI 模板**: `https://<proxy_host>:<proxy_port>/.well-known/masque/udp/{target_host}/{target_port}/`。
   - **Datagram 线格式**: 承载于 QUIC DATAGRAM 帧中，格式为 `Quarter Stream ID (varint)` + `Context ID (varint)` + `UDP Payload`。Context ID `0` 保留给原始 UDP 载荷，单包最大长度限制为 65527 字节。
   - **控制通道**: 请求与响应头部携带 `capsule-protocol = ?1`，协商启用 Capsule Protocol。

2. **RFC 9484 — Proxying IP in HTTP (CONNECT-IP)**:
   - **升级标识符**: `:protocol = connect-ip`
   - **请求方法**: Extended CONNECT，默认 URI 模板为 `https://<proxy_host>:<proxy_port>/.well-known/masque/ip/{target}/{ipproto}/`；全流量隧道时取通配符 `/.well-known/masque/ip/*/*/`。Cloudflare WARP 生产服务采用 `https://cloudflareaccess.com`。
   - **Datagram 线格式**: 承载于 QUIC DATAGRAM 帧中，格式为 `Quarter Stream ID (varint)` + `Context ID (varint)` + `IP Packet Payload`。Context ID `0` 保留给完整 IPv4/IPv6 数据包。
   - **胶囊协议控制信息**:
     - `ADDRESS_ASSIGN (0x01)`: 服务端下发分配的客户端 IP/前缀（Request ID varint, IP Version u8, IP Address 4/16B, Prefix Length u8）。
     - `ADDRESS_REQUEST (0x02)`: 客户端向服务端申请分配特定或任意（全0）IP。
     - `ROUTE_ADVERTISEMENT (0x03)`: 路由宣告（IP Version u8, Start IP, End IP, IP Protocol u8）。

3. **RFC 9297 — HTTP Datagrams and the Capsule Protocol**:
   - **协商机制**: HTTP/3 控制流（Stream Type `0x00`）上的 SETTINGS 帧中通告 `SETTINGS_H3_DATAGRAM = 0x33` (51) = 1。向后兼容早期 Cloudflare WARP 草案通告 `SETTINGS_H3_DATAGRAM_00 = 0x276` (630) = 1。
   - **Quarter Stream ID**: 请求流为客户端发起的双向流，其 stream ID 必为 4 的倍数，在 Datagram 头部取 `stream_id / 4`（varint），压缩传输开销。
   - **Capsule 协议格式**: `Capsule Type (varint)` + `Capsule Length (varint)` + `Capsule Value (bytes)`。运行于请求流的 DATA 帧内。
   - **DATAGRAM 胶囊 (0x00)**: 当底层传输不具备 QUIC DATAGRAM 帧能力（或运行于 HTTP/2 / TCP）时，通过 DATA 帧内的 DATAGRAM 胶囊承载 `Context ID (varint)` + `Payload`。

4. **RFC 8441 / RFC 9220 — Extended CONNECT in HTTP/2 and HTTP/3**:
   - 允许在 CONNECT 方法中携带 `:protocol` 伪头字段实现协议升级。
   - 服务端必须在 SETTINGS 帧中通告 `SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08` (8) = 1。

---

## 2. 架构设计与已有能力边界

NativeCore 坚持纯 Swift、零第三方包、内存优先的设计原则。MASQUE 协议栈的设计严格建立在已实测的现有基础设施之上。

### 2.1 双轨架构（Dual Architecture）

MASQUE 在生态中分为两条应用路线，本设计对二者提供统一建模：

```
+-------------------------------------------------------------------------+
|                        NativeCore MASQUE Outbound                       |
+-------------------------------------------------------------------------+
       |                                                 |
       v (Line A: L4 代理)                                v (Line B: L3 组网隧道)
 [RFC 9298 CONNECT-UDP]                          [RFC 9484 CONNECT-IP]
 (Surge / RFC 标准代理模式)                         (Cloudflare WARP / 私有组网)
       |                                                 |
       +--------------------+   +------------------------+
                            |   |
                            v   v
+-------------------------------------------------------------------------+
|                    HTTP/3 Extended CONNECT & Capsule                    |
|      (:method CONNECT, :protocol, capsule-protocol: ?1, SETTINGS)      |
+-------------------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------------------+
|                HTTP Datagram Layer (Quarter Stream ID + Context ID)     |
+-------------------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------------------+
|  Network.framework QUIC Group (NWConnectionGroup + NWProtocolQUIC)       |
|  - Unidirectional: H3 Control Stream (0x00 + SETTINGS 0x08, 0x33, 0x276)|
|  - Bidirectional: Request Streams (group.extract)                       |
|  - Datagram Channel: isDatagram = true, maxDatagramFrameSize = 1400     |
+-------------------------------------------------------------------------+
```

1. **Line A — CONNECT-UDP（L4 逐流代理）**:
   - 对标 Surge MASQUE 实现。
   - 客户端每个 UDP 转发请求动态开启一个双向 stream，发送 Extended CONNECT（`:protocol = connect-udp`，URI 包含目标主机与端口）。
   - 在该 stream 关联的 Quarter Stream ID 下，用 Context ID 0 双向收发 UDP 报文载荷。
2. **Line B — CONNECT-IP（L3 IP 数据包隧道）**:
   - 对标 Clash.Meta `type: masque` 与 Cloudflare WARP MASQUE 实现。
   - 建立单条长期存在的 Extended CONNECT 请求流（`:protocol = connect-ip`）。
   - 通过 Capsule 协商 IP 地址与路由（`ADDRESS_ASSIGN`、`ROUTE_ADVERTISEMENT`）。
   - 隧道侧将 lwIP 用户态协议栈绑定的虚拟网卡 IP 数据报文，直接打包为 Context ID 0 的 HTTP Datagrams 发送，将收到的 IP 报文注入 lwIP `netif->input`（架构完全对齐既有 WireGuard `nc_wg` 双网卡模型）。

### 2.2 现有 QUIC / H3 能力复用点

经深入查验代码库，MASQUE 可直接复用以下底层能力：
1. **Network.framework QUIC 基础设施 (`Shared/NativeCore/NCQUICStreamOptions.swift`, `NCHysteria2.swift`, `NCTUICUDP.swift`)**:
   - `NWConnectionGroup` 结合 `NWMultiplexGroup` 的多路复用连接生命周期管理。
   - `NCQUICStreamOptions.unidirectional`: 克隆创建单向控制流（已在 Hysteria2 / TUIC 经过真机与回环验证，规避了 `ENETDOWN` 坑）。
   - `NCQUICStreamOptions.datagram`: 克隆创建 RFC 9221 QUIC Datagram 报文流（`isDatagram = true`, `maxDatagramFrameSize = 1400`）。
   - `c.receiveMessage` 与 `c.send(content:contentContext:isComplete:completion:)` 的报文级别收发。
2. **HTTP/3 基础编解码 (`Shared/NativeCore/NCHysteria2.swift`)**:
   - `varintEncode` / `varintDecode`：QUIC RFC 9000 §16 变长整数编解码。
   - `http3Frame(type:payload:)`：H3 帧封装。
   - QPACK 静态表与静态字面量编解码器（`qpackEncodeInteger`, `qpackEncodeString`, `qpackDecodeFieldSection`）。
3. **HTTP/2 客户端状态机 (`Shared/NativeCore/NCH2.swift`)**:
   - `NCH2ClientCore`：当节点指定 `network: h2` 时，提供 H2 帧循环、流量控制窗口管理与 DATA 帧胶囊传输。
4. **加密与凭据库 (`Shared/NativeCore/NCTLS13.swift`, `CryptoKit`)**:
   - ECDSA P-256 私钥自签名证书生成（SecIdentity / TLS 客户端证书），支持 WARP MASQUE mTLS。
   - 服务端公钥指纹比对与固定（Peer Public Key Pinning）。

### 2.3 能力缺口与逐项清单（Gaps）

为使 MASQUE 在 S2 完整跑通，需补齐的缺口如下：

| 缺口编号 | 模块 | 现有状态 | MASQUE 需求 | 解决路径 |
|---|---|---|---|---|
| **GAP-1** | H3 SETTINGS 协商 | 仅通告 `0x01` (QPACK), `0x07`, `0x33` (H3_DATAGRAM) | 须补齐 `SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08`，且对 WARP 需兼顾 `0x276` | 在 `NCMASQUE.http3SettingsFrame` 中组装，S2 连接握手时发送 |
| **GAP-2** | QPACK Extended CONNECT | 仅实现了 POST /auth 的专用 QPACK 编码 | 需编码 `:method CONNECT`, `:protocol`, `:scheme https`, `:authority`, `:path`, `capsule-protocol ?1` | 已在 `NCMASQUE.qpackEncodeExtendedConnect` 实现，复用静态表索引 15, 23, 0, 1 |
| **GAP-3** | Capsule 协议解析器 | 无 Capsule 协议实现 | 需解析与封装 TLV 胶囊流，支持 `0x00` (DATAGRAM), `0x01` (ADDRESS_ASSIGN), `0x02`, `0x03` | 已在 `NCMASQUE.CapsuleParser` 与数据结构中实现 |
| **GAP-4** | Datagram 上下文多路分发 | TUIC/Hy2 为全局单一 UDP 会话 | CONNECT-UDP 需按 `Quarter Stream ID` 路由到对应流，按 `Context ID` 解析（0 为 UDP/IP 报文） | S2 实现 `NCMASQUEDatagramDemuxer`：哈希表 `quarterStreamID -> Handler` |
| **GAP-5** | WARP mTLS 证书注入 | 现有 TLS 配置只校验服务端证书 | WARP MASQUE 要求客户端以 P-256 私钥生成临时自签名证书作为客户端证书，并固定服务端公钥 | S2 利用 `Security.framework` 创建 `SecIdentity` 或在 TLS ClientHello 注入客户端证书，并在 `sec_protocol_options_set_verify_block` 比对 `public-key` |
| **GAP-6** | L3 IP 栈对接 | WireGuard 已完成 lwIP 第二 netif 对接 | CONNECT-IP 需在 lwIP 建立虚拟接口，接收服务端分配的 IP/前缀，双向中继 IP 报文 | 复用 `lwip/nc_wg` 现成的 netif 注册与 PCB 绑定机制（`nc_wg_netif_add`） |

---

## 3. 内存管理与性能关键点

1. **Jetsam 50MB 红线控制**:
   - iOS Network Extension 内存硬限制为 50MB。MASQUE 属于长连接多路复用协议，严禁在收发包热路径上分配临时大缓冲。
   - `CapsuleParser` 采用原地切片（`Data.SubSequence`）与增量偏移扫描（offset walk），仅在缓冲区耗尽或解析完毕后执行一次压实，避免 $O(N^2)$ 的多次前缀切片拷贝。
2. **Datagram 零拷贝与截断防护**:
   - RFC 9298 规定 UDP 报文上限为 65527 字节；QUIC DATAGRAM 单帧上限受限于 PMTU（通常为 1280~1400 字节）。
   - 发送时直接在原有报文前面拼接 `Quarter Stream ID (varint)` 与 `Context ID (varint)`（通常为 2 字节），接收时通过指针切片取出 payload，避免内存拷贝。
   - 严禁缓冲未决的未知 Context ID 报文超过 1 个 RTT，缓冲上限设为 16 帧，防范恶意对端利用内存耗尽进行拒绝服务攻击（RFC 9297 §3.2）。
3. **避免死锁与流控积压 (RFC 9297 §3.2)**:
   - 当使用 DATAGRAM 胶囊通过 stream DATA 帧传输时，不能在流控窗口内无限制累积胶囊数据；接收端按到达顺序流式处理，及时释放底层流控窗口更新（WINDOW_UPDATE）。

---

## 4. 字段对标与支持表

### 4.1 支持字段表（Supported Fields）

| 字段名 (Clash YAML) | 字段名 (Shadowrocket) | 字段名 (Surge) | 类型 | 含义与默认值 | 行为说明 |
|---|---|---|---|---|---|
| `name` | `#<fragment>` | `Name =` | String | 节点名称 | 节点唯一标识 |
| `type` | `masque://` | `masque` | String | 协议类型 | 统一映射为 canonical `masque` |
| `server` | `<host>` | `<host>` | String | 服务器地址 | 域名、IPv4 或 IPv6（支持括号 `[::1]`） |
| `port` | `<port>` | `<port>` | Int | 服务器端口 | 必须为有效正整数 (1-65535) |
| `private-key` | `privateKey` | `private-key` | String | 客户端私钥 | P-256 私钥，支持 base64 或 PEM 格式（自动清洗头尾） |
| `public-key` | `publicKey` | `public-key` | String | 服务端公钥 | P-256 公钥，用于固定认证（Pinning） |
| `ip` | `ip` / `tunnelIp` | `ip` | String | 客户端 IPv4 | 隧道内部分配的 IPv4 地址或 CIDR |
| `ipv6` | `ipv6` | `ipv6` | String | 客户端 IPv6 | 隧道内部分配的 IPv6 地址或 CIDR |
| `uri` | `template` / `uri` | `uri` | String | URI / 模板 | 默认为 `https://cloudflareaccess.com` 或 RFC 9298 默认路径 |
| `sni` | `sni` | `sni` | String | TLS SNI | 缺省时为 `consumer-masque.cloudflareclient.com` |
| `alpn` | `alpn` | `alpn` | [String] | TLS ALPN | 默认为 `["h3"]`（`network: h2` 时为 `["h2"]`） |
| `mtu` | `mtu` | - | Int | 隧道 MTU | 默认 1280，控制分片上限 |
| `udp` | `udp` | `udp-relay` | Bool | 是否启用 UDP | 默认 true |
| `remote-dns-resolve` | - | - | Bool | 远端 DNS 解析 | 是否通过节点解析域名 |
| `dns` | `dns` | - | [String] | 节点 DNS | 逗号分隔或数组，如 `1.1.1.1, 8.8.8.8` |
| `congestion-controller` | `cc` | - | String | 拥塞控制算法 | `bbr` / `cubic`（受限于系统内核支持） |
| `flag` | `flag` | - | String | 节点标签 | 如 `CDN`，用于展示 |
| `username` | - | `username` | String | HTTP Basic 用户名 | RFC 9298 代理认证凭据 |
| `password` | - | `password` | String | HTTP Basic 密码 | RFC 9298 代理认证凭据 |
| `mode` | `mode` | - | String | 运行模式 | `connect-udp`（支持出站代理）, `connect-ip`（模型已支持，连接器层显式拦截引导隧道） |
| `network` | `network` | - | String | 传输网络模式 | 支持 `quic` / `h3`（默认）, `h2`, `h3-l4proxy` |
| `skip-cert-verify` | - | `skip-cert-verify`| Bool | 跳过证书链校验 | WARP 模式下服务端通常非域名证书，需配合公钥固定 |

### 4.2 未支持字段表及原因（Unsupported Fields）

任何配置中出现以下未支持字段时，解析层与 `NCSupport` 均**显式标记节点为不可用并在诊断界面显示原因，绝不静默丢弃**：

| 字段名 | 来源 | 不支持原因与阻断级别 | 处理行为 |
|---|---|---|---|
| `ip-stack: gvisor` | Clash.Meta YAML | iOS NativeCore 仅采用纯 Swift 与轻量内置 lwIP，无 Go 运行时及 gVisor 依赖。 | `NCSupport` 拦截：`MASQUE ip-stack gvisor 尚未接入（仅支持 lwip / system）` |
| `port-hopping` | Surge | 端口动态跳跃需要外部网络接口轮询探测，S1/S2 连接器暂不实现该扩展。 | `NCSupport` 拦截：`MASQUE port-hopping 尚未接入` |
| `cwnd` / `bbr-profile` | Clash.Meta YAML | iOS Network.framework 托管 QUIC 拥塞窗口，应用层无法直接修改底层内核拥塞窗口数值。 | 解析层保留，标记或文档提示受限于系统沙箱 |
| `name-cert-verify` | Clash.Meta YAML | Clash.Meta 内该字段仅为占位符（源码标注 does not verify certificate names），MASQUE 走公钥固定。 | 忽略占位，由公钥校验覆盖 |
| `network: grpc` / `ws` | 错误或非标配置 | MASQUE 协议标准仅定义于 HTTP/3 (QUIC) 与 HTTP/2，不支持以 WebSocket 或 gRPC 作为底层载体。 | `NCSupport` 拦截：`MASQUE network ... 尚未接入` |
| Quantumult X 节点行 | Quantumult X | Quantumult X 官方未曾公布且不支持 MASQUE 协议（社群实测与官方文档均确认）。 | `NCQXImport` 显式记录警告并写入 `fields["unsupported"] = "Quantumult X 不支持 MASQUE 协议"`，诊断展示不可用 |

---

## 5. S2 连接器与回环测试实现

### 5.1 开源服务端选型与结论

为在 S2 接入 `tools/loopback/` 及 `UnitTests/NativeCoreLoopbackTests.swift` 自动化回归体系，对开源候选服务端评估如下：

| 服务端候选 | 语言 / 许可证 | 协议覆盖度 | 接入评估与结论 |
|---|---|---|---|
| **quic-go/masque-go** | Go / **MIT** | RFC 9298 (CONNECT-UDP over HTTP/3) | **选定落地 (RFC 9298)**：Marten Seemann / quic-go 官方参考实现。代码极度精炼（`cmd/proxy` 百余行），单一二进制原生支持 `-t <template> -b <addr> -k <key> -c <cert>`。在 CI macos-15 runner 上通过 Go 工具链秒级获取运行，零复杂 C/Rust 工具链依赖。 |
| **cloudflare/quiche** | Rust / **BSD-2-Clause** | RFC 9298 / RFC 9484 | **放弃理由**：quiche 虽覆盖全面，但依赖 Rust+Cargo 与 BoringSSL C 库，在 CI macos-15 runner 上的构建耗时达数分钟且跨架构编译风险较高。依派发方修正指示，切换为 `masque-go`。 |
| **metacubex/connect-ip-go** | Go / **MIT** | RFC 9484 (CONNECT-IP) | 备用（CONNECT-IP 参考服务端，本阶段应用层暂无需启动）。 |
| **vcarus/volto** | Rust / **MIT** | RFC 9298 (CONNECT-UDP) | 轻量，但活跃度与标准对齐度低于 `quic-go/masque-go`。 |

### 5.2 `tools/loopback` 接入实测与拓扑

1. **端口规划与冲突规避**:
   - 经与 `tools/loopback/start-servers.sh` 及 `sing-box-config.json` 现有分配（18001-18008 inbounds，18009 WG peer，18011 OpenConnect 保留）全面核验，统一将 MASQUE CONNECT-UDP 服务端监听端口定为 **18012**。
   - 文档、脚本、测试常量统一镜像为 **18012**。
2. **凭据与启动管理**:
   - 复用 loopback 自签名证书 `$RUN/cert.pem` 与 `$RUN/key.pem`（CN=localhost）。
   - `start-servers.sh` 启动命令：
     `masque-proxy -t "https://127.0.0.1:18012/.well-known/masque/udp/{target_host}/{target_port}/" -b "127.0.0.1:18012" -c "$RUN/cert.pem" -k "$RUN/key.pem"`
   - 进程存活性与启停纳入 `start`、`stop`、`status` 统一管理。
3. **回环测试用例 (`UnitTests/NativeCoreLoopbackTests.swift`)**:
   - `testMASQUEUDPEcho`: 建立 `loop-masque` 出站连接（端口 18012），目标为 UDP echo 后端 `127.0.0.1:18081`；
   - 经过真实 QUIC 握手、HTTP/3 控制流 SETTINGS 交换、双向流 Extended CONNECT (`:protocol = connect-udp`) 协商，建立代理隧道；
   - 发送 8KB 测试 DNS 查询数据报，校验原样 echo 返回，逐字节比对完全一致。
4. **测试结果**:
   - 本地沙箱无 Xcode 编译与模拟器运行环境，标注为：**待 CI**（由 `.github/workflows/proto-loopback.yml` 在 macos-15 runner 上验证）。
