# MASQUE S1 调研、设计、解析层与单测报告

- **协议**: MASQUE (RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP)
- **基线**: `astemo6/mihomo-ios` @ `6fd4bab`
- **分支**: `feat/nc-masque`（克隆目录 `~/mihomo-ios-test/repo-masque`）
- **交付阶段**: S1（调研 + 设计 + 解析层 + 单元测试 + 文档初版）

---

## 1. 交付文件清单

| 文件路径 | 变动类型 | 说明 |
|---|---|---|
| `docs/nc-proto-masque.md` | 新增 | MASQUE 设计文档：RFC 依据、双轨架构设计、QUIC/H3 复用与缺口、字段表、S2 回环计划 |
| `Shared/NativeCore/NCMASQUE.swift` | 新增 | MASQUE 配置模型 `NCMASQUE.Config`、Shadowrocket `masque://` 解析与生成、Varint 编解码、HTTP/3 Datagram 报文头编解码、Capsule Protocol（RFC 9297 / 9484）TLV 解析器与胶囊模型、H3 Extended CONNECT 协商与 QPACK 头部生成 |
| `Shared/NativeCore/NCSubscription.swift` | 修改 | 注册 `masque://` 模式解析入 `parseURI`；将 `masque` 加入 `selfSchemes` 与 `qxNodeTypes` |
| `Shared/NativeCore/NCConfImport.swift` | 修改 | Surge/Loon `[Proxy]` 配置行支持 `Name = masque, host, port, ...` 字段提取 |
| `Shared/NativeCore/NCQXImport.swift` | 修改 | Quantumult X 遇到 `masque` 节点行显式记录 warning 并注入 `unsupported` 字段（QX 无公开规范） |
| `Shared/NativeCore/NCSupport.swift` | 修改 | 将 `masque` 加入 `types`；新增 `masqueUnsupported(_ p: NCProxy) -> String?`，支持字段缺失拦截与不支持参数拦截 |
| `Shared/NativeCore/NCShareLink.swift` | 修改 | 扩展 `NCShareLink.encode`，支持 `type: masque` 导出为标准 `masque://` 格式 |
| `Shared/NativeCore/NCConnector.swift` | 修改 | 新增 `case "masque":` 显式占位提示 `masque: 数据面将在 S2 接入`，避免未命中默认分支 |
| `UnitTests/NativeCoreMASQUETests.swift` | 新增 | 包含正例（Clash YAML / Shadowrocket URI / Surge 行）、负例（格式错误 / 字段缺失）、不支持字段标记（gvisor / port-hopping / QX 不支持）、Wire 协议（Datagram / Capsule / Settings / QPACK）等 10 个测试用例 |
| `report-masque-s1.md` | 新增 | S1 执行总结与技术断言报告（本文） |

---

## 2. 字段支持与对标表摘要

对齐 Clash/mihomo Alpha YAML、Shadowrocket 2.2.90+ 分享链接与 Surge 5.22.0+ 配置语法：

### 2.1 支持字段

| 字段 | Clash YAML | Shadowrocket | Surge | 含义与解析行为 |
|---|---|---|---|---|
| 节点名称 | `name` | `#<name>` | `Name =` | 节点显示名称 |
| 协议类型 | `type: masque` | `masque://` | `masque` | 统一规范化为 `masque` |
| 服务器地址 | `server` | `<host>` | `<host>` | 域名、IPv4 或 IPv6（支持中括号） |
| 服务器端口 | `port` | `<port>` | `<port>` | 整数 1-65535 |
| 私钥 | `private-key` | `privateKey` | `private-key` | P-256 私钥，支持 base64 与 PEM（自动清洗头尾换行） |
| 公钥 | `public-key` | `publicKey` | `public-key` | P-256 服务端公钥，用于客户端公钥固定比对 |
| 内部 IPv4 | `ip` | `ip` / `tunnelIp` | `ip` | 隧道客户端 IPv4 地址 / CIDR |
| 内部 IPv6 | `ipv6` | `ipv6` | `ipv6` | 隧道客户端 IPv6 地址 / CIDR |
| URI 模板 | `uri` | `template` / `uri` | `uri` | 默认 `https://cloudflareaccess.com` 或 RFC 9298 路径 |
| SNI | `sni` | `sni` | `sni` | TLS SNI（缺省为 `consumer-masque.cloudflareclient.com`） |
| ALPN | `alpn` | `alpn` | `alpn` | 默认 `["h3"]`（`network: h2` 时为 `["h2"]`） |
| MTU | `mtu` | `mtu` | - | 隧道 MTU，默认 1280 |
| UDP | `udp` | `udp` | `udp-relay` | 是否启用 UDP 转发，默认 true |
| 远端 DNS | `remote-dns-resolve` | - | - | 是否通过节点进行远端 DNS 查询 |
| DNS 列表 | `dns` | `dns` | - | 数组或逗号分隔列表（如 `1.1.1.1, 8.8.8.8`） |
| 拥塞控制 | `congestion-controller` | `cc` | - | 拥塞控制偏好，如 `bbr` / `cubic` |
| 标签 | `flag` | `flag` | - | 节点标签（如 `CDN`） |
| 认证用户名 | `username` | - | `username` | RFC 9298 HTTP Basic 用户名 |
| 认证密码 | `password` | - | `password` | RFC 9298 HTTP Basic 密码 |
| 传输模式 | `network` | `network` | - | 支持 `quic` / `h3` (默认), `h2`, `h3-l4proxy` |
| 跳过证书校验 | `skip-cert-verify` | - | `skip-cert-verify` | 跳过证书链信任（WARP 配合公钥固定使用） |

### 2.2 不支持字段及显式标记原因

任何配置若包含以下参数，`NCSupport.unsupportedReason` 均显式标记为不可用并在诊断日志中展示，**不静默丢弃**：

| 字段 / 格式 | 标记不可用原因 |
|---|---|
| `ip-stack: gvisor` | NativeCore 为纯 Swift + 内置轻量 lwIP C 栈，无 Go 运行时及 gVisor 依赖。标记：`MASQUE ip-stack gvisor 尚未接入（仅支持 lwip / system）` |
| `port-hopping` | 端口跳跃涉及网络端口轮换定时器，S1/S2 连接器不纳入第一阶段。标记：`MASQUE port-hopping 尚未接入` |
| `network: grpc` / `ws` | MASQUE 协议规范仅定义于 HTTP/3 (QUIC) 与 HTTP/2，不支持非标载体。标记：`MASQUE network ... 尚未接入` |
| Quantumult X 节点 | Quantumult X 官方未提供 MASQUE 协议支持。标记：`Quantumult X 不支持 MASQUE 协议` |
| 关键认证缺失 | 缺少 `server`/`port`，或同时缺少 `private-key`/`public-key` 与 `username`/`password`。标记：`MASQUE 缺少 private-key / public-key 或认证凭据` |
| CONNECT-IP 缺少 IP | 使用密钥对握手（CONNECT-IP 组网模式）但缺少 `ip`/`ipv6`。标记：`MASQUE CONNECT-IP 缺少 ip / ipv6` |

---

## 3. 技术断言出处与权威依据

本实现中的每条核心技术判断均有公开标准规范或成熟开源项目依据，严禁凭空构造：

1. **RFC 9298 (Proxying UDP in HTTP)**:
   - §3.4: Extended CONNECT 请求必须使用 `:method = CONNECT`, `:protocol = connect-udp`, `:scheme = https`, `:authority`, `:path`。
   - §3.5: 响应状态码为 2xx，头部携带 `Capsule-Protocol: ?1`。
   - §5: HTTP Datagram 载荷格式为 `Context ID (varint)` + `UDP Payload`，Context ID `0` 为原始 UDP 包，上限 65527 字节。
2. **RFC 9484 (Proxying IP in HTTP)**:
   - §4.4: Extended CONNECT 请求使用 `:protocol = connect-ip`，全流量默认模板为 `/.well-known/masque/ip/*/*/`。
   - §4.7: 定义 `ADDRESS_ASSIGN (0x01)`、`ADDRESS_REQUEST (0x02)`、`ROUTE_ADVERTISEMENT (0x03)` 胶囊格式。
   - §6: HTTP Datagram 载荷格式为 `Context ID (varint)` + `IP Packet Payload`，Context ID `0` 为完整 IP 报文。
3. **RFC 9297 (HTTP Datagrams and the Capsule Protocol)**:
   - §2.1: QUIC DATAGRAM 帧内承载 `Quarter Stream ID (varint = stream_id / 4)` + `HTTP Datagram Payload`。
   - §2.1.1: 控制流（Stream Type `0x00`）通过 SETTINGS 帧通告 `SETTINGS_H3_DATAGRAM = 0x33` (51) = 1。
   - §3.2 & §3.5: Capsule 协议格式 `Capsule Type (varint)` + `Capsule Length (varint)` + `Capsule Value`；DATAGRAM 胶囊类型为 `0x00`。
4. **RFC 8441 / RFC 9220 (Extended CONNECT)**:
   - RFC 9220 §3: HTTP/3 服务端必须在 SETTINGS 帧通告 `SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08` (8) = 1。
5. **mihomo Alpha 分支源码 (`adapter/outbound/masque.go`, `transport/masque/masque.go`)**:
   - YAML 字段定义：`server`, `port`, `private-key`, `public-key`, `ip`, `ipv6`, `uri`, `sni`, `mtu`, `udp`, `remote-dns-resolve`, `dns`, `network`, `congestion-controller`。
   - Cloudflare WARP 默认参数：SNI `consumer-masque.cloudflareclient.com`, URI `https://cloudflareaccess.com`。
   - 向后兼容草案设置：通告 `0x276: 1`（`SETTINGS_H3_DATAGRAM_00`）。
   - 客户端证书：由 P-256 私钥生成临时自签名证书，服务端证书校验通过固定比对 `public-key` 实现。
6. **Surge 官方手册 (`manual.nssurge.com/policies/masque.html`)**:
   - 语法：`Name = masque, <host>, <port>[, username=user, password=pass, port-hopping=...]`。
   - 机制：TCP 走 HTTP/3 CONNECT 隧道多路复用，UDP 走 CONNECT-UDP (RFC 9298) 与 HTTP Datagrams (RFC 9297)，认证走 HTTP Basic。
7. **Shadowrocket 社群生产生态 (`byJoey/warp-masque-actions`, `JamesYoonbot/WARP-MASQUE`, `KxK3lv1n/usque-shadowrocket-clashmi-converter`)**:
   - 链接格式：`masque://<host>:<port>?publicKey=<pub>&privateKey=<priv>&ip=<ip>&dns=<dns>&udp=<udp>&cc=<cc>&flag=<flag>#<name>`。

---

## 4. S2 执行计划与待核实点

### 4.1 S2 工作目标
1. **数据面连接器 (`NCConnector.swift` / `NCMASQUESession.swift`)**:
   - 实现 `NCMASQUEClient` / `NCMASQUESession`：基于 `NWConnectionGroup` 建立 QUIC 连接并启动。
   - 控制流（单向 Stream Type `0x00`）发送包含 `0x08`, `0x33`, `0x276` 的 SETTINGS 帧。
   - 提取请求流发送 Extended CONNECT HEADERS（通过 QPACK 编码 `:method CONNECT`, `:protocol connect-udp` / `connect-ip`）。
   - 提取 QUIC Datagram 通道（`NWProtocolQUIC.Options.isDatagram = true`），挂接 `NCMASQUEDatagramDemuxer`。
2. **CONNECT-UDP 数据面**:
   - 针对出站 UDP 数据包，按目标地址提取或复用 CONNECT-UDP 双向流，在 Datagram 头部添加 `Quarter Stream ID` + `Context ID 0` 后发出。
   - 接收 Datagram，按 `Quarter Stream ID` 路由回对应 UDP 会话。
3. **CONNECT-IP 数据面**:
   - 解析服务端下发的 `ADDRESS_ASSIGN` 胶囊，提取分配的客户端 IP。
   - 接入现有 `nc_wg` 双网卡架构的 lwIP 用户态协议栈：客户端 TCP/UDP 连接绑定该 netif，流出的 IP 数据包包装为 Datagram 发往 MASQUE 服务端，服务端回程的 IP 报文注入 `netif->input`。
4. **回环测试集成 (`tools/loopback/`)**:
   - 选用 `quic-go/masque-go` 作为 RFC 9298 CONNECT-UDP 回环参考服务端，监听 `127.0.0.1:18009`，转发至 `18081` UDP echo 服务端。
   - 在 `UnitTests/NativeCoreLoopbackTests.swift` 编写 `testMASQUEUDPEcho`，验证真实 QUIC/H3 握手、Extended CONNECT 协商及数据原样 Echo。

### 4.2 S2 待核实与重点攻关点
1. **Network.framework TLS 客户端证书传递**:
   - Network.framework 的 `sec_protocol_options_t` 在 iOS 扩展中通过 `sec_protocol_options_set_challenge_block` 提供客户端证书。需在真机/模拟器核实自签名 P-256 证书与私钥组装为 `SecIdentity` 的系统兼容器行为。
2. **DATAGRAM 丢包与 PMTU 探测**:
   - 确认单包大小达到 1400 时的分片表现，确保设置 `maxDatagramFrameSize = 1400` 并与 PMTU 对齐。
3. **回环服务端二进制获取**:
   - 在 `tools/loopback/start-servers.sh` 中添加下载或编译 `masque-go` 代理二进制（`cmd/proxy`）的脚本逻辑，保持与 sing-box 同样的生命周期管理模式。

---

## 5. 红线与验收核对

- [x] 纯 Swift 实现，未引入任何 Go，未新增任何第三方库依赖。
- [x] 未触碰 `main` 与 `feat/nc-kernel` 分支。
- [x] 严格遵循只读点名文件原则，未进行全仓探索。
- [x] 遵守 S1 边界：未开 PR、未触发 CI。
- [x] 分支提交并推送至 `origin/feat/nc-masque`。
