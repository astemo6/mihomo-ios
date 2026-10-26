# TrustTunnel（AdGuard）S1 交付报告

- **分支**: `feat/nc-trusttunnel`
- **基线**: `6fd4bab` (`xcstrings: ja/ko self-check titles use canonical terms`)
- **工作区**: `/home/hatch/mihomo-ios-test/repo-tt`
- **阶段**: S1（调研 + 设计 + 解析层 + 单测 + 文档初版）

---

## 1. 交付文件清单

| 文件路径 | 状态 | 职责说明 |
|---|---|---|
| `docs/nc-proto-trusttunnel.md` | **新增** | TrustTunnel 协议设计文档：H2/H3 双线设计、复用与缺口、认证、内存控制、字段表、S2 回环计划 |
| `Shared/NativeCore/NCTrustTunnel.swift` | **新增** | TrustTunnel 核心解析与模型：RFC 9000 VarInt、Base64URL、TLV 解码/编码、`tt://?` 深度链接解析、标准 URI 解析、Wire 数据面帧封装 |
| `Shared/NativeCore/NCSubscription.swift` | **修改** | 订阅解析器扩展：注册 `tt`、`trusttunnel`、`trust-tunnel` URI 方案，JSON 节点类型适配 |
| `Shared/NativeCore/NCConfImport.swift` | **修改** | Surge / Loon `.conf` 导入器扩展：解析 `trust-tunnel` / `trusttunnel` 节点，提取 `username`、`password`、`quic`/`h3`、`sni`、`alpn`、`max-streams` |
| `Shared/NativeCore/NCQXImport.swift` | **修改** | Quantumult X 导入器扩展：显式拦截 `trusttunnel` / `trust-tunnel` 并记录警告，返回 `nil`，绝不静默丢弃 |
| `Shared/NativeCore/NCSupport.swift` | **修改** | 内核支持集扩展：添加 `trusttunnel`、`trust-tunnel` 到协议集合与 `h3` 传输集合；增加 `trusttunnelUnsupported` 校验 |
| `Shared/NativeCore/NCConnector.swift` | **修改** | 拨号器调度扩展：注册 `trusttunnel` 分支并给出明确的 S2 阶段占位提示 |
| `UnitTests/NativeCoreTrustTunnelTests.swift` | **新增** | 单元测试套件：覆盖最小/完整深度链接正例、订阅 URL 正例、URI 方案正例、Clash YAML、Surge .conf、负例校验、QX 拦截、unsupported 标记、数据面帧编解码 |
| `report-trusttunnel-s1.md` | **新增** | 本报告 |

---

## 2. 字段表摘要

### 2.1 支持字段表

| 规范化字段 | Clash YAML | Surge / Loon `.conf` | Deep Link `tt://?` (Tag) | 类型 | 默认值 | 语义与处理 |
|---|---|---|---|---|---|---|
| `server` | `server` | Positional 1 | `0x02` `addresses` | String | 必填 | 远端服务器主机名或 IP 地址 |
| `port` | `port` | Positional 2 | `0x02` `addresses` | Int | 443 | 远端服务器端口 |
| `username` | `username` | `username` | `0x05` `username` | String | 必填* | HTTP Basic Auth 用户名（*存在 subscription_url 时可省） |
| `password` | `password` | `password` | `0x06` `password` | String | 必填* | HTTP Basic Auth 密码（*存在 subscription_url 时可省） |
| `quic` | `quic` | `h3` / `quic` | `0x09` `upstream_protocol` | Bool | `false` | 传输开关：`false` = HTTP/2 over TLS，`true` = HTTP/3 over QUIC |
| `network` | `network` | - | `0x09` (导出) | String | `"h2"`/`"h3"` | 规范化底层传输标识 |
| `sni` / `servername` | `sni` | `sni` | `0x03` `custom_sni` / `0x01` | String | `server` | TLS SNI 覆盖 |
| `skip-cert-verify` | `skip-cert-verify` | `skip-cert-verify` | `0x07` `skip_verification` | Bool | `false` | 跳过服务端证书链校验 |
| `alpn` | `alpn` | `alpn` | - | [String] | `["h2"]`/`["h3"]` | 自定义 TLS ALPN 协商列表 |
| `udp` | `udp` | - | - | Bool | `true` | 是否启用 UDP 转发（经 `_udp2` 伪主机流） |
| `name` | `name` | 节点名 | `0x0c` `name` | String | `server` | 节点展示名称 |
| `max-streams` | `max-streams` | `max-streams` | - | Int | 12 | 单连接最大多路复用子流数 |
| `headers` | - | `headers` | - | String | nil | 握手自定义 HTTP 头部（Surge 格式） |
| `dns-upstreams` | - | - | `0x0d` `dns_upstreams` | [String] | `[]` | 节点附带的自定义 DNS 上游列表 |
| `subscription-url` | - | - | `0x0e` `subscription_url` | String | nil | 节点对应的 HTTPS 订阅获取/刷新地址 |
| `has-ipv6` | - | - | `0x04` `has_ipv6` | Bool | `true` | 是否包含 IPv6 支持 |

### 2.2 不支持字段及显式标记原因

| 字段 | 来源格式 | 诊断日志中文提示 | 技术原因与断言依据 |
|---|---|---|---|
| `anti-dpi` | Deep Link (Tag `0x0a`) | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | Anti-DPI 模式涉及修改 TLS ClientHello 字节流；iOS Network.framework 在内核层封装 TLS，不暴露 raw ClientHello 帧修改能力 |
| `client-random-prefix` | Deep Link (Tag `0x0b`) | `TrustTunnel anti-dpi / client-random-prefix 尚未接入` | 向 TLS ClientHello 注入指定前缀/掩码的随机数；Network.framework 无自定义 ClientHello random 注入 API |
| `client-random-auth-key` | Deep Link (Tag `0x0f`) | `TrustTunnel client-random-auth-key 尚未接入` | 基于 SNI 与 auth key 派生 ClientHello 随机数，同样受限于 Network.framework TLS 黑盒机制 |
| `icmp` | 官方规范 (§7) | `TrustTunnel icmp 尚未接入` | iOS NetworkExtension 不支持在代理流上暴露原生 ICMP echo 链路；仅代理 TCP 与 UDP 流量 |
| `congestion-controller` / `bbr-profile` | Mihomo YAML | 核心底层由系统管理，忽略不报错 | iOS `NWProtocolQUIC` 由 XNU 内核管理拥塞控制（Cubic/BBR），不支持用户态插入第三方拥塞算法 |
| **Quantumult X 节点** | `[server_local]` | `quantumultx [server_local]: trusttunnel has no Quantumult X format specification; explicitly unavailable` | Quantumult X 官方从未发布 TrustTunnel 规范及支持；导入时显式打回并记录 warning，绝不静默吞掉 |

---

## 3. 技术断言出处与查证证据

所有协议字段与设计结论均通过公开代码库与技术文档查证，绝无凭空臆造：

1. **官方规范与服务端开源状态**:
   - 官方代码库：`https://github.com/TrustTunnel/TrustTunnel`（原 `AdguardTeam/TrustTunnel`，已归档重定向至 TrustTunnel 官方组织）。
   - 许可证：Apache License 2.0（见代码库根目录 `LICENSE`）。
   - 核心规范：代码库 `PROTOCOL.md` (Version 1.0, Dec 24, 2025)。
     - §3.1 HTTP/2：ALPN 协商 `h2`，初始窗口 `131072`（Chrome 默认值）。
     - §3.2 HTTP/3：ALPN 协商 `h3`，RFC 9000 QUIC v1 (`0x00000001`)，超时设为 `2 * (connection_timeout + health_check_timeout)`。
     - §5.1 / §9.1 认证：每一条 CONNECT 请求必须携带 `proxy-authorization: Basic <base64(username:password)>`。
     - §5.2 状态码：`200 OK` 隧道建立；`407` 认证失败（自定义错误码 `0x1F`），客户端必须中断会话并重新认证。
     - §6.2 UDP 伪主机：保留标识 `:authority: _udp2`，单条流复用所有 UDP 包。
     - §6.3 / §6.4 UDP 帧结构：
       - 发送帧：`[Len u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][AppNameLen u8][AppName][Payload]`
       - 接收帧：`[Len u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][Payload]`
     - §11.2 IP 填充规则：IPv4 必须前置 12 字节全 0 补齐为 16 字节。
     - §8 保留探活主机：`_check`（默认超时 7000 ms）。
2. **深度链接（Deep Link）规范**:
   - 官方规范：代码库 `DEEP_LINK.md` (Version 2)。
   - URI 格式：`tt://?<base64url-payload>`（URL-safe Base64，无 padding）。
   - 字段编码：基于 RFC 9000 §16 VarInt 的 TLV 二进制格式。Tag 0x00（version 2）、Tag 0x01（hostname）、Tag 0x02（addresses，可多次出现）、Tag 0x03（custom_sni）、Tag 0x04（has_ipv6）、Tag 0x05（username）、Tag 0x06（password）、Tag 0x07（skip_verification）、Tag 0x08（certificate DER）、Tag 0x09（upstream_protocol: 1=h2, 2=h3）、Tag 0x0a（anti_dpi）、Tag 0x0b（client_random_prefix）、Tag 0x0c（name）、Tag 0x0d（dns_upstreams String[]）、Tag 0x0e（subscription_url）、Tag 0x0f（client_random_auth_key）。
3. **Surge 字段对标**:
   - 官方文档：`https://manual.nssurge.com/policies/trust-tunnel.html` (Mac 6.4.4+, iOS 5.22.0+)。
   - 语法：`Proxy = trust-tunnel, server, port, username=..., password=..., [h3=true], [max-streams=...]`。Surge 仅支持 TCP，不支持 UDP 转发。
4. **Mihomo / Clash 字段对标**:
   - 官方文档：`https://wiki.metacubex.one/en/config/proxies/trusttunnel/`。
   - 语法：`type: trusttunnel`，支持 `server`、`port`、`username`、`password`、`quic`（默认 false）、`udp`、`sni`、`skip-cert-verify`、`max-streams`、`health-check` 等。
5. **Quantumult X 状态**:
   - 经全面查证 Quantumult X 官方规范，其 `[server_local]` 仅支持 shadowsocks、vmess、vless、trojan、http、socks5、anytls 以及部分私有格式，不存在任何公开的 TrustTunnel 语法。

---

## 4. 单元测试覆盖情况

测试文件 `UnitTests/NativeCoreTrustTunnelTests.swift` 包含以下测试用例：
1. `testDeepLinkMinimal`：正例，解析官方 Python 工具链生成的最小 `tt://?` 链接（hostname, addresses, user, pass）。
2. `testDeepLinkMaximal`：正例，解析包含多地址、自定义 SNI、HTTP/3、跳过证书验证、DNS 上游列表的完整深度链接。
3. `testDeepLinkSubscriptionOnly`：正例，解析仅包含 `subscription_url` 的极简深度链接。
4. `testDeepLinkRoundtrip`：正例，深度链接序列化与反序列化全量字段往返一致性测试。
5. `testStandardURIScheme`：正例，解析 `trusttunnel://user:pass@host:port?quic=true&sni=...#name` 链接及 `trust-tunnel://` 连字符别名。
6. `testClashYAMLImport`：正例，解析包含 `type: trusttunnel` 的 Clash/Mihomo YAML 配置片段。
7. `testSurgeConfImport`：正例，解析 Surge `Proxy-TrustTunnel = trust-tunnel, ...` 配置行。
8. `testDeepLinkMissingRequiredFields`：负例，缺少 password、缺少 username、缺少 addresses 且无 subscription_url 均正确返回 `nil`。
9. `testDeepLinkUnsupportedVersion`：负例，Tag 0x00 版本号为 3（超过当前最大版本 2）时正确拒绝返回 `nil`。
10. `testDeepLinkInvalidSubscriptionUrl`：负例，非 `https://` 的订阅 URL 正确拒绝返回 `nil`。
11. `testDeepLinkCorruptedPayload`：负例，非法 base64 及截断数据安全处理返回 `nil`，不崩溃。
12. `testQuantumultXRejection`：负例，Quantumult X 配置中出现 `trusttunnel=` 时返回 `nil` 并在 `report.warnings` 中生成明确诊断警告。
13. `testUnsupportedFieldMarkers`：不支持字段标记测试：验证 `anti-dpi`、`client-random-prefix`、`client-random-auth-key`、`icmp`、缺少必填字段时 `NCSupport.unsupportedReason` 返回的中文原因；合法节点返回 `nil`。
14. `testWireFraming`：数据面帧测试：验证 CONNECT 请求头格式（Basic Auth 与 `:authority`）、IPv4 补 12 字节全 0 补齐为 16 字节逻辑、UDP 发送包与接收包的双向编解码往返。

---

## 5. S2 实施计划与待核实点

### 5.1 S2 工作划分
1. **连接器与会话管理 (`NCTrustTunnelSession`)**:
   - **H2 传输线**: 基于 `NCH2ClientCore` 扩展多流 ID 分发（流 ID 1, 3, 5...）；维护活动流哈希表与回包路由。
   - **H3 传输线**: 基于 `NWProtocolQUIC` 打开双向流，引入约 25 行紧凑 Swift QPACK Literal 编码器发送 HEADERS 帧；复用 `NCHy2.qpackDecodeFieldSection` 解析应答。
   - **连接池**: 支持 `max-streams` 多路复用上限；复用既有连接，超限开新连接。
2. **UDP 多路复用数据面**:
   - 建立至保留伪主机 `_udp2` 的独立流。
   - 实现 UDP 数据报收发封装/解封装，维护 120 秒超时映射表。
3. **回环测试集成**:
   - 在 `tools/loopback/start-servers.sh` 中下载官方编译好的 `trusttunnel_endpoint` 二进制。
   - 监听 `127.0.0.1:18009`，转发至 `18080` (TCP echo) 和 `18081` (UDP echo)。
   - 在 `UnitTests/NativeCoreLoopbackTests.swift` 中编写端到端真实套接字回环单测。

### 5.2 待核实点（S2 重点跟进）
1. **官方服务端 QUIC ALPN 兼容性**: 官方服务端在 HTTP/3 模式下对 ALPN 是否仅严格匹配 `h3`，对自签名证书的 SNI 匹配要求。
2. **多流并发下的流重置响应**: 当其中一条 CONNECT 流收到远端 RST 时，官方服务端是否会向客户端回送 `RST_STREAM` 还是直接终止整个 H2/H3 会话。
3. **UDP 帧 AppName 字段**: 规范中客户端发送帧带有 `App Name` 变长字段，官方服务端是否对 `App Name` 长度为 0 或空字符串无条件兼容接受。

---

## 6. 红线核验

- [x] 仅在 `~/mihomo-ios-test/repo-tt` 的 `feat/nc-trusttunnel` 分支工作；
- [x] 绝未触动 `main` 和 `feat/nc-kernel` 分支；
- [x] 未开 PR、未触发 CI；
- [x] 纯 Swift 代码，零 Go 代码，零新增第三方依赖；
- [x] 静态自洽，括号配平，符号引用真实存在；
- [x] 技术断言逐条具有出处支撑，字段完整对齐。
