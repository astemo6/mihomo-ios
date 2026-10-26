# NativeCore: OpenConnect (AnyConnect 兼容) — design note (feat/nc-openconnect, based on astemo6/mihomo-ios NativeCore 6fd4bab)

Status 2026-10-26 (S1): 协议调研、双通道设计、解析层（URI/Shadowrocket conf/Clash YAML/QuanX 不可用标记）、不支持字段显式拦截、解析单测完成。S2 将实现纯 Swift connector 数据面与 ocserv 回环测试。

---

## 1. 协议概述与架构设计 (Architecture & Overview)

OpenConnect 协议是与 Cisco AnyConnect 完全兼容的开源 SSL VPN 协议（由 Nikos Mavrogiannopoulos 和 David Woodhouse 等人制定并维护于 IETF 草案及开源实现中）。

协议采用**控制面与数据面分离的双通道架构 (Dual-Channel Architecture)**：
1. **主通道 (Primary Channel - CSTP over TLS/TCP)**：建立在标准 TLS（443 端口）之上的 HTTPS 连接。负责初始身份认证（XML 表单交互）、会话令牌分配、网络参数协商（IP、掩码、DNS、路由 Split-Include/Exclude、MTU），并在数据面上作为承载 IP 数据报文的保底可靠通道。
2. **辅通道 (Secondary Channel - DTLS over UDP)**：可选的基于 UDP 的数据通道。通过主 TLS 会话利用 RFC 5705 密钥导出器 (Keying Material Exporter) 衍生预共享密钥 (PSK)，在指定 UDP 端口建立 DTLS 会话，用于避免 TCP-over-TCP 引起的窗口重传和队头阻塞问题。

```
+-------------------------------------------------------------------------+
|                              Client (NativeCore)                        |
+-------------------------------------------------------------------------+
       |                                                 |
       | 1. TLS 1.2+ Handshake                          |
       | 2. HTTPS POST XML /auth                         |
       | 3. HTTP CONNECT /CSCOSSLC/tunnel               |
       |                                                 |
       v (TCP:443)                                       v (UDP:443 / X-DTLS-Port)
+----------------------------------+          +---------------------------+
| CSTP Control & Fallback Channel  |          |   DTLS Fast Data Channel  |
| 8-Byte Framing: STF\x01 + Header |          |   1-Byte Framing: Type    |
+----------------------------------+          +---------------------------+
       |                                                 |
       +-----------------------+-------------------------+
                               |
                               v
+-------------------------------------------------------------------------+
|                  Server (Cisco ASA / ocserv daemon)                     |
+-------------------------------------------------------------------------+
```

---

## 2. 认证状态机 (Authentication State Machine)

OpenConnect 的身份验证完全运行在 HTTPS/TLS 会话上，采用 XML 报文交互，遵循 `config-auth.dtd` 规范（出处：`draft-mavrogiannopoulos-openconnect-04` §2.2.1 - §2.2.4）。

### 2.1 状态转换流程

```
[Disconnected]
      |
      | 1. TLS 1.2/1.3 Handshake (SNI, SecTrust / Fingerprint Pinning)
      v
[TLS Established]
      |
      | 2. HTTP POST "/" (Content-Type: text/xml, config-auth type="init")
      v
[Auth Request Received] <-- HTTP 200 (config-auth type="auth-request", forms)
      |
      | 3. Fill Username, Password, Auth-Group
      | 4. HTTP POST form.action (e.g. "/auth" or "/+webvpn+/index.html")
      v
[Auth Reply Sent] (config-auth type="auth-reply")
      |
      +---> HTTP 401 Unauthorized --------> [Auth Failed / Prompt Retry]
      |
      +---> HTTP 200 (config-auth type="auth-request") -> [Multi-Factor Prompt]
      |
      +---> HTTP 200 (config-auth type="complete") ----> [Authenticated]
                                                              |
                                                              | Extract Cookie:
                                                              | Set-Cookie: webvpn=<token>
                                                              v
                                                    [Ready for Tunnel]
```

### 2.2 详细交互报文

1. **客户端发起 Init POST**：
   ```http
   POST / HTTP/1.1
   Host: vpn.example.com
   User-Agent: Open AnyConnect VPN Agent v5.01
   Content-Type: text/xml
   Content-Length: 148

   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE config-auth SYSTEM "config-auth.dtd">
   <config-auth client="vpn" type="init">
       <version who="vpn">v5.01</version>
   </config-auth>
   ```

2. **服务端返回 Auth-Request 表单**：
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <config-auth client="vpn" type="auth-request">
       <auth id="main">
           <title>Corporate VPN Login</title>
           <form action="/auth" method="post">
               <input label="Group:" name="group_list" type="select">
                   <choice name="Default" label="Default Realm"/>
                   <choice name="Engineering" label="Engineering"/>
               </input>
               <input label="Username:" name="username" type="text" />
               <input label="Password:" name="password" type="password" />
           </form>
       </auth>
   </config-auth>
   ```

3. **客户端提交凭据 (Auth-Reply)**：
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <config-auth client="vpn" type="auth-reply">
       <version who="vpn">v5.01</version>
       <auth>
           <group_list>Engineering</group_list>
           <username>alice</username>
           <password>Secret123!</password>
       </auth>
   </config-auth>
   ```

4. **服务端返回 Complete 与 Session Token**：
   ```http
   HTTP/1.1 200 OK
   Content-Type: text/xml
   Set-Cookie: webvpn=c304d2e...; path=/; secure; HttpOnly

   <?xml version="1.0" encoding="UTF-8"?>
   <config-auth client="vpn" type="complete">
       <version who="sg">0.1(1)</version>
       <auth id="success">
           <title>SSL VPN Service</title>
       </auth>
   </config-auth>
   ```
   客户端保存 `webvpn` cookie，后续 CONNECT 请求使用该 cookie 关联通道。若用户已配置 `cookie`，则可直接跳过 XML 认证流程，直入 CONNECT 请求。

---

## 3. CSTP 主数据通道协议 (CSTP over TLS/TCP)

认证成功后，客户端向相同 TLS 连接发起 HTTP `CONNECT` 升级为 CSTP 隧道（出处：`draft-mavrogiannopoulos-openconnect-04` §2.2.5 - §2.3；`openconnect/cstp.c`）。

### 3.1 隧道升级请求与响应

**客户端请求**：
```http
CONNECT /CSCOSSLC/tunnel HTTP/1.1
Host: vpn.example.com:443
User-Agent: Open AnyConnect VPN Agent v5.01
Cookie: webvpn=c304d2e...
X-CSTP-Version: 1
X-CSTP-Hostname: iPhone
X-CSTP-Address-Type: IPv4,IPv6
X-CSTP-Base-MTU: 1500
X-CSTP-MTU: 1406
X-DTLS-CipherSuite: PSK-NEGOTIATE
```

**服务端响应 (下发网络配置)**：
```http
HTTP/1.1 200 OK
X-CSTP-Version: 1
X-CSTP-Address: 192.168.100.25
X-CSTP-Netmask: 255.255.255.0
X-CSTP-Address-IP6: 2001:db8::1025/127
X-CSTP-DNS: 192.168.100.1
X-CSTP-Split-Include: 10.0.0.0/8
X-CSTP-Split-Include: 172.16.0.0/12
X-CSTP-Base-MTU: 1500
X-CSTP-MTU: 1406
X-CSTP-Keepalive: 300
X-CSTP-DPD: 30
X-DTLS-Port: 443
X-DTLS-App-ID: 7a8b9c...
X-DTLS-CipherSuite: PSK-NEGOTIATE
X-DTLS-Keepalive: 300
X-DTLS-DPD: 30
```

响应头 `\r\n\r\n` 之后立即进入原始 CSTP 二进制报文流。

### 3.2 CSTP 报文封装格式 (8 字节头部)

| 字节偏移 | 字段名 | 说明 |
|:---:|:---:|---|
| `0..3` | Magic | 固定为 `0x53 0x54 0x46 0x01`（ASCII "STF\x01"） |
| `4..5` | Length | 大端序 UInt16，表示后续负载字节数（不含 8 字节头部） |
| `6` | Type | 负载类型（见下表） |
| `7` | Reserved | 固定填 `0x00` |
| `8..` | Payload | IP 数据包或控制载荷 |

**有效负载类型 (Payload Types)**：
- `0x00` (`DATA`)：IPv4 或 IPv6 数据报文。
- `0x03` (`DPD-REQ`)：Dead Peer Detection 请求包，用于链路活性检测与路径 MTU 探测。对端必须以相同内容回复 `0x04`。
- `0x04` (`DPD-RESP`)：针对 `DPD-REQ` 的应答。
- `0x05` (`DISCONNECT`)：断开连接，后附 1 字节断开原因代码（`0xb0` 表示会话注销）。
- `0x07` (`KEEPALIVE`)：链路保活心跳包，载荷长度为 0。接收方以 `KEEPALIVE` 回复。
- `0x08` (`COMPRESSED DATA`)：压缩 IP 报文（默认不启用）。
- `0x09` (`TERMINATE`)：服务端停机通知。

---

## 4. DTLS 辅数据通道与回落策略 (DTLS over UDP & Fallback Strategy)

出处：`draft-mavrogiannopoulos-openconnect-04` §2.2.7 - §2.4；RFC 5705。

### 4.1 DTLS 协商与密钥导出
1. **密钥导出 (RFC 5705)**：
   在 CSTP TLS 主会话上，客户端与服务端通过 RFC 5705 Keying Material Exporter 独立计算 256 位（32 字节）预共享密钥：
   - Exporter Label: `"EXPORTER-openconnect-psk"`
   - Context: 空 (none)
   - Key Length: 32 bytes
2. **会话关联 (X-DTLS-App-ID)**：
   服务端在 CONNECT 响应中返回 `X-DTLS-App-ID: <hex-string>`（16-32 字节）。
   客户端在向 UDP 端口发送 DTLS 1.2 `ClientHello` 时，将该 App-ID 十六进制解码后直接填入 `ClientHello.SessionID` 字段。服务端依此将 UDP 会话绑定到对应的 TLS 会话。

### 4.2 DTLS 报文封装格式 (1 字节头部)

| 字节偏移 | 字段名 | 说明 |
|:---:|:---:|---|
| `0` | Type | 负载类型 UInt8（与 CSTP 保持一致，`0x00` 为 DATA） |
| `1..` | Payload | 原始 IP 数据报文 |

### 4.3 DTLS 并行启动与无缝回落策略 (Parallel Start & Graceful Fallback)

CSTP (TCP) 与 DTLS (UDP) 的容灾协作策略：
1. **CSTP 先行与即时通信**：CSTP 控制通道在 HTTP CONNECT 200 完成瞬间即可直接转发 IP 数据报文。数据传输**不需要**等待 DTLS 握手完成，消除初始连接等待延迟。
2. **DTLS 后台尝试**：后台异步向服务端 UDP 端口发起 DTLS 握手与 DPD 探测。
3. **平滑切入**：当收到 DTLS 握手成功并且通过首个 DTLS DPD 校验后，出站 IP 报文平滑切换为 DTLS UDP 发送。
4. **自动回落判决**：在以下情况下，数据通道立即或继续回落为 CSTP (TCP)，**绝不断开网络会话、不重置 lwIP/TUN 堆栈**：
   - 服务端未返回 `X-DTLS-Port` 或 `X-DTLS-CipherSuite: PSK-NEGOTIATE`；
   - 节点配置中显式指定 `dtls: false`；
   - UDP 握手超时（默认 3 秒）；
   - DTLS 连续 2 次 DPD 未收到回复（检测到网络运营商拦截 UDP / NAT 映射中断）。
5. **双向解封装容忍**：在回落期间或状态转换窗口内，入站引擎同时接收并解封来自 CSTP 和 DTLS 的数据包，保证任何在途报文不被丢弃。

---

## 5. 内存与性能设计注意点 (Memory & Performance)

依据 iOS Network Extension（上限 50MB Jetsam）与本项目 NativeCore 纯 Swift 规范：

1. **严格边界缓冲 (Bounded Read Buffers)**：
   CSTP 解帧缓冲区上限限制为 `receive_mtu + 8`（最大 16384 + 8 字节）。防止异常超大报文导致内存激增。
2. **零拷贝 / 切片转发 (Zero-Copy Slicing)**：
   CSTP 头部解封与封装直接使用 `Data` 切片和 `subdata` 操作，避免不必要的堆缓冲复制。
3. **单 GCD 串行队列模型**：
   状态机、CSTP 解帧及 DPD / Keepalive 定时器完全挂载在 `NCLwIP.queue` 或专用串行队列上，严禁在后台派发无边界线程，确保锁无关与资源可控。
4. **禁用数据面压缩 (Security Hardening)**：
   严格遵从 RFC 草案 Appendix A 建议，不启用 `oc-lz4` / `lzs` 压缩，避免在加密流上引入 CRIME / BREACH 类型的侧信道攻击风险，同时节省压缩字典带来的内存开销。

---

## 6. 支持字段表 (Supported Fields)

字段与 Shadowrocket 支持集完全对齐，并提供规范化映射：

| 字段名称 | 类型 | 默认值 | 来源映射 (URI / Conf / YAML) | 说明 |
|---|:---:|:---:|---|---|
| `name` | String | - | URI 锚点 `#name` / Conf 行头 / YAML `name` | 节点显示名称 |
| `type` | String | `"openconnect"` | 协议名 / `anyconnect` 别名自动规范化 | 节点规范化类型 |
| `server` | String | 必填 | 授权主机名 / Conf 第二字段 / YAML `server` | VPN 服务端域名或 IP |
| `port` | Int | `443` | 端口 / Conf 第三字段 / YAML `port` | 服务端端口 (1..65535) |
| `username` | String | 可选* | URI `user` / Conf `username=` / YAML `username` | 用户名（与 password 配合） |
| `password` | String | 可选* | URI `pass` / Conf `password=` / YAML `password` | 密码（与 username 配合） |
| `cookie` | String | 可选* | URI `cookie=` / Conf `cookie=` / YAML `cookie` | 已有的 `webvpn` 会话令牌，支持免密直连 |
| `auth-group` | String | `nil` | URI `group=` / Conf `auth-group=` / YAML `auth-group` | 服务端认证用户组 (Realm / Profile) |
| `sni` | String | `server` | URI `sni=` / Conf `sni=` / YAML `sni` | TLS 握手 SNI 扩展 |
| `skip-cert-verify` | Bool | `false` | URI `insecure=` / Conf `skip-cert-verify=` / YAML `skip-cert-verify` | 是否跳过自签名或证书链校验 |
| `server-cert-pin` | String | `nil` | URI `fingerprint=` / Conf `server-cert-pin=` / YAML `fingerprint` | 服务端证书 SHA-256 指纹固定 |
| `dtls` | Bool | `true` | URI `dtls=` / Conf `dtls=` / YAML `dtls` | 是否启用 DTLS UDP 辅数据通道 |
| `mtu` | Int | `1406` | URI `mtu=` / Conf `mtu=` / YAML `mtu` | 隧道 MTU 设定值 |
| `user-agent` | String | `"Open AnyConnect VPN Agent v5.01"` | URI `user_agent=` / Conf `user-agent=` | 客户端声明的 User-Agent |
| `local-hostname` | String | `nil` | URI `local_hostname=` / Conf `local-hostname=` | 客户端机器名（上报服务端） |

\*注：凭据要求满足 `(username && password) || cookie` 之一。

---

## 7. 未支持字段表与技术原因 (Unsupported Fields & Rationale)

依据简报红线，不支持的字段在解析层显式捕获并在 `NCSupport.unsupportedReason` 中向用户反馈不可用原因，**严禁静默丢弃**：

| 字段名称 | 来源/对标 | 不支持原因与依据 |
|---|---|---|
| `csd-wrapper` / `csd` | Cisco CSD (Cisco Secure Desktop) | 安全限制：CSD 机制要求客户端下载服务端下发的木马/扫描脚本执行。iOS 沙箱严禁动态执行外部二进制程序与 Shell 脚本，存在严重安全风险。 |
| `hip` / `hip-report` | GlobalProtect HIP | 私有机制：主机信息合规上报涉及端点安全检测专有协议，标准 OpenConnect 无通用公开规范。 |
| `tncc` | Juniper / Pulse TNCC | 私有合规检查：Trusted Network Connect Client 涉及外部 Java/Native 审计探针，iOS 平台不具备运行环境。 |
| `token-secret` / `totp` | 软件动态令牌 | 架构分工：动态 TOTP/SecurID 令牌生成属于前端 UI 交互层或外部 Authenticator，不应固化在只读节点模型内。 |
| `compression` (`oc-lz4`/`lzs`) | 传输压缩 | 安全漏洞与规范建议：RFC 草案 Appendix A 明确指出加密流上进行无状态压缩可能遭致 CRIME/BREACH 侧信道密钥攻击，且会增加内存与 CPU 抖动。 |
| `rekey-method: new-tunnel` | 隧道重连 Rekey | 重构成本：断开重拨会导致 TCP 会话中断，NativeCore 优先保证单会话持续平滑运行。 |

---

## 8. 三格式解析对标结论 (Format Alignment)

1. **Shadowrocket (有公开格式，已实现)**：
   - 分享链接：`openconnect://[user[:pass]@]host[:port]?group=...&cookie=...#Name` 及 `anyconnect://` 均完整实现。
   - 配置文件：Surge/Shadowrocket `[Proxy]` 中形如 `Name = openconnect, host, port, username=..., password=...` 完整解析。
2. **Clash / mihomo YAML (无官方协议，实现通用社区方言)**：
   - 经对标 `MetaCubeX/mihomo` 源码 `constant/adapters.go`，官方 mihomo 并无 `openconnect` 或 `anyconnect` outbound 类型。
   - 解析层按照通用规范支持 `type: openconnect` 及 `type: anyconnect` 的 YAML 节点导入并转换为 canonical 节点，兼容 sing-box 风格导出。
3. **Quantumult X (无公开格式，显式拒绝并报警)**：
   - 经对标 `crossutility/Quantumult-X/sample.conf`，QuanX 官方从未支持 OpenConnect / AnyConnect。
   - 在 `NCQXImport.swift` 的解析入口中对 `openconnect`/`anyconnect` 节点显式打标 `fields["unsupported"] = "Quantumult X 无公开 OpenConnect 格式"`，并在 `report.warnings` 中记录，展示层可见不可用原因。

---

## 9. S2 回环测试计划 (S2 Loopback Plan: ocserv)

S2 阶段将接入真实服务端 `ocserv` 进行回环测试。

### 9.1 拓扑集成 (`tools/loopback/`)

| 端口 | 服务 | 协议 | 认证方式 | 作用 |
|:---:|:---:|:---:|:---:|:---:|
| `18009` | `ocserv` | TCP (CSTP) | 用户名/密码 (`nc-loop-oc-user` / `nc-loop-oc-pw`) | CSTP 控制面与数据通道 |
| `18009` | `ocserv` | UDP (DTLS) | PSK-NEGOTIATE (RFC 5705 导出) | DTLS 高速数据通道 |

### 9.2 服务端配置草案 (`tools/loopback/ocserv.conf`)
- 复用 `tools/loopback/` 现有的自签名根证书与 localhost 服务端证书 (`__LOOPBACK_DIR__/cert.pem`)。
- 认证后端：使用简易密码文件 (`ocpasswd`) 配置测试账号。
- 网络配置：
  - `ipv4-network = 192.168.109.0/24`
  - `cstp-port = 18009`, `dtls-port = 18009`
  - `keepalive = 10`, `dpd = 10`
  - `try-mtu-discovery = false`
- 接入脚本：在 `tools/loopback/start-servers.sh` 中增加 `ocserv` 启动与 PID 监控逻辑；在 `.github/workflows/proto-loopback.yml` 安装 `ocserv` 软件包。

### 9.3 单测验证点
在 `UnitTests/NativeCoreLoopbackTests.swift` 中增加：
- OpenConnect CSTP TCP 模式回环 Echo 测试（向 `18080` 发送并校验回显）。
- OpenConnect DTLS UDP 模式回环 Echo 测试。
- DTLS 主动阻塞/中断时无缝回落 CSTP 的连通性测试。
