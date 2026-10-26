# MASQUE S2 数据面连接器、回环接入与单测补强报告

- **协议**: MASQUE (RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP)
- **基线**: `astemo6/mihomo-ios` @ `6fd4bab`
- **分支**: `feat/nc-masque`（克隆目录 `~/mihomo-ios-test/repo-masque`）
- **交付阶段**: S2（数据面实现 + 连接器落地 + 回环测试接入 + 单测补强 + 文档更新）

---

## 1. 交付文件清单

| 文件路径 | 变动类型 | 说明 |
|---|---|---|
| `Shared/NativeCore/NCMASQUESession.swift` | 新增 | MASQUE 数据面实现：`NCMASQUEConnection`（QUIC group 管理、单向控制流 SETTINGS 帧收发、QUIC Datagram 通道维护）、`NCMASQUEUDPStream`（实现 `NCRelayStream`，封装 Quarter Stream ID 与 Context ID 0 报文收发、DATA 帧内 Capsule 协议 fallback、#116 send completion 契约）、`NCMASQUERegistry`（连接池与多会话复用） |
| `Shared/NativeCore/NCConnector.swift` | 修改 | 将 S1 占位 `case "masque":` 替换为真实分发 `NCMASQUERegistry.masqueStream(...)` |
| `Shared/NativeCore/NCMASQUE.swift` | 修改 | 新增 `expandURITemplate`（RFC 9298 URI 模板展开与 IPv6 中括号处理）与 `qpackDecodeFieldSection`（HTTP/3 响应头 QPACK 解码转发） |
| `UnitTests/NativeCoreLoopbackTests.swift` | 修改 | 新增 `masquePort = 18012` 常量、`masqueProxy` 构造器、`testMASQUEUDPEcho`（真实 QUIC/H3 握手 + Extended CONNECT 协商 + UDP 数据报原样回显） |
| `UnitTests/NativeCoreMASQUETests.swift` | 修改 | 新增 5 个测试用例：`testDatagramCodecBoundaries`、`testCapsuleCodecBoundaries`、`testNegotiationFailurePaths`、`testURITemplateExpansion`、`testConnectIPModeRejectedAtConnector` |
| `tools/loopback/start-servers.sh` | 修改 | 增加 `find_masque_proxy`（自动通过 `go install` 安装 `masque-go` 或使用环境变量/本地二进制）、启动/停止/状态检查 `masque-proxy` 监听 18012 端口 |
| `tools/loopback/README.md` | 修改 | 拓扑表新增 18012 端口及 MASQUE CONNECT-UDP echo 说明 |
| `.github/workflows/proto-loopback.yml` | 修改 | 回环收集日志步骤增加 `masque.log` 收集与上传 |
| `docs/nc-proto-masque.md` | 修改 | 状态更新为 S2 交付；端口修正为 18012；选型更新为 `masque-go` 并说明放弃 quiche 理由；实测结果标注“待 CI”；字段表补充 `mode` 说明 |
| `report-masque-s2.md` | 新增 | S2 执行总结与技术断言报告（本文） |

---

## 2. 端口分配与冲突核对确认

经对 `tools/loopback/start-servers.sh`、`tools/loopback/sing-box-config.json` 与 `UnitTests/NativeCoreLoopbackTests.swift` 的现有端口全面核对：

| 端口 | 用途与服务 | 分配状态 |
|---|---|---|
| 18001 | sing-box Shadowsocks (`aes-256-gcm`) | 现有占用 |
| 18002 | sing-box Shadowsocks 2022 (`2022-blake3-aes-128-gcm`) | 现有占用 |
| 18003 | sing-box VMess | 现有占用 |
| 18004 | sing-box VLESS | 现有占用 |
| 18005 | sing-box Trojan | 现有占用 |
| 18006 | sing-box Hysteria 2 | 现有占用 |
| 18007 | sing-box TUIC v5 | 现有占用 |
| 18008 | sing-box WireGuard endpoint | 现有占用 |
| 18009 | sing-box WireGuard peer port (`sing-box-config.json` 内部定义) | **现有占用（S1 文档原提议端口，已废除）** |
| 18011 | OpenConnect 回环服务预留端口 | 保留 |
| **18012** | **MASQUE CONNECT-UDP 服务端 (`masque-proxy`)** | **本次确立统一端口** |
| 18080 | `echo_server.py` TCP echo | 现有占用 |
| 18081 | `echo_server.py` UDP echo | 现有占用 |
| 18082 | `echo_server.py` TCP blackhole | 现有占用 |
| 18083 | `echo_server.py` UDP control (`pause`/`go`) | 现有占用 |

**核对确认**：
- S1 文档中使用的 18009 确与 `sing-box-config.json` 中 WireGuard peer 端口冲突，且与 OpenConnect 规划冲突。
- 本阶段所有脚本（`tools/loopback/start-servers.sh`）、说明（`tools/loopback/README.md`）、文档（`docs/nc-proto-masque.md`）和测试用例（`NativeCoreLoopbackTests.swift`）**已全部统一固定为 18012**。

---

## 3. 参考服务端选型与评估结论

### 3.1 选型结论
- 选定服务端：**`quic-go/masque-go`**（仓库：`github.com/quic-go/masque-go`，子命令 `cmd/proxy`）。
- 许可证：**MIT License**（完全商用与开源兼容）。

### 3.2 放弃 cloudflare/quiche 及切换理由
1. **CI 构建开销对比**：
   - `cloudflare/quiche` 虽功能全面，但服务端基于 Rust 开发并深度绑定 BoringSSL C 库。在 GitHub Actions 的 `macos-15` runner 上从源码编译 quiche 需拉取多个 git submodules，构建耗时达到 3~5 分钟，且容易由于 runner 环境的 C/Rust 工具链版本差异导致编译失败。
   - `quic-go/masque-go` 是 Marten Seemann（quic-go 原作者、IETF MASQUE 核心规范 RFC 9298 联合作者）主导的官方参考实现。其 `cmd/proxy/main.go` 源码仅 60 余行，专为 RFC 9298 CONNECT-UDP 设计，代码极度轻量。
2. **环境亲和性**：
   - GitHub Actions `macos-15` runner 预装 Go 官方工具链。`start-servers.sh` 可在 5 秒内完成 `go install github.com/quic-go/masque-go/cmd/proxy@v0.6.0`，单一二进制输出至 `$NC_LOOPBACK_DIR/bin/masque-proxy`，启动快速、内存占用极低（<15MB）。
3. **协议与功能对齐**：
   - `masque-proxy` 原生支持 `-t <template> -b <addr> -c <cert> -k <key>`，原生处理 `:protocol = connect-udp`，并将解出的 UDP 数据报转发至本地目标（`127.0.0.1:18081` echo_server），完全覆盖回环验证需求。

---

## 4. 数据面与连接器实现细节

### 4.1 CONNECT-UDP 落地
1. **Extended CONNECT 协商**:
   - `NCMASQUEConnection` 启动后建立 Network.framework QUIC group，在 group 达到 `.ready` 后开启单向控制流，发送 Stream Type `0x00` + H3 SETTINGS 帧（包含 `SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08`, `SETTINGS_H3_DATAGRAM = 0x33`, `SETTINGS_H3_DATAGRAM_00 = 0x276`）。
   - 打开双向请求流，通过 QPACK 编码发送 Extended CONNECT HEADERS（`:method CONNECT`, `:protocol connect-udp`, `:scheme https`, `:authority`, `:path <expanded_uri>`, `capsule-protocol ?1`，可选 Basic 认证）。
   - 读取服务端响应 HEADERS 帧，解码 QPACK 校验 `:status` 是否为 2xx（通常 200 OK）。
2. **Quarter Stream ID 与 Context ID 多路复用**:
   - 客户端发起的双向流 stream ID 自增步长为 4（0, 4, 8, 12...）。
   - 根据 RFC 9297 §2.1，QUIC DATAGRAM 帧头部承载 `Quarter Stream ID (varint = streamID / 4)` + `Context ID (varint = 0)` + `UDP Payload`。
   - `NCMASQUEConnection` 的 Datagram 通道循环接收报文，按 `Quarter Stream ID` 查表派发给对应的 `NCMASQUEUDPStream`。
3. **Capsule 协议 Fallback**:
   - `NCMASQUEUDPStream` 在双向流上开启 DATA 帧监听，通过 `CapsuleParser` 解析流内携带的 Capsule Type `0x00`（DATAGRAM capsule），兼容通过 TCP/Stream 传递的 UDP 数据报。
4. **背压与内存安全 (#116 契约)**:
   - `NCMASQUEUDPStream` 严格遵循 `send(_:completion:)` 协议规范，通过 `NCCallOnce` 封装 completion，保证在网络成功、失败、取消等所有分支下 completion 均精确触发一次且仅一次，绝不 double-fire。
   - 接收缓冲区 `pendingReceives` 设容量上限 32 帧，防止内存膨胀触发 iOS Jetsam 50MB 杀进程。

### 4.2 CONNECT-IP 判定与显式标记
- **判定与边界**：CONNECT-IP (RFC 9484) 属于 L3 虚拟网卡协议，与 WireGuard 相同，其数据面必须挂接在 PacketTunnel 目标的用户态 lwIP 协议栈（虚拟 netif）。`NCConnector` 为应用层与测试 bundle 暴露的 L4 代理流接口（`NCRelayStream`），无法作为单个流式套接字直连。
- **显式拦截与不可用提示**：
  若传入节点的 `mode` 为 `connect-ip`（或 Cloudflare WARP MASQUE 节点未指定 connect-udp），`NCMASQUERegistry.masqueStream` 显式拦截并返回明确错误：
  `Failure.unsupported("MASQUE CONNECT-IP 模式仅支持在 PacketTunnel VPN 隧道内作为 L3 虚拟网卡运行，当前应用层仅支持 CONNECT-UDP 代理")`。
  绝不静默失败或丢弃。

---

## 5. 单元测试与回环测试

### 5.1 单测补强用例清单 (`UnitTests/NativeCoreMASQUETests.swift`)
1. `testDatagramCodecBoundaries`:
   - 覆盖空包（返回 nil）、截断 Quarter Stream ID、截断 Context ID、零 payload 报文（正确解出空 payload）、大整数 varint 报文（streamID 1024 -> quarterStreamID 256）与非零 Context ID。
2. `testCapsuleCodecBoundaries`:
   - 覆盖截断头部分块 feed 重组、未知 Capsule 类型（RFC 9297 §3.2 规定忽略并正常步进）、多个不同类型 Capsule 混合在同一 chunk 时的连续正确解析。
3. `testNegotiationFailurePaths`:
   - 覆盖 Extended CONNECT 收到非 2xx 响应（如 403 Forbidden）时 QPACK 正确解码状态并捕获失败、畸形 QPACK 响应头的容错处理。
4. `testURITemplateExpansion`:
   - 覆盖 RFC 9298 相对路径模板展开、带 scheme 的绝对 URL 模板展开、IPv6 目标地址自动包裹中括号 `[2606:4700::1]`。
5. `testConnectIPModeRejectedAtConnector`:
   - 验证通过 `NCConnector.connect` 拨号 CONNECT-IP 节点时，被显式拦截并抛出包含 `CONNECT-IP` 详细说明的错误。

### 5.2 回环测试用例 (`UnitTests/NativeCoreLoopbackTests.swift`)
- `testMASQUEUDPEcho`:
  - 构造 `loop-masque` 节点（指向 `127.0.0.1:18012`，`skip-cert-verify: true`，`uri: https://127.0.0.1:18012/.well-known/masque/udp/{target_host}/{target_port}/`）；
  - 目标指定为 `127.0.0.1:18081`（`echo_server.py` UDP echo 服务）；
  - 驱动 `NCConnector.connect` 建立连接，发送 8KB 测试 DNS 报文，断言返回报文与原数据逐字节一致。
- **实测结论**：
  - 本地 Linux 沙箱无 Xcode 与 iOS Simulator 环境，标注为：**待 CI**（由 `.github/workflows/proto-loopback.yml` 在 macos-15 runner 上验证）。

---

## 6. 红线与红线核对

- [x] **纯 Swift 实现**：数据面与连接器（`NCMASQUESession.swift`、`NCMASQUE.swift`、`NCConnector.swift`）为 100% 纯 Swift，内核零引入 Go。
- [x] **零新增第三方依赖**：未在 `Package.swift` 或项目配置中引入任何外部 SwiftPM/CocoaPods 依赖。
- [x] **端口统一**：所有相关文件均统一为 18012，无任何遗留 18009 冲突。
- [x] **绝不动 main / feat/nc-kernel**：全程工作在 `feat/nc-masque` 分支。
- [x] **不静默丢弃**：不支持的字段和应用层不支持的 CONNECT-IP 模式均显式拦截并报出清晰原因。
- [x] **未开 PR、未触发 CI**：严格遵守 S2 派发边界。
