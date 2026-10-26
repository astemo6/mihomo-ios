# NativeCore Sudoku S1 任务报告 — 规范可得性调研与解析层交付

## 1. 核心判定 (Verdict)

**判定结果：规范公开且开源 (Option A)。**

经过深入的 Web、GitHub 原文规范、主流代理内核及闭源/开源客户端代码库查证，判定 **Sudoku 代理协议的规范、线格式、加密机制、密钥协商、参考实现与服务端均已完全公开并开源**（遵循 GPL-3.0 许可证）。

因此，本阶段严格按照任务书 **Option A（规范公开）** 路径交付：
1. 编写协议设计规范文档 `docs/nc-proto-sudoku.md`（含传输与加密设计、字段对标矩阵、不支持字段表及 S2 回环计划）。
2. 在 `Shared/NativeCore/` 交付 Sudoku 解析层及验证逻辑（支持 Clash/mihomo YAML、官方 `sudoku://<base64url(json)>` 短链接、标准 URI、Surge/Shadowrocket `.conf` 及 Quantumult X 节点行格式），不支持/无效字段全部严格接入 `NCSupport` 显式不可用标记机制，杜绝静默失败或丢弃。
3. 在 `UnitTests/` 交付完整的解析单元测试套件 `NativeCoreSudokuTests.swift`（覆盖正例、负例及不支持标记用例）。

---

## 2. 证据链与出处 (Evidence Chain & Sources)

### 2.1 官方仓库与规范原文
- **官方规范与核心实现仓库**：`SUDOKU-ASCII/sudoku` (GitHub: `https://github.com/SUDOKU-ASCII/sudoku`)
- **开源许可证**：GNU General Public License v3.0 (`GPL-3.0`)
- **协议作者**：`saba-futai` / `saba`
- **活跃度**：仓库创建于 2025 年 11 月 28 日，截至 2026 年持续高频更新与维护，目前包含跨平台桌面端、Android 端 (`sudoku-android`) 以及单二进制服务端。
- **关键规范文档与代码出处**：
  - 协议总体与线格式文档：`doc/README.md`、`README.md`、`README.zh_CN.md`
  - 配置参数与字段说明：`configs/README.md`、`configs/README.zh_CN.md`
  - 短链接规范与字段定义：`internal/config/shortlink.go`（函数 `BuildShortLinkFromConfig`、`BuildConfigFromShortLink` 及结构体 `shortLinkPayload`）
  - 控制平面 KIP 消息与握手逻辑：`apis/config.go`、`internal/protocol/address.go`
  - AEAD 记录分帧与加密：`pkg/crypto/aead.go`、`apis/codec.go`

### 2.2 客户端与内核生态支持出处
- **MetaCubeX/mihomo (ClashMeta)**：
  - PR #2397 (`Add Sudoku protocol inbound & outbound support`) 于 2025-11-28 合入主线，在 Mihomo >= v1.19.21 提供出站 (`adapter/outbound/sudoku.go`) 与入站监听 (`listener/inbound/sudoku.go`) 完整支持。
  - 官方配置文档：`https://wiki.metacubex.one/en/config/proxies/sudoku/`
- **Shadowrocket (小火箭)**：
  - 官方正式版 v2.2.92 更新日志正式宣布支持 Sudoku 协议：*"特性(protocol): 新增 Sudoku 代理协议支持，并深度优化其数据转发路径以减少内存分配与拷贝"*（出处：App Store 历史版本记录、官方 Telegram 频道 `@ShadowrocketNews` 消息）。
  - Shadowrocket 支持通过 `sudoku://<base64url(json)>` 短链接以及 Clash YAML 订阅导入 Sudoku 节点。
- **Anywhere Proxy (iOS/macOS/tvOS)**：
  - GitHub 仓库：`https://github.com/NodePassProject/Anywhere`（GPL-3.0）
  - 作者同为 `saba-futai` / NodePassProject，为面向 Apple 平台的纯 Swift 原生 Sudoku 客户端实现，关键文件包括 `Shared/Networking/Protocols/Sudoku/SudokuConfiguration.swift`、`SudokuProxyConnection.swift`、`SudokuNativeCore.swift`、`ClashProxyParser.swift`。
- **sing-box**：
  - 官方测试分支：`SUDOKU-ASCII/sudoku-sing-box`
- **Quantumult X**：
  - 查证确认 Quantumult X 官方尚未原生支持 Sudoku。为保证兼容性，解析层已对 QX 风格节点行（`sudoku=server:port, ...`）提供支持，但在必要时标记不支持原因。

---

## 3. 协议传输、加密与数据面设计

1. **数独混淆层 (Steganography)**：
   - 将任意字节数据流（每字节 256 种可能）映射为 4×4 数独谜题（共有 288 种非同构体），每个谜题由 4 个 Clues 确定唯一解。
   - 采用真任意动态填充 (True Arbitrary Padding)：接收方利用数独谜题唯一可解性直接判别并丢弃非法或非唯一解的填充字节，无需在握手或帧头中协商填充长度。
   - 外观风格：
     - `prefer_ascii`：全打印 ASCII 字符，输出字节在抓包分析中呈现明文外观。
     - `prefer_entropy`：低熵字节布局，字节汉明重量保持在 3.0 左右（规避 GFW Report 3.4~4.6 的特征检测区间）。
     - 支持方向性模式（`up_ascii_down_entropy`、`up_entropy_down_ascii`）以及自定义 8 字符布局表（2个 x、2个 p、4个 v，如 `xpxvvpvv`）。
2. **下行模式**：
   - 纯数独下行 (`enable-pure-downlink: true`)：双向均走经典 4×4 数独提示编码。
   - 带宽优化下行 (`enable-pure-downlink: false`)：下行将字节拆为 6-bit 分片，降低带宽膨胀。
3. **HTTP 伪装层 (`httpmask`)**：
   - `legacy`：建立 TCP 连接后前置随机伪造 HTTP/1.1 请求头，随后转入原生数独流。
   - `stream` / `poll` / `auto` / `ws`：适用于 Cloudflare CDN / 反向代理穿透的真实 HTTP/WebSocket 隧道模式。
4. **AEAD 记录层**：
   - 头部 12 字节明文：`epoch`（uint32 BE，密钥轮换计数） + `seq`（uint64 BE，递增记录号），该 12 字节同时作为 AEAD 的 Nonce 和 AAD。
   - 密文帧：`body_len` (uint16 BE) + 12 字节头部 + sealed ciphertext。
   - 加密套件：`chacha20-poly1305`（默认）、`aes-128-gcm`、`none`（明文调试）。密钥由 `SHA256(key)` 派生。
5. **控制平面 (KIP 帧)**：
   - 统一格式：`"kip"` (3B) + `type` (1B) + `payload_len` (2B BE) + `payload`。
   - 类型：ClientHello (`0x01`)、ServerHello (`0x02`)、OpenTCP (`0x10`)、StartMux (`0x11`)、StartUoT (`0x12`)、KeepAlive (`0x14`)。
   - 握手载荷：8B 时间戳 + 8B 用户哈希 (`SHA256(key)[:8]`) + 16B 客户端随机 Nonce + 32B X25519 临时公钥 + 4B 特征位。

---

## 4. 文件变更清单 (File Manifest)

| 文件路径 | 变更类型 | 说明 |
|---|---|---|
| `docs/nc-proto-sudoku.md` | 新增 | Sudoku 协议设计规范、字段对标表、不支持字段表及 S2 回环计划文档 |
| `Shared/NativeCore/NCSudoku.swift` | 新增 | Sudoku 核心模型定义、AEAD/Table/HTTPMask 枚举、字段验证、短链接/URI 编解码与解析 |
| `Shared/NativeCore/NCSupport.swift` | 修改 | `types` 集合注册 `"sudoku"`，接入 `sudokuUnsupported` 字段合规检测与显式原因输出 |
| `Shared/NativeCore/NCSubscription.swift` | 修改 | `selfSchemes` 与 `qxNodeTypes` 注册 `"sudoku"`，接入短链接与 URI 解析及订阅列表去重 |
| `Shared/NativeCore/NCConfImport.swift` | 修改 | Surge/Shadowrocket `.conf` 解析器增加 `sudoku` 协议类型与字段映射（key, aead, table-type 等） |
| `Shared/NativeCore/NCQXImport.swift` | 修改 | Quantumult X 节点解析器增加 `sudoku` 类型与字段映射 |
| `Shared/NativeCore/NCConnector.swift` | 修改 | 拨号入口 `connectViaProxy` 增加 `case "sudoku"`，前置校验失败时返回明确原因，通过则占位等待 S2 |
| `UnitTests/NativeCoreSudokuTests.swift` | 新增 | 完整的单元测试套件（Clash YAML、短链接、URI、Surge .conf、QX、去重、负向测试、不支持字段标记、Connector 回调） |
| `report-sudoku-s1.md` | 新增 | 本报告（调研结论、出处、改动清单、支持/不支持表、S2 计划） |

---

## 5. 支持与不支持字段对标表

### 5.1 支持字段

| 字段名称 | YAML 键名 | 短链接键名 | Conf / QX 键名 | 类型 | 说明 |
|---|---|---|---|---|---|
| 服务器地址 | `server` | `h` | 2nd positional | String | 目标服务器 IP 或域名 |
| 端口 | `port` | `p` | 3rd positional | Int | 目标服务器端口 (1..65535) |
| 密钥 | `key` | `k` | `key=` / `password=` | String | 客户端私钥或服务端主公钥/共享密钥 |
| 节点名称 | `name` | `n` | Line key / `tag=` | String | 节点显示名称 |
| 加密算法 | `aead-method` / `aead` | `e` | `aead-method=` / `aead=` | String | `chacha20-poly1305`（默认）、`aes-128-gcm`、`none` |
| 表类型 / 字符集 | `table-type` / `ascii` | `a` | `table-type=` / `ascii=` | String | `prefer_entropy`（默认）、`prefer_ascii`、方向性模式 |
| 最小填充 | `padding-min` | — | `padding-min=` | Int | 填充百分比下限 (0..100) |
| 最大填充 | `padding-max` | — | `padding-max=` | Int | 填充百分比上限 (0..100，≥ min) |
| 自定义表布局 | `custom-table` | `t` | `custom-table=` | String | 8 字符（2个x、2个p、4个v，如 `xpxvvpvv`） |
| 多表轮换 | `custom-tables` | `ts` | — | [String] | 自定义表布局数组 |
| 纯数独下行 | `enable-pure-downlink` | `x` (反向: x=true 表示带宽优化) | `enable-pure-downlink=` | Bool | 默认 true；false 为 6-bit 拆分下行 |
| 多路复用 | `multiplex` | `hx` | `multiplex=` | String | `"off"`、`"auto"`、`"on"` |
| HTTP 伪装开关 | `httpmask.disable` | `hd` | `httpmask-disable=` | Bool | 是否完全禁用 HTTP 伪装 |
| HTTP 伪装模式 | `httpmask.mode` | `hm` | `httpmask-mode=` | String | `"legacy"`、`"stream"`、`"poll"`、`"auto"`、`"ws"` |
| HTTP 伪装 TLS | `httpmask.tls` | `ht` | `httpmask-tls=` | Bool | 伪装是否走 HTTPS |
| HTTP 伪装 Host | `httpmask.host` | `hh` | `httpmask-host=` | String | 伪装请求 Host / SNI |
| HTTP 伪装路径 | `httpmask.path-root` | `hy` | `httpmask-path=` | String | 伪装根路径前缀 |

### 5.2 不支持字段与显式标记原因

| 字段 / 场景 | 检测条件 | 显式不可用提示字符串 (`unsupportedReason`) | 原因与处置 |
|---|---|---|---|
| 缺少密钥 | `key` 为空 | `"Sudoku 缺少 key"` | 无法推导数独映射表与 AEAD 派生密钥 |
| 缺少服务器 | `server` 为空 | `"Sudoku 缺少 server"` | 无出站连接目标 |
| 端口无效 | `port <= 0` 或 `> 65535` | `"Sudoku 缺少有效 port"` | 端口数值超限 |
| 非法 AEAD | 非 `chacha20-poly1305` / `aes-128-gcm` / `none` | `"Sudoku 不支持的 aead-method: \(aead)"` | 仅支持协议规范内的 AEAD 套件 |
| 非法表类型 | 非 `prefer_ascii` / `prefer_entropy` / 定向模式 | `"Sudoku 不支持的 table-type: \(table)"` | 仅支持协议规范内已定义的数独字符映射类型 |
| 填充区间非法 | `min < 0` 或 `max < min` 或 `max > 100` | `"Sudoku padding 范围无效: \(min)-\(max) (须 0 <= min <= max <= 100)"` | 填充必须满足百分比合法区间 |
| 自定义表非法 | 长度不为 8 或字符非 2x+2p+4v | `"Sudoku custom-table 无效: 须由 2个x、2个p、4个v 组成的8字符 (如 xpxvvpvv)"` | 4×4 数独提示必须满足 420 种严格排列特征 |
| 非法伪装模式 | 模式不在 `legacy`/`stream`/`poll`/`auto`/`ws` | `"Sudoku httpmask mode 不支持: \(mode)"` | 未定义的 HTTP 伪装传输模式 |
| 反向代理配置 | 配置包含 `reverse` 块 | `"Sudoku reverse (反向代理) 尚未接入"` | 反向代理用于将客户端内网服务反向暴露，出站客户端不适用 |
| 服务端白名单 | 配置包含 `users` 列表 | `"Sudoku users (服务端白名单) 仅用于服务端"` | 服务端客户端配额计量与访问控制功能 |

---

## 6. S2 实施计划与建议 (S2 Plan & Recommendations)

1. **纯 Swift 数据面实现 (`Shared/NativeCore/NCSudokuSession.swift`)**：
   - 4×4 数独解谜算法：依据官方规范预先计算 288 种非同构谜题并进行紧凑编码，常驻内存 < 64 KB，实现 O(1) 编解码。
   - 动态随机填充注入与过滤：在发送端按 `paddingMin`/`paddingMax` 注入非唯一解谜题，接收端实时解谜并滤除填充。
   - CryptoKit 原生驱动：复用 `CryptoKit.ChaChaPoly` 与 `CryptoKit.AES.GCM` 处理 AEAD Record 分帧，零第三方依赖。
   - KIP 握手与 SOCKS5 目标地址序列化。
2. **回环测试服务搭建 (`tools/loopback/`)**：
   - 服务端选用官方开源 `sudoku` Go 二进制或 `mihomo` 容器镜像，配置监听 18443 端口。
   - 在 `UnitTests/NativeCoreLoopbackTests.swift` 新增 `testSudokuTCPPing` 与 `testSudokuUoT`。
   - 工作流 `.github/workflows/proto-loopback.yml` 接入自动化回归。
