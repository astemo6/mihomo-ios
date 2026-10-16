# Mihomo iOS（v0.4）

基于开源 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）内核的个人 iOS 代理客户端：深色卡片界面，首页只放最常用的东西，进阶功能按类别收在「更多」里。

> 本项目以 **GPL-3.0** 发布（见 `LICENSE` 与 `NOTICE`），与 mihomo 内核许可一致。仓库里没有任何节点、证书或密钥。

## 设计原则

1. **一个内部模型**：所有东西最终都是「mihomo 配置 + 我们自己的覆写 / 模块存储」。Surge、Quantumult X、Loon、Stash 的格式只在导入边缘做一次翻译，之后就是普通的 mihomo 配置或模块，不存在第二套运行逻辑。
2. **一种设计语言**：项目自己的深色卡片（`Theme` / `Card`），新页面不照搬其他客户端的布局。
3. **首页极简**：连接开关、出站模式、IP 卡片、流量。其他功能都在「更多」里分组：连接、规则与资源、模块重写与 MitM、工具与数据、设置。
4. **模块只有一个入口**：所有格式的模块都在「更多 → 模块」，用角标标出来源格式。
5. **宁缺毋滥**：做不精的功能先不做（仍推迟：主屏幕小组件、控制中心开关、实时活动、按 SSID 切策略、日 / 韩 / 俄语）。
6. **规则、重写、脚本都接受 Surge 与 Quantumult X 写法**（以及 Loon、Stash），只在边缘翻译一次。

## 功能

| 位置 | 内容 |
| --- | --- |
| 首页 | IP / ASN 卡片（出口 + 直连）、连接开关、规则 / 全局 / 直连、当前配置与节点、实时速度曲线、本次上传 / 下载 |
| 策略 | 已连接：实时策略组、点选切换、组测速。**未连接：「未连接 · 来自配置文件」离线策略页**——读取当前配置（含节点集缓存、合并的手动节点），可以选节点（按配置保存，下次连接时自动应用）、直接测速 |
| 请求 | 实时连接、最近关闭、MitM 解密的 HTTP 请求（头部 / 内容查看、**复制为 cURL、重放、编辑后重放**） |
| 配置 | 订阅流量 / 到期（`subscription-userinfo`，含剩余天数）；**节点处理**（每个订阅：过滤、重命名、旗帜、去重、排序 + 实时预览）；订阅 / 本地 YAML / 剪贴板 / 文件；**Surge / Quantumult X `.conf` 导入**（先显示转换报告：节点、策略组、规则、规则集数量与未转换项，重写部分作为模块导入）；手动节点 |
| 更多 → 连接 | 连接方式（全局隧道 / 仅代理）、按需连接（始终 / 仅 Wi-Fi / 仅蜂窝；App 内手动断开会暂停按需连接，直到下次手动连接）、DNS（国内 / 国外分流、引导 DNS、nameserver-policy、Fake-IP 过滤） |
| 更多 → 规则与资源 | 规则（实时或离线）+ **自定义规则**（Surge / QX / Loon / mihomo 写法，输入时实时校验并显示转换结果与策略组；远程 RULE-SET / DOMAIN-SET / QX filter_remote）；提供者（实时，或离线显示 URL / 类型 / 缓存内容）；**地理与规则库**（GeoIP MMDB、GEOIP dat、GEOSITE、GeoLite2-ASN：状态、更新时间、默认地址、自定义地址、国内镜像开关、下载进度与错误） |
| 首页 → 面板 | 只在已连接且模块带面板时出现一行入口：Surge `[Panel]` / Stash `tiles` 合并为一个「面板」页，脚本驱动、可刷新（不是主屏幕小组件） |
| 更多 → 模块、重写与 MitM | 模块（全部格式一个入口，格式角标；一键添加 BoxJS；参数含 Loon `[Argument]` 开关 / 选择；**策略映射**：模块规则里配置中不存在的策略名可逐个指定策略组）、重写、脚本、MitM |
| 更多 → 工具与数据 | 网络工具（Ping / TCP / DNS，连接时经过内核规则并显示策略链）、流量统计（Swift Charts，按天保存约 120 天）、日志、备份与恢复（文件 / 分享 / iCloud） |
| 更多 → 设置 | 内核设置（内存上限、隧道 MTU、手动节点合并进每个配置、日志、IPv6、局域网、控制器）、诊断（App Group、扩展 ID、启动日志） |
| 快捷指令 | 连接、断开、切换连接、切换出站模式、切换节点（App Intents）；主屏幕长按图标：连接 / 断开、规则 / 全局 / 直连 |
| 导入链接 | 只注册自己的 `mihomo://`（`mihomo://install-config?url=`、`install-module?url=`、`connect`、`disconnect`、`toggle`）。粘贴的 `loon://`、`stash://`、`surge:///`、`quantumult-x:///` 安装链接也能识别，但**不注册**这些 scheme，避免与其他客户端抢链接。可以用「文件」打开 `.sgmodule` `.plugin` `.stoverride` `.conf` `.list` `.yaml` |

## v0.4 要点

### 订阅管理（节点处理）

配置页左滑或长按订阅 →「节点处理」。规则保存在本机覆写 `mihomo/subscriptions.json`（按配置 ID），**生成运行配置时在 Go 侧应用**，下载的订阅文件不改动，所以更新订阅后规则依然有效。顺序：过滤 → 去前缀 / 旗帜 → 重命名 → 加旗帜 → 前缀 → 去重 → 排序 → 同名自动加序号。

| 项目 | 说明 |
| --- | --- |
| 保留 / 排除 | 关键词（`\|` 分隔，不区分大小写）或 JavaScript 正则（regexp2）；一键填入「剩余 / 到期 / 官网」等信息节点关键词 |
| 重命名 | 多条正则替换，按顺序执行，可用 `$1`；内置几个常用模板 |
| 前缀与旗帜 | 去掉指定前缀、去掉原有旗帜、按地区识别（中英文地名 / 城市 / 两三位代码 / 旗帜，约 45 个地区）添加旗帜 Emoji、统一添加前缀 |
| 去重 / 排序 | 去掉类型、地址、端口、凭据都相同的节点；按名称（自然排序）或按地区（港、澳、台、日、新、韩、美…）排序 |
| 实时预览 | 编辑时 300 ms 防抖调用 Go `SubPreview`：每个节点的原名 → 新名、地区、被移除的原因（未匹配保留 / 匹配排除 / 重复）；保存前若会移除全部节点会提示 |

改名或移除节点后，策略组成员、`dialer-proxy` 和直接指向节点的规则会同步更新；某个策略组的成员被全部过滤掉时自动放入 `DIRECT`，保证配置仍然有效。节点集（`proxy-providers`）用 mihomo 原生的 `filter` / `exclude-filter` / `override.proxy-name` / `override.additional-prefix` 实现过滤与重命名；旗帜、去重、排序只作用于配置里直接列出的节点。

### 脚本引擎补全

| 类型 | Surge | Loon | Quantumult X | Stash |
| --- | --- | --- | --- | --- |
| 定时（连接期间按计划执行） | `名称 = type=cron,cronexp="0 8 * * *",script-path=…,timeout=…,argument=…` | `cron "0 8 * * *" script-path=…, tag=…` | `[task_local]` `0 8 * * * https://…/a.js, tag=…, enabled=true` | `cron: script: [{name, cron, timeout, argument}]` + `script-providers` |
| 事件（网络变化） | `type=event,event-name=network-changed` | `network-changed script-path=…` | `event-network https://…` | — |
| 通用（手动运行 / 面板） | `type=generic` | `generic script-path=…` | `event-interaction https://…` | `tiles` 的脚本 |

- 时区：扩展启动时把设备时区（IANA 名称，内置 tzdata）交给 Go，cron 按本地时间触发（iOS 沙盒里 Go 默认是 UTC）。
- cron 表达式：5 段，或 6 段（首段为秒，QX 写法），支持 `*` `?` 列表、范围、步长、月份 / 星期英文缩写、`@daily` 等；日与星期同时限定时任一满足即执行。
- 调度在扩展里进行：只有隧道连接时才运行。只有定时 / 事件脚本、没有 MitM 与重写时，引擎只启动调度，不会把任何流量引到引擎。
- 定时 / 事件 / 通用脚本单独排队（一次一个，默认超时 30 秒，最长 300 秒），不占用 HTTP 脚本的并发；HTTP 脚本超时上限提高到 120 秒（BoxJS 需要）。
- 网络变化：扩展用 `NWPathMonitor` 监听物理网络（Wi-Fi ⇄ 蜂窝、接口变化，2 秒防抖），把 `$network`（`type`、`v4.primaryInterface`、`wifi.ssid` 恒为 null）和 `$event` 交给事件脚本。
- 新增 API：`$utils.geoip / ipasn / ipaso`（用内置 MMDB / ASN 库）、`$utils.ungzip`（gzip / zlib / deflate）、`$network`、`$event`、面板脚本的 `$input` / `$panel`；`$argument` 未设置时为 `undefined`（不再抛 ReferenceError）。
- `$persistentStore` 与 `$prefs` 是同一个存储（App Group 里的 `engine/store.json`），所有脚本共享，App 里可查看编辑。
- `$notification.post` / `$notify`：扩展发本地通知，同时记录最近 100 条到 `engine/notifications.json`，在 脚本 → 脚本通知记录 查看（断开时也能看）。
- 更多 → 脚本 → 定时与事件脚本：下次运行时间、上次结果 / 耗时、手动运行。

### BoxJS

模块页 + →「添加 BoxJS」导入官方 Surge 模块（chavyleung/scripts）。它把 `boxjs.com` / `boxjs.net` 加入 MitM 主机名，由 http-request 脚本在本地直接返回 BoxJS 页面（`$done({response})`），数据存进共享的 `$persistentStore`。前提：开启 HTTPS 解密并完全信任 CA 证书，然后在 Safari 打开 `https://boxjs.com`。

### 面板

模块里的 Surge `[Panel]`（`名称 = script-name=…,update-interval=…` 或静态 `title=…,content=…,style=…,icon=…`）和 Stash `tiles` 合并为一个「面板」页：图标（SF Symbols 名称）、标题、内容、`style`（good / info / alert / error）或 `icon-color` / `backgroundColor`。打开页面时刷新从未运行或已过期的面板，下拉全部刷新，单个也可刷新；连接期间按 `update-interval` 自动更新。首页只在有面板时显示一行入口。

### 请求抓取

MitM 解密的请求本来就在内存环形缓冲里（最近 200 条，头部全部记录，内容每个方向最多 32 KB）。v0.4 增加：复制为 cURL、重放、编辑后重放（方法 / URL / 头部 / 内容）。重放经内核的 inner 通道发出（仍按你的规则和策略），不再经过重写和脚本，结果显示在详情页并作为新记录（备注「重放 #id」）。二进制请求体或超过 32 KB 的请求体没有完整记录，不能重放。

### 多语言

String Catalog（`App/Localizable.xcstrings`），源语言简体中文，提供 English 与繁體中文（臺灣用語）。键由编译器提取（`SWIFT_EMIT_LOC_STRINGS`，CI 上传 `stringsdata` 供维护）。跟随系统语言，也可以在 iOS 设置 → Mihomo → 语言 单独切换。内核和 Go 侧返回的错误信息仍为中文。新增字符串后用 `scripts/i18n_sync.py <stringsdata 目录>` 补进目录（繁体自动转换，列出待翻译的英文）。

### 未做 / 推迟

- 按 SSID 切换策略：需要 `com.apple.developer.networking.wifi-info`，第三方重签的描述文件通常没有，读取 SSID 会静默失败；本轮不做，`$network.wifi.ssid` 恒为 null。
- 主 App 去掉 Libmihomo 以缩小 IPA：离线校验 / 导入 / 离线策略页 / 预览都依赖内核解析，换成更轻的 Go 库几乎省不下（解析节点就要链接全部协议）；可行的方案是把 Libmihomo 包成一个动态库 framework 由 App 和扩展共用（IPA 预计少 40% 左右），但扩展里 Go 运行时以动态库加载无法在 CI 上验证，风险是隧道无法启动，所以留到能真机测试时再做。
- 日 / 韩 / 俄语。

## v0.3 要点

- **PacketFlowBridge**（`PacketTunnel/PacketFlowBridge.swift`）：用 `socketpair(AF_UNIX, SOCK_DGRAM)` 连接 `NEPacketTunnelFlow.readPackets / writePackets`（公开 API）与内核的 tun fd，取代 v0.2 的 utun fd 扫描。系统 → 内核方向有界队列（512 包 / 2 MB）+ 写就绪源做背压；内核 → 系统方向每批最多 64 包；`ENOBUFS` 时 1–32 ms 指数退避。思路来自 Hako-Adapter（GPL-3.0），实现独立编写。
- **仅代理模式**：不接管路由与 DNS，只用 `NEProxySettings` 把 HTTP / HTTPS 指向扩展内 `127.0.0.1:7890` 的 mixed 端口。
- **内存守护**：Go 软上限（默认 36 MB，可调）+ `phys_footprint` / `os_proc_available_memory` 采样（接近上限时每 2 秒）+ 内存压力事件：先 `FreeOSMemory`，再关闭全部连接，避免被系统杀掉。
- **启动看门狗**：内核最多等 20 秒，扩展 30 秒看门狗必定回调，失败时显示中文原因，不会一直停在「连接中…」。启动日志记录每个阶段。
- **每日流量记录**：扩展每 2 分钟把内核计数增量写入 App Group（约 120 天）。

## 架构

```
┌────────────── 主 App（SwiftUI，iOS 16+）──────────────┐
│ VPNManager（NETunnelProviderManager + 按需连接）        │
│ ControllerClient ──HTTP/WebSocket──► 127.0.0.1:9090     │
│ ProfileStore / ProfileInspector（离线解析配置）         │
│ ImportRouter（mihomo:// + 外部链接 + 文档）、App Intents │
│ Libmihomo（校验、转换、离线解析、地理库安装）           │
└──────────────────────────────┬─────────────────────────┘
                               │ App Group（运行时从描述文件解析）
┌──────────── PacketTunnel 扩展（NEPacketTunnelProvider）┐
│ 全局隧道：198.18.0.1/16、默认路由、DNS 198.18.0.2、MTU  │
│ 仅代理：NEProxySettings → 127.0.0.1:<mixed-port>        │
│ PacketFlowBridge：packetFlow ⇄ socketpair ⇄ 内核 tun fd │
│ MemoryGuard、TrafficRecorder、30 s 看门狗、启动日志     │
│ LibmihomoStart(home, profile, fd)                       │
└────────────────────────────────────────────────────────┘
```

- `bridge/`：Go 包 `libmihomo`（gomobile）。启动时把配置与 `overrides.json`、`dns.json`、`rules.json`、模块合并为 `runtime.yaml`。
- 设置文件（App Group 容器 `mihomo/`）：`subscriptions.json`（每个订阅的节点处理规则）、`overrides.json`（内核覆写，含 `tunnelMode` `mixedPort` `tunMTU` `geoMirror` `geoURLs` `mergeManual`，解码容错）、`dns.json`、`rules.json`、`engine/`（MitM / 重写 / 脚本 / 模块）；每个配置旁的 `<id>.selected.json` 保存离线选择的节点。
- 工程由 XcodeGen 从 `project.yml` 生成；**Bundle ID 与 App Group 只在 `project.yml` 顶部改一处**。

## 协议支持

内核按 mihomo 默认构建（只加 `with_gvisor`，不使用任何 `no_*` 裁剪标签），包含 mihomo 支持的全部出站协议：Shadowsocks（含 2022、obfs / v2ray-plugin / shadow-tls 插件）、ShadowsocksR、VMess、VLESS（含 Reality、XTLS-Vision）、Trojan、Hysteria、Hysteria2、TUIC v5、WireGuard、Snell、AnyTLS、Mieru、SSH、SOCKS5、HTTP/HTTPS 等。

导入解析（`bridge/nodes.go`，带单元测试覆盖每种格式并经内核校验）：

| 格式 | 示例 |
| --- | --- |
| 分享链接 | `ss://` `ssr://` `vmess://`（v2rayN JSON）`vless://` `trojan://` `hysteria://` `hysteria2://` `hy2://` `tuic://` `wireguard://` `wg://` `snell://` `anytls://` `mierus://` `socks5://` `socks://` `http(s)://user:pass@host:port` |
| 订阅 | base64 编码的链接列表；mihomo / Clash YAML |
| Surge / Egern | `名称 = ss, host, 8388, encrypt-method=aes-128-gcm, password=…`（ss / vmess / trojan / snell / http / https / socks5 / socks5-tls / hysteria2 / tuic / anytls / ssh） |
| Quantumult X | `shadowsocks=host:port, method=…, password=…, tag=名称`（shadowsocks / vmess / vless / trojan / http / socks5） |

策略页每个节点都有协议角标。

## 内核自动升级

`.github/workflows/core-update.yml` 每天 02:00 UTC（也可手动运行，可指定版本）：

1. 通过 GitHub API 取 MetaCubeX/mihomo 最新**正式版**（`/releases/latest`，跳过 Prerelease-Alpha 等预发布）；
2. 与 `bridge/go.mod` 中的版本比较，较新时在分支 `core/mihomo-<tag>` 上执行 `go get github.com/metacubex/mihomo@<tag> && go mod tidy`，`go vet` + `go test`，提交 `core: mihomo <tag>`；
3. 通过 `workflow_call` 调用 `ios.yml` 在该分支完整构建一次（不发布）；
4. 成功 → 合并到默认分支，并用 `workflow_dispatch` 触发 `ios.yml` 发布新 IPA Release；失败 → 开 issue（或在已有 issue 下评论），默认分支不受影响。

内核版本**只记录在 `bridge/go.mod`**，`ios.yml` 构建时从中读取，所以自动升级不需要修改 workflow 文件（`GITHUB_TOKEN` 无权推送 `.github/workflows` 下的改动）。

## CI

`.github/workflows/ios.yml`（push 到 main 或手动运行）：setup-go → gomobile 构建 xcframework（按 bridge 源码与内核版本缓存）→ XcodeGen → `xcodebuild archive` → IPA → 上传 Artifact，并发布 GitHub Release（tag `v<版本>-build<N>`）。手动运行时可勾选 `build_only` 只编译不发布。

- **没有签名 secrets**：`CODE_SIGNING_ALLOWED=NO` 构建，然后用 `codesign -s -`（伪签名）把 entitlements 写进 App 和扩展，打包为 `Mihomo-<版本>-build<N>-unsigned.ipa`。Release 中同时附带 `app.entitlements` / `tunnel.entitlements`，方便重签工具使用。
- **有签名 secrets**：导入证书和两个描述文件，导出 `Mihomo-<版本>-build<N>-signed.ipa`。

## 获取可安装的签名版本

需要付费的 Apple Developer 账号（个人免费账号无法使用 Network Extension 能力）。

1. **注册 App ID**（Certificates, Identifiers & Profiles → Identifiers → +，App IDs）：
   - `com.astemo6.mihomo`：勾选 **App Groups** 和 **Network Extensions**。
   - `com.astemo6.mihomo.tunnel`：同样勾选 **App Groups** 和 **Network Extensions**。
   - 如果用自己的前缀，改 `project.yml` 顶部的 `APP_BUNDLE_ID` / `TUNNEL_BUNDLE_ID` / `APP_GROUP_ID`。
2. **注册 App Group**：Identifiers → 右上角切到 App Groups → +，`group.com.astemo6.mihomo`。然后回到两个 App ID，在 App Groups 能力里 Configure，勾选这个组。
3. **证书**：Apple Development（development 方式）或 Apple Distribution（ad-hoc 方式）。在钥匙串里导出为 `.p12`（带密码）。
4. **注册设备**（Devices → +，填 iPhone 的 UDID）。
5. **描述文件**（Profiles → +）：类型选 iOS App Development（或 Ad Hoc），分别给两个 App ID 各建一个，选上证书和设备，下载两个 `.mobileprovision`。
6. **添加仓库 Secrets**（Settings → Secrets and variables → Actions → New repository secret）：

   | Secret | 值 |
   | --- | --- |
   | `BUILD_CERTIFICATE_BASE64` | `base64 -i cert.p12 \| pbcopy` 的结果 |
   | `P12_PASSWORD` | 导出 p12 时设的密码 |
   | `APP_PROFILE_BASE64` | 主 App 描述文件的 base64 |
   | `TUNNEL_PROFILE_BASE64` | 扩展描述文件的 base64 |
   | `TEAM_ID` | 10 位 Team ID（Membership 页面） |
   | `KEYCHAIN_PASSWORD` | 任意随机字符串（CI 临时钥匙串用） |
   | `EXPORT_METHOD` | 可选：`development`（默认）或 `ad-hoc` |

7. Actions → iOS IPA → Run workflow。完成后在 Releases 下载 `*-signed.ipa`，用 Apple Configurator、Xcode（Devices 窗口拖入）或 `ideviceinstaller` 安装。

### 不配 secrets，直接自签

下载 `*-unsigned.ipa`，用 Sideloadly / ESign / 爱思等工具，配合**开启了 Network Extension + App Groups 能力**的证书和描述文件重签。注意：

- 两个 target 都必须带 `com.apple.developer.networking.networkextension = [packet-tunnel-provider]` 和 `com.apple.security.application-groups`；
- App Group 在运行时自动解析：App 和扩展各自读取包内 `embedded.mobileprovision` 中的 `com.apple.security.application-groups`，按字母序取第一个系统认可的组（都不可用时再回退到 Info.plist 中的值和 `group.com.astemo6.mihomo`），所以保持原 Bundle ID、用任意第三方购买的描述文件重签也能共享配置；隧道扩展 ID 从包内 PlugIns 的 packet-tunnel 扩展读取（回退为 `主程序 ID + .tunnel`），已保存的旧 VPN 配置会自动改指向新 ID；
- 连接失败时首页会弹窗显示原因；更多 → 诊断 显示解析出的 App Group、扩展 ID 和共享容器是否可用；
- 免费 Apple ID 证书不包含 Network Extension 能力，连接会失败。

## 使用

1. 「配置」→ + → 添加订阅链接（或从剪贴板 / 文件导入），保存时会用内核校验。
2. 「首页」打开开关，首次会弹出“添加 VPN 配置”系统提示，允许即可。
3. 「策略」里切换节点；首页左上角会自动刷新出口 IP 与 ASN。

## 重写 / MitM / 脚本 / 模块（v0.2）

入口：更多 → 重写与 MitM。四个页面共用一个「启用重写与脚本」总开关；HTTPS 解密另有独立开关。全部关闭时内核不会加载 HTTP 引擎，不额外占用内存。

### 工作方式

扩展内的 Go 桥接里运行一个本地 HTTP 引擎（127.0.0.1 随机端口）。开启后，启动内核前会向配置注入：

- 出站 `__MITM__`（`type: http` 指向本地引擎，策略页已隐藏）；
- 内联规则集 `__mitm_hosts` / `__mitm_skip`（由 MitM 主机名生成）；
- 置顶规则：MitM 主机的 UDP 443（QUIC）直接拒绝，让 App 回落到 TCP；MitM 主机的 TCP 443（或 `host:port` 指定的端口）交给引擎；有 HTTP 规则时所有 TCP 80 交给引擎；模块里的 REJECT / DIRECT 规则。

引擎解密后按规则处理请求，再通过内核的 inner 通道发出，**仍然按你原来的规则和策略组走代理**（不会因为 MitM 变成直连）。客户端支持 HTTP/1.1 与 HTTP/2（可关），WebSocket 透传。握手失败（证书固定 / 未信任 CA）的主机会自动放行 30 分钟并在日志中提示。注意：全局 / 直连模式下不使用规则，MitM 不生效。

### 安装并信任证书（手机上操作）

1. 更多 → MitM → 生成 CA 证书（ECDSA P-256，10 年；私钥只保存在本机 App Group 容器的 `mihomo/engine/ca/`，不进钥匙串、不上传、不在仓库里）。
2. 点「安装证书（通过 Safari）」，在 Safari 弹窗中选「允许」下载描述文件；也可以用「分享 / 存储描述文件」存到“文件”App 后点开。
3. 设置 → 已下载描述文件（或 通用 → VPN 与设备管理）→ 安装。
4. 设置 → 通用 → 关于本机 → **证书信任设置** → 打开「Mihomo MitM CA xxxxxx」的完全信任。
5. 回到 MitM 页，状态显示「已安装并完全信任」后打开「HTTPS 解密」，添加主机名（或启用带 hostname 的模块）。

可导出 `.cer`、或带密码的 `.p12`（含私钥，用于备份 / 迁移，也可从 p12 导入）。「重新生成证书」后需要重新安装并信任。

### 支持的语法

| 类别 | 支持 |
| --- | --- |
| MitM 主机名 | `hostname = %APPEND% a.com, *.b.com, -c.b.com, d.com:8443`（`*`/`?` 通配、`-` 排除、`:端口`），Surge `skip-server-cert-verify`、`h2` |
| Surge [URL Rewrite] | `正则 替换 302/307/header`，`正则 - reject / reject-200 / reject-img / reject-dict / reject-array / reject-drop`（`reject-tinygif`、`reject-no-drop`、`reject-video` 视为等价项） |
| Surge [Header Rewrite] | `正则 header-add/header-del/header-replace/header-replace-regex …`，以及 `http-request` / `http-response` 前缀的新写法 |
| Surge [Body Rewrite] | `http-request\|http-response 正则 查找1 替换1 查找2 替换2 …`、`http-response-jq 正则 'jq 表达式'`（gojq，支持 `jq-path=`） |
| Surge [Map Local] | `正则 data="…" data-type=text\|base64\|tiny-gif\|json\|file header="A:b\|C:d" status-code=200`（data 可为 URL / 本地文件 / 内联文本） |
| Surge [Script] | `名称 = type=http-request\|http-response,pattern=…,requires-body=1,max-size=…,binary-body-mode=1,script-path=URL或本地文件,argument=…,timeout=…,script-update-interval=…` |
| Surge [Rule]（模块） | `DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-WILDCARD / IP-CIDR(6) / GEOIP / IP-ASN / DST-PORT`，仅 REJECT* / DIRECT 策略；`URL-REGEX,…,REJECT*` 转为 URL 重写 |
| Surge 模块 | `#!name`、`#!desc`、`#!arguments=键:默认值,…` + `{{{键}}}` 替换（可在模块详情里改参数）、`#!arguments-desc` |
| Quantumult X | `正则 url reject/reject-200/reject-img/reject-dict/reject-array/302/307`、`request-header`/`response-header`（整段头部正则）、`request-body`/`response-body`、`script-request-header/-body`、`script-response-header/-body`、`script-echo-response`、`script-analyze-echo-response`、`echo-response`；`[rewrite_local]`、`[mitm]`、`[filter_local]`（host/host-suffix/host-keyword/ip-cidr 的 reject/direct）及无分段的重写片段 |
| Loon 插件 | `[Rewrite]` 的 `正则 reject*/302/307 目标`、`header-*`、`response-body-json-del/replace/add`、`response-body-replace-regex`、`mock-response-body`；`[Script]` 的 `http-request\|http-response 正则 script-path=…, requires-body=true, tag=…, argument=…` |
| Stash 覆写 | `http.mitm`、`http.rewrite` / `url-rewrite` / `header-rewrite` / `body-rewrite`、`http.script` + `script-providers` |

正则使用 regexp2（兼容 JavaScript 写法，支持前后向断言），匹配完整 URL。URL 重写与本地映射首条命中生效；头部、内容和脚本按顺序全部执行。需要处理内容时会把上游编码限制为 gzip/deflate/br 并自动解压。

### 脚本 API（goja 纯 Go 引擎，ES2015+，支持 async/await）

- Surge：`$request`（url、method、headers 大小写不敏感、body）、`$response`（status、headers、body）、`$done()`（请求阶段可改 url/method/headers/body，或 `{response:{status,headers,body}}` 直接返回；响应阶段可改 status/headers/body）、`$httpClient.get/post/put/delete/head/options/patch`（经内核发出，支持 `policy`、`binary-mode`、`insecure`、`auto-redirect`、`timeout`）、`$persistentStore.read/write`（存于 App Group，可在 脚本 → 持久化存储 查看编辑）、`$notification.post`（由扩展发本地通知，需在脚本页允许通知）、`$script`、`$environment`（声明为 Surge）、`$argument`、`console.*`、`setTimeout/setInterval`。
- Quantumult X：`$task.fetch`（Promise，支持 `opts.policy`）、`$prefs.valueForKey/setValueForKey/removeValueForKey/removeAllValues`、`$notify`，`$done({status:"HTTP/1.1 200 OK", …})`、`bodyBytes`。
- 二进制：`binary-body-mode` 时 body 为 `Uint8Array`（并提供 `bodyBytes`），`$done` 接受字符串 / Uint8Array / ArrayBuffer；另有 `TextEncoder`/`TextDecoder`、`atob`/`btoa`。
- 资源限制：每次执行使用独立运行时（编译结果缓存 16 个），同时最多 2 个脚本，默认超时 10 秒（超时则保持原样），需要 body 的规则缓冲上限 2 MB（`max-size` 可更小）。远程脚本经内核下载并缓存，按 `script-update-interval`（默认 1 天）后台更新。
- 定时 / 事件 / 通用脚本、`$utils`、面板见上方「v0.4 要点」。暂不支持：Surge `type=dns` / `type=rule` 脚本、`$httpAPI`、Egern 模块格式。

## 已知限制

- 网络扩展内存上限约 50 MB。大型 `GEOSITE` 规则、超大订阅或大量规则集会增加内存，建议优先使用 `.mrs` 规则集。
- 二进制体积：内核是一个 Go 静态库（构建已用 `-s -w -trimpath`，Release 再 strip），扩展可执行文件约 73 MB。磁盘体积不等于内存占用（代码页按需映射），但主 App 也链接了同一个库（用于校验 / 离线解析），所以 IPA 较大。
- 仅代理模式：不遵守系统代理的 App 与所有 UDP / QUIC 会直连；按 IP 的规则与 Fake-IP 不生效。
- iCloud 备份需要签名里有 iCloud 容器权限；没有时可在「保存到文件」时选 iCloud 云盘。
- MitM：HTTP/3（QUIC）无法解密，已对 MitM 主机阻断 UDP 443；证书固定的 App 会握手失败并被自动放行。
- QX `filter_remote` 没写 `force-policy` 时整份列表走 proxy（第一个手动选择组），列表内各行的策略被忽略。

## 许可与致谢

GPL-3.0。mihomo © MetaCubeX 及贡献者。PacketFlowBridge 与内存守护参考了 [TokenPLS/Hako](https://github.com/ProjectClash/Clash-Legacy) 与 [Hako-Adapter](https://github.com/ProjectClash/Clash-Adapter-Legacy)（现由 [ProjectClash](https://github.com/ProjectClash) 维护，均为 GPL-3.0）的设计，详见 `NOTICE` 与 App 内 更多 → 关于。
