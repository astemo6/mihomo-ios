# Tern（mihomo 内核的 iOS 客户端，原名 Mihomo iOS）

基于开源 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）内核的个人 iOS 代理客户端：卡片界面（深色 / 浅色），五个标签页——首页、策略、请求、工具、更多；首页只放最常用的东西，功能页在「工具」，设置在「更多」，进阶选项收在「更多 → 高级设置」。

> 本项目以 **GPL-3.0** 发布（见 `LICENSE` 与 `NOTICE`），与 mihomo 内核许可一致。仓库里没有任何节点、证书或密钥。

## 设计原则

1. **一个内部模型**：所有东西最终都是「mihomo 配置 + 我们自己的覆写 / 模块存储」。Surge、Quantumult X、Loon、Stash、Egern 的格式只在导入边缘做一次翻译（每种格式一个解析器），之后就是普通的 mihomo 配置或模块，不存在第二套运行逻辑。
2. **一种设计语言**：项目自己的深色卡片（`Theme` / `Card`），新页面不照搬其他客户端的布局。
3. **首页极简**：连接开关、出站模式、IP 卡片、流量和可选的首页面板。功能页是「工具」里的卡片（节点与订阅、规则、模块、重写、脚本、任务、HTTPS 解密、DNS、日志、网络工具）；「更多」放配置、统计、备份和 App 设置，连接方式 / 内核 / 测速等进阶项在「更多 → 高级设置」。
4. **模块只有一个入口**：所有格式的模块和远程资源（规则集、脚本）都在「工具 → 模块」，用角标标出来源格式。
5. **宁缺毋滥**：做不精的功能先不做（共享动态内核库只作为单独的 `-sharedcore` 测试 IPA 提供；资源解析器只保存地址、不运行；小组件、控制中心开关和实时活动作为单独的 `-widget` IPA 提供）。
6. **规则、重写、脚本都接受 Surge 与 Quantumult X 写法**（以及 Loon、Stash、Egern），只在边缘翻译一次。

## 功能

| 位置 | 内容 |
| --- | --- |
| 首页 | 连接开关、规则 / 全局 / 直连、IP / ASN 卡片（出口 + 直连，副标题可选）、当前配置与节点、实时速度曲线、本次上传 / 下载（全部流量或仅代理流量）；**首页面板**（内置卡片：网速、流量、连接时长、出口 IP、内网 IP、内存、解锁结果；模块 `[Panel]` / Stash `tiles` 与脚本任务也可固定；「编辑首页面板」拖动排序）；分析卡片（策略 / 规则 / 主机名，可选） |
| 策略 | 已连接：实时策略组、点选切换、组测速；长按策略组：测速、置顶、换图标、编辑；拖动或「编辑排序」调整策略组顺序；自动 / 故障转移组可开「智能选择」；任意策略组可设**前置代理**并显示策略链。**未连接：「未连接 · 来自配置文件」离线策略页**——读取当前配置（含节点集缓存、合并的手动节点），可以选节点（按配置保存，下次连接时自动应用）、直接测速 |
| 请求 | 实时连接、最近关闭、MitM 解密的 HTTP 请求（头部 / 内容查看、**复制为 cURL、重放、编辑后重放**、导出 HAR）、请求时间线 |
| 工具 → 节点与订阅 | 配置订阅与节点订阅分开管理：流量 / 到期（`subscription-userinfo`）、左右滑（更新、复制链接）、长按（编辑、停用、图标、节点处理、删除）；全部节点、手动节点（添加 / 编辑 / 分享 / 凭据查看）、节点集（停用 / 删除 / 编辑）、筛选节点（按地区 / 关键词生成策略组）、离线测速 |
| 工具 → 分流规则 | 规则（实时或离线，命中计数）+ **自定义规则**（Surge / QX / Loon / mihomo 写法，表单或文本模式，实时校验并显示转换结果与策略组；远程 RULE-SET / DOMAIN-SET / QX filter_remote；拖动排序） |
| 工具 → 模块 / 重写 / 脚本 / 定时任务 / HTTPS 解密 | **模块**（全部格式一个入口，格式角标；远程规则集 / 重写集 / 脚本各自的更新间隔、开关、错误、全部更新；一键添加 BoxJS；**模块库**浏览 / 搜索 / 预览；Loon `[Argument]` 参数；**策略映射**）、**本地模块**（重写规则 + MitM 主机名：表单编辑、拖动排序、文本模式）、**脚本调试台**、定时（cron）与通用脚本任务、HTTPS 解密（CA 证书、主机名、QUIC 选项） |
| 工具 → DNS / 日志 / 网络 | DNS（国内 / 国外分流、引导 DNS、nameserver-policy、Fake-IP 过滤、本地映射）、运行日志、DNS 日志、连接分析（按天保存）、网络工具（Ping / TCP / DNS，经过内核规则并显示策略链）、网速测试（带宽 / NAT 类型）、**解锁检测**（按策略 / 节点）、内网 IP 与路由器 |
| 更多 | 配置（**配置编辑器**：YAML 高亮、内核实时校验并标出错误行列；订阅配置只读，可「复制为本地配置」；**节点处理**：过滤、重命名、旗帜、去重、排序 + 实时预览；**覆写脚本**；订阅 / 本地 YAML / 剪贴板 / 文件；**Surge / Quantumult X / Loon / Clash `.conf` 导入**先显示转换报告）、流量统计（Swift Charts，按天保存约 120 天）、配置快照、**备份与恢复**（文件 / 分享 / iCloud、WebDAV 多版本可加密、iCloud 云盘同步文件夹）、更新资源、存储空间、深色与浅色、App 图标、开始标签页、首页流量统计范围、新手引导、诊断与反馈（**一键导出诊断包**、App Group 与候选组、扩展 ID、启动日志、隧道内存）、关于 |
| 更多 → 高级设置 | 连接方式（全局隧道 / 混合 / 仅代理、路由、跳过代理、阻止 QUIC、阻止 WebRTC、IPv6、**局域网共享**与多用户、按需连接：始终 / 仅 Wi-Fi / 仅蜂窝，App 内手动断开会暂停按需连接）、隧道（包含所有网络 / 本地网络 / APNs / 蜂窝网络服务 / 设备通信、兼容性增强模式、FaceTime 走代理）、地理数据库（GeoIP MMDB、GEOIP dat、GEOSITE、GeoLite2-ASN：状态、默认 / 自定义地址、国内镜像、下载进度与错误）、内核设置（内存上限、隧道 MTU、手动节点合并进每个配置、日志、控制器、切换节点时断开连接、网络变化时清空 DNS 缓存）、测速设置、出口信息来源 |
| 快捷指令 | 连接、断开、切换连接、切换出站模式、切换节点、**查询状态、切换配置、开关模块、更新订阅、运行脚本**（App Intents）；主屏幕长按图标：连接 / 断开、规则 / 全局 / 直连 |
| 导入链接 | 只注册自己的 `mihomo://`（`mihomo://install-config?url=`、`install-module?url=`、`connect`、`disconnect`、`toggle`）。粘贴的 `loon://`、`stash://`、`surge:///`、`quantumult-x:///`、`egern:/` 安装链接也能识别，但**不注册**这些 scheme，避免与其他客户端抢链接。可以用「文件」/其他 App 的「用 Tern 打开」打开 `.sgmodule` `.plugin` `.stoverride` `.module` `.snippet` `.conf` `.list` `.yaml` 和纯文本 |
| 小组件 / 实时活动（`-widget` IPA） | 主屏幕 / 锁屏小组件、控制中心开关、灵动岛与锁屏实时活动（速度、节点、累计流量） |
| iPad | 横向宽度为常规时用侧边栏（NavigationSplitView）显示五个分区，支持横竖屏与分屏；iPhone 保持底部标签栏 |

## 更新日志

各版本改动见 [CHANGELOG.md](CHANGELOG.md)，安装包见 [GitHub Releases](https://github.com/astemo6/mihomo-ios/releases)。

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
- 设置文件（App Group 容器 `mihomo/`）：`subscriptions.json`（每个订阅的节点处理规则）、`overrides.json`（内核覆写，含 `tunnelMode` `mixedPort` `tunMTU` `geoMirror` `geoURLs` `mergeManual`，解码容错；不含任何密钥）、`secrets.json`（控制器密钥与局域网共享密码，0600，只进加密备份）、`dns.json`、`rules.json`、`engine/`（MitM / 重写 / 脚本 / 模块）；每个配置旁的 `<id>.selected.json` 保存离线选择的节点。
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

- **没有签名 secrets**：`CODE_SIGNING_ALLOWED=NO` 构建，然后用 `codesign -s -`（伪签名）把 entitlements 写进 App 和扩展，打包为 `Mihomo-<版本>-build<N>-widget-unsigned.ipa`（v0.19 前另有不含小组件的 `-unsigned.ipa`）。Release 中同时附带 `app.entitlements` / `tunnel.entitlements`，方便重签工具使用。
- **有签名 secrets**：导入证书和两个描述文件，导出 `Mihomo-<版本>-build<N>-signed.ipa`。

`.github/workflows/ui-tests.yml`（Self-test，push 到 `test/**` 或手动运行）：Go 测试（含 `-race`）+ 模拟器 UI / 单元测试，不发布。UI 部分先由 `plan` job 选路径：

- **冒烟（smoke）**：分支相对 `origin/main` 的 merge-base（分支就在 main 上时，相对最近的发布标签 `v*-build*`）没有改动任何影响界面或文案的文件时，只跑一个组合（zh-Hans 浅色）：`test01_TabsAndHome`、`test03_MoreEveryPage`、`test04_NodeManager` + 全部 `MihomoUnitTests`；App 与测试包照常完整编译。
- **完整（full）**：改到 `App/**`、`Shared/**`、`Widget/**`、`UITests/**`、`project-uitests.yml`、任意 `*.xcstrings` / `*.strings` / `*.lproj` / `*.xcassets`，或 `project.yml` 里涉及 App/Shared/Widget 路径、字符串目录、资源、Info.plist、产品名、图标的行时，按原来的矩阵跑。
- 提交信息标记：`[shard:all]` 本仓库跑全部 8 个组合；`[shard:smoke]` 强制冒烟；`[shard:full]` 强制完整矩阵；`[only:<测试>]` / `[unit:<类>]` 只跑指定测试；`[skip-go]` / `[skip-ui]` 跳过 Go / UI。手动运行的 `shard` 输入对应 auto / full / smoke / all。完整规则见该 workflow 文件头部注释。

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
- App Group 在运行时自动解析：App、扩展和小组件各自读取包内 `embedded.mobileprovision` 中的 `com.apple.security.application-groups`；第一次按字母序取第一个系统认可的组（都不可用时再回退到 Info.plist 中的值和 `group.com.astemo6.mihomo`）并记住，之后优先用记住的组，其次是已有配置的组，描述文件续期后组列表变了也不会换到空容器，所以保持原 Bundle ID、用任意第三方购买的描述文件重签也能共享配置；隧道扩展 ID 从包内 PlugIns 的 packet-tunnel 扩展读取（回退为 `主程序 ID + .tunnel`），已保存的旧 VPN 配置会自动改指向新 ID；
- 连接失败时首页会弹窗显示原因；更多 → 诊断与反馈 显示解析出的 App Group、候选组、扩展 ID 和共享容器是否可用，组可能不对时会给出提示；
- 免费 Apple ID 证书不包含 Network Extension 能力，连接会失败。

## 使用

1. 「工具 → 节点与订阅」→ + → 添加配置订阅（或在「更多 → 配置」从剪贴板 / 文件导入），保存时会用内核校验。
2. 「首页」打开开关，首次会弹出“添加 VPN 配置”系统提示，允许即可。
3. 「策略」里切换节点；首页左上角会自动刷新出口 IP 与 ASN。

## 重写 / MitM / 脚本 / 模块（v0.2）

入口：工具 → 模块 / 重写 / 脚本 / HTTPS 解密（v0.7 起「重写」即「本地模块」，可用表单编辑）。这些页面共用一个「启用重写与脚本」总开关；HTTPS 解密另有独立开关。全部关闭时内核不会加载 HTTP 引擎，不额外占用内存。

### 工作方式

扩展内的 Go 桥接里运行一个本地 HTTP 引擎（127.0.0.1 随机端口）。开启后，启动内核前会向配置注入：

- 出站 `__MITM__`（`type: http` 指向本地引擎，策略页已隐藏）；
- 内联规则集 `__mitm_hosts` / `__mitm_skip`（由 MitM 主机名生成）；
- 置顶规则：MitM 主机的 UDP 443（QUIC）直接拒绝，让 App 回落到 TCP；MitM 主机的 TCP 443（或 `host:port` 指定的端口）交给引擎；有 HTTP 规则时所有 TCP 80 交给引擎；模块里的 REJECT / DIRECT 规则。

引擎解密后按规则处理请求，再通过内核的 inner 通道发出，**仍然按你原来的规则和策略组走代理**（不会因为 MitM 变成直连）。客户端支持 HTTP/1.1 与 HTTP/2（可关），WebSocket 透传。握手失败（证书固定 / 未信任 CA）的主机会自动放行 30 分钟并在日志中提示。注意：全局 / 直连模式下不使用规则，MitM 不生效。

### 安装并信任证书（手机上操作）

1. 工具 → HTTPS 解密 → 生成 CA 证书（ECDSA P-256，10 年；私钥只保存在本机 App Group 容器的 `mihomo/engine/ca/`，不进钥匙串、不上传、不在仓库里）。
2. 点「安装证书（通过 Safari）」，在 Safari 弹窗中选「允许」下载描述文件；也可以用「分享 / 存储描述文件」存到“文件”App 后点开。
3. 设置 → 已下载描述文件（或 通用 → VPN 与设备管理）→ 安装。
4. 设置 → 通用 → 关于本机 → **证书信任设置** → 打开「Mihomo MitM CA xxxxxx」的完全信任。
5. 回到 HTTPS 解密页，状态显示「已安装并完全信任」后打开「HTTPS 解密」，添加主机名（或启用带 hostname 的模块）。

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
- 定时 / 事件 / 通用脚本、`$utils`、面板见「v0.4 要点」；Egern 模块与 `$httpAPI` 见「v0.5 要点」。暂不支持：Surge `type=dns` / `type=rule` 脚本。Egern 原生 `ctx` 脚本见「v0.6 要点」。

## 已知限制

- 网络扩展内存上限约 50 MB。大型 `GEOSITE` 规则、超大订阅或大量规则集会增加内存，建议优先使用 `.mrs` 规则集。
- 二进制体积：内核是一个 Go 静态库（构建已用 `-s -w -trimpath`，Release 再 strip），扩展可执行文件约 73 MB。磁盘体积不等于内存占用（代码页按需映射），但主 App 也链接了同一个库（用于校验 / 离线解析），所以 IPA 较大。
- 仅代理模式：不遵守系统代理的 App 与所有 UDP / QUIC 会直连；按 IP 的规则与 Fake-IP 不生效。
- iCloud 备份需要签名里有 iCloud 容器权限；没有时可在「保存到文件」时选 iCloud 云盘。
- MitM：HTTP/3（QUIC）无法解密，默认对 MitM 主机阻断 UDP 443（可按主机放行，或选择全部阻断）；证书固定的 App 会握手失败并被自动放行。
- QX `filter_remote` 没写 `force-policy` 时整份列表走 proxy（第一个手动选择组），列表内各行的策略被忽略。

## 许可与致谢

GPL-3.0。mihomo © MetaCubeX 及贡献者。PacketFlowBridge 与内存守护参考了 [TokenPLS/Hako](https://github.com/ProjectClash/Clash-Legacy) 与 [Hako-Adapter](https://github.com/ProjectClash/Clash-Adapter-Legacy)（现由 [ProjectClash](https://github.com/ProjectClash) 维护，均为 GPL-3.0）的设计，详见 `NOTICE` 与 App 内 更多 → 关于。
