# Mihomo iOS（v0.2.1）

基于开源 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）内核的个人 iOS 代理客户端，界面参考 Quantumult X / Surge / Egern：深色优先、卡片式。

> 本项目以 **GPL-3.0** 发布（见 `LICENSE`），与 mihomo 内核许可一致。仓库里没有任何节点、证书或密钥。

## 功能

| 模块 | 内容 |
| --- | --- |
| 首页 | **左上角 IP / ASN 卡片**（出口 IP、国旗 + 国家/城市、ASN + 运营商；连接时第二行显示直连 IP）；轻点刷新、长按复制；连接 / 断开、切换节点、切换模式后自动刷新。大号连接开关、规则/全局/直连模式切换、当前配置与节点、实时上下行速度 + 曲线、总流量、内核内存、连接数 |
| 策略 | Egern 风格策略组卡片、节点网格、延迟着色、点选切换（select 组）、组测速、url-test / fallback / load-balance 状态 |
| 请求 | 实时连接列表（主机、规则、策略链、上下行、时长）、最近已关闭请求、搜索、单个 / 全部断开；经过 MitM 的连接带「MitM」标记并显示命中的规则 / 脚本；「HTTP」页签列出解密后的请求，可查看请求 / 响应头与内容（各最多 32 KB）|
| 配置 | 订阅链接（User-Agent `clash.meta` / `mihomo`、自动更新间隔、解析 `subscription-userinfo` 显示已用 / 总量 / 到期）、剪贴板导入、文件导入、本地 YAML 编辑器、全部更新、切换配置、保存前用真实内核校验；分享链接 / base64 订阅 / Surge·Egern·QX 节点行自动转换为 mihomo 配置 |
| 手动节点 | Shadowrocket 式添加单个节点：剪贴板粘贴、相机扫码、相册识别二维码、按协议填写的表单；节点存入本地「手动节点」配置（同名策略组）|
| 重写 / MitM（v0.2）| HTTPS 解密（自建 CA）、URL 重写、请求/响应头与内容改写、本地映射、JS 脚本、模块；兼容 Surge / Quantumult X / Loon / Stash 的常见写法，详见下文 |
| 更多 | 规则查看器、规则集 / 节点集提供者（含更新按钮）、日志（级别过滤、搜索、暂停、复制）、内核覆写设置、关于 / GPL 许可 |
| 即将推出 | 小组件、控制中心开关、快捷指令、cron 定时脚本 |

## v0.2.1 热修复（启动卡在「连接中…」）

- **内置地理数据库**：`Geo/` 下打包 MetaCubeX/meta-rules-dat 的 `geoip.metadb`（8.4 MB）、`GeoSite.dat`（4.3 MB）、`ASN.mmdb`（GeoLite2-ASN，9.0 MB），随扩展一起安装；启动前若内核目录里缺失（或文件小于 64 KB，视为下载中断）就复制进去，启动时无需下载。
- **国内可达的镜像**：强制 `geox-url` 指向 `https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/…`，`geodata-mode: false`（使用 mmdb）、`geodata-loader: memconservative`、`geo-auto-update: false`；`raw.githubusercontent.com` / `github.com/…/raw|blob/…` 上的规则集、节点集（未指定 `proxy:` 的）自动改走 jsDelivr 镜像。
- **启动不再被网络卡住**：内核在后台线程启动，最多等 20 秒；tun 一建立就返回成功，规则集 / 节点集在后台继续加载（加载完成前内核只放行内部请求）。超时会返回中文错误；扩展另有 30 秒看门狗，系统不会一直停在「连接中…」。
- **启动日志**：每次连接写 `startup-log.txt`（App Group 容器，保留上一次），记录网络设置、utun fd、内核开始 / 结束、`phys_footprint` 内存与 Go 堆、错误。更多 → 内核覆写设置 → 诊断 → 启动日志，可一键复制。

## 架构

```
┌────────────── 主 App（SwiftUI，iOS 16+）──────────────┐
│ NETunnelProviderManager 启停隧道                       │
│ ControllerClient ──HTTP/WebSocket──► 127.0.0.1:9090     │
│ ProfileStore：配置存放在 App Group 容器                 │
│ Libmihomo（仅用于配置校验 / 分享链接转换）              │
└──────────────────────────────┬─────────────────────────┘
                               │ App Group: group.com.astemo6.mihomo
┌──────────── PacketTunnel 扩展（NEPacketTunnelProvider）┐
│ 设置 198.18.0.1/16、默认路由、DNS 198.18.0.2            │
│ 扫描 fd 0…1024，getsockopt(UTUN_OPT_IFNAME) 找到 utun   │
│ LibmihomoStart(home, profile, fd)                       │
│   └─ mihomo：tun.file-descriptor + gVisor 栈 + fake-ip  │
│      external-controller 127.0.0.1:<port> + 随机密钥    │
└────────────────────────────────────────────────────────┘
```

- `bridge/mitm/`：HTTP 引擎（MitM / 重写 / 脚本 / 模块解析 / CA），通过 `hub/route.Register` 在控制器上挂 `/mitm/status|requests|hosts|logs` 供 App 读取。
- `bridge/`：Go 包 `libmihomo`，`gomobile bind -target=ios/arm64 -tags with_gvisor` 生成 `Frameworks/Libmihomo.xcframework`。API：`Start / Stop / Reload / ValidateConfig / ValidateConfigIn / ConvertShareLinks / Version / FreeMemory / SetMemoryLimit`。启动时把用户配置与 `overrides.json`（设置页的覆写项）合并为 `runtime.yaml`，强制 tun fd、仅本地监听的控制器、`find-process-mode: off`、`geodata-loader: memconservative`，Go 内存软上限 40 MB + 激进 GC。
- `PacketTunnel/`：网络扩展。`handleAppMessage` 支持 `reload`（重载配置）、`directIP`（扩展自身的请求不走隧道，用来查直连 IP）、`freeMemory`、`version`。
- `App/`：SwiftUI 主程序。`Shared/`：两个 target 共用（App Group 路径、覆写项、IP 查询）。
- IP 查询端点（依次回退，解析宽松）：ipinfo.io → ip-api.com → api.ip.sb → ipapi.co → ipwho.is。
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

`.github/workflows/ios.yml`（push 到 main 或手动运行）：setup-go → gomobile 构建 xcframework（按 bridge 源码与内核版本缓存）→ XcodeGen → `xcodebuild archive` → IPA → 上传 Artifact，并发布 GitHub Release（tag `v0.1.0-build<N>`）。

- **没有签名 secrets**：`CODE_SIGNING_ALLOWED=NO` 构建，然后用 `codesign -s -`（伪签名）把 entitlements 写进 App 和扩展，打包为 `Mihomo-0.1.0-build<N>-unsigned.ipa`。Release 中同时附带 `app.entitlements` / `tunnel.entitlements`，方便重签工具使用。
- **有签名 secrets**：导入证书和两个描述文件，导出 `Mihomo-0.1.0-build<N>-signed.ipa`。

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
- 连接失败时首页会弹窗显示原因；更多 → 内核覆写设置 → 诊断 显示解析出的 App Group、扩展 ID 和共享容器是否可用；
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
- 暂不支持：cron / generic / event 脚本、`$utils`、Surge Panel、Egern 模块格式。

## 已知限制

- 网络扩展内存上限约 50 MB。大型 `GEOSITE` 规则、超大订阅或大量规则集会增加内存，建议优先使用 `.mrs` 规则集；首页显示内核内存。
- utun fd 通过扫描 fd + `getsockopt(UTUN_OPT_IFNAME)` 获取，这是社区通用做法（sing-box / Hiddify），并非 Apple 公开 API。
- 首次使用 GEOIP / GEOSITE 规则时内核会下载地理数据库。
- MitM：HTTP/3（QUIC）无法解密，已对 MitM 主机阻断 UDP 443；证书固定的 App 会握手失败并被自动放行；HTTP 引擎、goja 与 gojq 让 Libmihomo 体积变大，但只有启用时才分配内存。

## 许可

GPL-3.0。mihomo © MetaCubeX 及贡献者。
