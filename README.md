# Mihomo iOS（v0.1）

基于开源 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）内核的个人 iOS 代理客户端，界面参考 Quantumult X / Surge / Egern：深色优先、卡片式。

> 本项目以 **GPL-3.0** 发布（见 `LICENSE`），与 mihomo 内核许可一致。仓库里没有任何节点、证书或密钥。

## 功能（v0.1）

| 模块 | 内容 |
| --- | --- |
| 首页 | **左上角 IP / ASN 卡片**（出口 IP、国旗 + 国家/城市、ASN + 运营商；连接时第二行显示直连 IP）；轻点刷新、长按复制；连接 / 断开、切换节点、切换模式后自动刷新。大号连接开关、规则/全局/直连模式切换、当前配置与节点、实时上下行速度 + 曲线、总流量、内核内存、连接数 |
| 策略 | Egern 风格策略组卡片、节点网格、延迟着色、点选切换（select 组）、组测速、url-test / fallback / load-balance 状态 |
| 请求 | 实时连接列表（主机、规则、策略链、上下行、时长）、最近已关闭请求、搜索、单个 / 全部断开 |
| 配置 | 订阅链接（User-Agent `clash.meta` / `mihomo`、自动更新间隔、解析 `subscription-userinfo` 显示已用 / 总量 / 到期）、剪贴板导入、文件导入、本地 YAML 编辑器、全部更新、切换配置、保存前用真实内核校验；分享链接 / base64 订阅 / Surge·Egern·QX 节点行自动转换为 mihomo 配置 |
| 手动节点 | Shadowrocket 式添加单个节点：剪贴板粘贴、相机扫码、相册识别二维码、按协议填写的表单；节点存入本地「手动节点」配置（同名策略组）|
| 更多 | 规则查看器、规则集 / 节点集提供者（含更新按钮）、日志（级别过滤、搜索、暂停、复制）、内核覆写设置、关于 / GPL 许可 |
| 即将推出 | 重写 / MitM、脚本、模块、小组件、控制中心开关、快捷指令 |

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
- 重签工具若修改了 Bundle ID，App Group 也必须一起改成描述文件里的组，否则 App 与扩展无法共享配置；
- 免费 Apple ID 证书不包含 Network Extension 能力，连接会失败。

## 使用

1. 「配置」→ + → 添加订阅链接（或从剪贴板 / 文件导入），保存时会用内核校验。
2. 「首页」打开开关，首次会弹出“添加 VPN 配置”系统提示，允许即可。
3. 「策略」里切换节点；首页左上角会自动刷新出口 IP 与 ASN。

## 已知限制

- 网络扩展内存上限约 50 MB。大型 `GEOSITE` 规则、超大订阅或大量规则集会增加内存，建议优先使用 `.mrs` 规则集；首页显示内核内存。
- utun fd 通过扫描 fd + `getsockopt(UTUN_OPT_IFNAME)` 获取，这是社区通用做法（sing-box / Hiddify），并非 Apple 公开 API。
- 首次使用 GEOIP / GEOSITE 规则时内核会下载地理数据库。

## 许可

GPL-3.0。mihomo © MetaCubeX 及贡献者。
