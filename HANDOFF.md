# Mihomo for Android — 暂停交接 (HANDOFF)

**状态：已暂停（HOLD）**，用户 2026-10-17 10:53 CST：「先优先跑原先的跟ios qx，android qx暂时hold」。

2026-10-17 下午：按派发指示恢复本地开发（A1 收尾 + A2 模块/重写/MitM/脚本），只本地提交、未推送。
Mihomo for Android 是用户 iOS 客户端（astemo6/mihomo-ios）的 Android 版本，界面沿用 QX 风格重做的设计。

- 分支：这个仓库目前作为 **astemo6/mihomo-ios 上的孤立分支 `android/main`** 推送（与 iOS 历史无关）。等新仓库 astemo6/mihomo-android 建好后，直接 `git push <new> android/main:main` 即可迁移。
- 本地工作目录：`/workspace/projects/7d77dd5e-b695-4cf0-bbd5-6be0ce900744/android`（独立 git 仓库，分支 main）。
- 这个分支上**已有 CI workflow `.github/workflows/android.yml`**（2026-10-17 加入）：**push 到 `android/**` 会触发 Actions 并发布 prerelease** `android-v0.1.0-buildN`。它不碰 iOS 的 workflow：iOS 的 `ios.yml` 只在 push 到 main 时触发，`core-update.yml` 只按定时或手动触发，而且这两个文件都不在这个分支上。

## 目前已有的内容

- `core/` 是 iOS Go bridge 的副本（mihomo-ios main **72b1132**，v0.9.0），模块路径改成了 `github.com/astemo6/mihomo-android/core`，内核版本与 iOS 一致，为 **mihomo v1.19.32**。
  - Android 改动只在 `core/platform*.go` 里：
    - `platformTun`：用 VpnService 的 fd 替换 iOS 的 socketpair 配置。去掉 recvmsgx/sendmsgx；MTU 设为 9000；协议栈可选 gvisor（默认）/system/mixed；dns-hijack 设为 any:53 + tcp；fake-ip-range 固定为 198.18.0.1/16，因此 tun 地址是 198.18.0.1/30，DNS 用 198.18.0.2。
    - `platformMemoryLimit`：内存上限为 192 MB（iOS 是 26 MB）。
    - `SetSocketProtector`（gomobile 接口 `Protect(fd int32) bool`，内部调用 `dialer.DefaultSocketHook`，做法同 CMFA）。
    - `SetTunStack`。
    - 测试：`platform_android_test.go`。
  - `bridge.go` 里只插了两行 hook 调用，由 `scripts/sync-core.sh <mihomo-ios checkout>` 负责插入。这个脚本可以重新同步 core 并重新打上 hook；hook 打不上时会直接报错。
- `LICENSE`（GPL-3.0）和 `NOTICE`（mihomo、iOS bridge、CMFA、FlClash 的署名）。`.gitignore` 排除了 keystore、AAR、APK 和 qx-frames。
- **Android 应用代码（2026-10-17，A0 + A1 初版）**：Gradle 工程（`settings.gradle.kts`、`app/`、wrapper 8.11.1、版本目录 `gradle/libs.versions.toml`），Kotlin/Compose 源码在 `app/src/main/java/io/github/astemo6/mihomo/`：
  - `core/Core.kt`：gomobile 绑定的封装。core 的 Go 包名是 `libmihomo`，所以 Java 类是 `libmihomo.Libmihomo`（Go `int`→`long`，`int32`→`int`，`error`→抛异常）；接口 `libmihomo.SocketProtector`、`libmihomo.Notifier`。
  - `data/`：`Overrides`（`filesDir/core/overrides.json`，字段与默认值同 iOS CoreOverrides；Android 额外生成随机 controller secret）、`ProfileStore`（`filesDir/profiles.json` + `profiles/<id>.yaml`）、`ImportRouter`、`AppSettings`（主题、分应用、协议栈等 Android 专属设置，存 SharedPreferences，不进 overrides.json）。
  - `api/`：external-controller REST + websocket（OkHttp）、出口 IP 查询。
  - `vpn/`：`MihomoVpnService`、`VpnController`、`VpnState`、`MihomoTileService`；`widget/StatusWidget`（RemoteViews）。
  - `ui/`：MainActivity（自带简单导航栈）、MainViewModel、home 面板、profiles、settings。
  - 字符串：`res/values`（简体，默认）、`values-b+zh+Hant`、`values-en`。
- **本地编译验证（2026-10-17）**：沙箱装了 OpenJDK 21 + Android SDK（platform 35 / build-tools 34），aapt2 用 qemu-x86_64 跑（`android.aapt2FromMavenOverride`），`libmihomo.aar` 用手写的 Java 存根代替（只为编译，签名按 gomobile 规则推断）。`:app:compileDebugKotlin` 和 `:app:assembleDebug` **通过**；`assembleRelease`（R8）在沙箱里内存不足被 OOM 杀掉，**未验证**，交给 CI。真实 AAR 和设备运行都**未验证**。本地构建目录在 `work/.android-build/`（不在仓库里）。
- **本地验证情况**：在沙箱里启动了 `GOOS=android go build`、`go vet` 和 `go test`，暂停前**还没出结果**。所以 core 的改动未经编译验证，恢复后第一件事就是跑这三项。
- 沙箱是 aarch64，而 Android SDK 的 aapt2 和 NDK 只有 x86_64 版本：AAR 和正式 APK 只能靠 CI 构建；本地只能用 qemu 跑 aapt2 做编译检查（见上）。

## 恢复步骤

1. 用 `scripts/sync-core.sh` 从 iOS 最新的 main 重新同步 core。然后运行 `go vet -tags with_gvisor ./...` 和 `go test ./...`，再用 `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...` 编译一遍。
2. 搭 Gradle 工程：AGP 8.7.x、Gradle 8.11.1、Kotlin 2.1 + Compose BOM、minSdk 26、targetSdk 35、JDK 17，applicationId 定为 `io.github.astemo6.mihomo`（暂定）。
3. 在 `.github/workflows/android.yml` 里配置 CI：
   - 触发条件：`push: branches: ['android/**']` 和 `workflow_dispatch`。
   - 用 setup-go 读取 `core/go.mod`，用 `gomobile bind -target=android/arm64,android/amd64 -androidapi 26 -tags with_gvisor` 生成 `app/libs/libmihomo.aar`，按 core 的哈希缓存。
   - 用 `gradle assembleRelease` 打包，并按 ABI 拆分输出 universal 和 arm64-v8a 两个 APK。
   - 签名用 CI 里临时生成的 keystore（不提交）。以后如果需要固定签名，先问用户，再放进 Secrets。
   - 发布 prerelease：tag 为 `android-v0.1.0-buildN`，标题为 “Android 预览 v0.1.0 (buildN)”，附件为 `Mihomo-Android-0.1.0-buildN-universal.apk` 和 `-arm64-v8a.apk`。iOS 的 tag 是 `v*-buildN`，这里加 `android-` 前缀，两者不会冲突。
4. 按下面的 A1 清单写应用代码。（2026-10-17：步骤 2–4 已完成初版，见清单）
5. 首次 push 后看 CI：gomobile AAR 是否生成（Java 包 `libmihomo`，若 gomobile 生成的签名与 `core/Core.kt` 推断的不一致，以编译报错为准修改 Core.kt），R8 release 是否通过；然后装 APK 上机验证 A1（连接、protect 防回环、分应用、重载、磁贴、小组件、导入链接）。

### 设计要点（已定）

- **进程**：VpnService 与 UI 在同一个进程里，Go runtime 只加载一次。
- **防回环**：内核 socket 一律调用 `VpnService.protect`。不把本应用加入排除列表，因为那样会在“始终开启 VPN + 锁定”模式下断网。这样做之后，应用自己的请求也走 VPN，出口 IP 和解锁检测可以复用 iOS 的 MIHOMO-PROBE 监听（127.0.0.1:7899）。
- **VpnService.Builder 参数**：
  - 地址 198.18.0.1/30，DNS 198.18.0.2，路由 0.0.0.0/0。
  - IPv6 开启时加 fdfe:dcba:9876::1/126 和路由 ::/0。
  - MTU 9000。
  - 分应用代理用 allow 或 deny 列表。
- **目录**：home 为 `filesDir/core`，配置文件放在 `filesDir/profiles/`。bridge 会在 `dirname(home)/profiles/manual-nodes.yaml` 找手动节点。
- **设置**：App 把设置写进 `home/overrides.json`，字段与 iOS 的 Overrides 相同：controllerPort、secret、mode、logLevel、ipv6Mode 等。之后用 external-controller 的 REST API 管理内核，与 iOS 一致。
- **导入**：
  - 先用 `ClassifyText` 判断类型：
    - profile：直接保存。
    - conf：用 `ImportConf` 转换，返回 yaml、module、rewriteRemotes 和 report。
    - nodes：用 `ConvertShareLinks` 转换。
    - module:*：交给 A2。
  - URL 订阅下载时 UA 设为 `clash.meta`，并读取 `subscription-userinfo`。
  - **SIP008 JSON 在 iOS 的 Go 解析器里也不支持**，需要补上（最好在 iOS 的 bridge 里加，再同步过来）。
- **界面规格**：见 `../notes/qx-spec.md`、`../notes/qx-ui-video.md` 和 `../notes/qx-frames/*.jpg`。帧截图不要提交。

## 需求清单 (REQUIREMENTS)

图例：[x] 已完成，[ ] 未做，[~] 部分完成。

### A0 基础设施
- [x] 独立 git 仓库，推送到 mihomo-ios 的孤立分支 `android/main`
- [x] Go core 从 iOS bridge 移植（mihomo v1.19.32），并带 Android hook（tun fd、protect、内存、协议栈）
- [x] 同步脚本 `scripts/sync-core.sh`
- [x] GPL-3.0 LICENSE 和 NOTICE（mihomo、CMFA、FlClash 署名）
- [~] core 本地验证（go build android / vet / test），已启动但未出结果
- [x] Gradle 工程（Kotlin + Compose + Material 3，minSdk 26，targetSdk 35）：AGP 8.7.3、Gradle 8.11.1、Kotlin 2.1.0、Compose BOM 2024.12.01、JDK 17，applicationId `io.github.astemo6.mihomo`；本地 assembleDebug 通过（存根 AAR）
- [~] gomobile AAR 构建（固定与 iOS 相同的 mihomo 版本）：CI 步骤已写（版本取自 core/go.mod，`-X …CoreVersion`），**尚未在 CI 跑过**
- [~] GitHub Actions `android.yml`：AAR 加 assembleRelease，产出 universal 和 arm64-v8a 两个 APK，用临时 keystore 签名（已写，**未运行**；R8 release 构建本地未验证）
- [~] Prerelease 发布 `android-v0.1.0-buildN`（workflow 里已配置，等首次 push 运行）
- [ ] 新仓库 astemo6/mihomo-android 建好后迁移（push android/main 为 main）

### A1 可用内核 + QX 布局
- [x] VpnService：连接与断开、前台通知（含实时速率、断开按钮）、socket protect、tun fd 传给内核（detachFd，内核持有）、重载、异常停止时给出原因（onRevoke、启动失败 FriendlyError）；底层网络切换时 setUnderlyingNetworks + SetNetworkState（未上机）
- [x] 首次连接时的 VPN 授权（VpnService.prepare；磁贴/小组件未授权时打开应用再授权）
- [x] 订阅导入：URL、剪贴板、文件（SAF）、分享链接，以及 `clash://` / `mihomo://install-config?url=` 链接（intent filter，含 clashmeta://、分享文本、打开文件；外部来源先弹确认）
- [x] 无需 parser 的原生解析：Clash/mihomo YAML、base64 或明文分享链接、Surge/QX/Loon 节点行、Surge/QX 完整配置（ImportConf）——App 端按 ClassifyText 路由；module:* 提示 A2
- [x] SIP008 JSON（Go 端新增，core 提交 8b2250a 由另一个 agent 完成；ClassifyText 归为 nodes，App 走 ConvertShareLinks，无需额外代码）
- [x] 配置文件列表：切换、更新、全部更新、重命名、删除、显示订阅流量与到期时间、自动更新间隔（在 App 启动/回到前台时检查，与 iOS 相同；没有后台定时任务）
- [x] external-controller 客户端（REST + 流式接口 logs/traffic/connections/memory，OkHttp websocket）
- [x] QX 头部：出口国旗、位置、ASN、IP（ipinfo.io / ip-api / ipwho.is / ip.sb 轮询），加上总开关和运行时长
- [x] 面板条：节点 / 网络活动 / 分流规则 / 重写规则 / 日志（彩色瓷砖，选中的瓷砖下方有下划线）
- [x] 节点面板：PROXY 资源卡片（订阅信息、节点数、展开、全部测速），自定义策略卡片（解析出的 ➤ 链路、展开后选择；未连接时用 InspectProfile + SaveSelection 离线选择/测速），点图标测速，长按单个节点测速；策略组图标取配置的 `icon:`（`ui/components/GroupIcon.kt`：OkHttp + 内存 LRU + `filesDir/icon-cache/` 磁盘缓存，缩到 128px，raw.githubusercontent 走 jsDelivr 镜像，失败回落首字母头像；iOS 的用户自选图标 group-icons.json 未做）
- [x] 模式切换（规则 / 全局 / 直连），风车长按弹出运行模式面板（节点面板顶部也有分段切换）
- [x] 网络活动面板：TCP/UDP 计数，记录行包含规则、策略链和流量，可关闭单个/全部连接
- [x] 分流规则面板：生效规则列表，带类型和策略标签（未连接时显示配置文件里的规则）
- [x] 重写规则面板：列出「我的重写」+ 各模块经 Go 引擎解析的规则（类型/阶段/模式/来源，停用的变灰，可搜索），“管理”进 设置 › 重写
- [x] 日志面板：实时日志、级别切换（debug/info/warning/error）、暂停、清空
- [x] 浮动工具栏：搜索模式（工具栏变为搜索框，过滤当前面板）、＋、流量统计（简单弹窗；完整统计见 A2 traffic）、DNS（进 DNS 工具页）、请求；长按任一按钮进入编辑模式（点选按钮后左移/右移/隐藏，✓ 完成，“更多”进面板 & 工具栏页）；风车固定最右（点按设置、长按运行模式）
- [x] DNS 工具（`ui/tools/DnsScreen.kt`）：查询测试（已连接走控制器 `/dns/query`，类型 A/AAAA/CNAME/HTTPS/TXT，显示 TTL 和耗时；未连接用系统解析）+ DNS 设置（同 iOS DNSView：`dns.json` 自定义 DNS/分流/引导/policy/Fake-IP 过滤，overrides.dnsMode，`localdns.json` 本地映射（ValidateHostEntry 校验）和真实 IP 域名），保存并重载
- [x] 面板 & 工具栏（`ui/settings/PanelsToolbarScreen.kt`，存 `UiLayout` SharedPreferences `ui_layout`）：面板排序/隐藏（至少留一个），工具栏按钮排序/隐藏，恢复默认
- [x] 设置页：QX 式分区按钮网格（节点 / 分流 / 重写 / MitM / 工具 & 分析 / 配置文件），第二组「数据 & 工具」：DNS、脚本、规则集、DNS 日志、流量统计、订阅管理、策略组、手动节点、诊断（后 7 项进 `ui/feature2/Feature2Placeholder.kt`，见下方“并行开发”）；“面板 & 工具栏”可用；其他设置：连接与内核（日志级别、DNS 模式、嗅探、IPv6 off/auto/always、IP 偏好、阻止 QUIC、协议栈、测速地址/超时、健康检查覆盖、局域网共享、混合/控制器端口）、分应用代理、外观、语言、关于
- [x] 浅色、深色、跟随系统（默认跟随系统）；浅灰底白卡片，深色主题也同样适配
- [x] Quick Settings 磁贴（开关，未授权时打开应用）
- [x] 桌面小组件 ×1（状态、开关、当前节点和模式；RemoteViews）
- [x] 多语言：简体中文（默认）、繁体中文、English（应用内切换用 AppCompatDelegate，Android 13+ 系统设置里也可单独选）
- [x] 分应用代理：允许或排除列表（Android 专属；本应用始终留在 VPN 内）

### A2 与 iOS 对齐
- [x] 模块、重写、MitM、脚本（复用 Go 引擎 core/mitm，无需新增 Go 导出）：`data/EngineStore.kt` 写 `home/engine/engine.json` + `engine/modules/<id>.txt`（字段同 iOS EngineShared），改动后 400ms 去抖重载内核；设置 › 重写：总开关、模块（URL / 文件 / 剪贴板导入，UA Surge iOS/3000，启用/停用、更新、全部更新、查看原文、删除）、我的重写（粘贴多行，hostname= 行进 MitM 列表）；设置 › MitM：HTTPS 解密开关、跳过证书验证、全部阻止 QUIC、CA 生成/重新生成（CAGenerate/CAInfo）、导出 DER 到 下载/Mihomo-CA.crt（Android 10+ MediaStore，8–9 用 SAF CreateDocument）、手动安装说明（设置 › 安全 › 加密与凭据 › 安装证书 › CA 证书，并说明 Android 7+ 应用默认不信任用户 CA）、主机名列表（自有可删，模块来源只读）；脚本页：我的脚本、模块脚本/cron/event 任务、脚本日志（控制器 `/mitm/logs` 轮询，清空）。导入路由：ClassifyText `module:*`（粘贴/分享/文件/订阅 URL）、`.sgmodule/.plugin/.lpx/.stoverride/.snippet/.module` 链接或文件、`clash|mihomo://install-module?url=` → 模块；Surge/QX 完整配置首次导入时 ImportConf 的 `module` 和 `rewriteRemotes` 也加进引擎（同 iOS）。引擎扩展（2026-10-17，分支 android/a2-engine）见下条
- [x] 引擎扩展（分支 `android/a2-engine`，无 core 改动，全部用已导出的 gobind 函数）：
  - 模块详情页 `ui/engine/ModuleDetailScreen.kt`（重写页点模块或「详情」进入，页内 BackHandler 导航）：信息、查看内容、更新；**模块参数**（Surge `#!arguments`/`#!arguments-desc`、Loon `[Argument]` switch/select、Egern compat_arguments），保存到 `engine.json` `modules[].args`（同 iOS EngineShared），重新 EngineParseText 并重载；恢复默认清空 args。
  - **模块策略映射**：`ModuleUnresolved` + `ProfileGroups`（当前配置文件），每个未知策略名下拉选组（或“自动（第一个手动组）”），存 `modules[].policies`，core/mitm/config.go 的 mapPolicy 读取。
  - **脚本编辑器 + 调试**（`ui/engine/ScriptEditorScreen.kt`）：本地脚本 `engine/scripts/*.js` 新建/编辑/保存/删除（脚本页「本地脚本」区）；脚本行/模块脚本点开看源码（远程脚本经 `ScriptSource` 读内核缓存副本，只读，可另存为本地）；「调试台」+「调试运行」走 `ScriptDebugRun`（http-request/http-response/generic/cron，样本请求/响应、argument、binary-body-mode、超时），显示控制台、通知、$done、处理后结果 / 本地响应。
  - **MitM 请求查看器**（`ui/engine/RequestsScreen.kt`，MitM 页「HTTP 请求」）：`/mitm/requests` 1.5 s 轮询、筛选、清空；详情 `/mitm/requests/{id}`（头部/内容分请求/响应、JSON 美化、复制、复制为 cURL、重放与编辑后重放 `POST /mitm/requests/{id}/replay`、「用此请求调试脚本」）。API 在 `data/EngineApi.kt`（独立 OkHttp，不改共享 ControllerClient）。
  - **p12 导入导出**（MitM 页 CA 卡片）：`CAExportP12`（密码 → SAF 保存 Mihomo-CA.p12）、`CAImportP12`（SAF 选文件 → 密码 → 替换 CA 并重载）。
  - **CA 信任检测**：`KeyStore("AndroidCAStore")` 按 DER SHA-256 匹配，显示 用户证书 / 系统证书 / 未安装；回到前台（ON_RESUME）自动重查。
  - **策略组图标自选**：`data/GroupIconStore.kt` 写 `<home>/group-icons.json`（同 iOS：组名 → URL，"" = 默认），节点面板长按组图标打开 `ui/components/GroupIconPicker.kt`（图片地址校验加载、3 个 QX 图标库网格 + 搜索（经 jsDelivr 镜像，索引缓存在 icon-cache/）、使用配置文件图标 / 默认图标、清除缓存）。feature2 的 GroupsScreen 未接（不改 feature2 文件）。
  - 字符串：`res/values*/strings_engine2.xml`，由 `scripts/gen-strings-engine2.py` 生成（简体 / English / 繁體），键名 `e2_`。
  - 仅编译检查，**未上机**：AndroidCAStore 行为、p12 与 iOS 互通、调试运行、重放均未在设备上验证。
- [ ] 规则列表导入（QX/Surge/Clash rule list，作为远程规则集）
- [ ] DNS 查询日志和 DNS 阻止的域名
- [ ] 流量统计：本次会话按策略统计、历史记录、流速
- [ ] 订阅管理：节点订阅作为 proxy-provider，支持过滤、重命名、排序
- [ ] 策略组编辑器：类型、正则筛选、预览、手动引用
- [ ] 手动节点（表单、二维码导入、分享链接导出）
- [ ] 每个节点的出口 IP 和解锁检测（MIHOMO-PROBE）
- [ ] 诊断包导出（脱敏）和安全模式连接

### A3 Android 加分项
- [ ] 更多小组件（节点切换、流量）和 App Shortcuts
- [ ] 始终开启 VPN、开机自启
- [ ] 按网络切换模式（Wi-Fi / 蜂窝 / SSID）
- [ ] 局域网共享（HTTP/SOCKS 端口）
- [ ] 固定签名 keystore（需用户同意后放进 GitHub Secrets）

## 并行开发（2026-10-17）
- 本工作区（分支 `android/main`）负责共享文件：`ui/MainActivity.kt` 导航（字符串路由 `Routes.*`）、`ui/settings/SettingsScreen.kt` 网格、`ui/home/HomeScreen.kt` 工具栏、`res/values*/strings.xml`。
- 另一 agent 在 worktree `../mihomo-android-a2data`（分支 `android/a2-data`）做 A2 数据功能，代码放 `ui/feature2/`（和 `data/feature2/`）。入口路由是纯字符串：`rulesets`、`dnslog`、`traffic`、`nodesubs`、`groups`、`manualnodes`、`diagnostics`（`ui/feature2/Feature2Placeholder.kt` 的 `Feature2Routes`）。MainActivity 对这些路由调用 `Feature2Screen(route, onBack)`；合并时只需把 `Feature2Screen` 的函数体换成按 route 分发到真实页面（若需要 vm，可改签名并同步改 MainActivity 那一行）。标题字符串 `f2_*` 已在 strings.xml。

## 本地验证记录（2026-10-17 12:30 CST）
- `app/` 的 Kotlin 已对照**真实 gobind 生成的 Java 绑定**（`gobind -lang=java -tags android,with_gvisor`，javac 编成 classes.jar 放进占位 AAR）跑过 `:app:compileDebugKotlin`，BUILD SUCCESSFUL。`Core.kt` 的签名已确认，无需再猜。
- 仍未验证：真实 `gomobile bind` 产出的 .so、R8 release 构建（沙箱内存不足）、真机运行。
- 2026-10-17 13:xx CST：A1 补全（工具栏编辑/搜索模式、DNS 工具、面板 & 工具栏、策略组图标）+ A2 模块/重写/MitM/脚本 + feature2 入口，`:app:compileDebugKotlin` 对真实 gobind 绑定 BUILD SUCCESSFUL。未上机：MediaStore 导出、证书安装流程、MitM 实际解密、图标加载均未在设备上验证。

## 2026-10-17 合并 android/a2-data
- 合并 `android/a2-data`（1ed3fb1, ffe75f6）：规则集、DNS 日志、流量统计、节点订阅、策略组编辑、手动节点、出口 IP/解锁检测、诊断包/安全模式。详见 `HANDOFF-feature2.md`。
- 删除 `Feature2Placeholder.kt`，路由直接进入 `Feature2Router.kt`；`MihomoApp` 调用 `Feature2Hooks.onAppCreate`，`MainActivity.onResume` 调用 `Feature2Hooks.onForeground`。
- 验证：`:app:compileDebugKotlin` BUILD SUCCESSFUL（真实 gobind 绑定）。未真机测试。
- 待办：普通连接时清除 `safeMode`（目前只能在诊断页“正常重连”退出）；`ProfileStore` 增加固定 id 新增接口替换 `ManualNodes.ensureProfile`；二维码扫描。（模块参数/策略映射、脚本编辑调试、MitM 请求查看、p12、CA 信任检测、组图标自选已在 android/a2-engine 完成）
