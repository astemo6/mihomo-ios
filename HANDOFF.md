# Mihomo for Android — 暂停交接 (HANDOFF)

**状态：已暂停（HOLD）**，用户 2026-10-17 10:53 CST：「先优先跑原先的跟ios qx，android qx暂时hold」。
Mihomo for Android 是用户 iOS 客户端（astemo6/mihomo-ios）的 Android 版本，界面沿用 QX 风格重做的设计。

- 分支：这个仓库目前作为 **astemo6/mihomo-ios 上的孤立分支 `android/main`** 推送（与 iOS 历史无关）。等新仓库 astemo6/mihomo-android 建好后，直接 `git push <new> android/main:main` 即可迁移。
- 本地工作目录：`/workspace/projects/7d77dd5e-b695-4cf0-bbd5-6be0ce900744/android`（独立 git 仓库，分支 main）。
- 这个分支上**还没有 CI workflow**，所以推送不会触发任何 Actions，也不会碰 iOS 的 workflow：iOS 的 `ios.yml` 只在 push 到 main 时触发，`core-update.yml` 只按定时或手动触发，而且这两个文件都不在这个分支上。

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
- **还没有 Android 应用代码**：没有 Gradle 工程、Kotlin 和 Compose 代码，也没有 CI。
- **本地验证情况**：在沙箱里启动了 `GOOS=android go build`、`go vet` 和 `go test`，暂停前**还没出结果**。所以 core 的改动未经编译验证，恢复后第一件事就是跑这三项。
- 沙箱是 aarch64，而 Android SDK 的 aapt2 和 NDK 只有 x86_64 版本，所以 APK 和 AAR 只能靠 CI 构建，本地只能跑 Go。

## 恢复步骤

1. 用 `scripts/sync-core.sh` 从 iOS 最新的 main 重新同步 core。然后运行 `go vet -tags with_gvisor ./...` 和 `go test ./...`，再用 `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...` 编译一遍。
2. 搭 Gradle 工程：AGP 8.7.x、Gradle 8.11.1、Kotlin 2.1 + Compose BOM、minSdk 26、targetSdk 35、JDK 17，applicationId 定为 `io.github.astemo6.mihomo`（暂定）。
3. 在 `.github/workflows/android.yml` 里配置 CI：
   - 触发条件：`push: branches: ['android/**']` 和 `workflow_dispatch`。
   - 用 setup-go 读取 `core/go.mod`，用 `gomobile bind -target=android/arm64,android/amd64 -androidapi 26 -tags with_gvisor` 生成 `app/libs/libmihomo.aar`，按 core 的哈希缓存。
   - 用 `gradle assembleRelease` 打包，并按 ABI 拆分输出 universal 和 arm64-v8a 两个 APK。
   - 签名用 CI 里临时生成的 keystore（不提交）。以后如果需要固定签名，先问用户，再放进 Secrets。
   - 发布 prerelease：tag 为 `android-v0.1.0-buildN`，标题为 “Android 预览 v0.1.0 (buildN)”，附件为 `Mihomo-Android-0.1.0-buildN-universal.apk` 和 `-arm64-v8a.apk`。iOS 的 tag 是 `v*-buildN`，这里加 `android-` 前缀，两者不会冲突。
4. 按下面的 A1 清单写应用代码。

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
- [ ] Gradle 工程（Kotlin + Compose + Material 3，minSdk 26，targetSdk 35）
- [ ] gomobile AAR 构建（固定与 iOS 相同的 mihomo 版本）
- [ ] GitHub Actions `android.yml`：AAR 加 assembleRelease，产出 universal 和 arm64-v8a 两个 APK，用临时 keystore 签名
- [ ] Prerelease 发布 `android-v0.1.0-buildN`
- [ ] 新仓库 astemo6/mihomo-android 建好后迁移（push android/main 为 main）

### A1 可用内核 + QX 布局
- [ ] VpnService：连接与断开、前台通知、socket protect、tun fd 传给内核、重载、异常停止时给出原因
- [ ] 首次连接时的 VPN 授权（VpnService.prepare）
- [ ] 订阅导入：URL、剪贴板、文件（SAF）、分享链接，以及 `clash://` / `mihomo://install-config?url=` 链接（intent filter）
- [ ] 无需 parser 的原生解析：Clash/mihomo YAML、base64 或明文分享链接、Surge/QX/Loon 节点行、Surge/QX 完整配置（ImportConf）
- [ ] SIP008 JSON（Go 端新增）
- [ ] 配置文件列表：切换、更新、删除、显示订阅流量与到期时间、自动更新间隔
- [ ] external-controller 客户端（REST + 流式接口 logs/traffic/connections）
- [ ] QX 头部：出口国旗、位置、ASN、IP，加上总开关
- [ ] 面板条：节点 / 网络活动 / 分流规则 / 重写规则 / 日志（彩色瓷砖，选中的瓷砖下方有下划线）
- [ ] 节点面板：PROXY 资源卡片（订阅信息、节点数、展开），自定义策略卡片（解析出的 ➤ 链路、展开后选择），点图标测速，长按单个节点测速
- [ ] 模式切换（规则 / 全局 / 直连），风车长按弹出运行模式面板
- [ ] 网络活动面板：TCP/UDP 计数，记录行包含规则、策略链和流量，可关闭连接
- [ ] 分流规则面板：生效规则列表，带类型和策略标签
- [ ] 重写规则面板（A1 先只读或占位）
- [ ] 日志面板：实时日志和级别切换
- [ ] 浮动工具栏：编辑/搜索、＋、流量统计、DNS、请求，风车点按进设置
- [ ] 设置页：QX 式分区按钮网格（节点 / 分流 / 重写 / MitM / 工具 & 分析 / 配置文件），以及面板 & 工具栏、其他设置
- [ ] 浅色、深色、跟随系统（默认跟随系统）；浅灰底白卡片，深色主题也同样适配
- [ ] Quick Settings 磁贴（开关，未授权时打开应用）
- [ ] 桌面小组件 ×1（状态、开关、当前节点和模式）
- [ ] 多语言：简体中文（默认）、繁体中文、English
- [ ] 分应用代理：允许或排除列表（Android 专属）

### A2 与 iOS 对齐
- [ ] 模块、重写、MitM、脚本（复用 Go 引擎 mitm/：模块导入、启用和停用、CA 生成与导出，Android 上需要用户手动安装 CA 证书）
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
