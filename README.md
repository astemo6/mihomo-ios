# Mihomo iOS（v0.12）

基于开源 [mihomo](https://github.com/MetaCubeX/mihomo)（Clash Meta）内核的个人 iOS 代理客户端：深色卡片界面，首页只放最常用的东西，进阶功能按类别收在「更多」里。

> 本项目以 **GPL-3.0** 发布（见 `LICENSE` 与 `NOTICE`），与 mihomo 内核许可一致。仓库里没有任何节点、证书或密钥。

## 设计原则

1. **一个内部模型**：所有东西最终都是「mihomo 配置 + 我们自己的覆写 / 模块存储」。Surge、Quantumult X、Loon、Stash、Egern 的格式只在导入边缘做一次翻译（每种格式一个解析器），之后就是普通的 mihomo 配置或模块，不存在第二套运行逻辑。
2. **一种设计语言**：项目自己的深色卡片（`Theme` / `Card`），新页面不照搬其他客户端的布局。
3. **首页极简**：连接开关、出站模式、IP 卡片、流量。其他功能都在「更多」里分组：连接、规则与资源、模块重写与 MitM、工具与数据、设置。
4. **模块只有一个入口**：所有格式的模块和远程资源（规则集、脚本）都在「更多 → 模块与资源」，用角标标出来源格式。
5. **宁缺毋滥**：做不精的功能先不做（仍推迟：共享动态内核库；资源解析器只保存地址、不运行；小组件、控制中心开关和实时活动作为单独的 `-widget` IPA 提供）。
6. **规则、重写、脚本都接受 Surge 与 Quantumult X 写法**（以及 Loon、Stash、Egern），只在边缘翻译一次。

## 功能

| 位置 | 内容 |
| --- | --- |
| 首页 | IP / ASN 卡片（出口 + 直连）、连接开关、规则 / 全局 / 直连、当前配置与节点、实时速度曲线、本次上传 / 下载 |
| 策略 | 已连接：实时策略组、点选切换、组测速；自动 / 故障转移组可开「智能选择」；任意策略组可设**前置代理**；长按节点可**分享**（链接 + 二维码）。**未连接：「未连接 · 来自配置文件」离线策略页**——读取当前配置（含节点集缓存、合并的手动节点），可以选节点（按配置保存，下次连接时自动应用）、直接测速 |
| 请求 | 实时连接、最近关闭、MitM 解密的 HTTP 请求（头部 / 内容查看、**复制为 cURL、重放、编辑后重放**） |
| 配置 | **配置编辑器**（YAML 高亮、内核实时校验并标出错误行列、保存并重载；订阅配置只读，可「复制为本地配置」）；订阅流量 / 到期（`subscription-userinfo`，含剩余天数）；**节点处理**（每个订阅：过滤、重命名、旗帜、去重、排序 + 实时预览）；订阅 / 本地 YAML / 剪贴板 / 文件；**Surge / Quantumult X `.conf` 导入**（先显示转换报告：节点、策略组、规则、规则集数量与未转换项，重写部分作为模块导入）；手动节点 |
| 更多 → 连接 | 连接方式（全局隧道 / 仅代理）、**局域网共享**（显示本机 Wi-Fi / 个人热点地址与 HTTP+SOCKS5 端口）、按需连接（始终 / 仅 Wi-Fi / 仅蜂窝；App 内手动断开会暂停按需连接，直到下次手动连接）、DNS（国内 / 国外分流、引导 DNS、nameserver-policy、Fake-IP 过滤） |
| 更多 → 规则与资源 | 规则（实时或离线）+ **自定义规则**（Surge / QX / Loon / mihomo 写法，输入时实时校验并显示转换结果与策略组；远程 RULE-SET / DOMAIN-SET / QX filter_remote）；提供者（实时，或离线显示 URL / 类型 / 缓存内容）；**地理与规则库**（GeoIP MMDB、GEOIP dat、GEOSITE、GeoLite2-ASN：状态、更新时间、默认地址、自定义地址、国内镜像开关、下载进度与错误） |
| 首页 → 面板 | 只在已连接且模块带面板时出现一行入口：Surge `[Panel]` / Stash `tiles` 合并为一个「面板」页，脚本驱动、可刷新（不是主屏幕小组件） |
| 更多 → 模块、重写与 MitM | **本地模块**（自己的重写规则 + MitM 主机名：表单编辑、拖动排序、文本模式，置顶在模块与资源里）、**脚本调试台**（JS 编辑器 + 调试运行）；**模块与资源**（全部格式一个入口，格式角标；远程规则集 / 重写集 / 脚本各自的更新间隔、上次更新、开关、错误、全部更新；一键添加 BoxJS；参数含 Loon `[Argument]` 开关 / 选择；**策略映射**：模块规则里配置中不存在的策略名可逐个指定策略组）、重写、脚本、MitM |
| 更多 → 工具与数据 | 网络工具（Ping / TCP / DNS，连接时经过内核规则并显示策略链）、**解锁检测**（按策略 / 节点）、连接分析（按天保存）、流量统计（Swift Charts，按天保存约 120 天）、日志、备份与恢复（文件 / 分享 / iCloud） |
| 更多 → 设置 | 内核设置（内存上限、隧道 MTU、手动节点合并进每个配置、日志、IPv6、控制器）、App 图标（默认 / 石墨 / 极光）、诊断（**一键导出诊断包**、App Group、扩展 ID、启动日志） |
| 快捷指令 | 连接、断开、切换连接、切换出站模式、切换节点、**查询状态、切换配置、开关模块、更新订阅、运行脚本**（App Intents）；主屏幕长按图标：连接 / 断开、规则 / 全局 / 直连 |
| 导入链接 | 只注册自己的 `mihomo://`（`mihomo://install-config?url=`、`install-module?url=`、`connect`、`disconnect`、`toggle`）。粘贴的 `loon://`、`stash://`、`surge:///`、`quantumult-x:///`、`egern:/` 安装链接也能识别，但**不注册**这些 scheme，避免与其他客户端抢链接。可以用「文件」/其他 App 的「用 Mihomo 打开」打开 `.sgmodule` `.plugin` `.stoverride` `.module` `.snippet` `.conf` `.list` `.yaml` 和纯文本；剪贴板有新内容时顶部出现「粘贴导入」横幅 |
| iPad | 横向宽度为常规时用侧边栏（NavigationSplitView）显示五个分区，支持横竖屏与分屏；iPhone 保持底部标签栏 |

## v0.12 要点

- **按网络切换运行模式**（更多 → 连接方式 → 按网络切换策略 → 运行模式；Quantumult X `running_mode_trigger`）：蜂窝、Wi-Fi 和指定 Wi-Fi（SSID）各自使用 规则 / 全局 / 直连，或不切换。VPN 扩展在连接、重载和每次网络变化时应用，和按网络切换策略组一起记录在「最近一次切换」里；首页的模式显示会跟着更新。手动切换的模式保持到下一次网络变化。读取 Wi-Fi 名称需要重签描述文件包含 wifi-info 权限，否则只按 Wi-Fi / 蜂窝匹配。
- **出口信息查询**（更多 → 设置 → 出口信息查询；QX `geo_location_checker`）：首页出口信息可以改用自己的 JSON 接口；再填一个 QX 的 geo_location_checker 脚本时，脚本读取 `$response.body`，`$done({title, subtitle})` 决定首页标题和第二行（在 Go 脚本引擎里运行，脚本缓存一天）。关闭后不再查询出口 IP（= `disabled`）。带测试按钮。
- **QX 远程分流不写 force-policy 时按每行自己的策略分流**：列表下载后（导入后自动下载，或 提供者 → 更新）按行里的策略拆成多个规则集，依次匹配；配置里没有的策略名自动建成手动选择组（和 QX 一样），没有策略的行仍走原来的策略（proxy）。配置文件本身不改，下载前整份列表走 proxy。
- **资源解析器**（订阅管理 → 高级）：只保存 QX 的 `resource_parser_url`，不下载、不运行——节点、规则、重写资源都由 Mihomo 直接识别。
- **QX 导入**：`running_mode_trigger`、`geo_location_checker`、`resource_parser_url` 在导入报告的「连接设置」里列出，一键应用。
- **从连接添加规则**：请求页长按一条连接 → 添加规则…（域名后缀 / 完整域名 / 关键词 / IP 段 + 策略），存为自定义规则并立即重载；也可以拷贝主机名。
- **DNS 缓存**（更多 → DNS，已连接时）：清空 DNS 缓存、清空 Fake-IP 缓存。
- **稳定性**：滑掉的实时活动不再挡住下次连接时的新活动，重复的活动会被结束；任务页只在连接时轮询，未连接时点运行会说明原因。
- 未做：`[http_backend]`（QX 在扩展里监听 127.0.0.1:9999；iOS 上回环地址不经过隧道，做不精，先不做）。

## v0.11 要点

- **任务**（更多 → 任务，或 脚本 → 工具）：按 Quantumult X「HTTP 请求」的方式列出所有定时、网络变化、交互和通用脚本（来自脚本列表和启用的模块，Surge / Loon / QX / Stash / Egern 写法都算）。顶部「自动运行」总开关；定时和网络变化任务各有开关（覆盖行内的 `enabled=` / `enable=`，写成 `enabled=false` 的任务也会列出、默认关闭）；`img-url` 图标；左滑立即运行。点进任务可以看计划、来源、脚本地址，以及最近 10 次运行记录（时间、触发方式、耗时、结果和 console 输出）。未连接时也能查看列表、开关和运行记录。
- **交互脚本**（QX `event-interaction`）：在「策略」里长按节点 → 交互脚本，脚本通过 `$environment.params` 收到节点名称，`$done({title, message | htmlMessage})` 的结果以卡片显示；任务详情里也可以选节点运行。
- **Quantumult X 配置导入补全**：`[dns]` 指定域名的服务器（`server=/域名/IP` → nameserver-policy）、`doh-server` / `doq-server`（有加密 DNS 时不再用普通 DNS 和系统 DNS，和 QX 一致）、`no-system`、`prefer-doh3`、`no-ipv6`、`address=` / `alias=`（→ 本地映射）；`[general]` 的 `dns_exclusion_list`（→ 真实 IP 域名）、`udp_drop_list` / `udp_whitelist`（→ 规则）、`fallback_udp_policy`、`server_check_url` / `server_check_timeout`；`excluded_routes`、`ssid_suspended_list`、`udp_drop_list` 里的 QUIC 在导入报告里列为「连接设置」，可一键应用到 连接方式 / 受信任 Wi-Fi / 阻止 QUIC；`[policy]` 的 `alive-checking`、`round-robin` / `dest-hash` 策略；`[server_remote]` 的 `as-policy`；`[filter_remote]` 的 `FILTER_LAN` / `FILTER_REGION` 和 `inserted-resource` 顺序；`[server_local]` 的 SSR（`ssr-protocol`）、`anytls`、`fast-open`、`tls-cert-sha256`、`tls-alpn`、`udp-over-tcp`；`[rewrite_local]` 的 `jsonjq-request-body` / `jsonjq-response-body` 和 `url-and-header`；`[mitm]` 的 `skip_validating_cert`。没有对应项的键在报告里注明（v0.12 起 `running_mode_trigger`、`geo_location_checker`、`resource_parser_url` 也会导入）。
- **App 关闭时的实时活动**：实时活动开启时，VPN 扩展每 10 秒把速度、总流量和当前节点写到 App Group（一次内核调用，不常驻额外内存）；App 退到后台后约 25 秒内继续刷新，之后在系统允许后台刷新时更新，锁定屏幕 / 灵动岛上的刷新按钮（iOS 17+）可随时拉取最新数据。数据过时时显示「更新于 时:分」，不再停在旧速度上。
- **错误提示**：内核接口返回的错误改为中文说明（密钥不匹配、扩展还是旧版本需重连、脚本引擎未运行、超时、连不上内核），模块下载失败显示 HTTP 状态。

## v0.10 要点

- **配置快照**（更多 → 工具与数据 → 配置快照）：导入 / 编辑 / 更新 / 删除配置、添加或删除模块、编辑手动节点、策略组、节点订阅以及恢复备份之前自动保存一份（内容与上一份相同则跳过，最多 20 份，可固定）；每份快照可查看与当前配置的差异（逐文件 +行 / −行），一键恢复，恢复前再保存一份当前状态。可关闭自动快照，也可手动创建。
- **存储空间**（同一分组）：按类别显示占用（配置、规则集 / 节点集缓存、地理数据库、快照、日志与诊断、图标缓存、临时文件、流量与分析记录），可清除未被任何配置引用的提供者缓存、日志、图标缓存、临时文件、旧快照和统计记录。
- **HAR 导出**（请求 → HTTP 右上角分享按钮，或单个请求详情 → 导出 HAR）：把 MitM / 重写引擎抓到的请求导出为 HAR 1.2（请求 / 响应头、文本正文、状态、耗时；二进制或被截断的正文会在 comment 中注明），可用 Charles、Proxyman、浏览器开发者工具打开。
- **网络测试**（更多 → 工具与数据 → 网络测试）：在内核中按当前规则运行。带宽：延迟 + 4 路并发下载 / 上传，实时曲线，显示所走的策略链（默认 speed.cloudflare.com，可改地址）。NAT 类型：RFC 5780 映射与过滤检测（完全锥形 / 受限锥形 / 端口受限锥形 / 对称型 / UDP 不通），显示公网 UDP 地址和测试步骤（默认依次尝试 stun.miwifi.com、stun.stunprotocol.org、Google、Cloudflare）。
- **同步文件夹（iCloud 云盘）**（更多 → 备份与恢复 → 同步文件夹）：选一个「文件」里的文件夹（例如 iCloud 云盘中的 Mihomo 文件夹），上传 / 下载 `Mihomo-sync.json`（配置、手动节点、模块、脚本、覆写、DNS、规则、策略组编辑；不含 MitM 证书）。可在 App 退到后台且内容有变化时自动上传；下载需确认，覆盖前自动快照。用安全书签访问，不需要 iCloud 容器权限，重签名后也能用。
- **实时活动 / 灵动岛**（更多 → 设置 → 外观）：连接时在锁定屏幕和灵动岛显示状态、已连接时长、当前节点和上下行速度。由现有小组件扩展绘制（只在 `-widget` IPA 中出现，不需要新的 Bundle ID）；时长持续走动（v0.11 起 App 关闭时也会更新，见上）。
- **订阅格式**：节点订阅 / 配置订阅支持 SIP008（Shadowsocks JSON `{"version":1,"servers":[…]}`）和 sing-box JSON outbounds，包括 Base64 包装的 JSON。
- 备份现在也包含节点订阅和策略组编辑。

## v0.9 要点

- **浅色模式**：更多 → 设置 → 外观，可选「跟随系统」（默认）/ 浅色 / 深色。所有卡片、背景、强调色、状态色、图表和代码编辑器都有浅色与深色两套配色，设计语言不变；导入页和系统弹窗跟随同一设置；小组件始终跟随系统。
- **订阅管理**（配置页左上角 / 更多 → 订阅 → 订阅管理）：配置订阅、节点订阅和当前配置里的节点集（含 QX server_remote）集中在一个列表；每张卡片显示类型（配置 / 节点）、节点数、已用 / 总流量进度条、到期日、上次更新时间和自动更新间隔。可添加只含节点的「节点订阅」（任意格式：Clash YAML、分享链接、Base64、QX / Surge 节点行），它会作为 mihomo 节点集（proxy-provider）加入每个配置——默认加入含节点的手动选择组和自动选择组，也可指定策略组；支持单个 / 全部更新、启用 / 停用、编辑链接 / 名称 / UA / 间隔、节点处理（过滤 / 重命名 / 排序）、复制链接和删除。节点订阅由 App 下载，断开时也能更新。
- **策略组编辑**（策略页卡片右侧的调节按钮或长按图标；右上角 + 新建）：类型（手动选择 / 自动选择 / 故障转移 / 负载均衡）、成员（节点、其他策略组、DIRECT / REJECT，增删与拖动排序）、使用的节点集、包含全部节点、筛选 / 排除正则（实时预览匹配的节点）、测速地址 / 间隔 / 容差 / 懒惰测速 / 负载均衡策略、图标；重命名（规则和其他组里的引用随之更新）、复制、删除、「恢复原始」。修改保存在本机覆写里，不改动配置文件；保存前检查空组和循环引用。页面下方列出指向该组的规则，可跳转到规则页。
- **按 Wi-Fi 自动连接 / 按网络切换策略**（更多 → 连接方式）：按需连接可设为「仅指定 Wi-Fi」，并可为不同 Wi-Fi / 蜂窝网络指定策略组的选择（需要 wifi-info 权限与「使用 App 期间」定位权限；重签名描述文件需包含 Access WiFi Information）。
- 小组件（中号）显示当前订阅的剩余流量。

## v0.8.1 要点（真机测试修复：导入 Quantumult X 配置）

- **「用 Mihomo 打开」/ 分享 / 从文件导入都会有反馈**：导入确认页改由最上层的界面弹出（等文件选择器或其他弹窗关闭后再弹），以前在新手引导、设置弹窗或文件选择器还没收起时会被系统静默丢弃。冷启动时打开的文件也会补发。任何打开的文件或链接都会显示导入页，或说明无法导入的原因。
- **读取更稳**：在安全作用域内立即读取（协调读取，iCloud 文件会先下载），支持 UTF-8（含 BOM）、UTF-16、GB18030；`.conf` / `.txt` / `.snippet` / 无扩展名 / 其他 App 自定义类型都按内容识别（增加 public.data 作为备选文档类型）。每次打开都记入诊断启动日志（扩展名、类型、字节数）。
- **完整的 QX 配置识别为配置**：含 `[server_local]` / `[server_remote]` / `[policy]` / `[filter_local]` / `[filter_remote]` 的文本一律走配置转换（以前 `http://` 开头的远程行可能被误认成 Stash 覆写）。
- **QX 转换补全**：`[server_remote]` 订阅转为 mihomo 节点集（经本地 `/nodes/convert` 下载，支持 QX / Surge 行、分享链接、Base64 和 Clash YAML）；`server-tag-regex` 组包含全部节点集再过滤，`resource-tag-regex` 只用匹配的订阅，成员是远程节点名的组改用订阅；`[rewrite_remote]` 中启用的链接导入时逐个添加为远程模块。
- 粘贴 Surge / QX 配置、从文件导入、「用 Mihomo 打开」共用同一个弹出方式和同一个 QX 转换器。
- **QX 重写完整导入**：`[rewrite_remote]` 每一行成为一个独立的远程模块（名称取 `tag=` 或文件名，保留 `enabled=`、更新间隔和源地址，导入时由 App 直接下载，失败的可在「模块与资源」中更新）；`[rewrite_local]` 全部类型（reject 系列、302/307、请求/响应头和体改写、各类脚本、echo-response、url-and-header）与 `[task_local]` 定时任务进入导入模块；`[mitm]` 主机名保留，CA 的 passphrase / p12 不会被复制。导入页按「重写 / 脚本 / MitM 主机 / 远程重写 / 定时任务」分别计数，并列出每一行不支持的内容；需要 MitM 时提示一键前往开启并安装证书。「更多」中的重写、脚本数量包含已启用模块的内容，与「模块与资源」一致。
- **规则集保留源地址，App 可直接下载**：导入后的规则集 / 节点订阅在配置里保留原始 URL（不再显示 `127.0.0.1` 转换地址），名称取 QX `tag=` 或文件名（如 YouTube、Privacy、Unbreak，重名自动加序号）。未连接时可在「更多 → 提供者」点「全部更新」或单个更新，由 App 下载并转换到内核读取的缓存文件（遵循 GitHub 镜像设置），显示进度、错误、更新时间与条数；连接后内核按更新间隔从源地址刷新。旧版本导入的 `custom-<hash>` 名称在启动时自动迁移，规则引用随之更新。

## v0.8 要点

### 节点出口与解锁检测（策略页长按节点；更多 → 工具与数据 → 解锁检测）

- **每个节点的出口**：策略页长按任一节点或策略组 →「出口与解锁检测」，显示经由它出去的 IP、国家 / 城市、时区、ASN 与运营商（与首页头部同一个组件、同一组查询接口），可复制。
- **解锁检测**：Netflix（全部 / 仅自制剧）、Disney+、YouTube Premium（地区）、ChatGPT（含「仅网页版」）、Claude、Gemini、TikTok、Spotify、哔哩哔哩港澳台 / 台湾。可以选一个策略组（用它当前的选择）或组里的某个节点，也可以「逐个检测组内节点」。节点卡片上显示小角标「🔓 n/m」（最近一次检测里可用的服务数）。
- 实现：运行配置多了一个隐藏策略组 `MIHOMO-PROBE`（只是引用全部节点与策略组）和一个只监听 `127.0.0.1:7899` 的入站（`listeners`，固定交给这个组）。App 通过控制器选好要测的策略，再从**主程序**经由这个本机端口发请求——网络扩展里不增加任何任务，内存不变。检测按策略逐个进行，互不干扰；不经过分流规则。
- 检测依据各服务网页 / 接口的公开表现（与常见的解锁检测脚本同一套判断），服务改版后可能失准；「检测失败」表示没读出结果，不等于被封锁。v0.7 及更早的连接需要重连一次才有探测入口。

### 流量构成：Wi-Fi / 蜂窝、直连 / 代理

- **Wi-Fi / 蜂窝**：隧道本来每 2 分钟记一次流量，现在同时记下当时用的网络，按天保存（v0.8 之前的天数显示为「未区分」）。
- **直连 / 代理**、各策略流量、主机名排行：App 打开期间对连接的采样，**按天保存最多 90 天**（App 自己的存储，扩展不参与）。
- 「连接分析」新增范围：本次连接 / 今天 / 7 天 / 30 天，以及「流量构成」卡片；「流量统计」也加了流量构成和每天的 Wi-Fi / 蜂窝明细。

### 自动组固定、IPv6

- **固定 / 解除固定**：自动（url-test）与故障转移（fallback）组里轻点或长按节点即可固定，组卡片显示「已固定」，一键解除。用的是 mihomo 原生接口（`PUT` / `DELETE /proxies/{组}`），重连后仍然保持。开启「智能选择」的组由评分器决定，不提供手动固定。
- **IPv6：关 / 自动 / 总是**（更多 → 连接方式）。「自动」= 每次连接时看当前 Wi-Fi / 蜂窝有没有公网 IPv6，有才开。另加「节点 IP 优先」：默认双栈 / IPv4 优先 / IPv6 优先 / 仅 IPv4 / 仅 IPv6，作用于没有自己写 `ip-version` 的节点（含节点集）。

### 节点编辑器「高级」

- ECH（`ech-opts`）、证书指纹固定（`fingerprint`）、多路复用（`smux`：协议、最大连接数、填充）、TCP Fast Open、MPTCP、IP 版本；只在 mihomo 对该协议支持时出现。

### 快捷指令

- 新增：查询状态（返回连接状态 / 模式 / 节点 / 配置，可接着用）、切换配置、开关模块（开启 / 关闭 / 切换）、更新订阅、运行脚本（按名称运行定时 / 通用脚本，需要已连接）。

### 首页

- 未连接时也显示策略卡片（来自配置文件），在这里选的节点保存到配置，下次连接生效。

### 未做

- 按 SSID 切策略、「仅在这些 Wi-Fi 下连接」、实时活动、共享动态内核库（仍等真机验证）。

## v0.7 要点

这一轮补齐与 Surge / Loon / Egern / Shadowrocket 的几块差距，全部沿用同一个内部模型（mihomo 配置 + 我们的覆写 / 模块存储）和同一套深色卡片。

### 脚本调试台（更多 → 脚本 → 工具 → 脚本调试台）

- 自带轻量 JS 编辑器（`UITextView` + 自写正则高亮：注释、字符串、关键字、`$` API、数字；改动只重新着色受影响的段落；键盘上方一排常用符号）。没有引入任何第三方依赖。
- **调试运行**：用样本或抓到的请求执行一次，显示 `console.log` 输出（带毫秒时间）、`$done` 参数、修改后的请求 / 响应或本地应答、通知、耗时与错误（语法错误、异常、超时）。脚本类型可选请求 / 响应 / 通用。
- 入口：脚本列表左滑「调试」或长按「在调试台打开」；本地脚本文件；新建 / 编辑脚本表单里的「调试运行」；**请求 → 详情 → 用此请求调试脚本**（把抓到的 URL、头部、请求体、状态码和响应体带进样本）。远程脚本打开缓存副本（只读，可另存为本地脚本）。
- 实现：Go `ScriptDebugRun` 在 App 进程里起一个一次性引擎，复用线上同一个 `ScriptRunner`（同样的全局对象、Egern ctx 适配），只把控制台和通知截下来；`$httpClient` 直接联网，`$persistentStore` 用真实存储。

### 本地模块：可视化重写 / MitM 编辑（更多 → 重写，或 模块与资源 顶部）

- 你自己的重写规则和 MitM 主机名就是「本地模块」，与导入的模块在同一个管理页里（置顶一行），存储仍是原来的 `engine.json` `rules` / `hostnames`，没有第二份存储。
- 表单：拒绝（reject / reject-200 / reject-img / reject-dict / reject-array / reject-drop）、重定向 302 / 307、请求头 / 响应头（添加 / 替换 / 删除 / 正则替换）、请求体 / 响应体正则替换、本地映射（文本 / Base64 / 文件或 URL / 1×1 GIF、Content-Type、状态码、额外头）。每改一个字段就由 Go 解析器生成标准 Surge 行并校验（正则错误、缺目标等），通过才能保存。
- 拖动排序、开关、搜索；「文本」切换为整段文本编辑（`hostname =` 行、`#off` 前缀表示停用、上一行注释作为备注），保存前整段校验。Quantumult X / Loon 写法的已有规则能打开到对应表单，表单表达不了的（JSON 操作、jq）按文本编辑。

### 前置代理（代理链）

- 手动节点：节点编辑页「前置代理」，写入节点自身的 `dialer-proxy`。开启「把手动节点加入每个配置」后还可以选当前订阅里的策略组。
- 策略组：策略页展开任意组 →「前置代理」。保存在我们的覆写存储 `groups.json`（与智能选择同一处），构建运行配置时给组内每个节点加 `dialer-proxy`，组引用的节点集加 `override.dialer-proxy`（mihomo 不允许直接给策略组设 dialer-proxy）。
- 循环检测在 Go：候选列表已排除会形成循环的节点 / 组；构建时会跳过会成环的成员、去掉配置里原有的成环或指向不存在策略的 `dialer-proxy`，并写进启动日志。安全模式不应用策略组前置代理。

### 节点分享

- 手动节点左滑「分享」/ 长按，策略页长按节点：分享链接 + 二维码，复制或系统分享。支持 ss（含 obfs / v2ray-plugin）、ssr、vmess、vless（含 Reality）、trojan、hysteria2、hysteria、tuic、anytls、socks5、http(s)、wireguard、snell、ssh；mieru 等没有通用链接格式的类型会说明原因。
- 手动节点 → 右上角 →「导出为订阅文本」：Base64 订阅（每行一个链接），可复制或分享为文件，列出未能导出的节点。
- 不做遮挡（这是你自己的操作），但每处都有提示：链接包含服务器和密码。

### 配置编辑器

- YAML 高亮；输入停顿 0.7 秒后用内核解析器校验（与连接时完全相同的覆写和节点处理），底部显示节点 / 策略组 / 规则 / 节点集数量，或错误原因与「第 N 行 M 列」，点一下跳到出错行并标红。YAML 语法错误用二分法定位到最先出错的那一行；节点、策略组、规则、节点集的错误按名称或规则内容回到你的原文。
- 本地配置「保存并重载」；订阅配置只读（更新订阅会覆盖），可「复制为本地配置」。

### 连接方式（更多 → 连接方式）

一页管住隧道怎么建，改完重连一次即可（页面会给出「立即重新连接」）。

- **模式**：TUN（默认，所有 TCP / UDP 与 DNS 经过内核）；**VPN 混合**（TUN 之外再设系统 HTTP / HTTPS 代理指向本机 mixed-port，类似 Loon `proxymode=mix` / Surge 兼容模式，遵守系统代理的 App 直接把域名交给内核）；**仅代理**（只设系统代理，不接管路由和 DNS）。
- **阻止 QUIC**：关（mihomo 原生：节点不支持 UDP 时 QUIC 会改走直连）/ **仅非直连**（默认，即 v0.6.1 行为：规则选直连或节点支持 UDP 时 QUIC 照常；本该走代理却会被迫直连的 UDP 443 被拒绝，App 改用 TCP）/ 始终（拒绝全部 QUIC，与 MitM 页的「全部」合并为一条规则）。
- **IPv6** 开关从「内核设置」移到这里。
- **隧道范围**（NETunnelProviderProtocol 公开 API）：接管所有网络流量（includeAllNetworks），开启后可排除局域网、推送通知 APNs、运营商服务（iOS 16.4+）、设备间通信（iOS 17.4+）。保存时写入 VPN 配置。
- **路由**：接管的路由 / 排除的路由（CIDR，IPv4 与 IPv6）和跳过代理列表都可编辑，默认值就是以前写死在扩展里的值，可一键恢复；无效的行标出并禁止保存。
- **按需连接**：新增「受信任的 Wi-Fi」——在这些 SSID 下断开（NEOnDemandRule ssidMatch，区分大小写），适用于「始终」和「仅 Wi-Fi」。
- **局域网共享**：显示本机 Wi-Fi / 个人热点的 IP:端口和子网，一键复制；可选用户名 + 密码（mihomo `authentication`，本机自己的系统代理免认证）；「仅允许局域网设备」（`lan-allowed-ips` = 10/8、172.16/12、192.168/16、链路本地、IPv6 ULA、本机）默认开启。iOS 可能在锁屏或 App 长时间在后台时挂起网络扩展，共享会中断；只在可信网络开启。
- **重置 VPN 配置**：断开、从系统删除本 App 的 VPN 配置并重建（iOS 会再次询问），配置文件和设置不受影响。

### DNS：本地映射与真实 IP 域名（更多 → DNS）

- **本地 DNS 映射**（mihomo `hosts:`）：域名 / `+.后缀` / `*.通配` → 一个或多个 IP，或一个域名；可逐条停用。与配置文件自带的 hosts 合并，同名以这里为准。
- **真实 IP 域名**（加入 `fake-ip-filter`）：解析为真实 IP 而不是 Fake-IP，适合 STUN、游戏、局域网服务。与配置文件的列表合并；Fake-IP 过滤为白名单模式时不生效（页面会提示）。
- 两者存在我们自己的 `localdns.json`，不改配置文件，不依赖「使用自定义 DNS」开关；已加入备份与诊断包。

### 策略页

- **排序**：配置顺序 / 按延迟 / 按名称；「测速后自动排序」开启时测完才重新排，测速过程中节点不跳动。
- **策略组图标**：读取配置里 proxy-groups 的 `icon:`；导入 Quantumult X 时 `img-url=`、Surge / Loon 的 `icon-url=`（仅 http/https 图片）转为 `icon:`。每个组可以长按图标或在展开后点「图标」更换：粘贴图片地址，或从 Koolson/Qure（Qure Color）、Orz-3/mini、Semporia/Hand-Painted 图标库挑选（按 JSON 索引经 jsDelivr 镜像加载）。你的选择存在 `group-icons.json`（我们的覆写存储），不改配置文件；图片缩放后缓存在 App Group 的 `icon-cache/`，加载失败回退到 SF Symbol。图标同时显示在策略页和首页策略卡片。

### 首页

- 头部改为出口位置优先：国旗 + 地区（大字），下面一行时区 · ASN · IP（小字），右侧是普通开关（无发光、无强调色填充）；下方一行状态 · 运行时长 · 当前配置。轻点刷新，长按复制。
- 连接后显示最多 4 张策略卡片：组图标、组名和解析后的链路（如 `节点选择 ➤ 🇯🇵 东京 01`）及延迟，点进去可直接切换节点。其余保持精简。

### 连接分析（更多 → 工具与数据 → 连接分析）

- Egern 式分析页（不在首页）：全部 / 活跃连接数，各策略流量（堆叠条 + 图例），规则命中次数（环形卡片，可查看全部），主机名流量排行（可搜索）。
- 数据来自 App 本来就在轮询的 `/connections`，只在 App 里累计，网络扩展的内存不受影响；从本次连接开始统计，断开清零。

### 小组件与控制中心开关（单独的 IPA）

- Release 里有两个 IPA：`Mihomo-<版本>-build<N>-unsigned.ipa`（与以前一样，只含主程序和隧道扩展）和 `Mihomo-<版本>-build<N>-widget-unsigned.ipa`（另含小组件扩展）。另附 `widget.entitlements`。
- 小组件扩展 Bundle ID = 主 ID + `.widget`（与隧道 `.tunnel` 同一规则），App Group 运行时解析（与主程序、隧道相同），所以用同一个覆盖三者的显式 App ID 描述文件重签即可，重签工具会处理扩展。
- 内容：连接状态、当前策略组 / 节点、连接 / 断开按钮（iOS 17+ 交互式小组件，主屏小 / 中尺寸与锁屏）；iOS 18+ 控制中心开关。开关直接用公开的 NETunnelProviderManager，与 App 内的规则一致（手动连接恢复按需连接、手动断开暂停按需连接、不以安全模式启动）。

### 测速地址

- 预设增至 10 个，每个带简短名称：Google (gstatic)、Cloudflare、Apple、华为 (HTTP)、Google (HTTP)、Google、Cloudflare (HTTP)、Apple Captive、Microsoft、国内 vivo（适合测直连组）。

### 其他

- App 图标：默认、石墨、极光三个深色图标（`setAlternateIconName`）。
- 未做：实时活动、按 SSID 切换策略组、「仅在这些 Wi-Fi 下连接」、共享动态内核库（见 v0.7.1 计划）。

## v0.6.1 要点（真机测试修复）

第一次真机测试（iPhone 16 Pro，iOS 18.7）发现的问题，这一版只修这些：

- **连接时策略页每个节点都显示「超时」，但节点其实能用。** 根因：内核对使用默认测速地址的策略组在 `/proxies` 里返回空的 `testUrl`，App 把这个空地址传给 `/group/{name}/delay`，内核解析不了，于是每个节点都失败。现在连接时测速一律经由内核（`/group/{name}/delay`、`/proxies/{name}/delay`）并使用「更多 → 测速」里的地址和超时；只有未连接时才从本机离线测速（同样用这个地址）。策略组名和节点名（emoji、空格、斜杠等）在路径和查询参数里都严格百分号编码。
- **新增「更多 → 测速」**：预设地址（gstatic、Cloudflare、Apple、华为 hicloud）或自定义地址（必须是 http/https 完整地址），超时默认 5 秒（1–30 秒），以及「健康检查也使用此地址」开关（默认关闭；开启后自动选择 / 故障转移组和节点集的健康检查统一改用该地址）。
- **扩展内存贴着上限跑。** 真机诊断包里，内存上限 40 MB 时扩展常驻 38–40 MB，启动后不到 1 秒就到 44–45 MB，持续报 critical 压力。现在 Go 软上限默认 26 MB（可调 20–30 MB，超出范围回到默认），GOGC 75，启动时限制并行与更积极回收（测试中常驻堆峰值 31.9 → 19 MB）；内存守护按占用分级：44 MB 以下只记录压力，40/44 MB 释放内存，47 MB 或可用内存少于 3 MB 时关闭最旧的 25% 连接，带冷却时间。
- **UDP 443 走了直连。** 根因：mihomo 匹配到的规则如果指向不支持 UDP 的节点，会跳过这条规则继续往下找，最后找不到就直接 DIRECT（连 MATCH 之后也是）。于是 QUIC 绕过了用户的分流规则，在国内要么连不上、要么泄露。现在规则末尾追加 `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`：这类 QUIC 被拒绝后，App 会回落到 TCP，按规则走代理；其他 UDP 行为不变。
- **断开原因**：扩展记录系统给出的停止原因（例如「VPN 配置被关闭」），在「诊断」和诊断包里显示。
- **首页**：连接后状态卡片不再用强调色填充和光晕，和其他卡片同样的样式，只保留状态文字和一个小圆点。
- 引擎监听的竞态修复；新增字符串已翻译为 6 种语言。

## v0.6 要点（质量轮）

这一轮不加大功能，目标是：装上就能用、出问题能马上知道为什么、真机反馈一步到位。

### 导出诊断包（更多 → 诊断 → 导出诊断包）

一键生成一个 zip，通过系统分享面板发出去（也可以「复制为文本」贴进聊天）：

| 文件 | 内容 |
| --- | --- |
| `info.txt` | App / 隧道扩展 / 内核版本、iOS 与机型、语言、Bundle ID、App Group（来源、容器是否可用、描述文件里的组）、VPN 状态与最近错误、扩展当前内存、连接方式 / DNS / MTU / 内存上限 / 安全模式等开关 |
| `startup-log.txt` | 启动阶段日志（本次 + 上一次） |
| `last-error.txt` | 扩展最近一次写下的失败原因 |
| `core-log.txt` | 内核最近 400 行日志（扩展里的环形缓冲，每 30 秒、停止和启动失败时落盘，所以被系统杀掉后也留得下来） |
| `memory.txt` | 扩展内存采样：每 10 秒一条（最多 30 分钟），footprint、可用内存、Go 堆、goroutine、连接数、脚本运行时数量 |
| `config-effective.yaml` / `config-next-start.yaml` | 上次启动实际使用的配置 / 下次连接会生成的配置 |
| `modules.txt` | 重写与脚本、MitM 开关；每个模块的格式、启用状态、贡献的重写 / 主机名 / 定时任务 / 面板 / 内核规则数量和解析错误 |
| `settings/` | 覆写、DNS、自定义规则、订阅处理、智能选择、资源状态、配置列表 |

**全部脱敏**（Go `bridge/redact.go`，有单元测试）：服务器地址 / SNI / Host、密码、UUID、各种密钥（WireGuard、Reality、PSK）、`authentication`、控制器密钥、订阅链接和节点集 URL 整条替换；其他 URL 去掉账号、查询参数和像令牌的路径段；日志里出现过的这些值同样被替换，另外替换 UUID、`password=` / `token=` 之类、Bearer 令牌，公网 IPv4 只保留前两段。节点名、协议、端口、策略组和规则保留，方便看问题。

### 启动更稳、失败说中文

- 内核启动包了一层 panic 拦截：配置解析里出现的崩溃变成一条错误，扩展不会直接退出。
- 内核的英文错误前面加上中文原因（YAML 格式、策略组引用不存在、节点参数缺失、规则集 / 节点集下载失败、地理数据库缺失、端口被占用……），原文保留在后面。
- 启动前检查配置需要的地理数据库是否在位，缺失写进启动日志。
- NetworkExtension 的错误码（拒绝添加 VPN、配置被停用、签名缺少权限……）翻译成中文；App Group 不可用时直接在首页说明，不再去启动必然失败的扩展。
- App 与扩展之间的消息都有超时（扩展卡住时界面不会跟着卡住）；去掉了所有强制解包。
- **安全模式**：启动失败后，弹窗和首页都提供「以安全模式连接」——只用配置文件本身连接，暂停模块、重写、脚本、MitM、自定义规则和智能选择，用来判断问题出在配置还是扩展功能。安全模式运行时首页有一张卡片，点「恢复正常连接」即回到正常模式；手动打开开关也总是正常模式。

### 首次使用引导

第一次打开（还没有任何配置时）出现三步引导，每步都可跳过：导入配置（订阅链接或剪贴板）→ 允许添加 VPN 配置 → MitM 证书（可选，生成并通过 Safari 安装，附信任步骤）。之后可在 更多 → 新手引导 再看一次。

### 界面一致性

- 统一的空状态（图标 + 标题 + 一句说明）、错误行和加载行，所有列表与卡片页面共用。
- 等宽日志、角标等固定字号改为跟随「动态字体」缩放（默认大小不变）。
- 术语统一：`scripts/term_audit.py` 检查六种语言里「配置 / 节点 / 订阅 / 重写 / 规则集」等只有一个叫法；繁体中文修正 OpenCC 的用词（腳本、延伸功能、全域、面板），`i18n_sync.py` 生成繁体时自动套用。
- 俄语 / 日语里过长的分段标签与固定宽度控件已调整（日志级别、统计页时间范围、TCP 工具）。

### 扩展内存

- MitM 请求抓取：除了每条 32 KB 的上限，整个环形缓冲的内容总量限制在 4 MB；超出时最旧的记录先丢掉内容（保留请求行和头部），之前最坏情况是 12.8 MB。内容被丢弃的请求不能重放（会说明原因）。
- 脚本运行时：每次执行一个 goja 运行时、执行完即释放（定时器停止、迟到的回调看到已取消的上下文直接退出），`memory.txt` 记录存活数量；测试确认 20 次执行后为 0 且没有泄漏 goroutine。
- 定时脚本不会重叠：同一任务上一次还在跑时新的触发直接跳过。
- 面板只在看得见时刷新：扩展只在 App 最近显示过面板（面板页打开期间每 30 秒拉取一次）时按 `update-interval` 自动刷新，App 在后台时不跑任何面板脚本。
- 内核日志 / 内存采样的环形缓冲有上限（400 行 × 600 字节、180 条）。上述上限都有 Go 测试，抓取缓冲另有基准测试。

### Egern 原生脚本

`export default async function(ctx)` 脚本通过一层很薄的适配运行（`bridge/mitm/egernadapter.go`）：把导出改成本地函数，用现有的 Surge 兼容接口拼出 `ctx`，再把返回值交给 `$done`。支持 `ctx.request` / `ctx.response`（`text()` / `json()` / `arrayBuffer()`，大小写不敏感的 Headers）、`ctx.respond()`、`ctx.abort()`、返回 `{url, method, headers, body}` / `{status, headers, body}`、`ctx.http.*`（`timeout`、`policy`、`redirect`、`insecureTls`）、`ctx.storage`（与 `$persistentStore` 共用）、`ctx.notify`、`ctx.lookupIP`、`ctx.compress`、`ctx.env`（模块里脚本的 `env`）、`ctx.cron`、`ctx.script`、`ctx.device`（来自 `$network`）。通用脚本返回的小组件 DSL 转成面板：第一段文字为标题，其余为内容，`backgroundColor` 保留。不支持：`ctx.ssh`、Blob / FormData / ReadableStream 形式的 body、`import` 或多个导出。

## v0.5 要点

### 模块与资源（更多 → 模块与资源）

原来的「模块」页扩展为唯一的资源管理器（没有第二个并列页面），一个列表、按类型筛选（全部 / 模块 / 规则集 / 脚本）：

| 类型 | 来源 | 存在哪里 |
| --- | --- | --- |
| 模块 / 重写集 | URL 或粘贴的 Surge / QX / Loon / Stash / Egern 模块、QX 重写片段、重写列表 | `engine.json` 的 modules（新增 `interval`） |
| 规则集 | 自定义规则里的 `RULE-SET` / `DOMAIN-SET` / QX `filter_remote`，以及启用模块引用的远程规则集（只读，随模块开关） | `rules.json`（每条自带 `interval`） |
| 脚本 | 启用的模块和脚本行引用的远程 `.js` | `engine.json` 的 `scriptResources`（停用 / 覆盖更新间隔） |

每项显示格式角标、上次更新时间（缓存文件的修改时间，所以内核自己的规则集更新和引擎的脚本刷新也会反映出来）、更新间隔、开关和上次失败原因；左滑立即更新，右上角全部更新，打开 App 时自动更新到期的资源（最多每 10 分钟检查一次）。下载由 App 完成（URLSession），字节交给 Go 的 `ResourceStore` 校验后写入内核读取的同一个缓存：模块需能解析出内容、规则集转换为 mihomo 规则（Surge / Loon / Stash / QX 列表与 Egern YAML 规则集），拿到网页（失效链接 / 需要登录）时不会覆盖旧文件。停用一个脚本后，引用它的规则、定时任务和面板都不再运行，模块本身保持启用。

### Egern 模块

Egern YAML 模块是又一个边缘解析器（`bridge/mitm/egern.go`），翻译为与其他格式相同的内部模型：

| Egern | 翻译为 |
| --- | --- |
| `name` / `description`、`compat_arguments`（`{{{参数}}}` 替换，布尔值显示为开关）、`compat_arguments_desc` | 模块名、说明、模块详情里的参数 |
| `rules`（domain / domain_suffix / domain_keyword / domain_regex / domain_wildcard / ip_cidr(6) / geoip / asn / url_regex / dest_port / protocol / rule_set / and / or / not，`no_resolve`） | 内核规则（`url_regex` + REJECT 转为 URL 重写；远程 `rule_set` 进入资源管理器，Egern YAML 规则集会被转换） |
| `url_rewrites`（重定向 / header 模式 / `http://reject-*`）、`header_rewrites`（add / replace / delete）、`body_rewrites`（request/response `_regex` / `_jq`）、`map_locals` | 重写规则 |
| `scriptings`（http_request / http_response / schedule / generic / network，`arguments._compat.$argument`、`body_required`、`binary_body`、`max_size`、`timeout`、`update_interval`、`disabled`） | 脚本与定时 / 事件 / 通用任务 |
| `mitm.hostnames`（列表或 includes / excludes） | MitM 主机名 |
| `widgets` | 面板（由同名或 `script_name` 指定的通用脚本通过 `$done({title, content})` 填充） |

报告为不支持：`dns`、`http_captures`、`bypass_tunnel_proxy`、`real_ip_domains`、`env_schema`、ssid / bssid / cellular / user_agent 规则。社区里由 Surge 模块转换来的 Egern 模块用的是兼容写法（`_compat.$argument`），可以直接运行；Egern 原生 `export default async function(ctx)` 脚本从 v0.6 起通过 ctx 适配层运行（见「v0.6 要点」）。

### `$httpAPI`（Surge）

脚本可调用 `$httpAPI(method, path, body, callback)`：`GET /v1/policies`、`GET /v1/policy_groups`、`GET /v1/policy_groups/select?group_name=`、`POST /v1/policy_groups/select {group_name, policy}`、`GET|POST /v1/outbound {mode: direct|proxy|rule}`、`GET /v1/profiles/current`、`POST /v1/profiles/reload`。其他路径回调 `{error}` 并记录日志。Surge `type=dns` / `type=rule` 脚本需要挂进 mihomo 的 DNS 解析和规则匹配热路径（每个连接同步跑 JS），本轮评估后不做。

### 智能选择（自动 / 故障转移组）

策略页展开 url-test 或 fallback 组，可打开「智能选择」（标「智能」角标）。它是组上的一个选项而不是新组类型，配置文件保持原样：组照常按配置里的 url / interval 做 mihomo 健康检查，扩展每 30 秒用最近 10 次检查结果打分（最近 5 次成功的加权平均延迟 ×（1 + 2 × 失败率），最后一次失败 ×2，不可用 ×4），通过组自身的「固定」机制选中得分最好的节点；只有新节点明显更好（低于当前 85%）才切换，节点失效时 mihomo 立即切走。设置按配置保存在 `mihomo/groups.json`，状态见控制器 `GET /smart`。

### iPad

`TARGETED_DEVICE_FAMILY` 改为 iPhone + iPad。常规宽度用 `NavigationSplitView`：侧边栏是首页 / 策略 / 请求 / 配置 / 更多和连接状态，右侧是同一套页面；iPad 支持四个方向和分屏。iPhone 仍是竖屏 + 底部标签栏。

### 从其他 App 导入（不加分享扩展）

决定：**本轮不做 Share / Action 扩展**。第三个 target 需要第三个 Bundle ID（`com.astemo6.mihomo.share`）和对应的描述文件，用户购买的描述文件通常只覆盖主程序和隧道两个 ID，重签后扩展会失效甚至导致安装失败。改为两个不需要新描述文件的入口：

- 文档类型：`.sgmodule` `.plugin` `.stoverride` `.module` `.snippet` `.conf` `.list` `.yaml` 和纯文本都能「用 Mihomo 打开」/「拷贝到 Mihomo」；`.yaml` 会识别 Egern / Stash 模块，文本会识别订阅链接、配置、模块和节点链接（节点进入「手动节点」）。
- 粘贴横幅：App 回到前台且剪贴板在别处被改过时，顶部出现一条横幅，点系统的「粘贴」按钮（`PasteButton`，iOS 不会弹出粘贴授权提示）才读取并导入；15 秒后自动消失。

### QUIC / HTTP3

非 MitM 流量本来就允许 QUIC。MitM 页新增「QUIC（HTTP/3）」：默认「仅阻断 MitM 主机」（回落到 TCP 才能解密），可把个别 MitM 主机加入「允许 QUIC」列表（它们的 HTTP/3 不再被解密），或选「全部阻断」让所有 App 回落 TCP（不开 MitM 也生效）。

### 多语言

新增日本語、한국어、Русский（共 6 种：简体中文源语言、繁體中文、English、日、韩、俄），都在 `App/Localizable.xcstrings`。`scripts/i18n_sync.py` 现在除了同步编译器提取的键外，还支持 `--export <lang> out.tsv`（导出未翻译的键和英文）与 `--import <lang> in.tsv`（导入翻译）。Go 侧返回的错误信息仍为中文。

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

- 按 SSID 切换策略：需要 `com.apple.developer.networking.wifi-info`（还要定位授权）；尚未实现，`$network.wifi.ssid` 恒为 null。按 SSID 自动断开（受信任的 Wi-Fi）由系统按需规则完成，不需要这项权限。
- 主 App 去掉 Libmihomo 以缩小 IPA：离线校验 / 导入 / 离线策略页 / 预览都依赖内核解析，换成更轻的 Go 库几乎省不下（解析节点就要链接全部协议）；可行的方案是把 Libmihomo 包成一个动态库 framework 由 App 和扩展共用（IPA 预计少 40% 左右），但扩展里 Go 运行时以动态库加载无法在 CI 上验证，风险是隧道无法启动，所以留到能真机测试时再做。
- 日 / 韩 / 俄语（已在 v0.5 完成）。

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

入口：更多 → 模块、重写与 MitM（v0.7 起「重写」即「本地模块」，可用表单编辑）。这些页面共用一个「启用重写与脚本」总开关；HTTPS 解密另有独立开关。全部关闭时内核不会加载 HTTP 引擎，不额外占用内存。

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
