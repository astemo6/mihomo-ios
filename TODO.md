# Tern 待办事项

更新：2026-10-24。领取任务请在「负责人」填名字，并在对应分支开发。做完把状态改成 ✅ 并写上提交。

## 协作约定

- 集成分支：`release/0.19.17`（推送到 `test/home-egern-v2` 跑 CI）。功能分支从它切出：`feat/<主题>` / `fix/<主题>`，完成后合回集成分支。
- 只有维护者推 `main` 并发版；中间推 `main` 一律带 `[skip ci]`，否则会触发发版。
- 测试：推到 `test/**` 跑 Self-test（`[shard:all]` 跑全量 UI 矩阵）与 Checks；iOS 编译用 `ios.yml` 的 `workflow_dispatch` + `build_only`。macOS runner 很紧张，同一提交不要重复派 run，失败 job 用 rerun-failed-jobs。
- 重写/脚本兼容必须通用（Surge / Loon / QX / Egern），不能针对单个脚本或 URL 打补丁。
- 文案 6 种语言（en / ja / ko / ru / zh-Hans，zh-Hant 由 OpenCC s2twp 生成）；`scripts/term_audit.py` 必须保持 `inconsistent: 0`；`Localizable.xcstrings` 结尾不留换行。
- CHANGELOG「未发布」条目用中文。
- 不改首页策略卡片 / 圆环下钻逻辑；保留「FaceTime 走代理」设置。
- 只展示真实数据；根页面不观察 DashboardModel；重活不上主线程。
- Android 只推 `android/**`。

## P0：v0.19.22 发布（进行中）

原则：所有功能和 CI 全绿才发布，不发半成品。

| # | 事项 | 分支 / 提交 | 状态 | 负责人 |
|---|---|---|---|---|
| 1 | 喜马拉雅自动断连：脚本有界准入队列、客户端断开即释放、内存紧张时原样放行 | `fix/code-review` 32431dc, 17598a4 | 代码完成，待集成 CI | 维护者 |
| 2 | YouTube 去广告失效：尊重 `max-size`（`-1` 不限）/ `binary-body-mode`，否则按剩余内存动态预算（≤8 MB），大 body 一次只处理一个，减少拷贝 | 同上 | 代码完成，待集成 CI | 维护者 |
| 3 | JavaScriptCore 作为默认脚本引擎（无开关），失败/超时/wedge 自动回退 goja，脚本日志记录实际引擎 | `feat/jsc-engine` 15b1ea4 | 分支 CI 绿，待集成 | 维护者 |
| 4 | 内核升级 mihomo v1.19.33 | `feat/mihomo-1.19.33` 21d0699 | 待集成 CI | 维护者 |
| 5 | 开关类设置热应用（ReloadHot）+ 高级设置 → 网络 → Tailscale 页 | `feat/hot-apply` c1fbb6a | 待集成 CI | 维护者 |
| 6 | Final 策略可改；配置规则可编辑 / 停用 / 删除 / 恢复；标题统一「分流规则」 | `feat/rule-edit` 3f6faef | 待集成 CI | 维护者 |
| 7 | 界面审查：页面标题与入口一致、旧路径文案、通知权限状态、搜索入口补全 | `fix/ui-audit` 51e19db | 待集成 CI | 维护者 |
| 8 | 首页下拉卡顿（顶部栏每帧重绘 + 下拉自测量反馈环） | `fix/home-pull-jank` 365247b | 待集成 CI | 维护者 |
| 9 | 更多页行高与工具页统一（TernRowMetrics） | `fix/more-row-height` 029a983 | 待集成 CI | 维护者 |
| 10 | 修既有 UI 测试失败：test33 左滑删除重写、test40「筛选节点」、test03 可莉分类名未翻译、test05 Hysteria2 保存按钮、test09 测速开关 | 集成分支 | 进行中 | 维护者 |
| 11 | 集成分支 Self-test go job 失败（疑似 bridge.Start 数据竞争）修复 | 集成分支 | 进行中 | 维护者 |
| 12 | 发布前真机验证：喜马拉雅并发/断开取消、YouTube 去广告、内存曲线（诊断 → 隧道内存）、首页下拉手感、JSC 用时 | — | 待办 | 需真机 |

## P1：原生 MitM / 重写 / 脚本路径（约 2 周）

目标：mihomo（Go）继续负责协议、规则、DNS、TUN，内核更新仍可自动打包；把最吃内存的 MitM → 重写 → 脚本热路径搬到扩展内的原生 Swift + JavaScriptCore。设计文档编写中，完成后放到 `docs/native-mitm-design.md`。

| # | 事项 | 状态 | 负责人 |
|---|---|---|---|
| 1 | 架构设计：连接从 mihomo 交给原生处理器的方式、TLS 终止（按主机签发叶证书）、HTTP/1.1 + HTTP/2、流式解压（gzip / deflate / br） | 进行中 | 维护者 |
| 2 | Go 侧交接接口 + 测试；规则表由 Go 解析后交给原生层 | 进行中 | 可领取 |
| 3 | Swift：TLS 终止与证书缓存 | 待办 | 可领取 |
| 4 | Swift：HTTP/1.1 与 HTTP/2 解析、请求/响应头重写 | 待办 | 可领取 |
| 5 | Swift：body 预算与准入队列（移植 0.19.22 语义：max-size、binary-body-mode、动态预算、单个大 body、断开取消、压力放行） | 待办 | 可领取 |
| 6 | 原生路径任一失败自动回退 Go 路径，日志记录 | 待办 | 可领取 |
| 7 | 兼容测试：`UnitTests/ScriptEngineConformance.json` + QX 重写语料，覆盖 Surge / Loon / QX / Egern | 待办 | 可领取 |
| 8 | 真机内存基准：目标在 NE 50 MB 限制内留足余量 | 待办 | 需真机 |

## P2：自动化与其他

| # | 事项 | 状态 | 负责人 |
|---|---|---|---|
| 1 | 内核自动发版：`core-update.yml` 开出的升级分支 CI 全绿后自动打包发布 | 待办 | 可领取 |
| 2 | Sub-Store 编译内存偏高 | 待办 | 可领取 |
| 3 | 设备日志确认 0.19.21 配置重载后内存回落（"memory shed" / "reload memory" 日志） | 待办 | 需真机 |
| 4 | `出口信息来源` 测试失败时的真实原因（等用户反馈） | 待办 | 需真机 |
| 5 | 优化：大 body 锁等待期间占用脚本槽位（最多拖慢其他脚本 3 s） | 待办 | 可领取 |
| 6 | 优化：PacketFlowBridge 每个上行包单独分配 Data，可改 sendmsg 双 iovec | 待办 | 可领取 |
| 7 | 优化：TrafficSplit 启动时在主线程同步读历史文件 | 待办 | 可领取 |
| 8 | 文案：「手动节点」与「本地节点」统一；高级设置副标题补「隧道」 | 待办 | 可领取 |
| 9 | 面板刷新失败时给出提示（目前静默） | 待办 | 可领取 |
| 10 | 冷启动 / 停止隧道时 `stopTunnel` 未清 `traffic`（无害，顺手修） | 待办 | 可领取 |
| 11 | Android 签名：固定 keystore 存入 Secrets（需仓库所有者确认） | 待办 | 所有者 |
