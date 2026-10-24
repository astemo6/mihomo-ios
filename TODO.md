# Tern 待办与分工

更新：2026-10-24。按「工作线」分工：每条线有固定负责人和文件范围，别人不碰这条线的文件，避免重复和冲突。

## 怎么领

1. 一条线只认领一个负责人。在「分工总表」把「待认领」改成你的名字，推 `main` 时带 `[skip ci]`。
2. 先认领再写代码：从对应基线切分支 `feat/<线>-<主题>` 或 `fix/<线>-<主题>`，马上推一个空提交占位，免得两人做同一件事。
3. 只改自己那条线「拥有的文件」。确实要动别的线的文件，先在对应条目下留言，由该线负责人改或同意后再改。
4. 做完：在条目里填提交号，状态改 ✅，交给 A 线合进集成分支。只有 A 线推 `main`、发版。

## 分工总表

| 线 | 内容 | 负责人 | 拥有的文件 | 基线分支 | 何时开始 |
|---|---|---|---|---|---|
| A | v0.19.22 集成、CI、发版；原生 MitM 的 Go 侧 | 维护者（Hark） | 集成分支 `release/0.19.17`、`test/home-egern-v2`、`CHANGELOG.md`、版本号、`bridge/**` | — | 进行中 |
| B | 原生 MitM / 重写 / 脚本，拆成 B1–B10 十个类别，各自认领 | 见 B 线表 | 见 B 线表 | `feat/native-mitm` | B4 现在可做，其余等 0.19.22 发版 |
| C | 真机验证（不写代码） | 待认领 | 只提 Issue / 贴日志 | 正式版 / TestFlight | 0.19.22 发版后 |
| D | 界面与文案小修 | 待认领 | `App/Views/**`、`App/Localizable.xcstrings`（文案只此一线改） | 0.19.22 发版后的 `main` | 0.19.22 发版后 |
| E | 隧道性能优化 | 待认领 | `PacketTunnel/**`（B 线文件除外）、Sub-Store 相关 | 0.19.22 发版后的 `main` | 0.19.22 发版后 |
| F | CI 与自动化 | 待认领 | `.github/workflows/**`、`scripts/**` | `main` | 现在可开始 |

说明：0.19.22 正在集成，`App/`、`PacketTunnel/`、`bridge/` 冲突风险很高，所以 B / D / E 等发版后再动；F 和 A 不重叠，现在就能做。

## A 线：v0.19.22（维护者，进行中，别人勿动）

原则：所有功能和 CI 全绿才发布，不发半成品。8 个分支已合入集成分支（87c90f6），正在跑唯一一套全量 CI。

| # | 事项 | 提交 | 状态 |
|---|---|---|---|
| 1 | 喜马拉雅自动断连：脚本有界准入队列、断开即释放、内存紧张原样放行 | 32431dc, 17598a4 | 已合入，等 CI |
| 2 | YouTube 去广告失效：尊重 `max-size` / `-1` / `binary-body-mode`，动态 body 预算，大 body 串行 | 同上 | 已合入，等 CI |
| 3 | JavaScriptCore 默认脚本引擎，失败/超时/wedge 自动回退 goja | 15b1ea4 | 87c90f6 一致性 37/37 绿（goja 1285 ms / JSC 2061 ms，stops 1，无 wedge），等 072f77a 全量 CI |
| 4 | mihomo v1.19.33 | 21d0699 | 已合入，等 CI |
| 5 | 设置热应用 + 高级设置 → 网络 → Tailscale | c1fbb6a | 已合入，等 CI |
| 6 | Final 策略、配置规则编辑/停用/删除/恢复，「分流规则」 | 3f6faef | test91 Final 选择页「恢复配置原样」找不到 → 072f77a 移到顶部，等 CI |
| 7 | 界面审查（标题、旧路径、通知权限、搜索入口） | 51e19db | 已合入，等 CI |
| 8 | 首页下拉卡顿 | 365247b | PinnedHeaderScrollTests 4/4 绿（87c90f6），等 072f77a 全量 CI |
| 9 | 更多页行高统一 | 029a983 | test91_RowHeightParity 绿（87c90f6），等 072f77a 全量 CI |
| 10 | 既有 UI 测试失败（test03/05/09/11/12/25/33/40/58）；可莉分类名翻译；订阅页脚「左滑删除或编辑」 | c48f714, b12faaf, 87c90f6 | ✅ 87c90f6 中英 light:1/3、dark 全绿，等 072f77a 复核 |
| 11 | `bridge.Start` 数据竞争 | 集成分支 | `-race` ours 0（竞争已消失）；测试 hook 二次 close panic → 4b2ea57，等 CI |
| 12 | Go brotli 读取器接受截断的 br 数据（一行修复） | — | 待办 |
| 13 | 原生 MitM Go 侧（body 通道、TLS 交接、relay）已在 `feat/native-mitm` 4fec47b，发版后推送并交给 B 线 | 4fec47b | 本地完成 |

## B 线：原生 MitM / 重写 / 脚本（按类别拆分，可多人并行）

目标：mihomo（Go）继续管协议、规则、DNS、TUN；把最吃内存的 MitM → 重写 → 脚本热路径搬到扩展里的原生 Swift + JavaScriptCore，任何一步失败自动回到 Go 路径。代码在 `feat/native-mitm`（4fec47b，0.19.22 发版后由 A 线推上来）；设计文档同时放到 `docs/native-mitm-design.md`。

每个类别一个负责人，只改「文件」列里的文件；跨类别改接口先在条目下留言。「依赖」为空的现在就能做（不需要等 0.19.22，也不占 CI）。

| 类别 | 任务 | 文件 | 依赖 | 估算 | 真机 | 负责人 | 状态 |
|---|---|---|---|---|---|---|---|
| B1 解压与 body 存储（Swift） | `NativeBodyStore` 首次编译、`NativeBodyStoreTests` 通过；gzip 多段、zlib/raw deflate、brotli（`COMPRESSION_BROTLI`）流式解码 | `PacketTunnel/NativeBodyStore.swift`、`UnitTests/NativeBody*` | 分支推上来 | 0.5–1 天 | 否 | 维护者（Hark） | 代码已写，未编译 |
| B2 JSC 接入（Swift） | `JSCScriptEngine` 读原生 blob、生成 UTF-8 文本、≥64 KB 结果原生存放 | `PacketTunnel/JSCScriptEngine.swift` | B1 | 0.5 天 | 否 | 维护者（Hark） | 代码已写，未编译 |
| B3 Go 侧通道与回退 | body 通道、预算/准入语义、失败回退与熔断；Go brotli 截断数据误收（一行修复） | `bridge/mitm/nativelane.go`、`handler_lane.go`、`bridge/nativebodies.go` | 无 | 0.5 天 | 否 | 维护者（A 线） | 已完成，待 `-race` |
| B4 兼容语料 | 把 QX 重写清单与 Surge / Loon / Egern 语法样例做成回放用例，覆盖 body 通道（JSC 与 goja 结果一致） | `UnitTests/ScriptEngineConformance.json`、`bridge/mitm/testdata/**` | 无 | 0.5–1 天 | 否 | astemo6 | ✅ `feat/b4-conformance` 0f5ffe3：语料 37→49 条（QX/Surge/Loon/Egern body 通道 12 条）+ testdata 四方言样本；TestEngineConformance 与 mitm 整包本地全绿（goja + native 替身），JSC 侧待 CI 的 ScriptEngineConformanceTests 复核 |
| B5 第一期真机验证 | YouTube / 小红书 / 喜马拉雅各 5 分钟内存曲线；iOS 17 与 18 br 解码；熔断不触发；1 小时后原生 body 计数归零 | 只提 Issue（与 C 线合作） | B1、B2 | 1–2 天 | 是 | 待认领 | 待办 |
| B6 Go flow API | 规则匹配与脚本语义留在 Go，Swift 只负责分帧和搬数据 | `bridge/mitm/flow*.go` | 分支推上来（目前只有设计） | 3–5 天 | 否 | 维护者（Hark） | 待办 |
| B7 TLS 终止（Swift） | 按主机签发叶证书（PKCS#12，iOS 17/18 导入验证）、证书缓存、握手失败上报证书固定逻辑 | `PacketTunnel/NativeMitM/TLS*.swift` | B6 | 2–3 天 | 是 | astemo6 | 骨架 |
| B8 HTTP/1.1 解析与上游（Swift） | 请求/响应头重写、分块传输、通过 Go `relay.go` 回连 mihomo | `PacketTunnel/NativeMitM/HTTP*.swift`、`Upstream*.swift` | B6 | 3–5 天 | 是 | astemo6 | 骨架 |
| B9 边界情况 | WebSocket、网络切换、只报 h2 的客户端（gRPC）留在 Go | `PacketTunnel/NativeMitM/**`（与 B7/B8 负责人协调） | B7、B8 | 2–3 天 | 是 | astemo6 | 待办 |
| B10 第二期对比 | 第二期与 Go 路径的内存对比，决定是否上线 | 只提 Issue | B7–B9 | 1 天 | 是 | 待认领 | 待办 |

顺序：第一期（B1–B5）大约 3–5 天就能上线，拿到大部分内存收益（3 MB gzip body 在 Go 堆里从 +4.2–6.5 MB 降到 +0.6–1.6 MB）。第二期（B6–B10）预计 2–3 周，收益约 1–3 MB，先看 B5 实测再决定做不做。现在就能开工的：B4（B3 由维护者收尾）。

## C 线：真机验证（待认领，不写代码）

结果请提 Issue，附 诊断 → 隧道内存 截图和诊断日志。

| # | 检查 | 状态 |
|---|---|---|
| 1 | 喜马拉雅打开 1 分钟不断连，扩展内存曲线 | 待办 |
| 2 | YouTube 无广告（`youtube.response` 未被跳过） | 待办 |
| 3 | 小红书脚本耗时、脚本日志里显示的引擎（JSC / goja） | 待办 |
| 4 | 首页下拉手感、更多页行高 | 待办 |
| 5 | 切开关后不再整体重载（热应用），日志 "memory shed" / "reload memory" 后内存回落 | 待办 |
| 6 | `出口信息来源` 测试失败时显示的原因 | 待办 |

## D 线：界面与文案（待认领，0.19.22 发版后开始）

文案改动必须 6 种语言（en / ja / ko / ru / zh-Hans，zh-Hant 由 OpenCC s2twp 生成），`scripts/term_audit.py` 保持 `inconsistent: 0`，`Localizable.xcstrings` 结尾不留换行。

| # | 事项 | 状态 |
|---|---|---|
| 1 | 「手动节点」与「本地节点」统一用词 | 待办 |
| 2 | 高级设置副标题补「隧道」 | 待办 |
| 3 | 面板刷新失败时给出提示（目前静默） | 待办 |

## E 线：隧道性能（待认领，0.19.22 发版后开始）

| # | 事项 | 状态 |
|---|---|---|
| 1 | 大 body 锁等待期间占用脚本槽位（最多拖慢其他脚本 3 s） | 待办 |
| 2 | PacketFlowBridge 每个上行包单独分配 Data，可改 sendmsg 双 iovec | 待办 |
| 3 | TrafficSplit 启动时在主线程同步读历史文件 | 待办 |
| 4 | 冷启动 / 停止隧道时 `stopTunnel` 未清 `traffic` | 待办 |
| 5 | Sub-Store 编译内存偏高 | 待办 |

注意：E 线 #1 的代码在 `bridge/mitm/`，属于 A 线文件，做之前先留言，由 A 线确认接口。

## F 线：CI 与自动化（待认领，现在可开始）

| # | 事项 | 状态 |
|---|---|---|
| 1 | `core-update.yml` 开出的内核升级分支，CI 全绿后自动打包；发版仍需人工点头 | 待办 |
| 2 | macOS runner 排队：同一提交去重、失败只重跑失败 job | 待办 |
| 3 | 推 `feat/**` 不触发 `checks.yml`（目前任何推送都跑，影响占位分支） | 待办 |

## 通用约定

- 测试：推 `test/**` 跑 Self-test（`[shard:all]` 全量 UI）与 Checks；iOS 编译用 `ios.yml` 的 `workflow_dispatch` + `build_only`。同一提交不重复派 run。
- 推 `main` 一律带 `[skip ci]`，否则会触发发版（只有 A 线发版）。
- 重写/脚本兼容必须通用（Surge / Loon / QX / Egern），不能针对单个脚本或 URL 打补丁。
- CHANGELOG「未发布」条目用中文，由 A 线合并时统一写。
- 不改首页策略卡片 / 圆环下钻逻辑；保留「FaceTime 走代理」设置。
- 只展示真实数据；根页面不观察 DashboardModel；重活不上主线程。
