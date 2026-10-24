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
| B | 原生 MitM 的 Swift 侧（编译、单测、TLS 前端） | 待认领 | `PacketTunnel/NativeBodyStore.swift`、`PacketTunnel/NativeMitM/**`、`PacketTunnel/JSCScriptEngine.swift`、`UnitTests/NativeBody*` | `feat/native-mitm`（0.19.22 发版后由 A 线推上来） | 0.19.22 发版后 |
| C | 真机验证（不写代码） | 待认领 | 只提 Issue / 贴日志 | 正式版 / TestFlight | 0.19.22 发版后 |
| D | 界面与文案小修 | 待认领 | `App/Views/**`、`App/Localizable.xcstrings`（文案只此一线改） | 0.19.22 发版后的 `main` | 0.19.22 发版后 |
| E | 隧道性能优化 | 待认领 | `PacketTunnel/**`（B 线文件除外）、Sub-Store 相关 | 0.19.22 发版后的 `main` | 0.19.22 发版后 |
| F | CI 与自动化 | 待认领 | `.github/workflows/**`、`scripts/**` | `main` | 现在可开始 |
| G | Android | 待认领 | 只推 `android/**`，需求见 `android/main` 分支的 `HANDOFF.md` A0–A3 | `android/main` | 现在可开始 |

说明：0.19.22 正在集成，`App/`、`PacketTunnel/`、`bridge/` 冲突风险很高，所以 B / D / E 等发版后再动；F、G 和 A 不重叠，现在就能做。

## A 线：v0.19.22（维护者，进行中，别人勿动）

原则：所有功能和 CI 全绿才发布，不发半成品。8 个分支已合入集成分支（87c90f6），正在跑唯一一套全量 CI。

| # | 事项 | 提交 | 状态 |
|---|---|---|---|
| 1 | 喜马拉雅自动断连：脚本有界准入队列、断开即释放、内存紧张原样放行 | 32431dc, 17598a4 | 已合入，等 CI |
| 2 | YouTube 去广告失效：尊重 `max-size` / `-1` / `binary-body-mode`，动态 body 预算，大 body 串行 | 同上 | 已合入，等 CI |
| 3 | JavaScriptCore 默认脚本引擎，失败/超时/wedge 自动回退 goja | 15b1ea4 | 已合入，等 CI |
| 4 | mihomo v1.19.33 | 21d0699 | 已合入，等 CI |
| 5 | 设置热应用 + 高级设置 → 网络 → Tailscale | c1fbb6a | 已合入，等 CI |
| 6 | Final 策略、配置规则编辑/停用/删除/恢复，「分流规则」 | 3f6faef | 已合入，等 CI |
| 7 | 界面审查（标题、旧路径、通知权限、搜索入口） | 51e19db | 已合入，等 CI |
| 8 | 首页下拉卡顿 | 365247b | 已合入，等 CI |
| 9 | 更多页行高统一 | 029a983 | 已合入，等 CI |
| 10 | 既有 UI 测试失败（test03/05/09/11/12/25/33/40/58）；可莉分类名翻译；订阅页脚「左滑删除或编辑」 | c48f714, b12faaf, 87c90f6 | 已修，等 CI |
| 11 | `bridge.Start` 数据竞争 | 集成分支 | 已修，等 `-race` |
| 12 | Go brotli 读取器接受截断的 br 数据（一行修复） | — | 待办 |
| 13 | 原生 MitM Go 侧（body 通道、TLS 交接、relay）已在 `feat/native-mitm` 4fec47b，发版后推送并交给 B 线 | 4fec47b | 本地完成 |

## B 线：原生 MitM Swift 侧（待认领，0.19.22 发版后开始）

设计文档发版后放到 `docs/native-mitm-design.md`。Go 侧接口由 A 线维护，要改接口在这里留言。

| # | 事项 | 估算 | 需真机 | 状态 |
|---|---|---|---|---|
| 1 | 第一阶段：`NativeBodyStore.swift` 首次 CI 编译、`NativeBodyStoreTests` 通过（推 `test/native-mitm`，提交信息带 `[unit:NativeBodyStoreTests]`） | 0.5–1 天 | 否 | 待办 |
| 2 | 第一阶段：真机内存与正确性（YouTube / 小红书 / 喜马拉雅各 5 分钟，iOS 17 与 18 的 br 解码，熔断不触发，1 小时后原生 body 计数归零） | 1–2 天 | 是（与 C 线配合） | 待办 |
| 3 | 第二阶段：Swift TLS 前端、HTTP/1.1、上游连接（`PacketTunnel/NativeMitM/**`，目前未加入编译目标）。先看第一阶段实测再决定是否做 | 5–8 天 | 是 | 暂缓 |

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

## G 线：Android（待认领，现在可开始）

只推 `android/**`，需求见 `android/main` 分支的 `HANDOFF.md` A0–A3。固定签名 keystore 存入 Secrets 需仓库所有者确认。

## 通用约定

- 测试：推 `test/**` 跑 Self-test（`[shard:all]` 全量 UI）与 Checks；iOS 编译用 `ios.yml` 的 `workflow_dispatch` + `build_only`。同一提交不重复派 run。
- 推 `main` 一律带 `[skip ci]`，否则会触发发版（只有 A 线发版）。
- 重写/脚本兼容必须通用（Surge / Loon / QX / Egern），不能针对单个脚本或 URL 打补丁。
- CHANGELOG「未发布」条目用中文，由 A 线合并时统一写。
- 不改首页策略卡片 / 圆环下钻逻辑；保留「FaceTime 走代理」设置。
- 只展示真实数据；根页面不观察 DashboardModel；重活不上主线程。
