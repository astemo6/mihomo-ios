# A2 feature2 分支交接（android/a2-data）

本分支在 `android/main` bf68d73 之上，只新增文件，不改共享文件，便于合并。

## 入口

`io.github.astemo6.mihomo.ui.feature2.Feature2Screen(route: String, onBack: () -> Unit)`（`ui/feature2/Feature2Router.kt`）。
路由常量在 `Feature2Routes`：`rulesets`、`dnslog`、`traffic`、`nodesubs`、`groups`、`manualnodes`、`diagnostics`；
`Feature2Routes.titleRes(route)` 给出各页标题的字符串资源，可直接用于设置页按钮。
每页自带顶栏和内部导航（编辑页用 BackHandler），`onBack` 只在离开功能时调用。

## 主分支合并时建议接的几处（都是一行，可选）

1. 导航：在 MainActivity 的屏幕栈里加一个 `FEATURE2(route)`，渲染 `Feature2Screen(route, onBack = pop)`；设置页网格
   「节点 / 分流 / 工具 & 分析」等按钮跳到对应 route（节点订阅 → nodesubs，策略组 → groups，手动节点 → manualnodes，
   规则列表 → rulesets，DNS → dnslog（可替换工具栏的 DNS 占位），流量统计 → traffic，诊断 → diagnostics）。
2. `MihomoApp.onCreate` 里调用 `Feature2Hooks.onAppCreate(this)`：流量历史和 DNS / 拦截日志从应用启动就开始记录
   （不接的话从第一次打开 feature2 页面开始记录）。
3. 回到前台时（`ProfileStore.autoUpdateIfNeeded()` 所在处）调用 `Feature2Hooks.onForeground(context)`：节点订阅按间隔自动更新。
4. 安全模式：iOS 每次正常连接都会把 `overrides.safeMode` 清回 false。Android 的 `MihomoVpnService.startVpn` 目前不清，
   因此用户从诊断页进入安全模式后，要点「恢复正常连接」才会退出。建议主分支在普通连接（磁贴、开关）时写回 `safeMode=false`。

## 各页与数据（与 iOS 同名文件、同字段）

| route | 文件 | 存储 |
|---|---|---|
| rulesets | RuleSetsScreen | `<home>/rules.json`（CustomRule：单行规则与远程列表，桥接 CheckCustomRules / CheckRuleLine / ProfileGroups） |
| dnslog | DnsLogScreen, data/DnsLog | 内存：`/logs?level=debug` 里的 `[DNS]` 行与 `using REJECT` 行；`/dns/query` 查询工具 |
| traffic | TrafficScreen, data/TrafficStats | `filesDir/traffic-history.json`（TrafficTotals 每 30 s，含 Wi-Fi / 蜂窝）、`filesDir/analytics-history.json`（前台时 /connections 增量，按策略 / 域名） |
| nodesubs | NodeSubsScreen, data/NodeSubStore | `<home>/node-subscriptions.json`、`<home>/nodesubs/<id>.yaml`（ProviderStore convert "nodes"）、`<home>/subscriptions.json`（节点处理，SubPreview 实时预览） |
| groups | GroupsScreen | `<home>/group-edits.json`（GroupSpecs / GroupEditCheck）、`<home>/groups.json`（智能选择、前置代理 SetGroupChain / ChainCandidates）、`GET /smart` |
| manualnodes | ManualNodesScreen, NodeForm | `profiles/manual-nodes.yaml`（ManualList / AddText / Upsert / Delete，NodeShareLink，ManualSubscription），`overrides.mergeManual` |
| diagnostics | DiagnosticsScreen, data/Diagnostics, ProbeScreen | WriteDiagnosticBundle → SAF 保存 zip；DiagnosticSummary 复制 / 分享；安全模式连接；节点探测 |

节点探测（data/PolicyProbe）：`PUT /proxies/MIHOMO-PROBE` 选中策略后，OkHttp 经 `127.0.0.1:<ProbePort>`（默认 7899）
发请求；出口 IP（ipinfo.io / ip-api / ipwho.is）和 10 项解锁检测与 iOS 相同，结果存在 `filesDir/probe-results.json`。
入口：手动节点每行的「出口 IP / 解锁检测」，以及诊断页「节点探测」里选任意节点或策略组。

手动节点配置项：ProfileStore 没有按固定 id 新增配置的接口，`ManualNodes.ensureProfile` 直接把 `manual-nodes` 写进
`profiles.json`，再调用 `ProfileStore.init()` 重新加载。合并后可以改成 ProfileStore 自己的方法。

字符串：`res/values*/strings_feature2.xml` 由 `scripts/gen-strings-feature2.py` 生成（简体、English，繁体用 OpenCC s2twp
转换），键名都以 `f2_` 开头。改文案请改脚本里的表再运行。

## 未做 / 限制

- 二维码：没有加扫码依赖（需要改 app/build.gradle.kts）。现在的做法是用系统相机或其他扫码 App 扫描，再把链接粘贴进来；
  导出用分享链接（复制 / 系统分享），没有生成二维码图片。如果要做，可以加 zxing-android-embedded 或 ML Kit code scanner。
- DNS 日志：Fake-IP 模式下大部分查询在本地直接返回 Fake-IP，不会产生上游查询日志，页面上有说明。
  「被拦截的域名」是 REJECT / REJECT-DROP 规则拦下的连接，按域名汇总。iOS 参考代码里没有找到对应页面，这一页是按需求新写的。
- 规则集离线下载（iOS ProviderPlan / ProviderStore 在未连接时由 App 下载）没有做，远程列表在连接后由内核下载。
- 以上都只做了编译检查（`:app:compileDebugKotlin`，对照真实 gobind 绑定），**没有上机验证**。
