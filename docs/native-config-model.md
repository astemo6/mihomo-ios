# 原生内核规范配置模型（canonical model）

状态：设计稿（2026-10-24）。用户拍板：原生内核**不受限于 mihomo**——
内部模型按 Quantumult X / Loon / Surge 三家语义的并集自有设计，
mihomo YAML 降为导入格式之一，与 Surge / Loon / QX 的 .conf 平级。

## 1. 原则

1. **导入器架构**：任何来源格式先解析为源无关的规范模型，引擎只消费规范模型。
   新增格式 = 新增一个导入器，引擎零改动。
2. **语义以规范模型为准**：四家语义冲突时，规范模型选更强/更明确的一家并在本文记录；
   导入器负责把源格式语义翻译过来，翻译不了的写进转换报告，不静默丢弃。
3. **未知即报告**：无法映射的段落/参数进 `NCImportReport`（warnings 列表），
   App 侧可展示。属于 B 线的段落（Rewrite/MITM/Script）标注 `skippedNonKernel`。
4. **顺序即语义**：规则自上而下首个命中生效（四家一致）；组内成员顺序保留。

## 2. 规范模型

```swift
struct NCCanonicalConfig {
    var meta: NCMeta                 // 名称、来源格式、导入时间
    var general: NCGeneral           // 模式(rule/global/direct)、IPv6、UDP、嗅探开关、log 级别
    var dns: NCDNSModel              // §3
    var hosts: [NCHostEntry]         // 静态映射/通配/别名 + 按域名指定 DNS
    var nodes: [NCNode]              // 单个代理节点（原 NCProxy 的演进：type + 参数袋）
    var subscriptions: [NCNodeSubscription]  // 节点订阅（QX server_remote / Loon remote proxy / mihomo proxy-provider / Surge policy-path 外部节点）
    var groups: [NCGroup]           // §4
    var ruleSets: [NCRuleSetRef]     // 规则订阅（四家方言，见规则订阅设计）
    var rules: [NCRuleEntry]         // 已解析规则（原 [String] 演进为结构化，保留原文备查）
    var report: NCImportReport
}
```

`NCNode` 保持 `type: String + fields: [String: NCJSONValue]` 参数袋形态——
协议种类开放增长（ss/vmess/vless/trojan/hy2/tuic/wireguard/snell/…），
强类型化每个协议只会让导入器和引擎互相拖累；参数校验在连接器拨号时做。

## 3. DNS 模型（对标三家并集）

```swift
struct NCDNSModel {
    var mode: enum { fakeIP, redirHost, normal }        // Surge 无 fake-ip；QX/Loon 有 dns 劫持+fake 语义
    var fakeIPRange4: CIDR; var fakeIPRange6: CIDR?     // v6 fake（QX/Surge 均支持 v6 场景）
    var alwaysRealIP: [String]                          // Surge always-real-ip ∪ mihomo fake-ip-filter ∪ Loon 排除名单
    var defaultServers: [NCDNSServer]                   // 明文 UDP/TCP
    var encryptedServers: [NCDNSServer]                 // DoH / DoT / DoQ（server 地址串统一解析：https://、tls://、quic://、域名#/接口 等修饰）
    var domainServers: [(domainSuffix, NCDNSServer)]    // 按域名指定上游：QX `server=/d/s`、Surge/Loon [Host] `d = server:x`、mihomo nameserver-policy 归一至此
    var fallback: [NCDNSServer]; var fallbackFilter: NCFallbackFilter  // mihomo 语义（geosite/ipcidr 判定走 fallback）
    var respectRules: Bool                              // DNS 查询本身是否走规则分流（mihomo respect-rules / Surge 行为）
}
```

语义决定：fake-ip 模式下 A/AAAA 均可 fake（有 v6 range 时）；`alwaysRealIP` 命中 →
返回真实解析且不建 fake 映射；按域名上游优先级高于默认与 fallback；
DoQ 列入加密上游一等公民（三家均已支持）。

## 4. 策略组模型

```swift
struct NCGroup {
    var name: String
    var kind: enum { select, urlTest, fallback, loadBalance, external }  // external = 成员来自订阅（Surge 外部策略/QX static+remote）
    var members: [String]            // 节点名/组名/订阅引用
    var url: String; var interval: Int; var tolerance: Int   // 健康检查（url-test/fallback）
    var includeRegex: String?; var excludeRegex: String?      // QX/Loon 订阅节点正则过滤
    var subnetConditions: [NCSubnetCondition]?                // Surge SUBNET：SSID/BSSID/网络类型 → 指定成员
}
```

语义决定：显式选择（select 组用户点选）在所有组类型中优先——沿用现有
NCGroupEngine 已验证行为；load-balance 支持 round-robin 与 consistent-hashing
两种（mihomo 有、Surge 无 → 取并集，源格式没有的导入时不生成）。

## 5. 规则模型

规则条目结构化为 `(type, payload, policy, options)`，类型取四家并集：
DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-WILDCARD / DOMAIN-SET（引用规则集）、
IP-CIDR / IP-CIDR6 / GEOIP / IP-ASN、SRC-IP / SRC-PORT / DST-PORT / IN-PORT、
NETWORK（wifi/cellular/wired）、SUBNET（SSID 条件）、PROTOCOL（TCP/UDP/DOH/QUIC…）、
HOSTNAME-TYPE（IPv4/IPv6/domain）、PROCESS-NAME（iOS 上尽力而为，多为不可得→不命中）、
RULE-SET（引用规则集）、AND / OR / NOT、FINAL/MATCH。
options：`no-resolve`、规则集引用时的 `extended` 标记等。

## 6. 四个导入器映射要点

| 概念 | mihomo YAML | Surge .conf | Loon .conf | QX .conf |
|---|---|---|---|---|
| 节点 | proxies[] | [Proxy] 行 | [Proxy] 行 | [server_local] 行（`ss=…, tag=`） |
| 节点订阅 | proxy-providers | 外部策略 policy-path | [Remote Proxy] | [server_remote]（带 filter 正则） |
| 策略组 | proxy-groups | [Proxy Group] | [Proxy Group] | [policy]（static/url-test/available/round-robin…） |
| 规则 | rules[] | [Rule] | [Rule] | [filter_local] |
| 规则订阅 | rule-providers | RULE-SET / DOMAIN-SET 行 | [Remote Rule] | [filter_remote]（force-policy/tag） |
| DNS | dns: | [General] dns-server/encrypted-dns-server + [Host] | [General]/[Host] | [dns]（server=/doh-server=） |
| Hosts | hosts: | [Host] | [Host] | [host] / dns address= |

节点行语法：Surge/Loon 为 `名 = 类型, 服务器, 端口, k=v…`；QX 为
`类型=服务器:端口, k=v…, tag=名`。协议名归一在导入器内完成，词汇以引擎现有
开关为准（如 SS 的规范名是 `ss`，与 NCConnector 的 case 及 mihomo 导入器一致）。

## 7. 与现有代码的关系

- `NCConfig`（mihomo JSON 形）保留为 **mihomo 导入器的中间产物**，随后映射到规范模型；
  `NativeCoreEngine` 改为消费规范模型。现有 `NCGroupEngine` / `NCRuleMatcher` /
  `NCFakeIPPool` / DNS 转发等按解析后结构工作的代码基本保留，改造集中在配置层。
- Go 侧 `LibmihomoNativeConfigJSON` 导出在规范模型落地后仅服务旧路径，
  YAML 导入器（NCYAML 已就绪）接通后，隧道加载配置不再依赖 Go。
