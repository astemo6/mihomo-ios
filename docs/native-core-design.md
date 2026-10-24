# 原生内核（NativeCore）设计与契约

创建：2026-10-24。目标：用原生 Swift（控制面）+ C（数据面，后续 lwIP）写一个新内核，
逐步替换 PacketTunnel 里的 mihomo（Go）内核，解决扩展内存平台期 40 MB、余量 ~10 MB、
被 jetsam 杀的问题（实测见 bridge/memshed.go）。App 与 UI 不动。

## 原则

1. **先独立写、后替换**：新内核先作为独立模块长出来，用仓库现有测试语料验收；
   接入时只动 PacketTunnel 启动路径，带开关，启动失败自动回退 `LibmihomoStart`。
2. **mihomo 是规格书 + 对照组**：规则/DNS/策略组/Vision/Reality/嗅探的语义以 mihomo
   实现为准 1:1 复刻；同一配置喂新旧内核做差分测试（沿用 bridge 的 e2e 模式）。
3. **按进程拆替换面**：Swift 侧共调用 131 个 Libmihomo 函数，其中只有约 20–30 个
   属于隧道进程（Start/Reload/Stop、内存、网络变化）；其余约 100 个是 App 进程的
   工具函数（订阅解析、导入、规则校验、Geo、CA），不占 NE 内存配额，过渡期原样
   保留 Go，最后再逐批移植。
4. **配置格式不变**：新内核直接吃 mihomo YAML 语义。过渡期由 Go 侧新增导出
   `NativeConfigJSON(homeDir)`：把 buildRuntime 已生成的 runtime.yaml 转成 JSON
   喂给原生侧（JSON 是 YAML 子集，语义与现网一致），原生侧不引入 YAML 解析器。

## 功能分档（叠加顺序）

- **档 1（小火箭级）**：TUN 数据面（lwIP）、DNS + Fake-IP、规则引擎、策略组
  （select/url-test/fallback）、出站 DIRECT/REJECT/SOCKS5/HTTP/Shadowsocks、
  控制器 REST 基础（/proxies、/traffic、/version）。
- **档 2（Egern 级）**：VMess、Trojan、VLESS（先无 Reality）、WireGuard、
  负载均衡、rule/provider 加载与更新、/connections 与连接统计、模块格式运行时兼容。
- **档 3（QX 级）**：VLESS Reality/Vision（BoringSSL）、TUIC/Hy2（quiche FFI）、
  MITM 与新内核拨号回连打通（与 B 线原生 MITM 合流）、$task 运行时语义。

不在范围：Tailscale（现实现焊在 gVisor 上，档 3 后单独评估）、smart 组
（先以 /smart 接口形状占位，语义后补）。

## 接口契约（隧道进程）

新内核对外只暴露与现隧道调用面等价的入口（Swift 侧）：

- 生命周期：`start(home:profilePath:tunFd:) throws`、`reload(profilePath:hot:) throws`、
  `stop()`、`isRunning: Bool`、`version: String`
- 内存：`shedMemory(level:reason:) -> String`、`freeMemory()`、`memoryStats() -> String`
  （返回形状与 LibmihomoMemoryStats 一致，PacketTunnelProvider 的内存治理逻辑不改）
- 网络：`setNetworkState(type:ssid:)`、`notifyNetworkChanged(json:) -> Int`、
  `flushDNSCache()`
- 控制器 REST：监听与现控制器相同端口/secret，至少 /version、/proxies、
  /proxies/{name}、/traffic、/connections、/providers/proxies、/providers/rules、
  /rules；自加的 /timeline、/smart、/app/traffic 在档 2 前返回与现形状一致的空/占位数据，
  App 侧解码不许失败。

## 模块图（代码落位）

- `Shared/NativeCore/`：纯逻辑（Foundation/CryptoKit，无 NE 依赖），App 与
  PacketTunnel 共编译，单元测试从 MihomoUnitTests 以 `@testable import Mihomo` 覆盖。
  Widget 目标在 project.yml 里排除 NativeCore，保持小体积。
  - NCConfig（配置模型，JSON 解码）、NCRule（规则解析/匹配）、NCIP（IP/CIDR 工具）、
    NCFakeIP（Fake-IP 池）、NCOutbound（出站报文构造）、NCShadowsocks（SS AEAD）。
- `PacketTunnel/NativeCore/`：NE 胶水（后续批次）：数据面、NWConnection 连接管理、
  控制器服务、与 PacketTunnelProvider 的开关接线（默认关）。

## 验收

- 每批：单元测试（UnitTests/NativeCoreTests.swift）+ CI（checks + ios build_only）全绿。
- 协议/规则语义：与 mihomo 差分（同配置、同输入，比命中策略/DNS 应答/REST 输出）。
- 真机（用户负责）：装包后看诊断 → 隧道内存曲线，对照现版本 26–29 MB 起步 /
  40 MB 平台期；浸泡与 jetsam 观察按 C 线清单执行。

## 平台限制记录（2026-10-24 核查）

- **TUIC（v4/v5）暂不可行**：① TUIC 的 Authenticate / Packet / Dissociate /
  Heartbeat 命令全部走 QUIC 单向流，而 Network.framework 的 NWConnectionGroup
  只暴露双向流提取（`extract(connectionTo:using:)`），无公开的单向流 API；
  ② v5 的认证令牌还需 TLS ExportKeyingMaterial（RFC 5705 exporter），
  Network.framework 同样未暴露。绕行方案是内嵌完整 QUIC 栈（如 quiche/msquic
  的 C 库），属独立立项量级，不在本批次内。连接器对 tuic 类型返回明确的
  unsupported 说明，不静默失败。
- Hysteria2 的 QUIC datagram 绑定方式仍待真机验证（见 NCHysteria2 注释）。
