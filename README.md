# NativeCore 内核分支（feat/nc-kernel）

本分支只用来同步 **NativeCore**——Tern iOS App 的纯 Swift 代理内核（数据面 + 内嵌 lwIP 的 C 代码 + JavaScriptCore 脚本，**零 Go**）。协议 / 规则 / DNS 语义对标 [Clash.Meta](https://github.com/MetaCubeX/mihomo) 与 Surge / Loon / Quantumult X。

- 完整的新 App（界面、导入器、CI、发布）在 **`feat/nc-integrate`**；旧 Go 版稳定线 v0.19.26 在 `main`，Go 内核归档在 `archive/go-kernel-v0.19.26`。
- 当前内容：2026-10-25 从 `feat/nc-integrate` 898ea26 同步（提交 ccad5cf）。下一次同步在 **v0.20.0 预览版发布之后**。

> GPL-3.0（见 `LICENSE` 与 `NOTICE`）。仓库里没有任何节点、证书或密钥。

## 内容

| 目录 | 内容 | 语言 |
| --- | --- | --- |
| `Shared/NativeCore/` | App 与隧道共用的内核库：配置规范模型与导入器（Clash.Meta YAML、Surge / QX 等）、出站协议、TLS 1.2/1.3、QUIC、H2 / HPACK、DNS / fake-IP、规则 / 规则集 / GeoSite / MMDB、策略组、订阅、分享链接、节点可用性判断（`NCSupport.swift`） | Swift |
| `PacketTunnel/NativeCore/` | 隧道内的数据面与引擎：`NativeTunnelCore` / `NativeCoreEngine` 生命周期、`NCDataPlane`（packetFlow ⇄ lwIP）、TCP / UDP 会话、拨号与链式代理、WireGuard、本地 HTTP/SOCKS、控制器 API、健康检查、内存采样 | Swift |
| `PacketTunnel/NativeCore/lwip/` | lwIP 2.2（BSD-3，见 `VENDORED.md`）+ C 胶水 `nc_stack.c`（TUN 任意目的地址的 TCP 终止、逐流 UDP 会话）与 `nc_wg.c`（WireGuard 独立 netif），经 `NCBridge.h` 桥接到 Swift | C |
| `PacketTunnel/NativeMitM/` | MitM：TLS 终止与叶证书签发、HTTP/1.1 / HTTP/2、URL / 头部 / 内容重写（ICU 正则）、请求记录、脚本调度、内存治理；`Script/TernPrelude.js` 提供 Surge / QX 脚本 API | Swift + JavaScript |

分支上其余目录（`App/`、`Widget/`、`bridge/` 等）是从 `main` 继承的旧 App 外壳，只用来让内核能在原工程里编译，**不在这里维护**，也不代表 Tern 的现状。

## 架构

```
NEPacketTunnelFlow ──► NCDataPlane ──► lwIP（C）──► TCP 流 / UDP 会话
                          │
                          ├─ 嗅探域名 → 规则匹配 → 策略组（select / url-test / fallback / load-balance / relay）
                          ├─ DNS：fake-IP、分流解析、UDP/TCP/DoT/DoH/DoQ 上游
                          ├─ 出站：Swift 协议实现（NWConnection）· WireGuard（nc_wg netif）· DIRECT / REJECT
                          └─ MitM 主机 → NativeMitM（TLS 解密 → 重写 → JSC 脚本）→ 仍按原规则出站
控制器 HTTP API（127.0.0.1）· 健康检查 / 延迟测试 · 内存采样与压力时裁剪连接
```

- **数据面**：Swift 读 packetFlow，交给内嵌 lwIP 还原为 TCP / UDP；单线程 raw API（NO_SYS），按 Network Extension 内存预算裁剪。
- **规则与策略组**：规则集（含 `.mrs`）、GeoSite、MMDB、嗅探；策略组含智能选择与前置代理链。
- **DNS**：fake-IP（reload 清空）、nameserver-policy、连接复用。
- **控制器**：与 App 通信的 HTTP API（连接、流量、内存、日志、切换节点、测速）。
- **MitM / 重写 / 脚本**：全部在隧道内完成；脚本由系统 JavaScriptCore 执行。
- **内存预算**：隧道扩展约 50 MB 上限；内核按预算限制缓冲与并发，内存压力时按比例断开连接。

## 协议支持（本分支当前内容）

Shadowsocks / SS2022（插件 obfs、v2ray-plugin、shadow-tls、gost-plugin、restls）、ShadowsocksR、VMess、VLESS（Reality、XTLS-Vision、mlkem768x25519plus encryption）、Trojan、Snell、AnyTLS、Hysteria、Hysteria2、TUIC v5、Mieru、SSH、WireGuard、SOCKS5、HTTP / HTTPS。不支持的节点保留在配置中并标为不可用，原因见 `NCSupport.swift`。

**已在 `feat/nc-integrate`、下一次内核同步（v0.20.0 预览版发布后）才进入本分支**：Juicity、Brook、gost-relay、NaïveProxy 与 HTTP/2 / HTTP/3 CONNECT 代理、xhttp 传输、ECH、cloak / kcptun 插件、Tailscale、Lua 自定义后端、OpenConnect（DTLS、split 路由）、Sudoku（与官方服务端 TCP 互通）、TrustTunnel（H2 + H3、UDP）、MASQUE（CONNECT-UDP + CONNECT-IP）、本机隧道（兼容 LocalDevVPN），以及之后的内存与稳定性修复。

## 零 Go

内核目录不含任何 Go 代码。隧道扩展只编译 Swift 与 lwIP / 胶水 C 代码，不链接任何 Go 框架（`project.yml` 中 PacketTunnel 目标的依赖只有 NetworkExtension）。

## 如何嵌入 App

- XcodeGen 的 PacketTunnel 目标编译 `PacketTunnel/`（含 `NativeCore/`、`NativeMitM/`）与 `Shared/`；`SWIFT_OBJC_BRIDGING_HEADER = PacketTunnel/NativeCore/NCBridge.h`，头文件搜索路径指向 `lwip/`、`lwip/include`、`lwip/port`；`TernPrelude.js` 作为资源打包。
- `PacketTunnelProvider` 持有 `NativeTunnelCore.shared`：`startTunnel` 时由 `NativeCoreEngine` 读取 App 写在 App Group 里的运行配置，`NCDataPlane` 直接读写 `packetFlow`；`handleAppMessage` 处理 reload 与状态查询；内存压力时调用 `shedConnections`。
- App 目标也编译 `Shared/NativeCore/`（导入、校验、离线解析配置）；Widget 目标排除 `Shared/NativeCore/**`。

## 测试

- 单元测试：`UnitTests/NativeCore*Tests.swift`、`AppTests/NativeCore*Tests.swift`（协议编解码、TLS 1.3、Vision、SS2022、规则集、DNS 策略、配置导入等）。
- 协议回环（真实服务端）、UI 测试与 E2E 回放在 `feat/nc-integrate` 上运行；本分支的内核代码只同步已在那里通过最终门禁的版本。

## 开发流程

- **不要直接在本分支提交内核改动。** 内核改动在 `feat/nc-integrate` 上以 lane（`fix/nc-<题目>` / `feat/nc-<题目>`）开发、验证并合并；每次发布后，由维护者把 `Shared/NativeCore`、`PacketTunnel/NativeCore`、`PacketTunnel/NativeMitM` 同步到这里（提交带 `[skip ci]`，作者 zhihenglu）。
- 本分支只接受同步提交与文档改动；`scripts/term_audit.py` 必须为 0。
- 协议只有对真实服务端回环通过后才在 `NCSupport` 中放开。

## 许可与致谢

GPL-3.0。

- [mihomo](https://github.com/MetaCubeX/mihomo)（Clash.Meta，MetaCubeX，GPL-3.0）：协议、规则与配置语义的参考（Swift 独立实现，不链接上游代码）。
- [TokenPLS/Hako](https://github.com/ProjectClash/Clash-Legacy) 与 [Hako-Adapter](https://github.com/ProjectClash/Clash-Adapter-Legacy)（现由 [ProjectClash](https://github.com/ProjectClash) 维护，GPL-3.0）：NetworkExtension 内存控制与包流桥接的设计参考。
- [lwIP](https://savannah.nongnu.org/projects/lwip/) 2.2（BSD-3-Clause），内嵌于 `PacketTunnel/NativeCore/lwip/`。
- 系统 JavaScriptCore（脚本）与 ICU（正则）。
