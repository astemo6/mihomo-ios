# NativeCore 真机验证清单

用途：NativeCore（Go-zero 后唯一内核）每次大版本 / 内核改动合入后的真机回归。模拟器与 CI 测不了
Network Extension 的内存与数据面行为，本清单只能真机跑。每项一行：操作 → 通过判据。
跑完把本文件复制一份到当次发布记录，逐项打勾并填 Build 号。

**环境**：付费开发者证书签名的 IPA（免费证书无 Network Extension 能力，必失败）；一台真机；
每个协议至少一个可用测试节点；一个能看请求头/回显的站点（如 `https://httpbin.org/headers`、
`https://ipleak.net`）；大文件下载源（≥1 GB）与可限速的上传环境各一。

**读数来源**：隧道内存 = App「更多 → 诊断与反馈 → 隧道内存」；jetsam 记录 = iOS「设置 →
隐私与安全性 → 分析与改进 → 分析数据」里的 `JetsamEvent-*.ips`（看进程名 PacketTunnel / Tern
与时间戳）；出口 IP = 首页 IP 卡片或 ipleak。

## 1. 内存

- [ ] **新会话占用**：杀掉 App 重开 → 连接 → 静置 1 分钟后读隧道内存，记录数值。
  通过：数值 < 40 MB（系统上限约 50 MB，须留 ≥10 MB 余量；老 Go 内核新会话为 26–29 MB，作对照）。
- [ ] **平台期**：正常使用 4 小时（浏览、视频、一次大下载穿插），每 30 分钟记录一次隧道内存。
  通过：后 2 小时的读数波动 ≤ 3 MB，不随连接数持续爬升。
- [ ] **jetsam 观察**：平台期结束后查分析数据。通过：测试时段内无新增 PacketTunnel 的 JetsamEvent。
- [ ] **大规则集**：换一份含大 GEOSITE / 大规则集的配置连接并使用 10 分钟。
  通过：连接成功、内存仍在 50 MB 上限内且无 jetsam；诊断里无规则集加载失败。

## 2. 协议连通（每行一个节点，逐行验）

统一操作：选中该节点 → 连接 → 打开 ipleak 看出口 IP → 下载 50 MB 文件 → 断开重连一次。

| 协议 | 附加验点 | 通过判据 |
| --- | --- | --- |
| Shadowsocks AEAD | — | 出口 IP = 落地 IP，下载完成，重连仍通 |
| Shadowsocks 2022 | — | 同上 |
| Shadowsocks + 插件 | obfs / v2ray-plugin(ws) / shadow-tls 各一 | 同上；插件握手无报错日志 |
| ShadowsocksR | 任一 protocol + obfs 组合 | 同上 |
| VMess AEAD | ws 与 tcp 传输各一 | 同上 |
| VLESS plain | — | 同上 |
| VLESS + Reality | — | 同上；启动日志无 REALITY 校验失败 |
| VLESS + Vision | flow = xtls-rprx-vision | 同上 |
| VLESS encryption | mlkem768x25519plus 节点 | 同上 |
| Trojan | — | 同上 |
| Hysteria2 | 含 UDP 会话（见 §5） | 同上 |
| Hysteria v1 | protocol = udp | 同上 |
| TUIC v5 | token 与 uuid 两种鉴权 | 同上 |
| WireGuard | 含一条 AmneziaWG 1.0（jc/jmin/jmax/h1–h4）节点 | 同上；握手日志有最新 handshake 时间 |
| Snell | v4/v5 任一 | 同上 |
| AnyTLS | — | 同上 |
| Mieru | transport = TCP | 同上 |
| SSH | 私钥登录一（口令保护私钥 + 文件路径各一，#118） | 同上；known-hosts 指纹与服务器一致 |
| SOCKS5 / HTTP CONNECT | — | 同上 |
| DIRECT / REJECT | 规则模式下命中各一 | DIRECT 出口 = 本地 IP；REJECT 立即失败不超时 |

- [ ] **已知不支持项**：导入含 Tailscale、Mieru UDP transport、AmneziaWG 2.0（h 范围 / s3 / s4）、
  restls fingerprint、v2ray-plugin http-upgrade 的节点各一。通过：节点保留在列表中，
  「诊断」逐条给出与 `NCSupport` 一致的原因，不崩溃、不用其他内核兜底。

## 3. MitM 与脚本

前置：工具 → HTTPS 解密 → 生成 CA → Safari 安装描述文件 → 系统设置里安装并在
「证书信任设置」打开完全信任 → 回 App 确认状态为「已安装并完全信任」。

- [ ] **解密链路**：开 HTTPS 解密并把 `httpbin.org` 加入 MitM 主机名，访问 `https://httpbin.org/headers`。
  通过：请求页能看到该请求的明文头部；浏览器无证书警告。
- [ ] **http-request 脚本**：脚本给请求加一个自定义头，httpbin 回显。通过：回显里有该头。
- [ ] **http-response 脚本 + jq**：响应阶段脚本改一处 body、再挂一条 `http-response-jq` 改一处字段。
  通过：页面 / 接口返回的是改后的内容，两条都生效且顺序正确。
- [ ] **证书固定 App 放行**：打开一个已知证书固定的 App（如银行 / 支付类）。
  通过：该 App 联网正常，日志有握手失败自动放行记录，不反复弹窗。
- [ ] **Surge type=dns 脚本**：导入含 `type=dns` 脚本的模块，查询脚本目标域名。
  通过（执行接线完成后）：返回脚本给定的答案；未接线时只验导入注册不报错、诊断无异常。
- [ ] **Surge type=rule 脚本**：导入含 `type=rule` 脚本的模块，触发其匹配条件。
  通过（执行接线完成后）：连接走向脚本裁决的策略；未接线时只验导入注册不报错。
- [ ] **Egern ctx 脚本**：导入一个 Egern 模块（`scriptings:` 含 http_request 一条，带 env / argument）。
  通过：脚本被触发，`ctx.env` 与对象 argument 在脚本内可读，超时设置生效（故意写死循环脚本，
  到 timeout 应被中止且连接保持原样）。

## 4. 生命周期（reload / stop / restart）

- [ ] **热 reload**：连接状态下改当前配置的一条规则 → 在 App 内重载配置 → 立刻用新规则目标验证。
  通过：新规则立即命中；reload 期间正在进行的下载不中断、不重连节点。
- [ ] **reload 换配置**：连接中切换到另一份配置。通过：隧道不断（VPN 图标不消失），
  出口与策略组变为新配置，Fake-IP 旧映射不串（见 §5 DNS 项）。
- [ ] **stop**：断开连接。通过：首页状态未连接；诊断显示隧道已停；再查隧道内存读数消失 / 归零。
- [ ] **restart ×5**：连续连接 → 断开 5 次。通过：每次都能连上，无残留进程感（无「连不上需杀 App」），
  无新增 jetsam。
- [ ] **网络切换**：连接中 Wi-Fi ↔ 蜂窝各切一次、锁屏静置 10 分钟后解锁。
  通过：两种情况都自动恢复可用（打开网页验证），不需手动重连。

## 5. UDP

- [ ] **DNS over UDP**：规则模式下连续打开 10 个未访问过的域名。通过：全部解析成功；
  Fake-IP 模式下每个域名在「请求」里能看到 fake-IP 与真实落地对应，无串话。
- [ ] **DNS 加密上游**：配置 DoH 与 DoT 上游各一，冷启动后首查。通过：首查不超时，
  重复查询同一域名第二次明显更快（连接复用 / 合并生效的粗判）。
- [ ] **非 DNS UDP（QUIC）**：用支持 HTTP/3 的浏览器打开一个 h3 站点并播放视频 3 分钟。
  通过：视频不断流；「请求」里能看到对应 UDP 会话。
- [ ] **协议 UDP 转发**：分别经 Hysteria2、TUIC、WireGuard 节点做一次 UDP 依赖操作
  （如游戏登录或实时语音 1 分钟）。通过：操作成功、无明显丢包断续。
- [ ] **UDP 空闲回收**：打开若干 UDP 会话后静置 15 分钟再逐个复用 / 新建。
  通过：新会话正常建立，内存较峰值回落，旧会话复用不出现把数据发给错误对端。

## 6. 背压

- [ ] **大下载**：经任一节点下载 1 GB 文件，开始 / 中段 / 结束各记一次隧道内存。
  通过：三段读数差 ≤ 5 MB（不随已下载量线性增长），下载速率稳定无周期性归零。
- [ ] **慢上行**：把上行限速到约 50 KB/s 后上传 200 MB 文件，上传期间同时浏览网页。
  通过：网页连接可正常建立与加载（不被上行队列整体拖死），上传最终完成。
- [ ] **慢消费者**：用一个故意慢读的本地接收端拉一条大响应（或暂停下载 App 的写入）。
  通过：其他连接不受影响，隧道内存不随未读数据无界增长，恢复读取后数据完整。

## 记录格式（失败时）

每条失败记：清单项、Build 号、节点协议（脱敏）、现象一句话、隧道内存读数、
日志位置（App 日志时间点 / JetsamEvent 文件名）。内存类失败另附平台期记录表。
