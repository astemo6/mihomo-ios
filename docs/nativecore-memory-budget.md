# NativeCore 内存预算（PacketTunnel 扩展，jetsam 限额约 50 MB）

审计与收紧记录（fix/nc-memory）。数字口径：**常量** = 代码里的写死上限，可直接核对；
**估算** = 按数据结构大小推算，未经真机测量。真机平台期数据到位后回填本表。

历史参照（旧内核时代的实测）：新会话扩展占 26–29 MB，数小时后平台期
40–40.4 MB、余量约 10 MB，曾被 jetsam 杀。NativeCore 去掉旧运行时后基线下降，
但规则量、连接队列与脚本上下文成为主要项，逐项如下。

## 分项估算

### 1. 基线运行时（估算）

| 项 | 量级 | 说明 |
|---|---|---|
| Swift/Foundation/Network 框架 + 扩展二进制 | ~4–6 MB | 系统框架共享页按比例计入 footprint |
| JavaScriptCore 空 VM | ~1–2 MB | 一个 JSVirtualMachine（见第 6 项） |
| TernPrelude.js 源码 | 36 KB（常量，文件大小） | 每上下文求值一次，堆占用计入第 6 项 |

### 2. lwIP 协议栈（常量为主，`PacketTunnel/NativeCore/lwip/port/lwipopts.h`）

静态池在启动时一次性分配，与连接数无关；TCP 窗口的**载荷**从共享堆/池里出，
不按连接单独分配，所以每连接的可变占用由全栈总量封顶。

| 项 | 改前 | 改后（本 PR） | 字节账 |
|---|---|---|---|
| MEM_SIZE（堆） | 384 KB | **320 KB** | −64 KB；堆消费者是 PBUF_RAM 发送副本，受 TCP_SND_BUF 与 Swift 侧 outbox 背压约束 |
| PBUF_POOL_SIZE × 2048 B | 96 | **80** | 池载荷 192 KB → 160 KB，含 pbuf 头共约 −33 KB |
| MEMP_NUM_PBUF | 96 | 96 | 96 × ~64 B ≈ 6 KB |
| MEMP_NUM_TCP_PCB | 128 | 128 | 128 × ~0.25 KB（估算）≈ 32 KB |
| MEMP_NUM_TCP_PCB_LISTEN | 48 | **24** | −24 × ~104 B ≈ −2.4 KB |
| MEMP_NUM_TCP_SEG | 128 | 128 | ≈ 4 KB |
| MEMP_NUM_UDP_PCB | 64 | 64 | ≈ 6 KB |
| RAW_PCB / SYS_TIMEOUT 等 | — | — | ≈ 3 KB |
| nc_stack.c g_scratch | 70 000 B | 70 000 B | 静态收发暂存 |
| **合计** | ≈ 0.71 MB | **≈ 0.61 MB** | 窗口未动：TCP_WND = TCP_SND_BUF = 16 × 1460 = 23 360 B、TCP_SND_QUEUELEN 32，吞吐不受影响 |

### 3. 每连接缓冲（常量，#116 背压口径 + 本 PR 补齐）

「上限」指该连接在对端/读者完全停滞时能被钉住的最大字节数。读者正常消费时队列接近空。

| 缓冲 | 上限 | 出处 |
|---|---|---|
| NCDataPlane 下行 outbox | ~48 KB | 2 × TCP_SND_BUF（rv2-life 既有） |
| 协议流待发（SS/VMess/VLESS 等纯编码器） | 由 #116 send completion 背压，单块 ≤ 64 KB 级 | NCRelayFlow |
| Mux 流：待发 / 入站排队 | 64 KB / 256 KB | NCMuxStream.maxPendingSend / maxQueuedInbound（既有） |
| AnyTLS 流：待发 / 入站排队 | 64 KB / 512 KB | NCAnyTLSStream（既有；无协议流控，入站上限为刻意取舍，不下调） |
| **Mux/AnyTLS 会话流表** | **128 流/会话（本 PR 新增）** | 此前无上限：流数 × 单流上限即会话最坏占用（理论值 ~40 MB / ~72 MB，读者全停滞时） |
| **TLS 客户端流明文队列（含 Vision splice 溢出队列）** | **256 KB（本 PR 新增）** | 此前无上限：记录泵与 receive 解耦，对端快、读者停时线性增长（Trojan/VLESS/VMess 主路径） |
| **QUIC 三件套 TCP 流（Hy2/Hy1/TUIC）握手 outbox / 入站 inbox** | **各 256 KB（本 PR 新增）** | 此前均无上限；超限走各流既有 fail |
| **Vision 流 outQueue** | **256 KB（本 PR 新增）** | 泵自链式、与消费者解耦，此前无上限 |
| **WebSocket 帧长 / 分片消息** | **各 1 MB（本 PR 新增）** | 此前 127 形长度（可声明 2^63）与分片累积均无校验 |
| **Hy2 控制流缓冲** | **64 KB（本 PR 新增）** | 控制帧只有 SETTINGS/鉴权 HEADERS 等小帧；声明长度为对端 varint |
| **UDP 帧流残留缓冲（Mux/AnyTLS/Trojan/VLESS 会话）** | **128 KB（本 PR 新增）** | 合法帧 ≤ 64 KB；首帧畸形时解析不消费、残留只进不出，超限 cancel 会话 |
| **SSH 通道 outbox / inbox、kex 暂存** | **256 KB / 512 KB / 256 KB（本 PR 新增）** | inbox 上限 = 对外宣称的 windowSize；超限走 connectionLost |
| **Restls sendBuf（writePending 暂存）** | **256 KB（本 PR 新增）** | 超限置 sendOverflowed，TLS 流随即失败 |
| **H2Mux 头块在飞流数** | **128 流（本 PR 新增）** | 单流头块已有 64 KB 上限，流数此前无上限 |
| **H2 隧道流：待发 / 入站排队 / 单条 gRPC 消息** | **256 KB / 256 KB / 1 MB（本 PR 新增）** | 此前三处均无上限（核心对 DATA 立即回窗口，协议层不限） |
| H2 核心帧 / 头块 | 16 KB / 64 KB | NCH2ClientCore.maxFrameSize / maxHeaderBlock（既有） |
| SOCKS5 回复 / HTTP CONNECT 头 | 512 B / 16 KB | NCConnector.maxSOCKSReply 等（既有），握手另有 12 s 截止 |
| VMess 记录 / 响应头 | ≤ ~64 KB | 协议 u16 长度自限（核对结论，无需改码） |
| **TUIC 分片重组** | **64 KB/包 × 16 包（本 PR 新增字节上限）** | 此前只有包数上限，无字节上限 |
| **Hy2 UDP 分片重组** | **16 条消息 × 64 KB（本 PR 新增）** | 此前字典无任何上限，消息 ID 由对端选 |
| UDP 会话预连接待发 | 64 包（Mux/AnyTLS 本 PR 补齐；Hy2 64、Mieru 32 既有） | 会话接通前到达的包，超限丢弃（UDP 语义） |
| NCLocalProxy 头 / 本地连接 | 64 KB | maxHead（既有） |

场景估算（估算）：50 条活跃连接、队列平均 1/4 占用 ≈ 3–5 MB；病理场景 100 条
Mux 连接读者全停滞 ≈ 100 × (48 + 256 + 64) KB ≈ 37 MB——上限防的是无界增长，
不是把病理场景变便宜；真出现这种占用应先看背压遥测再议下调 mux 入站上限。

### 4. DNS（常量）

| 项 | 上限 | 说明 |
|---|---|---|
| NCRealIPMap（仅 redir-host 模式） | 4096 条 | 每条约 80–150 B（估算）→ ≤ ~0.6 MB；满时整表清空（既有） |
| 引擎规则解析缓存 resolveCache | 512 名 | ≈ 50 KB（估算），reload 时清空（既有） |
| 上行协调器 | 在途 32 + **待启动条目 512（本 PR 新增）** | 合并等待者不占条目；超限的新查询立即按 nil 失败（调用方既有语义） |
| DoT/DoH 连接池 | 每上游 1 条连接；**每连接待发 64 条、DoH 应答缓冲 256 KB（本 PR 新增）** | 此前待发队列无条数上限（超时只作用于在飞的那一条） |
| fake-IP 池 | 8192 条/族（常量） | 每条 v4 约 80–140 B、v6 约 120–200 B（估算）→ 双池满载合计 ≈ 1.7–2.7 MB；落盘恢复两侧均按 capacity 截断（既有，#117 v2 格式） |

### 5. 规则 / GeoSite / GEOIP 常驻

| 项 | 形态与量级 |
|---|---|
| 规则数组 + DOMAIN-SUFFIX trie | 引擎按 snapshot 整体替换，reload 时旧集随旧状态释放（无累积）。rule-set 索引每条约 50–180 B（精确集 ~50–90 B、trie 节点 ~100–180 B，估算）；顶层规则 NCRule 含 raw 整行重复存一份，约 150–350 B/条（估算） |
| rule-provider / DOMAIN-SET | 载入即驻留索引；**双闸已封顶**（NCRuleProviderStore：下载 > 32 MB 或解析条数 > 300 000 视为失败保留旧表，见「已落地」第 10 条）；DOMAIN-SET 匹配为原地 trie/集合查询、不复制（已核对）。量级：5 万条 ≈ 2.5–9 MB，20 万条 ≈ 10–36 MB |
| GeoSite.dat | 全文以 `mappedIfSafe` 打开，常驻 = 被触页；仓库内文件 4 272 778 B（实测） |
| **GeoSite 已解析分类缓存** | **本 PR 新增字节上限：LRU 8 类 且 ≤ 8 MB（每条 ~72 B 估算）**；此前只有类数上限，8 个大分类（geosite:cn 一类约 10 万条 ≈ 5–9 MB）理论可钉住数十 MB |
| GEOIP / ASN mmdb | mmap 零拷贝懒查（NCMMDB 映射文件、按需二分、逐 bit 走树、命中才解码），常驻仅触页；仓库内 geoip.metadb 8 423 059 B、ASN.mmdb 8 974 108 B（实测）只占虚拟地址。脚本侧另开一份 alwaysMapped 句柄，页由 OS 共享、增量很小 |
| NCGeoStore | 仅 App 进程（下载/安装/诊断），不进扩展常驻 |

### 6. JSC 脚本上下文（本 PR 收紧）

现状设计（已核对 `PacketTunnel/JSCScriptEngine.swift`）：单个 JSVirtualMachine、
全部求值在专用 JSCThread 串行（JSContext 非线程安全由此规避）；每脚本一个主上下文
复用（`__tern_begin` 每轮重置全局状态），并发同脚本走临时上下文、用完即弃；内存
紧张时 governor 触发 collect()，单轮结束后可用内存 < 14 MB 也收集。

缺口：上下文缓存**无条数上限且 drop() 已无调用方**（旧内核时代的缓存淘汰随旧内核一起
删了），加载过的每个不同脚本（含配置变更后的旧版本）常驻到隧道结束。

| 项 | 改前 | 改后（本 PR） |
|---|---|---|
| 缓存脚本数 | 无上限 | **LRU 上限 32**（JSCScriptEngine.maxCachedScripts），load 时逐出最久未用且空闲者，忙碌条目跳过、从不杀运行中的脚本 |
| 单上下文成本 | prelude 堆 ~0.3 MB（估算）+ 源码 | 32 个 ≈ ≤ ~10 MB 最坏（估算）；典型 5 个脚本 ≈ 1.5–2 MB |
| 脚本 body 预算 | reserve 1.5 MB、单 body 硬顶 8 MB（常量，NativeScriptBodyBudget） | 不变；准入按实时可用内存，body 总占用由「可用 − reserve」构造性封顶 |

### 7. 汇总与平台期目标（估算）

| 场景 | 基线+lwIP | 连接 | DNS+fakeIP | 规则+GeoSite | JSC | 合计 |
|---|---|---|---|---|---|---|
| 典型（5 万规则、50 连接、5 脚本） | ~6.5 MB | ~4 MB | ~4 MB | ~6 MB | ~2 MB | **~23 MB** |
| 重载（20 万规则、100 连接、32 脚本） | ~6.5 MB | ~10 MB | ~6 MB | ~20 MB | ~10 MB | **~52 MB** ⚠️ |

平台期目标：典型配置 ≤ 30 MB、重载配置 ≤ 45 MB（留 ≥ 5 MB 余量）。重载场景的
大头是规则常驻与 JSC 缓存上限的乘积，两者都已封顶但仍需真机回填验证。

## 已落地（本 PR）

1. lwipopts：MEM_SIZE 384→320 KB、PBUF_POOL_SIZE 96→80、TCP_PCB_LISTEN 48→24。
2. Mux/AnyTLS 会话流表上限 128（超限返回预失败流，不上线路）。
3. TLS 客户端明文/splice 队列 256 KB；QUIC 三件套（Hy2/Hy1/TUIC）outbox/inbox 各
   256 KB；Vision outQueue 256 KB；WebSocket 帧/消息各 1 MB；Hy2 控制流 64 KB；
   UDP 帧流残留 128 KB；SSH 通道 256/512 KB 与 kex 暂存 256 KB；Restls sendBuf
   256 KB；H2Mux 头块在飞流 128。超限均走各模块既有失败/关闭语义。
4. H2 隧道流待发/入站 256 KB、gRPC 单消息 1 MB，超限失败流且 send completion 恰好一次。
5. TUIC 重组 64 KB/包、Hy2 重组 16 条 × 64 KB。
6. UDP Mux/AnyTLS 会话预连接队列 64 包（与 Hy2 对齐）；DNS 池每连接待发 64 条、
   DoH 应答缓冲 256 KB。
7. DNS 协调器待启动条目上限 512。
8. GeoSite 分类缓存增加 8 MB 估算字节上限（与 8 类 LRU 并行）。
9. JSC 脚本上下文缓存 LRU 上限 32 + 逐出路径接回 drop 的 trash/forget 机制。
10. rule-provider 双闸（后续 fix/nc-provider-gate 落地）：NCRuleProviderStore 的
    `maxPayloadBytes = 32 * 1024 * 1024`、`maxEntries = 300_000`，加在 refresh 与
    loadCached 的共同必经点 `populateIndex`（inline payload 在 loadCached 内直接
    查条数闸）。超限抛 `NCRuleProviderGateError`、按刷新失败处理：不换内存表、
    不覆盖磁盘缓存、不更新时间戳，日志写明是 size/count 超限（与网络失败区分）。

已知残留：SSR obfs 的 held（random_head / tls1.2_ticket_auth）——codec 协议无失败
通道、held 是 obfs 时序语义的一部分，硬改会破坏协议；其量级 = 服务器首包到达前
应用的上行量，实践中受首包时延约束，未在本 PR 处理。

## 建议未落地（按收益排序）

1. **规则紧凑表示**：20 万条级订阅的规则常驻（10–36 MB）可经后缀 trie 共享尾串 /
   字符串驻留再压 30–50%（估算）；rule-set 的 others 条目不存 raw 整行也可省每条
   一行长度。属加载器结构改造，建议先做内存遥测再定。
2. **Mux/AnyTLS 单流上限复核**：Mux 入站 256 KB、AnyTLS 入站 512 KB 为既有值；
   与 128 流表相乘的理论最坏仍高（~40 / ~72 MB）。实际占用受读者消费速度决定，
   待背压遥测（overflow 触发次数）后再议下调；AnyTLS 因无协议流控更需谨慎。
3. **JSC 临时上下文与 run 数换新**：同脚本并发的临时 context 无计数上限（用完即弃，
   风险低于常驻池）；prelude reset() 不恢复被改写的基线全局值/原型污染，可给 Ctx 加
   run 计数、满 ~200 次整 context 换新兜底。均建议随脚本路后续处理。
4. **DNS 缓存 minTTL 钳制**：上游给极大 TTL 时条目久驻（内存影响小于其行为影响，
   属 DNS 语义，归 DNS 路）。
5. **fake-IP maxEntries 8192 → 4096 复核**：双池满载可省约 1 MB，代价是高域名量
   场景映射回收变早（应答 TTL 仅 1 s，风险低）；与 DNS 路口径对齐后再定。
