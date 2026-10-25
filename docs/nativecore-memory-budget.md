# NativeCore 内存预算（PacketTunnel 扩展，jetsam 限额约 50 MB）

审计与收紧记录（fix/nc-memory）。数字口径：**常量** = 代码里的写死上限，可直接核对；
**估算** = 按数据结构大小推算，未经真机测量。真机平台期数据到位后回填本表。

历史参照（Go 时代，仓库 memshed.go 实测）：新会话扩展占 26–29 MB，数小时后平台期
40–40.4 MB、余量约 10 MB，曾被 jetsam 杀。NativeCore 去掉 Go 运行时后基线下降，
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
| **Mux/AnyTLS 会话流表** | **256 流/会话（本 PR 新增）** | 此前无上限：流数 × 单流上限即会话最坏占用 |
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
| 应答缓存 NCDNSCache | 4096 条 | 满时整表按 60 s 间隔淘汰；每条约 0.3–1 KB（估算）→ ≤ ~2–4 MB |
| 上行协调器 | 在途 32 + **待启动条目 512（本 PR 新增）** | 合并等待者不占条目；超限的新查询立即按 nil 失败（调用方既有语义） |
| DoT/DoH 连接池 | 每上游 1 条连接 | #117 既有 |
| fake-IP 池 | 8192 条/族（常量） | 每条约 200 B（估算）→ v4+v6 各 ≤ ~1.6 MB；落盘恢复两侧均按 capacity 截断（既有，#117 v2 格式） |

### 5. 规则 / GeoSite / GEOIP 常驻

| 项 | 形态与量级 |
|---|---|
| 规则数组 + DOMAIN-SUFFIX trie | 引擎按 snapshot 整体替换，reload 时旧集随旧状态释放（无累积）。常驻 ≈ 每条规则 50–80 B（估算）：5 万条 ≈ 3–4 MB，20 万条 ≈ 12–16 MB——**大订阅下第一大常驻项** |
| rule-provider / DOMAIN-SET | 载入即驻留数组/集合（每条约 100–150 B，估算），无条数上限——集合大小由订阅本身决定；DOMAIN-SET 匹配为原地 trie/集合查询、不复制（已核对） |
| GeoSite.dat | 全文以 `mappedIfSafe` 打开，常驻 = 被触页；文件本身 5–15 MB（视发行版） |
| **GeoSite 已解析分类缓存** | **本 PR 新增字节上限：LRU 8 类 且 ≤ 8 MB（每条 ~72 B 估算）**；此前只有类数上限，8 个大分类（各 5–10 万条）理论可钉住数十 MB |
| GEOIP / ASN mmdb | mmap 零拷贝懒查（NCMMDB 映射文件、按需二分），常驻仅触页；文件 60–100 MB 只占虚拟地址 |
| NCGeoStore | 仅 App 进程（下载/安装/诊断），不进扩展常驻 |

### 6. JSC 脚本上下文（本 PR 收紧）

现状设计（已核对 `PacketTunnel/JSCScriptEngine.swift`）：单个 JSVirtualMachine、
全部求值在专用 JSCThread 串行（JSContext 非线程安全由此规避）；每脚本一个主上下文
复用（`__tern_begin` 每轮重置全局状态），并发同脚本走临时上下文、用完即弃；内存
紧张时 governor 触发 collect()，单轮结束后可用内存 < 14 MB 也收集。

缺口：上下文缓存**无条数上限且 drop() 已无调用方**（Go 时代的缓存淘汰随 Go 一起
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
2. Mux/AnyTLS 会话流表上限 256（超限返回预失败流，不上线路）。
3. H2 隧道流待发/入站 256 KB、gRPC 单消息 1 MB，超限失败流且 send completion 恰好一次。
4. TUIC 重组 64 KB/包、Hy2 重组 16 条 × 64 KB。
5. UDP Mux/AnyTLS 会话预连接队列 64 包（与 Hy2 对齐）。
6. DNS 协调器待启动条目上限 512。
7. GeoSite 分类缓存增加 8 MB 估算字节上限（与 8 类 LRU 并行）。
8. JSC 脚本上下文缓存 LRU 上限 32 + 逐出路径接回 drop 的 trash/forget 机制。

## 建议未落地（按收益排序）

1. **规则紧凑表示**：20 万条级订阅的规则常驻（12–16 MB）可经后缀 trie 共享尾串 /
   字符串驻留再压 30–50%（估算）。属加载器结构改造，建议独立一路，先做内存遥测再定。
2. **Mux 入站上限 256 KB → 128 KB 复核**：待背压遥测（overflow 触发次数）证明读者
   停滞尾部后下调；AnyTLS 512 KB 因无协议流控保持不动。
3. **DNS 缓存 minTTL 钳制**：上游给极大 TTL 时条目久驻（内存影响小于其行为影响，
   属 DNS 语义，归 DNS 路）。
4. **NCDNSCache 满表淘汰为 O(cap) 扫描**：4096 条下每 60 s 至多一次，可接受；
   若条目上限上调需先改近似 LRU（性能路）。
5. **GeoSite.dat 改 mmap 直读**：现为 mappedIfSafe Data（已是映射优先），若发行版
   文件继续变大，可评估完全不驻留的按需页入——收益取决于真机触页数据。
