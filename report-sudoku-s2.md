# NativeCore Sudoku S2 任务报告 — 回环接入（官方黑盒对端）与测试落盘

> 收窄版 S2 第二段。数据面本身已在上一段完成并 push（commit 2041932，纯 Swift 数据面 + connector 接入），
> 本段按任务书只做四件事：① tools/loopback 接入官方服务端黑盒对端（18015）；② 回环用例 + 密钥协商向量/
> 编解码边界/错误密钥负例单测；③ 文档按实现现状更新（含净室依据）；④ 本报告。未改任何数据面代码，
> 未运行长时间抓包/联调（本机无 Xcode），所有提交带 `[skip ci]`，未触发 CI、未开 PR、未动 main / feat/nc-kernel。

---

## 1. 本段做了什么

1. **官方服务端黑盒接入**（sing-box 没有 sudoku inbound，必须用官方二进制）：
   - `tools/loopback/start-servers.sh`：新增 `find_sudoku_bin`（固定版本下载，`SUDOKU_VERSION` 默认
     `0.5.2.0`、`SUDOKU_BIN` 覆盖），`start/stop/status` 全部纳入 sudoku 进程，18015 加入 `wait_tcp`
     就绪探测与 ready 输出。
   - `tools/loopback/sudoku-config.json`（新）：`mode=server`、`local_port=18015`、
     `aead=chacha20-poly1305`、`ascii=prefer_ascii`、`padding_min/max=0`（服务端不注入填充，减少解码器
     干扰项）、`enable_pure_downlink=true`、`httpmask.disable=true`、`multiplex=off`、
     `suspicious_action=fallback` + `fallback_address=127.0.0.1:18080`（握手失败会被回放到 echo 后端再
     反射回来，不会挂死客户端）。字段名逐一对照上游 `configs/server.config.json` 模板与
     `internal/config/config.go` 的 json tag。
   - 密钥：服务端 `key` 为真实 Ed25519 master 公钥 hex（`3388f6b5…451d`），客户端测试常量为对应的
     split（"available"）私钥 hex（128 字符）。生成脚本用 RFC 8032 参考实现，先通过 RFC 8032 测试向量 1
     自检再做 `(r+k)·B == x·B` 校验；脚本与产物都在 /tmp，密钥本体落在仓库的两处常量镜像里（仅回环测试值）。
   - 发布物核验：release tag 为四段式 `v0.5.2.0`（GitHub API 实测，`v0.5.2` 会 404），tarball 内二进制名
     为平铺的 `sudoku`（下载解包实测过 linux-amd64 包）。
   - `README.md` 拓扑表补 18015 行与环境变量说明；"常量镜像"从三处改为四处（README 表 /
     sing-box-config.json / sudoku-config.json / 测试常量 + 脚本就绪行）。
   - `.github/workflows/proto-loopback.yml`：归档 `sudoku.log`、stop 步骤打印其尾部，头注释同步——仅回环
     相关改动。
2. **回环与单元测试**：
   - `NativeCoreLoopbackTests.swift`：`testSudokuTCPEcho`（经 NCConnector → 官方服务端 → echo 的全链路
     回声，**这是互通性判决用例**）、`testSudokuWrongKeyRejected`（错误密钥必须失败、不得返回流）、18015
     加入端口探活；sudoku 节点构造器与 `sudoku-config.json` 逐字段镜像。
   - `NativeCoreSudokuTests.swift`（+282 行）：
     - 密钥协商向量：`deriveUserHash` 三条 SHA256 向量（128-hex/64-hex/字符串回退，独立用 hashlib 计算）；
       RFC 7748 §6.1 X25519 全套向量（公钥/共享秘密）；ClientHello 逐字节布局断言（"kip"+0x01+len=68 +
       时间戳 BE + user_hash + nonce + pub + features=0）；ServerHello 解析（合法/nonce 不符/短载荷）；
       KIP 帧往返与坏 magic 拒绝；OpenTCP 域名与 IPv4 两种字节形态。
     - 编解码边界：四种布局全 256 字节往返；prefer_ascii 输出必须落在可打印区（0x20–0x6F）；整组垃圾
       （非 one-hot v 位）按填充丢弃、尾部 1–3 字节忽略、空输入；XVP pack/unpack 全组合 + 非 one-hot
       拒绝 + 非法 pattern 拒绝；同 key 确定性、异 key 表不同且交叉解码不还原；显式钉住"编码器暂不注入
       填充"的现状契约（paddingMin/Max 已解析未使用）。
     - AEAD 错误密钥负例与边界：双算法往返；分帧布局与 seq 递进（epoch=0、seq=0→1）；**异 key 解封必须抛错**
       （chacha/aes 都测）；密文/篡改 tag 抛错；截断记录返回 nil（等更多字节）而非抛错；body_len<12 与
       缺 tag 抛错；none 模式为"u16 长度 + 明文"分帧（与官方透传不同，已注释并在文档标注）。
   - 修正 S1 遗留过时用例：`testConnectorDialReturnsDeferredToS2` 断言的错误信息在 2041932 接入真拨号后
     已不存在，改为 `testConnectorDialFailsAgainstClosedPort`（对关闭端口拨号必须报错且无流）。
3. **文档** `docs/nc-proto-sudoku.md` 按实现现状重写：§2.4/2.5 修正为官方 v0.5.2 的真实密钥调度与载荷；
   新增 §2.6 逐层互通对照表（15 行，✅/❌/⚠️ 逐项给出上游文件行号证据）；§3 字段表加"S2 data-plane note"
   列；§5 从计划改为已交付实现描述；新增 §6 净室依据章节；§7 回环接好、结果待 CI；§8 S3 修复清单。

## 2. 重要发现：净室数据面当前无法与官方服务端互通（静态结论，判决留 CI）

读上游 v0.5.2 源码（只读，用于黑盒对端运营与互通分析，未抄任何代码）后确认，分帧层与控制面布局完全一致，
但密钥调度与表格派生有三处结构性分歧，任何一处都足以使握手失败：

| 层 | 官方 v0.5.2（出处） | 本仓净室实现（2041932） |
|---|---|---|
| 握手记录密钥 | `HKDF-Expand(SHA256(key字符串), "sudoku-psk-c2s"/"-s2c")` 方向性双钥（`internal/tunnel/session_keys.go:16-21`） | 单把 `SHA256(key字节)`，双向同钥（`NCSudokuSession.swift` `NCSudokuAEAD.init`） |
| 握手后换钥 | X25519 ECDH + HKDF 派生会话钥并 `Rekey`（`session_keys.go:25-47`、`kip_hello.go`、`handshake_server.go:152`） | 无 ECDH 混入、无换钥 |
| 表格播种 | `int64(BE(SHA256(key串)[:8]))` 播种 **math/rand v1** 后 Fisher-Yates，"the math/rand v1 stream is part of the wire contract"，前 256 槽映射字节（`pkg/obfs/sudoku/grid.go:80-89`） | 自研 xorshift67，播种方式与 PRNG 流都不同 |

另有两处次级分歧：客户端会把 split 私钥规范化成 master 公钥串再参与 PSK/表种子（`internal/app/client.go`
`normalizeClientKey`，我们未做）；官方 `aead=none` 是完全透传不分帧，我们用 u16 分帧。填充方向：官方可在
**每个 clue 字节之间**插填充、解码用流式 hint 缓冲（`classic_encode.go:57-69`、`classic_decode.go`），我们
只按 4 字节对齐组解码——即便将来表格对齐，带填充的下行流也会错位。

**对 CI 的预测**（写进文档，等 CI 判决）：`testSudokuTCPEcho` 预期失败——服务端把解不开的 ClientHello 视为
非法流量走 fallback，把已读前缀回放到 18080 echo、echo 原样反射，客户端解封成功（同一把钥）但 KIP 类型是
0x01 而非 0x02，报 `Invalid ServerHello message`。`testSudokuWrongKeyRejected` 无论互通与否都应通过。
一致的部分同样有实测依据：record 分帧（`record_conn.go:36-41`）、KIP 帧、ClientHello/ServerHello 载荷
（`kip.go:173/246`）、user_hash 推导（`kip.go:157`）、288 宫格枚举顺序（`grid.go:26`）。

## 3. 文件清单（本段两个提交）

| 文件 | 变更 | 说明 |
|---|---|---|
| `tools/loopback/sudoku-config.json` | 新增 | 官方服务端回环配置（18015，字段名对照上游模板） |
| `tools/loopback/start-servers.sh` | 修改 | find_sudoku_bin 下载（默认 v0.5.2.0，SUDOKU_BIN/SUDOKU_VERSION 覆盖）、start/stop/status、18015 就绪探测 |
| `tools/loopback/README.md` | 修改 | 拓扑表 +18015、环境变量、密钥说明、常量镜像改四处、Sudoku 覆盖说明 |
| `.github/workflows/proto-loopback.yml` | 修改 | 归档/打印 sudoku.log，头注释同步（仅回环相关） |
| `UnitTests/NativeCoreLoopbackTests.swift` | 修改 | sudoku 常量与节点构造器、`testSudokuTCPEcho`、`testSudokuWrongKeyRejected`、端口探活 +18015 |
| `UnitTests/NativeCoreSudokuTests.swift` | 修改 | 密钥协商向量 / 编解码边界 / AEAD 错误密钥负例共 19 个新用例；替换过时的 connector 占位用例 |
| `docs/nc-proto-sudoku.md` | 重写 | 实现现状 + §2.6 互通对照表 + §6 净室依据 + §7 回环待 CI + §8 S3 清单 |
| `report-sudoku-s2.md` | 新增 | 本报告 |

提交：`4de510a`（①②，已 push）、本报告与文档为第二个提交（③④，随后 push）。两提交均带 `[skip ci]`。

## 4. 测试与 CI 结果

- 本机无 Xcode：Swift 未编译，交付标准为静态自洽（全部新断言只引用已核对过签名的符号：
  `NCSudokuKIP.*`、`NCSudokuAEAD.*`、`NCSudokuCodec.*`、`NCSudoku.deriveUserHash/hexDecode`、
  `NCTarget.ip/atypEncoded`、CryptoKit `Curve25519`；括号配平已脚本自检）。
- 脚本类：`bash -n` 通过；下载路径用 linux-amd64 包实测（tar 成员名 `sudoku` 确认）；
  `start-servers.sh stop` 冒烟通过；两个 JSON 解析通过。
- **CI 未触发**（`[skip ci]`）。S3 触发 `proto-loopback.yml` 时的预期：官方服务端起、端口探活过、
  错误密钥负例过、`testSudokuTCPEcho` 按上文预测失败——这是**预期中的红灯**，是 §8 修复工作的输入，
  不是本段接入的缺陷；其余协议用例不受影响（sudoku 服务端故障会 fail-fast，与 sing-box 同等对待）。

## 5. 支持 / 不支持字段

解析层与 `NCSupport` 显式标记与 S1 完全一致（未改动），全表见 `docs/nc-proto-sudoku.md` §3/§4。
本段新增的是数据面现状注记：`padding-min/max` 已解析未使用（编码器不注填充，有钉住现状的用例）、
`enable-pure-downlink=false`（packed 下行）与 UoT/UDP 未实现、httpmask 仅 legacy/关闭、multiplex 解析
但数据面无会话复用（features=0，协议合法）。后几项暂以"连接期握手错误"呈现，S3 应补显式
`unsupportedReason`（文档 §4 已记录该缺口）。

## 6. 遗留问题与 S3 计划

1. **互通修复（数据面，需另开任务段）**：按依赖序 ① key 规范化（Ed25519 标量纯 Swift 推导）→
   ② PSK 方向性 HKDF → ③ math/rand v1 流移植（文档明言的 wire contract）→ ④ ServerHello 后
   X25519+HKDF 换钥 → ⑤ epoch HMAC 换钥 + 收序校验 → ⑥ 流式解码缓冲（clue 间填充）→ ⑦ none 模式
   分帧对齐决策 → ⑧ 可选：packed 下行 / UoT / mux / httpmask 隧道模式 + 显式不支持标记。净室姿态：
   按行为规范重实现，不抄 Go 源（上游 GPL-3.0，文档 §6 有许可注记）。
2. `testSudokuTCPEcho` 在修复前会红——这是设计好的判决用例，不要因红而跳过或删除。
3. 回环密钥是本仓专用测试值；若 S3 需要官方客户端二进制对打，用 `./sudoku -keygen` 另发一对即可，
   服务端配置与测试常量两处镜像需同步。

## 7. 证据出处索引

- 上游 v0.5.2（tag `v0.5.2.0`，clone 只读于 /tmp）：`internal/tunnel/session_keys.go:16-21,25-47`；
  `internal/tunnel/kip.go:157,173,192,246`；`internal/tunnel/kip_hello.go:24`（60s 偏移）；
  `internal/tunnel/handshake_client.go:71-72`；`internal/tunnel/handshake_server.go:152`；
  `internal/app/client.go`（normalizeClientKey）；`pkg/crypto/record_conn.go:30,36-41,238,270`；
  `pkg/crypto/keypair.go`（master/split 密钥关系）；`pkg/obfs/sudoku/grid.go:26,80-89`；
  `pkg/obfs/sudoku/classic_encode.go:57-69`；`pkg/obfs/sudoku/classic_decode.go:7-35`；
  `internal/config/config.go`（json tag）；`configs/server.config.json`、`configs/README.md`；
  `cmd/sudoku-tunnel/main.go`（-keygen）；`.github/workflows/release.yml`（资产命名）。
- 发布物：GitHub API releases 列表（tag `v0.5.2.0`；darwin-arm64/linux-amd64 tar.gz 均 200 实测）。
- 标准向量：RFC 7748 §6.1（X25519）、RFC 8032 测试向量 1（ed25519 参考实现自检）、hashlib SHA-256。
- 本仓：`Shared/NativeCore/NCSudokuSession.swift`、`Shared/NativeCore/NCSudoku.swift`（2041932）；
  常量镜像四处（§3 表）。
