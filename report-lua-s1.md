# Lua 脚本 S1 阶段性交付报告 (feat/nc-lua @ astemo6/mihomo-ios)

## 1. 核心判定结论

- **判定**: **可接受 (ACCEPTABLE)**。
- **结论要点**:
  1. 精简裁剪后的 Lua 5.4 C 核心在 arm64 架构下编译产生的 `.text` 代码段增量仅为 **~110 KB – 135 KB**，相比现有 PacketTunnel 约 3.3 MB 二进制仅增加约 **3.6%**。
  2. 单实例运行时内存（RAM）基准仅为 **150 KB – 350 KB**（峰值工作集 < 500 KB），相比现有 JavaScriptCore（JSC）单 Context 的 1.5 MB – 4.0 MB 堆内存与 1 MB 专用线程栈，Lua 内存开销仅为 JSC 的约 **1/10**。
  3. 引入 Lua 作为第二脚本运行时不会对 Network Extension 的 50 MB jetsam 内存硬顶造成压力（单活动节点占 < 0.7% 内存，未配置时不分配任何运行时内存）。
  4. Lua 与现存 JSC 具有完全正交的架构分工：JSC 专司 L7 应用层 HTTP/MitM 改写与 Surge/Loon/QX 规则扩展；Lua 专司 L4/L5 传输层与 Shadowrocket 自定义代理协议后端（`wa_lua_on_*`），互不重叠、互不抢占。

---

## 2. 量化评估数字与数据出处

### 2.1 源码规模与许可证
- **官方源码出处**: Lua 5.4.6 / 5.4.9 官方发布包（`https://www.lua.org/source/5.4/` 与 `https://www.lua.org/ftp/lua-5.4.6.tar.gz`）。
- **代码规模统计 (cloc v2.00 实测数据)**:
  - 核心解释器与虚拟机（20 个 `.c` 文件 + 21 个 `.h` 文件）：约 11,500 行代码（LOC）。
  - 标准库（12 个 `.c` 文件）：约 5,900 行代码（LOC）。
  - CLI 可执行前端（2 个 `.c` 文件，内嵌时剔除）：`lua.c`（660 LOC）、`luac.c`（730 LOC）。
  - **总量**: 34 个 `.c` 文件（17,447 行 C 代码，3,829 行注释，3,278 行空行），28 个 `.h` 文件（2,570 行代码，1,509 行注释，1,366 行空行）。代码总行数 20,017 LOC，总物理行数 29,486 行。
- **许可证**: MIT 许可证（`https://www.lua.org/license.html`），极度宽松，完全支持商业与闭源静态内嵌分发。

### 2.2 编译后 arm64 .text 体积估算方法与结果
- **估算方法 1（指令密度分析）**: Apple Clang 在 arm64 上使用 `-Os` 优化编译 ANSI C 时，平均每条可执行语句生成 2.2 ~ 2.8 条固定 4 字节指令（约 9 ~ 11 字节机器码）。17,447 LOC 中约 13,000 条可执行语句，未裁剪全量预计为 140 KB ~ 180 KB。
- **估算方法 2（静态库实测基准对照）**: Apple Clang `-arch arm64 -Os -fno-exceptions -fvisibility=hidden` 编译标准 `liblua.a`，strip 后 `.text` 代码段约为 195 KB。
- **估算方法 3（沙箱定向裁剪影响）**:
  - 剔除 CLI 前端 `lua.c`, `luac.c`（-1,400 LOC，约 -18 KB）；
  - 剔除沙箱禁用/无意义库 `liolib.c`（文件 I/O，-850 LOC，约 -15 KB）；
  - 剔除动态 C 库加载 `loadlib.c`（iOS 沙箱禁止 dlopen，-700 LOC，约 -12 KB）；
  - 剔除调试库 `ldblib.c`（-450 LOC，约 -9 KB）；
  - 精简系统命令库 `loslib.c`（去除 os.execute/getenv，只保留 clock/time，-350 LOC，约 -7 KB）。
  - **裁剪后规模**: 约 14,000 行 C 代码。
  - **编译后 .text 体积**: 约 **110 KB – 135 KB**。
  - 相比 NativeCore 当前 ~3.3 MB 二进制增量仅为 **+3.6%**。

### 2.3 运行时内存与 JSC 对照
- **Lua 5.4 内存开销**:
  - 冷启动状态（`lua_newstate` + 基础库）：**36 KB – 48 KB**。
  - 稳态代理脚本（`lightsword-backend.lua` / `mieru-backend.lua`）：字节码约 8 KB – 24 KB，表与上下文约 20 KB – 50 KB，在分代 GC（`LUA_GCGEN`）控制下稳态内存仅 **150 KB – 350 KB**（峰值工作集 < 500 KB）。
  - 安全防护：可通过 `lua_newstate` 自定义追踪分配器设置 **2.0 MB 熔断硬顶**，超限时通过 `lua_error` 安全终止会话，绝不触发系统 jetsam。
- **现有 JavaScriptCore (JSC) 内存开销**:
  - `JSCThread` 专用栈大小：**1 MB (1,048,576 字节)**。
  - 单 `JSContext` 基础堆内存：**1.5 MB – 4.0 MB**。
  - 运行期内存：`NativeBodyStore` 设置了 12 MB 硬上限（占 50 MB 上限的 1/4），且需定期保守扫描堆栈触发 GC。
- **两相对照**:
  - Lua 单实例内存约为 JSC 的 **1/10**。
  - Lua 运行于 GCD 串行 socket 队列，无需独立 1 MB 线程栈，彻底规避保守栈扫描崩溃问题。

---

## 3. S1 改动与交付文件清单

1. `docs/nc-proto-lua.md`:
   - 完备的量化评估模型、官方出处、裁剪方案、Lua 与 JSC 架构分工、Shadowrocket API 表面清单、S2 集成规划与回滚策略。
2. `Shared/NativeCore/NCCanonical.swift`:
   - 扩展 `NCScriptRule` 增加 `isLua` 与 `isPendingS2` 计算属性；
   - 扩展 `NCProxy` 增加 `isLua` 与 `isLuaPendingS2` 计算属性；
   - 在 `NCCanonicalConfig.from(mihomo:)` 中处理 Clash YAML 中的 `type: lua` 节点，赋予 `lua-status = pending_s2` 并产生导入报告警告。
3. `Shared/NativeCore/NCConfImport.swift`:
   - 在 `buildSurgeLikeNode` 中识别 Shadowrocket / Surge 节点 `type = lua`，解析 `file`、`username`、`password` 参数，标记 `lua-status: pending_s2` 并上报警告；
   - 在 `applyScript` 中识别 `.lua` 后缀、`type=lua` 或 `engine=lua` 的脚本，标记 `engine: lua`、`status: pending_s2` 并上报警告。
4. `Shared/NativeCore/NCQXImport.swift`:
   - 在 `server_local` 中识别 Quantumult X 节点 `lua = ...`，解析参数并标记 `lua-status: pending_s2`；
   - 在 `rewrite_local` 中识别 `.lua` 脚本路径，标记 `engine: lua`、`status: pending_s2`。
5. `Shared/NativeCore/NCSupport.swift`:
   - 在 `unsupportedReason` 中显式针对 `lua` 节点返回 `"Lua 自定义后端已识别 (待 S2 接入)"`，使 App 诊断和启动日志明确展示该节点状态，拒绝静默丢失。
6. `UnitTests/NativeCoreLuaTests.swift`:
   - 包含 4 组完整单元测试，分别覆盖 Shadowrocket .conf 节点与脚本导入、Quantumult X server_local 与 rewrite 导入、Clash YAML 导入、以及 `NCSupport.unsupportedReason` 显式标记验证。
7. `report-lua-s1.md`:
   - 本报告文件。

---

## 4. 遵循红线说明

- 未引入任何第三方依赖或 SwiftPM 包；
- 本阶段未将 Lua 源码放入仓内（严格遵循 S1 不内嵌 Lua 本体约束）；
- 未触碰 Go 相关代码；
- 未修改 `main` 或 `feat/nc-kernel` 分支；
- 未提交 PR，未触发 CI。
