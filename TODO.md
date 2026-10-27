# Tern 待办

更新：2026-10-27。内核为 NativeCore（纯 Swift + lwIP / WireGuard 的少量 C）。已完成的事项见 `CHANGELOG.md`。

## 发版前

| # | 事项 | 说明 |
|---|---|---|
| 1 | 改名后的签名 | Bundle ID 改为 `com.astemo6.tern`（`.tunnel` / `.widget`），App Group `group.com.astemo6.tern`。仓库里没有签名 secrets 时 CI 照常出未签名 IPA；若配置签名 secrets，证书的描述文件必须覆盖新 ID 和新 App Group（见 `CI.md`）。 |
| 2 | 旧版用户迁移说明 | 新 App 不继承旧版数据：发版说明里写清「旧版导出备份 → Tern 里 更多 → 备份与恢复 导入」。 |
| 3 | 真机回归 | 按 `docs/nativecore-device-checklist.md` 跑一遍（内存、热应用、HTTPS 解密、脚本、小组件 / 控制中心开关需要重新添加）。 |

## 代码整理

| # | 事项 | 说明 |
|---|---|---|
| 1 | 内存治理里的空实现 | `RuntimeMemoryControlling` 与 governor 的堆上限 / 回收一半现在是 no-op（`NativeNoopMemoryControl`）；删掉需要同时改写 governor 的单元测试。 |
| 2 | `RWRegex.lenient` | 恒为 true 的开关，和上一条一起折叠。 |
| 3 | 脚本上下文缓存 | JSC 上下文缓存没有条数上限（`docs/nativecore-memory-budget.md`），加 LRU 上限。 |
| 4 | 小项 | `NCSSRHTTPSimple` 只有测试在用；若干 `Array.removeFirst` 队列可换环形缓冲；`NativeMitmRuntime.errors` 未使用。 |
| 5 | 关于页 GPL 文案 | 「与 … 内核许可一致」的措辞在下次改关于页文案时一并更新（5 种语言）。 |

## 约定

- 测试：推 `test/**` 跑 Self-test 与 Checks；iOS 编译用 `ios.yml` 的 `workflow_dispatch` + `build_only`。同一提交不重复派 run。
- 推 `main` 一律带 `[skip ci]`，否则会触发发版。
- 重写 / 脚本兼容必须通用（Surge / Loon / QX / Egern），不针对单个脚本或 URL 打补丁。
- 文案改动 5 种语言（en / ja / ko / ru / zh-Hans，zh-Hant 由 OpenCC s2twp 生成），`scripts/term_audit.py` 保持通过。
- 只展示真实数据；根页面不观察 DashboardModel；重活不上主线程。
