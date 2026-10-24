# CI 说明（GitHub Actions）

| Workflow | 文件 | 什么时候跑 | runner |
|---|---|---|---|
| Checks | `checks.yml` | 推 `main` / `test/**` / `core/**`；PR；手动；被 core-update 调用 | ubuntu |
| Self-test | `ui-tests.yml` | 推 `test/**`；手动（`only` / `skip_go` / `shard`）；被 core-update 调用 | go: ubuntu，ui: macOS ×4 |
| iOS IPA | `ios.yml` | 推 `main` = 发版；手动 `build_only` = 只编译；被 core-update 调用 | macOS |
| Core auto-update | `core-update.yml` | 每天 02:00 UTC；手动（`tag`、`rebuild`） | ubuntu + 调用上面三个 |
| Core release (manual) | `core-release.yml` | 只能手动：维护者批准发布内核升级候选 | ubuntu |

推 `feat/**`、`fix/**`、`draft/**` 等工作分支**不跑任何 workflow**。要测就推到 `test/**`（或开 PR，只跑 Checks）。
（GitHub 按被推送提交里的 workflow 文件决定触发；基于旧提交、还没合入这版 checks.yml 的分支推送时仍会跑 Checks，rebase / merge 之后就不会了。Android 的 `android.yml` 在 `android/**` 分支上，另算。）
推 `main` 一律带 `[skip ci]`，否则会触发 ios.yml 发版。

## 提交信息标记（Self-test）

- `[only:testName]`：只跑这个 UI 测试（在 light 分片 1 里跑，其余分片跳过构建）；可写多个。
- `[unit:Class]`：再加一个单元测试类。
- `[skip-go]`：不跑 Go 作业。`[skip-ui]`：不跑 macOS UI 分片（只改 Go 时用）。
- `[shard:all]`：一个仓库里跑全部 8 个组合。**别用**——占满 macOS 配额；失败只重跑失败的部分。
- **冒烟路径（默认 auto）**：相对 main 的 merge-base（在 main 上则相对上一个 `v*-build*` 标签）没有改动界面相关文件（App/Views、xcstrings、UITests 等）时，UI 只跑一个 zh-Hans light 冒烟组合（test01/03/04 + 全部单元测试），否则跑完整矩阵；`[shard:smoke]` / `[shard:full]` 或 dispatch `shard=smoke|full` 强制。

## 排队与去重

- **同一分支的新推送会取消旧的运行**（同一 workflow 内）：Self-test 按分支（`selftest-<ref>`），Checks 按分支 / PR，
  build_only 按 ref。`main` 上的 Checks 和发版构建不会被取消。
  所以：一轮 UI 还没跑完时别往同一个 `test/**` 分支推；要并行验证另一个修复，推到另一个 `test/**` 分支（各自一组）。
- **同一提交只测一次**：Self-test 开头的 `dedupe` 作业（几秒，ubuntu）查同一 SHA 在**别的分支**上是否已有
  排队中 / 运行中 / 成功的 Self-test；有就跳过 go 和 ui，摘要里给出那次运行的链接。
  - 只对 push 生效；手动派发（workflow_dispatch）和对被跳过运行的「Re-run」一定会真跑。
  - 若被参照的那次后来被取消或失败了，对被跳过的这次点 Re-run all jobs 即可。
- **PR 不重复**：PR 的 head 是本仓库的 `test/**` 或 `core/**` 分支时，push 已经跑过 Checks，PR 那次的作业直接跳过
  （跳过的作业对必需检查算通过）。来自 fork 或其它分支的 PR 照常跑。

## 失败只重跑失败的作业

运行**结束后**才能重跑（运行中不行；要么等它结束，要么取消后再重跑）。重跑用的是同一个提交和同一条提交信息，
所以 `[only:]` / `[skip-ui]` 等标记照样生效，也不会新开 run 号。

```bash
gh run rerun <run-id> --failed -R astemo6/mihomo-ios        # 只重跑失败的作业（及其依赖它们的作业）
gh run rerun <run-id> --job <job-id> -R astemo6/mihomo-ios  # 只重跑某一个作业（job id 见 gh run view <run-id>）
gh run view <run-id> -R astemo6/mihomo-ios                  # 看哪些作业失败、拿 job id
# REST：POST /repos/astemo6/mihomo-ios/actions/runs/<run-id>/rerun-failed-jobs
#       POST /repos/astemo6/mihomo-ios/actions/jobs/<job-id>/rerun
```

网页：打开运行 → 右上角 Re-run jobs → Re-run failed jobs；或在左侧单个作业上点重跑图标。

选择哪种方式：

- runner 基础设施问题（如 “Test crashed with signal kill while preparing to run tests”）、明显的偶发失败 → `--failed`。
- 只有一个 UI 测试失败、想验证修复 → 推修复到**另一个** `test/**` 分支并带 `[only:testName]`，
  或手动派发 Self-test：`gh workflow run ui-tests.yml -R astemo6/mihomo-ios --ref test/xxx -f only=MihomoUITests/MihomoUITests/testNN_Name -f skip_go=true`。
- 只改了 Go → 提交带 `[skip-ui]`。

## 内核升级（core-update）与发版审批

1. 每天检查 MetaCubeX/mihomo 最新正式版。有新版本 → 在 `core/mihomo-<tag>` 上升级 `bridge/go.mod`，go vet + go test 通过后推送。
2. 对**这个提交**（固定 SHA）跑：Checks + Self-test（Go vet / test / `-race` + 本仓库的 UI 分片：zh-Hans light 1–3 + dark）。
   GITHUB_TOKEN 推送的分支不会触发其它 workflow，所以这些是 core-update 以 `workflow_call` 调用的，结果在同一个 run 里。
3. 都通过后才调用 ios.yml `build_only` 构建（有签名 secrets 就签名，`EXPORT_METHOD` 决定 development / ad-hoc / app-store）。
   构建号用「最近一次 iOS IPA run 号.本次 core-update run 号」，如 `297.12`（合法的 CFBundleVersion，排在 297 之后）。
4. 全绿 → `candidate` 作业生成 artifact **`core-candidate-<tag>`**（IPA、entitlements、`manifest.json`、`SHA256SUMS`，保留 30 天），
   然后开 PR（`core/mihomo-<tag>` → main），PR 正文和运行摘要里写好了批准发布的命令。**到这里什么都没发布，main 没动。**
5. 任一步失败 → 开 / 更新 issue「内核自动升级失败：mihomo <tag>」，写明哪一步。

### 批准发布（维护者）

候选只有在维护者手动运行 **Core release (manual)** 后才会发布：

- 网页：Actions → Core release (manual) → Run workflow → `run_id` = 那次 Core auto-update 的 run id，`confirm` = mihomo 版本（如 `v1.19.34`）。
- 命令行：`gh workflow run core-release.yml -R astemo6/mihomo-ios -f run_id=<run-id> -f confirm=<tag>`

它会核对：run 确实是 Core auto-update 且 `candidate` 作业成功；`confirm` 与候选一致；校验和；`core/mihomo-<tag>` 分支
在候选之后没有新提交；同名 release 不存在。然后把**已经测过的那份 IPA 原样**发成 GitHub prerelease
`v<版本>-build<构建号>-mihomo-<tag>`，tag 指向 core 分支上被测的提交。不重新构建、不推送也不合并 main。

之后：合并 PR 到 main 会照常触发一次发版构建；如果候选已经发过、不想再发一版，合并提交信息里带 `[skip ci]`。

尚未接入：上传 TestFlight（需要 App Store Connect API key secrets，且 `EXPORT_METHOD=app-store` 的签名）。
目前候选 IPA 签名与否取决于仓库的签名 secrets。

### 修好后重测

在 `core/mihomo-<tag>` 上推修复（推送本身只会跑 Checks），然后手动运行 Core auto-update：`tag=<tag>`、勾选 `rebuild`。
它不再升级，直接对分支当前提交走上面第 2–4 步，产出新的候选（新的 run id）。
不勾 `rebuild` 时，分支已存在就跳过（避免每天重复）；删除分支后再运行会从 main 重新升级。
