# CI 说明（GitHub Actions）

| Workflow | 文件 | 什么时候跑 | runner |
|---|---|---|---|
| Checks | `checks.yml` | 推 `main` / `test/**` / `core/**`；PR；手动 | ubuntu（term-audit） |
| Unit tests | `unit-tests.yml` | **PR 到 `main`**；手动（任意 ref）；`workflow_call` | macOS 构建 ×1 + 测试 ×1 |
| Self-test | `ui-tests.yml` | 推 `test/**`；手动（`only` / `shard` / `extras`） | ubuntu（dedupe、plan）+ macOS 构建 ×1 + UI / unit 组合 |
| E2E replay | `e2e-replay.yml` | 手动（`fixture`）；Self-test `extras=e2e` | macOS 构建 ×1 + 回放 ×1（仅 astemo6，需 secret） |
| Proto loopback | `proto-loopback.yml` | 改动内核 / loopback 文件的推送；手动（`jobs`）；Self-test `extras=proto` | macOS 构建 ×1–2 + 每个作业 ×1 |
| Build for testing | `build-for-testing.yml` | 只被上面几个调用（`workflow_call`） | macOS |
| iOS IPA | `ios.yml` | 推 `main` = 发版；手动 `build_only` = 只编译 | macOS |

内核为 NativeCore（纯 Swift）：早期的 `core-update.yml`（每日内核升级）、`core-release.yml`（候选发布审批）
和 Self-test 里的旧内核作业都已删除。

推 `feat/**`、`fix/**`、`draft/**` 等工作分支**不跑任何 workflow**。要测就推到 `test/**`，或开 PR 到 `main`（跑 Checks + Unit tests），
或手动派发：`gh workflow run unit-tests.yml -R astemo6/mihomo-ios --ref <branch>`。
（GitHub 按被推送提交里的 workflow 文件决定触发；基于旧提交、还没合入这版 workflow 的分支推送时仍按旧文件触发，rebase / merge 之后就不会了。Android 的 `android.yml` 在 `android/**` 分支上，另算。）
推 `main` 一律带 `[skip ci]`，否则会触发 ios.yml 发版。

### 合并到 main 需要测试通过

- `unit-tests.yml` 在每个目标为 `main` 的 PR 上跑 `TernUnitTests` 整个包（`UnitTests/` + `AppTests/`，宿主为 App，模拟器，**不跑 UI 测试**）。
- 要让「必须测试通过才能合并」真正生效，需要维护者在仓库 Settings → Branches → `main` 的保护规则里把
  **`Unit tests / unit`** 设为 required status check（workflow 只负责跑，强制在分支保护里配置）。
- 直接推 `main`（不经 PR）不会跑 Unit tests；发版前应先走 PR，或手动派发一次。
- Self-test 的冒烟路径和完整矩阵（astemo6）里的 `unit` 组合也会跑全部单元测试类；那是 `test/**` 上的完整自测，与 PR 上的 Unit tests 互不替代。

## 一次构建，到处测试（ci/speedup，2026-10-27）

- 每个 run 每个 scheme 只构建一次：`build-for-testing.yml` 做 `build-for-testing`（`TernUITests` = App + 单元测试 + UI 测试；
  `TernE2E` = App + 单元测试 + E2E 隧道测试），把 `Build/Products`（含 `.xctestrun`）打成 `tern-products-<scheme>` artifact；
  各测试作业用 `.github/actions/tern-prebuilt`（同一个 Xcode、模拟器提前启动、下载解包）后 `xcodebuild -xctestrun … test-without-building`。
  以前每个 macOS 作业各自编译 6–15 分钟，一次全量 CI 要编译 16 次。
- 编译缓存：Xcode 26 compilation caching（按内容寻址）+ actions/cache。GitHub 缓存按分支隔离（加上默认分支），
  所以新的 `test/**` 分支第一次是冷编译，同一分支之后的运行才命中。
- UI 完整矩阵每种语言 N 个作业（`<lang>:K/N`）：每个作业 = 一份 light 测试 + 一份 dark 检查（test01/03/04/05，原来的 dark:0），
  按实测时长平衡（`scripts/ci/ui-shards.py` + `scripts/ci/ui-test-times.tsv`；测试从 `UITests/*.swift` 读出，新测试自动排进去，
  第 N 个作业的 light 部分 = TernUITests 里其余全部）。同一次运行里该仓库还要跑 unit / E2E / IPA / proto-loopback 时 N = 4
  （每个约 35 分钟测试），否则 N = 5（约 28 分钟）。某个作业明显超过估计时，用新一轮运行的时长更新 tsv。
- 单元测试单独一个 `unit` 组合（只在 astemo6 / 其它仓库跑一次；en 镜像不再重复跑同一个单元测试包）。
- **全量 CI = 两次派发**（每个仓库一次，共用各自的构建）：
  ```bash
  gh workflow run ui-tests.yml -R astemo6/mihomo-ios --ref test/xxx -f shard=full -f extras=e2e,ipa,checks
  # 镜像（scripts 见 work 区 ci-mirror.sh 推 test ref）：
  gh workflow run ui-tests.yml -R astemo666/mihomo-ios --ref test/xxx -f shard=full -f extras=proto,masque-warp
  ```
  `extras`：`e2e`、`proto`（= loopback,openconnect,masque-ip）或单独的 `loopback` / `openconnect` / `masque-ip` / `masque-warp`、
  `ipa`（ios.yml build_only）、`checks`；`all` = e2e,proto,ipa,checks。单独派发 e2e-replay.yml / proto-loopback.yml / unit-tests.yml 照旧可用（它们自己构建一次）。

## 提交信息标记（Self-test）

- `[only:testName]`：只跑这个 UI 测试（`light:sel` 一个组合 + `dark:sel`；只选了单元测试时不跑 dark）；可写多个。
- `[unit:Class]`：再加一个单元测试类。
- `[skip-ui]`：不跑 macOS UI 分片。
- `[shard:all]`：一个仓库里跑两种语言的全部组合（2×5 个作业 + unit）。**别用**——占满 macOS 配额；失败只重跑失败的部分。
- **冒烟路径（默认 auto）**：相对 main 的 merge-base（在 main 上则相对上一个 `v*-build*` 标签）没有改动界面相关文件（App/Views、xcstrings、UITests 等）时，UI 只跑一个 zh-Hans light 冒烟组合（test01/03/04；单元测试在并行的 `unit` 组合里），否则跑完整矩阵（每种语言 N 个 light+dark 作业，astemo6 再加 unit）；`[shard:smoke]` / `[shard:full]` 或 dispatch `shard=smoke|full` 强制。

## 排队与去重

- **同一分支的新推送会取消旧的运行**（同一 workflow 内）：Self-test 按分支（`selftest-<ref>`），Checks 按分支 / PR，
  build_only 按 ref。`main` 上的 Checks 和发版构建不会被取消。
  所以：一轮 UI 还没跑完时别往同一个 `test/**` 分支推；要并行验证另一个修复，推到另一个 `test/**` 分支（各自一组）。
- **同一提交只测一次**：Self-test 开头的 `dedupe` 作业（几秒，ubuntu）查同一 SHA 在**别的分支**上是否已有
  排队中 / 运行中 / 成功的 Self-test；有就跳过 ui，摘要里给出那次运行的链接。
  - 只对 push 生效；手动派发（workflow_dispatch）和对被跳过运行的「Re-run」一定会真跑。
  - 若被参照的那次后来被取消或失败了，对被跳过的这次点 Re-run all jobs 即可。
- **PR 不重复（Checks）**：PR 的 head 是本仓库的 `test/**` 或 `core/**` 分支时，push 已经跑过 Checks，PR 那次的作业直接跳过
  （跳过的作业对必需检查算通过）。来自 fork 或其它分支的 PR 照常跑。Unit tests 不做这种跳过：到 `main` 的 PR 每次都跑。
- **Unit tests**：同一个 PR 的新提交会取消旧的运行。

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
  或手动派发 Self-test：`gh workflow run ui-tests.yml -R astemo6/mihomo-ios --ref test/xxx -f only=TernUITests/TernUITests/testNN_Name`。

## 签名（ios.yml）

`ios.yml` 读取 secrets `BUILD_CERTIFICATE_BASE64`、`P12_PASSWORD`、`APP_PROFILE_BASE64`、`TUNNEL_PROFILE_BASE64`、
`WIDGET_PROFILE_BASE64`、`TEAM_ID`、`KEYCHAIN_PASSWORD`、`EXPORT_METHOD`。四个关键的（证书、App / 隧道描述文件、Team ID）
都在时导出已签名 IPA，否则输出未签名 IPA（目前发布的都是未签名版，由用户自签）。
Bundle ID 与 App Group 取自 `project.yml`：`com.astemo6.tern`、`com.astemo6.tern.tunnel`、`com.astemo6.tern.widget`、
`group.com.astemo6.tern`（2026-10-27 改名）。配置签名 secrets 时，三个描述文件必须对应这三个 App ID，并包含
Network Extensions（packet-tunnel-provider）与这个 App Group 能力；为旧 ID 生成的描述文件不能用。
