# E2E replay

`.github/workflows/e2e-replay.yml` replays a real user config end to end on CI:

1. **Stage 1** (`UnitTests/NativeCoreE2EReplayTests.swift`, App module): `ImportRouter.route` →
   `ConfImport.save` (QX / Surge .conf: profile, 「（重写）」 module, `[rewrite_remote]` modules, settings, rule-set /
   node-set downloads) or `TernFullExport.applyInApp`; the QX `[mitm]` p12 is imported like the CA page does; then the
   connect path's runtime generation (`E2EPrep` = `NativeRuntimePrep.prepareSyncLocked` without the App Group guard).
2. **Stage 2** (`E2ETests/TernE2ETunnelTests.swift`, own bundle compiling the PacketTunnel sources):
   `NativeTunnelCore.start(home:flow:…)` in-process with a synthetic `NEPacketTunnelFlow` (`E2EFlow`) feeding the
   real lwIP data plane, the real controller and the real MitM front.

Every scenario prints one redacted `E2E-RESULT|stage|name|PASS/FAIL/SKIP/INFO|detail` line; `summarize.py` turns
them into the job summary. A FAIL listed in `known-gaps.txt` shows as KNOWN and does not fail the job.

## Fixture

* `fixture.enc` — the encrypted real fixture (never commit plaintext). Decrypted in the workflow with the repository
  secret `TERN_E2E_KEY` (Settings → Secrets and variables → Actions):

  ```sh
  # encrypt (locally; the passphrase is the TERN_E2E_KEY value)
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in my-export.conf -out tools/e2e/fixture.enc -pass env:TERN_E2E_KEY
  # what the workflow runs
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in tools/e2e/fixture.enc -pass env:TERN_E2E_KEY -out "$RUNNER_TEMP/fixture.conf"
  ```
* `sample/` — the sanitized fallback: a QX .conf whose nodes, subscription, rule lists, remote module and scripts all
  live on 127.0.0.1 (`start-e2e.sh`: the `tools/loopback` sing-box fleet, a second sing-box with VMess+ws / SS,
  `e2e_server.py` on :18480). Domains `*.localtest.me` resolve to 127.0.0.1 in public DNS.

Run: Actions → E2E replay → Run workflow (`fixture`: auto | sample | real). auto = real when the secret exists.

## Secrets never leave the job

`mask.py add-mask` masks every server host / password / uuid / URL / passphrase of the fixture; the tests redact the
same values (plus the runtime's) in every result line; `mask.py scrub` + `check` run over every uploaded file.

## Reading the summary

The job summary (and `report.md` / `summary.md` in the `e2e-replay-<sample|real>` artifact) has one row per scenario:

| result | meaning |
|---|---|
| ✅ PASS | the scenario worked end to end |
| ❌ FAIL | a bug — fails the job unless listed in `known-gaps.txt` |
| 🟧 KNOWN | a FAIL listed in `known-gaps.txt` (the line names the branch that fixes it, or "not implemented") |
| 🟩 FIXED? | a PASS still listed in `known-gaps.txt` — delete the line |
| ⏭️ SKIP | could not run here (no internet / public DNS on the runner, node unreachable from CI, sample-only scenario); the detail says why |
| ℹ️ INFO | context only (fixture size, CA import, `stage-done`) |

Each stage ends with an `app/stage-done` or `tunnel/stage-done` INFO line. `summarize.py --expect-stages app,tunnel`
turns a missing one into a FAIL (hang, crash, step timeout, stage never ran), so a partial run can't go green.
Stage 1 prints `prep +N.Ns: <step>` notes and has a watchdog (`TEST_RUNNER_TERN_E2E_PREP_TIMEOUT`, default 600 s)
that fails `runtime-generation` with the last step reached instead of hanging the job. The `notes` block lists the
import report, prep warnings, unsupported / unparsed rules and the tunnel's startup log (all redacted).

## Artifacts

`e2e-replay-<kind>`: `summary.md` (= `report.md`), `results.jsonl`, `notes.txt`, `stage1.log` / `stage2.log`
(scrubbed; dropped when `mask.py check` still finds a secret) and their `*.extract.txt`. Never the fixture, the
handoff, or anything decrypted.

## Known gaps

`known-gaps.txt`: `<scenario fnmatch pattern> TAB <why — branch that fixes it | not implemented>`. Add a line only with
evidence from a run (run id in the reason); delete it when the fixing branch lands and the scenario shows FIXED?.

## Device-parity scenarios (fix/nc-tls-scripts)

Added after device build506 (2026-10-27) showed failures the replay had passed over:

| scenario | stage | fails when |
|---|---|---|
| `node-tls:<provider>` | tunnel | every provider node through `/proxies/{name}/delay` (8 in parallel, ≤ 60 per provider): ok ratio, TLS handshake ratio, the provider body format (Clash YAML / JSON / [base64] share links / QX lines / Surge lines, from the core's `proxy provider <p>: body …` line or the re-parsed cache) and whether it is a QX `[server_remote]` provider (then: how many TLS nodes still verify without `tls-verification=true`), and a failure-reason histogram (stage · reason ×N). FAIL on an internal TLS error of our own stack (CertificateVerify, record decrypt, certificate parse, signature invalid, unexpected message, key agreement, inner content type, HelloRetryRequest), on a certificate-trust error (`-98xx`) for a node whose skip-cert-verify is on (in the config or as dialed), or on a `-98xx` QX `[server_remote]` node the QX TLS default was not applied to. Every `-98xx` failure (≤ 20) gets an evidence line: redacted TLS fields (type / network, skip-cert-verify in the config and as dialed — NCStream's `· verify on` / `· skip-cert-verify on` — SNI none / IP / name, REALITY, fingerprint, pin) and a direct probe of the server from the runner (negotiated TLS version, chain count, leaf key type, self-signed, validity, subject vs SNI, issuer, SecTrust verdict with names masked). No server, SNI or credential is printed. Server / network failures (ws 4xx/5xx, timeouts) only go into the histogram. |
| `script-trigger`, `script-trigger-console` | tunnel | a request built from a script rule of the real config (literal MitM host, sampled path) through the TUN + MitM front to the real host produces no `[SCRIPT]` line / no 脚本日志 line for that script (internet + public DNS needed, else SKIP). |
| `selfcheck-integrity` | tunnel | script-rule / MitM-host counts differ between the App's snapshot and the core (`/mitm/status`), or an unloadable script is not named in 脚本日志. |
| `stale-fakeip-host` | tunnel | an HTTP request **with a Host header** to an unmapped fake IP gets an HTTP answer instead of an RST (the C stack accepts after the 3-way handshake, so the refusal is an RST right after it, before any byte; the App self-check's probe — the Host used to be sniffed and the request served). |
| `reimport`, `reimport-provider-update`, `reimport-runtime` | app | delete the imported profile, import the same fixture again, force-update every provider (`ProviderUpdater.updateAll`), regenerate the runtime. Provider failures that are the environment (HTTP 4xx/5xx, timeouts, network) are listed as INFO inside the row; any other error (e.g. 「路径不在内核目录内」) fails. Stage 2 runs on the re-imported profile. |

The App's 一键自检 itself needs VPNManager and the UI, so it is not run here; its tunnel-side checks are the rows above
plus `stale-fakeip-reset` / `fakeip-persist-restore`.
