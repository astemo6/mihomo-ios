# Protocol loopback servers

Local reference servers for `UnitTests/NativeCoreLoopbackTests.swift`
(fix/nc-proto-loopback): the NativeCore outbound stacks are driven through
`NCConnector` against a real server, byte-exact echo is checked, the #116
`send(_:completion:)` back-pressure contract is exercised on a real socket,
and the SS / SS2022 UDP wire formats are round-tripped.

## Run

```sh
tools/loopback/start-servers.sh start    # downloads pinned sing-box on first run
tools/loopback/start-servers.sh status
tools/loopback/start-servers.sh stop
```

Then run the tests (from the repo root, project generated as in
unit-tests.yml):

```sh
xcodegen generate --spec project-uitests.yml
TEST_RUNNER_NC_LOOPBACK=1 xcodebuild -project Mihomo.xcodeproj \
  -scheme MihomoUITests -destination 'platform=iOS Simulator,name=iPhone 16 Pro' \
  -only-testing:MihomoUnitTests/NativeCoreLoopbackTests test
```

Without the env var the tests probe the SS port and run if the servers are
already up; with neither, every test skips (the normal unit-test run is
unaffected). CI runs this via `.github/workflows/proto-loopback.yml`.

Runtime state (sing-box binary, rendered config, self-signed cert, logs,
pidfiles) lives in `$NC_LOOPBACK_DIR` (default `/tmp/nc-loopback`), never in
the repo. Environment overrides: `SING_BOX_VERSION` (default `1.12.24`),
`SING_BOX_BIN`.

## Topology (all 127.0.0.1)

| Port | What |
| ---: | --- |
| 18001 | sing-box Shadowsocks inbound — `aes-256-gcm` / `nc-loop-ss-pw` |
| 18002 | sing-box Shadowsocks inbound — `2022-blake3-aes-128-gcm` / PSK `bmMtbG9vcC0yMDIyLXB3MA==` |
| 18003 | sing-box VMess inbound — uuid `b831381d-6324-4d53-ad4f-8cda48b30811`, alterId 0 |
| 18004 | sing-box VLESS inbound — same uuid, no flow |
| 18005 | sing-box Trojan inbound — `nc-loop-trojan-pw`, self-signed TLS (CN=localhost) |
| 18006 | sing-box Hysteria2 inbound — `nc-loop-hy2-pw`, TLS ALPN h3 |
| 18007 | sing-box TUIC inbound — same uuid / `nc-loop-tuic-pw`, ALPN h3, BBR |
| 18008 | sing-box WireGuard endpoint (UDP) — test keypair, see config |
| 18080 | `echo_server.py` TCP echo |
| 18081 | `echo_server.py` UDP echo |
| 18082 | `echo_server.py` TCP blackhole (accepts, reads nothing while paused) |
| 18083 | `echo_server.py` UDP control: datagram `go` → blackhole discards; `pause` → holds again |

All inbounds route to a `direct` outbound, so the target a client asks for
*is* the backend it reaches: tests aim at 18080 for echo and 18082 for
back-pressure. All credentials and keys are loopback-only test values,
generated for this purpose — never reuse them anywhere else.

sing-box field notes (1.12.24): the Shadowsocks inbound takes no `network`
field — omitting it enables TCP+UDP. Trojan/Hysteria2/TUIC use the
self-signed cert the start script generates into the runtime dir
(`__LOOPBACK_DIR__` in the template is substituted at render time).

## Coverage notes

- TCP echo: SS, SS2022, VMess, VLESS, Trojan, Hysteria2, TUIC.
- Back-pressure (SS, VMess): against the blackhole. If an environment's
  buffers absorb everything sent, the lag never appears and the test skips
  with an explanation instead of failing — the property is then not
  observable there. The deterministic half of the contract stays in
  `NativeCoreFlowControlTests` (held fake stream).
- UDP echo: SS and SS2022, driven through the Shared wire primitives
  (`NCSSEncoder`/`NCSSDecoder`, `NCSS2022UDPCrypto`) — the `NCUDPSession`
  classes themselves live in the PacketTunnel target, which the app-hosted
  test bundle cannot link.
- **WireGuard**: server endpoint stands up, but there is no client test —
  NativeCore's WireGuard dialer only exists inside the tunnel (userspace
  lwIP stack), `NCConnector` reports it unsupported in the app/test bundle.
- **Mieru**: sing-box has no mieru inbound, so there is no reference server;
  not covered rather than faked.

The constants in this table, `sing-box-config.json` and
`UnitTests/NativeCoreLoopbackTests.swift` are three copies of one truth —
change them together.
