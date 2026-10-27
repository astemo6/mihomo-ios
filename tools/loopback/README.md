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
TEST_RUNNER_NC_LOOPBACK=1 xcodebuild -project Tern.xcodeproj \
  -scheme TernUITests -destination 'platform=iOS Simulator,name=iPhone 16 Pro' \
  -only-testing:TernUnitTests/NativeCoreLoopbackTests test
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
| 18014 | sing-box VLESS inbound with ECH — same uuid, TLS + ECH (`outer.localhost` / `localhost`) |
| 18015 | sing-box Trojan inbound with ECH — `nc-loop-trojan-pw`, TLS + ECH (`outer.localhost` / `localhost`) |
| 18016 | `lua-mock-server.py` — Lua backend peer: `HE`→`HO` greeting, then XOR-0x5A relay to 18080 (fix/nc-proto-lua-int) |
| 18018 | sing-box plain HTTP CONNECT inbound (no auth) — peer for the verbatim Shadowrocket `http-backend.lua` (fix/nc-proto-lua-int) |
| 18040 | sing-box naive inbound, TCP (HTTP/2 CONNECT + naive padding) — `nc-loop` / `nc-loop-naive-pw`, self-signed TLS |
| 18041 | sing-box naive inbound, UDP (HTTP/3 over QUIC, ALPN h3) — same user |
| 18060 | sing-box Trojan inbound over WebSocket `/tj` — same password, self-signed TLS (fix/nc-silent-fail) |
| 18061 | sing-box VLESS inbound over HTTPUpgrade `/up` (v2ray-http-upgrade) |
| 18062 | sing-box VLESS inbound over WebSocket `/ed`, max_early_data 2048 in `Sec-WebSocket-Protocol` |
| 18063 | sing-box Trojan inbound over gRPC (service `TunSvc`), self-signed TLS |
| 18013 | trusttunnel_endpoint — H2 (TCP) & H3 (UDP) inbound, Basic auth `nc-loop-tt-user`/`nc-loop-tt-pw` |
| 18012 | masque-proxy — RFC 9298 CONNECT-UDP (HTTP/3) / self-signed TLS (CN=localhost) |
| 18446 | (UDP, job `masque-ip` only) RFC 9484 CONNECT-IP proxy — upstream connect-ip-go integration proxy in an Alpine VM (tools/loopback/connectip), template https://proxy:4433/vpn |
| 18080 | `echo_server.py` TCP echo |
| 18081 | `echo_server.py` UDP echo |
| 18082 | `echo_server.py` TCP blackhole (accepts, reads nothing while paused) |
| 18083 | `echo_server.py` UDP control: datagram `go` → blackhole discards; `pause` → holds again |
| 18084 | `echo_server.py` UDP DNS: every query → one A answer 192.0.2.53 (DNS-over-UDP through Sudoku UoT) |
| 18090 | official Sudoku server v0.5.2.0 (`sudoku/entropy.json`) — prefer_entropy, chacha20-poly1305, legacy HTTP mask, pure downlink; fallback → 18080 |
| 18091 | official Sudoku server (`sudoku/ascii-packed.json`) — prefer_ascii, aes-128-gcm, no HTTP mask, packed downlink |
| 18092 | official Sudoku server (`sudoku/directional-none.json`) — up_ascii_down_entropy, custom table `xpxvvpvv`, aead none |
| 18093 | official Sudoku server (`sudoku/rotation.json`) — custom-tables `xpxvvpvv` / `vxpvxvvp` (ClientHello table hint), packed downlink |
| 18094 | official Sudoku server (`sudoku/closed-fallback.json`) — like 18090, fallback → 18099 (nothing listens: wrong key = closed socket) |
| 18095 | `python3 -m http.server` origin serving `sudoku-fetch.txt` (48 KiB) for the HTTP-fetch-through-Sudoku test |

Sudoku key: the servers hold the master **public** key `3388f6b5…451d`; the tests dial with the split private key
(exercising client key normalisation) and with the public key itself. CI builds the server from the pinned tag's source
(`SUDOKU_BIN`); locally `start-servers.sh` downloads the release tarball.

All inbounds route to a `direct` outbound, so the target a client asks for
*is* the backend it reaches: tests aim at 18080 for echo and 18082 for
back-pressure. All credentials and keys are loopback-only test values,
generated for this purpose — never reuse them anywhere else.

sing-box field notes (1.12.24): the Shadowsocks inbound takes no `network`
field — omitting it enables TCP+UDP. Trojan/Hysteria2/TUIC use the
self-signed cert the start script generates into the runtime dir
(`__LOOPBACK_DIR__` in the template is substituted at render time).
Trojan+ECH (:18015) and VLESS+ECH (:18014) enable TLS ECH with the test
keypair in `tools/loopback/ech_key.pem`.

## ECH (Encrypted Client Hello) notes

Ports 18014 (`vless-ech-in`) and 18015 (`trojan-ech-in`) configure TLS with ECH enabled.
Fixed test-only materials live in `tools/loopback/`:
- `ech_key.pem`: ECH private keys for the sing-box server (generated via `sing-box generate ech-keypair outer.localhost`).
- `ech_config.pem`: Matching ECHConfigList for client connections (`outer.localhost` outer SNI, `localhost` inner SNI).
- `ech_config_stale.pem`: Mismatched/stale ECHConfigList (`stale.outer.localhost`) used to verify server `retry_configs` rejection and retry round trip.

These materials are strictly for loopback testing with self-signed TLS certificates; never use in production.

## Coverage notes

- TCP echo: SS, SS2022, VMess, VLESS, Trojan, Hysteria2, TUIC.
- ECH echo (Trojan/VLESS + ECH): accept and retry round trips against 18015/18014 (client ECH handshake landing in E4).
- TCP echo: SS, SS2022, VMess, VLESS, Trojan, Hysteria2, TUIC, Naïve (h2 and h3, padding
  negotiated, several concurrent streams on one shared h2 session).
- Naïve UDP-over-TCP (UoT v2 through the CONNECT tunnel to the UDP echo); wrong password → 407.
- HTTP2 / HTTP3 proxies without naive padding: no sing-box inbound speaks plain h2/h3 CONNECT
  (the naive inbound insists on the `padding` header), so they are covered by the unit tests
  (NativeCoreNaiveH2H3Tests) and share the naive h2/h3 transport code exercised here.
- TrustTunnel (official trusttunnel_endpoint): H2 TCP echo + wrong password → 407; H3 track not available yet.
- Back-pressure (SS, VMess): against the blackhole. If an environment's
  buffers absorb everything sent, the lag never appears and the test skips
  with an explanation instead of failing — the property is then not
  observable there. The deterministic half of the contract stays in
  `NativeCoreFlowControlTests` (held fake stream).
- UDP echo: SS and SS2022, driven through the Shared wire primitives
  (`NCSSEncoder`/`NCSSDecoder`, `NCSS2022UDPCrypto`) — the `NCUDPSession`
  classes themselves live in the PacketTunnel target, which the app-hosted
  test bundle cannot link.
- Hysteria2 UDP echo: the shared `NCHysteria2Connection` (Shared) over its
  RFC 9221 QUIC datagram flow — spec UDPMessages to the hy2 inbound → UDP echo
  backend; a 3000-byte packet exercises fragmentation and reassembly both ways.
- **MASQUE**: RFC 9298 CONNECT-UDP echo against `masque-proxy` on port 18012
- **MASQUE CONNECT-IP** (job `masque-ip`, E2ETests/NCMASQUEIPLoopbackTests): real RFC 9484 proxy in a QEMU VM; through the tunnel 10.89.1.1 TCP echo :9000 (1 MiB byte-exact), UDP echo :9001, DNS :53 (*.mq.test), HTTP :8080
  (QUIC / HTTP/3 Datagrams targeting UDP echo `:18081`).
- **WireGuard**: server endpoint stands up, but there is no client test —
  NativeCore's WireGuard dialer only exists inside the tunnel (userspace
  lwIP stack), `NCConnector` reports it unsupported in the app/test bundle.
- **OpenConnect**: not sing-box — a real ocserv in an Alpine VM under QEMU
  (`ocserv/start-ocserv-vm.sh`, cloud-init `ocserv/user-data`; TCP 443 →
  127.0.0.1:18443), job `openconnect` in proto-loopback.yml, test class
  `E2ETests/NCOpenConnectLoopbackTests.swift` (TernE2ETunnelTests, because the
  netif is PacketTunnel code). Behind the tunnel: TCP echo :9000, UDP echo
  :9001, dnsmasq :53 (`*.oc.test` → 10.77.0.1), busybox httpd :8080.
- **Mieru**: sing-box has no mieru inbound, so there is no reference server;
  not covered rather than faked.

The constants in this table, `sing-box-config.json` and
`UnitTests/NativeCoreLoopbackTests.swift` are three copies of one truth —
change them together.
