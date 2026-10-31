import Foundation

/// fix/kit-wireguard-prod PROBE fixture: a 10-node profile lifted verbatim from the kit
/// probe's REDUCED seed (same nodes, same DNS section) for the concurrency sweep test in
/// NCWireGuardTunnelDelayTests — the group-test shape test99 drives (width-10 parallel
/// per-member delay calls), reproduced in-process.
enum NCWireGuardSweepFixture {
    static let yaml = """
proxies:
- name: Tern-SS-AEAD
  type: ss
  server: 45.92.159.155
  port: 24004
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: true
- name: Tern-VLESS
  type: vless
  server: 45.92.159.155
  port: 24009
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  network: tcp
  udp: true
- name: Tern-Trojan
  type: trojan
  server: 45.92.159.155
  port: 24012
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-Hysteria2
  type: hysteria2
  server: 45.92.159.155
  port: 24014
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-TUIC
  type: tuic
  server: 45.92.159.155
  port: 24015
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  password: yeCsUwsFbAhUYMUgdeiC
  alpn:
  - h3
  udp: true
  congestion-controller: bbr
  sni: tern.test
  skip-cert-verify: true
- name: Tern-SS-KCPTun
  type: ss
  server: 45.92.159.155
  port: 24023
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: false
  plugin: kcptun
  plugin-opts:
    key: HJ8AfY4jBv6wcD0Xf220
    crypt: aes
    mode: fast
    nocomp: true
    smuxver: 1
    datashard: 10
    parityshard: 3
    mtu: 1350
    sndwnd: 1024
    rcvwnd: 1024
- name: Tern-SSR
  type: ssr
  server: 45.92.159.155
  port: 24026
  cipher: aes-256-cfb
  password: o8nAqMvxluL2CvQocwdg
  protocol: auth_aes128_md5
  obfs: tls1.2_ticket_auth
  udp: true
- name: Tern-Snell5
  type: snell
  server: 45.92.159.155
  port: 24028
  psk: jynh5z8U6g5lctGAyUnwFxYG
  password: jynh5z8U6g5lctGAyUnwFxYG
  version: 5
  udp: true
- name: Tern-WireGuard
  type: wireguard
  server: 45.92.159.155
  port: 24034
  ip: 10.66.0.2
  udp: true
  mtu: 1280
  dns:
  - 1.1.1.1
  private-key: OJVQcAQumlNiADByjF03bEqlq5jHFN2k3DFN0BaE/Eo=
  public-key: pDuHgrRuI0rWdogrndZwuyr/D68pUDok1FbXP9Rk0X0=
  remote-dns-resolve: true
- name: Tern-AmneziaWG
  type: wireguard
  server: 45.92.159.155
  port: 24035
  ip: 10.67.0.2
  udp: true
  mtu: 1280
  dns:
  - 1.1.1.1
  private-key: SEVf8Xe/xQjVtDts7zCsKgH5Mo14jT9IU3xAqmo0OUM=
  public-key: gqz9RvmIyupAg3w25yP/5n4SaYsh9V1Ihr8eTmkJfDQ=
  remote-dns-resolve: true
  amnezia-wg-option:
    jc: 4
    jmin: 40
    jmax: 70
    s1: 29
    s2: 56
    h1: 610898151
    h2: 1285981084
    h3: 1767517731
    h4: 1995304650
proxy-groups:
- name: Tern-Test
  type: select
  proxies:
  - Tern-SS-AEAD
  - Tern-VLESS
  - Tern-Trojan
  - Tern-Hysteria2
  - Tern-TUIC
  - Tern-Snell5
  - Tern-SSR
  - Tern-SS-KCPTun
  - Tern-WireGuard
  - Tern-AmneziaWG
rules:
- MATCH,Tern-Test
"""
}
