import Foundation

/// fix/kit-wireguard-prod PROBE fixtures lifted verbatim from the kit probe's REDUCED seed:
/// `yaml` = a 10-node subset (both WG-family nodes included) for the width-10 sweep;
/// `reducedYAML` = the complete reduced profile (34 nodes + Tern-Test) for the width-30
/// sliding-window sweep — the exact shape ControllerClient.membersDelay drives
/// (DelayStream.groupWidth = 30) when test99 taps the group test button.
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
    static let reducedYAML = """
proxies:
- name: Tern-SOCKS5
  type: socks5
  server: 45.92.159.155
  port: 24001
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
- name: Tern-HTTP
  type: http
  server: 45.92.159.155
  port: 24002
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
- name: Tern-HTTPS
  type: http
  server: 45.92.159.155
  port: 24003
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  tls: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-SS-AEAD
  type: ss
  server: 45.92.159.155
  port: 24004
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: true
- name: Tern-SS2022
  type: ss
  server: 45.92.159.155
  port: 24005
  cipher: 2022-blake3-aes-128-gcm
  password: a2+IgTLmntrk6cIeF6UAFw==
  udp: true
- name: Tern-SS-ShadowTLS
  type: ss
  server: 45.92.159.155
  port: 24006
  cipher: aes-128-gcm
  password: SAI1G1Hi9IMWxT8j1dYst0Rq
  udp: false
  plugin: shadow-tls
  client-fingerprint: chrome
  plugin-opts:
    host: www.microsoft.com
    password: o12D3YF7YmlxDLLNlTDW
    version: 3
- name: Tern-VMess
  type: vmess
  server: 45.92.159.155
  port: 24007
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  alterId: 0
  cipher: auto
  network: tcp
  udp: true
- name: Tern-VMess-WS
  type: vmess
  server: 45.92.159.155
  port: 24008
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  alterId: 0
  cipher: auto
  network: ws
  udp: true
  ws-opts:
    path: /y9dglm5u
    headers:
      Host: tern.test
- name: Tern-VLESS
  type: vless
  server: 45.92.159.155
  port: 24009
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  network: tcp
  udp: true
- name: Tern-VLESS-Reality
  type: vless
  server: 45.92.159.155
  port: 24010
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: www.apple.com
  client-fingerprint: chrome
  reality-opts:
    public-key: Wp6PjTC3gfcCEMQ3pG0ROusHdgAs7Lfsx023gfGDEVY
    short-id: 21dde3c3112bbc4b
- name: Tern-VLESS-Vision
  type: vless
  server: 45.92.159.155
  port: 24011
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: tern.test
  client-fingerprint: chrome
  skip-cert-verify: true
- name: Tern-VLESS-MLKEM
  type: vless
  server: 45.92.159.155
  port: 24018
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  network: tcp
  udp: true
  encryption: mlkem768x25519plus.native.0rtt.bPK78QJ90wb6GT1w3C6W1k0FcIHrfrT60gmvJbgdWxg
- name: Tern-Trojan
  type: trojan
  server: 45.92.159.155
  port: 24012
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-Hysteria
  type: hysteria
  server: 45.92.159.155
  port: 24013
  protocol: udp
  up: 50 Mbps
  down: 100 Mbps
  alpn:
  - hysteria
  udp: true
  auth-str: BJOSucxjZsULJdnsyNPT
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
- name: Tern-AnyTLS
  type: anytls
  server: 45.92.159.155
  port: 24016
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-Naive-H2
  type: naive
  server: 45.92.159.155
  port: 24017
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  quic: false
  udp: true
  udp-over-tcp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-Naive-H3
  type: naive
  server: 45.92.159.155
  port: 24017
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  quic: true
  udp: true
  udp-over-tcp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-SS-Obfs
  type: ss
  server: 45.92.159.155
  port: 24021
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: false
  plugin: obfs
  plugin-opts:
    mode: http
    host: www.bing.com
- name: Tern-SS-V2ray
  type: ss
  server: 45.92.159.155
  port: 24022
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: false
  plugin: v2ray-plugin
  plugin-opts:
    mode: websocket
    host: tern.test
    path: /y566yq2t
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
- name: Tern-SS-Cloak
  type: ss
  server: 45.92.159.155
  port: 24024
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: false
  plugin: cloak
  plugin-opts:
    UID: KCW/YoRV4J+FJD7akXaaqA==
    PublicKey: uuDne9KZXYrt3/1YlskNzpFM5i1oRONAS3oDJP98vko=
    ServerName: www.bing.com
    EncryptionMethod: plain
    BrowserSig: chrome
    NumConn: 4
    ProxyMethod: shadowsocks
- name: Tern-SS-Restls
  type: ss
  server: 45.92.159.155
  port: 24025
  cipher: aes-256-gcm
  password: K0Alt8rg3ONkK6f97ISlQnKq
  udp: false
  plugin: restls
  client-fingerprint: chrome
  plugin-opts:
    host: www.microsoft.com
    password: P4nax6QorC3yJinvT0aW
    version-hint: tls13
    restls-script: 300?100,400~100,350~100,600~100,300~200,300~100
- name: Tern-SSR
  type: ssr
  server: 45.92.159.155
  port: 24026
  cipher: aes-256-cfb
  password: o8nAqMvxluL2CvQocwdg
  protocol: auth_aes128_md5
  obfs: tls1.2_ticket_auth
  udp: true
- name: Tern-Snell4
  type: snell
  server: 45.92.159.155
  port: 24027
  psk: jynh5z8U6g5lctGAyUnwFxYG
  password: jynh5z8U6g5lctGAyUnwFxYG
  version: 4
  udp: true
- name: Tern-Snell5
  type: snell
  server: 45.92.159.155
  port: 24028
  psk: jynh5z8U6g5lctGAyUnwFxYG
  password: jynh5z8U6g5lctGAyUnwFxYG
  version: 5
  udp: true
- name: Tern-Mieru
  type: mieru
  server: 45.92.159.155
  port: 24029
  transport: TCP
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  multiplexing: MULTIPLEXING_LOW
- name: Tern-SSH
  type: ssh
  server: 45.92.159.155
  port: 24030
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
- name: Tern-Brook
  type: brook
  server: 45.92.159.155
  port: 24031
  password: yeCsUwsFbAhUYMUgdeiC
  transport: server
  udp: true
- name: Tern-GOST-Relay
  type: gost-relay
  server: 45.92.159.155
  port: 24032
  username: terndpa3
  password: yeCsUwsFbAhUYMUgdeiC
  tls: true
  udp: true
  sni: tern.test
  skip-cert-verify: true
- name: Tern-Juicity
  type: juicity
  server: 45.92.159.155
  port: 24033
  uuid: 6ceb5215-15b9-4ef3-8a48-61ee6ff3ae71
  password: yeCsUwsFbAhUYMUgdeiC
  udp: true
  congestion-controller: bbr
  sni: tern.test
  skip-cert-verify: true
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
  - Tern-SOCKS5
  - Tern-HTTP
  - Tern-HTTPS
  - Tern-SS-AEAD
  - Tern-SS2022
  - Tern-SS-ShadowTLS
  - Tern-VMess
  - Tern-VMess-WS
  - Tern-VLESS
  - Tern-VLESS-Reality
  - Tern-VLESS-Vision
  - Tern-VLESS-MLKEM
  - Tern-Trojan
  - Tern-Hysteria
  - Tern-Hysteria2
  - Tern-TUIC
  - Tern-AnyTLS
  - Tern-Naive-H2
  - Tern-Naive-H3
  - Tern-SS-Obfs
  - Tern-SS-V2ray
  - Tern-SS-KCPTun
  - Tern-SS-Cloak
  - Tern-SS-Restls
  - Tern-SSR
  - Tern-Snell4
  - Tern-Snell5
  - Tern-Mieru
  - Tern-SSH
  - Tern-Brook
  - Tern-GOST-Relay
  - Tern-Juicity
  - Tern-WireGuard
  - Tern-AmneziaWG
rules:
- MATCH,Tern-Test
"""
}
