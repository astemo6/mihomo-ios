# Tern 服务器自测工具包

在你自己的 Linux VPS 上一键装好 Tern 支持的各个协议的**参考服务端**，用来在真机上验证 Tern 的协议实现。
每个服务端都是一个 systemd 服务；凭据随机生成；结束时打印端口表、每个节点的导入文本和终端二维码，
外加一个包含全部节点的订阅地址。

> 这是测试工具：服务以 root 运行、凭据写在 `/root/tern-test/`，测完请 `--uninstall`。不要拿它当生产代理。

## 系统要求

- Debian 12、Ubuntu 22.04 或 Ubuntu 24.04，x86_64 或 arm64（脚本会检测；其他 Debian 系会警告后继续尝试）
- root、systemd、公网 IPv4
- WireGuard 需要内核模块，ocserv / AmneziaWG 需要 `/dev/net/tun`（OpenVZ / LXC 容器型 VPS 可能没有）
- 云厂商的安全组 / 防火墙要另外放行下表端口（TCP 和 UDP 都要）。本机防火墙由脚本处理：ufw 启用时用 `ufw allow`，
  否则用带 `tern-test` 注释的 iptables 规则（由 `tern-net.service` 在开机时加上、卸载时删掉）

## 一键安装

```sh
curl -fsSL https://raw.githubusercontent.com/astemo6/mihomo-ios/refs/heads/tools/server-test/tools/server-test/install.sh | sudo bash
```

带参数时：

```sh
curl -fsSL https://raw.githubusercontent.com/astemo6/mihomo-ios/refs/heads/tools/server-test/tools/server-test/install.sh -o install.sh
sudo bash install.sh --only ss,vless-reality,hysteria2,openconnect,trusttunnel,sudoku,masque-ip
```

| 参数 | 作用 |
|---|---|
| （无） | 安装全部协议，自签证书 |
| `--only a,b,c` | 只装这些协议（id 见下表，`--list` 列出） |
| `--skip a,b` | 跳过这些协议 |
| `--domain auto` | 用 `<IP 横线形式>.sslip.io` 申请 Let's Encrypt 证书（certbot standalone，需要 80/tcp 能从公网访问） |
| `--domain 域名 [--email 邮箱]` | 用你自己的域名（A 记录先指向 VPS）申请证书 |
| `--ip 1.2.3.4` | 手动指定公网 IP（自动探测失败时） |
| `--port-base 24000` | 端口基数（默认 24000，下表端口 = 基数 + 偏移） |
| `--no-firewall` | 不动本机防火墙 |
| `--show` | 重新打印端口表、节点和二维码 |
| `--uninstall` | 卸载（服务、文件、防火墙规则、测试用户、本工具装的软件包） |

可以重复运行：凭据保存在 `/root/tern-test/state.json`，重跑沿用原凭据；本次没选中的协议，其服务会被停掉并移除。

## 协议、端口与服务端

二维码一列说明 Tern「添加节点 → 扫描二维码」扫到的是什么：**链接** = 分享链接；**Surge 行** = `名称 = 类型, …` 节点行；
**YAML** = 以 `proxies:` 开头的 Clash 节点片段。三种都会进入 Tern 的同一个节点导入器（扫码 → 粘贴框 → `添加`）。

| id | 端口 | 协议 | 服务端（版本） | systemd 服务 | 二维码 |
|---|---|---|---|---|---|
| `socks` | 24001 tcp+udp | SOCKS5（用户名密码） | sing-box 1.12.24 | tern-sing-box | 链接 |
| `http` | 24002 tcp | HTTP 代理 | sing-box | tern-sing-box | 链接 |
| `https` | 24003 tcp | HTTPS 代理 | sing-box | tern-sing-box | YAML（自签时）/ 链接（有域名时） |
| `ss` | 24004 tcp+udp | Shadowsocks aes-256-gcm | sing-box | tern-sing-box | 链接 |
| `ss2022` | 24005 tcp+udp | Shadowsocks 2022-blake3-aes-128-gcm | sing-box | tern-sing-box | 链接 |
| `ss-shadowtls` | 24006 tcp | SS + shadow-tls v3（握手站 www.microsoft.com） | sing-box | tern-sing-box | YAML |
| `vmess` | 24007 tcp | VMess (AEAD, TCP) | sing-box | tern-sing-box | 链接 |
| `vmess-ws` | 24008 tcp | VMess + WebSocket | sing-box | tern-sing-box | 链接 |
| `vless` | 24009 tcp | VLESS 明文 TCP | sing-box | tern-sing-box | 链接 |
| `vless-reality` | 24010 tcp | VLESS + Reality + xtls-rprx-vision | sing-box | tern-sing-box | 链接 |
| `vless-vision` | 24011 tcp | VLESS + TLS + xtls-rprx-vision | sing-box | tern-sing-box | 链接 |
| `vless-enc` | 24018 tcp | VLESS mlkem768x25519plus 加密 | Xray 26.10.21 | tern-xray | 链接 |
| `trojan` | 24012 tcp | Trojan | sing-box | tern-sing-box | 链接 |
| `hysteria` | 24013 udp | Hysteria v1 | sing-box | tern-sing-box | 链接 |
| `hysteria2` | 24014 udp | Hysteria2 | sing-box | tern-sing-box | 链接 |
| `tuic` | 24015 udp | TUIC v5（bbr, h3） | sing-box | tern-sing-box | 链接 |
| `anytls` | 24016 tcp | AnyTLS | sing-box | tern-sing-box | 链接 |
| `naive` | 24017 tcp+udp | Naïve：H2（TCP）与 H3（UDP）两个节点 | sing-box | tern-sing-box | 链接 |
| `ss-obfs` | 24021 tcp | SS + simple-obfs http | shadowsocks-rust 1.25.0 + simple-obfs (apt) | tern-ssrust | 链接 |
| `ss-v2ray` | 24022 tcp | SS + v2ray-plugin websocket | shadowsocks-rust + shadowsocks-v2ray-plugin (apt) | tern-ssrust | 链接 |
| `ss-kcptun` | 24023 udp | SS + kcptun（aes / fast / nocomp / smux v1） | kcptun (apt) → 本机 SS | tern-kcptun | YAML |
| `ss-cloak` | 24024 tcp | SS + Cloak | Cloak 2.12.0 → 本机 SS | tern-cloak | YAML |
| `ss-restls` | 24025 tcp | SS + restls（tls13，伪装 www.microsoft.com） | restls 0.1.1 → 本机 SS | tern-restls | YAML |
| `ssr` | 24026 tcp+udp | ShadowsocksR aes-256-cfb / auth_aes128_md5 / tls1.2_ticket_auth | shadowsocksr (Python, 固定提交) | tern-ssr | 链接 |
| `snell4` | 24027 tcp+udp | Snell v4 | 官方 snell-server 4.1.1 | tern-snell4 | Surge 行 |
| `snell5` | 24028 tcp+udp | Snell v5 | 官方 snell-server 5.0.1 | tern-snell5 | Surge 行 |
| `mieru` | 24029 tcp | Mieru（TCP） | mita 3.39.0 (.deb) | mita | 链接 |
| `ssh` | 24030 tcp | SSH（只允许端口转发的测试用户，独立于系统 sshd） | OpenSSH | tern-sshd | 链接 |
| `brook` | 24031 tcp+udp | Brook server | brook 20270101 | tern-brook | 链接 |
| `gost-relay` | 24032 tcp | GOST v3 relay+tls | gost 3.3.1 | tern-gost | YAML |
| `juicity` | 24033 udp | Juicity | juicity-server 0.5.0 | tern-juicity | 链接 |
| `wireguard` | 24034 udp | WireGuard（10.66.0.0/24，NAT 出网） | 内核 + wireguard-tools | tern-wg | 链接 |
| `awg` | 24035 udp | AmneziaWG 1.0（Jc/Jmin/Jmax/S1/S2/H1–H4） | amneziawg-go + amneziawg-tools（在 VPS 上编译） | tern-awg | YAML |
| `openconnect` | 24036 tcp+udp | OpenConnect，密码认证，DTLS 开（Tern 客户端走 CSTP） | ocserv (apt) | tern-ocserv | 链接 |
| `trusttunnel` | 24037 tcp+udp | TrustTunnel H2（TCP）与 H3（UDP）两个节点 | 官方 trusttunnel_endpoint 1.1.0 | tern-trusttunnel | 链接 |
| `sudoku` | 24038 tcp | Sudoku（prefer_entropy / chacha20-poly1305 / legacy HTTP mask） | 官方 sudoku 0.5.2.0 | tern-sudoku | 链接 |
| `masque-ip` | 24039 udp | MASQUE CONNECT-IP（RFC 9484，全流量 NAT 出网） | connect-ip-go 集成代理（在 VPS 上编译） | tern-connectip | YAML |
| `masque-udp` | 24040 udp | MASQUE CONNECT-UDP（RFC 9298，只承载 UDP） | masque-go 0.6.0 proxy（在 VPS 上编译） | tern-masque | YAML |
| — | 24041 tcp | 订阅文件（HTTPS，随机 token 路径） | Python 小服务 | tern-sub | 订阅 URL |
| — | 24042 tcp | 订阅文件（HTTP 备用，仅自签证书时） | 同上 | tern-sub | 订阅 URL |

服务端版本与 `tools/loopback/` 在 CI 里跑通的一致：sing-box 1.12.24、trusttunnel_endpoint 1.1.0、Sudoku 0.5.2.0、
connect-ip-go 23c2121、masque-go 0.6.0。Go 只在 VPS 上编译服务端软件用（装在 `/opt/tern-test/go`，卸载时删除）。

另有一个 `tern-net.service`：本机防火墙放行、ocserv / WireGuard / AmneziaWG / CONNECT-IP 的 NAT 与转发，
以及 CONNECT-IP 用的网络命名空间 `terncip`（connect-ip-go 的集成代理通过 veth `tcip0` 收发 IP 包）。

## 证书

- **默认自签**：CN / SNI 为 `tern.test`，SAN 含 VPS IP。所有 TLS / QUIC 节点都带 `sni: tern.test` 和
  `skip-cert-verify: true`；安装结束会打印证书 SHA-256 指纹，可自行核对。
- **`--domain auto` / `--domain 域名`**：Let's Encrypt 证书，节点不跳过校验，SNI 为该域名；80/tcp 保持放行以便自动续期。
- Reality 用的是 www.microsoft.com 的真实握手，不用本机证书。

## 二维码与订阅

- 每个节点打印一个终端二维码（`qrencode -t ANSIUTF8`）和下面的原文，PNG 存在 `/root/tern-test/qr/`。
- 在 Tern：**添加节点 → 扫描二维码**（或「从相册」选 PNG），识别出的文本进入粘贴框，点「添加」。
- 订阅：同一份 Clash 配置（`proxies` + 一个 `Tern-Test` 选择组 + `MATCH`）由 `tern-sub` 提供：
  - 有域名证书时用 HTTPS 地址；
  - 自签证书时 iOS 不信任 HTTPS 地址，请用打印出的 **HTTP 备用地址**（Tern 允许 http 订阅）。
  - 订阅二维码给 iPhone 相机扫（拷贝链接），然后在 Tern「添加订阅」里粘贴；Tern 的节点扫码框只接受节点文本。
- 全部节点的 YAML 也在 `/root/tern-test/tern-nodes.yaml`，分享链接汇总在 `/root/tern-test/links.txt`。

## 不需要 / 没有服务端的协议

- **Cloudflare WARP (MASQUE)**：连的是 Cloudflare 的服务器，不需要自建服务端；用 WARP 注册工具得到的
  `type: masque`（private-key / public-key / ip）节点即可。
- **Tailscale**：需要 tailnet 协调服务，不在本工具范围内。
- **Lua 后端**：取决于你自己的脚本，没有通用服务端。
- **Shadowrocket 式 http2 / http3 纯代理**：没有不带 naive padding 的现成服务端；同一套 H2 / H3 代码由 `naive` 两个节点覆盖。
- **gost-plugin**（SS 插件）：上游仓库已不可用，跳过。
- **ECH**：未单独部署（需要 ECH 密钥与 DNS HTTPS 记录配合）。

## 已知问题（Tern 侧）

- Snell：`snell://` 分享链接和只写 `psk:` 的 Clash 节点会把密钥放在 `psk` 字段，而拨号读取的是 `password`，
  会报「snell missing psk」。因此本工具 Snell 的二维码用 Surge 行（导入时 `psk=` 会映射到 `password`），
  订阅 YAML 里同时写了 `psk` 和 `password`。

## 文件位置

| 路径 | 内容 |
|---|---|
| `/opt/tern-test/bin/` | 下载 / 编译的服务端二进制 |
| `/opt/tern-test/etc/` | 各服务端配置 |
| `/opt/tern-test/certs/` | 证书 |
| `/etc/systemd/system/tern-*.service` | systemd 服务 |
| `/root/tern-test/` | 凭据（state.json）、节点（nodes.json / tern-nodes.yaml / links.txt）、二维码 PNG |

查看某个服务的日志：`journalctl -u tern-sing-box -n 50`（Mieru 是 `journalctl -u mita`）。

## 卸载

```sh
sudo bash install.sh --uninstall
```

会停止并删除全部 `tern-*` 服务、`tern-net` 加的防火墙 / NAT 规则和网络命名空间、ufw 规则、SSH 测试用户、
Let's Encrypt 证书（如果是本工具申请的）、本工具通过 apt 装的软件包（不会卸 curl / openssl / python3 / iptables / openssh-server 这类基础包），
以及 `/opt/tern-test` 和 `/root/tern-test`。
