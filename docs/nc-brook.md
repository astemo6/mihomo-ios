# Brook 出站（feat/nc-brook）

纯 Swift 实现 txthinking/brook 客户端协议，零 Go。协议细节以 brook 官方源码为准
（streamclient.go / packetclient.go / simplestreamclient.go / simplepacketclient.go / websocket.go / brooklink.go / quic.go）。

## 支持范围

| brook 服务端 | TCP | UDP |
|---|---|---|
| `brook server` | 加密流（TCP） | 加密 UDP 包；`udp-over-tcp` 时走流 |
| `brook wsserver` | HTTP Upgrade 后的**裸**流（无 WebSocket 帧） | 同一条流（奇数时间戳） |
| `brook wssserver` | 同上，TLS（ALPN http/1.1） | 同上 |
| `brook quicserver` | QUIC 双向流（ALPN h3，按节点共享一条 QUIC 连接） | QUIC datagram（≤1197 字节，每个 UDP 会话一条连接）；`udp-over-stream` 时走流 |

`without-brook-protocol`（ws/wss/quic）：密码变为 SHA-256(password) 明文头，后续不加密。

未实现：brook GUI 用户系统 `token`（NCSupport 标为不可用）；wss `fragment`（ClientHello 分片）只保存不生效。

## YAML 字段（`type: brook`）

```yaml
- name: b1
  type: brook
  server: 1.2.3.4          # 实际拨号地址（brook link 的 address）
  port: 443
  password: hello
  transport: wssserver     # server | wsserver | wssserver | quicserver（缺省 server）
  host: example.com        # ws/wss/quic URL 的主机：Host 头 + SNI；可写 host:port
  path: /ws                # ws/wss 路径（缺省 /ws）
  udp-over-tcp: false      # server
  udp-over-stream: false   # quicserver
  without-brook-protocol: false
  skip-cert-verify: false  # link: insecure
  ca: "-----BEGIN CERTIFICATE-----…"   # 仅信任此 CA（Go RootCAs 语义）
  client-fingerprint: chrome           # wss：手写 ClientHello（link: tlsfingerprint）
  client-hkdf-info: brook
  server-hkdf-info: brook
  udp: true
```

## brook:// 链接

`brook://KIND?KIND=<server>&password=…&name=…`（Go url.Values：键排序、QueryEscape、空格为 `+`）。
导入（NCSubscriptionParser → NCBrookLink.parse）与分享（NCShareLink → NCBrookLink.encode）互逆；
`brook://socks5?...` 导入为普通 socks5 节点。

## 线格式要点

- KEY = HKDF-SHA256(password, salt=12 字节 nonce, info="brook")，AES-256-GCM。
- 流帧 = GCM(BE16 长度)[18] + GCM(载荷)[len+16]；nonce 前 8 字节小端计数，每次 seal/open 后 +1。
- 首帧 = BE32 Unix 时间（TCP 偶数 / UDP 奇数）+ SOCKS5 地址；服务端拒绝 60 秒前的请求（依赖设备时钟）。
- TCP 每帧载荷 ≤ 2014 字节（服务端 2048 缓冲）。

## 文件

- `Shared/NativeCore/NCBrook.swift`：编解码、选项、WS 升级、QUIC 连接/池、拨号、链接。
- `PacketTunnel/NativeCore/NCBrookUDP.swift`：UDP 会话（包 / 流 / QUIC datagram）。
- `UnitTests/NativeCoreBrookTests.swift`：密钥派生、帧、包、链接向量（Python 依 brook 源码生成）。
- Shared/NativeCore、PacketTunnel/NativeCore 改动需同步 feat/nc-kernel。
