# NativeCore: NaïveProxy, HTTP/2 and HTTP/3 proxies (feat/nc-naive-h2h3)

Pure Swift, no Go. Files (Shared/NativeCore unless noted — **Shared/NativeCore and PacketTunnel/NativeCore
changes must be synced to feat/nc-kernel**):

| File | What |
| --- | --- |
| `NCNaive.swift` | `NCH2H3ProxyOptions` (config → options), `NCHTTPConnect` (CONNECT header list, QPACK encoder), `NCNaivePadding` (padding codec, `padding` header value, negotiation) |
| `NCH2ProxySession.swift` | multiplexed HTTP/2 CONNECT session (one TLS connection, one stream per flow) on `NCH2MuxCore` |
| `NCH3ProxySession.swift` | HTTP/3 CONNECT over Network.framework QUIC (`NCH3ProxyConnection` + `NCH3ProxyStream` + `NCH3FrameReader`) |
| `NCConnectorNaive.swift` | registries + dial (`NCConnector.naiveH2H3Stream`), lifecycle counts / drain (`"naive"`) |
| `NCMux.swift` | `NCH2MuxCore.openStream(headers:)` (additive) |
| `NCConnector.swift` | dispatch hook, `sharedSessionCounts` / `closeAllSharedSessions` gain `"naive"` |
| `NCSupport.swift` | types `naive`, `http2`/`h2`, `http3`/`h3` |
| `NCSubscription.swift` / `NCShareLink.swift` | `naive+https://`, `naive+quic://`, `http2://`, `http3://`; sing-box `naive` outbound JSON |
| `PacketTunnel/NativeCore/NCUDPUoTSession.swift`, `NCDataPlane.swift` | naive `udp-over-tcp` (UoT v2) |
| `App/Core/NCConfigValidator.swift`, `Models.swift`, `ImportTools.swift` | type names accepted / labelled |

## Config (Clash-style YAML)

```yaml
- name: naive-h2
  type: naive
  server: naive.example.com
  port: 443
  username: user
  password: pass
  # optional
  sni: naive.example.com          # / servername; default: server
  skip-cert-verify: false
  client-fingerprint: chrome      # ClientHello shape of the h2 TLS (default chrome)
  quic: false                     # true = HTTP/3 (sing-box `quic`, link naive+quic://)
  extra-headers: {X-Foo: bar}     # map, list of "K: v", or CRLF string (sing-box extra_headers)
  insecure-concurrency: 1         # h2 connections the flows are spread over (1–8)
  udp-over-tcp: false             # UDP via UoT v2 (sing-box udp_over_tcp); needs a sing-box-style server

- {name: h2, type: http2, server: h2.example.com, port: 443, username: u, password: p}   # also `h2`
- {name: h3, type: http3, server: h3.example.com, port: 443, username: u, password: p}   # also `h3`
```

`http2`/`http3` are Shadowrocket's HTTP2 / HTTP3 types: plain HTTP CONNECT tunnelled in an HTTP/2 stream
(TLS, ALPN h2) or an HTTP/3 request stream (QUIC, ALPN h3), Basic proxy authorization, no padding.
mihomo has no naive / h2 / h3 proxy types; field names follow sing-box (snake_case → kebab-case) and the
existing Clash conventions (`sni`, `skip-cert-verify`, `client-fingerprint`).

## Wire

* CONNECT: `:method CONNECT`, `:authority host:port` (IPv6 bracketed), `proxy-authorization: Basic …`,
  extra headers. Naive adds `padding: <16 Huffman-hostile chars + '~' to 16–32>` and
  `padding-type-request: 1, 0`. Sends are held until the 2xx response.
* Padding (naive, variant 1): negotiated by the response (`padding-type-reply: 1`, or the legacy
  `padding` header as sing-box / caddy send it). The first 8 writes and 8 reads of each tunnel are
  `[len u16][pad u8][payload][pad zeros]` (writes > 65535 split, one frame each), then raw.
* h2: one TLS connection per node (hand-rolled TLS, chrome ClientHello), streams multiplexed; our
  SETTINGS: push off, stream window 256 KB (returned on consumption → bounded per-stream buffer),
  connection window 2 MB. Idle session closed after 90 s; GOAWAY drains. Works over chain transports
  (private single-stream session).
* h3: one QUIC connection per node; control stream with SETTINGS (QPACK table 0); a bidi stream per flow,
  DATA frames both ways; server uni streams drained, never reset. Reads are pulled (≤128 KB inbox) so
  QUIC flow control back-pressures. Not over chain transports.
* UoT: tunnel to `sp.v2.udp-over-tcp.arpa:0`, request `[0][socks addr]`, packets `[family][addr][port][len][payload]`.

## Verified

* Unit: `UnitTests/NativeCoreNaiveH2H3Tests.swift` (codec, headers, HPACK/QPACK, h3 reader, links,
  sing-box JSON, h2 session against a scripted server).
* Loopback: sing-box 1.12.24 naive inbound — 18040 (TCP/h2) and 18041 (UDP/h3); TCP echo, chunked echo
  across the padded boundary, 3 concurrent streams on one session, 407 on a wrong password, UoT echo over
  h2 and h3. Plain h2/h3 proxies have no sing-box inbound (naive requires the padding header) and are
  covered by the unit tests plus the shared h2/h3 code exercised by the naive loopback.
