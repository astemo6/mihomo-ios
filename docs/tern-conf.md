# Tern .conf (profile format)

Tern's user-facing profile is a Quantumult X-style `.conf` (user decision 2026-10-28). The editor (配置 → 编辑配置)
shows and saves it; Clash-style YAML is import-only. Code: `App/Core/TernConf.swift` (serializer / parser),
`App/Core/TernConfStore.swift` (storage, migration, editor text, live check).

## Files per profile

| file | role |
|---|---|
| `profiles/<id>.conf` | source of truth (profile sections only) |
| `profiles/<id>.yaml` | derived internal cache, regenerated from the .conf on save; the runtime reads it (phase 1) |
| `profiles/<id>.conf.state` | SHA-256 of the YAML the .conf was synced with |
| `profiles/<id>.yaml.pre-conf` | the YAML before its first .conf (written once at migration) |

A YAML changed by another writer (subscription update, node editor, group order, snapshot restore) no longer matches
`.conf.state`; the next sync regenerates the .conf from it (lossless, comments of a hand-edited .conf are lost).

## Lines

* `[section]` headers (case-insensitive; a repeated section continues the first). `#`, `;`, `//` start a comment line.
* `key = value` sections: `[general]`, `[dns]` (plus QX lines), `[mitm]`.
* Comma lines: `first, field, key=value, …` in `[policy]`, `[server_local]`, `[server_remote]`, `[filter_remote]`,
  `[filter_local]`, `[rewrite_remote]`.

### Values
`true` / `false` / `null`, numbers, JSON (`"quoted string"`, `[list]`, `{mapping}`), anything else is plain text.
In comma lines a plain value escapes `%` `,` `"` (and `=` in positional fields, a leading `[` `{`, edge spaces,
line breaks) as `%25 %2C %22 %3D %5B %7B %20 %0A`; JSON values run to their closing quote / bracket and only escape `%`.
URL first fields escape only `%` `,` `"` (a hand-written `%20` stays as written).

## Profile sections

| section | internal key | form |
|---|---|---|
| `[general]` | every other top-level key | `key = value`; nested mappings as dotted keys (`tun.stack = system`); a key that is not `[A-Za-z0-9_-]+` is JSON-quoted |
| `[dns]` | `dns` (+ `hosts`) | `server=1.1.1.1` / `doh-server=https://…` (nameserver, in order), `server=/domain/value` (nameserver-policy), `address=/domain/ip` (hosts), `no-ipv6` (ipv6: false), other keys as `key = value` |
| `[policy]` | `proxy-groups` | `static=` select, `url-latency-benchmark=` url-test, `available=` fallback, `round-robin=` load-balance (`dest-hash=` = load-balance + consistent-hashing); other types by their own name (`relay=`). `name, member…, key=value…`; `check-interval`=interval, `img-url`=icon, `server-tag-regex`=filter; `direct` / `reject` / `reject-drop` = DIRECT / REJECT / REJECT-DROP unless a node or group has that name |
| `[server_local]` | `proxies` | QX node lines (`shadowsocks= vmess= vless= trojan= http= socks5= anytls=`, read by the same parser as the QX importer) + `tern-<key>=<value>` corrections and `tern-unset=a|b` for what the QX form cannot say; other types as `type=host:port, key=value…, tag=name` (`-` = no address) |
| `[server_remote]` | `proxy-providers` | `url, tag=name, update-interval=s, key=value…` (`-` = no url; type http implied by a url) |
| `[filter_remote]` | `rule-providers` | same as `[server_remote]`. A QX line with `force-policy=P` is a QX list (behavior classical, text, `x-convert=list`) plus `RULE-SET,tag,P` placed before the local rules; `enabled=false` skips it |
| `[filter_local]` | `rules` | `type, value, policy[, options]`: `host` `host-suffix` `host-keyword` `host-wildcard` `ip-cidr` `ip6-cidr` `geoip` (2-letter code lower-case) `ip-asn` `user-agent` `final`; other types lower-case (`rule-set`, `geosite`, `and`, `sub-rule` …); logical rules keep their inner text |

Fallbacks (verified, so nothing is lost): `tern-node=-, json=<node>`, `tern-group=-, json=<group>`,
`-, tag=<name>, json=<provider>`, `tern-raw, <rule>`, `tern-raw-json, <value>`.

## Shared sections (engine.json, the same in every profile)

Written below the banner `# —— 以下各段为所有配置共用…`; not stored in `<id>.conf`, applied to engine.json on save.

* `[rewrite_remote]` — modules: `url|tern-local, tag=, update-interval=, opt-parser=false, enabled=, tern-id=,
  tern-custom-name=true, tern-updated=, tern-argument=<json>, tern-policy=<json>`.
* `[rewrite_local]` — local rewrite and script lines verbatim; `#line` = disabled; pragmas (comments to QX):
  `#!rewrite = bool`, `#!script = bool` (master switches), `#!note = text`, `#!list = rewrite|script` (when the line's
  own syntax would put it in the other list), `#!item = <base64 JSON>` (a line that cannot be written verbatim).
* `[task_local]` — cron / event script lines. Order is kept within scripts and within tasks (their interleaving is not).
* `[script_resource]` — `path-or-url, disabled=, interval=`.
* `[mitm]` — `hostname = a, -b`, `enable`, `skip_validating_cert`, `h2`, `capture-bodies`, `quic`, `quic-allow`,
  `passphrase` + `p12` (base64 PKCS#12 of the CA; the passphrase is stable per device). The diagnostics bundle never
  includes the CA.
