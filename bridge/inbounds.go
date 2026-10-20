package libmihomo

import (
	"net"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// v0.19.10 (review 5 go-core P1-1): inbound blocks a profile may carry from a desktop / router setup.
// listeners default to listen 0.0.0.0, allow-lan does not affect them, lan-allowed-ips defaults to
// everything and authentication is only set by us when 局域网共享 is on, so a remote profile could turn
// the phone into an open SOCKS / SS / TUIC proxy or port forward on Wi-Fi.
//
// v0.19.12 (review 6 go-core P2-1, Quantumult X behaviour, user 2026-10-21 「跟quanx一个处理逻辑」): the
// only thing ever shared to the LAN is the app's own HTTP / SOCKS proxy. lan-allowed-ips /
// skip-auth-prefixes only guard http / socks / mixed, so a protocol inbound would expose the profile
// author's password to the LAN (and, over IPv6, the internet).
//
//   - Always: tunnels (plain port forwards) are dropped; tun / redir / tproxy / tunnel and other unknown
//     listener types are dropped (meaningless on iOS, and break the start). Protocol inbounds
//     (shadowsocks / vmess / vless / trojan / tuic / hysteria2 / anytls / sudoku / mieru) and the legacy
//     tuic-server / ss-config / vmess-config are forced to listen on 127.0.0.1 (this device only),
//     whatever 局域网共享 says, with one warning line per inbound (name only, never credentials).
//   - 局域网共享 off: socks / http / mixed listeners stay only when they already listen on loopback.
//   - 局域网共享 on: socks / http / mixed listeners get the 局域网共享 users.

// lanListenerTypesAuth are listener types that take mihomo `users` (username / password).
var lanListenerTypesAuth = map[string]bool{"socks": true, "http": true, "mixed": true}

// lanListenerTypesOwnAuth are protocol listeners that authenticate with their own credentials. They are
// never shared to the LAN: their listen address is forced to loopback.
var lanListenerTypesOwnAuth = map[string]bool{
	"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "tuic": true,
	"hysteria2": true, "anytls": true, "sudoku": true, "mieru": true,
}

// legacyInboundURLKeys are top-level mihomo inbound servers configured as one URL
// (ss://cipher:password@host:port[,host:port…]).
var legacyInboundURLKeys = []string{"ss-config", "vmess-config"}

func sanitizeProfileInbounds(raw map[string]any, o Overrides) {
	var dropped []string
	drop := func(k string) {
		if _, ok := raw[k]; ok {
			delete(raw, k)
			dropped = append(dropped, k)
		}
	}
	loopbackOnly := func(what string) {
		log.Warnln("[Bridge] 配置里的入站 %s 已改为仅监听 127.0.0.1（局域网只共享本机 HTTP / SOCKS 代理）", what)
	}
	drop("tunnels")

	// legacy top-level inbound servers
	if m := asMap(raw["tuic-server"]); m != nil {
		if l := strings.TrimSpace(asString(m["listen"])); l != "" {
			if nl, changed, ok := loopbackHostList(l); !ok {
				drop("tuic-server")
			} else if changed {
				m["listen"] = nl
				loopbackOnly("tuic-server")
			}
		}
	} else if _, ok := raw["tuic-server"]; ok && raw["tuic-server"] != nil {
		drop("tuic-server")
	}
	for _, k := range legacyInboundURLKeys {
		v, ok := raw[k]
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			drop(k)
			continue
		}
		if strings.TrimSpace(s) == "" {
			continue
		}
		if ns, changed, ok := loopbackInboundURL(s); !ok {
			drop(k)
		} else if changed {
			raw[k] = ns
			loopbackOnly(k)
		}
	}

	var creds []any
	if o.AllowLan {
		creds = lanCredentials(o)
	}
	kept := []any{}
	var gone []string
	for _, l := range asList(raw["listeners"]) {
		m := asMap(l)
		if m == nil {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(asString(m["type"])))
		name := asString(m["name"])
		switch {
		case name == probeListener:
			kept = append(kept, m)
		case lanListenerTypesOwnAuth[typ]:
			if !loopbackListen(asString(m["listen"])) {
				m["listen"] = "127.0.0.1"
				loopbackOnly("listeners: " + name + "(" + typ + ")")
			}
			kept = append(kept, m)
		case lanListenerTypesAuth[typ] && !o.AllowLan:
			// Loopback-only listeners stay (reachable from this device only, like our own probe listener
			// and the proxy-mode mixed-port); anything listening on another address is dropped.
			if loopbackListen(asString(m["listen"])) {
				kept = append(kept, m)
			} else {
				gone = append(gone, name+"("+typ+")")
			}
		case lanListenerTypesAuth[typ]:
			if len(creds) > 0 {
				users := make([]any, 0, len(creds))
				for _, c := range creds {
					u, p, _ := strings.Cut(c.(string), ":")
					users = append(users, map[string]any{"username": u, "password": p})
				}
				m["users"] = users
			} else {
				// no 局域网共享 user: fall back to the global authentication (none) like mixed-port
				delete(m, "users")
			}
			kept = append(kept, m)
		default:
			gone = append(gone, name+"("+typ+")")
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		dropped = append(dropped, "listeners: "+strings.Join(gone, ", "))
	}
	if _, ok := raw["listeners"]; ok || len(kept) > 0 {
		raw["listeners"] = kept
	}
	if len(dropped) > 0 {
		log.Warnln("[Bridge] 已忽略配置里的入站设置（iOS 仅开放 局域网共享 端口）：%s", strings.Join(dropped, "; "))
	}
}

// loopbackHostList rewrites a mihomo listen list ("0.0.0.0:443", ":443,[::]:8443") so every address
// is on 127.0.0.1 (loopback addresses are kept). ok is false when an entry is not host:port.
func loopbackHostList(s string) (out string, changed, ok bool) {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		host, port, err := net.SplitHostPort(p)
		if err != nil || port == "" {
			return s, false, false
		}
		if host != "" && loopbackListen(host) {
			parts[i] = p
			continue
		}
		parts[i] = net.JoinHostPort("127.0.0.1", port)
		changed = true
	}
	return strings.Join(parts, ","), changed, true
}

// loopbackInboundURL rewrites the host list of a legacy inbound URL
// (ss://cipher:password@:8388 → ss://cipher:password@127.0.0.1:8388). The user info is copied
// untouched; it is never parsed or logged.
func loopbackInboundURL(s string) (string, bool, bool) {
	i := strings.Index(s, "://")
	if i < 0 {
		return s, false, false
	}
	rest := s[i+3:]
	hostStart := 0
	authEnd := len(rest)
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		hostStart = at + 1
	}
	if j := strings.IndexAny(rest[hostStart:], "/?#"); j >= 0 {
		authEnd = hostStart + j
	}
	hosts, changed, ok := loopbackHostList(rest[hostStart:authEnd])
	if !ok {
		return s, false, false
	}
	return s[:i+3] + rest[:hostStart] + hosts + rest[authEnd:], changed, true
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// loopbackListen: listen address reachable from this device only ("" means 0.0.0.0 in mihomo).
func loopbackListen(a string) bool {
	a = strings.Trim(strings.TrimSpace(a), "[]")
	if a == "localhost" {
		return true
	}
	ip := net.ParseIP(a)
	return ip != nil && ip.IsLoopback()
}
