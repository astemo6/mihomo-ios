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
//   - 局域网共享 off: every profile listener (only our probe listener is added later), tunnels,
//     tuic-server, ss-config and vmess-config are dropped.
//   - 局域网共享 on: tunnels (plain port forwards, no auth possible) are still dropped; tun / redir /
//     tproxy / tunnel listeners are dropped (meaningless on iOS, and break the start); socks / http /
//     mixed listeners get the 局域网共享 users. Protocol inbounds (shadowsocks / vmess / vless / trojan /
//     tuic / hysteria2 / anytls, and the legacy tuic-server / ss-config / vmess-config) carry their own
//     credentials and are kept.

// lanListenerTypesAuth are listener types that take mihomo `users` (username / password).
var lanListenerTypesAuth = map[string]bool{"socks": true, "http": true, "mixed": true}

// lanListenerTypesOwnAuth are protocol listeners that authenticate with their own credentials.
var lanListenerTypesOwnAuth = map[string]bool{
	"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "tuic": true,
	"hysteria2": true, "anytls": true, "sudoku": true, "mieru": true,
}

func sanitizeProfileInbounds(raw map[string]any, o Overrides) {
	var dropped []string
	drop := func(k string) {
		if _, ok := raw[k]; ok {
			delete(raw, k)
			dropped = append(dropped, k)
		}
	}
	drop("tunnels")
	if !o.AllowLan {
		drop("tuic-server")
		drop("ss-config")
		drop("vmess-config")
		// Loopback-only listeners stay (reachable from this device only, like our own probe listener and
		// the proxy-mode mixed-port); anything listening on another address is dropped.
		kept := []any{}
		var gone []string
		for _, l := range asList(raw["listeners"]) {
			m := asMap(l)
			if m == nil {
				continue
			}
			typ := strings.ToLower(strings.TrimSpace(asString(m["type"])))
			name := asString(m["name"])
			if name == probeListener || (lanListenerTypesAuth[typ] || lanListenerTypesOwnAuth[typ]) && loopbackListen(asString(m["listen"])) {
				kept = append(kept, m)
				continue
			}
			gone = append(gone, name)
		}
		if len(gone) > 0 {
			sort.Strings(gone)
			dropped = append(dropped, "listeners: "+strings.Join(gone, ", "))
		}
		raw["listeners"] = kept
	} else if ls := asList(raw["listeners"]); len(ls) > 0 {
		creds := lanCredentials(o)
		kept := []any{}
		var bad []string
		for _, l := range ls {
			m := asMap(l)
			if m == nil {
				continue
			}
			typ := strings.ToLower(strings.TrimSpace(asString(m["type"])))
			name := asString(m["name"])
			switch {
			case name == probeListener:
				kept = append(kept, m)
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
			case lanListenerTypesOwnAuth[typ]:
				kept = append(kept, m)
			default:
				bad = append(bad, name+"("+typ+")")
			}
		}
		if len(bad) > 0 {
			sort.Strings(bad)
			dropped = append(dropped, "listeners: "+strings.Join(bad, ", "))
		}
		raw["listeners"] = kept
	}
	if len(dropped) > 0 {
		log.Warnln("[Bridge] 已忽略配置里的入站设置（iOS 仅开放 局域网共享 端口）：%s", strings.Join(dropped, "; "))
	}
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
