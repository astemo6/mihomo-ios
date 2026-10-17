package libmihomo

// Native subscription formats (qx/rebuild: "no resource parser needed"): SIP008 JSON and sing-box JSON
// outbounds are converted to mihomo proxies here, next to the share-link / Surge / QX / Loon line parsers
// in nodes.go. DetectNodeFormat reports which format a subscription body is, for the UI.

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// parseJSONNodes handles SIP008 ({"servers":[…]}) and sing-box ({"outbounds":[…]}, or a bare array of
// outbounds). ok=false when the text is not one of them.
func parseJSONNodes(text string) (out []map[string]any, format string, ok bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return nil, "", false
	}
	var root any
	if err := json.Unmarshal([]byte(t), &root); err != nil {
		return nil, "", false
	}
	var list []any
	switch r := root.(type) {
	case map[string]any:
		if s, ok := r["servers"].([]any); ok {
			for _, x := range s {
				if m, ok := x.(map[string]any); ok {
					if p := sip008(m); p != nil {
						out = append(out, p)
					}
				}
			}
			return out, "SIP008", true
		}
		if o, ok := r["outbounds"].([]any); ok {
			list = o
		} else {
			return nil, "", false
		}
	case []any:
		list = r
	default:
		return nil, "", false
	}
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			if p := singBoxOutbound(m); p != nil {
				out = append(out, p)
			}
		}
	}
	return out, "sing-box", true
}

func sip008(m map[string]any) map[string]any {
	server := strOf(m["server"])
	if server == "" {
		return nil
	}
	p := map[string]any{
		"name":     nameOr(firstNonEmpty(strOf(m["remarks"]), strOf(m["id"])), server),
		"type":     "ss",
		"server":   server,
		"port":     intOf(m["server_port"]),
		"cipher":   strOf(m["method"]),
		"password": strOf(m["password"]),
		"udp":      true,
	}
	if plugin := strOf(m["plugin"]); plugin != "" {
		opts := map[string]any{}
		for _, kv := range strings.Split(strOf(m["plugin_opts"]), ";") {
			k, v, _ := strings.Cut(kv, "=")
			switch strings.TrimSpace(k) {
			case "obfs":
				opts["mode"] = strings.TrimSpace(v)
			case "obfs-host", "host":
				opts["host"] = strings.TrimSpace(v)
			case "path":
				opts["path"] = strings.TrimSpace(v)
			case "tls":
				opts["tls"] = true
			case "mode":
				opts["mode"] = strings.TrimSpace(v)
			}
		}
		if strings.Contains(plugin, "obfs") {
			p["plugin"] = "obfs"
		} else if strings.Contains(plugin, "v2ray") {
			p["plugin"] = "v2ray-plugin"
			if opts["mode"] == nil {
				opts["mode"] = "websocket"
			}
		} else {
			p["plugin"] = plugin
		}
		p["plugin-opts"] = opts
	}
	return p
}

func singBoxTLS(p map[string]any, m map[string]any) {
	tls, _ := m["tls"].(map[string]any)
	if tls == nil || !boolOf(tls["enabled"]) {
		return
	}
	typ := strOf(p["type"])
	if typ == "vmess" || typ == "vless" || typ == "http" || typ == "socks5" {
		p["tls"] = true
	}
	if sn := strOf(tls["server_name"]); sn != "" {
		if typ == "vmess" || typ == "vless" {
			p["servername"] = sn
		} else {
			p["sni"] = sn
		}
	}
	if boolOf(tls["insecure"]) {
		p["skip-cert-verify"] = true
	}
	if a, ok := tls["alpn"].([]any); ok && len(a) > 0 {
		p["alpn"] = a
	}
	if u, ok := tls["utls"].(map[string]any); ok && boolOf(u["enabled"]) {
		if fp := strOf(u["fingerprint"]); fp != "" {
			p["client-fingerprint"] = fp
		}
	}
	if r, ok := tls["reality"].(map[string]any); ok && boolOf(r["enabled"]) {
		p["reality-opts"] = map[string]any{"public-key": strOf(r["public_key"]), "short-id": strOf(r["short_id"])}
		if p["client-fingerprint"] == nil {
			p["client-fingerprint"] = "chrome"
		}
	}
}

func singBoxTransport(p map[string]any, m map[string]any) {
	tr, _ := m["transport"].(map[string]any)
	if tr == nil {
		return
	}
	switch strOf(tr["type"]) {
	case "ws":
		p["network"] = "ws"
		ws := map[string]any{"path": firstNonEmpty(strOf(tr["path"]), "/")}
		if h, ok := tr["headers"].(map[string]any); ok && len(h) > 0 {
			ws["headers"] = h
		}
		p["ws-opts"] = ws
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": strOf(tr["service_name"])}
	case "http":
		p["network"] = "h2"
		h2 := map[string]any{"path": firstNonEmpty(strOf(tr["path"]), "/")}
		if hosts, ok := tr["host"].([]any); ok && len(hosts) > 0 {
			h2["host"] = hosts
		}
		p["h2-opts"] = h2
	case "httpupgrade":
		p["network"] = "ws"
		p["ws-opts"] = map[string]any{"path": firstNonEmpty(strOf(tr["path"]), "/"), "v2ray-http-upgrade": true}
	}
}

func singBoxOutbound(m map[string]any) map[string]any {
	typ := strOf(m["type"])
	server := strOf(m["server"])
	if server == "" {
		return nil
	}
	p := map[string]any{"name": nameOr(strOf(m["tag"]), server), "server": server, "port": intOf(m["server_port"])}
	switch typ {
	case "shadowsocks":
		p["type"] = "ss"
		p["cipher"] = strOf(m["method"])
		p["password"] = strOf(m["password"])
		p["udp"] = true
		if plugin := strOf(m["plugin"]); plugin != "" {
			sp := sip008(map[string]any{"server": server, "plugin": plugin, "plugin_opts": m["plugin_opts"]})
			p["plugin"], p["plugin-opts"] = sp["plugin"], sp["plugin-opts"]
		}
	case "vmess":
		p["type"] = "vmess"
		p["uuid"] = strOf(m["uuid"])
		p["alterId"] = intOf(m["alter_id"])
		p["cipher"] = firstNonEmpty(strOf(m["security"]), "auto")
		p["udp"] = true
	case "vless":
		p["type"] = "vless"
		p["uuid"] = strOf(m["uuid"])
		if f := strOf(m["flow"]); f != "" {
			p["flow"] = f
		}
		p["udp"] = true
	case "trojan":
		p["type"] = "trojan"
		p["password"] = strOf(m["password"])
		p["udp"] = true
	case "hysteria2":
		p["type"] = "hysteria2"
		p["password"] = strOf(m["password"])
		if o, ok := m["obfs"].(map[string]any); ok && strOf(o["type"]) != "" {
			p["obfs"] = strOf(o["type"])
			p["obfs-password"] = strOf(o["password"])
		}
		if v := intOf(m["up_mbps"]); v > 0 {
			p["up"] = fmt.Sprintf("%d Mbps", v)
		}
		if v := intOf(m["down_mbps"]); v > 0 {
			p["down"] = fmt.Sprintf("%d Mbps", v)
		}
	case "tuic":
		p["type"] = "tuic"
		p["uuid"] = strOf(m["uuid"])
		p["password"] = strOf(m["password"])
		if c := strOf(m["congestion_control"]); c != "" {
			p["congestion-controller"] = c
		}
		if u := strOf(m["udp_relay_mode"]); u != "" {
			p["udp-relay-mode"] = u
		}
	case "anytls":
		p["type"] = "anytls"
		p["password"] = strOf(m["password"])
		p["udp"] = true
	case "socks":
		p["type"] = "socks5"
		if u := strOf(m["username"]); u != "" {
			p["username"], p["password"] = u, strOf(m["password"])
		}
		p["udp"] = true
	case "http":
		p["type"] = "http"
		if u := strOf(m["username"]); u != "" {
			p["username"], p["password"] = u, strOf(m["password"])
		}
	case "ssh":
		p["type"] = "ssh"
		p["username"] = firstNonEmpty(strOf(m["user"]), "root")
		if pw := strOf(m["password"]); pw != "" {
			p["password"] = pw
		}
		if k := strOf(m["private_key"]); k != "" {
			p["private-key"] = k
		}
	case "wireguard":
		p["type"] = "wireguard"
		p["private-key"] = strOf(m["private_key"])
		p["public-key"] = strOf(m["peer_public_key"])
		if psk := strOf(m["pre_shared_key"]); psk != "" {
			p["pre-shared-key"] = psk
		}
		if addrs, ok := m["local_address"].([]any); ok {
			for _, a := range addrs {
				s, _, _ := strings.Cut(strOf(a), "/")
				if strings.Contains(s, ":") {
					p["ipv6"] = s
				} else if p["ip"] == nil {
					p["ip"] = s
				}
			}
		}
		if mtu := intOf(m["mtu"]); mtu > 0 {
			p["mtu"] = mtu
		}
		p["udp"] = true
	default:
		return nil
	}
	singBoxTLS(p, m)
	singBoxTransport(p, m)
	return p
}

// DetectNodeFormat reports what kind of node source a text is and how many nodes it holds, as JSON:
// {"format":"Clash YAML","count":169}. Formats: Clash YAML, SIP008, sing-box, 分享链接, Base64 分享链接,
// Surge / QX / Loon 节点行, 未识别.
func DetectNodeFormat(text string) string {
	format, count := detectNodeFormat(text)
	b, _ := json.Marshal(map[string]any{"format": format, "count": count})
	return string(b)
}

func detectNodeFormat(text string) (string, int) {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if t == "" {
		return "未识别", 0
	}
	if nodes, f, ok := parseJSONNodes(t); ok {
		return f, len(nodes)
	}
	if strings.Contains(t, "proxies:") || strings.Contains(t, "proxy-providers:") {
		var raw map[string]any
		if yaml.Unmarshal([]byte(t), &raw) == nil && raw != nil {
			return "Clash YAML", len(proxiesOf(raw))
		}
	}
	b64 := false
	if !strings.Contains(t, "://") && !strings.Contains(t, "=") {
		if d, ok := tryB64(t); ok {
			b64 = true
			t = d
		}
	}
	nodes, _ := parseNodeText(t)
	if len(nodes) == 0 {
		return "未识别", 0
	}
	if strings.Contains(t, "://") {
		if b64 {
			return "Base64 分享链接", len(nodes)
		}
		return "分享链接", len(nodes)
	}
	return "Surge / QX / Loon 节点行", len(nodes)
}
