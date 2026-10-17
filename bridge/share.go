package libmihomo

// Node sharing: mihomo proxy map → share link (the formats our own importer and mihomo's
// common/convert read back), and a manual-node list → base64 subscription text.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

func sStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case bool:
				if t {
					return "true"
				}
			case int, int64, float64, uint16, uint32:
				return fmt.Sprint(t)
			}
		}
	}
	return ""
}

func sBool(m map[string]any, k string) bool {
	switch t := m[k].(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	case int:
		return t != 0
	}
	return false
}

func sList(m map[string]any, k string) []string {
	var out []string
	switch t := m[k].(type) {
	case []any:
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
	case []string:
		out = t
	case string:
		if t != "" {
			out = strings.Split(t, ",")
		}
	}
	return out
}

func sMap(m map[string]any, k string) map[string]any {
	if x, ok := m[k].(map[string]any); ok {
		return x
	}
	return map[string]any{}
}

func hostPort(m map[string]any) string {
	return net.JoinHostPort(sStr(m, "server"), sStr(m, "port"))
}

func frag(name string) string { return "#" + url.PathEscape(name) }

// encodeQuery keeps the order stable and skips empty values.
type kvList [][2]string

func (l *kvList) add(k, v string) {
	if v != "" {
		*l = append(*l, [2]string{k, v})
	}
}

func (l kvList) String() string {
	if len(l) == 0 {
		return ""
	}
	parts := make([]string, 0, len(l))
	for _, kv := range l {
		parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(kv[1]))
	}
	return "?" + strings.Join(parts, "&")
}

// transportQuery adds the Xray-style transport / TLS parameters shared by vless / vmess-AEAD / trojan.
func transportQuery(m map[string]any, q *kvList, trojan bool) {
	netw := strings.ToLower(sStr(m, "network"))
	switch netw {
	case "", "tcp":
		if !trojan {
			q.add("type", "tcp")
		}
	case "ws":
		q.add("type", "ws")
		o := sMap(m, "ws-opts")
		q.add("path", sStr(o, "path"))
		q.add("host", sStr(sMap(o, "headers"), "Host", "host"))
	case "httpupgrade":
		q.add("type", "httpupgrade")
		o := sMap(m, "ws-opts")
		q.add("path", sStr(o, "path"))
		q.add("host", sStr(sMap(o, "headers"), "Host", "host"))
	case "grpc":
		q.add("type", "grpc")
		q.add("serviceName", sStr(sMap(m, "grpc-opts"), "grpc-service-name"))
	case "h2":
		q.add("type", "http")
		o := sMap(m, "h2-opts")
		q.add("path", sStr(o, "path"))
		if h := sList(o, "host"); len(h) > 0 {
			q.add("host", h[0])
		}
	case "http":
		q.add("type", "tcp")
		q.add("headerType", "http")
		o := sMap(m, "http-opts")
		if p := sList(o, "path"); len(p) > 0 {
			q.add("path", p[0])
		}
		if h := sList(sMap(o, "headers"), "Host"); len(h) > 0 {
			q.add("host", h[0])
		}
	default:
		q.add("type", netw)
	}
	if fp := sStr(m, "client-fingerprint"); fp != "" {
		q.add("fp", fp)
	}
	if a := sList(m, "alpn"); len(a) > 0 {
		q.add("alpn", strings.Join(a, ","))
	}
}

// ShareLinkFor encodes one proxy. Types without a common link format return an error.
func ShareLinkFor(m map[string]any) (string, error) {
	name := sStr(m, "name")
	typ := strings.ToLower(sStr(m, "type"))
	if sStr(m, "server") == "" && typ != "wireguard" {
		return "", errors.New("节点缺少服务器地址")
	}
	switch typ {
	case "ss":
		user := base64.RawURLEncoding.EncodeToString([]byte(sStr(m, "cipher") + ":" + sStr(m, "password")))
		var q kvList
		switch sStr(m, "plugin") {
		case "obfs", "simple-obfs":
			o := sMap(m, "plugin-opts")
			q.add("plugin", "obfs-local;obfs="+sStr(o, "mode")+";obfs-host="+sStr(o, "host"))
		case "v2ray-plugin":
			o := sMap(m, "plugin-opts")
			p := "v2ray-plugin;mode=" + sStr(o, "mode") + ";host=" + sStr(o, "host") + ";path=" + sStr(o, "path")
			if sBool(o, "tls") {
				p += ";tls"
			}
			q.add("plugin", p)
		case "":
		default:
			return "", fmt.Errorf("ss 插件 %s 没有通用分享格式", sStr(m, "plugin"))
		}
		if sBool(m, "udp-over-tcp") {
			q.add("uot", "1")
		}
		return "ss://" + user + "@" + hostPort(m) + q.String() + frag(name), nil
	case "ssr":
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		body := strings.Join([]string{sStr(m, "server"), sStr(m, "port"), sStr(m, "protocol"), sStr(m, "cipher"), sStr(m, "obfs"), b64(sStr(m, "password"))}, ":")
		body += "/?obfsparam=" + b64(sStr(m, "obfs-param")) + "&protoparam=" + b64(sStr(m, "protocol-param")) + "&remarks=" + b64(name)
		return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(body)), nil
	case "vmess":
		v := map[string]any{"v": "2", "ps": name, "add": sStr(m, "server"), "port": sStr(m, "port"), "id": sStr(m, "uuid"),
			"aid": sStr(m, "alterId"), "scy": sStr(m, "cipher"), "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
		if v["aid"] == "" {
			v["aid"] = "0"
		}
		if v["scy"] == "" {
			v["scy"] = "auto"
		}
		switch strings.ToLower(sStr(m, "network")) {
		case "ws", "httpupgrade":
			o := sMap(m, "ws-opts")
			v["net"], v["path"], v["host"] = strings.ToLower(sStr(m, "network")), sStr(o, "path"), sStr(sMap(o, "headers"), "Host", "host")
		case "grpc":
			v["net"], v["path"] = "grpc", sStr(sMap(m, "grpc-opts"), "grpc-service-name")
		case "h2":
			o := sMap(m, "h2-opts")
			v["net"], v["path"] = "h2", sStr(o, "path")
			if h := sList(o, "host"); len(h) > 0 {
				v["host"] = h[0]
			}
		case "http":
			o := sMap(m, "http-opts")
			v["type"] = "http"
			if p := sList(o, "path"); len(p) > 0 {
				v["path"] = p[0]
			}
			if h := sList(sMap(o, "headers"), "Host"); len(h) > 0 {
				v["host"] = h[0]
			}
		}
		if sBool(m, "tls") {
			v["tls"] = "tls"
			v["sni"] = sStr(m, "servername")
			if a := sList(m, "alpn"); len(a) > 0 {
				v["alpn"] = strings.Join(a, ",")
			}
			if fp := sStr(m, "client-fingerprint"); fp != "" {
				v["fp"] = fp
			}
		}
		b, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
	case "vless":
		var q kvList
		q.add("encryption", firstNonEmpty(sStr(m, "encryption"), "none"))
		q.add("flow", sStr(m, "flow"))
		if ro := sMap(m, "reality-opts"); sStr(ro, "public-key") != "" {
			q.add("security", "reality")
			q.add("pbk", sStr(ro, "public-key"))
			q.add("sid", sStr(ro, "short-id"))
		} else if sBool(m, "tls") {
			q.add("security", "tls")
		} else {
			q.add("security", "none")
		}
		q.add("sni", sStr(m, "servername"))
		transportQuery(m, &q, false)
		if sBool(m, "skip-cert-verify") {
			q.add("allowInsecure", "1")
		}
		return "vless://" + url.PathEscape(sStr(m, "uuid")) + "@" + hostPort(m) + q.String() + frag(name), nil
	case "trojan":
		var q kvList
		q.add("sni", sStr(m, "sni", "servername"))
		transportQuery(m, &q, true)
		if ro := sMap(m, "reality-opts"); sStr(ro, "public-key") != "" {
			q.add("security", "reality")
			q.add("pbk", sStr(ro, "public-key"))
			q.add("sid", sStr(ro, "short-id"))
		}
		if sBool(m, "skip-cert-verify") {
			q.add("allowInsecure", "1")
		}
		return "trojan://" + url.PathEscape(sStr(m, "password")) + "@" + hostPort(m) + q.String() + frag(name), nil
	case "hysteria2", "hy2":
		var q kvList
		q.add("sni", sStr(m, "sni"))
		if sBool(m, "skip-cert-verify") {
			q.add("insecure", "1")
		}
		q.add("obfs", sStr(m, "obfs"))
		q.add("obfs-password", sStr(m, "obfs-password"))
		if a := sList(m, "alpn"); len(a) > 0 {
			q.add("alpn", strings.Join(a, ","))
		}
		q.add("pinSHA256", sStr(m, "fingerprint"))
		q.add("up", sStr(m, "up"))
		q.add("down", sStr(m, "down"))
		hp := hostPort(m)
		if ports := sStr(m, "ports"); ports != "" {
			hp = net.JoinHostPort(sStr(m, "server"), ports)
		}
		user := ""
		if pw := sStr(m, "password"); pw != "" {
			user = url.PathEscape(pw) + "@"
		}
		return "hysteria2://" + user + hp + "/" + q.String() + frag(name), nil
	case "hysteria":
		var q kvList
		q.add("peer", sStr(m, "sni"))
		q.add("auth", sStr(m, "auth-str", "auth_str"))
		q.add("obfs", sStr(m, "obfs"))
		q.add("protocol", sStr(m, "protocol"))
		q.add("upmbps", sStr(m, "up"))
		q.add("downmbps", sStr(m, "down"))
		if a := sList(m, "alpn"); len(a) > 0 {
			q.add("alpn", strings.Join(a, ","))
		}
		if sBool(m, "skip-cert-verify") {
			q.add("insecure", "1")
		}
		return "hysteria://" + hostPort(m) + q.String() + frag(name), nil
	case "tuic":
		var q kvList
		q.add("congestion_control", sStr(m, "congestion-controller"))
		if a := sList(m, "alpn"); len(a) > 0 {
			q.add("alpn", strings.Join(a, ","))
		}
		q.add("sni", sStr(m, "sni"))
		if sBool(m, "disable-sni") {
			q.add("disable_sni", "1")
		}
		q.add("udp_relay_mode", sStr(m, "udp-relay-mode"))
		user := url.PathEscape(sStr(m, "token"))
		if u := sStr(m, "uuid"); u != "" {
			user = url.PathEscape(u) + ":" + url.PathEscape(sStr(m, "password"))
		}
		return "tuic://" + user + "@" + hostPort(m) + q.String() + frag(name), nil
	case "anytls":
		var q kvList
		q.add("sni", sStr(m, "sni"))
		if sBool(m, "skip-cert-verify") {
			q.add("insecure", "1")
		}
		q.add("hpkp", sStr(m, "fingerprint"))
		return "anytls://" + url.PathEscape(sStr(m, "password")) + "@" + hostPort(m) + "/" + q.String() + frag(name), nil
	case "socks5", "http":
		scheme := "socks5"
		if typ == "http" {
			scheme = "http"
			if sBool(m, "tls") {
				scheme = "https"
			}
		}
		user := ""
		if u := sStr(m, "username"); u != "" {
			user = url.UserPassword(u, sStr(m, "password")).String() + "@"
		}
		var q kvList
		if scheme == "https" {
			q.add("sni", sStr(m, "sni"))
		}
		return scheme + "://" + user + hostPort(m) + q.String() + frag(name), nil
	case "wireguard":
		server, port := sStr(m, "server"), sStr(m, "port")
		var pub, psk, reserved string
		if peers, ok := m["peers"].([]any); ok && len(peers) > 0 {
			if p, ok := peers[0].(map[string]any); ok {
				server, port = firstNonEmpty(sStr(p, "server"), server), firstNonEmpty(sStr(p, "port"), port)
				pub, psk = sStr(p, "public-key"), sStr(p, "pre-shared-key")
				reserved = strings.Join(sList(p, "reserved"), ",")
			}
		}
		pub = firstNonEmpty(pub, sStr(m, "public-key"))
		psk = firstNonEmpty(psk, sStr(m, "pre-shared-key"))
		if reserved == "" {
			reserved = strings.Join(sList(m, "reserved"), ",")
		}
		if server == "" {
			return "", errors.New("节点缺少服务器地址")
		}
		var q kvList
		q.add("publickey", pub)
		var addrs []string
		if ip := sStr(m, "ip"); ip != "" {
			addrs = append(addrs, ip+"/32")
		}
		if ip := sStr(m, "ipv6"); ip != "" {
			addrs = append(addrs, ip+"/128")
		}
		q.add("address", strings.Join(addrs, ","))
		q.add("presharedkey", psk)
		q.add("reserved", reserved)
		q.add("mtu", sStr(m, "mtu"))
		if port == "" {
			port = "51820"
		}
		return "wireguard://" + url.PathEscape(sStr(m, "private-key")) + "@" + net.JoinHostPort(server, port) + q.String() + frag(name), nil
	case "snell":
		var q kvList
		q.add("version", sStr(m, "version"))
		o := sMap(m, "obfs-opts")
		q.add("obfs", sStr(o, "mode"))
		q.add("obfs-host", sStr(o, "host"))
		return "snell://" + url.PathEscape(sStr(m, "psk")) + "@" + hostPort(m) + q.String() + frag(name), nil
	case "ssh":
		user := url.User(sStr(m, "username"))
		if pw := sStr(m, "password"); pw != "" {
			user = url.UserPassword(sStr(m, "username"), pw)
		}
		var q kvList
		if k := sStr(m, "private-key"); k != "" {
			q.add("private-key", k)
		}
		q.add("private-key-passphrase", sStr(m, "private-key-passphrase"))
		q.add("host-key", strings.Join(sList(m, "host-key"), "|"))
		return "ssh://" + user.String() + "@" + hostPort(m) + q.String() + frag(name), nil
	}
	return "", fmt.Errorf("%s 类型没有通用的分享链接格式", typ)
}

// NodeShareLink encodes one node given as JSON (the manual-node list / editor model).
// Returns "" on failure; LastError() has the reason.
func NodeShareLink(nodeJSON string) string {
	m := map[string]any{}
	if err := json.Unmarshal([]byte(nodeJSON), &m); err != nil {
		lastError = err.Error()
		return ""
	}
	s, err := ShareLinkFor(m)
	if err != nil {
		lastError = err.Error()
		return ""
	}
	return s
}

// NodeShareLinkByName encodes a node of a profile (after subscription processing, like the runtime sees it).
func NodeShareLinkByName(homeDir, profilePath, name string) string {
	raw := profileRaw(homeDir, profilePath)
	for _, p := range proxiesOf(raw) {
		if str(p["name"]) == name {
			s, err := ShareLinkFor(p)
			if err != nil {
				lastError = err.Error()
				return ""
			}
			return s
		}
	}
	lastError = "在配置里找不到这个节点（节点集里的节点请到提供者页查看）"
	return ""
}

// ManualSubscription returns the manual-node profile as a base64 subscription (one link per line,
// v2rayN style). skipped lists nodes that have no link format, as JSON {"text": …, "skipped": […], "count": n}.
func ManualSubscription(path string) string {
	out := map[string]any{"text": "", "skipped": []string{}, "count": 0}
	raw, err := loadYAML(path)
	if err == nil {
		var links, skipped []string
		for _, p := range proxiesOf(raw) {
			s, err := ShareLinkFor(p)
			if err != nil {
				skipped = append(skipped, str(p["name"])+"："+err.Error())
				continue
			}
			links = append(links, s)
		}
		out["text"] = base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
		out["count"] = len(links)
		if skipped != nil {
			out["skipped"] = skipped
		}
	} else if !os.IsNotExist(err) {
		out["error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	return string(b)
}
