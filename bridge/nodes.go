package libmihomo

// Node import: share URIs (via mihomo's own converter plus extra schemes),
// base64 subscriptions, Surge/Egern lines and Quantumult X lines → mihomo proxies.
// Plus helpers to maintain a local "手动节点" profile.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/convert"

	"go.yaml.in/yaml/v3"
)

const ManualGroupName = "手动节点"

func tryB64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t") {
		return "", false
	}
	s2 := strings.NewReplacer("\r", "", "\n", "").Replace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s2); err == nil {
			return string(b), true
		}
	}
	return "", false
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitHostPort(hp string) (string, int, error) {
	hp = strings.TrimSpace(hp)
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		// v0.13.1: QX / Surge write IPv6 servers without brackets ("2606:4700::1:443"); the last colon
		// is the port when the rest parses as an IPv6 address.
		i := strings.LastIndex(hp, ":")
		if i <= 0 || strings.Count(hp, ":") < 3 || strings.Contains(hp, "[") {
			return "", 0, err
		}
		if _, perr := netip.ParseAddr(hp[:i]); perr != nil {
			return "", 0, err
		}
		h, p = hp[:i], hp[i+1:]
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

func firstQ(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func csv(s string) []any {
	var out []any
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// wireguard://<private-key>@host:port?publickey=..&address=10.0.0.2/32,fd00::2/128&reserved=1,2,3&mtu=1280#name
// wg://host:port?pk=<private>&peer_pk=<public>&local_address=...  (Hiddify style)
func parseWireGuard(line string) (map[string]any, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	port := atoi(u.Port(), 51820)
	priv := ""
	if u.User != nil {
		priv = u.User.Username()
		if p, ok := u.User.Password(); ok && p != "" {
			priv += ":" + p
		}
		priv, _ = url.PathUnescape(priv)
	}
	if priv == "" {
		priv = firstQ(q, "privatekey", "private_key", "private-key", "secretKey", "pk")
	}
	pub := firstQ(q, "publickey", "public_key", "public-key", "peer_public_key", "peer_pk", "peerPublicKey")
	if priv == "" || pub == "" {
		return nil, errors.New("wireguard: 缺少 private/public key")
	}
	p := map[string]any{"type": "wireguard", "server": u.Hostname(), "port": port,
		"private-key": priv, "public-key": pub, "udp": true}
	for _, a := range csv(firstQ(q, "address", "ip", "local_address", "localAddress", "ips")) {
		s := a.(string)
		ip := strings.SplitN(s, "/", 2)[0]
		if strings.Contains(ip, ":") {
			p["ipv6"] = ip
		} else {
			p["ip"] = ip
		}
	}
	if _, ok := p["ip"]; !ok {
		p["ip"] = "172.16.0.2"
	}
	if v := firstQ(q, "presharedkey", "pre_shared_key", "preshared_key", "psk"); v != "" {
		p["pre-shared-key"] = v
	}
	if v := firstQ(q, "reserved"); v != "" {
		var r []any
		for _, x := range csv(v) {
			r = append(r, atoi(x.(string), 0))
		}
		if len(r) == 3 {
			p["reserved"] = r
		} else {
			p["reserved"] = v
		}
	}
	if v := firstQ(q, "mtu"); v != "" {
		p["mtu"] = atoi(v, 1408)
	}
	p["name"] = nameOr(u.Fragment, "WireGuard "+u.Hostname())
	return p, nil
}

// snell://psk@host:port?version=4&obfs=http&obfs-host=bing.com#name
func parseSnell(line string) (map[string]any, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	psk := ""
	if u.User != nil {
		psk = u.User.Username()
	}
	if psk == "" {
		psk = firstQ(q, "psk")
	}
	if psk == "" {
		return nil, errors.New("snell: 缺少 psk")
	}
	p := map[string]any{"type": "snell", "server": u.Hostname(), "port": atoi(u.Port(), 443), "psk": psk,
		"version": atoi(firstQ(q, "version"), 4), "udp": true}
	if o := firstQ(q, "obfs"); o != "" && o != "none" {
		p["obfs-opts"] = map[string]any{"mode": o, "host": firstQ(q, "obfs-host", "host")}
	}
	p["name"] = nameOr(u.Fragment, "Snell "+u.Hostname())
	return p, nil
}

func nameOr(n, def string) string {
	if d, err := url.PathUnescape(n); err == nil {
		n = d
	}
	if strings.TrimSpace(n) == "" {
		return def
	}
	return strings.TrimSpace(n)
}

// splitParams splits "a, b, k=v, k2=\"x,y\"" on commas outside quotes.
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ',' && !inQ:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func kvs(parts []string) (pos []string, kv map[string]string) {
	kv = map[string]string{}
	for _, p := range parts {
		if i := strings.Index(p, "="); i > 0 {
			kv[strings.ToLower(strings.TrimSpace(p[:i]))] = strings.Trim(strings.TrimSpace(p[i+1:]), "\"")
		} else {
			pos = append(pos, strings.Trim(p, "\""))
		}
	}
	return
}

func applyWS(p map[string]any, path, host string) {
	opts := map[string]any{}
	if path != "" {
		opts["path"] = path
	}
	if host != "" {
		opts["headers"] = map[string]any{"Host": host}
	}
	p["network"] = "ws"
	p["ws-opts"] = opts
}

func headerHost(h string) string {
	// "Host:example.com|User-Agent:x"
	for _, seg := range strings.Split(h, "|") {
		kv := strings.SplitN(seg, ":", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "host") {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

// Surge / Egern: "Name = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=x, udp-relay=true"
func parseSurgeLine(line string) (map[string]any, error) {
	eq := strings.Index(line, "=")
	if eq <= 0 {
		return nil, errors.New("not a surge line")
	}
	name := strings.TrimSpace(line[:eq])
	pos, kv := kvs(splitParams(line[eq+1:]))
	if len(pos) < 3 {
		return nil, errors.New("surge: 参数不足")
	}
	typ := strings.ToLower(pos[0])
	server := pos[1]
	port := atoi(pos[2], 0)
	if port == 0 {
		return nil, errors.New("surge: 端口无效")
	}
	p := map[string]any{"name": name, "server": server, "port": port}
	udp := truthy(kv["udp-relay"]) || truthy(kv["udp"])
	sni := kv["sni"]
	skip := truthy(kv["skip-cert-verify"])
	setTLS := func() {
		p["tls"] = true
		if sni != "" {
			p["servername"] = sni
		}
		if skip {
			p["skip-cert-verify"] = true
		}
	}
	switch typ {
	case "ss", "shadowsocks":
		p["type"] = "ss"
		p["cipher"] = firstNonEmpty(kv["encrypt-method"], kv["method"], kv["cipher"])
		p["password"] = kv["password"]
		p["udp"] = udp
		if o := kv["obfs"]; o != "" {
			p["plugin"] = "obfs"
			p["plugin-opts"] = map[string]any{"mode": o, "host": kv["obfs-host"]}
		}
		if v := kv["shadow-tls-password"]; v != "" {
			p["plugin"] = "shadow-tls"
			p["client-fingerprint"] = "chrome"
			p["plugin-opts"] = map[string]any{"host": kv["shadow-tls-sni"], "password": v, "version": atoi(kv["shadow-tls-version"], 3)}
		}
	case "vmess":
		p["type"] = "vmess"
		p["uuid"] = kv["username"]
		p["alterId"] = 0
		p["cipher"] = vmessCipher(kv["encrypt-method"])
		p["udp"] = true
		if truthy(kv["ws"]) {
			applyWS(p, kv["ws-path"], headerHost(kv["ws-headers"]))
		}
		if truthy(kv["tls"]) {
			setTLS()
		}
	case "trojan":
		p["type"] = "trojan"
		p["password"] = kv["password"]
		p["udp"] = true
		if sni != "" {
			p["sni"] = sni
		}
		if skip {
			p["skip-cert-verify"] = true
		}
		if truthy(kv["ws"]) {
			applyWS(p, kv["ws-path"], headerHost(kv["ws-headers"]))
		}
	case "snell":
		p["type"] = "snell"
		p["psk"] = kv["psk"]
		p["version"] = atoi(kv["version"], 4)
		p["udp"] = true
		if o := kv["obfs"]; o != "" {
			p["obfs-opts"] = map[string]any{"mode": o, "host": kv["obfs-host"]}
		}
	case "http", "https":
		p["type"] = "http"
		if len(pos) >= 5 {
			p["username"], p["password"] = pos[3], pos[4]
		}
		p["username"] = firstNonEmpty(kv["username"], strOf(p["username"]))
		p["password"] = firstNonEmpty(kv["password"], strOf(p["password"]))
		if typ == "https" {
			setTLS()
		}
	case "socks5", "socks5-tls":
		p["type"] = "socks5"
		if len(pos) >= 5 {
			p["username"], p["password"] = pos[3], pos[4]
		}
		p["username"] = firstNonEmpty(kv["username"], strOf(p["username"]))
		p["password"] = firstNonEmpty(kv["password"], strOf(p["password"]))
		p["udp"] = udp
		if typ == "socks5-tls" {
			setTLS()
		}
	case "hysteria2", "hy2":
		p["type"] = "hysteria2"
		p["password"] = kv["password"]
		if sni != "" {
			p["sni"] = sni
		}
		if skip {
			p["skip-cert-verify"] = true
		}
		if v := kv["download-bandwidth"]; v != "" {
			p["down"] = v + " Mbps"
		}
	case "tuic", "tuic-v5":
		p["type"] = "tuic"
		p["uuid"] = kv["uuid"]
		p["password"] = firstNonEmpty(kv["password"], kv["token"])
		if sni != "" {
			p["sni"] = sni
		}
		if skip {
			p["skip-cert-verify"] = true
		}
		if v := kv["alpn"]; v != "" {
			p["alpn"] = csv(strings.ReplaceAll(v, "|", ","))
		} else {
			p["alpn"] = []any{"h3"}
		}
		p["congestion-controller"] = "bbr"
		p["udp-relay-mode"] = "native"
	case "anytls":
		p["type"] = "anytls"
		p["password"] = kv["password"]
		if sni != "" {
			p["sni"] = sni
		}
		if skip {
			p["skip-cert-verify"] = true
		}
		p["udp"] = true
	case "ssh":
		p["type"] = "ssh"
		p["username"] = kv["username"]
		p["password"] = kv["password"]
		if v := kv["private-key"]; v != "" {
			p["private-key"] = v
		}
		if v := kv["private-key-passphrase"]; v != "" {
			p["private-key-passphrase"] = v
		}
		if v := firstNonEmpty(kv["server-fingerprint"], kv["host-key"]); v != "" {
			p["host-key"] = []any{v}
		}
	default:
		return nil, fmt.Errorf("surge: 不支持的类型 %s", typ)
	}
	return p, nil
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Quantumult X: "shadowsocks=host:port, method=aes-128-gcm, password=x, obfs=http, obfs-host=h, tag=Name"
func parseQXLine(line string) (map[string]any, error) {
	eq := strings.Index(line, "=")
	if eq <= 0 {
		return nil, errors.New("not qx")
	}
	typ := strings.ToLower(strings.TrimSpace(line[:eq]))
	parts := splitParams(line[eq+1:])
	if len(parts) == 0 {
		return nil, errors.New("qx: 空")
	}
	host, port, err := splitHostPort(parts[0])
	if err != nil {
		return nil, fmt.Errorf("qx: 地址无效 %s", parts[0])
	}
	_, kv := kvs(parts[1:])
	p := map[string]any{"server": host, "port": port, "name": nameOr(kv["tag"], typ+" "+host)}
	obfs := strings.ToLower(kv["obfs"])
	obfsHost := kv["obfs-host"]
	obfsURI := kv["obfs-uri"]
	overTLS := truthy(kv["over-tls"]) || obfs == "over-tls" || obfs == "wss"
	tlsHost := firstNonEmpty(kv["tls-host"], obfsHost)
	skip := strings.EqualFold(kv["tls-verification"], "false")
	switch typ {
	case "shadowsocks":
		p["type"] = "ss"
		p["cipher"] = kv["method"]
		p["password"] = kv["password"]
		p["udp"] = truthy(kv["udp-relay"])
		if proto := kv["ssr-protocol"]; proto != "" {
			// v0.11: ShadowsocksR (QX writes it as shadowsocks + ssr-protocol).
			p["type"] = "ssr"
			p["protocol"] = proto
			if pp := kv["ssr-protocol-param"]; pp != "" {
				p["protocol-param"] = pp
			}
			p["obfs"] = firstNonEmpty(obfs, "plain")
			if obfsHost != "" {
				p["obfs-param"] = obfsHost
			}
			break
		}
		switch obfs {
		case "http", "tls":
			p["plugin"] = "obfs"
			p["plugin-opts"] = map[string]any{"mode": obfs, "host": obfsHost}
		case "ws", "wss":
			opts := map[string]any{"mode": "websocket", "host": obfsHost, "path": firstNonEmpty(obfsURI, "/")}
			if obfs == "wss" {
				opts["tls"] = true
			}
			p["plugin"] = "v2ray-plugin"
			p["plugin-opts"] = opts
		}
	case "vmess", "vless":
		p["type"] = typ
		p["uuid"] = kv["password"]
		p["udp"] = true
		if typ == "vmess" {
			p["alterId"] = 0
			p["cipher"] = vmessCipher(kv["method"])
		} else if f := kv["vless-flow"]; f != "" {
			p["flow"] = f
		}
		if obfs == "ws" || obfs == "wss" {
			applyWS(p, obfsURI, obfsHost)
		}
		if overTLS {
			p["tls"] = true
			if tlsHost != "" {
				p["servername"] = tlsHost
			}
			if skip {
				p["skip-cert-verify"] = true
			}
		}
		if pk := kv["reality-base64-pubkey"]; pk != "" {
			p["tls"] = true
			p["reality-opts"] = map[string]any{"public-key": pk, "short-id": kv["reality-hex-shortid"]}
			p["client-fingerprint"] = "chrome"
		}
	case "trojan":
		p["type"] = "trojan"
		p["password"] = kv["password"]
		p["udp"] = truthy(kv["udp-relay"])
		if tlsHost != "" {
			p["sni"] = tlsHost
		}
		if skip {
			p["skip-cert-verify"] = true
		}
		if obfs == "wss" || obfs == "ws" {
			applyWS(p, obfsURI, obfsHost)
		}
	case "http":
		p["type"] = "http"
		p["username"] = kv["username"]
		p["password"] = kv["password"]
		if overTLS {
			p["tls"] = true
			if skip {
				p["skip-cert-verify"] = true
			}
		}
	case "socks5":
		p["type"] = "socks5"
		p["username"] = kv["username"]
		p["password"] = kv["password"]
		p["udp"] = truthy(kv["udp-relay"])
		if overTLS {
			p["tls"] = true
			if skip {
				p["skip-cert-verify"] = true
			}
		}
	case "anytls":
		p["type"] = "anytls"
		p["password"] = kv["password"]
		p["udp"] = true
		if tlsHost != "" {
			p["sni"] = tlsHost
		}
		if skip {
			p["skip-cert-verify"] = true
		}
	default:
		return nil, fmt.Errorf("qx: 不支持的类型 %s", typ)
	}
	qxNodeExtras(p, kv, typ)
	return p, nil
}

// qxNodeExtras maps the remaining QX [server_local] keys (v0.11): fast-open, tls-cert-sha256, tls-alpn,
// udp-over-tcp, tls-host for http/socks5. tls-pubkey-sha256 / tls-no-session-* / tls13 have no mihomo
// equivalent and are ignored.
func qxNodeExtras(p map[string]any, kv map[string]string, typ string) {
	if truthy(kv["fast-open"]) {
		p["tfo"] = true
	}
	hasTLS := p["tls"] == true || typ == "trojan" || typ == "anytls"
	if fp := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(kv["tls-cert-sha256"])); len(fp) == 64 && hasTLS {
		if _, err := hex.DecodeString(fp); err == nil {
			p["fingerprint"] = fp
		}
	}
	if a := qxALPN(kv["tls-alpn"]); len(a) > 0 && hasTLS {
		p["alpn"] = a
	}
	if (typ == "http" || typ == "socks5") && p["tls"] == true {
		if h := kv["tls-host"]; h != "" {
			p["sni"] = h
		}
	}
	if p["type"] == "ss" {
		switch strings.ToLower(strings.TrimSpace(kv["udp-over-tcp"])) {
		case "true", "sp.v1":
			p["udp-over-tcp"], p["udp-over-tcp-version"] = true, 1
		case "sp.v2":
			p["udp-over-tcp"], p["udp-over-tcp-version"] = true, 2
		}
	}
}

// qxALPN reads tls-alpn: either a list ("h2:http/1.1", "h2|http/1.1", "h2 http/1.1") or the TLS wire form in
// hex (length-prefixed protocol names, e.g. 02683208687474702f312e31).
func qxALPN(v string) []any {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if b, err := hex.DecodeString(v); err == nil && len(b) > 1 {
		var out []any
		for i := 0; i < len(b); {
			n := int(b[i])
			if n == 0 || i+1+n > len(b) {
				out = nil
				break
			}
			out = append(out, string(b[i+1:i+1+n]))
			i += 1 + n
		}
		if len(out) > 0 {
			return out
		}
	}
	var out []any
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == '|' || r == ' ' || r == ';' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

var qxTypes = map[string]bool{"shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "http": true, "socks5": true, "anytls": true}

// ParseNodeText converts any supported node text into mihomo proxy maps.
func parseNodeText(text string) ([]map[string]any, []string) {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	// qx/rebuild: SIP008 / sing-box JSON subscriptions parse natively (no resource parser needed).
	if nodes, _, ok := parseJSONNodes(text); ok {
		return uniqueNames(nodes), nil
	}
	// Base64-wrapped SIP008 / sing-box JSON (some panels serve the JSON encoded).
	if d, ok := tryB64(text); ok {
		if nodes, _, ok := parseJSONNodes(strings.TrimSpace(d)); ok {
			return uniqueNames(nodes), nil
		}
	}
	if !strings.Contains(text, "://") && !strings.Contains(text, "=") {
		if d, ok := tryB64(text); ok {
			text = d
		}
	} else if d, ok := tryB64(text); ok && strings.Contains(d, "://") {
		text = d
	}
	var out []map[string]any
	var errs []string
	var uris []string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		lower := strings.ToLower(line)
		var p map[string]any
		var err error
		switch {
		case strings.HasPrefix(lower, "wireguard://"), strings.HasPrefix(lower, "wg://"):
			p, err = parseWireGuard(line)
		case strings.HasPrefix(lower, "snell://"):
			p, err = parseSnell(line)
		case strings.HasPrefix(lower, "ssh://"):
			p, err = parseSSH(line)
		case strings.HasPrefix(lower, "hy2://"):
			uris = append(uris, "hysteria2://"+line[len("hy2://"):])
			continue
		case strings.HasPrefix(lower, "socks://"), strings.HasPrefix(lower, "socks5://"), strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
			p, err = parseSocksHTTP(line)
		case strings.Contains(line, "://"):
			uris = append(uris, line)
			continue
		case strings.Contains(line, "="):
			key := strings.ToLower(strings.TrimSpace(line[:strings.Index(line, "=")]))
			if qxTypes[key] {
				p, err = parseQXLine(line)
			} else {
				p, err = parseSurgeLine(line)
			}
		default:
			continue
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out = append(out, p)
	}
	if len(uris) > 0 {
		conv, err := convert.ConvertsV2Ray([]byte(strings.Join(uris, "\n")))
		if err != nil {
			errs = append(errs, err.Error())
		}
		out = append(out, conv...)
	}
	return uniqueNames(out), errs
}

// uniqueNames gives every node a non-empty, unique name ("x", "x 2", …).
func uniqueNames(out []map[string]any) []map[string]any {
	seen := map[string]int{}
	for _, p := range out {
		n := strOf(p["name"])
		if n == "" {
			n = fmt.Sprintf("%v %v", p["type"], p["server"])
		}
		if c := seen[n]; c > 0 {
			seen[n] = c + 1
			n = fmt.Sprintf("%s %d", n, c+1)
		} else {
			seen[n] = 1
		}
		p["name"] = n
	}
	return out
}

// ssh://user[:password]@host[:port][?private-key=…&private-key-passphrase=…&host-key=…&host-key-algorithms=…]#name
// private-key may be PEM (URL-encoded), base64 of a PEM, or a path inside the core home dir.
// Aliases accepted: pk / privateKey / key, passphrase, hostkey / host_key / server-key, user= when not in userinfo.
func parseSSH(line string) (map[string]any, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" {
		return nil, errors.New("ssh: 缺少服务器地址")
	}
	q := u.Query()
	p := map[string]any{"type": "ssh", "server": u.Hostname(), "port": atoi(u.Port(), 22)}
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if user == "" {
		user = firstQ(q, "user", "username")
	}
	if pass == "" {
		pass = firstQ(q, "password", "pass")
	}
	if user == "" {
		return nil, errors.New("ssh: 缺少用户名")
	}
	p["username"] = user
	if pass != "" {
		p["password"] = pass
	}
	if k := firstQ(q, "private-key", "privateKey", "private_key", "pk", "key"); k != "" {
		if !strings.Contains(k, "-----BEGIN") {
			if d, ok := tryB64(k); ok && strings.Contains(d, "-----BEGIN") {
				k = d
			}
		}
		p["private-key"] = k
	}
	if pp := firstQ(q, "private-key-passphrase", "passphrase", "privateKeyPassphrase"); pp != "" {
		p["private-key-passphrase"] = pp
	}
	if hk := firstQ(q, "host-key", "hostkey", "host_key", "server-key", "serverKey"); hk != "" {
		var keys []any
		for _, k := range strings.Split(hk, "|") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			p["host-key"] = keys
		}
	}
	if alg := firstQ(q, "host-key-algorithms", "hostKeyAlgorithms"); alg != "" {
		p["host-key-algorithms"] = csv(alg)
	}
	if pass == "" && p["private-key"] == nil {
		return nil, errors.New("ssh: 需要密码或私钥")
	}
	p["name"] = nameOr(u.Fragment, "ssh "+u.Hostname())
	return p, nil
}

// socks5://[user:pass@]host:port#name, also base64("user:pass") userinfo; http(s)://user:pass@host:port#name
func parseSocksHTTP(line string) (map[string]any, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if u.Port() == "" {
		return nil, errors.New("代理链接缺少端口")
	}
	p := map[string]any{"server": u.Hostname(), "port": atoi(u.Port(), 0)}
	if u.User != nil {
		user := u.User.Username()
		pass, hasPass := u.User.Password()
		if !hasPass {
			if d, ok := tryB64(user); ok && strings.Contains(d, ":") {
				kv := strings.SplitN(d, ":", 2)
				user, pass = kv[0], kv[1]
			}
		}
		if user != "" {
			p["username"] = user
			p["password"] = pass
		}
	}
	switch scheme {
	case "socks", "socks5", "socks5h":
		p["type"] = "socks5"
		p["udp"] = true
	default:
		p["type"] = "http"
		if scheme == "https" {
			p["tls"] = true
			if sni := u.Query().Get("sni"); sni != "" {
				p["sni"] = sni
			}
		}
	}
	p["name"] = nameOr(u.Fragment, fmt.Sprintf("%s %s", p["type"], u.Hostname()))
	return p, nil
}

func buildConfigFromProxies(proxies []map[string]any) ([]byte, error) {
	if len(proxies) == 0 {
		return nil, errors.New("未识别到节点")
	}
	names := make([]any, 0, len(proxies))
	px := make([]any, 0, len(proxies))
	for _, p := range proxies {
		names = append(names, p["name"])
		px = append(px, p)
	}
	auto := map[string]any{"name": "自动选择", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50}
	sel := map[string]any{"name": "节点选择", "type": "select", "proxies": append([]any{"自动选择", "DIRECT"}, names...)}
	cfg := map[string]any{
		"mode":         "rule",
		"proxies":      px,
		"proxy-groups": []any{sel, auto},
		"rules":        defaultRules("节点选择"),
	}
	return yaml.Marshal(cfg)
}

func defaultRules(target string) []any {
	return []any{
		"DOMAIN-SUFFIX,local,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"GEOIP,CN,DIRECT",
		"MATCH," + target,
	}
}

// ParseNodes returns a JSON array of mihomo proxy objects parsed from text
// (share links, base64 subscription, Surge/Egern or Quantumult X lines). "" on failure; see LastError.
func ParseNodes(text string) string {
	ps, errs := parseNodeText(text)
	if len(ps) == 0 {
		if len(errs) > 0 {
			setLastError(strings.Join(errs, "; "))
		} else {
			setLastError("未识别到节点")
		}
		return ""
	}
	b, _ := json.Marshal(ps)
	return string(b)
}

// ---- Manual nodes profile -------------------------------------------------

func loadYAML(path string) (map[string]any, error) {
	raw := map[string]any{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return raw, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		raw = map[string]any{}
	}
	return raw, nil
}

func proxiesOf(raw map[string]any) []map[string]any {
	var out []map[string]any
	if l, ok := raw["proxies"].([]any); ok {
		for _, x := range l {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func writeManual(path string, proxies []map[string]any) error {
	names := []any{}
	px := []any{}
	for _, p := range proxies {
		names = append(names, p["name"])
		px = append(px, p)
	}
	cfg := map[string]any{
		"mode":    "rule",
		"proxies": px,
		"proxy-groups": []any{
			map[string]any{"name": ManualGroupName, "type": "select", "proxies": append(append([]any{}, names...), "DIRECT")},
		},
		"rules": defaultRules(ManualGroupName),
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ManualList returns the proxies of the manual profile as a JSON array.
func ManualList(path string) string {
	raw, err := loadYAML(path)
	if err != nil {
		setLastError(err.Error())
		return "[]"
	}
	ps := proxiesOf(raw)
	if ps == nil {
		ps = []map[string]any{}
	}
	b, _ := json.Marshal(ps)
	return string(b)
}

// ManualAddText parses text and appends all nodes to the manual profile. Returns the number added (or -1; see LastError).
func ManualAddText(path, text string) int32 {
	ps, errs := parseNodeText(text)
	if len(ps) == 0 {
		setLastError("未识别到节点")
		if len(errs) > 0 {
			setLastError(strings.Join(errs, "; "))
		}
		return -1
	}
	raw, err := loadYAML(path)
	if err != nil {
		setLastError(err.Error())
		return -1
	}
	cur := proxiesOf(raw)
	names := map[string]bool{}
	for _, p := range cur {
		names[strOf(p["name"])] = true
	}
	for _, p := range ps {
		n := strOf(p["name"])
		base, i := n, 2
		for names[n] {
			n = fmt.Sprintf("%s %d", base, i)
			i++
		}
		p["name"] = n
		names[n] = true
		cur = append(cur, p)
	}
	if err := writeManual(path, cur); err != nil {
		setLastError(err.Error())
		return -1
	}
	return int32(len(ps))
}

// ManualUpsert inserts or replaces (by oldName) a node given as a JSON object. Returns "" or an error.
func ManualUpsert(path, nodeJSON, oldName string) string {
	var node map[string]any
	if err := json.Unmarshal([]byte(nodeJSON), &node); err != nil {
		return err.Error()
	}
	if strOf(node["name"]) == "" || strOf(node["type"]) == "" || strOf(node["server"]) == "" {
		return "名称、类型、服务器不能为空"
	}
	// JSON numbers → int for YAML neatness
	for k, v := range node {
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			node[k] = int64(f)
		}
	}
	raw, err := loadYAML(path)
	if err != nil {
		return err.Error()
	}
	cur := proxiesOf(raw)
	replaced := false
	for i, p := range cur {
		n := strOf(p["name"])
		if (oldName != "" && n == oldName) || (oldName == "" && n == strOf(node["name"])) {
			cur[i] = node
			replaced = true
			break
		}
	}
	if !replaced {
		cur = append(cur, node)
	}
	// Validate just this node by building a throwaway runtime config.
	if b, err := yaml.Marshal(map[string]any{"proxies": []any{node}, "rules": []any{"MATCH,DIRECT"}}); err == nil {
		if e := validateBytes(b); e != "" {
			return e
		}
	}
	if err := writeManual(path, cur); err != nil {
		return err.Error()
	}
	return ""
}

// ManualDelete removes a node by name.
func ManualDelete(path, name string) string {
	raw, err := loadYAML(path)
	if err != nil {
		return err.Error()
	}
	var out []map[string]any
	for _, p := range proxiesOf(raw) {
		if strOf(p["name"]) != name {
			out = append(out, p)
		}
	}
	if err := writeManual(path, out); err != nil {
		return err.Error()
	}
	return ""
}

func vmessCipher(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return "chacha20-poly1305"
	case "aes-128-gcm":
		return "aes-128-gcm"
	case "none":
		return "none"
	case "zero":
		return "zero"
	}
	return "auto"
}
