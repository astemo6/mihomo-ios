package libmihomo

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareLinkRoundTrip(t *testing.T) {
	nodes := []map[string]any{
		{"name": "SS 香港", "type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "p@ss:w", "plugin": "obfs", "plugin-opts": map[string]any{"mode": "http", "host": "bing.com"}},
		{"name": "VM ws", "type": "vmess", "server": "a.example.com", "port": 443, "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0, "cipher": "auto", "tls": true, "servername": "sni.example.com", "network": "ws", "ws-opts": map[string]any{"path": "/ray", "headers": map[string]any{"Host": "h.example.com"}}},
		{"name": "VL reality", "type": "vless", "server": "b.example.com", "port": 443, "uuid": "uuid-1", "flow": "xtls-rprx-vision", "tls": true, "servername": "www.apple.com", "client-fingerprint": "safari", "reality-opts": map[string]any{"public-key": "PBK", "short-id": "ab"}},
		{"name": "TJ", "type": "trojan", "server": "c.example.com", "port": 443, "password": "pw", "sni": "c.example.com", "skip-cert-verify": true},
		{"name": "HY2", "type": "hysteria2", "server": "d.example.com", "port": 443, "password": "pw2", "sni": "d.example.com", "obfs": "salamander", "obfs-password": "o"},
		{"name": "TUIC", "type": "tuic", "server": "e.example.com", "port": 443, "uuid": "u5", "password": "p5", "congestion-controller": "bbr", "alpn": []any{"h3"}},
		{"name": "SOCKS", "type": "socks5", "server": "f.example.com", "port": 1080, "username": "u", "password": "p"},
		{"name": "HTTPS", "type": "http", "server": "g.example.com", "port": 443, "username": "u", "password": "p", "tls": true},
		{"name": "ANY", "type": "anytls", "server": "h.example.com", "port": 443, "password": "ap", "sni": "h.example.com"},
		{"name": "WG", "type": "wireguard", "server": "i.example.com", "port": 51820, "private-key": "PRIV=", "public-key": "PUB=", "ip": "172.16.0.2", "reserved": []any{1, 2, 3}},
		{"name": "SN", "type": "snell", "server": "j.example.com", "port": 443, "psk": "k", "version": 4},
		{"name": "SSR", "type": "ssr", "server": "k.example.com", "port": 443, "cipher": "aes-256-cfb", "password": "pw", "protocol": "origin", "obfs": "plain"},
		{"name": "SSH", "type": "ssh", "server": "l.example.com", "port": 22, "username": "root", "password": "pw"},
	}
	var links []string
	for _, n := range nodes {
		s, err := ShareLinkFor(n)
		if err != nil {
			t.Fatalf("%v: %v", n["name"], err)
		}
		links = append(links, s)
	}
	back, errs := parseNodeText(strings.Join(links, "\n"))
	if len(errs) > 0 || len(back) != len(nodes) {
		t.Fatalf("parse back %d/%d errs %v\n%s", len(back), len(nodes), errs, strings.Join(links, "\n"))
	}
	byName := map[string]map[string]any{}
	for _, b := range back {
		byName[str(b["name"])] = b
	}
	check := func(name, key, want string) {
		t.Helper()
		b := byName[name]
		if b == nil {
			t.Fatalf("missing %s in %v", name, links)
		}
		if got := sStr(b, key); got != want {
			t.Fatalf("%s.%s = %q want %q", name, key, got, want)
		}
	}
	check("SS 香港", "password", "p@ss:w")
	check("SS 香港", "cipher", "aes-128-gcm")
	check("SS 香港", "plugin", "obfs")
	check("VM ws", "uuid", "11111111-2222-3333-4444-555555555555")
	check("VM ws", "servername", "sni.example.com")
	check("VM ws", "network", "ws")
	if sStr(sMap(byName["VM ws"], "ws-opts"), "path") != "/ray" {
		t.Fatal("vmess ws path")
	}
	check("VL reality", "flow", "xtls-rprx-vision")
	check("VL reality", "servername", "www.apple.com")
	if sStr(sMap(byName["VL reality"], "reality-opts"), "public-key") != "PBK" {
		t.Fatal("reality")
	}
	check("TJ", "password", "pw")
	check("TJ", "skip-cert-verify", "true")
	check("HY2", "password", "pw2")
	check("HY2", "obfs-password", "o")
	check("TUIC", "password", "p5")
	check("TUIC", "uuid", "u5")
	check("SOCKS", "password", "p")
	check("HTTPS", "tls", "true")
	check("ANY", "password", "ap")
	check("WG", "private-key", "PRIV=")
	check("WG", "public-key", "PUB=")
	check("SN", "psk", "k")
	check("SSR", "password", "pw")
	check("SSH", "password", "pw")

	if _, err := ShareLinkFor(map[string]any{"name": "x", "type": "mieru", "server": "a", "port": 1}); err == nil {
		t.Fatal("mieru should have no link")
	}
}

func TestManualSubscriptionAndByName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.yaml")
	y := "proxies:\n  - {name: A, type: trojan, server: a.com, port: 443, password: x}\n  - {name: M, type: mieru, server: m.com, port: 1, username: u, password: p, transport: TCP}\n"
	_ = os.WriteFile(path, []byte(y), 0o644)
	var r struct {
		Text    string   `json:"text"`
		Skipped []string `json:"skipped"`
		Count   int      `json:"count"`
	}
	_ = json.Unmarshal([]byte(ManualSubscription(path)), &r)
	dec, _ := base64.StdEncoding.DecodeString(r.Text)
	if r.Count != 1 || len(r.Skipped) != 1 || !strings.HasPrefix(string(dec), "trojan://x@a.com:443") {
		t.Fatalf("%+v %s", r, dec)
	}
	if s := NodeShareLinkByName(dir, path, "A"); !strings.HasPrefix(s, "trojan://") {
		t.Fatalf("by name %q %s", s, LastError())
	}
	if s := NodeShareLinkByName(dir, path, "nope"); s != "" {
		t.Fatal("missing node")
	}
}
