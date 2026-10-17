package libmihomo

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"go.yaml.in/yaml/v3"
)

// SIP008 (https://shadowsocks.org/doc/sip008.html) through the subscription paths: profile import
// (ConvertShareLinks), base64-wrapped bodies and node subscriptions (parseNodeText).
func TestSIP008Subscription(t *testing.T) {
	body := `{"version":1,"servers":[
	 {"id":"27b8a625-4f4b-4428-9f0f-8a2317db7c79","remarks":"SG 01","server":"sg.example.com","server_port":8388,"password":"example","method":"chacha20-ietf-poly1305"},
	 {"id":"7842c068-c667-41f2-8f7d-04feece3cb67","remarks":"SG 01","server":"198.51.100.7","server_port":8389,"password":"AAAAAAAAAAAAAAAAAAAAAA==","method":"2022-blake3-aes-128-gcm","plugin":"v2ray-plugin","plugin_opts":"server;tls;host=cdn.example.com;path=/ws"},
	 {"server":"","server_port":1,"password":"x","method":"aes-128-gcm"}
	],"bytes_used":274877906944,"bytes_remaining":824633720832}`
	for name, text := range map[string]string{"plain": body, "base64": base64.StdEncoding.EncodeToString([]byte(body))} {
		nodes, errs := parseNodeText(text)
		if len(errs) > 0 || len(nodes) < 2 {
			t.Fatalf("%s: %v %v", name, nodes, errs)
		}
		if nodes[0]["name"] != "SG 01" || nodes[1]["name"] == "SG 01" {
			t.Fatalf("%s: names not unique: %v / %v", name, nodes[0]["name"], nodes[1]["name"])
		}
		for _, n := range nodes[:2] {
			if n["type"] != "ss" {
				t.Fatalf("%s: %v", name, n)
			}
			if _, err := adapter.ParseProxy(n); err != nil {
				t.Fatalf("%s: core rejects %v: %v", name, n, err)
			}
		}
		yml := ConvertShareLinks(text)
		if yml == "" {
			t.Fatalf("%s: ConvertShareLinks: %s", name, LastError())
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(yml), &cfg); err != nil {
			t.Fatal(err)
		}
		if ps, _ := cfg["proxies"].([]any); len(ps) < 2 || !strings.Contains(yml, "sg.example.com") {
			t.Fatalf("%s: %s", name, yml)
		}
	}
	if f := DetectNodeFormat(body); !strings.Contains(f, "SIP008") {
		t.Fatalf("detect: %s", f)
	}
}
