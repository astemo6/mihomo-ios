package libmihomo

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

func TestNativeJSONFormats(t *testing.T) {
	sip := `{"version":1,"servers":[{"id":"1","remarks":"HK 01","server":"hk.example.com","server_port":8388,"password":"pw","method":"aes-256-gcm","plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=a.com"}]}`
	nodes, errs := parseNodeText(sip)
	if len(errs) > 0 || len(nodes) != 1 || nodes[0]["name"] != "HK 01" || nodes[0]["plugin"] != "obfs" {
		t.Fatalf("sip008: %v %v", nodes, errs)
	}
	sb := `{"outbounds":[
	 {"type":"vless","tag":"JP Reality","server":"jp.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision",
	  "tls":{"enabled":true,"server_name":"www.apple.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123"}}},
	 {"type":"hysteria2","tag":"HY2","server":"h.example.com","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"h.example.com"}},
	 {"type":"tuic","tag":"TUIC","server":"t.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","password":"p","congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"]}},
	 {"type":"vmess","tag":"WS","server":"v.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto","tls":{"enabled":true},"transport":{"type":"ws","path":"/ws","headers":{"Host":"v.example.com"}}},
	 {"type":"anytls","tag":"ANY","server":"a.example.com","server_port":443,"password":"p","tls":{"enabled":true}},
	 {"type":"selector","tag":"proxy","outbounds":["JP Reality"]},
	 {"type":"direct","tag":"direct"}
	]}`
	nodes, errs = parseNodeText(sb)
	if len(errs) > 0 || len(nodes) != 5 {
		t.Fatalf("sing-box: %d %v", len(nodes), errs)
	}
	for _, n := range nodes {
		if _, err := adapter.ParseProxy(n); err != nil {
			b, _ := json.Marshal(n)
			t.Errorf("core rejects %s: %v", b, err)
		}
	}
	f, c := detectNodeFormat(sb)
	if f != "sing-box" || c != 5 {
		t.Errorf("detect sing-box: %s %d", f, c)
	}
	if f, c := detectNodeFormat("proxies:\n  - {name: a, type: ss, server: x, port: 1, cipher: aes-128-gcm, password: p}\n"); f != "Clash YAML" || c != 1 {
		t.Errorf("detect yaml: %s %d", f, c)
	}
	if f, _ := detectNodeFormat("ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#a"); f != "分享链接" {
		t.Errorf("detect uri: %s", f)
	}
}
