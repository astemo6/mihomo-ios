package libmihomo

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

// v0.13: share links for VLESS xhttp and Mieru come back through the importer unchanged.
func TestV013ShareXHTTPAndMieru(t *testing.T) {
	nodes := []map[string]any{
		{"name": "VL xhttp", "type": "vless", "server": "x.example.com", "port": 443, "uuid": "11111111-2222-3333-4444-555555555555",
			"tls": true, "servername": "x.example.com", "encryption": "none", "network": "xhttp",
			"xhttp-opts": map[string]any{"path": "/xh", "host": "cdn.example.com", "mode": "stream-one"}},
		{"name": "MI", "type": "mieru", "server": "m.example.com", "port": 2999, "username": "u", "password": "p", "transport": "TCP", "multiplexing": "MULTIPLEXING_LOW"},
		{"name": "MI range", "type": "mieru", "server": "m.example.com", "port-range": "2090-2099", "username": "u", "password": "p", "transport": "UDP"},
	}
	for _, n := range nodes {
		link, err := ShareLinkFor(n)
		if err != nil {
			t.Fatalf("%s: %v", n["name"], err)
		}
		got, errs := parseNodeText(link)
		if len(got) != 1 {
			t.Fatalf("%s: %s parsed into %d nodes (%v)", n["name"], link, len(got), errs)
		}
		g := got[0]
		if g["type"] != n["type"] || g["server"] != n["server"] {
			t.Fatalf("%s: round trip %v", n["name"], g)
		}
		switch n["type"] {
		case "vless":
			o, _ := g["xhttp-opts"].(map[string]any)
			if g["network"] != "xhttp" || o["path"] != "/xh" || o["host"] != "cdn.example.com" || o["mode"] != "stream-one" {
				t.Fatalf("xhttp lost: %s → %v", link, g)
			}
		case "mieru":
			if g["transport"] != n["transport"] || g["username"] != "u" || g["password"] != "p" {
				t.Fatalf("mieru lost: %s → %v", link, g)
			}
			if pr, ok := n["port-range"]; ok && g["port-range"] != pr {
				t.Fatalf("mieru range lost: %s → %v", link, g)
			}
		}
		if _, err := adapter.ParseProxy(g); err != nil {
			t.Fatalf("%s: core rejects %v: %v", n["name"], g, err)
		}
	}
}
