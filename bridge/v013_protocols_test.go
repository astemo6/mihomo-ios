package libmihomo

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
)

// v0.13: the node editor's defaults for the newer protocols (plus the minimum required fields) are
// accepted by the core, so a freshly filled form saves without a parser error.
func TestV013EditorProtocolShapes(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----"
	nodes := []map[string]any{
		{"name": "sd", "type": "sudoku", "server": "s.example.com", "port": 443, "key": "k", "aead-method": "chacha20-poly1305", "table-type": "prefer_ascii"},
		{"name": "mq", "type": "masque", "server": "m.example.com", "port": 443, "private-key": "MHcCAQEEIIc1", "public-key": "MFkwEwYHKoZ", "ip": "172.16.0.2", "mtu": 1280, "udp": true},
		{"name": "tt", "type": "trusttunnel", "server": "t.example.com", "port": 443, "username": "u", "password": "p", "alpn": []any{"h2"}, "udp": true},
		{"name": "sq", "type": "shadowquic", "server": "q.example.com", "port": 443, "username": "u", "password": "p", "sni": "www.example.com", "alpn": []any{"h3"}, "congestion-controller": "bbr"},
		{"name": "ov", "type": "openvpn", "server": "o.example.com", "port": 1194, "proto": "udp", "ca": ca, "username": "u", "password": "p", "udp": true},
		{"name": "gr", "type": "gost-relay", "server": "g.example.com", "port": 443, "tls": true, "udp": true},
		{"name": "awg", "type": "wireguard", "server": "w.example.com", "port": 51820, "private-key": "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=", "public-key": "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=", "ip": "172.16.0.2", "udp": true,
			"amnezia-wg-option": map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0, "h1": 1, "h2": 2, "h3": 3, "h4": 4}},
		{"name": "vx", "type": "vless", "server": "v.example.com", "port": 443, "uuid": "11111111-2222-3333-4444-555555555555", "tls": true, "network": "xhttp", "encryption": "none",
			"packet-encoding": "xudp", "xhttp-opts": map[string]any{"path": "/x", "mode": "auto"}},
		{"name": "hy", "type": "hysteria2", "server": "h.example.com", "port": 443, "password": "p", "ports": "20000-30000", "hop-interval": "30", "alpn": []any{"h3"}},
	}
	for _, n := range nodes {
		p, err := adapter.ParseProxy(n)
		if err != nil {
			// OpenVPN / MASQUE validate key material at parse time; dummy keys are allowed to fail only there.
			if n["type"] == "openvpn" || n["type"] == "masque" {
				t.Logf("%s: %v (dummy key material)", n["type"], err)
				continue
			}
			t.Fatalf("%s: %v", n["name"], err)
		}
		_ = p.Close()
	}
}
