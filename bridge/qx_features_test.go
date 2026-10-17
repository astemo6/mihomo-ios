package libmihomo

import (
	"reflect"
	"testing"
)

func TestProxyFeatures(t *testing.T) {
	cases := []struct {
		m    map[string]any
		want []string
	}{
		{map[string]any{"type": "vmess", "alterId": 0, "network": "ws", "tls": true, "skip-cert-verify": true}, []string{"ws", "tls", "skip-cert", "aead"}},
		{map[string]any{"type": "vless", "flow": "xtls-rprx-vision", "reality-opts": map[string]any{"public-key": "x"}, "tfo": true}, []string{"tfo", "tls", "reality", "vision"}},
		{map[string]any{"type": "ss", "plugin": "obfs", "plugin-opts": map[string]any{"mode": "tls"}, "udp-over-tcp": true}, []string{"uot", "tls"}},
		{map[string]any{"type": "trojan", "alpn": []any{"h2"}, "fingerprint": "ab"}, []string{"tls", "pin", "alpn"}},
		{map[string]any{"type": "ss"}, nil},
	}
	for i, c := range cases {
		if got := proxyFeatures(c.m); !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
