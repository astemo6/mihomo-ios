package libmihomo

import "testing"

func TestAndroidTunRewrite(t *testing.T) {
	raw := map[string]any{"tun": map[string]any{"enable": true, "stack": "gvisor", "file-descriptor": 42, "mtu": 4064, "recvmsgx": false, "sendmsgx": false},
		"dns": map[string]any{"fake-ip-range": "28.0.0.1/8"}}
	androidTun(raw, Overrides{})
	tun := raw["tun"].(map[string]any)
	if _, ok := tun["recvmsgx"]; ok {
		t.Fatal("recvmsgx kept")
	}
	if tun["mtu"] != AndroidTunMTU || tun["file-descriptor"] != 42 {
		t.Fatalf("tun = %v", tun)
	}
	if raw["dns"].(map[string]any)["fake-ip-range"] != androidFakeIPRange {
		t.Fatal("fake-ip-range not pinned")
	}
	none := map[string]any{}
	androidTun(none, Overrides{}) // no tun section: untouched
	if _, ok := none["tun"]; ok {
		t.Fatal("tun added")
	}
}
