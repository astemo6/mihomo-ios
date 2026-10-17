package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

func TestPickNetPolicy(t *testing.T) {
	r := netPolicyRule{Group: "P", WiFi: "A", Cellular: "B", SSIDs: map[string]string{"Home": "DIRECT"}}
	cases := []struct{ typ, ssid, node, reason string }{
		{"wifi", "Home", "DIRECT", "ssid"},
		{"wifi", "home", "A", "wifi"}, // case-sensitive like iOS
		{"wifi", "", "A", "wifi"},
		{"cellular", "", "B", "cellular"},
		{"wired", "", "", ""},
	}
	for _, c := range cases {
		n, why := pickNetPolicy(r, c.typ, c.ssid)
		if n != c.node || why != c.reason {
			t.Fatalf("%s/%s: got %s/%s want %s/%s", c.typ, c.ssid, n, why, c.node, c.reason)
		}
	}
	if n, _ := pickNetPolicy(netPolicyRule{Group: "P", SSIDs: map[string]string{"X": "A"}}, "wifi", "Y"); n != "" {
		t.Fatalf("no rule must keep the group: %s", n)
	}
}

func TestApplyNetPolicy(t *testing.T) {
	home := t.TempDir()
	prof := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: B, type: socks5, server: 127.0.0.1, port: 2}\nproxy-groups:\n  - {name: P, type: select, proxies: [A, B, DIRECT]}\n  - {name: U, type: url-test, proxies: [A, B]}\nrules:\n  - MATCH,P\n"
	path := filepath.Join(home, "p1.yaml")
	_ = os.WriteFile(path, []byte(prof), 0o644)
	rt, err := buildRuntime([]byte(prof), defaultOverrides(), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	rules := map[string][]netPolicyRule{"p1": {
		{Group: "P", WiFi: "DIRECT", Cellular: "B", SSIDs: map[string]string{"Office": "A"}},
		{Group: "U", WiFi: "A"},
		{Group: "Missing", Cellular: "A"},
	}}
	b, _ := json.Marshal(rules)
	_ = os.WriteFile(netPolicyPath(home), b, 0o644)
	now := func() string {
		m, _ := tunnel.Proxies()["P"].MarshalJSON()
		var v map[string]any
		_ = json.Unmarshal(m, &v)
		return str(v["now"])
	}
	set := func(typ, ssid string) {
		npMu.Lock()
		npType, npSSID, npKnown = typ, ssid, true
		npMu.Unlock()
	}
	defer func() {
		npMu.Lock()
		npType, npSSID, npKnown = "", "", false
		npMu.Unlock()
	}()
	set("cellular", "")
	if n := applyNetPolicy(home, path, "test"); n != 1 || now() != "B" {
		t.Fatalf("cellular: n=%d now=%s", n, now())
	}
	var st netPolicyState
	sb, _ := os.ReadFile(netPolicyStatePath(home))
	_ = json.Unmarshal(sb, &st)
	if len(st.Applied) != 2 || st.Applied[1].Error == "" {
		t.Fatalf("state: %s", sb)
	}
	set("wifi", "Office")
	applyNetPolicy(home, path, "test")
	if now() != "A" {
		t.Fatalf("ssid: now=%s", now())
	}
	sb, _ = os.ReadFile(netPolicyStatePath(home))
	st = netPolicyState{}
	_ = json.Unmarshal(sb, &st)
	for _, a := range st.Applied {
		if a.Group == "U" && a.Error == "" {
			t.Fatalf("url-test groups are not switched: %s", sb)
		}
	}
	set("wifi", "Cafe")
	applyNetPolicy(home, path, "test")
	if now() != "DIRECT" {
		t.Fatalf("wifi: now=%s", now())
	}
	// No rule for wired: keeps the current member.
	set("wired", "")
	if n := applyNetPolicy(home, path, "test"); n != 0 || now() != "DIRECT" {
		t.Fatalf("wired: n=%d now=%s", n, now())
	}
}
