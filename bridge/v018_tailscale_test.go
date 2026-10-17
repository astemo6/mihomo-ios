package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.18: Tailscale node plumbing that does not need tsnet (runs without build tags).

func TestV018NormalizeTailscale(t *testing.T) {
	home := t.TempDir()
	raw := map[string]any{"proxies": []any{
		map[string]any{"name": "ts", "type": "tailscale"},
		map[string]any{"name": "东京", "type": "tailscale"},
		map[string]any{"name": "大阪", "type": "tailscale"},
		map[string]any{"name": "abs-out", "type": "tailscale", "state-dir": "/etc/ts"},
		map[string]any{"name": "abs-in", "type": "tailscale", "state-dir": filepath.Join(home, "x", "ts"), "hostname": "phone"},
		map[string]any{"name": "dotdot", "type": "tailscale", "state-dir": "../../ts"},
		map[string]any{"name": "rel", "type": "tailscale", "state-dir": "my/ts"},
		map[string]any{"name": "ss", "type": "ss", "server": "192.0.2.1", "port": 1},
	}}
	if n := normalizeTailscale(raw, home); n != 7 {
		t.Fatalf("normalized %d, want 7", n)
	}
	ps := asList(raw["proxies"])
	get := func(i int, k string) string { return str(ps[i].(map[string]any)[k]) }
	if d := get(0, "state-dir"); !strings.HasPrefix(d, "tailscale/ts-") {
		t.Errorf("default dir %q", d)
	}
	if get(1, "state-dir") == get(2, "state-dir") {
		t.Errorf("chinese names collide: %q", get(1, "state-dir"))
	}
	if d := get(3, "state-dir"); !strings.HasPrefix(d, "tailscale/") {
		t.Errorf("absolute path outside home kept: %q", d)
	}
	if d := get(4, "state-dir"); d != filepath.Join(home, "x", "ts") || get(4, "hostname") != "phone" {
		t.Errorf("inside home changed: %q %q", d, get(4, "hostname"))
	}
	if d := get(5, "state-dir"); !strings.HasPrefix(d, "tailscale/") {
		t.Errorf(".. kept: %q", d)
	}
	if d := get(6, "state-dir"); d != "my/ts" {
		t.Errorf("relative changed: %q", d)
	}
	if get(0, "hostname") != "mihomo-ios" {
		t.Errorf("hostname default %q", get(0, "hostname"))
	}
	if _, ok := ps[7].(map[string]any)["state-dir"]; ok {
		t.Errorf("ss touched")
	}
}

func TestV018TailscaleOfflineTestRefused(t *testing.T) {
	if d := TestDelay(`{"name":"ts","type":"tailscale","auth-key":"tskey-auth-xxxx"}`, "http://127.0.0.1:1/", 500); d != -1 {
		t.Fatalf("offline test of tailscale returned %d", d)
	}
	if !strings.Contains(LastError(), "Tailscale") {
		t.Fatalf("error %q", LastError())
	}
}

func TestV018TailscaleSummary(t *testing.T) {
	s := NodeSummaryJSON(`{"name":"ts","type":"tailscale","auth-key":"tskey-auth-secret","hostname":"phone","control-url":"https://hs.example.com","accept-routes":true,"exit-node":"auto:any","ephemeral":true}`)
	if strings.Contains(s, "tskey-auth-secret") {
		t.Fatalf("auth key leaked: %s", s)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(s), &m)
	ts, _ := m["tailscale"].(map[string]any)
	if ts["hostname"] != "phone" || ts["control-url"] != "https://hs.example.com" || ts["accept-routes"] != true || ts["exit-node"] != "auto:any" || ts["ephemeral"] != true {
		t.Fatalf("summary %s", s)
	}
	creds, _ := m["credentials"].([]any)
	found := false
	for _, c := range creds {
		found = found || c == "auth-key"
	}
	if !found {
		t.Fatalf("auth-key not listed as credential: %s", s)
	}
}

func TestV018ServerlessUpsert(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manual.yaml")
	_ = os.WriteFile(p, []byte("proxies: []\n"), 0o644)
	// Without with_gvisor the core rejects the type itself; the server check must not be what fails.
	e := ManualUpsert(p, `{"name":"ts","type":"tailscale","auth-key":"tskey-auth-xxxx"}`, "")
	if strings.Contains(e, "服务器不能为空") {
		t.Fatalf("serverless node rejected for missing server: %s", e)
	}
	if e := ManualUpsert(p, `{"name":"x","type":"ss"}`, ""); !strings.Contains(e, "服务器不能为空") {
		t.Fatalf("ss without server accepted: %q", e)
	}
}

func TestV018MemorySnapshot(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(MemorySnapshot(30<<20, 35<<20, 20<<20)), &m); err != nil {
		t.Fatal(err)
	}
	if m["footprint"].(float64) != 30<<20 || m["peak"].(float64) != 35<<20 || m["available"].(float64) != 20<<20 {
		t.Fatalf("snapshot %v", m)
	}
	ts, _ := m["tailscale"].(map[string]any)
	if ts == nil || ts["minAvailableToStart"].(float64) != tsMinAvailableToStart {
		t.Fatalf("tailscale status missing: %v", m)
	}
	tsObserveLog("[Tailscale](ts) To start this tsnet server, restart with TS_AUTHKEY set, or go to: https://login.tailscale.com/a/abc123")
	if !strings.Contains(TailscaleStatus(), "https://login.tailscale.com/a/abc123") {
		t.Fatalf("auth url not captured: %s", TailscaleStatus())
	}
}
