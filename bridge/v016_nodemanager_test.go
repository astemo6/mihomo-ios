package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV016NodeSummary(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	_ = os.WriteFile(NodeSubPath(home, "a"), []byte("proxies:\n  - {name: jp1, type: vless, server: 2.2.2.2, port: 443, uuid: 11111111-2222-3333-4444-555555555555, network: ws, tls: true, servername: example.com, flow: xtls-rprx-vision}\n"), 0o644)
	b, _ := json.Marshal([]NodeSub{{ID: "a", Name: "机场B", Enabled: true}})
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	profile := filepath.Join(root, "p.yaml")
	_ = os.WriteFile(profile, []byte(v09Profile), 0o644)

	var s map[string]any
	_ = json.Unmarshal([]byte(NodeSummary(home, profile, "hk1")), &s)
	if s["type"] != "ss" || s["server"] != "1.1.1.1" || s["source"] != "" || s["cipher"] != "aes-128-gcm" {
		t.Fatalf("hk1 %v", s)
	}
	if c := s["credentials"].([]any); len(c) != 1 || c[0] != "password" {
		t.Fatalf("creds %v", c)
	}
	out := NodeSummary(home, profile, "jp1")
	if strings.Contains(out, "11111111") || strings.Contains(out, "\"x\"") {
		t.Fatalf("secret leaked: %s", out)
	}
	_ = json.Unmarshal([]byte(out), &s)
	if s["source"] != "机场B" || s["network"] != "ws" || s["security"] != "tls" || s["sni"] != "example.com" || s["flow"] != "xtls-rprx-vision" {
		t.Fatalf("jp1 %v", s)
	}
	if !strings.Contains(NodeSummary(home, profile, "nope"), "error") {
		t.Fatal("missing node should error")
	}
	j := NodeSummaryJSON(`{"name":"m","type":"trojan","server":"3.3.3.3","port":443,"password":"secret"}`)
	if strings.Contains(j, "secret\"") && !strings.Contains(j, "\"password\"") {
		t.Fatalf("json %s", j)
	}
	_ = json.Unmarshal([]byte(j), &s)
	if s["security"] != "tls" || s["shareable"] != true {
		t.Fatalf("manual %v", s)
	}
	// Offline test finds node-subscription nodes (the 1 ms timeout makes it fail, but not with "找不到").
	if NodeTestDelay(home, profile, "nope", "https://www.gstatic.com/generate_204", 1) != -1 || !strings.Contains(LastError(), "找不到") {
		t.Fatal("missing node")
	}
	_ = NodeTestDelay(home, profile, "jp1", "https://www.gstatic.com/generate_204", 1)
	if strings.Contains(LastError(), "找不到") {
		t.Fatalf("jp1 not found: %s", LastError())
	}
}
