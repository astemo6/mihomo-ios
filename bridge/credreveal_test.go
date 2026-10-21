package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hotfix/node-cred-reveal: NodeConfig returns the full node (secrets included) for any source; the summary
// lists nested secrets by dotted path but never their values.
func TestNodeConfigAndNestedCredentials(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	sub := "proxies:\n  - {name: tw1, type: vless, server: 2.2.2.2, port: 443, uuid: 11111111-2222-3333-4444-555555555555, tls: true, servername: example.com, reality-opts: {public-key: PUBKEYabc, short-id: 0123abcd}, client-fingerprint: chrome}\n"
	_ = os.WriteFile(NodeSubPath(home, "a"), []byte(sub), 0o644)
	b, _ := json.Marshal([]NodeSub{{ID: "a", Name: "机场B", Enabled: true}})
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	profile := filepath.Join(root, "p.yaml")
	_ = os.WriteFile(profile, []byte(v09Profile), 0o644)

	out := NodeConfig(home, profile, "tw1")
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("config %q: %v", out, err)
	}
	if m["uuid"] != "11111111-2222-3333-4444-555555555555" || m["type"] != "vless" || m["server"] != "2.2.2.2" {
		t.Fatalf("config %v", m)
	}
	ro, _ := m["reality-opts"].(map[string]any)
	if ro["public-key"] != "PUBKEYabc" || ro["short-id"] != "0123abcd" {
		t.Fatalf("reality %v", ro)
	}
	if NodeConfig(home, profile, "nope") != "" {
		t.Fatal("missing node should be empty")
	}
	// Profile node too.
	if c := NodeConfig(home, profile, "hk1"); c == "" {
		t.Fatal("profile node hk1")
	}

	sum := NodeSummary(home, profile, "tw1")
	var s map[string]any
	_ = json.Unmarshal([]byte(sum), &s)
	got := map[string]bool{}
	for _, c := range s["credentials"].([]any) {
		got[c.(string)] = true
	}
	if !got["uuid"] || !got["reality-opts.public-key"] || !got["reality-opts.short-id"] {
		t.Fatalf("creds %v", s["credentials"])
	}
	for _, secret := range []string{"PUBKEYabc", "0123abcd", "11111111-2222"} {
		if strings.Contains(sum, secret) {
			t.Fatalf("summary leaked %s: %s", secret, sum)
		}
	}

	wg := NodeSummaryJSON(`{"name":"w","type":"wireguard","private-key":"x","peers":[{"server":"1.1.1.1","port":1,"public-key":"P1","pre-shared-key":"S1"}],"plugin-opts":{"password":"pp"}}`)
	_ = json.Unmarshal([]byte(wg), &s)
	got = map[string]bool{}
	for _, c := range s["credentials"].([]any) {
		got[c.(string)] = true
	}
	if !got["peers.0.public-key"] || !got["peers.0.pre-shared-key"] || !got["plugin-opts.password"] || !got["private-key"] {
		t.Fatalf("wg creds %v", s["credentials"])
	}
}
