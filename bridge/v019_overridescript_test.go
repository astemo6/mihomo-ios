package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.19 覆写脚本: profile → JSON for the script, script output validated and stored, read instead of
// the profile while current, ignored when stale or in safe mode.

const v019Profile = `proxies:
  - {name: a, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [a]}
rule:
  - MATCH,PROXY
`

func v019Home(t *testing.T) (home, prof string) {
	t.Helper()
	home = t.TempDir()
	ob, _ := json.Marshal(defaultOverrides())
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof = filepath.Join(home, "profiles", "abc.yaml")
	_ = os.MkdirAll(filepath.Dir(prof), 0o755)
	if err := os.WriteFile(prof, []byte(v019Profile), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestV019ScriptInputNormalised(t *testing.T) {
	_, prof := v019Home(t)
	js, err := ScriptInput(prof)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["rule"]; ok {
		t.Fatal("rule: should be renamed to rules:")
	}
	if r, _ := m["rules"].([]any); len(r) != 1 || r[0] != "MATCH,PROXY" {
		t.Fatalf("rules = %v", m["rules"])
	}
	if p, ok := m["proxy-providers"].(map[string]any); !ok || len(p) != 0 {
		t.Fatalf("proxy-providers should be an empty object, got %v", m["proxy-providers"])
	}
	px := m["proxies"].([]any)[0].(map[string]any)
	if px["port"].(float64) != 8388 {
		t.Fatalf("port = %v", px["port"])
	}
}

func TestV019ScriptOutputStoredAndUsed(t *testing.T) {
	home, prof := v019Home(t)
	js, _ := ScriptInput(prof)
	var m map[string]any
	_ = json.Unmarshal([]byte(js), &m)
	// what a script would do: add a node + group, rename the rule target
	m["proxies"] = append(m["proxies"].([]any), map[string]any{"name": "b", "type": "ss", "server": "127.0.0.2", "port": 8389, "cipher": "aes-128-gcm", "password": "y"})
	m["proxy-groups"] = append(m["proxy-groups"].([]any), map[string]any{"name": "AI", "type": "select", "proxies": []any{"b", "PROXY"}})
	m["rules"] = []any{"DOMAIN-SUFFIX,openai.com,AI", "MATCH,PROXY"}
	out, _ := json.Marshal(m)
	if msg := ScriptOutputApply(home, prof, string(out), `["test.js"]`); msg != "" {
		t.Fatal(msg)
	}
	y := ScriptOutputYAML(home, prof)
	if !strings.Contains(y, "port: 8389") || strings.Contains(y, "8389.0") || strings.Contains(y, "e+") {
		t.Fatalf("ports must stay integers:\n%s", y)
	}
	if strings.Contains(y, "proxy-providers") {
		t.Fatalf("empty proxy-providers should be dropped:\n%s", y)
	}
	b, err := readRuntimeProfile(home, prof, false)
	if err != nil || !strings.Contains(string(b), "openai.com") {
		t.Fatalf("runtime profile should be the script output, got %v\n%s", err, b)
	}
	var st map[string]any
	_ = json.Unmarshal([]byte(ScriptOutputStatus(home, prof)), &st)
	if st["exists"] != true || st["fresh"] != true {
		t.Fatalf("status = %v", st)
	}
	if msg := ValidateConfigIn(home, prof); msg != "" {
		t.Fatalf("validate with output: %s", msg)
	}
	// offline inspection sees the script's group
	var ins struct {
		Groups []struct{ Name string } `json:"groups"`
	}
	_ = json.Unmarshal([]byte(InspectProfile(home, prof)), &ins)
	found := false
	for _, g := range ins.Groups {
		found = found || g.Name == "AI"
	}
	if !found {
		t.Fatalf("inspect should list the script's group AI: %+v", ins.Groups)
	}
	// safe mode: the profile itself
	if b, _ := readRuntimeProfile(home, prof, true); strings.Contains(string(b), "openai.com") {
		t.Fatal("safe mode must ignore the script output")
	}
	// the profile changes (subscription update) → stale → profile itself
	_ = os.WriteFile(prof, []byte(v019Profile+"# changed\n"), 0o644)
	if b, _ := readRuntimeProfile(home, prof, false); strings.Contains(string(b), "openai.com") {
		t.Fatal("stale output must not be used")
	}
	_ = json.Unmarshal([]byte(ScriptOutputStatus(home, prof)), &st)
	if st["fresh"] != false {
		t.Fatalf("status should be stale: %v", st)
	}
	ScriptOutputClear(home, prof)
	if ScriptOutputYAML(home, prof) != "" {
		t.Fatal("clear left the output")
	}
}

func TestV019ScriptOutputInvalidRejected(t *testing.T) {
	home, prof := v019Home(t)
	js, _ := ScriptInput(prof)
	_ = ScriptOutputApply(home, prof, js, `["ok.js"]`)
	if ScriptOutputYAML(home, prof) == "" {
		t.Fatal("unchanged config should be stored")
	}
	// a group that references a missing proxy fails validation; nothing (old or new) stays
	bad := `{"proxies":[],"proxy-groups":[{"name":"X","type":"select","proxies":["missing"]}],"rules":["MATCH,X"]}`
	msg := ScriptOutputApply(home, prof, bad, `["bad.js"]`)
	if msg == "" || !strings.Contains(msg, "校验失败") {
		t.Fatalf("expected a validation error, got %q", msg)
	}
	if ScriptOutputYAML(home, prof) != "" {
		t.Fatal("a failed run must remove the previous output")
	}
	if msg := ScriptOutputApply(home, prof, `[1,2]`, `[]`); msg == "" {
		t.Fatal("an array is not a config")
	}
}

func TestV019FlushDNSCacheNoCore(t *testing.T) {
	// Must not panic without a running core (the extension may call it during start-up).
	FlushDNSCache()
}

func TestV019LanMultiUser(t *testing.T) {
	o := defaultOverrides()
	o.AllowLan = true
	o.LanAuth = LanAuth{Username: "main", Password: "p0"}
	o.LanUsers = []LanAuth{{Username: " tv ", Password: "p1"}, {Username: "main", Password: "dup"}, {Username: "a:b", Password: "x"}, {Username: "nopw"}, {Username: "kid", Password: "p:2"}}
	raw := map[string]any{}
	applyInbound(raw, o)
	got, _ := raw["authentication"].([]any)
	want := []string{"main:p0", "tv:p1", "kid:p:2"}
	if len(got) != len(want) {
		t.Fatalf("authentication = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("authentication[%d] = %v, want %s", i, got[i], want[i])
		}
	}
	// extra users only, main empty: still protected
	o.LanAuth = LanAuth{}
	raw = map[string]any{}
	applyInbound(raw, o)
	if got, _ := raw["authentication"].([]any); len(got) != 3 {
		t.Fatalf("extra users without a main user: %v", got)
	}
	o.LanUsers = nil
	raw = map[string]any{}
	applyInbound(raw, o)
	if _, ok := raw["authentication"]; ok {
		t.Fatal("no users → no authentication")
	}
}
