package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestGithubToMirror(t *testing.T) {
	cases := map[string]string{
		"https://raw.githubusercontent.com/u/r/main/a/b.yaml":         "https://testingcf.jsdelivr.net/gh/u/r@main/a/b.yaml",
		"https://raw.githubusercontent.com/u/r/refs/heads/dev/x.list": "https://testingcf.jsdelivr.net/gh/u/r@dev/x.list",
		"https://github.com/u/r/raw/main/rules/cn.mrs":                "https://testingcf.jsdelivr.net/gh/u/r@main/rules/cn.mrs",
		"https://github.com/u/r/blob/master/p.txt":                    "https://testingcf.jsdelivr.net/gh/u/r@master/p.txt",
		"https://gist.githubusercontent.com/u/abc/raw/sub.yaml":       "",
		"https://github.com/u/r/releases/download/latest/geoip.dat":   "",
		"https://example.com/x.yaml":                                  "",
	}
	for in, want := range cases {
		got, ok := githubToMirror(in)
		if want == "" {
			if ok {
				t.Errorf("%s should stay, got %s", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%s -> %s (want %s)", in, got, want)
		}
	}
}

func TestRuntimeGeoAndProviders(t *testing.T) {
	prof := sample + `rule-providers:
  cn: {type: http, behavior: domain, url: "https://raw.githubusercontent.com/u/r/main/cn.yaml", interval: 86400}
  px: {type: http, behavior: domain, url: "https://raw.githubusercontent.com/u/r/main/px.yaml", proxy: PROXY}
geox-url:
  mmdb: https://github.com/x/y/releases/download/latest/geoip.metadb
geodata-mode: true
`
	o := defaultOverrides()
	rt, err := buildRuntime([]byte(prof), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = yaml.Unmarshal(rt, &m)
	if m["geodata-mode"] != false || m["geodata-loader"] != "memconservative" || m["geo-auto-update"] != false {
		t.Fatalf("geo opts: %v %v %v", m["geodata-mode"], m["geodata-loader"], m["geo-auto-update"])
	}
	gx := m["geox-url"].(map[string]any)
	if !strings.HasPrefix(gx["mmdb"].(string), "https://testingcf.jsdelivr.net/") {
		t.Fatalf("geox %v", gx)
	}
	rp := m["rule-providers"].(map[string]any)
	if u := rp["cn"].(map[string]any)["url"]; u != "https://testingcf.jsdelivr.net/gh/u/r@main/cn.yaml" {
		t.Fatalf("cn url %v", u)
	}
	if u := rp["px"].(map[string]any)["url"]; u != "https://raw.githubusercontent.com/u/r/main/px.yaml" {
		t.Fatalf("px url %v", u)
	}
}

// A provider that can never download must not block Start: it returns once the core is up.
func TestStartDoesNotWaitForProviders(t *testing.T) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19291
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	logPath := filepath.Join(home, "startup.log")
	SetStageLog(logPath, 8*3600)
	defer SetStageLog("", 0)
	prof := filepath.Join(home, "p.yaml")
	// 10.255.255.1 is a black hole: the HTTP fetch hangs until its own timeout.
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rule-providers:
  slow: {type: http, behavior: domain, url: "http://10.255.255.1/slow.yaml", path: ./slow.yaml, interval: 86400}
rules:
  - RULE-SET,slow,demo
  - MATCH,DIRECT
`), 0o644)
	t0 := time.Now()
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	if d := time.Since(t0); d > 8*time.Second {
		t.Fatalf("Start took %s", d)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "core start end") {
		t.Fatalf("stage log: %s", b)
	}
	t.Logf("start %s\n%s", time.Since(t0), b)
}
