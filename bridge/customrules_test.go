package libmihomo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCustomRulesEndToEnd(t *testing.T) {
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/qx.list":
			fmt.Fprint(w, "# QX filter\nhost-suffix, ads.example, reject\nhost-keyword, track, reject\nuser-agent, Foo*, reject\n")
		case "/surge.list":
			fmt.Fprint(w, "DOMAIN-SUFFIX,video.example\nIP-CIDR,9.9.9.0/24,no-resolve\n")
		case "/set.txt":
			fmt.Fprint(w, ".cdn.example\nexact.example\n")
		}
	}))
	defer list.Close()
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19293
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	rules := customRulesFile{Rules: []CustomRule{
		{ID: "a", Line: "host-suffix, apple.com, direct", Enabled: true},
		{ID: "b", Line: "DOMAIN-KEYWORD,google,proxy", Enabled: true},
		{ID: "c", Line: list.URL + "/qx.list, tag=广告, force-policy=reject, update-interval=3600", Enabled: true},
		{ID: "d", Line: "RULE-SET," + list.URL + "/surge.list,Proxy", Enabled: true},
		{ID: "e", Line: "DOMAIN-SET," + list.URL + "/set.txt,DIRECT", Enabled: true},
		{ID: "f", Line: "USER-AGENT,Instagram*,Proxy", Enabled: true},
		{ID: "g", Line: "DOMAIN,x.com,Netflix", Enabled: true},
		{ID: "h", Line: "DOMAIN,off.com,DIRECT", Enabled: false},
	}}
	rb, _ := json.Marshal(rules)
	_ = os.WriteFile(filepath.Join(home, "rules.json"), rb, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [demo, DIRECT]}
rules:
  - MATCH,DIRECT
`), 0o644)
	var checks []ruleCheck
	_ = json.Unmarshal([]byte(CheckCustomRules(home, prof)), &checks)
	if len(checks) != 8 || checks[5].Error == "" || checks[6].Unresolved != "Netflix" || checks[1].Policy != "Proxy" {
		t.Fatalf("checks %+v", checks)
	}
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	get := func(path string) string {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:19293"+path, nil)
		req.Header.Set("Authorization", "Bearer s")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	var body string
	for i := 0; i < 50; i++ {
		body = get("/providers/rules")
		if strings.Count(body, `"ruleCount":2`) >= 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if strings.Count(body, `"ruleCount":2`) < 3 {
		t.Fatalf("providers: %s", body)
	}
	rs := get("/rules")
	for _, want := range []string{`"payload":"apple.com"`, `"proxy":"REJECT"`, `"proxy":"Proxy"`} {
		if !strings.Contains(rs, want) {
			t.Fatalf("rules missing %s: %s", want, rs)
		}
	}
	if strings.Contains(rs, "off.com") || strings.Contains(rs, "x.com") {
		t.Fatalf("disabled/unresolved leaked: %s", rs)
	}
	var un []string
	_ = json.Unmarshal([]byte(ModuleUnresolved(home, prof, "[Rule]\nDOMAIN,a.com,Netflix\nDOMAIN,b.com,proxy\n", "{}")), &un)
	if len(un) != 1 || un[0] != "Netflix" {
		t.Fatalf("module unresolved %v", un)
	}
}
