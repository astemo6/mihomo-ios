package libmihomo

// v0.19.10: review 5 lane 1 (Go bridge core) fixes. Probes from work/review5/lane1-probes turned into tests.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

const v01910Profile = `proxies:
  - {name: a, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: pw1234567}
proxy-groups:
  - {name: P, type: select, proxies: [a]}
rules:
  - MATCH,P
`

const v01910Inbounds = `listeners:
  - {name: socks-in, type: socks, port: 10808}
  - {name: ss-in, type: shadowsocks, port: 10809, cipher: aes-128-gcm, password: x}
  - {name: tun-in, type: tun, stack: system}
  - {name: local-in, type: mixed, listen: 127.0.0.1, port: 10813}
tunnels:
  - tcp,0.0.0.0:6553,192.0.2.9:53,P
tuic-server: {enable: true, listen: 0.0.0.0:10443}
ss-config: ss://aes-128-gcm:pw@:10811
vmess-config: vmess://aes-128-gcm:uuid@:10812
`

func v01910Runtime(t *testing.T, prof string, o Overrides) map[string]any {
	t.Helper()
	rt, err := buildRuntime([]byte(prof), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func listenerNames(raw map[string]any) []string {
	var out []string
	for _, l := range asList(raw["listeners"]) {
		out = append(out, str(asMap(l)["name"]))
	}
	return out
}

// P1-1: profile inbounds stripped while 局域网共享 is off.
func TestV01910InboundsStrippedLanOff(t *testing.T) {
	raw := v01910Runtime(t, v01910Profile+v01910Inbounds, defaultOverrides())
	for _, k := range []string{"tunnels", "tuic-server", "ss-config", "vmess-config"} {
		if _, ok := raw[k]; ok {
			t.Errorf("%s kept with 局域网共享 off: %v", k, raw[k])
		}
	}
	names := listenerNames(raw)
	for _, n := range names {
		if n != probeListener && n != "local-in" {
			t.Errorf("profile listener %q kept with 局域网共享 off (listeners %v)", n, names)
		}
	}
	if len(names) != 2 {
		t.Errorf("want only the probe + loopback listeners, got %v", names)
	}
	// probe listener still loopback only
	for _, l := range asList(raw["listeners"]) {
		if m := asMap(l); str(m["name"]) == probeListener && str(m["listen"]) != "127.0.0.1" {
			t.Errorf("probe listener listen = %v", m["listen"])
		}
	}
}

// P1-1: 局域网共享 on keeps auth-capable listeners and applies the LAN users.
func TestV01910InboundsLanOnAuth(t *testing.T) {
	o := defaultOverrides()
	o.AllowLan = true
	o.MixedPort = 7890
	o.LanAuth.Username, o.LanAuth.Password = "lanuser", "lanpass99"
	raw := v01910Runtime(t, v01910Profile+v01910Inbounds, o)
	if _, ok := raw["tunnels"]; ok {
		t.Error("tunnels (no auth possible) kept with 局域网共享 on")
	}
	got := map[string]map[string]any{}
	for _, l := range asList(raw["listeners"]) {
		m := asMap(l)
		got[str(m["name"])] = m
	}
	if _, ok := got["tun-in"]; ok {
		t.Error("tun listener kept")
	}
	if _, ok := got["ss-in"]; !ok {
		t.Error("shadowsocks listener (own password) dropped with 局域网共享 on")
	}
	socks, ok := got["socks-in"]
	if !ok {
		t.Fatalf("socks listener dropped with 局域网共享 on: %v", listenerNames(raw))
	}
	users := asList(socks["users"])
	if len(users) != 1 || str(asMap(users[0])["username"]) != "lanuser" || str(asMap(users[0])["password"]) != "lanpass99" {
		t.Fatalf("socks listener users = %v", socks["users"])
	}
	rt, _ := yaml.Marshal(raw)
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("runtime with LAN listeners does not parse: %v", err)
	}
}

// P1-2: pattern-based redaction.
func TestV01910RedactKeys(t *testing.T) {
	r := newRedactor()
	cfg := map[string]any{
		"proxies": []any{
			map[string]any{"name": "ts", "type": "tailscale", "auth-key": "tskey-auth-kAbCdEf123456-SECRETSECRETSECRET"},
			map[string]any{"name": "et", "type": "easytier", "network-name": "home", "network-secret": "myEasySecret99"},
			map[string]any{"name": "v", "type": "vless", "encryption": "mlkem768x25519plus.native.0rtt.SECRETKEYMATERIALxyz", "alterId": 0},
			map[string]any{"name": "w", "type": "wireguard", "local-private-key": "LOCALPRIVKEYAAAA", "identity-secret": "IDSECRET1234", "x-padding-key": "PADKEY123456"},
		},
		"dns":     map[string]any{"nameserver-policy": map[string]any{"+.monkey.com": "8.8.8.8"}},
		"profile": map[string]any{"store-selected": true},
	}
	b, _ := yaml.Marshal(r.config(cfg))
	out := string(b)
	for _, leak := range []string{"tskey-auth", "myEasySecret99", "SECRETKEYMATERIAL", "LOCALPRIVKEY", "IDSECRET", "PADKEY"} {
		if strings.Contains(out, leak) {
			t.Errorf("config leaks %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"8.8.8.8", "network-name: home", "store-selected: true"} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted, %q missing:\n%s", keep, out)
		}
	}
	txt := newRedactor().text("auth-key: tskey-auth-kAbCdEf123456-SECRETSECRETSECRET network-secret=myEasySecret99 " +
		"import vmess://eyJhZGQiOiIxOTguNTEuMTAwLjciLCJpZCI6InNlY3JldCJ9 rules https://cdn.example.com/geoip/release/geoip.dat")
	for _, leak := range []string{"tskey-auth-k", "myEasySecret99", "eyJhZGQiOiIxOTgu"} {
		if strings.Contains(txt, leak) {
			t.Errorf("text leaks %q: %s", leak, txt)
		}
	}
	if !strings.Contains(txt, "https://cdn.example.com/geoip/release/geoip.dat") {
		t.Errorf("readable public URL path redacted: %s", txt)
	}
}

const v01910DialerProfile = `proxies:
  - {name: a, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: pw1234567}
  - {name: b, type: ss, server: 192.0.2.2, port: 443, cipher: aes-128-gcm, password: pw1234567, dialer-proxy: P}
proxy-groups:
  - {name: P, type: select, proxies: [a]}
  - {name: R, type: select, proxies: [b, P]}
dns:
  enable: true
  nameserver: ["https://1.1.1.1/dns-query#P", "tls://8.8.8.8#P&ecs=1.2.3.0/24"]
  nameserver-policy: {"+.example.com": "https://9.9.9.9/dns-query#P"}
rules:
  - MATCH,R
`

// P1-3: rename / delete carries into dialer-proxy and DNS #group; the merged config parses.
func TestV01910GroupRenameDialerProxy(t *testing.T) {
	for _, tc := range []struct {
		ed   GroupEdit
		want string
	}{
		{GroupEdit{Spec: &GroupSpec{Name: "Q", Type: "select", Proxies: []string{"a"}}}, "Q"},
		{GroupEdit{Deleted: true}, ""},
	} {
		raw := map[string]any{}
		_ = yaml.Unmarshal([]byte(v01910DialerProfile), &raw)
		w := applyGroupEdits(raw, &GroupEdits{Edits: map[string]GroupEdit{"P": tc.ed}})
		b := asMap(asList(raw["proxies"])[1])
		if got := str(b["dialer-proxy"]); got != tc.want {
			t.Errorf("deleted=%v: dialer-proxy = %q, want %q", tc.ed.Deleted, got, tc.want)
		}
		dns := asMap(raw["dns"])
		ns := fmt.Sprint(dns["nameserver"], asMap(dns["nameserver-policy"]))
		if strings.Contains(ns, "#P") {
			t.Errorf("deleted=%v: DNS still names P: %s", tc.ed.Deleted, ns)
		}
		if tc.want == "Q" && !strings.Contains(ns, "#Q&ecs=1.2.3.0/24") {
			t.Errorf("rename lost DNS params: %s", ns)
		}
		if tc.ed.Deleted && len(w) == 0 {
			t.Error("delete gave no warning")
		}
		out, _ := yaml.Marshal(raw)
		if _, err := executor.ParseWithBytes(out); err != nil {
			t.Errorf("deleted=%v: core parse error: %v", tc.ed.Deleted, err)
		}
	}
}

// P1-3: GroupEditCheck parses the merged config.
func TestV01910GroupEditCheckParses(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "mihomo")
	_ = os.MkdirAll(home, 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "profiles"), 0o755)
	pp := filepath.Join(dir, "profiles", "p1.yaml")
	if err := os.WriteFile(pp, []byte(v01910DialerProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, _ := json.Marshal(GroupEdits{Edits: map[string]GroupEdit{"P": {Spec: &GroupSpec{Name: "Q", Type: "select", Proxies: []string{"a"}}}}})
	if r := GroupEditCheck(home, pp, string(ok)); r != "" {
		t.Fatalf("valid rename refused: %s", r)
	}
	// a group whose only member is an unknown proxy: structurally non-empty, but mihomo refuses it
	bad, _ := json.Marshal(GroupEdits{Edits: map[string]GroupEdit{"P": {Spec: &GroupSpec{Name: "P", Type: "select", Proxies: []string{"no-such-node"}}}}})
	if r := GroupEditCheck(home, pp, string(bad)); !strings.Contains(r, "无法使用") {
		t.Fatalf("broken edit accepted: %q", r)
	}
}

// P2-1: read-only helpers see the override-script output.
func TestV01910ScriptOutputHelpers(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "mihomo")
	_ = os.MkdirAll(filepath.Join(home, "scripted"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "profiles"), 0o755)
	pp := filepath.Join(dir, "profiles", "p1.yaml")
	_ = os.WriteFile(pp, []byte(v01910Profile), 0o644)
	scripted := v01910Profile + "  - RULE-SET,ads,REJECT\nrule-providers:\n  ads: {type: http, behavior: domain, url: \"https://example.com/ads.txt\", path: ./ruleset/ads.txt, interval: 86400}\n"
	scripted = strings.Replace(scripted, "proxies:\n", "proxies:\n  - {name: scripted-node, type: ss, server: 192.0.2.7, port: 443, cipher: aes-128-gcm, password: pw7654321}\n", 1)
	scripted = strings.Replace(scripted, "rules:\n  - MATCH,P\n  - RULE-SET,ads,REJECT\n", "rules:\n  - RULE-SET,ads,REJECT\n  - MATCH,P\n", 1)
	yp, mp := scriptedPaths(home, pp)
	_ = os.WriteFile(yp, []byte(scripted), 0o644)
	mb, _ := json.Marshal(scriptedMeta{Source: sha256Hex([]byte(v01910Profile)), At: 1})
	_ = os.WriteFile(mp, mb, 0o644)
	resetRuntimeCache()
	if s := NodeSummary(home, pp, "scripted-node"); strings.Contains(s, "找不到") {
		t.Errorf("NodeSummary misses script node: %s", s)
	}
	if s := ProviderPlan(home, pp); !strings.Contains(s, "ads") {
		t.Errorf("ProviderPlan misses script rule-provider: %s", s)
	}
	// the cache key follows the scripted output
	k1 := runtimeCacheKey(home, pp)
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(yp, []byte(scripted+"\n"), 0o644)
	if runtimeCacheKey(home, pp) == k1 {
		t.Error("runtimeCacheKey ignores scripted output")
	}
}

// P2-2: regex matcher has a real timeout and never gives false negatives under load.
func TestV01910RegexMatcherNoFalseNegative(t *testing.T) {
	m, err := newMatcher(`香港|HK`, true)
	if err != nil {
		t.Fatal(err)
	}
	if m.re.MatchTimeout != time.Second {
		t.Fatalf("MatchTimeout = %v", m.re.MatchTimeout)
	}
	names := make([]string, 50)
	for i := range names {
		names[i] = "🇭🇰 香港 IPLC 专线 " + strings.Repeat("x", i) + " HK-01 | 1.5x 倍率"
	}
	miss, total := 0, 0
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		for _, n := range names {
			total++
			if !m.match(n) {
				miss++
			}
		}
	}
	if miss > 0 {
		t.Fatalf("%d / %d positive names reported as no-match", miss, total)
	}
}

// P2-3: Surge include-all-proxies / include-other-group.
func TestV01910SurgeIncludeAll(t *testing.T) {
	conf := "[Proxy]\nA = ss, 192.0.2.1, 443, encrypt-method=aes-128-gcm, password=pw\nB = ss, 192.0.2.2, 443, encrypt-method=aes-128-gcm, password=pw\n" +
		"[Proxy Group]\nProxy = select, include-all-proxies=true\nAuto = url-test, A, B\nOther = select, include-other-group=\"Proxy,Auto\", DIRECT\n[Rule]\nFINAL,Proxy\n"
	var res struct{ YAML string }
	if err := json.Unmarshal([]byte(ImportConf(conf)), &res); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(res.YAML), &raw); err != nil {
		t.Fatal(err)
	}
	gs := map[string]map[string]any{}
	for _, g := range asList(raw["proxy-groups"]) {
		gs[str(asMap(g)["name"])] = asMap(g)
	}
	if !boolOf(gs["Proxy"]["include-all-proxies"]) || fmt.Sprint(gs["Proxy"]["proxies"]) == "[DIRECT]" {
		t.Errorf("Proxy group: %v", gs["Proxy"])
	}
	other := fmt.Sprint(gs["Other"]["proxies"])
	if !strings.Contains(other, "Proxy") || !strings.Contains(other, "Auto") || !strings.Contains(other, "DIRECT") {
		t.Errorf("Other group members: %s", other)
	}
	if _, err := executor.ParseWithBytes([]byte(res.YAML)); err != nil {
		t.Errorf("imported config does not parse: %v", err)
	}
}

// P2-4: rule-hits pruning.
func TestV01910RuleHitsPrune(t *testing.T) {
	now := time.Now()
	d := RuleHitsData{Rules: map[string]*RuleHitEntry{}}
	d.Rules["old"] = &RuleHitEntry{Total: 9, LastHit: now.Add(-40 * 24 * time.Hour).Unix()}
	for i := 0; i < ruleHitsMaxEntries+100; i++ {
		d.Rules[fmt.Sprint("k", i)] = &RuleHitEntry{Total: 1, LastHit: now.Add(-time.Duration(i) * time.Second).Unix()}
	}
	pruneRuleHits(&d, now)
	if _, ok := d.Rules["old"]; ok {
		t.Error("40-day-old entry kept")
	}
	if len(d.Rules) != ruleHitsMaxEntries {
		t.Errorf("entries = %d", len(d.Rules))
	}
	if _, ok := d.Rules["k0"]; !ok {
		t.Error("newest entry pruned")
	}
	if _, ok := d.Rules[fmt.Sprint("k", ruleHitsMaxEntries+50)]; ok {
		t.Error("oldest entry kept")
	}
}

// P2-5: writeFileAtomic uses a unique temp file (no fixed <file>.tmp left / shared).
func TestV01910WriteFileAtomicUnique(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rule-hits.json")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				_ = writeFileAtomic(p, []byte(fmt.Sprintf(`{"writer":%d,"pad":"%s"}`, i, strings.Repeat("x", 4096))))
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("corrupt file after concurrent writes: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
}

// P2-6: the core never runs at log-level debug (no unauthenticated /debug/pprof).
func TestV01910NoDebugLogLevel(t *testing.T) {
	o := defaultOverrides()
	o.LogLevel = "debug"
	raw := v01910Runtime(t, v01910Profile, o)
	if raw["log-level"] != "info" {
		t.Fatalf("log-level = %v", raw["log-level"])
	}
	raw = v01910Runtime(t, "log-level: debug\n"+v01910Profile, defaultOverrides())
	if raw["log-level"] == "debug" {
		t.Fatalf("profile log-level debug passed through")
	}
}

// P2-7: ring payload caps.
func TestV01910LogRingPayloadCaps(t *testing.T) {
	r := &logRing{cap: 4, max: dnsLogPayloadMax}
	r.add(logEntry{Payload: strings.Repeat("d", 1000)})
	g := &logRing{cap: 4}
	g.add(logEntry{Payload: strings.Repeat("g", 1000)})
	if n := len(r.buf[0].Payload); n > dnsLogPayloadMax+len("…") {
		t.Errorf("dns payload %d", n)
	}
	if n := len(g.buf[0].Payload); n > logPayloadMax+len("…") {
		t.Errorf("general payload %d", n)
	}
	if dnsLog.max != dnsLogPayloadMax || generalLog.cap != logRingCap {
		t.Error("ring config")
	}
}
