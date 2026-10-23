package libmihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// v0.19.22 开关类设置热应用 (hotapply.go): for every change a hot path takes, the core state after ReloadHot equals the
// state after a full Reload of the same inputs, and runtime.yaml on disk is the same file the full reload writes.

const hotProfileHead = `proxies:
  - {name: a, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [DIRECT, a]}
`

func hotProfile(sets []string, extraRules ...string) string {
	var b strings.Builder
	b.WriteString(hotProfileHead)
	if len(sets) > 0 {
		b.WriteString("rule-providers:\n")
		for _, s := range sets {
			fmt.Fprintf(&b, "  %s: {type: file, behavior: domain, path: ./rules/%s.yaml}\n", s, s)
		}
	}
	b.WriteString("rules:\n")
	for _, r := range extraRules {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	for _, s := range sets {
		fmt.Fprintf(&b, "  - RULE-SET,%s,Proxy\n", s)
	}
	b.WriteString("  - MATCH,DIRECT\n")
	return b.String()
}

type hotState struct {
	Rules     []string
	Providers []string
	Mode      string
	Level     string
	Engine    string
	Runtime   string
}

func hotSnapshot(t *testing.T, home string) hotState {
	t.Helper()
	var s hotState
	for _, r := range tunnel.Rules() {
		s.Rules = append(s.Rules, fmt.Sprintf("%s,%s,%s", r.RuleType().String(), r.Payload(), r.Adapter()))
	}
	for name, rp := range tunnel.RuleProviders() {
		s.Providers = append(s.Providers, fmt.Sprintf("%s:%d", name, rp.Count()))
	}
	sort.Strings(s.Providers)
	s.Mode = tunnel.Mode().String()
	s.Level = log.Level().String()
	engMu.Lock()
	s.Engine = eng.Summary()
	engMu.Unlock()
	b, err := os.ReadFile(filepath.Join(home, "runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s.Runtime = string(b)
	return s
}

func (s hotState) diff(o hotState) string {
	var out []string
	if strings.Join(s.Rules, "\n") != strings.Join(o.Rules, "\n") {
		out = append(out, fmt.Sprintf("rules:\n  %v\n  %v", s.Rules, o.Rules))
	}
	if strings.Join(s.Providers, ",") != strings.Join(o.Providers, ",") {
		out = append(out, fmt.Sprintf("providers: %v vs %v", s.Providers, o.Providers))
	}
	if s.Mode != o.Mode {
		out = append(out, "mode: "+s.Mode+" vs "+o.Mode)
	}
	if s.Level != o.Level {
		out = append(out, "log level: "+s.Level+" vs "+o.Level)
	}
	if s.Engine != o.Engine {
		out = append(out, "engine: "+s.Engine+" vs "+o.Engine)
	}
	if s.Runtime != o.Runtime {
		out = append(out, "runtime.yaml differs")
	}
	return strings.Join(out, "\n")
}

type hotEnv struct {
	t       *testing.T
	home    string
	prof    string
	logPath string
	ov      Overrides
	logOff  int
}

func (e *hotEnv) writeProfile(body string) {
	if err := os.WriteFile(e.prof, []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *hotEnv) writeOverrides() {
	b, _ := json.Marshal(e.ov)
	_ = os.WriteFile(filepath.Join(e.home, "overrides.json"), b, 0o644)
}

func (e *hotEnv) writeEngine(c *mitm.Config) {
	dir := mitm.EngineDir(e.home)
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.Marshal(c)
	_ = os.WriteFile(filepath.Join(dir, "engine.json"), b, 0o644)
}

// newLog returns the startup log written since the last call.
func (e *hotEnv) newLog() string {
	b, _ := os.ReadFile(e.logPath)
	s := string(b)
	if e.logOff > len(s) {
		e.logOff = 0
	}
	out := s[e.logOff:]
	e.logOff = len(s)
	return out
}

// hot runs ReloadHot, checks the log says hot-apply with want, then a full Reload of the same inputs, and compares.
func (e *hotEnv) hot(name, want string) {
	e.t.Helper()
	e.newLog()
	if err := ReloadHot(e.prof); err != nil {
		e.t.Fatalf("%s: ReloadHot: %v", name, err)
	}
	l := e.newLog()
	if !strings.Contains(l, "hot-apply") || !strings.Contains(l, want) {
		e.t.Fatalf("%s: want hot-apply %q in the log, got:\n%s", name, want, l)
	}
	if strings.Contains(l, "reload memory") {
		e.t.Fatalf("%s: hot path ran the full reload:\n%s", name, l)
	}
	h := hotSnapshot(e.t, e.home)
	if err := Reload(e.prof); err != nil {
		e.t.Fatalf("%s: full Reload: %v", name, err)
	}
	if l := e.newLog(); !strings.Contains(l, "reload memory") {
		e.t.Fatalf("%s: full Reload did not run:\n%s", name, l)
	}
	f := hotSnapshot(e.t, e.home)
	if d := h.diff(f); d != "" {
		e.t.Fatalf("%s: state after hot-apply != after full reload:\n%s", name, d)
	}
}

// full runs ReloadHot for a change the hot path must leave to the full reload.
func (e *hotEnv) full(name, why string) {
	e.t.Helper()
	e.newLog()
	if err := ReloadHot(e.prof); err != nil {
		e.t.Fatalf("%s: ReloadHot: %v", name, err)
	}
	l := e.newLog()
	if !strings.Contains(l, "reload ("+why) || !strings.Contains(l, "reload memory") {
		e.t.Fatalf("%s: want full reload (%s), got:\n%s", name, why, l)
	}
	if strings.Contains(l, "hot-apply") {
		e.t.Fatalf("%s: hot-applied a change that needs the full reload:\n%s", name, l)
	}
}

func TestV01922HotApply(t *testing.T) {
	home := t.TempDir()
	e := &hotEnv{t: t, home: home, prof: filepath.Join(home, "profiles", "hot.yaml"), logPath: filepath.Join(home, "startup.log")}
	_ = os.MkdirAll(filepath.Join(home, "profiles"), 0o755)
	_ = os.MkdirAll(filepath.Join(home, "rules"), 0o755)
	for i, s := range []string{"one", "two", "three"} {
		var b strings.Builder
		b.WriteString("payload:\n")
		for j := 0; j <= i; j++ {
			fmt.Fprintf(&b, "  - '+.%s%d.example.org'\n", s, j)
		}
		_ = os.WriteFile(filepath.Join(home, "rules", s+".yaml"), []byte(b.String()), 0o644)
	}
	e.ov = defaultOverrides()
	e.ov.ControllerPort = 19631
	e.ov.Secret = "s"
	e.ov.DNSMode = "redir-host"
	e.writeOverrides()
	SetStageLog(e.logPath, 0)
	defer SetStageLog("", 0)
	e.writeProfile(hotProfile([]string{"one", "two"}, "DOMAIN-SUFFIX,a.test,Proxy"))
	if err := Start(home, e.prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	// Let the Start apply finish loading (ReloadHot falls back to the full reload while it runs).
	for i := 0; i < 100 && applyInFlight.Load() > 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}

	// Nothing changed: still hot (a switch flipped back and forth inside the coalescing window).
	e.hot("unchanged", "engine")

	// Custom rule added / rule order: rules only.
	e.writeProfile(hotProfile([]string{"one", "two"}, "DOMAIN-SUFFIX,b.test,DIRECT", "DOMAIN-SUFFIX,a.test,Proxy"))
	e.hot("rules", "rules (")

	// Rule set switched off: its provider and its RULE-SET line go.
	e.writeProfile(hotProfile([]string{"one"}, "DOMAIN-SUFFIX,b.test,DIRECT", "DOMAIN-SUFFIX,a.test,Proxy"))
	e.hot("rule-set off", "−1")
	if _, ok := tunnel.RuleProviders()["two"]; ok {
		t.Fatal("rule set two still live after it was switched off")
	}

	// Rule sets switched on: parsed and loaded in place.
	e.writeProfile(hotProfile([]string{"one", "two", "three"}, "DOMAIN-SUFFIX,a.test,Proxy"))
	e.hot("rule-sets on", "+2")
	if rp := tunnel.RuleProviders()["three"]; rp == nil || rp.Count() != 3 {
		t.Fatalf("rule set three not loaded: %v", rp)
	}

	// A rule set's settings changed (another file): rebuilt in place.
	_ = os.WriteFile(filepath.Join(home, "rules", "three-b.yaml"), []byte("payload:\n  - '+.x.example.org'\n"), 0o644)
	e.writeProfile(strings.Replace(hotProfile([]string{"one", "two", "three"}, "DOMAIN-SUFFIX,a.test,Proxy"), "./rules/three.yaml", "./rules/three-b.yaml", 1))
	e.hot("rule-set changed", "~1")

	// 出站模式 and 日志级别 (overrides).
	e.ov.Mode = "global"
	e.ov.LogLevel = "warning"
	e.writeOverrides()
	e.hot("mode + log level", "mode global")
	if tunnel.Mode().String() != "global" || log.Level() != log.WARNING {
		t.Fatalf("mode %s / level %s not applied", tunnel.Mode(), log.Level())
	}
	e.ov.Mode = ""
	e.ov.LogLevel = "info"
	e.writeOverrides()
	e.hot("mode back", "mode rule")

	// 直连时丢弃 STUN: a parse option, not a runtime.yaml key.
	e.ov.StunDropDirect = true
	e.writeOverrides()
	e.hot("stun drop", "stun/webrtc")
	if r := tunnel.Rules(); len(r) == 0 || !isSTUNDropRule(r[0]) {
		t.Fatal("STUN drop rule not first after hot-apply")
	}
	e.ov.StunDropDirect = false
	e.writeOverrides()
	e.hot("stun drop off", "stun/webrtc")

	// 阻止 QUIC (连接方式): a rule.
	e.ov.BlockQUIC = "always"
	e.writeOverrides()
	e.hot("block quic", "rules (")

	// Rewrite engine: the first rewrite rule adds the engine outbound (proxies change) → full; switching one of two
	// rules after that changes only the engine sets → hot.
	ec := &mitm.Config{Enabled: true, Rules: []mitm.Item{
		{ID: "1", Enabled: true, Line: `^https?://ad\.example\.com/x url reject`},
		{ID: "2", Enabled: true, Line: `^https?://ad\.example\.com/y url reject-200`},
	}}
	e.writeEngine(ec)
	e.full("engine on", "proxies changed")
	ec.Rules[1].Enabled = false
	e.writeEngine(ec)
	e.hot("rewrite off", "engine (rewrite / script / MitM sets)")
	engMu.Lock()
	sum := eng.Summary()
	engMu.Unlock()
	if strings.Contains(sum, "ad\\.example\\.com/y") || !strings.Contains(sum, "ad\\.example\\.com/x") {
		t.Fatalf("engine rules after hot-apply: %s", sum)
	}
	// MitM hostnames: the inline host set is rebuilt in place.
	ec.MitM = true
	ec.Hostnames = []string{"ad.example.com"}
	e.writeEngine(ec)
	e.hot("mitm on", "+1") // the first host adds the inline host set + steering rules (the engine outbound is there)
	ec.Hostnames = []string{"ad.example.com", "b.example.com"}
	e.writeEngine(ec)
	e.hot("mitm host added", "~1")

	// Not hot: DNS (and with it IPv6 / sniffer / tun-derived settings) and proxies.
	e.ov.DNSMode = "fake-ip"
	e.writeOverrides()
	e.full("dns mode", "")
	e.writeProfile(strings.Replace(hotProfile([]string{"one"}), "port: 1,", "port: 2,", 1))
	e.full("node edit", "proxies changed")

	// 安全模式 and another profile never go hot.
	other := filepath.Join(home, "profiles", "other.yaml")
	_ = os.WriteFile(other, []byte(hotProfile(nil)), 0o644)
	e.newLog()
	if err := ReloadHot(other); err != nil {
		t.Fatal(err)
	}
	if l := e.newLog(); !strings.Contains(l, "reload (another profile)") {
		t.Fatalf("profile switch: %s", l)
	}

	// runtime.yaml edited outside an apply: not the live one → full.
	_ = os.WriteFile(filepath.Join(home, "runtime.yaml"), []byte("# stale\n"), 0o644)
	e.newLog()
	if err := ReloadHot(other); err != nil {
		t.Fatal(err)
	}
	if l := e.newLog(); !strings.Contains(l, "reload (runtime.yaml on disk is not the live one)") {
		t.Fatalf("stale runtime.yaml: %s", l)
	}

	Stop()
	if err := ReloadHot(other); err == nil {
		t.Fatal("ReloadHot after Stop should be refused")
	}
}
