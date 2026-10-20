package libmihomo

// Review 6 · lane 1 (Go bridge core) — one test per fix / optimisation (work/review6/go-core.md).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

// P1-1: a Surge managed config (#!MANAGED-CONFIG first line) is a config again; BoxJS-style modules with a
// [General] section stay modules (v0.19.9).
func TestV01911ClassifyManagedConf(t *testing.T) {
	body := "[General]\nloglevel = notify\n\n[Proxy]\nA = ss, 192.0.2.1, 443, encrypt-method=aes-128-gcm, password=p\n\n[Proxy Group]\nP = select, A\n\n[Rule]\nFINAL,P\n"
	cases := map[string]string{
		"#!MANAGED-CONFIG https://example.com/sub?token=x interval=86400 strict=false\n\n" + body: "conf",
		"#!managed-config https://example.com/s interval=3600\n[General]\nloglevel = notify\n":     "conf",
		"#!name=Some Profile\n" + body: "conf", // [Proxy] / [Proxy Group] only exist in configs
		body:                           "conf",
		"#!name=BoxJS\n#!desc=x\n\n[General]\nforce-http-engine-hosts = %APPEND% boxjs.com\n\n[Script]\nBoxJS = type=http-request,pattern=^https?://boxjs.com,script-path=https://example.com/box.js\n\n[MITM]\nhostname = %APPEND% boxjs.com\n": "module:surge",
		"#!name=Plain\n[URL Rewrite]\n^https?://ad.example.com - reject\n": "module:surge",
	}
	for in, want := range cases {
		if got := ClassifyText(in); got != want {
			t.Errorf("%q…: got %q want %q", strings.SplitN(in, "\n", 2)[0], got, want)
		}
	}
}

// P2-2: ProviderStore / setResState / own-policy parts use unique temp files (no fixed "<file>.tmp" left or shared).
func TestV01911AtomicWriters(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, "rules", "r.yaml")
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	// a stale fixed-name temp file from an older build must neither be used nor block the write
	_ = os.WriteFile(cache+".tmp", []byte("garbage"), 0o644)
	if r := ProviderStore(home, "rule", cache, "", []byte("payload:\n  - DOMAIN,example.com\n")); strings.Contains(r, `"error":"`) && !strings.Contains(r, `"error":""`) {
		t.Fatalf("ProviderStore: %s", r)
	}
	b, _ := os.ReadFile(cache)
	if !strings.Contains(string(b), "example.com") {
		t.Fatalf("cache: %q", b)
	}
	if g, _ := os.ReadFile(cache + ".tmp"); string(g) != "garbage" {
		t.Fatalf("fixed .tmp was reused: %q", g)
	}
	setResState(home, "k", "")
	if _, err := os.Stat(resStatePath(home)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(resStatePath(home) + ".tmp"); err == nil {
		t.Fatal("setResState still writes a fixed .tmp")
	}
	n, err := splitOwnPolicyList(cache, []byte("DOMAIN,a.example.com,DIRECT\nDOMAIN,b.example.com,PROXY\n"))
	if err != nil || n == 0 {
		t.Fatalf("own policy: %d %v", n, err)
	}
	for _, p := range readOwnPolicyParts(cache) {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(cache), p.File)); err != nil || len(b) == 0 {
			t.Fatalf("part %s: %v", p.File, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(cache))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") && e.Name() != "r.yaml.tmp" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// P2-3: LiveStatus' node starts from the first visible group of the runtime order, not GLOBAL's members.
func TestV01911LiveNodeRuntimeOrder(t *testing.T) {
	prof := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: B, type: socks5, server: 127.0.0.1, port: 2}\n" +
		"proxy-groups:\n  - {name: H, type: select, hidden: true, proxies: [B]}\n  - {name: Main, type: select, proxies: [A, B]}\n  - {name: GLOBAL, type: select, proxies: [B]}\nrules:\n  - MATCH,Main\n"
	rt, err := buildRuntime([]byte(prof), defaultOverrides(), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	old := tunnel.Mode()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.SetMode(tunnel.Rule)
	defer tunnel.SetMode(old)
	prev := liveGroupOrder.Load()
	defer func() {
		if prev != nil {
			liveGroupOrder.Store(prev)
		} else {
			liveGroupOrder.Store([]string(nil))
		}
	}()
	liveGroupOrder.Store([]string{"H", "Main", "GLOBAL"})
	if n := liveNode(); n != "A" {
		t.Fatalf("liveNode = %q, want A (Main's selection; GLOBAL is user-defined with [B])", n)
	}
	liveGroupOrder.Store([]string(nil)) // no order yet: old GLOBAL walk
	if n := liveNode(); n == "" {
		t.Fatal("fallback walk returned nothing")
	}
}

// P2-4: user regexes (rename, include, group filter) are bounded instead of regexp2's "forever".
func TestV01911UserRegexTimeout(t *testing.T) {
	c := compileSub(SubRules{Renames: []RenameRule{{Pattern: "(a+)+$", Replace: "x"}}})
	if len(c.renames) != 1 || c.renames[0].MatchTimeout != userRegexTimeout {
		t.Fatalf("rename timeout: %+v", c.renames)
	}
	m, _ := newMatcher("(a+)+$", true)
	if m.re.MatchTimeout != userRegexTimeout {
		t.Fatal("include timeout")
	}
	rs, err := compileGroupRegs("(a+)+$`HK")
	if err != nil || len(rs) != 2 || rs[0].MatchTimeout != userRegexTimeout {
		t.Fatalf("group filter timeout: %v", err)
	}
	if userRegexTimeout > 5*time.Second {
		t.Fatal("timeout too long for the tunnel start budget")
	}
}

// P2-5: rule-set URLs are logged without tokens / queries.
func TestV01911RuleSetLogURL(t *testing.T) {
	got := logURL("https://user:pw@rules.example.com/list/Ab3dEf9hIjK2mNoP7qRs/reject.list?token=s3cr3t")
	for _, bad := range []string{"pw", "s3cr3t", "Ab3dEf9hIjK2mNoP7qRs"} {
		if strings.Contains(got, bad) {
			t.Fatalf("leak %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "rules.example.com") || !strings.Contains(got, "reject.list") {
		t.Fatalf("lost the readable part: %q", got)
	}
}

// P2-6: $httpAPI policy switches are persisted to the cache file (a Reload restores them).
func TestV01911HTTPAPISelectPersisted(t *testing.T) {
	prof := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: PSEL, type: select, proxies: [A, DIRECT]}\nrules:\n  - MATCH,PSEL\n"
	rt, err := buildRuntime([]byte(prof), defaultOverrides(), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	// the cache file opens once per process under the home dir of that moment (a Start in another test may have
	// opened it already; either way SelectedMap must show the switch)
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	defer C.SetHomeDir(oldHome)
	was := profile.StoreSelected.Load()
	profile.StoreSelected.Store(true)
	defer profile.StoreSelected.Store(was)
	if _, err := httpAPI("POST", "/v1/policy_groups/select", map[string]any{"group_name": "PSEL", "policy": "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	c := cachefile.Cache()
	if c == nil || c.DB == nil {
		t.Skip("no cache file in this environment")
	}
	if got := c.SelectedMap()["PSEL"]; got != "DIRECT" {
		t.Fatalf("cache file selection = %q", got)
	}
}

// OPT-1: a YAML subscription passes through /nodes/convert without a copy.
func TestV01911ConvertNodesNoCopy(t *testing.T) {
	data := []byte("\ufeffproxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n")
	out, n, err := convertNodesText(data)
	if err != nil || n != -1 || &out[0] != &data[0] {
		t.Fatalf("passthrough copied or failed: n=%d err=%v", n, err)
	}
	out, n, err = convertNodesText([]byte("trojan://pw@127.0.0.1:443#T\n"))
	if err != nil || n != 1 || !strings.Contains(string(out), "trojan") {
		t.Fatalf("share-link path: %d %v %q", n, err, out)
	}
}

// OPT-2: the redactor reuses its replacer until a new secret is remembered, with the same result.
func TestV01911RedactorReplacerCache(t *testing.T) {
	r := newRedactor()
	r.remember("supersecret1")
	if got := r.text("x supersecret1 y"); strings.Contains(got, "supersecret1") {
		t.Fatal(got)
	}
	p := r.repl
	_ = r.text("again")
	if r.repl != p || p == nil {
		t.Fatal("replacer rebuilt without a new secret")
	}
	r.remember("supersecret1") // known: no rebuild
	if r.repl != p {
		t.Fatal("rebuilt on a known secret")
	}
	r.remember("another-secret-2")
	if got := r.text("supersecret1 another-secret-2"); strings.Contains(got, "secret") && !strings.Contains(got, "<redacted>") {
		t.Fatal(got)
	}
	if got := r.text("another-secret-2"); strings.Contains(got, "another-secret-2") {
		t.Fatal("new secret not scrubbed:", got)
	}
}
