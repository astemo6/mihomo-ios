package libmihomo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
)

// B04: an empty controller secret is replaced by a random one and written back, never run as "".
func TestR7B04EmptySecretNeverReachesRuntime(t *testing.T) {
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"secret":"","controllerPort":9191,"mode":"rule"}`), 0o644)
	o := readOverrides(home)
	if len(o.Secret) < 16 {
		t.Fatalf("want a random secret, got %q", o.Secret)
	}
	b, _ := os.ReadFile(filepath.Join(home, "overrides.json"))
	raw := map[string]any{}
	_ = json.Unmarshal(b, &raw)
	if raw["secret"] != o.Secret || raw["mode"] != "rule" || raw["controllerPort"] != float64(9191) {
		t.Fatalf("secret must be written back, other keys kept: %s", b)
	}
	if again := readOverrides(home); again.Secret != o.Secret {
		t.Fatalf("second read must reuse the stored secret: %q vs %q", again.Secret, o.Secret)
	}
	rt, err := buildRuntime([]byte("proxies: []\nrules: [MATCH,DIRECT]\n"), o, 0)
	if err != nil || !strings.Contains(string(rt), "secret: "+o.Secret) {
		t.Fatalf("runtime secret: %v\n%s", err, rt)
	}
	// No overrides.json at all: a per-process random secret, nothing created.
	empty := t.TempDir()
	o2 := readOverrides(empty)
	if o2.Secret == "" || o2.Secret != readOverrides(empty).Secret {
		t.Fatalf("missing file: want a stable process secret, got %q", o2.Secret)
	}
	if _, err := os.Stat(filepath.Join(empty, "overrides.json")); err == nil {
		t.Fatal("must not create overrides.json")
	}
}

// B11: concurrent recorders keep a ring in seq order, and a reader following the cursor never skips a line.
func TestR7B11LogRingConcurrentOrder(t *testing.T) {
	gen, dns := &logRing{cap: logRingCap}, &logRing{cap: logRingCap}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	seen := map[string]bool{}
	var cursor uint64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			r := logHistoryFrom(gen, cursor, "")
			for _, e := range r.Logs {
				seen[e.Payload] = true
			}
			cursor = r.Seq
			select {
			case <-stop:
				r := logHistoryFrom(gen, cursor, "")
				for _, e := range r.Logs {
					seen[e.Payload] = true
				}
				return
			default:
			}
		}
	}()
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				recordLogEventTo(gen, dns, log.Event{LogLevel: log.INFO, Payload: fmt.Sprintf("w%d-%d", w, i)}, time.Now())
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-readerDone
	all, _ := gen.since(0)
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatalf("ring out of seq order at %d: %d after %d", i, all[i].Seq, all[i-1].Seq)
		}
	}
	if len(seen) != 1600 {
		t.Fatalf("cursor reader missed lines: saw %d of 1600", len(seen))
	}
}

// freeTCPPort (B12) returns a loopback port nothing listens on right now.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// copyRepoGeo (B12) puts the repository's bundled Geo/ files into home (as the app does before Start), so
// tests that parse geosite / geoip rules never download them. Skips when they are missing and MIHOMO_OFFLINE=1.
func copyRepoGeo(t *testing.T, home string) {
	t.Helper()
	for _, f := range []string{"GeoSite.dat", "geoip.metadb"} {
		b, err := os.ReadFile(filepath.Join("..", "Geo", f))
		if err != nil {
			if os.Getenv("MIHOMO_OFFLINE") == "1" {
				t.Skipf("offline and no bundled %s", f)
			}
			continue // online: mihomo downloads it as before
		}
		if err := os.WriteFile(filepath.Join(home, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// B12: the helpers above actually give a free port and the geo files.
func TestR7B12OfflineHelpers(t *testing.T) {
	p := freeTCPPort(t)
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatalf("port %d not free: %v", p, err)
	}
	l.Close()
	home := t.TempDir()
	copyRepoGeo(t, home)
	if fi, err := os.Stat(filepath.Join(home, "GeoSite.dat")); err != nil || fi.Size() == 0 {
		t.Fatalf("GeoSite.dat not copied: %v", err)
	}
}

// B31: ClassifyText on a 50 MB single line is bounded; big real inputs classify as before.
func TestR7B31ClassifyHugeTextBounded(t *testing.T) {
	huge := strings.Repeat("a", 50<<20)
	st := time.Now()
	if c := ClassifyText(huge); c != "" {
		t.Fatalf("junk classified as %q", c)
	}
	if d := time.Since(st); d > 2*time.Second {
		t.Fatalf("ClassifyText took %v on 50 MB", d)
	}
	// A big profile whose `proxies:` sits after the head still is a profile.
	big := "rules:\n" + strings.Repeat("  - DOMAIN,example.com,DIRECT\n", 20000) + "proxies:\n  - {name: a, type: ss}\n"
	if c := ClassifyText(big); c != "profile" {
		t.Fatalf("big profile: %q", c)
	}
	// Many share links (> head) are still nodes; so is a long single-line base64 subscription.
	var sb strings.Builder
	for i := 0; i < 8000; i++ {
		fmt.Fprintf(&sb, "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.%d:8388#n%d\n", i%250, i)
	}
	links := sb.String()
	if len(links) <= classifyHeadMax {
		t.Fatalf("fixture too small: %d", len(links))
	}
	if c := ClassifyText(links); c != "nodes" {
		t.Fatalf("share links: %q", c)
	}
	if c := ClassifyText(base64.StdEncoding.EncodeToString([]byte(links))); c != "nodes" {
		t.Fatalf("base64 subscription: %q", c)
	}
	// A Surge config head still decides.
	conf := "[General]\nloglevel = notify\n[Proxy]\nA = ss, 1.2.3.4, 1, encrypt-method=aes-128-gcm, password=x\n[Rule]\n" + strings.Repeat("DOMAIN,example.com,DIRECT\n", 20000)
	if c := ClassifyText(conf); c != "conf" {
		t.Fatalf("surge conf: %q", c)
	}
}

// B32: a node edit parses the edited runtime once; the original's re-check and a validate of the committed
// file reuse the cached result.
func TestR7B32ValidationCached(t *testing.T) {
	var calls int
	old := validateParse
	validateParse = func(rt []byte) error { calls++; return old(rt) }
	defer func() { validateParse = old }()
	validateMu.Lock()
	validateCache = map[[32]byte]validateEntry{}
	validateMu.Unlock()

	home := t.TempDir()
	p := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(p, []byte("proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,a\n"), 0o644)
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatal(e)
	}
	if e := ValidateConfigIn(home, p); e != "" || calls != 1 {
		t.Fatalf("second validate of the same runtime must be cached: calls=%d err=%q", calls, e)
	}
	// Edit a node: one parse for the edited runtime …
	if e := ProfileNodeUpsert(home, p, `{"name":"a","type":"ss","server":"5.6.7.8","port":1,"cipher":"aes-128-gcm","password":"x"}`, "a"); e != "" {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatalf("edit: want 1 more parse, calls=%d", calls)
	}
	// … and the app's validate of the committed file afterwards is free.
	if e := ValidateConfigIn(home, p); e != "" || calls != 2 {
		t.Fatalf("validate after commit must hit the cache: calls=%d err=%q", calls, e)
	}
	// A profile that already fails (rule → unknown policy): the edit is re-checked against the original, whose
	// result the earlier validate cached — only the edited runtime is parsed.
	p2 := filepath.Join(home, "p2.yaml")
	_ = os.WriteFile(p2, []byte("proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,nope\n"), 0o644)
	if e := ValidateConfigIn(home, p2); e == "" {
		t.Fatal("fixture must fail")
	}
	before := calls
	if e := ProfileNodeUpsert(home, p2, `{"name":"a","type":"ss","server":"5.6.7.8","port":1,"cipher":"aes-128-gcm","password":"x"}`, "a"); e != "" {
		t.Fatalf("edit of an already failing profile must be allowed: %s", e)
	}
	if calls-before != 1 {
		t.Fatalf("failing original: want only the edited runtime parsed, got %d parses", calls-before)
	}
}
