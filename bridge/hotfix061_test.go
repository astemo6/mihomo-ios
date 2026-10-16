package libmihomo

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

func TestUDPFallbackRuleLastAndParses(t *testing.T) {
	home := t.TempDir()
	prof := []byte("proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: 🐟 漏网之鱼, type: select, proxies: [A]}\nrules:\n  - DOMAIN-SUFFIX,cn,DIRECT\n  - MATCH,🐟 漏网之鱼\n")
	rt, err := buildRuntime(prof, readOverrides(home), 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	rules := asList(raw["rules"])
	if str(rules[len(rules)-1]) != UDPFallbackRule || str(rules[len(rules)-2]) != "MATCH,🐟 漏网之鱼" {
		t.Fatalf("rules %v", rules)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Rules[len(cfg.Rules)-1].RuleType().String(); got != "AND" {
		t.Fatalf("last rule %s", got)
	}
}

func TestMemoryLimitClampAndTestURL(t *testing.T) {
	home := t.TempDir()
	for in, want := range map[int]int{40: 26, 36: 26, 28: 28, 20: 20, 0: 26, 31: 26} {
		_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(fmt.Sprintf(`{"memoryLimitMB":%d}`, in)), 0o644)
		if got := readOverrides(home).MemoryLimitMB; got != want {
			t.Fatalf("limit %d → %d want %d", in, got, want)
		}
	}
	// Tolerant: bad URL / timeout / wrong JSON type fall back.
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"testURL":"ftp://x","testTimeoutMs":5}`), 0o644)
	o := readOverrides(home)
	if o.TestURL != defaultTestURL || o.TestTimeoutMs != 5000 {
		t.Fatalf("%+v", o)
	}
}

func TestOverrideHealthCheck(t *testing.T) {
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"testURL":"https://cp.cloudflare.com/generate_204","overrideHealthCheck":true}`), 0o644)
	prof := []byte(`proxies:
  - {name: A, type: socks5, server: 127.0.0.1, port: 1}
proxy-providers:
  p: {type: file, path: ./p.yaml, health-check: {enable: true, url: "http://www.gstatic.com/generate_204", interval: 300}}
proxy-groups:
  - {name: Auto, type: url-test, proxies: [A], url: "http://www.gstatic.com/generate_204", interval: 300}
  - {name: Sel, type: select, proxies: [A]}
rules:
  - MATCH,Sel
`)
	rt, _ := buildRuntime(prof, readOverrides(home), 0)
	s := string(rt)
	if strings.Contains(s, "http://www.gstatic.com") || strings.Count(s, "https://cp.cloudflare.com/generate_204") != 2 {
		t.Fatalf("%s", s)
	}
	// Off by default.
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{}`), 0o644)
	rt, _ = buildRuntime(prof, readOverrides(home), 0)
	if !strings.Contains(string(rt), "http://www.gstatic.com") {
		t.Fatal("override applied while off")
	}
}

// swiftEnc mirrors ControllerClient.enc: urlPathAllowed minus "/?#%".
func swiftEnc(s string) string {
	const ok = "-._~!$&'()*+,;=:@"
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(ok, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// The live 测速 path: controller /proxies/{name}/delay and /group/{name}/delay with emoji, spaces and
// slashes in names, the way the app encodes them.
func TestControllerDelayEmojiNames(t *testing.T) {
	var hits atomic.Int32
	// mihomo's DIRECT refuses loopback targets, so serve on a LAN address.
	ip := ""
	if addrs, _ := net.InterfaceAddrs(); true {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				ip = n.IP.String()
				break
			}
		}
	}
	if ip == "" {
		t.Skip("no non-loopback IPv4")
	}
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Skip(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(204)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19393
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: "🇭🇰 香港 01 [IPLC]", type: direct}
  - {name: "JP/东京 #2", type: direct}
proxy-groups:
  - {name: "🚀 节点选择", type: select, proxies: ["🇭🇰 香港 01 [IPLC]", "JP/东京 #2"]}
rules:
  - MATCH,🚀 节点选择
`), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:19393"+path, nil)
		req.Header.Set("Authorization", "Bearer s")
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ {
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	q := "?url=" + srv.URL + "/generate_204&timeout=5000"
	for _, n := range []string{"🇭🇰 香港 01 [IPLC]", "JP/东京 #2"} {
		code, body := get("/proxies/" + swiftEnc(n) + "/delay" + q)
		if code != 200 || !strings.Contains(body, `"delay"`) {
			t.Fatalf("%s: %d %s", n, code, body)
		}
	}
	code, body := get("/group/" + swiftEnc("🚀 节点选择") + "/delay" + q)
	if code != 200 || !strings.Contains(body, "IPLC") {
		t.Fatalf("group: %d %s", code, body)
	}
	if hits.Load() < 3 {
		t.Fatalf("test server hits %d", hits.Load())
	}
}

// Peak heap during startup with many classical rule providers, with and without startup pacing.
// MEMBENCH=1 go test -run TestStartupPeakHeap -v
func TestStartupPeakHeap(t *testing.T) {
	if os.Getenv("MEMBENCH") == "" {
		t.Skip("set MEMBENCH=1")
	}
	home := t.TempDir()
	var y strings.Builder
	y.WriteString("proxies:\n  - {name: A, type: direct}\nrule-providers:\n")
	for i := 0; i < 18; i++ {
		var r strings.Builder
		r.WriteString("payload:\n")
		for j := 0; j < 6000; j++ {
			fmt.Fprintf(&r, "  - DOMAIN-SUFFIX,host%d-%d.example.com\n", i, j)
		}
		_ = os.WriteFile(filepath.Join(home, fmt.Sprintf("r%d.yaml", i)), []byte(r.String()), 0o644)
		fmt.Fprintf(&y, "  r%d: {type: file, behavior: classical, path: ./r%d.yaml}\n", i, i)
	}
	y.WriteString("rules:\n")
	for i := 0; i < 18; i++ {
		fmt.Fprintf(&y, "  - RULE-SET,r%d,A\n", i)
	}
	y.WriteString("  - MATCH,A\n")
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(y.String()), 0o644)
	measure := func(pacing bool) uint64 {
		debug.FreeOSMemory()
		var peak atomic.Uint64
		stop := make(chan struct{})
		go func() {
			var ms runtime.MemStats
			for {
				select {
				case <-stop:
					return
				default:
				}
				runtime.ReadMemStats(&ms)
				// Resident heap estimate: what iOS counts as dirty memory for the Go heap.
				if v := ms.HeapSys - ms.HeapReleased; v > peak.Load() {
					peak.Store(v)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
		_ = pacing
		if err := safeApply(home, prof, 0); err != nil {
			t.Fatal(err)
		}
		close(stop)
		Stop()
		return peak.Load()
	}
	// One mode per process so the runs don't share a heap. MEMBENCH=old: v0.6.0 settings (GOMEMLIMIT
	// 40 MB, GOGC 100, no startup pacing); MEMBENCH=new: v0.6.1 (26 MB, GOGC 75, pacing).
	old := os.Getenv("MEMBENCH") == "old"
	if old {
		testOldPacing, disablePacing = true, true
	}
	pk := measure(!old)
	t.Logf("peak resident Go heap during apply (%s): %.1f MB", os.Getenv("MEMBENCH"), float64(pk)/(1<<20))
}
