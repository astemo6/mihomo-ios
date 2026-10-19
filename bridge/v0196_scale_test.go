package libmihomo

import (
	"encoding/base64"
	"reflect"

	"fmt"
	"go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v0.19.6 (review 7): stress / scale tests. Synthetic inputs only (placeholder servers / passwords).
// Each measured call reports wall time and the peak heap seen while it ran; bounds are generous
// (CI machines vary) but catch quadratic loops and runaway memory against the NE's ~50 MB budget.

type scaleResult struct {
	d        time.Duration
	peakHeap uint64 // peak HeapAlloc above the baseline, bytes
	alloc    uint64 // total bytes allocated
}

func scaleMeasure(f func()) scaleResult {
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base, baseTotal := ms.HeapAlloc, ms.TotalAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()
	t0 := time.Now()
	f()
	d := time.Since(t0)
	close(stop)
	wg.Wait()
	runtime.ReadMemStats(&ms)
	if ms.HeapAlloc > peak.Load() {
		peak.Store(ms.HeapAlloc)
	}
	p := peak.Load()
	if p < base {
		p = base
	}
	return scaleResult{d: d, peakHeap: p - base, alloc: ms.TotalAlloc - baseTotal}
}

func (r scaleResult) String() string {
	return fmt.Sprintf("%s, peak heap +%.1f MB, alloc %.1f MB", r.d.Round(time.Millisecond), float64(r.peakHeap)/(1<<20), float64(r.alloc)/(1<<20))
}

func scaleMB(n uint64) uint64 { return n << 20 }

// ---------- generators ----------

func genYAMLProfile(nodes, rules, groups, providers int) []byte {
	var b strings.Builder
	b.Grow(nodes*120 + rules*48)
	b.WriteString("mixed-port: 7890\nmode: rule\nlog-level: info\nproxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "  - {name: \"HK %05d\", type: ss, server: 192.0.2.%d, port: %d, cipher: aes-128-gcm, password: pw%d, udp: true}\n", i, i%250+1, 10000+i%50000, i)
	}
	b.WriteString("proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "      - \"HK %05d\"\n", i)
	}
	b.WriteString("  - {name: Auto, type: url-test, url: 'http://www.gstatic.com/generate_204', interval: 300, include-all-proxies: true}\n")
	for g := 0; g < groups; g++ {
		fmt.Fprintf(&b, "  - {name: G%03d, type: select, proxies: [Proxy, Auto, DIRECT]}\n", g)
	}
	if providers > 0 {
		b.WriteString("rule-providers:\n")
		for p := 0; p < providers; p++ {
			fmt.Fprintf(&b, "  rp%04d: {type: file, behavior: domain, path: ./rules/rp%04d.yaml}\n", p, p)
		}
	}
	b.WriteString("rules:\n")
	for p := 0; p < providers; p++ {
		fmt.Fprintf(&b, "  - RULE-SET,rp%04d,Proxy\n", p)
	}
	for i := 0; i < rules; i++ {
		tgt := "Proxy"
		if groups > 0 {
			tgt = fmt.Sprintf("G%03d", i%groups)
		}
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,d%06d.example.com,%s\n", i, tgt)
		case 1:
			fmt.Fprintf(&b, "  - DOMAIN,host%06d.example.net,DIRECT\n", i)
		case 2:
			fmt.Fprintf(&b, "  - DOMAIN-KEYWORD,kw%06d,%s\n", i, tgt)
		default:
			fmt.Fprintf(&b, "  - IP-CIDR,10.%d.%d.0/24,%s,no-resolve\n", (i/256)%256, i%256, tgt)
		}
	}
	b.WriteString("  - MATCH,Proxy\n")
	return []byte(b.String())
}

func genSSLinks(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		ui := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("aes-128-gcm:pw%d", i)))
		fmt.Fprintf(&b, "ss://%s@192.0.2.%d:%d#%s\n", ui, i%250+1, 10000+i%50000, fmt.Sprintf("JP%%20%05d", i))
		if i%5 == 1 {
			fmt.Fprintf(&b, "trojan://pw%d@198.51.100.%d:443?sni=t%d.example.com#US%%20%05d\n", i, i%250+1, i, i)
		}
	}
	return b.String()
}

func genSurgeConf(nodes, rules int) string {
	var b strings.Builder
	b.WriteString("[General]\nloglevel = notify\ndns-server = 223.5.5.5\n\n[Proxy]\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "N%05d = ss, 192.0.2.%d, %d, encrypt-method=aes-128-gcm, password=pw%d, udp-relay=true\n", i, i%250+1, 10000+i, i)
	}
	b.WriteString("\n[Proxy Group]\nProxy = select, ")
	for i := 0; i < nodes; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "N%05d", i)
	}
	b.WriteString("\nAuto = url-test, policy-regex-filter=N0, url=http://www.gstatic.com/generate_204, interval=600\n\n[Rule]\n")
	for i := 0; i < rules; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "DOMAIN-SUFFIX,d%06d.example.com,Proxy\n", i)
		case 1:
			fmt.Fprintf(&b, "DOMAIN-KEYWORD,k%06d,DIRECT\n", i)
		default:
			fmt.Fprintf(&b, "IP-CIDR,10.%d.%d.0/24,Proxy,no-resolve\n", (i/256)%256, i%256)
		}
	}
	b.WriteString("FINAL,Proxy\n")
	return b.String()
}

func genQXConf(nodes, rules int) string {
	var b strings.Builder
	b.WriteString("[general]\nnetwork_check_url=http://www.gstatic.com/generate_204\n\n[server_local]\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "shadowsocks=192.0.2.%d:%d, method=aes-128-gcm, password=pw%d, udp-relay=true, tag=Q%05d\n", i%250+1, 10000+i, i, i)
	}
	b.WriteString("\n[policy]\nstatic=Proxy, ")
	for i := 0; i < nodes; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "Q%05d", i)
	}
	b.WriteString("\n\n[filter_local]\n")
	for i := 0; i < rules; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "host-suffix, d%06d.example.com, Proxy\n", i)
		case 1:
			fmt.Fprintf(&b, "host-keyword, k%06d, direct\n", i)
		default:
			fmt.Fprintf(&b, "ip-cidr, 10.%d.%d.0/24, Proxy\n", (i/256)%256, i%256)
		}
	}
	b.WriteString("final, Proxy\n")
	return b.String()
}

func writeScaleProfile(t testing.TB, home string, body []byte) string {
	t.Helper()
	dir := filepath.Join(home, "profiles")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------- exploratory numbers (always logged) ----------

func TestV0196ScaleExplore(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	home := v0194Home(t)
	prof := genYAMLProfile(5000, 20000, 40, 0)
	path := writeScaleProfile(t, home, prof)
	t.Logf("profile %d KB", len(prof)>>10)
	steps := []struct {
		name string
		f    func()
	}{
		{"InspectProfile", func() { _ = InspectProfile(home, path) }},
		{"buildRuntime", func() { _, _ = buildRuntime(prof, overridesFor(home, path), 0) }},
		{"ValidateConfigIn", func() {
			if s := ValidateConfigIn(home, path); s != "" {
				t.Errorf("validate: %.300s", s)
			}
		}},
		{"ProfileGroups", func() { _ = ProfileGroups(home, path) }},
		{"CheckCustomRules", func() { _ = CheckCustomRules(home, path) }},
		{"GroupSpecs", func() { _ = GroupSpecs(home, path) }},
		{"ProfileGroupNames", func() { _ = ProfileGroupNames(path) }},
		{"ProfileNodeGet", func() { _ = ProfileNodeGet(path, "HK 04999") }},
		{"NodeSummary", func() { _ = NodeSummary(home, path, "HK 04999") }},
		{"ProfileCheck", func() { _ = ProfileCheck(home, path, string(prof)) }},
		{"ScriptInput", func() { _, _ = ScriptInput(path) }},
		{"ProviderPlan", func() { _ = ProviderPlan(home, path) }},
		{"ProfileNodeUpsert", func() {
			_ = ProfileNodeUpsert(home, path, `{"name":"HK 00007","type":"ss","server":"192.0.2.9","port":443,"cipher":"aes-128-gcm","password":"x"}`, "HK 00007")
		}},
		{"ProfileNodeDelete", func() { _ = ProfileNodeDelete(home, path, "HK 00008") }},
		{"ProfileRenameRefs", func() { _ = ProfileRenameRefs(home, path, "HK 00009", "HK 00009b") }},
	}
	for _, s := range steps {
		r := scaleMeasure(s.f)
		t.Logf("%-18s %s", s.name, r)
	}
	links := genSSLinks(5000)
	for _, s := range []struct {
		name string
		f    func()
	}{
		{"ParseNodes 6k links", func() { _ = ParseNodes(links) }},
		{"ParseNodes b64 6k", func() { _ = ParseNodes(base64.StdEncoding.EncodeToString([]byte(links))) }},
		{"ConvertShareLinks 6k", func() { _ = ConvertShareLinks(links) }},
		{"DetectNodeFormat 6k", func() { _ = DetectNodeFormat(links) }},
		{"ClassifyText surge", func() { _ = ClassifyText(genSurgeConf(5000, 20000)) }},
		{"ImportConf surge 5k/20k", func() { _ = ImportConf(genSurgeConf(5000, 20000)) }},
		{"ImportConf qx 5k/20k", func() { _ = ImportConf(genQXConf(5000, 20000)) }},
	} {
		r := scaleMeasure(s.f)
		t.Logf("%-24s %s", s.name, r)
	}
}

func genRuleList(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0:
			fmt.Fprintf(&b, "DOMAIN-SUFFIX,d%07d.example.com\n", i)
		case 1:
			fmt.Fprintf(&b, "DOMAIN,h%07d.example.org\n", i)
		default:
			fmt.Fprintf(&b, "IP-CIDR,10.%d.%d.0/24,no-resolve\n", (i/256)%256, i%256)
		}
	}
	return b.String()
}

// Bodies the NE converts itself (/rules/convert, /nodes/convert cap downloads at 16 MB) and the
// app-side converters (50 MB, one huge line).
func TestV0196ScaleExploreBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	list16 := genRuleList(16 << 20 / 32)
	t.Logf("rule list %d MB", len(list16)>>20)
	oneLine := strings.Repeat("A", 50<<20)
	links := genSSLinks(150000)
	t.Logf("links body %d MB", len(links)>>20)
	b64 := base64.StdEncoding.EncodeToString([]byte(links))
	for _, s := range []struct {
		name string
		f    func()
	}{
		{"convertListText 16MB classical", func() { _, _, _ = convertListText(strings.NewReader(list16), "") }},
		{"convertListText 16MB one line", func() { _, _, _ = convertListText(strings.NewReader(oneLine[:16<<20]), "") }},
		{"convertNodesText 16MB b64", func() { _, _, _ = convertNodesText([]byte(b64)) }},
		{"ParseNodes 50MB one line", func() { _ = ParseNodes(oneLine) }},
		{"ConvertShareLinks 50MB one line", func() { _ = ConvertShareLinks(oneLine) }},
		{"DetectNodeFormat 50MB one line", func() { _ = DetectNodeFormat(oneLine) }},
		{"ClassifyText 50MB one line", func() { _ = ClassifyText(oneLine) }},
		{"ImportConf 50MB one line", func() { _ = ImportConf(oneLine) }},
		{"ParseNodes 180k links", func() { _ = ParseNodes(links) }},
	} {
		r := scaleMeasure(s.f)
		t.Logf("%-32s %s", s.name, r)
	}
}

// neLimit runs f under a GOMEMLIMIT like the extension's (36 MB = 3/4 of the ~48 MB it starts with), so
// the peak heap measured is close to the live set rather than uncollected garbage.
func neLimit(f func()) scaleResult {
	old := debug.SetMemoryLimit(36 << 20)
	defer debug.SetMemoryLimit(old)
	return scaleMeasure(f)
}

// A large profile's runtime is written as JSON (YAML flow style): same content as the YAML encoding, the
// core accepts it, nameserver-policy order kept, and building it stays within the extension's budget.
func TestV0196LargeRuntimeIsJSONAndEquivalent(t *testing.T) {
	home := v0194Home(t)
	prof := genYAMLProfile(5000, 20000, 40, 0)
	prof = append(prof, []byte("dns:\n  nameserver-policy:\n    '+.zzz.example': [223.5.5.5]\n    'geosite:cn': [119.29.29.29]\n    '+.aaa.example': [1.1.1.1]\n")...)
	path := writeScaleProfile(t, home, prof)
	o := overridesFor(home, path)
	var rt []byte
	var err error
	r := neLimit(func() { rt, err = buildRuntime(prof, o, 0) })
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("buildRuntime 5k nodes / 20k rules: %s, %d KB", r, len(rt)>>10)
	if rt[0] != '{' {
		t.Fatalf("large runtime not written as JSON: %.80s", rt)
	}
	if r.peakHeap > scaleMB(30) {
		t.Errorf("buildRuntime peak heap %.1f MB (yaml.Marshal was ~58 MB)", float64(r.peakHeap)/(1<<20))
	}
	// Same content as the YAML encoding.
	raw := map[string]any{}
	if err := yaml.Unmarshal(prof, &raw); err != nil {
		t.Fatal(err)
	}
	var fromJSON, fromYAML map[string]any
	if err := yaml.Unmarshal(rt, &fromJSON); err != nil {
		t.Fatalf("JSON runtime is not YAML-parseable: %v", err)
	}
	yb, _ := marshalConfig(mustRuntimeMap(t, prof, o), false)
	if err := yaml.Unmarshal(yb, &fromYAML); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Fatal("JSON and YAML runtime differ")
	}
	// nameserver-policy order as in the profile.
	var doc struct {
		DNS struct {
			Policy yaml.Node `yaml:"nameserver-policy"`
		} `yaml:"dns"`
	}
	_ = yaml.Unmarshal(rt, &doc)
	var keys []string
	for i := 0; i+1 < len(doc.DNS.Policy.Content); i += 2 {
		keys = append(keys, doc.DNS.Policy.Content[i].Value)
	}
	if strings.Join(keys, " ") != "+.zzz.example geosite:cn +.aaa.example" {
		t.Fatalf("nameserver-policy order %v", keys)
	}
	if s := ValidateConfigIn(home, path); s != "" { // sets the home dir and parses the (JSON) runtime
		t.Fatalf("validate: %s", s)
	}
	// A small profile keeps block YAML.
	small, _ := buildRuntime(genYAMLProfile(20, 20, 2, 0), o, 0)
	if small[0] == '{' {
		t.Fatal("small runtime written as JSON")
	}
}

func mustRuntimeMap(t *testing.T, prof []byte, o Overrides) map[string]any {
	t.Helper()
	rt, err := buildRuntime(prof, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(rt, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// /nodes/convert for a 5k-node share-link subscription stays small and produces a provider the core loads.
func TestV0196NodesConvertBounded(t *testing.T) {
	links := genSSLinks(5000)
	var out []byte
	var n int
	var err error
	r := neLimit(func() { out, n, err = convertNodesText([]byte(base64.StdEncoding.EncodeToString([]byte(links)))) })
	if err != nil || n != 6000 {
		t.Fatalf("convert: n=%d err=%v", n, err)
	}
	t.Logf("convertNodesText 6k nodes (b64): %s, %d KB", r, len(out)>>10)
	if r.peakHeap > scaleMB(25) {
		t.Errorf("peak heap %.1f MB (yaml.Marshal was ~60 MB)", float64(r.peakHeap)/(1<<20))
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil || len(doc.Proxies) != 6000 {
		t.Fatalf("provider YAML: %d proxies, %v", len(doc.Proxies), err)
	}
	if doc.Proxies[0]["name"] != "JP 00000" || doc.Proxies[0]["cipher"] != "aes-128-gcm" {
		t.Fatalf("first proxy %v", doc.Proxies[0])
	}
	// The same body through the core's provider path: a profile using the converted file.
	home := v0194Home(t)
	_ = os.WriteFile(filepath.Join(home, "sub.yaml"), out, 0o644)
	p := writeScaleProfile(t, home, []byte("proxy-providers:\n  sub: {type: file, path: ./sub.yaml}\nproxy-groups:\n  - {name: P, type: select, use: [sub]}\nrules:\n  - MATCH,P\n"))
	if s := ValidateConfigIn(home, p); s != "" {
		t.Fatalf("validate: %s", s)
	}
}
