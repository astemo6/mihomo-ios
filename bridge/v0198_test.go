package libmihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

// v0.19.8: a 停用 node subscription contributes no provider; groups that chose it in `use:` (筛选节点 with only
// some subscriptions as its source) must not break the config.
func TestV0198DisabledNodeSubDroppedFromUse(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	node := func(n string) []byte {
		return []byte("proxies:\n  - {name: " + n + ", type: ss, server: 192.0.2.9, port: 443, cipher: aes-128-gcm, password: x}\n")
	}
	_ = os.WriteFile(NodeSubPath(home, "a"), node("a1"), 0o644)
	_ = os.WriteFile(NodeSubPath(home, "b"), node("b1"), 0o644)
	subs := []NodeSub{{ID: "a", Name: "SelfBuild", Enabled: true}, {ID: "b", Name: "eds", Enabled: false}}
	b, _ := json.Marshal(subs)
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	edits := map[string]GroupEdits{"p1": {Added: []GroupSpec{
		{Name: "只用eds", Type: "url-test", Use: []string{"eds"}, URL: "http://www.gstatic.com/generate_204", Interval: 300},
		{Name: "两个订阅", Type: "select", Use: []string{"SelfBuild", "eds"}},
	}}}
	eb, _ := json.Marshal(edits)
	_ = os.WriteFile(groupEditsPath(home), eb, 0o644)
	profile := []byte("proxies:\n  - {name: n1, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: x}\n" +
		"proxy-groups:\n  - {name: 节点选择, type: select, proxies: [n1, 只用eds, 两个订阅]}\nrules:\n  - MATCH,节点选择\n")
	rt, err := buildRuntime(profile, Overrides{home: home, profileID: "p1", Mode: "rule", DNSMode: "fake-ip"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	pp, _ := raw["proxy-providers"].(map[string]any)
	if _, ok := pp["eds"]; ok {
		t.Fatal("disabled subscription merged as a provider")
	}
	if _, ok := pp["SelfBuild"]; !ok {
		t.Fatal("enabled subscription missing")
	}
	gs := map[string]map[string]any{}
	for _, gv := range asList(raw["proxy-groups"]) {
		g := gv.(map[string]any)
		gs[str(g["name"])] = g
	}
	if u := strList(gs["只用eds"]["use"]); len(u) != 0 || !reflect.DeepEqual(strList(gs["只用eds"]["proxies"]), []string{"DIRECT"}) {
		t.Fatalf("group of only the disabled subscription: use %v proxies %v", u, gs["只用eds"]["proxies"])
	}
	if u := strList(gs["两个订阅"]["use"]); !reflect.DeepEqual(u, []string{"SelfBuild"}) {
		t.Fatalf("mixed group use = %v", u)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core refused the runtime: %v", err)
	}
	// Enabling it again brings it back.
	subs[1].Enabled = true
	b, _ = json.Marshal(subs)
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	rt, _ = buildRuntime(profile, Overrides{home: home, profileID: "p1", Mode: "rule", DNSMode: "fake-ip"}, 0)
	if !strings.Contains(string(rt), "nodesubs/b.yaml") {
		t.Fatal("re-enabled subscription not merged")
	}
}

const v0198QX = `[general]
server_check_url=http://cp.cloudflare.com/generate_204
server_check_timeout=2000
[server_local]
shadowsocks=192.0.2.1:8388, method=aes-128-gcm, password=x, tag=n1
[policy]
static=节点选择, proxy, 自动, direct
static=流媒体, 节点选择, proxy, direct
url-latency-benchmark=自动, server-tag-regex=.*, check-interval=600
static=AdBlock, reject, direct
[filter_local]
host-suffix, google.com, proxy
final, 节点选择
`

// v0.19.8 device report: the QX built-in `proxy` group (generated first by the importer) stayed first whatever
// order was saved. Both directions must stick in the copy, in the core's group order (GLOBAL lists groups in the
// order the policy page shows), and after the copy is regenerated from its source.
func TestV0198GeneratedProxyGroupFollowsOrder(t *testing.T) {
	var r struct{ YAML, Error string }
	if err := json.Unmarshal([]byte(ImportConf(v0198QX)), &r); err != nil || r.Error != "" {
		t.Fatalf("import: %v %s", err, r.Error)
	}
	home := t.TempDir()
	src := filepath.Join(home, "src.yaml")
	cp := filepath.Join(home, "copyid.yaml")
	_ = os.WriteFile(src, []byte(r.YAML), 0o644)
	if got := groupNamesOf(t, []byte(r.YAML)); got[0] != "proxy" {
		t.Fatalf("importer order %v", got)
	}
	coreOrder := func(b []byte) []string {
		rt, err := buildRuntime(b, Overrides{Mode: "rule", DNSMode: "fake-ip"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := executor.ParseWithBytes(rt)
		if err != nil {
			t.Fatal(err)
		}
		var g struct{ All []string }
		jb, _ := json.Marshal(cfg.Proxies["GLOBAL"])
		_ = json.Unmarshal(jb, &g)
		var out []string
		for _, n := range g.All {
			if p := cfg.Proxies[n]; p != nil && n != ProbeGroup && len(strings.TrimSpace(n)) > 0 {
				switch n {
				case "节点选择", "流媒体", "自动", "AdBlock", "proxy":
					out = append(out, n)
				}
			}
		}
		return out
	}
	check := func(step string, want []string) {
		t.Helper()
		b, _ := os.ReadFile(cp)
		if got := groupNamesOf(t, b); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: file order %v, want %v", step, got, want)
		}
		if got := coreOrder(b); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: core order %v, want %v", step, got, want)
		}
	}
	// 1. First reorder: 节点选择 above proxy (proxy moves down) → copy created.
	want1 := []string{"节点选择", "proxy", "流媒体", "自动", "AdBlock"}
	o1, _ := json.Marshal(want1)
	if res := GroupOrderCopy(home, src, cp, string(o1)); !strings.Contains(res, `"changed":true`) {
		t.Fatalf("copy: %s", res)
	}
	check("copy", want1)
	// 2. proxy to the bottom, then 节点选择 below proxy… i.e. any order where proxy is not first.
	want2 := []string{"流媒体", "自动", "AdBlock", "proxy", "节点选择"}
	o2, _ := json.Marshal(want2)
	if res := ReorderGroups(home, cp, string(o2)); !strings.Contains(res, `"changed":true`) {
		t.Fatalf("reorder: %s", res)
	}
	check("reorder", want2)
	// 3. Stored order (as the app keeps it) + regenerate from the source → order kept.
	eb, _ := json.Marshal(map[string]GroupEdits{"copyid": {Order: want2}})
	_ = os.WriteFile(groupEditsPath(home), eb, 0o644)
	if res := GroupOrderRegenerateForced(home, src, cp); strings.Contains(res, `"error":"`) {
		t.Fatalf("regenerate: %s", res)
	}
	check("regenerate", want2)
	// 4. Back to proxy first works too.
	want3 := []string{"proxy", "AdBlock", "节点选择", "流媒体", "自动"}
	o3, _ := json.Marshal(want3)
	_ = ReorderGroups(home, cp, string(o3))
	check("proxy back to top", want3)
}

// v0.19.8: QX server_check_timeout=2000 made most nodes 超时 (mihomo's unified delay includes the handshake).
func TestV0198ImportedCheckTimeoutClamped(t *testing.T) {
	for in, want := range map[int]int{1000: 5000, 2000: 5000, 5000: 5000, 8000: 8000, 30000: 10000} {
		if got := importedCheckTimeout(in); got != want {
			t.Fatalf("importedCheckTimeout(%d) = %d, want %d", in, got, want)
		}
	}
	var r struct{ YAML string }
	_ = json.Unmarshal([]byte(ImportConf(v0198QX)), &r)
	if !strings.Contains(r.YAML, "timeout: 5000") || strings.Contains(r.YAML, "timeout: 2000") {
		t.Fatalf("url-test group timeout not clamped:\n%s", r.YAML)
	}
}

// v0.19.8 device report: GLOBAL edited in 编辑策略组 (手动选择, members = 节点选择 only) still listed DIRECT /
// REJECT / every node. The edit (stored as an added group, or keyed GLOBAL) must emit a real GLOBAL group with
// exactly those members; 全局 mode keeps working; the runtime group order file lists every group.
func TestV0198EditedGlobalGroup(t *testing.T) {
	profile := []byte("proxies:\n  - {name: n1, type: ss, server: 192.0.2.1, port: 443, cipher: aes-128-gcm, password: x}\n" +
		"proxy-groups:\n  - {name: 节点选择, type: select, proxies: [n1, DIRECT]}\n  - {name: 自动, type: url-test, proxies: [n1], url: 'http://www.gstatic.com/generate_204', interval: 300}\nrules:\n  - MATCH,节点选择\n")
	spec := GroupSpec{Name: "GLOBAL", Type: "select", Proxies: []string{"节点选择"}}
	for name, e := range map[string]GroupEdits{
		"added": {Added: []GroupSpec{spec}},
		"keyed": {Edits: map[string]GroupEdit{"GLOBAL": {Spec: &spec}}},
	} {
		home := t.TempDir()
		eb, _ := json.Marshal(map[string]GroupEdits{"p1": e})
		_ = os.WriteFile(groupEditsPath(home), eb, 0o644)
		for _, mode := range []string{"rule", "global"} {
			var order []string
			rt, err := buildRuntimeWith(profile, Overrides{home: home, profileID: "p1", Mode: mode, DNSMode: "fake-ip"}, 0,
				func(raw map[string]any) { order = runtimeGroupNames(raw) })
			if err != nil {
				t.Fatal(name, err)
			}
			cfg, err := executor.ParseWithBytes(rt)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, mode, err)
			}
			var g struct {
				All []string
				Now string
			}
			jb, _ := json.Marshal(cfg.Proxies["GLOBAL"])
			_ = json.Unmarshal(jb, &g)
			if !reflect.DeepEqual(g.All, []string{"节点选择"}) || g.Now != "节点选择" {
				t.Fatalf("%s/%s: GLOBAL = %+v", name, mode, g)
			}
			if !reflect.DeepEqual(order, []string{"节点选择", "自动", "GLOBAL"}) {
				t.Fatalf("%s: runtime group order %v", name, order)
			}
			if strings.ToLower(cfg.General.Mode.String()) != mode {
				t.Fatalf("mode %v", cfg.General.Mode)
			}
		}
	}
	// No edit: mihomo's own GLOBAL (everything) as before.
	rt, _ := buildRuntime(profile, Overrides{Mode: "rule", DNSMode: "fake-ip"}, 0)
	cfg, _ := executor.ParseWithBytes(rt)
	jb, _ := json.Marshal(cfg.Proxies["GLOBAL"])
	if !strings.Contains(string(jb), `"DIRECT"`) || !strings.Contains(string(jb), `"自动"`) {
		t.Fatalf("auto GLOBAL changed: %s", jb)
	}
	home := t.TempDir()
	writeRuntimeGroupOrder(home, []string{"a", "GLOBAL"})
	if b, _ := os.ReadFile(filepath.Join(home, RuntimeGroupOrderFile)); string(b) != `["a","GLOBAL"]` {
		t.Fatalf("order file %s", b)
	}
}

// v0.19.8: 日志 / DNS 日志 history kept from tunnel start in bounded rings, read with a seq cursor.
func TestV0198LogRings(t *testing.T) {
	generalLog.clear()
	dnsLog.clear()
	now := time.Now()
	ev := func(l log.LogLevel, p string) log.Event { return log.Event{LogLevel: l, Payload: p} }
	recordLogEvent(ev(log.INFO, "[TCP] a --> b"), now)
	recordLogEvent(ev(log.DEBUG, "[DNS] example.com --> [192.0.2.1]"), now)
	recordLogEvent(ev(log.WARNING, "[Provider] slow"), now)
	recordLogEvent(ev(log.DEBUG, "[Sniffer] noise"), now) // below the user's level (INFO): dropped
	g := logHistory("general", 0, "")
	if len(g.Logs) != 2 || g.Logs[0].Payload != "[TCP] a --> b" || g.Logs[1].Type != "warning" {
		t.Fatalf("general = %+v", g.Logs)
	}
	d := logHistory("dns", 0, "")
	if len(d.Logs) != 1 || !strings.HasPrefix(d.Logs[0].Payload, "[DNS] ") {
		t.Fatalf("dns = %+v", d.Logs)
	}
	// Cursor: only newer entries; level filter.
	cur := g.Seq
	recordLogEvent(ev(log.ERROR, "[Core] boom"), now)
	if n := logHistory("general", cur, ""); len(n.Logs) != 1 || n.Logs[0].Payload != "[Core] boom" || n.Seq <= cur {
		t.Fatalf("since cursor = %+v", n)
	}
	if w := logHistory("general", 0, "warning"); len(w.Logs) != 2 {
		t.Fatalf("level filter = %+v", w.Logs)
	}
	// Bounded: oldest dropped, order kept, payload cut on a rune boundary.
	for i := 0; i < logRingCap+50; i++ {
		recordLogEvent(ev(log.INFO, fmt.Sprintf("line %d %s", i, strings.Repeat("节", 300))), now)
	}
	all := logHistory("general", 0, "")
	if len(all.Logs) != logRingCap {
		t.Fatalf("ring size %d", len(all.Logs))
	}
	// Other tests' cores may log into the same global ring meanwhile (the diag subscriber is process-wide), so
	// check our own lines only: newest kept, at least the 50 oldest dropped, numbers strictly increasing.
	prev := -1
	for _, e := range all.Logs {
		var n int
		if _, err := fmt.Sscanf(e.Payload, "line %d ", &n); err != nil {
			continue
		}
		if prev == -1 && n < 50 {
			t.Fatalf("oldest not dropped: line %d kept", n)
		}
		if n <= prev {
			t.Fatalf("order: line %d after %d", n, prev)
		}
		prev = n
	}
	if prev != logRingCap+49 {
		t.Fatalf("newest line = %d", prev)
	}
	for i := 1; i < len(all.Logs); i++ {
		if all.Logs[i].Seq <= all.Logs[i-1].Seq {
			t.Fatal("seq not increasing")
		}
	}
	if p := all.Logs[len(all.Logs)-1].Payload; len(p) > logPayloadMax+len("…") || !utf8.ValidString(p) {
		t.Fatalf("payload not cut cleanly: %d bytes", len(p))
	}
	ringFor("general").clear()
	if len(logHistory("general", 0, "").Logs) != 0 {
		t.Fatal("clear")
	}
}
