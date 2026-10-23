package libmihomo

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

const readableSmall = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
unified-delay: true
profile: {store-selected: true}
sniffer:
  enable: true
  sniff: {TLS: {ports: [443]}, HTTP: {ports: [80], override-destination: true}}
hosts:
  router.lan: 192.168.1.1
dns:
  nameserver: [https://1.1.1.1/dns-query]
  enable: true
  enhanced-mode: fake-ip
  nameserver-policy:
    "+.zz.example": 223.5.5.5
    "+.aa.example": 119.29.29.29
    "geosite:cn": [223.5.5.5]
proxies:
  - {password: "123456", name: 香港 01, cipher: aes-128-gcm, port: 8388, server: hk.example.com, type: ss, udp: true}
  - {name: "日本 02", type: vmess, server: jp.example.com, port: 443, uuid: 00000000-0000-0000-0000-000000000000, alterId: 0, cipher: auto, tls: true, network: ws, ws-opts: {headers: {Host: jp.example.com}, path: /ws}}
  - {name: "yes", type: trojan, server: us.example.com, port: 443, password: "0123", sni: us.example.com}
rule-providers:
  ads: {type: inline, behavior: domain, payload: [+.ads.example, +.track.example]}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [自动选择, 香港 01, 日本 02, "yes", DIRECT]}
  - {type: url-test, name: 自动选择, proxies: [香港 01, 日本 02, "yes"], interval: 300, url: "https://www.gstatic.com/generate_204"}
rules:
  - RULE-SET,ads,REJECT
  - DOMAIN-SUFFIX,google.com,节点选择
  - GEOIP,LAN,DIRECT,no-resolve
  - MATCH,节点选择
`

func bigProfile(nodes, rules int) string {
	var b strings.Builder
	b.WriteString("mixed-port: 7890\nmode: rule\nlog-level: info\nproxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "  - {name: \"节点 %05d\", type: ss, server: n%d.example.com, port: %d, cipher: aes-128-gcm, password: \"pw%d\", udp: true}\n", i, i, 10000+i%50000, i)
	}
	b.WriteString("proxy-groups:\n  - name: 选择\n    type: select\n    proxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "      - \"节点 %05d\"\n", i)
	}
	b.WriteString("rules:\n")
	for i := 0; i < rules-1; i++ {
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,d%d.example.com,%s\n", i, map[bool]string{true: "选择", false: "DIRECT"}[i%3 == 0])
	}
	b.WriteString("  - MATCH,选择\n")
	return b.String()
}

func decodeAny(t *testing.T, s string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

// peakHeap runs f while sampling HeapAlloc; returns the peak above the starting heap.
func peakHeap(f func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	if p := peak.Load(); p > base {
		return p - base
	}
	return 0
}

func TestFinalConfigReadableEquivalent(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		big     bool
	}{
		{"small", readableSmall, false},
		{"5k-nodes-20k-rules", bigProfile(5000, 20000), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "profile.yaml")
			if err := os.WriteFile(p, []byte(tc.profile), 0o644); err != nil {
				t.Fatal(err)
			}
			var lean, readable string
			var errLean, errReadable error
			leanPeak := peakHeap(func() { lean, errLean = FinalConfig(dir, p) })
			readPeak := peakHeap(func() { readable, errReadable = FinalConfigReadable(dir, p, "测试配置", "0.19.22 (296)") })
			if errLean != nil || errReadable != nil {
				t.Fatalf("lean %v readable %v", errLean, errReadable)
			}
			t.Logf("%s: output %d KB (lean %d KB, %d lines); peak heap readable %.1f MB, lean export %.1f MB",
				tc.name, len(readable)>>10, len(lean)>>10, strings.Count(readable, "\n"), float64(readPeak)/(1<<20), float64(leanPeak)/(1<<20))

			// Same config as the lean export, value for value.
			a, b := decodeAny(t, lean), decodeAny(t, readable)
			if !reflect.DeepEqual(a, b) {
				for k := range a {
					if !reflect.DeepEqual(a[k], b[k]) {
						t.Errorf("key %q differs:\nlean     %#v\nreadable %#v", k, a[k], b[k])
					}
				}
				for k := range b {
					if _, ok := a[k]; !ok {
						t.Errorf("readable has extra key %q", k)
					}
				}
				t.FailNow()
			}
			// And mihomo's own parser accepts it with the same proxies / groups / rules.
			cr, err := executor.ParseWithBytes([]byte(readable))
			if err != nil {
				t.Fatalf("mihomo parse: %v", err)
			}
			cl, err := executor.ParseWithBytes([]byte(lean))
			if err != nil {
				t.Fatalf("mihomo parse lean: %v", err)
			}
			if len(cr.Proxies) != len(cl.Proxies) || len(cr.Rules) != len(cl.Rules) {
				t.Fatalf("parsed proxies %d/%d rules %d/%d", len(cr.Proxies), len(cl.Proxies), len(cr.Rules), len(cl.Rules))
			}
			for i := range cr.Rules {
				if cr.Rules[i].Payload() != cl.Rules[i].Payload() || cr.Rules[i].Adapter() != cl.Rules[i].Adapter() {
					t.Fatalf("rule %d differs", i)
				}
			}

			// Layout: header, section order, comments.
			if !strings.HasPrefix(readable, "# Tern 导出的最终配置") || !strings.Contains(readable, "# 配置：测试配置") ||
				!strings.Contains(readable, "# Tern 版本：0.19.22 (296)") || !strings.Contains(readable, "内核不读取") {
				t.Fatalf("header:\n%s", readable[:min(len(readable), 800)])
			}
			order := []string{"\nmode:", "\nproxies:", "\nproxy-groups:", "\nrules:"}
			if !tc.big {
				order = []string{"\nallow-lan:", "\nmode:", "\nlog-level:", "\nprofile:", "\nsniffer:", "\ndns:",
					"\nhosts:", "\nproxies:", "\nproxy-groups:", "\nrule-providers:", "\nrules:"}
			}
			last := -1
			for _, k := range order {
				i := strings.Index(readable, k)
				if i < 0 || i < last {
					t.Fatalf("%q missing or out of order:\n%s", k, readable)
				}
				last = i
			}
			for _, c := range []string{"# ===== 通用设置 =====", "# ===== 节点（共 ", "# ===== 策略组（共 ", "# ===== 规则（共 "} {
				if !strings.Contains(readable, c) {
					t.Fatalf("missing comment %q", c)
				}
			}
			if strings.Contains(readable, "{\"") || strings.Contains(readable, "\"name\":") {
				t.Fatalf("JSON leaked into export")
			}
			if tc.big {
				if !strings.Contains(readable, "# ===== 节点（共 5000 个）=====") || !strings.Contains(readable, fmt.Sprintf("# ===== 规则（共 %d 条", len(asList(a["rules"])))) {
					t.Fatalf("counts wrong: %q", grepLines(readable, "# ====="))
				}
				// One node per line in flow style, keys in mihomo order.
				if !strings.Contains(readable, "\n  - {name: 节点 00042, type: ss, server: n42.example.com, port: 10042, cipher: aes-128-gcm, password: pw42, udp: true}\n") {
					i := strings.Index(readable, "节点 00042")
					t.Fatalf("flow node line not found near:\n%s", readable[max(0, i-200):min(len(readable), i+200)])
				}
				// The rendering step alone (the runtime config is already built) against the lean export's
				// clean-up of the same bytes.
				rt, err := buildRuntime([]byte(tc.profile), defaultOverrides(), 0)
				if err != nil {
					t.Fatal(err)
				}
				var r1, r2 string
				renderPeak := peakHeap(func() { r1, _ = renderReadable(rt, dir, "", exportMeta{}) })
				stripPeak := peakHeap(func() { r2, _ = stripAppInternalsFor(rt, dir, "") })
				t.Logf("runtime config %d KB: render peak %.1f MB, lean clean-up peak %.1f MB", len(rt)>>10,
					float64(renderPeak)/(1<<20), float64(stripPeak)/(1<<20))
				if r1 == "" || r2 == "" || renderPeak > stripPeak*3/2+(8<<20) || readPeak > 128<<20 {
					t.Fatalf("readable export peak heap %.1f MB (render %.1f MB, lean clean-up %.1f MB)",
						float64(readPeak)/(1<<20), float64(renderPeak)/(1<<20), float64(stripPeak)/(1<<20))
				}
				return
			}
			// Small: block style, keys in mihomo order, nameserver-policy order kept.
			for _, want := range []string{
				"  - name: 香港 01\n    type: ss\n    server: hk.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: \"123456\"\n",
				"  - name: \"yes\"\n", "find-process-mode: \"off\"\n", "# ===== 节点（共 3 个）=====\n", "# ===== DNS 设置 =====\n", "    ws-opts:\n      path: /ws\n      headers:\n",
				"  - name: 自动选择\n    type: url-test\n    proxies:\n",
				"dns:\n  enable: true\n", "  nameserver-policy:\n    +.zz.example: 223.5.5.5\n    +.aa.example: 119.29.29.29\n",
			} {
				if !strings.Contains(readable, want) {
					t.Fatalf("missing %q in:\n%s", want, readable)
				}
			}
			t.Logf("sample:\n%s", readable)
		})
	}
}

func grepLines(s, sub string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}
