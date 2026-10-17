package libmihomo

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

// A typical Quantumult X config: nodes only from subscriptions, remote filters / rewrites, groups that
// pick nodes by regex or list remote server tags.
const qxTypical = "\ufeff;Quantumult X sample\r\n" +
	"[general]\r\nserver_check_url=http://www.gstatic.com/generate_204\r\n\r\n" +
	"[dns]\r\nserver=223.5.5.5\r\nserver=/example.cn/119.29.29.29\r\n\r\n" +
	"[policy]\r\n" +
	"static=节点选择, 香港节点, 日本节点, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png\r\n" +
	"url-latency-benchmark=香港节点, server-tag-regex=港|HK, check-interval=600, tolerance=50\r\n" +
	"available=日本节点, resource-tag-regex=机场A, server-tag-regex=日本|JP\r\n" +
	"static=手选, 🇺🇸 美国 01, 🇺🇸 美国 02\r\n\r\n" +
	"[server_remote]\r\n" +
	"https://sub.example.com/api/v1/client/subscribe?token=abc&flag=quanx, tag=机场A, update-interval=86400, opt-parser=true, enabled=true\r\n" +
	"http://plain.example.net/qx.txt, tag=机场B, enabled=true\r\n" +
	"https://old.example.org/s, tag=停用, enabled=false\r\n\r\n" +
	"[filter_remote]\r\n" +
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Netflix/Netflix.list, tag=Netflix, force-policy=节点选择, update-interval=172800, opt-parser=false, enabled=true\r\n" +
	"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/China/China.list, tag=China, force-policy=direct, enabled=true\r\n\r\n" +
	"[rewrite_remote]\r\n" +
	"https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf, tag=BoxJS, update-interval=172800, opt-parser=false, enabled=true\r\n" +
	"https://example.com/off.conf, tag=off, enabled=false\r\n\r\n" +
	"[server_local]\r\n\r\n" +
	"[filter_local]\r\nhost-suffix, local, direct\r\nip-cidr, 10.0.0.0/8, direct\r\nfinal, 节点选择\r\n\r\n" +
	"[rewrite_local]\r\n^https?://example\\.com/ad url reject\r\n\r\n" +
	"[task_local]\r\n\r\n" +
	"[mitm]\r\nhostname = example.com\r\n"

func TestClassifyQXConfig(t *testing.T) {
	if c := ClassifyText(qxTypical); c != "conf" {
		t.Fatalf("typical QX config classified as %q", c)
	}
	// A plain http:// remote line used to make it look like a Stash override.
	only := "[server_remote]\nhttp://a.example/qx, tag=A\n\n[filter_remote]\nhttp://b.example/l.list, tag=B, force-policy=proxy\n"
	if c := ClassifyText(only); c != "conf" {
		t.Fatalf("remote-only QX config classified as %q", c)
	}
	// Indented / CRLF section headers.
	if c := ClassifyText("  [policy]  \r\nstatic=A, direct\r\n"); c != "conf" {
		t.Fatalf("indented section: %q", c)
	}
	// Modules / snippets stay modules.
	if c := ClassifyText("#!name=x\n[rewrite_local]\n^http://a url reject\n[mitm]\nhostname = a.com\n"); !strings.HasPrefix(c, "module:") {
		t.Fatalf("QX snippet classified as %q", c)
	}
}

func TestImportQXTypical(t *testing.T) {
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(qxTypical)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("error: %s", res.Error)
	}
	if res.Report.Format != "qx" {
		t.Fatalf("format %s", res.Report.Format)
	}
	var enabled []remoteModule
	for _, m := range res.RewriteRemotes {
		if m.Enabled {
			enabled = append(enabled, m)
		}
	}
	if len(enabled) != 1 || !strings.Contains(enabled[0].URL, "boxjs") {
		t.Fatalf("rewrite_remote: %v", res.RewriteRemotes)
	}
	if !res.Report.Module {
		t.Fatalf("rewrite_local / mitm should become a module")
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(res.YAML), &cfg); err != nil {
		t.Fatal(err)
	}
	pp, _ := cfg["proxy-providers"].(map[string]any)
	if len(pp) != 2 || pp["机场A"] == nil || pp["机场B"] == nil {
		t.Fatalf("proxy-providers: %v", pp)
	}
	if a := pp["机场A"].(map[string]any); !strings.HasPrefix(str(a["url"]), "https://sub.example.com/") || str(a["x-convert"]) != "nodes" {
		t.Fatalf("provider url %v", a)
	}
	groups := map[string]map[string]any{}
	for _, g := range asList(cfg["proxy-groups"]) {
		m := g.(map[string]any)
		groups[str(m["name"])] = m
	}
	if groups["香港节点"]["include-all"] != true || str(groups["香港节点"]["filter"]) != "港|HK" {
		t.Fatalf("HK group: %v", groups["香港节点"])
	}
	if use := asList(groups["日本节点"]["use"]); len(use) != 1 || str(use[0]) != "机场A" {
		t.Fatalf("JP group (resource-tag-regex): %v", groups["日本节点"])
	}
	if use := asList(groups["手选"]["use"]); len(use) != 2 {
		t.Fatalf("group of remote server tags should use the subscriptions: %v", groups["手选"])
	}
	if str(groups["节点选择"]["icon"]) == "" {
		t.Fatalf("img-url not kept")
	}
	rp, _ := cfg["rule-providers"].(map[string]any)
	if len(rp) != 2 {
		t.Fatalf("rule-providers: %v", rp)
	}
	rules := asList(cfg["rules"])
	if last := str(rules[len(rules)-1]); last != "MATCH,节点选择" {
		t.Fatalf("last rule %s", last)
	}
	// The core accepts the runtime config built from the imported profile.
	o := defaultOverrides()
	rt, err := buildRuntime([]byte(res.YAML), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), "/nodes/convert?url=https%3A%2F%2Fsub.example.com") {
		t.Fatalf("provider not routed through /nodes/convert:\n%s", rt)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects imported QX config: %v\n%s", err, rt)
	}
}

func TestConvertNodesText(t *testing.T) {
	qx := "shadowsocks=1.2.3.4:443, method=aes-128-gcm, password=pw, tag=🇭🇰 HK 01\ntrojan=5.6.7.8:443, password=pw, over-tls=true, tls-host=a.example, tag=🇯🇵 JP 01\n"
	out, n, err := convertNodesText([]byte(qx))
	if err != nil || n != 2 || !strings.Contains(string(out), "proxies:") {
		t.Fatalf("qx lines: n=%d err=%v\n%s", n, err, out)
	}
	y := []byte("proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n")
	if out, n, _ := convertNodesText(y); n != -1 || string(out) != string(y) {
		t.Fatalf("yaml should pass through")
	}
	if _, _, err := convertNodesText([]byte("<html>login</html>")); err == nil {
		t.Fatalf("html must fail")
	}
}
