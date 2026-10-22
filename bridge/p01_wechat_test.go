package libmihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// P0-1 (v0.19.17): a Quantumult X config with a WeChat filter_remote on a 微信消息 policy group.
// testdata/qx_wechat.list is blackmatrix7/ios_rule_script rule/QuantumultX/WeChat/WeChat.list
// (UPDATED 2025-06-06), fetched through jsDelivr on 2026-10-22.
const p01WeChatURL = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/WeChat/WeChat.list"

const p01QXConf = `[general]
server_check_url=http://www.qualcomm.cn/generate_204
udp_drop_list=1900, 80

[dns]
server=223.5.5.5

[policy]
static=🚀 节点选择, 🇭🇰 香港 01, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png
static=微信消息, direct, 🚀 节点选择, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/WeChat.png
static=🍎 苹果服务, direct, 🚀 节点选择

[server_local]
shadowsocks=hk.example.com:8388, method=aes-128-gcm, password=pwd, fast-open=false, udp-relay=true, tag=🇭🇰 香港 01

[filter_remote]
` + p01WeChatURL + `, tag=微信, force-policy=微信消息, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Apple/Apple.list, tag=Apple, force-policy=🍎 苹果服务, update-interval=172800, opt-parser=false, enabled=true

[filter_local]
host-suffix, weixin.qq.com, 微信消息
ip-cidr, 125.88.145.0/24, 微信消息, no-resolve
geoip, cn, direct
final, 🚀 节点选择
`

func p01Import(t *testing.T, conf string) (confResult, map[string]any) {
	t.Helper()
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(conf)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal([]byte(res.YAML), &cfg); err != nil {
		t.Fatal(err)
	}
	return res, cfg
}

func p01Group(cfg map[string]any, name string) map[string]any {
	gl, _ := cfg["proxy-groups"].([]any)
	for _, g := range gl {
		if m, ok := g.(map[string]any); ok && str(m["name"]) == name {
			return m
		}
	}
	return nil
}

func p01HasRule(cfg map[string]any, rule string) bool {
	for _, r := range strList(cfg["rules"]) {
		if r == rule {
			return true
		}
	}
	return false
}

// wechatProvider returns the name of the rule-provider whose source is the WeChat list.
func p01WeChatProvider(cfg map[string]any) (string, map[string]any) {
	rp, _ := cfg["rule-providers"].(map[string]any)
	for n, v := range rp {
		m, _ := v.(map[string]any)
		if src := firstNonEmpty(str(m["x-source"]), str(m["url"])); strings.Contains(src, "/WeChat/WeChat.list") {
			return n, m
		}
	}
	return "", nil
}

func TestP01WeChatFilterRemoteImported(t *testing.T) {
	res, cfg := p01Import(t, p01QXConf)
	for _, s := range res.Report.Skipped {
		if strings.Contains(s, "WeChat") || strings.Contains(s, "微信") {
			t.Fatalf("WeChat entry skipped: %s", s)
		}
	}
	if res.Report.RulesSkipped != 0 {
		t.Fatalf("rulesSkipped %d: %v", res.Report.RulesSkipped, res.Report.Skipped)
	}
	if g := p01Group(cfg, "微信消息"); g == nil || fmt.Sprint(g["proxies"]) != "[DIRECT 🚀 节点选择]" {
		t.Fatalf("微信消息 group: %v", g)
	}
	name, p := p01WeChatProvider(cfg)
	if name != "微信" || str(p["url"]) != p01WeChatURL || str(p["x-convert"]) != "list" {
		t.Fatalf("WeChat provider %q %v", name, p)
	}
	if p["interval"] != 172800 {
		t.Fatalf("update-interval not kept: %v", p["interval"])
	}
	for _, r := range []string{"RULE-SET,微信,微信消息", "DOMAIN-SUFFIX,weixin.qq.com,微信消息", "IP-CIDR,125.88.145.0/24,微信消息,no-resolve", "RULE-SET,Apple,🍎 苹果服务"} {
		if !p01HasRule(cfg, r) {
			t.Fatalf("rule %q missing: %v", r, cfg["rules"])
		}
	}
}

// QX accepts a quoted force-policy and names that differ only in spaces / emoji variation selectors; both
// must land on the existing group instead of dropping the whole WeChat list.
func TestP01ForcePolicyQuotedOrSpaced(t *testing.T) {
	for _, fp := range []string{`"微信消息"`, ` 微信 消息 `, "微信消息\u200b", "'微信消息'"} {
		conf := strings.Replace(p01QXConf, "force-policy=微信消息,", "force-policy="+fp+",", 1)
		res, cfg := p01Import(t, conf)
		name, _ := p01WeChatProvider(cfg)
		if name == "" || !p01HasRule(cfg, "RULE-SET,"+name+",微信消息") {
			t.Errorf("force-policy=%q: WeChat list not imported; skipped %v", fp, res.Report.Skipped)
		}
	}
}

// A force-policy naming no group: the list cannot be imported, and the report must say so loudly (right
// section, counted, a note at the top), never drop it silently.
func TestP01MissingPolicyIsReported(t *testing.T) {
	conf := strings.Replace(p01QXConf, "force-policy=微信消息,", "force-policy=WeChat,", 1)
	res, cfg := p01Import(t, conf)
	if name, _ := p01WeChatProvider(cfg); name != "" {
		t.Fatalf("provider for a missing policy: %s", name)
	}
	if res.Report.RulesSkipped != 1 {
		t.Fatalf("rulesSkipped %d", res.Report.RulesSkipped)
	}
	found := false
	for _, s := range res.Report.Skipped {
		if strings.HasPrefix(s, "[filter_remote] "+p01WeChatURL) && strings.Contains(s, "整个规则列表未导入") && strings.Contains(s, "「WeChat」不存在") {
			found = true
		}
	}
	if !found {
		t.Fatalf("skip not reported under [filter_remote]: %v", res.Report.Skipped)
	}
	if len(res.Report.Notes) == 0 || !strings.Contains(res.Report.Notes[0], "1 条分流规则 / 规则列表没有导入") {
		t.Fatalf("no leading note: %v", res.Report.Notes)
	}
	// Two groups that fold to the same name: never guess.
	amb := strings.Replace(p01QXConf, "static=🍎 苹果服务, direct, 🚀 节点选择", "static=🍎 苹果服务, direct, 🚀 节点选择\nstatic=微信 消息, direct", 1)
	amb = strings.Replace(amb, "force-policy=微信消息,", "force-policy=微信消 息,", 1)
	res, _ = p01Import(t, amb)
	if res.Report.RulesSkipped != 1 {
		t.Fatalf("ambiguous loose match must not resolve: %v", res.Report.Skipped)
	}
}

func TestP01SkippedOverflowIsCounted(t *testing.T) {
	var b strings.Builder
	b.WriteString("[policy]\nstatic=P, direct\n[filter_local]\n")
	for i := 0; i < 230; i++ {
		fmt.Fprintf(&b, "host, h%d.example.com, Missing\n", i)
	}
	b.WriteString("final, P\n")
	res, _ := p01Import(t, b.String())
	if res.Report.RulesSkipped != 230 {
		t.Fatalf("rulesSkipped %d", res.Report.RulesSkipped)
	}
	last := res.Report.Skipped[len(res.Report.Skipped)-1]
	if !strings.Contains(last, "另有 30 项未转换") {
		t.Fatalf("overflow not reported: %q", last)
	}
}

// Rules survive the upgrade path: profile written as the app does, the v0.8.1 provider migration
// (ProfileStore.load on every launch), the runtime build the tunnel uses, the core's own parser, and the
// app's download of the list into the cache file the core reads.
func TestP01WeChatRulesSurviveMigrationAndRuntime(t *testing.T) {
	res, _ := p01Import(t, p01QXConf)
	home := t.TempDir()
	prof := filepath.Join(home, "profiles", "wechat.yaml")
	_ = os.MkdirAll(filepath.Dir(prof), 0o755)
	if err := os.WriteFile(prof, []byte(res.YAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := MigrateProfileProviders(prof); n != 0 {
		t.Fatalf("migration rewrote a current profile: %d", n)
	}
	b, _ := os.ReadFile(prof)
	if string(b) != res.YAML {
		t.Fatal("migration changed the profile")
	}
	o := readOverrides(home)
	rt, err := buildRuntime(b, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	name, p := p01WeChatProvider(raw)
	if name != "微信" || str(p["x-source"]) != p01WeChatURL || !strings.Contains(str(p["url"]), "127.0.0.1") {
		t.Fatalf("runtime provider %q %v", name, p)
	}
	if !p01HasRule(raw, "RULE-SET,微信,微信消息") || p01Group(raw, "微信消息") == nil {
		t.Fatalf("runtime lost the WeChat rule / group: %v", raw["rules"])
	}
	if e := ValidateConfigIn(home, prof); e != "" {
		t.Fatalf("core refuses the imported profile: %s", e)
	}
	// The app downloads the list (ProviderPlan → ProviderStore) into the file the core reads.
	var plan []providerTask
	_ = json.Unmarshal([]byte(ProviderPlan(home, prof)), &plan)
	list, err := os.ReadFile("testdata/qx_wechat.list")
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, pt := range plan {
		if pt.Name != "微信" {
			continue
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(ProviderStore(home, "rule", pt.Path, pt.Convert, list)), &out)
		got, _ := os.ReadFile(pt.Path)
		if out["error"] != "" || !strings.Contains(string(got), "DOMAIN-SUFFIX,weixin.qq.com") || !strings.Contains(string(got), "DOMAIN-SUFFIX,qpic.cn") {
			t.Fatalf("store %v\n%s", out, got)
		}
		stored = true
	}
	if !stored {
		t.Fatalf("WeChat list not in the download plan: %+v", plan)
	}
}

// A 配置订阅 serving the QX config (ProfileStore.download → normalize → ConvertShareLinks) used to come
// out as a node-only template: no 微信消息 group, no WeChat rules.
func TestP01QXConfigAsProfileSubscription(t *testing.T) {
	y := ConvertShareLinks(p01QXConf)
	if y == "" {
		t.Fatal(LastError())
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal([]byte(y), &cfg); err != nil {
		t.Fatal(err)
	}
	if p01Group(cfg, "微信消息") == nil || !p01HasRule(cfg, "RULE-SET,微信,微信消息") || !p01HasRule(cfg, "DOMAIN-SUFFIX,weixin.qq.com,微信消息") {
		t.Fatalf("subscription lost the WeChat group / rules:\n%s", y)
	}
	if !strings.HasPrefix(y, "# Tern: converted from a Quantumult X config") {
		t.Fatalf("no report header:\n%s", y[:200])
	}
	home := t.TempDir()
	prof := filepath.Join(home, "sub.yaml")
	_ = os.WriteFile(prof, []byte(y), 0o644)
	if e := ValidateConfigIn(home, prof); e != "" {
		t.Fatalf("core refuses the converted subscription: %s", e)
	}
	// Skipped rules are listed in the profile itself.
	y = ConvertShareLinks(strings.Replace(p01QXConf, "force-policy=微信消息,", "force-policy=WeChat,", 1))
	if !strings.Contains(y, "#   未导入的分流规则 / 规则列表：1") || !strings.Contains(y, "#   未转换：[filter_remote] "+p01WeChatURL) {
		t.Fatalf("skipped list not in the header:\n%s", y)
	}
	// Node lists (no [policy] / rules) keep the node-line converter.
	plain := "[Proxy]\nHK = ss, hk.example.com, 8388, encrypt-method=aes-128-gcm, password=pw\n"
	if y := ConvertShareLinks(plain); !strings.Contains(y, "节点选择") {
		t.Fatalf("node list no longer converted as nodes:\n%s", y)
	}
}

// Rules lost from the profile (an older build, an edit) come back from the saved original .conf.
func TestP01RestoreLostRulesFromSource(t *testing.T) {
	res, cfg := p01Import(t, p01QXConf)
	// Simulate the reported state: WeChat list, its rules and the 微信消息 group are gone.
	delete(cfg["rule-providers"].(map[string]any), "微信")
	var kept []any
	for _, r := range strList(cfg["rules"]) {
		if !strings.Contains(r, "微信消息") {
			kept = append(kept, r)
		}
	}
	cfg["rules"] = kept
	var groups []any
	for _, g := range cfg["proxy-groups"].([]any) {
		if str(g.(map[string]any)["name"]) != "微信消息" {
			groups = append(groups, g)
		}
	}
	cfg["proxy-groups"] = groups
	lost, _ := yaml.Marshal(cfg)
	home := t.TempDir()
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, lost, 0o644)

	var rr restoreResult
	_ = json.Unmarshal([]byte(RestoreConfRules(prof, true)), &rr)
	if !strings.Contains(rr.Error, "原始 .conf") {
		t.Fatalf("no source: %+v", rr)
	}
	if e := SaveConfSource(prof, p01QXConf); e != "" || !HasConfSource(prof) {
		t.Fatal(e)
	}
	_ = json.Unmarshal([]byte(RestoreConfRules(prof, false)), &rr)
	if len(rr.Providers) != 1 || len(rr.Groups) != 1 || len(rr.Rules) != 3 {
		t.Fatalf("preview %+v", rr)
	}
	if b, _ := os.ReadFile(prof); string(b) != string(lost) {
		t.Fatal("preview wrote the profile")
	}
	_ = json.Unmarshal([]byte(RestoreConfRules(prof, true)), &rr)
	b, _ := os.ReadFile(prof)
	got := map[string]any{}
	_ = yaml.Unmarshal(b, &got)
	if p01Group(got, "微信消息") == nil || !p01HasRule(got, "RULE-SET,微信,微信消息") || !p01HasRule(got, "DOMAIN-SUFFIX,weixin.qq.com,微信消息") {
		t.Fatalf("not restored:\n%s", b)
	}
	// Order: restored rules sit where the original had them, before GEOIP and MATCH.
	rules := strList(got["rules"])
	idx := func(s string) int {
		for i, r := range rules {
			if r == s {
				return i
			}
		}
		return -1
	}
	if !(idx("DOMAIN-SUFFIX,weixin.qq.com,微信消息") < idx("GEOIP,cn,DIRECT") && idx("RULE-SET,微信,微信消息") < idx("MATCH,🚀 节点选择") && strings.HasPrefix(rules[len(rules)-1], "MATCH,")) {
		t.Fatalf("order %v", rules)
	}
	if e := ValidateConfigIn(home, prof); e != "" {
		t.Fatalf("core refuses the restored profile: %s", e)
	}
	// Idempotent.
	_ = json.Unmarshal([]byte(RestoreConfRules(prof, true)), &rr)
	if len(rr.Providers)+len(rr.Groups)+len(rr.Rules) != 0 {
		t.Fatalf("second restore changed things: %+v", rr)
	}
	_ = res
	// Deleting the profile removes the saved source.
	_ = ForgetProfile(home, "x", prof)
	if HasConfSource(prof) {
		t.Fatal("source kept after ForgetProfile")
	}
}
