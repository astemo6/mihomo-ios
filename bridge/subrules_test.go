package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

const subProfile = `
proxies:
  - {name: "🇭🇰 香港 01 | IPLC", type: ss, server: 1.1.1.1, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "香港 02", type: ss, server: 1.1.1.2, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "日本 Tokyo 10", type: ss, server: 1.1.1.3, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "日本 Tokyo 2", type: ss, server: 1.1.1.4, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "US Los Angeles", type: ss, server: 1.1.1.5, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "剩余流量：100GB", type: ss, server: 1.1.1.6, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "套餐到期：2027-01-01", type: ss, server: 1.1.1.7, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "香港 02 备用", type: ss, server: 1.1.1.2, port: 8388, cipher: aes-128-gcm, password: a}
  - {name: "台湾 TW 01", type: ss, server: 1.1.1.8, port: 8388, cipher: aes-128-gcm, password: a}
proxy-groups:
  - {name: PROXY, type: select, proxies: [AUTO, "🇭🇰 香港 01 | IPLC", "香港 02", "日本 Tokyo 10", "日本 Tokyo 2", "US Los Angeles", "剩余流量：100GB", "香港 02 备用", "台湾 TW 01"]}
  - {name: AUTO, type: url-test, proxies: ["剩余流量：100GB"]}
rules:
  - DOMAIN,a.com,香港 02
  - DOMAIN,b.com,剩余流量：100GB
  - MATCH,PROXY
`

func TestDetectRegion(t *testing.T) {
	cases := map[string]string{
		"🇭🇰 香港 01": "HK", "Hong Kong 03": "HK", "HK-IPLC": "HK", "日本 Tokyo": "JP", "US Los Angeles": "US",
		"美国 01": "US", "新加坡": "SG", "台湾 01": "TW", "韩国 首尔": "KR", "UK London": "GB", "Germany": "DE",
		"印尼 01": "ID", "印度 01": "IN", "澳门": "MO", "澳洲": "AU", "Plus 01": "", "HUSKY": "",
	}
	for in, want := range cases {
		if got := DetectRegion(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	if flagOf("HK") != "🇭🇰" || flagOf("JP") != "🇯🇵" {
		t.Fatal("flag")
	}
}

func TestNaturalLess(t *testing.T) {
	if !naturalLess("节点 2", "节点 10") || naturalLess("节点 10", "节点 2") || !naturalLess("a", "b") {
		t.Fatal("natural order")
	}
}

func runSub(t *testing.T, r SubRules) map[string]any {
	t.Helper()
	o := defaultOverrides()
	r.Enabled = true
	o.sub = &r
	rt, err := buildRuntime([]byte(subProfile), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects processed profile: %v\n%s", err, rt)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	return raw
}

func names(raw map[string]any) []string {
	var out []string
	for _, p := range proxiesOf(raw) {
		out = append(out, str(p["name"]))
	}
	return out
}

func TestSubFilterRenameSort(t *testing.T) {
	raw := runSub(t, SubRules{
		Exclude: "剩余|到期", Dedupe: true, AddFlag: true, Sort: "region",
		Renames: []RenameRule{{Pattern: `\s*\|\s*IPLC`, Replace: " IPLC"}, {Pattern: `Tokyo\s*`, Replace: ""}},
	})
	got := strings.Join(names(raw), ",")
	want := "🇭🇰 香港 01 IPLC,🇭🇰 香港 02,🇹🇼 台湾 TW 01,🇯🇵 日本 2,🇯🇵 日本 10,🇺🇸 US Los Angeles"
	if got != want {
		t.Fatalf("names\n got %s\nwant %s", got, want)
	}
	// group members renamed / removed; AUTO lost its only member → DIRECT
	for _, x := range raw["proxy-groups"].([]any) {
		g := x.(map[string]any)
		ps := strList(g["proxies"])
		switch str(g["name"]) {
		case "PROXY":
			if strings.Join(ps, ",") != "AUTO,🇭🇰 香港 01 IPLC,🇭🇰 香港 02,🇯🇵 日本 10,🇯🇵 日本 2,🇺🇸 US Los Angeles,🇹🇼 台湾 TW 01" {
				t.Fatalf("PROXY members %v", ps)
			}
		case "AUTO":
			if strings.Join(ps, ",") != "DIRECT" {
				t.Fatalf("AUTO members %v", ps)
			}
		}
	}
	rules := strList(raw["rules"])
	if !contains(rules, "DOMAIN,a.com,🇭🇰 香港 02") || !contains(rules, "DOMAIN,b.com,DIRECT") {
		t.Fatalf("rules not remapped: %v", rules)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestSubIncludeRegexAndUniqueNames(t *testing.T) {
	raw := runSub(t, SubRules{Include: `^(香港|日本)`, Regex: true, Renames: []RenameRule{{Pattern: `^(香港|日本).*$`, Replace: "$1"}}, Prefix: "A-"})
	got := strings.Join(names(raw), ",")
	if got != "A-香港,A-日本,A-日本 2,A-香港 2" {
		t.Fatalf("got %s", got)
	}
	// keywords are case-insensitive
	raw = runSub(t, SubRules{Include: "tokyo|los"})
	if len(names(raw)) != 3 {
		t.Fatalf("keyword include: %v", names(raw))
	}
}

func TestSubBadRegexKeepsProfile(t *testing.T) {
	o := defaultOverrides()
	o.sub = &SubRules{Enabled: true, Include: "([", Regex: true}
	if _, err := buildRuntime([]byte(subProfile), o, 0); err != nil {
		t.Fatal(err)
	}
	errs := applySubRules(map[string]any{}, o.sub)
	if len(errs) == 0 {
		t.Fatal("expected an error for a bad regex")
	}
}

func TestSubProviders(t *testing.T) {
	prof := `
proxy-providers:
  air:
    type: http
    url: https://example.com/sub
    path: ./providers/air.yaml
    filter: "IPLC"
proxy-groups:
  - {name: PROXY, type: select, use: [air]}
rules: ["MATCH,PROXY"]
`
	o := defaultOverrides()
	o.sub = &SubRules{Enabled: true, Include: "香港|日本", Exclude: "到期", AddFlag: true, Prefix: "X ", Renames: []RenameRule{{Pattern: "IPLC", Replace: "专线"}}}
	rt, err := buildRuntime([]byte(prof), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects provider override: %v\n%s", err, rt)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	air := raw["proxy-providers"].(map[string]any)["air"].(map[string]any)
	if str(air["filter"]) != "(?=.*(IPLC))(?i)(香港|日本)" || str(air["exclude-filter"]) != "(?i)(到期)" {
		t.Fatalf("filters: %v / %v", air["filter"], air["exclude-filter"])
	}
	ov := air["override"].(map[string]any)
	if str(ov["additional-prefix"]) != "X " || len(asList(ov["proxy-name"])) != 2 {
		t.Fatalf("override: %v", ov)
	}
}

func TestSubPreviewAndStore(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "mihomo")
	_ = os.MkdirAll(filepath.Join(dir, "profiles"), 0o755)
	_ = os.MkdirAll(home, 0o755)
	pp := filepath.Join(dir, "profiles", "p1.yaml")
	_ = os.WriteFile(pp, []byte(subProfile), 0o644)
	var res previewResult
	if err := json.Unmarshal([]byte(SubPreview(home, pp, `{"exclude":"剩余|到期","dedupe":true}`)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Total != 9 || res.Kept != 6 {
		t.Fatalf("preview %d/%d: %+v", res.Kept, res.Total, res.Nodes)
	}
	reasons := map[string]string{}
	for _, n := range res.Nodes {
		reasons[n.Original] = n.Reason
	}
	if reasons["香港 02 备用"] != "重复节点" || reasons["剩余流量：100GB"] != "匹配排除规则" {
		t.Fatalf("reasons %v", reasons)
	}
	// stored rules are picked up by overridesFor (by profile id) and applied by InspectProfile
	b, _ := json.Marshal(map[string]SubRules{"p1": {Enabled: true, Include: "日本"}})
	_ = os.WriteFile(subRulesPath(home), b, 0o644)
	var ins inspectResult
	_ = json.Unmarshal([]byte(InspectProfile(home, pp)), &ins)
	if len(ins.Proxies) != 2 {
		t.Fatalf("inspect after rules: %+v", ins.Proxies)
	}
	if v := ValidateConfigIn(home, pp); v != "" {
		t.Fatal(v)
	}
	// disabled rules → untouched
	b, _ = json.Marshal(map[string]SubRules{"p1": {Enabled: false, Include: "日本"}})
	_ = os.WriteFile(subRulesPath(home), b, 0o644)
	_ = json.Unmarshal([]byte(InspectProfile(home, pp)), &ins)
	if len(ins.Proxies) != 9 {
		t.Fatalf("disabled rules applied: %d", len(ins.Proxies))
	}
}

func TestSetTimeZone(t *testing.T) {
	old := time.Local
	defer func() { time.Local = old }()
	SetTimeZone("Asia/Shanghai", 8*3600)
	if _, off := time.Now().Zone(); off != 8*3600 {
		t.Fatalf("offset %d", off)
	}
	SetTimeZone("Not/AZone", -3600)
	if _, off := time.Now().Zone(); off != -3600 {
		t.Fatalf("fallback offset %d", off)
	}
}
