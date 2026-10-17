package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"go.yaml.in/yaml/v3"
)

const qx012 = "[general]\n" +
	"running_mode_trigger=filter, all_proxy, Home-5G:all_direct, Office:filter\n" +
	"geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://example.com/IP_API.js\n" +
	"resource_parser_url=https://example.com/resource-parser.js\n" +
	"[policy]\n" +
	"static=节点选择, direct\n" +
	"static=Netflix, 节点选择, direct\n" +
	"[server_local]\n" +
	"shadowsocks=1.2.3.4:443, method=aes-128-gcm, password=pw, tag=HK\n" +
	"[filter_remote]\n" +
	"https://example.com/Mixed.list, tag=Mixed, enabled=true\n" +
	"https://example.com/Forced.list, tag=Forced, force-policy=direct, enabled=true\n" +
	"[filter_local]\n" +
	"final, 节点选择\n"

func TestQX012GeneralKeys(t *testing.T) {
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(qx012)), &res); err != nil || res.Error != "" {
		t.Fatalf("%v %s", err, res.Error)
	}
	s := res.Settings
	if s == nil || s.ModeTrigger == nil {
		t.Fatalf("settings %+v", s)
	}
	mt := *s.ModeTrigger
	if !mt.Enabled || mt.Cellular != "rule" || mt.WiFi != "global" || mt.SSIDs["Home-5G"] != "direct" || mt.SSIDs["Office"] != "rule" {
		t.Fatalf("trigger %+v", mt)
	}
	if s.GeoAPI != "http://ip-api.com/json/?lang=zh-CN" || s.GeoScript != "https://example.com/IP_API.js" || s.ParserURL != "https://example.com/resource-parser.js" {
		t.Fatalf("geo/parser %+v", s)
	}
	notes := strings.Join(res.Report.Notes, "\n")
	if strings.Contains(notes, "running_mode_trigger") || strings.Contains(notes, "geo_location_checker") {
		t.Fatalf("notes %s", notes)
	}
	var r2 confResult
	_ = json.Unmarshal([]byte(ImportConf("[general]\ngeo_location_checker=disabled\n[server_local]\nshadowsocks=1.2.3.4:443, method=aes-128-gcm, password=pw, tag=HK\n")), &r2)
	if r2.Settings == nil || !r2.Settings.GeoDisabled {
		t.Fatalf("disabled %+v", r2.Settings)
	}
}


func TestPickMode(t *testing.T) {
	mt := ModeTrigger{Enabled: true, Cellular: "rule", WiFi: "global", SSIDs: map[string]string{"Home": "direct"}}
	cases := [][3]string{{"wifi", "Home", "direct"}, {"wifi", "Cafe", "global"}, {"wifi", "", "global"}, {"cellular", "", "rule"}, {"wired", "", ""}}
	for _, c := range cases {
		if m, _ := pickMode(mt, c[0], c[1]); m != c[2] {
			t.Fatalf("%v → %q", c, m)
		}
	}
	mt.Enabled = false
	if m, _ := pickMode(mt, "cellular", ""); m != "" {
		t.Fatal("disabled trigger applied")
	}
	home := t.TempDir()
	b, _ := json.Marshal(ModeTrigger{Enabled: true, Cellular: "direct"})
	_ = os.WriteFile(modeTriggerPath(home), b, 0o644)
	tunnel.SetMode(tunnel.Rule)
	st := netPolicyState{}
	if !applyModeTrigger(home, "cellular", "", &st) || tunnel.Mode() != tunnel.Direct || st.Mode != "direct" || st.ModeReason != "cellular" {
		t.Fatalf("apply %+v %v", st, tunnel.Mode())
	}
	if applyModeTrigger(home, "cellular", "", &st) {
		t.Fatal("second apply should be a no-op")
	}
	tunnel.SetMode(tunnel.Rule)
}

func TestOwnPolicySplit(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	var res confResult
	_ = json.Unmarshal([]byte(ImportConf(qx012)), &res)
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(res.YAML), &raw); err != nil {
		t.Fatal(err)
	}
	rp := raw["rule-providers"].(map[string]any)
	mixed, _ := rp["Mixed"].(map[string]any)
	forced, _ := rp["Forced"].(map[string]any)
	if mixed == nil || forced == nil || !truthyAny(mixed["x-own-policy"]) || truthyAny(forced["x-own-policy"]) {
		t.Fatalf("providers %v", rp)
	}
	if !strings.Contains(strings.Join(res.Report.Notes, "\n"), "force-policy") {
		t.Fatal("missing own-policy note")
	}
	prof := filepath.Join(home, "profiles", "qx.yaml")
	_ = os.MkdirAll(filepath.Dir(prof), 0o755)
	_ = os.WriteFile(prof, []byte(res.YAML), 0o644)

	var plan []providerTask
	_ = json.Unmarshal([]byte(ProviderPlan(home, prof)), &plan)
	var task *providerTask
	for i := range plan {
		if plan[i].Name == "Mixed" {
			task = &plan[i]
		}
		if plan[i].Name == "Forced" && plan[i].Convert != "list" {
			t.Fatalf("forced convert %q", plan[i].Convert)
		}
	}
	if task == nil || task.Convert != "list-split" {
		t.Fatalf("plan %+v", plan)
	}
	list := "# test\nhost-suffix, netflix.com, Netflix\nhost, ads.example.com, reject\nhost-suffix, google.com, proxy\n" +
		"ip-cidr, 10.9.0.0/16, direct, no-resolve\nhost-keyword, spotify, Spotify\nDOMAIN-SUFFIX,plain.com\nhost-suffix, nflxvideo.net, netflix\n"
	var st struct {
		Count int    `json:"count"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(ProviderStore(home, "rule", task.Path, task.Convert, []byte(list))), &st)
	if st.Error != "" || st.Count != 7 {
		t.Fatalf("store %+v", st)
	}
	parts := readOwnPolicyParts(task.Path)
	if len(parts) != 6 { // Netflix, reject, proxy, direct, Spotify, netflix (case-sensitive custom names)
		t.Fatalf("parts %+v", parts)
	}
	b, _ := os.ReadFile(prof)
	rt, err := buildRuntime(b, overridesFor(home, prof), 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	_ = yaml.Unmarshal(rt, &out)
	var rules []string
	for _, r := range out["rules"].([]any) {
		rules = append(rules, r.(string))
	}
	joined := strings.Join(rules, "\n")
	for _, want := range []string{"RULE-SET,Mixed#Netflix,Netflix", "RULE-SET,Mixed#reject,REJECT", "RULE-SET,Mixed#proxy,节点选择", "RULE-SET,Mixed#direct,DIRECT", "RULE-SET,Mixed#Spotify,Spotify", "RULE-SET,Mixed#netflix,Netflix", "RULE-SET,Mixed,节点选择", "RULE-SET,Forced,DIRECT"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if strings.Index(joined, "RULE-SET,Mixed#Netflix") > strings.Index(joined, "RULE-SET,Mixed,") {
		t.Fatal("split rules must come before the fallback rule")
	}
	created := false
	for _, g := range out["proxy-groups"].([]any) {
		m := g.(map[string]any)
		if m["name"] == "Spotify" && m["type"] == "select" {
			created = true
		}
	}
	if !created {
		t.Fatal("Spotify group not auto-created")
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejected runtime: %v", err)
	}
}

func TestGeoLocationRun(t *testing.T) {
	code := `var o = JSON.parse($response.body); $done({title: o.country + " " + o.city, subtitle: o.as, ip: o.query, description: "x"})`
	var r geoResult
	_ = json.Unmarshal([]byte(GeoLocationRun(t.TempDir(), code, "http://ip-api.com/json", `{"country":"日本","city":"东京","as":"AS2516 KDDI","query":"1.2.3.4"}`)), &r)
	if r.Error != "" || r.Title != "日本 东京" || r.Subtitle != "AS2516 KDDI" || r.IP != "1.2.3.4" {
		t.Fatalf("%+v", r)
	}
	_ = json.Unmarshal([]byte(GeoLocationRun(t.TempDir(), "$done({})", "", "{}")), &r)
	if r.Error == "" {
		t.Fatal("expected an error for an empty result")
	}
}
