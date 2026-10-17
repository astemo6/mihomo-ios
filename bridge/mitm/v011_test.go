package mitm

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// v0.11: QX url-and-header + jsonjq-*-body.
func TestQXURLAndHeaderAndJSONJQ(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText("[rewrite_local]\n"+
		`^https://api\.example\.com/v1 User-Agent:\sMyApp url-and-header reject-dict`+"\n"+
		`^https://api\.example\.com/feed url jsonjq-response-body 'del(.ads) | .vip = true'`+"\n"+
		`^https://api\.example\.com/up url jsonjq-request-body jq-path=https://example.com/a.jq`+"\n", "QX", nil)
	if len(rs.Rules) != 3 || len(rs.Errors) > 0 || len(rs.Unsupported) > 0 {
		t.Fatalf("rules=%d errors=%v unsupported=%v", len(rs.Rules), rs.Errors, rs.Unsupported)
	}
	r := rs.Rules[0]
	if r.Kind != KindURL || r.Action != "reject-dict" || r.HeaderPattern == "" {
		t.Fatalf("url-and-header: %+v", r)
	}
	req, _ := http.NewRequest("GET", "https://api.example.com/v1/x", nil)
	req.Header.Set("User-Agent", "MyApp/1.0")
	if !r.matchReq("https://api.example.com/v1/x", req) {
		t.Fatal("should match with the header")
	}
	req.Header.Set("User-Agent", "Other")
	if r.matchReq("https://api.example.com/v1/x", req) {
		t.Fatal("should not match without the header")
	}
	if j := rs.Rules[1]; j.Kind != KindJQ || j.Phase != "response" || j.JQ != "del(.ads) | .vip = true" {
		t.Fatalf("jsonjq response: %+v", j)
	}
	if j := rs.Rules[2]; j.Kind != KindJQ || j.Phase != "request" || j.Data != "https://example.com/a.jq" {
		t.Fatalf("jsonjq request: %+v", j)
	}
	e := &Engine{}
	out, err := e.applyBodyRule(rs.Rules[1], []byte(`{"ads":[1],"vip":false,"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["ads"] != nil || m["vip"] != true || m["x"] != float64(1) {
		t.Fatalf("jq result %s", out)
	}
}

const interactionJS = `console.log("node=" + $environment.params); $done({title: "结果", message: $environment.params});`

// v0.11: task prefs (master switch + per task), run log, list snapshot, interaction params.
func TestTaskPrefsHistoryInteraction(t *testing.T) {
	cfg := &Config{Enabled: true, Scripts: items(
		`签到 = type=cron,cronexp="0 8 * * *",script-path=int.js`,
		`网络 = type=event,event-name=network-changed,script-path=int.js,enable=false`,
	)}
	h := newHarness(t, cfg, map[string]string{"int.js": interactionJS})
	rs := Build(h.home, cfg)
	rs.ParseText("[task_local]\nevent-interaction int.js, tag=交互脚本\n", "QX", nil)
	h.e.Reload(cfg, rs)
	var list []*Task
	b, err := os.ReadFile(filepath.Join(h.home, taskListFile))
	if err != nil || json.Unmarshal(b, &list) != nil || len(list) != 3 {
		t.Fatalf("task-list.json: %v %s", err, b)
	}
	var cron, ev, inter string
	for _, s := range h.e.tasks.list() {
		switch s.Kind {
		case TaskCron:
			cron = s.ID
			if !s.Enabled {
				t.Error("cron should be enabled")
			}
		case TaskEvent:
			ev = s.ID
			if s.Enabled {
				t.Error("enable=false event should be off")
			}
		case TaskInteraction:
			inter = s.ID
		}
	}
	if cron == "" || ev == "" || inter == "" {
		t.Fatalf("kinds: %+v", h.e.tasks.list())
	}
	if n := h.e.NetworkChanged(map[string]any{"a": 1}); n != 0 {
		t.Fatalf("disabled event ran: %d", n)
	}
	h.e.tasks.setPrefs(TaskPrefs{Enabled: map[string]bool{ev: true}})
	if n := h.e.NetworkChanged(map[string]any{"a": 2}); n != 1 {
		t.Fatalf("enabled event should run: %d", n)
	}
	h.e.tasks.setPrefs(TaskPrefs{Paused: true, Enabled: map[string]bool{ev: true}})
	if n := h.e.NetworkChanged(map[string]any{"a": 3}); n != 0 {
		t.Fatalf("paused: %d", n)
	}
	var p TaskPrefs
	b, _ = os.ReadFile(filepath.Join(h.home, taskPrefsFile))
	if json.Unmarshal(b, &p) != nil || !p.Paused || !p.Enabled[ev] {
		t.Fatalf("prefs file: %s", b)
	}
	out, err := h.e.tasks.runAs(h.e.tasks.find(inter), map[string]any{"$params": "🇯🇵 东京 01"}, "interaction")
	if err != nil || out["message"] != "🇯🇵 东京 01" {
		t.Fatalf("interaction: %v %v", out, err)
	}
	hist := h.e.tasks.historyFor(inter)
	if len(hist) != 1 || !hist[0].OK || hist[0].Trigger != "interaction" || len(hist[0].Logs) == 0 {
		t.Fatalf("history: %+v", hist)
	}
	found := false
	for _, l := range hist[0].Logs {
		if len(l) > 0 && contains(l, "node=🇯🇵 东京 01") {
			found = true
		}
	}
	if !found {
		t.Fatalf("console line not in run log: %v", hist[0].Logs)
	}
	for i := 0; i < 12; i++ {
		_, _ = h.e.tasks.run(h.e.tasks.find(cron), nil)
	}
	if n := len(h.e.tasks.historyFor(cron)); n != historyPerTask {
		t.Fatalf("history cap: %d", n)
	}
	saved := map[string][]RunRecord{}
	b, _ = os.ReadFile(filepath.Join(h.home, taskHistoryFile))
	if json.Unmarshal(b, &saved) != nil || len(saved[cron]) != historyPerTask || len(saved[inter]) != 1 {
		t.Fatalf("history file: %d %d", len(saved[cron]), len(saved[inter]))
	}
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestQXMitMKeys(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText("[mitm]\nskip_validating_cert = true\nskip_src_ip = 192.168.1.5\nhostname = a.com, -b.a.com\n", "QX", nil)
	if rs.SkipCertVerify == nil || !*rs.SkipCertVerify || len(rs.Unsupported) > 0 || len(rs.Errors) > 0 {
		t.Fatalf("skip=%v unsupported=%v errors=%v", rs.SkipCertVerify, rs.Unsupported, rs.Errors)
	}
}
