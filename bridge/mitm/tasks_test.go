package mitm

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCronParse(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	base := time.Date(2026, 10, 17, 7, 59, 30, 0, loc) // Saturday
	cases := []struct {
		expr string
		want string
	}{
		{"0 8 * * *", "2026-10-17 08:00:00"},
		{"*/15 * * * *", "2026-10-17 08:00:00"},
		{"30 7 * * *", "2026-10-18 07:30:00"},
		{"0 9 * * 1-5", "2026-10-19 09:00:00"},
		{"0 9 * * MON", "2026-10-19 09:00:00"},
		{"0 0 1 * *", "2026-11-01 00:00:00"},
		{"0 12 * * 7", "2026-10-18 12:00:00"},
		{"45 59 7 * * *", "2026-10-17 07:59:45"}, // 6 fields with seconds (QX)
		{"@hourly", "2026-10-17 08:00:00"},
		{"0 10 15 * 0", "2026-10-18 10:00:00"}, // dom OR dow
		{"5,35 8 * * *", "2026-10-17 08:05:00"},
		{"0 8-10/2 * * *", "2026-10-17 08:00:00"},
		{"\"0 8 * * *\"", "2026-10-17 08:00:00"},
	}
	for _, c := range cases {
		cr, err := ParseCron(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := cr.Next(base).Format("2006-01-02 15:04:05"); got != c.want {
			t.Errorf("%s: next %s want %s", c.expr, got, c.want)
		}
	}
	for _, bad := range []string{"", "* * *", "61 * * * *", "0 25 * * *", "a b c d e", "*/0 * * * *"} {
		if _, err := ParseCron(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

const taskModule = `#!name=任务测试
[Script]
签到 = type=cron,cronexp="0 8 * * *",script-path=checkin.js,timeout=60,argument=a=1
网络 = type=event,event-name=network-changed,script-path=net.js
面板脚本 = type=generic,script-path=panel.js,timeout=5
dnsx = type=dns,script-path=dns.js

[Panel]
信息面板 = script-name=面板脚本,update-interval=600
静态 = title="标题",content="第一行\n第二行",style=info,icon=wifi
`

const loonTasks = `#!name=Loon
[Script]
cron "30 9 * * *" script-path=https://example.com/loon.js, timeout=30, tag=Loon签到, enable=true
cron "0 1 * * *" script-path=https://example.com/off.js, tag=关闭的, enable=false
network-changed script-path=https://example.com/net.js, tag=Loon网络
generic script-path=https://example.com/gen.js, tag=Loon通用
`

const qxTasks = `[task_local]
0 8 * * * https://example.com/qx.js, tag=QX签到, img-url=https://x/y.png, enabled=true
0 9 * * * https://example.com/qx-off.js, tag=QX关闭, enabled=false
event-network https://example.com/qx-net.js, tag=QX网络
event-interaction https://example.com/qx-int.js, tag=QX交互
`

const stashTasks = `name: Stash
cron:
  script:
    - name: stash-checkin
      cron: "0 7 * * *"
      timeout: 20
tiles:
  - name: stash-tile
    interval: 600
    title: 流量
    content: 读取中
    icon: chart.bar
    backgroundColor: "#663399"
script-providers:
  stash-checkin:
    url: https://example.com/stash.js
    interval: 86400
  stash-tile:
    url: https://example.com/tile.js
`

func TestTaskSyntaxes(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(taskModule, "Surge模块", nil)
	if len(rs.Tasks) != 3 || len(rs.Panels) != 2 || len(rs.Unsupported) != 1 {
		t.Fatalf("surge: tasks=%d panels=%d unsupported=%v errors=%v", len(rs.Tasks), len(rs.Panels), rs.Unsupported, rs.Errors)
	}
	if tk := rs.Tasks[0]; tk.Kind != TaskCron || tk.Cron != "0 8 * * *" || tk.Script.Timeout != 60 || tk.Script.Argument != "a=1" {
		t.Errorf("surge cron: %+v %+v", tk, tk.Script)
	}
	if rs.Tasks[1].Kind != TaskEvent || rs.Tasks[2].Kind != TaskGeneric || rs.Tasks[2].Script.Timeout != 5 {
		t.Errorf("surge event/generic: %+v %+v", rs.Tasks[1], rs.Tasks[2])
	}
	if p := rs.Panels[0]; p.Script != "面板脚本" || p.Interval != 600 {
		t.Errorf("surge panel: %+v", p)
	}
	if p := rs.Panels[1]; p.Title != "标题" || p.Content != "第一行\n第二行" || p.Icon != "wifi" || p.Style != "info" {
		t.Errorf("static panel: %+v", p)
	}

	rs = &Ruleset{}
	rs.ParseText(loonTasks, "Loon插件", nil)
	// v0.11: enable=false lines stay in the list, switched off
	if len(rs.Tasks) != 4 || !rs.Tasks[1].DisabledByLine || rs.Tasks[0].DisabledByLine {
		t.Fatalf("loon tasks %d: %+v errors=%v", len(rs.Tasks), rs.Tasks, rs.Errors)
	}
	if tk := rs.Tasks[0]; tk.Kind != TaskCron || tk.Cron != "30 9 * * *" || tk.Script.Name != "Loon签到" || tk.Script.Timeout != 30 {
		t.Errorf("loon cron: %+v", tk.Script)
	}
	if rs.Tasks[2].Kind != TaskEvent || rs.Tasks[3].Kind != TaskGeneric {
		t.Errorf("loon kinds: %s %s", rs.Tasks[2].Kind, rs.Tasks[3].Kind)
	}

	rs = &Ruleset{}
	rs.ParseText(qxTasks, "QX", nil)
	if len(rs.Tasks) != 4 {
		t.Fatalf("qx tasks %d: %+v errors=%v", len(rs.Tasks), rs.Tasks, rs.Errors)
	}
	if tk := rs.Tasks[0]; tk.Kind != TaskCron || tk.Script.Path != "https://example.com/qx.js" || tk.Script.Name != "QX签到" || tk.Icon != "https://x/y.png" {
		t.Errorf("qx cron: %+v", tk.Script)
	}
	if !rs.Tasks[1].DisabledByLine || rs.Tasks[2].Kind != TaskEvent || rs.Tasks[3].Kind != TaskInteraction {
		t.Errorf("qx kinds")
	}
	// a QX task line typed into the user scripts list (no section)
	rs = &Ruleset{}
	rs.ParseLine("0 8 * * * https://example.com/qx.js, tag=QX签到", "script", "用户")
	if len(rs.Tasks) != 1 {
		t.Errorf("qx line outside task_local: %+v %v", rs.Tasks, rs.Errors)
	}

	rs = &Ruleset{}
	rs.ParseText(stashTasks, "Stash", nil)
	if rs.Format != "stash" || len(rs.Tasks) != 2 || len(rs.Panels) != 1 {
		t.Fatalf("stash: format=%s tasks=%d panels=%d errors=%v", rs.Format, len(rs.Tasks), len(rs.Panels), rs.Errors)
	}
	if rs.Tasks[0].Cron != "0 7 * * *" || rs.Panels[0].Script != "stash-tile" || rs.Panels[0].Interval != 600 {
		t.Errorf("stash: %+v %+v", rs.Tasks[0], rs.Panels[0])
	}
}

const checkinJS = `
const n = Number($persistentStore.read("runs") || 0) + 1;
$persistentStore.write(String(n), "runs");
$httpClient.get({url: "https://api.test.com/echo", insecure: true, headers: {"X-T": "1"}}, (err, resp, data) => {
  const j = JSON.parse(data);
  $notification.post("签到", "第 " + n + " 次", j.headers["X-T"] + ":" + $argument + ":" + $script.type, {"open-url": "https://x"});
  console.log("ok " + $utils.geoip("1.1.1.1") + " " + $utils.ipasn("1.1.1.1") + " " + $utils.ipaso("1.1.1.1"));
  $done();
});
`

const netJS = `$prefs.setValueForKey(JSON.stringify({ev: $event.name, ssid: $network.wifi.ssid}), "lastNet"); $done();`

const panelJS = `
const u = new Uint8Array($argument ? [] : []);
const z = $utils.ungzip(new Uint8Array(JSON.parse($persistentStore.read("gz"))));
$done({title: "已用 " + new TextDecoder().decode(z), content: "第一行\n" + ($panel ? $panel.title : "?"), icon: "bolt.fill", "icon-color": "#FF0000", style: "good"});
`

func TestTaskRunsAndPanels(t *testing.T) {
	cfg := &Config{Enabled: true, Scripts: items(
		`签到 = type=cron,cronexp="0 8 * * *",script-path=checkin.js,argument=arg1`,
		`网络 = type=event,event-name=network-changed,script-path=net.js`,
		`面板脚本 = type=generic,script-path=panel.js`,
	)}
	h := newHarness(t, cfg, map[string]string{"checkin.js": checkinJS, "net.js": netJS, "panel.js": panelJS})
	h.e.SetGeoLookup(func(ip string) (string, string, string) { return "AU", "13335", "Cloudflare" })
	var notes []string
	h.e.SetNotifier(func(title, sub, body, url string) { notes = append(notes, title+"|"+sub+"|"+body+"|"+url) })

	// panels come from the user list too when added as module text; build one directly
	rs := Build(h.home, cfg)
	rs.Panels = append(rs.Panels, &Panel{ID: "p1", Name: "面板", Title: "初始", Script: "面板脚本", Source: "用户", Format: "surge"})
	h.e.Reload(cfg, rs)

	list := h.e.tasks.list()
	if len(list) != 3 {
		t.Fatalf("tasks: %+v", list)
	}
	var cronID string
	for _, s := range list {
		if s.Kind == TaskCron {
			cronID = s.ID
			if s.NextRun == 0 {
				t.Error("cron task has no next run")
			}
		}
	}
	out, err := h.e.tasks.run(h.e.tasks.find(cronID), nil)
	if err != nil {
		t.Fatalf("cron run: %v", err)
	}
	_ = out
	if len(notes) != 1 || notes[0] != "签到|第 1 次|1:arg1:cron|https://x" {
		t.Errorf("notification: %v", notes)
	}
	if n := h.e.Notices.List(); len(n) != 1 || n[0].Script != "签到" {
		t.Errorf("notice log: %+v", n)
	}
	var sawGeo bool
	for _, l := range h.e.Logs.List(0, "签到") {
		if strings.Contains(l.Msg, "ok AU 13335 Cloudflare") {
			sawGeo = true
		}
	}
	if !sawGeo {
		t.Errorf("$utils geo missing: %+v", h.e.Logs.List(0, ""))
	}
	if st := h.e.tasks.list(); st[0].LastRun == 0 && st[1].LastRun == 0 {
		t.Error("last run not recorded")
	}

	// event script with $network + $event, shared store with $prefs
	if n := h.e.NetworkChanged(map[string]any{"wifi": map[string]any{"ssid": "Home"}}); n != 1 {
		t.Fatalf("event tasks started: %d", n)
	}
	if n := h.e.NetworkChanged(map[string]any{"wifi": map[string]any{"ssid": "Home"}}); n != 0 {
		t.Fatal("same network should be debounced")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if v, _ := h.e.Store.Read("lastNet"); v == `{"ev":"network-changed","ssid":"Home"}` {
			break
		}
		if time.Now().After(deadline) {
			v, _ := h.e.Store.Read("lastNet")
			t.Fatalf("event script result %q logs=%+v", v, h.e.Logs.List(0, ""))
		}
		time.Sleep(50 * time.Millisecond)
	}

	// panel via generic script, $utils.ungzip
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("12 GB"))
	_ = zw.Close()
	arr, _ := json.Marshal(func() []int {
		var o []int
		for _, b := range buf.Bytes() {
			o = append(o, int(b))
		}
		return o
	}())
	h.e.Store.Write("gz", string(arr), false)
	st, err := h.e.tasks.refreshPanel("p1")
	if err != nil || st.Error != "" {
		t.Fatalf("panel: %v %+v", err, st)
	}
	if st.Title != "已用 12 GB" || st.Content != "第一行\n初始" || st.Icon != "bolt.fill" || st.IconColor != "#FF0000" || st.Style != "good" {
		t.Errorf("panel content: %+v", st.Panel)
	}
	if pl := h.e.tasks.panelList(); len(pl) != 1 || pl[0].Updated == 0 {
		t.Errorf("panel list: %+v", pl)
	}
}

func TestReplayAndCapture(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/nothing - reject`)}
	h := newHarness(t, cfg, nil)
	req := `{"a":1}`
	r, _ := h.client.Post("https://api.test.com/echo", "application/json", strings.NewReader(req))
	r.Body.Close()
	var id int64
	for _, s := range h.e.Requests.List(0) {
		if strings.HasSuffix(s.URL, "/echo") {
			id = s.ID
		}
	}
	if id == 0 {
		t.Fatalf("request not captured: %+v", h.e.Requests.List(0))
	}
	ent := h.e.Requests.Get(id)
	if ent.ReqBodyS != req || ent.ReqLen != len(req) {
		t.Fatalf("captured body %q len %d", ent.ReqBodyS, ent.ReqLen)
	}
	res, err := h.e.Replay(id, nil)
	if err != nil || res.Status != 200 || !strings.Contains(res.Body, `"body":"{\"a\":1}"`) || !strings.Contains(res.Body, `"method":"POST"`) {
		t.Fatalf("replay: %v %+v", err, res)
	}
	body := `{"b":2}`
	res, err = h.e.Replay(id, &ReplayRequest{Method: "PUT", Body: &body, Headers: map[string]string{"X-Edit": "1"}})
	if err != nil || !strings.Contains(res.Body, `"method":"PUT"`) || !strings.Contains(res.Body, `"X-Edit":"1"`) || !strings.Contains(res.Body, `{\"b\":2}`) {
		t.Fatalf("edited replay: %v %+v", err, res)
	}
	if e := h.e.Requests.Get(res.ID); e == nil || len(e.Notes) == 0 || !strings.HasPrefix(e.Notes[0], "重放") {
		t.Fatalf("replay not logged")
	}
	if _, err := h.e.Replay(99999, nil); err == nil {
		t.Fatal("missing id should fail")
	}
}

// BoxJS: the official module serves the boxjs.com virtual host from an http-request script through
// MitM; the script answers locally ($done({response})) and keeps its data in $persistentStore.
const boxjsModule = `#!name=BoxJs
#!desc=http://boxjs.com
#!category=BoxJs

[General]
force-http-engine-hosts = %APPEND% boxjs.com, boxjs.net, *.boxjs.com, *.boxjs.net

[Script]
Rewrite: BoxJs = type=http-request,pattern=^https?:\/\/(.+\.)?boxjs\.(com|net),script-path=box.js, requires-body=true, timeout=120

[MITM]
hostname = %INSERT% boxjs.com, boxjs.net, *.boxjs.com, *.boxjs.net
`

const boxJS = `
const isSurge = typeof $environment !== 'undefined' && !!$environment['surge-version'];
const path = $request.url.replace(/^https?:\/\/[^/]+/, '');
if ($request.method === 'POST') { $persistentStore.write($request.body, 'chavy_boxjs_userCfgs'); }
const cfg = $persistentStore.read('chavy_boxjs_userCfgs') || '{}';
$done({response: {status: 200, headers: {'Content-Type': 'text/html;charset=UTF-8'}, body: '<html>BoxJs ' + isSurge + ' ' + path + ' ' + cfg + '</html>'}});
`

func TestBoxJSVirtualHost(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Modules: []Module{{ID: "boxjs", Name: "BoxJs", Enabled: true}}}
	h := newHarness(t, cfg, map[string]string{"box.js": boxJS})
	if err := writeFileForTest(ModulePath(h.home, "boxjs"), boxjsModule); err != nil {
		t.Fatal(err)
	}
	rs := Build(h.home, cfg)
	if len(rs.Rules) != 1 || rs.Rules[0].Script.Timeout != 120 || len(rs.Hostnames) != 4 {
		t.Fatalf("boxjs module: rules=%d hosts=%v errors=%v", len(rs.Rules), rs.Hostnames, rs.Errors)
	}
	h.e.Reload(cfg, rs)
	resp, body := h.get("https://boxjs.com/#/home")
	if resp.StatusCode != 200 || body != "<html>BoxJs true / {}</html>" {
		t.Fatalf("boxjs page: %d %q", resp.StatusCode, body)
	}
	r, err := h.client.Post("https://boxjs.com/api/save", "application/json", strings.NewReader(`{"theme":"dark"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	_, body = h.get("https://boxjs.com/")
	if !strings.Contains(body, `{"theme":"dark"}`) {
		t.Fatalf("boxjs store: %q", body)
	}
}

func writeFileForTest(p, s string) error {
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	return os.WriteFile(p, []byte(s), 0o644)
}
