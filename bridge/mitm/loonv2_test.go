package mitm

import (
	"encoding/json"
	"strings"
	"testing"
)

// Loon 3.5.1 expression syntax (.lpx plugins: 可莉插件中心 and others) — loonv2.go.

const lv2Plugin = `#!name=示例插件
#!desc=Loon 新语法
#!tag=去广告, 依赖
#!icon=https://example.com/icon.png

[Argument]
enabled = switch,true,tag=启用
blockFeed = switch,false,tag=信息流
region = select,"CN","US",tag=地区
level = select,1,2,3,type=number,tag=等级
Weather.Provider = select,"ColorfulClouds","WeatherKit",tag=数据源
token = input,"",tag=令牌
cron = input,"0 8 * * *",tag=时间
app = select,"tg","telegram",tag=客户端

[Rewrite]
request if ${url} ~= /^https:\/\/a\.com\/ad/i then reject_dict(200)
request if ${url} ~= /^https:\/\/a\.com\/r404/ then reject(404)
request if ${url} ~= /^https:\/\/a\.com\/r451/ then reject(451, "nope")
request if ${url} ~= /^https:\/\/a\.com\/img/ then reject_img(200)
request if ${url} ~= /^https:\/\/a\.com\/arr/ then reject_array(204)
request if ${url} ~= /^https:\/\/old\.com(\/.*)$/ as m then redirect(302, "https://new.com${m.1}?p=$x")
request if ${url} ~= /^https:\/\/t\.me\/(\w+)$/ as item then redirect(307, "${app}://resolve?domain=${item.1}")
request if ${url} ~= /^https:\/\/h\.com/ then request.header.set("X-Loon", "true") | request.header.del(["Cookie", "Referer"]) | request.header.replace("User-Agent", /iPhone OS (\d+)/i, "iPhone OS $1")
response if ${url} ~= /^https:\/\/j\.com\/a/ then response.json.delete(["data.ads", "data.banner"])
response if ${url} ~= /^https:\/\/j\.com\/b/ then response.json.replace(["data.vip", "data.level", "data.region", "data.s"], [true, ${level}, ${region}, "true"])
response if ${url} ~= /^https:\/\/j\.com\/c/ then response.json.jq(".data |= del(.ads) | .x = \"a, b\"")
response if ${url} ~= /^https:\/\/j\.com\/d/ then response.json.jq_file("https://example.com/f.jq")
response if ${url} ~= /^https:\/\/j\.com\/e/ then response.json.jq_file("local.jq")
response if ${url} ~= /^https:\/\/b\.com/ then response.body.replace([/false/, /"x":(\d)/], ["true", "\"y\":$1"])
response if ${url} ~= /^https:\/\/m\.com/ then response.body.mock("json", ` + "`" + `{"code":0,"msg":"a|b"}` + "`" + `, 201) | response.header.set("X-Mock", "1")
response if ${url} ~= /^https:\/\/m\.com\/f/ then response.body.mock_file("png", "https://example.com/a.png")
request if ${enabled} == true && ${url} ~= /^https:\/\/on\.com/ then reject(200)
request if ${blockFeed} == true && ${url} ~= /^https:\/\/off\.com/ then reject(200)
request if ${url} ~= /^https:\/\/x\.com/ || ${url} ~= /^https:\/\/y\.com/i then reject(200)
request if ${url} ~= /^https:\/\/z\.com/ && ${url} ~= /token=/ then reject(200)
request if ${request.method} == "POST" && ${url} ~= /^https:\/\/p\.com/ then reject(200)
request if ${url} ~= /^https:\/\/q\.com/ then request.body.mock("json", "{}")
^https:\/\/legacy\.com\/{region} reject-dict

[Script]
response if ${url} ~= /^https:\/\/s\.com\/api/i then script("https://example.com/s.js", {${region}, ${level}, ${enabled}, ${token}, ${Weather.Provider}}) with tag="S 响应", requires_body=true, binary_body_mode=true, timeout=30
request if ${url} ~= /^https:\/\/s\.com\/req/ then script("https://example.com/r.js", "a=1&b=${region}") with enable=${blockFeed}
request if ${url} ~= /^https:\/\/s\.com\/q/ then script("https://example.com/q.js")
response if ${response.status} == 200 then script("https://example.com/bad.js")
cron ${cron} then script("https://example.com/cron.js", {${token}}) with tag="签到", timeout=120
generic then script("https://example.com/tool.js") with tag="工具", img_url="https://example.com/t.png", enable=${blockFeed}
network-changed then script("https://example.com/net.js")
http-response ^https:\/\/legacy\.com\/s script-path=https://example.com/l.js, argument=[{region},{level}], tag=旧语法

[MitM]
hostname = a.com, j.com
`

func lv2Parse(t *testing.T, text string, args map[string]string) *Ruleset {
	t.Helper()
	rs := &Ruleset{}
	rs.ParseText(text, "示例", args)
	return rs
}

func lv2Find(rs *Ruleset, sub string) []*Rule {
	var out []*Rule
	for _, r := range rs.Rules {
		if strings.Contains(r.Line, sub) {
			out = append(out, r)
		}
	}
	return out
}

func TestLoonV2Rewrite(t *testing.T) {
	rs := lv2Parse(t, lv2Plugin, nil)
	if len(rs.Errors) != 0 {
		t.Fatalf("errors: %q", rs.Errors)
	}
	if rs.Format != "loon" || rs.Name != "示例插件" {
		t.Fatalf("format %q name %q", rs.Format, rs.Name)
	}
	one := func(sub string) *Rule {
		t.Helper()
		rr := lv2Find(rs, sub)
		if len(rr) != 1 {
			t.Fatalf("%s: %d rules", sub, len(rr))
		}
		return rr[0]
	}
	r := one(`a\.com\/ad`)
	if r.Kind != KindURL || r.Action != "reject-dict" || !r.match("https://A.com/ad/1") || r.match("https://b.com/ad") {
		t.Fatalf("reject_dict: %+v", r)
	}
	if r := one("r404"); r.Action != "reject" {
		t.Fatalf("reject(404): %+v", r)
	}
	if r := one("r451"); r.Kind != KindMapLocal || r.Status != 451 || r.Data != "nope" {
		t.Fatalf("reject(451): %+v", r)
	}
	if r := one(`a\.com\/img`); r.Action != "reject-img" {
		t.Fatalf("reject_img: %+v", r)
	}
	if r := one(`a\.com\/arr`); r.Kind != KindMapLocal || r.Status != 204 || r.Data != "[]" {
		t.Fatalf("reject_array(204): %+v", r)
	}
	r = one("old")
	if r.Action != "302" || r.Target != "https://new.com${1}?p=$$x" {
		t.Fatalf("redirect: %+v", r)
	}
	if got, _ := r.re.Replace("https://old.com/a/b", r.Target, -1, 1); got != "https://new.com/a/b?p=$x" {
		t.Fatalf("redirect result %q", got)
	}
	if r := one(`t\.me`); r.Action != "307" || r.Target != "tg://resolve?domain=${1}" {
		t.Fatalf("redirect with argument: %+v", r)
	}
	// One line, three actions in order.
	hs := lv2Find(rs, `h\.com`)
	if len(hs) != 3 || hs[0].Headers[0].Op != "del" || hs[0].Headers[1].Op != "add" || hs[0].Headers[1].Value != "true" ||
		len(hs[1].Headers) != 2 || hs[1].Headers[1].Name != "Referer" ||
		hs[2].Headers[0].Op != "replace-regex" || hs[2].Headers[0].Regex != `(?i)iPhone OS (\d+)` || hs[2].Headers[0].Value != "iPhone OS $1" {
		t.Fatalf("header actions: %+v %+v %+v", hs[0], hs[1], hs[2])
	}
	if r := one(`j\.com\/a`); r.Kind != KindJSON || r.Phase != "response" || len(r.JSON) != 2 || r.JSON[1].Op != "del" || r.JSON[1].Path != "data.banner" {
		t.Fatalf("json.delete: %+v", r)
	}
	r = one(`j\.com\/b`)
	want := []string{"true", "1", `"CN"`, `"true"`}
	for i, w := range want {
		if r.JSON[i].Op != "replace" || r.JSON[i].Value != w {
			t.Fatalf("json.replace %d: %+v", i, r.JSON[i])
		}
	}
	if r := one(`j\.com\/c`); r.Kind != KindJQ || r.JQ != `.data |= del(.ads) | .x = "a, b"` {
		t.Fatalf("jq (a | inside the string is not an action pipe): %+v", r)
	}
	if r := one(`j\.com\/d`); r.Kind != KindJQ || r.Data != "https://example.com/f.jq" {
		t.Fatalf("jq_file: %+v", r)
	}
	if r := one(`b\.com`); r.Kind != KindBody || len(r.Body) != 2 || r.Body[1].Regex != `"x":(\d)` || r.Body[1].Repl != `"y":$1` {
		t.Fatalf("body.replace: %+v", r)
	}
	r = one(`m\.com/ then`)
	if r.Kind != KindMapLocal || r.Status != 201 || r.Data != `{"code":0,"msg":"a|b"}` || r.RespHeaders["Content-Type"] != "application/json" || r.RespHeaders["X-Mock"] != "1" || r.DataType != "text" {
		t.Fatalf("mock: %+v", r)
	}
	if r := one(`m\.com\/f`); r.DataType != "file" || r.Data != "https://example.com/a.png" || r.RespHeaders["Content-Type"] != "image/png" {
		t.Fatalf("mock_file: %+v", r)
	}
	if r := one(`on\.com`); r.Action != "reject-200" || !r.match("https://on.com/") {
		t.Fatalf("switch argument true: %+v", r)
	}
	if rr := lv2Find(rs, `off\.com`); len(rr) != 0 {
		t.Fatalf("switch argument false must drop the line: %+v", rr)
	}
	r = one(`x\.com`)
	if !r.match("https://x.com/") || !r.match("https://Y.com/") || r.match("https://z.com/") {
		t.Fatalf("|| of URL regexes: %q", r.Pattern)
	}
	r = one(`z\.com`)
	if !r.match("https://z.com/?token=1") || r.match("https://z.com/") || r.match("https://a.com/?token=1") {
		t.Fatalf("&& of URL regexes: %q", r.Pattern)
	}
	if r := one("reject-dict"); r.Pattern != `^https:\/\/legacy\.com\/CN` {
		t.Fatalf("classic {key} substitution next to the new syntax: %q", r.Pattern)
	}
	for _, sub := range []string{"request.method", "local.jq", "request.body.mock", "bad.js"} {
		found := false
		for _, u := range rs.Unsupported {
			found = found || strings.Contains(u, sub)
		}
		if !found {
			t.Fatalf("%s should be reported unsupported: %q", sub, rs.Unsupported)
		}
	}
	if len(lv2Find(rs, `p\.com`)) != 0 {
		t.Fatal("a method condition must not widen into a URL-only rule")
	}
	if len(rs.Arguments) != 8 || rs.Arguments[4].Key != "Weather.Provider" {
		t.Fatalf("arguments: %+v", rs.Arguments)
	}
}

func TestLoonV2Scripts(t *testing.T) {
	rs := lv2Parse(t, lv2Plugin, map[string]string{"level": "3", "token": "abc"})
	r := lv2Find(rs, "s.js")
	if len(r) != 1 {
		t.Fatalf("script rules: %d", len(r))
	}
	sc := r[0].Script
	if r[0].Phase != "response" || sc.Type != "http-response" || sc.Name != "S 响应" || !sc.RequiresBody || !sc.BinaryBody || sc.Timeout != 30 || !sc.ArgObject {
		t.Fatalf("script: %+v %+v", r[0], sc)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(sc.Argument), &obj); err != nil {
		t.Fatal(err)
	}
	if obj["region"] != "CN" || obj["level"] != float64(3) || obj["enabled"] != true || obj["token"] != "abc" || obj["Weather.Provider"] != "ColorfulClouds" {
		t.Fatalf("object $argument: %s", sc.Argument)
	}
	if !strings.HasPrefix(sc.Argument, `{"region":`) {
		t.Fatalf("keys in the plugin's order: %s", sc.Argument)
	}
	if len(lv2Find(rs, "r.js")) != 0 {
		t.Fatal("enable=${blockFeed} (false) must drop the script")
	}
	if q := lv2Find(rs, "q.js"); len(q) != 1 || q[0].Script.Timeout != 20 || q[0].Script.HasArgument || q[0].Script.Name != "q" {
		t.Fatalf("defaults: %+v", q)
	}
	if l := lv2Find(rs, "l.js"); len(l) != 1 || l[0].Script.Argument != `{"region":"CN","level":3}` {
		t.Fatalf("classic script line beside the new syntax: %+v", l)
	}
	var cron, generic, event *Task
	for _, tk := range rs.Tasks {
		switch tk.Kind {
		case TaskCron:
			cron = tk
		case TaskGeneric:
			generic = tk
		case TaskEvent:
			event = tk
		}
	}
	if cron == nil || cron.Cron != "0 8 * * *" || cron.Script.Name != "签到" || cron.Script.Timeout != 120 || cron.Script.Argument != `{"token":"abc"}` {
		t.Fatalf("cron: %+v", cron)
	}
	if generic == nil || !generic.DisabledByLine || generic.Icon != "https://example.com/t.png" || generic.Script.Name != "工具" {
		t.Fatalf("generic: %+v", generic)
	}
	if event == nil || event.Script.Timeout != 300 {
		t.Fatalf("network-changed: %+v", event)
	}
	// String argument with a template.
	rs = lv2Parse(t, lv2Plugin, map[string]string{"blockFeed": "true", "region": "US"})
	if r := lv2Find(rs, "r.js"); len(r) != 1 || r[0].Script.Argument != "a=1&b=US" || r[0].Script.ArgObject {
		t.Fatalf("string argument: %+v", r)
	}
	if r := lv2Find(rs, `off\.com`); len(r) != 1 {
		t.Fatal("switch on by the user enables the rewrite")
	}
	// Empty input / no-value argument inside an object is null (Loon).
	rs = lv2Parse(t, lv2Plugin, nil)
	if r := lv2Find(rs, "s.js"); !strings.Contains(r[0].Script.Argument, `"token":null`) {
		t.Fatalf("no value → null: %s", r[0].Script.Argument)
	}
}

func TestLoonV2Errors(t *testing.T) {
	for _, l := range []string{
		`request if ${url} ~= /a/ then reject_dict()`,
		`request if ${url} ~= /a/ then nope(1)`,
		`request if ${missing} == true then reject(200)`,
		`request if ${url} ~= /a/ then response.json.delete("x")`,
		`request if ${url} ~= /a/ then request.header.set(["A", "B"], "1")`,
		`request if ${url} ~= /a/ || ${url} ~= /b/ then redirect(302, "https://x")`,
		`request if ${url} ~= /a/ then script("a.js") with what=1`,
		`request if ${url} ~= "a then reject(200)`,
		`request if ${response.status} == 200 then reject(200)`,
		`request if ${enabled} == true then script("a.js")`,
	} {
		rs := &Ruleset{}
		rs.ParseLine(l, "rewrite", "用户")
		if len(rs.Rules) != 0 || len(rs.Errors) != 1 {
			t.Fatalf("%s → rules %d errors %q unsupported %q", l, len(rs.Rules), rs.Errors, rs.Unsupported)
		}
	}
	// Single lines from the rule editor (no plugin arguments) work too.
	rs := &Ruleset{}
	rs.ParseLine(`request if ${url} ~= /^https:\/\/a\.com/ then reject_dict(200)`, "", "用户")
	if len(rs.Rules) != 1 || rs.Rules[0].Action != "reject-dict" {
		t.Fatalf("editor line: %+v %q", rs.Rules, rs.Errors)
	}
	// Classic lines that only look similar stay classic.
	for _, l := range []string{`http-request ^https://a script-path=a.js`, `cron "0 8 * * *" script-path=a.js`, `request ^https://a header-del Cookie`} {
		if IsLoonV2Line(l) {
			t.Fatalf("%s is classic syntax", l)
		}
	}
}

// A plugin that only has [Script] lines in the new syntax is still detected as Loon.
func TestLoonV2FormatDetection(t *testing.T) {
	rs := lv2Parse(t, "#!name=x\n[Script]\nrequest if ${url} ~= /^https:\\/\\/a/ then script(\"https://e.com/a.js\")\n[MitM]\nhostname = a\n", nil)
	if rs.Format != "loon" || len(rs.Rules) != 1 {
		t.Fatalf("format %q rules %d errors %q", rs.Format, len(rs.Rules), rs.Errors)
	}
}
