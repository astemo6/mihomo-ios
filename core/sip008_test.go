package libmihomo

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

const sip008Sample = `{
  "version": 1,
  "servers": [
    {"id":"27b8a625-4f4b-4428-9f0f-8a2317db7c79","remarks":"Plain","server":"1.2.3.4","server_port":8388,"password":"pw1","method":"chacha20-ietf-poly1305"},
    {"id":"7842c068-c667-41f2-8f7d-04feece3cb67","remarks":"Obfs","server":"ss.example.com","server_port":"8389","password":"pw2","method":"aes-256-gcm","plugin":"obfs-local","plugin_opts":"obfs=tls;obfs-host=www.bing.com"},
    {"id":"a2","remarks":"SimpleObfs","server":"5.6.7.8","server_port":443,"password":"pw3","method":"aes-128-gcm","plugin":"simple-obfs","plugin_opts":"obfs=http"},
    {"id":"a3","remarks":"V2","server":"v2.example.com","server_port":443,"password":"pw4","method":"aes-256-gcm","plugin":"v2ray-plugin","plugin_opts":"tls;host=cdn.example.com;path=/ws;mux=0"},
    {"id":"a4-no-remarks","server":"9.9.9.9","server_port":8388,"password":"AAAAAAAAAAAAAAAAAAAAAA==","method":"2022-blake3-aes-128-gcm"}
  ],
  "bytes_used": 274877906944,
  "bytes_remaining": 824633720832
}`

func TestSIP008Parse(t *testing.T) {
	ps, errs, ok := parseSIP008(sip008Sample)
	if !ok || len(errs) != 0 || len(ps) != 5 {
		t.Fatalf("ok=%v errs=%v n=%d", ok, errs, len(ps))
	}
	byName := map[string]map[string]any{}
	for _, p := range ps {
		if p["type"] != "ss" {
			t.Fatalf("type %v", p)
		}
		byName[p["name"].(string)] = p
	}
	if p := byName["Plain"]; p["server"] != "1.2.3.4" || p["port"] != 8388 || p["cipher"] != "chacha20-ietf-poly1305" || p["password"] != "pw1" || p["plugin"] != nil {
		t.Fatalf("plain %v", p)
	}
	o := byName["Obfs"]
	if o["port"] != 8389 || o["plugin"] != "obfs" {
		t.Fatalf("obfs %v", o)
	}
	if po := o["plugin-opts"].(map[string]any); po["mode"] != "tls" || po["host"] != "www.bing.com" {
		t.Fatalf("obfs opts %v", po)
	}
	if po := byName["SimpleObfs"]["plugin-opts"].(map[string]any); byName["SimpleObfs"]["plugin"] != "obfs" || po["mode"] != "http" {
		t.Fatalf("simple-obfs %v", byName["SimpleObfs"])
	}
	v := byName["V2"]
	po := v["plugin-opts"].(map[string]any)
	if v["plugin"] != "v2ray-plugin" || po["mode"] != "websocket" || po["tls"] != true || po["host"] != "cdn.example.com" || po["path"] != "/ws" || po["mux"] != false {
		t.Fatalf("v2ray %v", v)
	}
	if byName["a4-no-remarks"] == nil {
		t.Fatalf("id fallback name missing: %v", byName)
	}
}

func TestSIP008Classify(t *testing.T) {
	if got := ClassifyText(sip008Sample); got != "nodes" {
		t.Fatalf("ClassifyText=%q", got)
	}
	if got := ClassifyText("\ufeff" + sip008Sample); got != "nodes" {
		t.Fatalf("ClassifyText BOM=%q", got)
	}
	// Bare array form (lenient).
	arr := `[{"server":"1.2.3.4","server_port":8388,"password":"p","method":"aes-128-gcm","remarks":"A"}]`
	if got := ClassifyText(arr); got != "nodes" {
		t.Fatalf("ClassifyText array=%q", got)
	}
	// Unrelated JSON must not be classified as nodes.
	for _, s := range []string{`{"version":1}`, `{"foo":"bar"}`, `[1,2,3]`, `{"servers":[]}`} {
		if got := ClassifyText(s); got == "nodes" {
			t.Fatalf("%s classified as nodes", s)
		}
	}
}

func TestSIP008Errors(t *testing.T) {
	doc := `{"version":1,"servers":[
	  {"remarks":"ok","server":"1.2.3.4","server_port":8388,"password":"p","method":"aes-128-gcm"},
	  {"remarks":"quic","server":"1.2.3.4","server_port":8388,"password":"p","method":"aes-128-gcm","plugin":"v2ray-plugin","plugin_opts":"mode=quic"},
	  {"remarks":"kcp","server":"1.2.3.4","server_port":8388,"password":"p","method":"aes-128-gcm","plugin":"kcptun"},
	  {"remarks":"noport","server":"1.2.3.4","password":"p","method":"aes-128-gcm"}
	]}`
	ps, errs := parseNodeText(doc)
	if len(ps) != 1 || len(errs) != 3 {
		t.Fatalf("ps=%d errs=%v", len(ps), errs)
	}
}

func TestSIP003Opts(t *testing.T) {
	kv := sip003Opts(`tls;host=a\;b.com;path=/x\=y; mux = 4`)
	if _, ok := kv["tls"]; !ok || kv["host"] != "a;b.com" || kv["path"] != "/x=y" || kv["mux"] != "4" {
		t.Fatalf("%v", kv)
	}
}

func TestSIP008ConvertShareLinks(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	y := ConvertShareLinks(sip008Sample)
	if y == "" {
		t.Fatalf("ConvertShareLinks failed: %s", LastError())
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(y), &cfg); err != nil {
		t.Fatal(err)
	}
	if px, _ := cfg["proxies"].([]any); len(px) != 5 {
		t.Fatalf("proxies %v", cfg["proxies"])
	}
	if !strings.Contains(y, "v2ray-plugin") || !strings.Contains(y, "plugin-opts") {
		t.Fatalf("plugin missing:\n%s", y)
	}
	if e := validateBytes([]byte(y)); e != "" {
		t.Fatalf("mihomo rejected converted config: %s\n%s", e, y)
	}
	// Each node also round-trips through the manual-node path (core proxy parser).
	var nodes []map[string]any
	if err := json.Unmarshal([]byte(ParseNodes(sip008Sample)), &nodes); err != nil || len(nodes) != 5 {
		t.Fatalf("ParseNodes %v %s", err, LastError())
	}
	for _, n := range nodes {
		b, _ := json.Marshal(n)
		if e := ManualUpsert(filepath.Join(t.TempDir(), "m.yaml"), string(b), ""); e != "" {
			t.Fatalf("core rejected %s: %s", b, e)
		}
	}
}
