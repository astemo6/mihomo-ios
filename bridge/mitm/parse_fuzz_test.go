package mitm

import (
	"os"
	"strings"
	"testing"
)

// FuzzParseText: module / plugin / rewrite text from a subscription (Surge, Loon incl. .lpx, Quantumult X,
// Egern YAML) must never panic the parser — it runs in the extension on every reload.
func FuzzParseText(f *testing.F) {
	for _, name := range []string{"testdata/yt_ddgksf2013_qx.conf", "testdata/yt_enhance.sgmodule", "testdata/yt_loon.plugin"} {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("[Script]\nx = type=http-response,pattern=^https://a,requires-body=1,max-size=-1,script-path=a.js\n[MITM]\nhostname = %APPEND% a.com")
	f.Add("[rewrite_local]\n^https://a url script-response-body https://x/a.js\n^https://b url reject-200\n[mitm]\nhostname = *.a.com")
	f.Add("[Rewrite]\n^https://a response if body.json then json.delete(\"a\") | header.del(x)\n[Script]\nhttp-response ^https://a script-path=a.js, requires-body=true, tag=a\n")
	f.Add("name: x\nmitm:\n  hostnames:\n    includes: [a.com]\nscriptings:\n  - http_response:\n      name: a\n      match: ^https://a\n      script_url: https://x/a.js\n      body_required: true\n      max_size: 100\n")
	f.Add("#!arguments=a:1,b:\"x\"\n#!arguments-desc=...\n[Argument]\nk = switch,true,false,tag=K\n")
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 64<<10 {
			return
		}
		rs := &Ruleset{}
		rs.ParseText(text, "fuzz", map[string]string{"a": "1"})
		_ = ParseModuleArgs(text)
		for _, r := range rs.Rules {
			if r.Kind == KindScript && r.Script == nil {
				t.Fatalf("script rule without a script: %q", r.Line)
			}
			_ = r.match("https://a.com/x?y=1")
		}
		_ = strings.Join(rs.Hostnames, ",")
	})
}
