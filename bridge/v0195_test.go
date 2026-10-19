package libmihomo

// v0.19.5: override-script output kept dns.nameserver-policy sorted by key (Go map on both sides of the
// script); mihomo uses the first matching entry. Placeholders only.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func v0195Order(t *testing.T, s string, keys ...string) {
	t.Helper()
	last := -1
	for _, k := range keys {
		i := strings.Index(s, k)
		if i < 0 || i < last {
			t.Fatalf("order of %v lost (at %q):\n%s", keys, k, s)
		}
		last = i
	}
}

func TestV0195ScriptKeepsNameserverPolicyOrder(t *testing.T) {
	home := v0194Home(t)
	profile := []byte(`proxies:
  - {name: a, type: ss, server: a.example.com, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [a]}
dns:
  enable: true
  nameserver: [223.5.5.5]
  nameserver-policy:
    "rule-set:corp": 10.0.0.1
    "+.z.example.com": 10.0.0.2
    "geosite:cn": 223.5.5.5
rule-providers:
  corp: {type: inline, behavior: domain, payload: [corp.example.com]}
rules:
  - MATCH,DIRECT
`)
	p := v0194Write(t, home, "ns.yaml", profile)
	in, err := ScriptInput(p)
	if err != nil {
		t.Fatal(err)
	}
	// the script sees the profile's order
	v0195Order(t, in, "rule-set:corp", "+.z.example.com", "geosite:cn")

	// identity, then a script that inserts entries in its own order (first and last)
	for _, src := range []string{
		`function main(c) { return c; }`,
		`function main(c) { const p = c.dns['nameserver-policy']; const n = { '+.b.example.com': '10.0.0.7' };
		   for (const k of Object.keys(p)) n[k] = p[k]; n['+.a.example.com'] = '10.0.0.8'; c.dns['nameserver-policy'] = n; return c; }`,
	} {
		out := v0194RunOverride(t, src, in, nil)
		if msg := ScriptOutputApply(home, p, out, `["t"]`); msg != "" {
			t.Fatalf("apply: %s", msg)
		}
		y := ScriptOutputYAML(home, p)
		if strings.Contains(src, "b.example.com") {
			v0195Order(t, y, "+.b.example.com", "rule-set:corp", "+.z.example.com", "geosite:cn", "+.a.example.com")
		} else {
			v0195Order(t, y, "rule-set:corp", "+.z.example.com", "geosite:cn")
		}
		// and through to the runtime config the core gets
		rp, err := readRuntimeProfile(home, p, false)
		if err != nil {
			t.Fatal(err)
		}
		rt, err := buildRuntime(rp, Overrides{Mode: "rule"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(src, "b.example.com") {
			v0195Order(t, string(rt), "+.b.example.com", "rule-set:corp", "+.z.example.com", "geosite:cn", "+.a.example.com")
		} else {
			v0195Order(t, string(rt), "rule-set:corp", "+.z.example.com", "geosite:cn")
		}
	}
	_ = os.RemoveAll(filepath.Join(home, "scripted"))
}

// Values that are lists / maps and keys with JSON escapes survive the ordered round trip.
func TestV0195OrderedJSONObject(t *testing.T) {
	m := map[string]any{"b\"q": []any{"1.1.1.1", "8.8.8.8"}, "a": map[string]any{"x": 1}}
	b, err := orderedJSONObject{keys: []string{"b\"q", "a"}, vals: m}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"b\"q":["1.1.1.1","8.8.8.8"],"a":{"x":1}}` {
		t.Fatalf("got %s", b)
	}
	y, err := scriptOutputYAML(`{"dns":{"nameserver-policy":{"z.example.com":["1.1.1.1"],"a.example.com":"8.8.8.8","m\"x":"9.9.9.9"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	v0195Order(t, string(y), "z.example.com", "a.example.com", `m"x`)
}
