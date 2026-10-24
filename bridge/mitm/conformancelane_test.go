package mitm

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// laneConformanceCases: text / binary bodies × every lane encoding × small / ≥ 64 KB results, untouched
// $done($response), $done({}), the body handed back as is, a BOM and invalid UTF-8 in text mode.
func laneConformanceCases() []ConformanceCase {
	small := `{"ad":true,"items":[1,2,3],"s":"中文"}`
	large := `{"ad":true,"pad":"` + strings.Repeat("abcdefghij", 9000) + `"}` // 90 KB: the result is a lane put
	bin := make([]byte, 70<<10)
	for i := range bin {
		bin[i] = byte(i*7 + i>>8)
	}
	type body struct {
		name, text string
		b64        bool
	}
	bodies := []body{
		{"small", small, false},
		{"large", large, false},
		{"bom", "\ufeff" + small, false},
		{"badutf8", "{\"a\":\"\xff\xfe\"}", false},
	}
	scripts := map[string]string{
		"replace":   `$done({body: $response.body.replace(/"ad":true/g, '"ad":false') + "/" + $response.body.length});`,
		"untouched": `$done($response);`,
		"empty":     `$done({});`,
		"same":      `$done({body: $response.body});`,
		"headers":   `$done({headers: Object.assign({}, $response.headers, {"X-L": String($response.body.length)})});`,
	}
	var cases []ConformanceCase
	for _, enc := range []string{"", "gzip", "deflate", "br"} {
		for _, b := range bodies {
			for sn, code := range scripts {
				cases = append(cases, ConformanceCase{
					Name: fmt.Sprintf("lane-%s-%s-%s", orNone(enc), b.name, sn), Lane: true, Encoding: enc,
					Input: DebugInput{Code: code, Type: "http-response", Response: &DebugHTTP{Status: 200,
						Headers: map[string]string{"Content-Type": "application/json"}, Body: b.text}},
				})
			}
		}
		cases = append(cases, ConformanceCase{
			Name: "lane-" + orNone(enc) + "-binary", Lane: true, Encoding: enc, Repeat: 2,
			Input: DebugInput{Type: "http-response", Binary: true,
				Code:     `var u = new Uint8Array($response.bodyBytes); var o = new Uint8Array(u.length); for (var i = 0; i < u.length; i++) o[i] = u[i] ^ 0x5a; $done({bodyBytes: o});`,
				Response: &DebugHTTP{Status: 200, Body: base64.StdEncoding.EncodeToString(bin), BodyBase64: true}},
		})
	}
	return cases
}

// TestEngineConformanceLane: lane cases give the same output on the native engine (through the lane, fake
// store) as on goja (plain bytes), the native engine really reads / stores lane bodies, and no handle is left.
func TestEngineConformanceLane(t *testing.T) {
	l := useFakeLane(t)
	home := t.TempDir()
	for _, c := range laneConformanceCases() {
		r := RunConformance(home, c, true)
		if !r.OK {
			t.Errorf("%s: missing %q\n%s", c.Name, r.Missing, r.Diff)
		}
		if r.LaneLive != 0 || l.live() != 0 {
			t.Fatalf("%s: lane handles left: go %d, store %d", c.Name, r.LaneLive, l.live())
		}
	}
	if l.opened.Load() == 0 || l.engineTakes.Load() == 0 || l.stored.Load() == 0 {
		t.Fatalf("lane not exercised: opened %d, engine takes %d, stored %d", l.opened.Load(), l.engineTakes.Load(), l.stored.Load())
	}
	t.Logf("lane conformance: opened %d, engine takes %d, stored %d", l.opened.Load(), l.engineTakes.Load(), l.stored.Load())
}

// TestEngineConformanceLaneNotRegistered: a lane case without a lane fails when the native engine is required.
func TestEngineConformanceLaneNotRegistered(t *testing.T) {
	old, _ := nativeJS.Load().(nativeBox)
	if msg := SetNativeEngine(newFakeNative()); msg != "" {
		t.Fatal(msg)
	}
	defer func() {
		if old.n != nil {
			nativeJS.Store(old)
		} else {
			SetNativeEngine(nil)
		}
	}()
	c := laneConformanceCases()[0]
	if r := RunConformance(t.TempDir(), c, true); r.OK || !strings.Contains(r.Diff, "lane not registered") {
		t.Fatalf("%+v", r)
	}
	if r := RunConformance(t.TempDir(), c, false); !r.OK {
		t.Fatalf("not required: %+v", r)
	}
}
