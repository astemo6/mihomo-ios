package mitm

import (
	"strings"
	"testing"
)

// Merge of feat/substore with review5 (main): a requires-body script with max-size=-1 still receives a
// request body between MaxBody and MaxScriptBody (Sub-Store backups), while a body rewrite on the same
// flow keeps the 2 MB MaxBody cap and a default script (max-size=0) is skipped.
func TestMergeScriptBodyCapAboveMaxBody(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-request,pattern=^https://api\.test\.com/echo\?big=1,requires-body=1,max-size=-1,script-path=big.js`,
		`small = type=http-request,pattern=^https://api\.test\.com/echo\?small=1,requires-body=1,script-path=big.js`)}
	js := `$done({body: JSON.stringify({len: $request.body.length})})`
	h := newHarness(t, cfg, map[string]string{"big.js": js})
	payload := strings.Repeat("a", MaxBody+(512<<10)) // 2.5 MB
	_, body := h.do("POST", "https://api.test.com/echo?big=1", payload)
	if !strings.Contains(body, `\"len\":2621440`) && !strings.Contains(body, `"len":2621440`) {
		t.Fatalf("max-size=-1 script did not get the 2.5 MB body: %s", clip(body, 300))
	}
	_, body = h.do("POST", "https://api.test.com/echo?small=1", payload)
	if strings.Contains(body, `len`) {
		t.Fatalf("default script must skip a body above MaxBody: %s", clip(body, 300))
	}
	if len(body) < MaxBody {
		t.Fatalf("skipped body must pass through untruncated, got %d bytes", len(body))
	}
	if scriptBodyLimit(&Script{MaxSize: -1}) != MaxScriptBody || scriptBodyLimit(&Script{}) != MaxBody {
		t.Fatal("scriptBodyLimit caps")
	}
}
