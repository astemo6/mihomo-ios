package libmihomo

import "testing"

// Review 5 P1-2: legacy ss:// base64 links and subscription path tokens in free text.
func TestRedactShareLinks(t *testing.T) {
	r := newRedactor()
	cases := map[string]string{
		"import: start n:ss://YWVzLTEyOC1nY206cHdAMS4yLjMuNDo0NDM=#hk":           "import: start n:ss://<redacted>#hk",
		"fetch https://sub.example.com/link/AbCdEf123456XyZ ok":                  "fetch https://sub.example.com/link/<redacted> ok",
		"fetch https://sub.example.com/s/q8w7e6r5t4 ok":                          "fetch https://sub.example.com/s/<redacted> ok",
		"get https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/x.mrs": "get https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/x.mrs",
	}
	for in, want := range cases {
		if got := r.text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
}
