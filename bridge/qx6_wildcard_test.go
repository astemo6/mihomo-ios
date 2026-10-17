package libmihomo

import "testing"

func TestQXWildcardFix(t *testing.T) {
	for in, want := range map[string]string{
		"*testflight.apple.com": "+.testflight.apple.com",
		"*.apple.com":           "+.apple.com",
		"apple.com":             "+.apple.com",
		"a*b.example.com":       "+.example.com",
		"+.lan":                 "+.lan",
	} {
		if got := qxPolicyDomain(in); got != want {
			t.Errorf("qxPolicyDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if got := qxHostDomain("*testflight.apple.com"); got != "+.testflight.apple.com" {
		t.Errorf("qxHostDomain = %q", got)
	}
}
