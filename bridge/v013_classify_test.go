package libmihomo

import "testing"

func TestV013ClassifyStashRulesOnly(t *testing.T) {
	if got := ClassifyText("name: Stash\nrules:\n  - DOMAIN-SUFFIX,a.com,REJECT\nrule-providers:\n  x:\n    behavior: domain\n    url: https://e.com/x.yaml\n"); got != "module:stash" {
		t.Fatalf("got %q", got)
	}
	if got := ClassifyText("proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: p}\nrules:\n  - MATCH,DIRECT\n"); got != "profile" {
		t.Fatalf("profile got %q", got)
	}
}
