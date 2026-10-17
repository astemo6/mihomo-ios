package mitm

import (
	"strings"
	"testing"
)

// v0.13 importer edge cases: Loon [Argument] and Stash .stoverride.
func TestV013LoonArgumentEdges(t *testing.T) {
	plugin := `#!name=参数测试
[Argument]
去广告 = switch,true,tag=去广告
pol = select,"DIRECT","REJECT",tag=策略
host = input,"a.example.com",tag=主机

[Rule]
DOMAIN,{host},{pol}
DOMAIN,ads.example.com,REJECT, enable = {去广告}

[Rewrite]
^https?:\/\/{{{host}}}\/ad - reject-200,enable={去广告}

[MITM]
hostname = {host}
`
	var rs Ruleset
	rs.ParseText(plugin, "t", nil)
	if len(rs.Arguments) != 3 || rs.Arguments[0].Key != "去广告" || rs.Arguments[0].Type != "switch" {
		t.Fatalf("args %+v", rs.Arguments)
	}
	if len(rs.Rules) != 1 || !strings.Contains(rs.Rules[0].Pattern, "a.example.com") {
		t.Fatalf("rewrite with {{{host}}} / enable: %+v", rs.Rules)
	}
	core := strings.Join(rs.CoreRules, "|")
	if !strings.Contains(core, "a.example.com") || !strings.Contains(core, "ads.example.com") {
		t.Fatalf("core rules %v (unsupported %v)", rs.CoreRules, rs.Unsupported)
	}
	if len(rs.Hostnames) != 1 || rs.Hostnames[0] != "a.example.com" {
		t.Fatalf("hosts %v", rs.Hostnames)
	}

	var off Ruleset
	off.ParseText(plugin, "t", map[string]string{"去广告": "false", "pol": "DIRECT"})
	if len(off.Rules) != 0 {
		t.Fatalf("switch off should drop the rewrite: %+v", off.Rules)
	}
	for _, r := range off.CoreRules {
		if strings.Contains(r, "ads.example.com") {
			t.Fatalf("switch off should drop the rule: %v", off.CoreRules)
		}
	}
}

func TestV013StashOverrideEdges(t *testing.T) {
	ov := `name: Stash 规则覆写
desc: rules only
rules#!replace:
  - RULE-SET,ads,REJECT
  - RULE-SET,cidr,DIRECT
  - RULE-SET,bin,REJECT
  - DOMAIN-SUFFIX,example.org,DIRECT
rule-providers:
  ads:
    behavior: domain
    url: https://example.com/ads.yaml
    interval: 86400
  cidr:
    behavior: ipcidr
    url: https://example.com/cidr.txt
    format: text
  bin:
    behavior: domain
    format: mrs
    url: https://example.com/ads.mrs
http:
  mitm#!append:
    - "api.example.com"
    - "-skip.example.com"
  script:
    - match: ^https://api\.example\.com/v1
      name: fix
      type: response
      require-body: true
script-providers:
  fix:
    url: https://example.com/fix.js
    interval: 86400
`
	var rs Ruleset
	rs.ParseText(ov, "t", nil)
	if rs.Format != "stash" || rs.Name != "Stash 规则覆写" {
		t.Fatalf("format %q name %q", rs.Format, rs.Name)
	}
	core := strings.Join(rs.CoreRules, "\n")
	if !strings.Contains(core, "DOMAIN-SET,https://example.com/ads.yaml,REJECT") || !strings.Contains(core, "RULE-SET,https://example.com/cidr.txt,DIRECT") {
		t.Fatalf("providers not resolved: %v (unsupported %v, errors %v)", rs.CoreRules, rs.Unsupported, rs.Errors)
	}
	if len(rs.Unsupported) != 1 || !strings.Contains(rs.Unsupported[0], "mrs") {
		t.Fatalf("mrs should be reported: %v", rs.Unsupported)
	}
	if len(rs.Hostnames) != 2 || len(rs.Rules) != 1 || rs.Rules[0].Phase != "response" {
		t.Fatalf("hosts %v rules %+v errors %v", rs.Hostnames, rs.Rules, rs.Errors)
	}

	// rules-only override is still recognised as Stash.
	var only Ruleset
	only.ParseText("rules:\n  - DOMAIN,a.example.com,REJECT\n", "t", nil)
	if only.Format != "stash" || len(only.CoreRules) != 1 {
		t.Fatalf("rules-only: %q %v", only.Format, only.CoreRules)
	}
}

func TestV013BareCIDRListLines(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.0/24":    "IP-CIDR,1.2.3.0/24,no-resolve",
		"- '10.0.0.1'":  "IP-CIDR,10.0.0.1/32,no-resolve",
		"2001:db8::/32": "IP-CIDR6,2001:db8::/32,no-resolve",
		"example.com":   "DOMAIN,example.com",
	} {
		if got, ok := ConvertListLine(in, "list"); !ok || got != want {
			t.Fatalf("%q → %q (%v), want %q", in, got, ok, want)
		}
	}
}

func TestV013IsStashExported(t *testing.T) {
	if !IsStash("name: x\nrules#!replace:\n  - DOMAIN,a.com,REJECT\n") || IsStash("[Rule]\nDOMAIN,a.com,REJECT\n") {
		t.Fatal("IsStash")
	}
}
