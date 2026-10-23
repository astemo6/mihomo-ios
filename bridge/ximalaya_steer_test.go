package libmihomo

import (
	"net/netip"
	"os"
	"testing"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
)

// TestXimalayaSteeringMatchesIPOnlyConnections (v0.19.17 喜马拉雅): evaluates the injected __mitm_hosts
// payload with mihomo's own rule parser. 喜马拉雅 resolves through HTTPDNS, so its connections reach
// mihomo as a bare destination IP (no host; with sniffing off or no SNI there is no sniffed host
// either). The module's IP wildcards (180.153.*.*, 114.80.139.2*) must select those connections —
// as DOMAIN-WILDCARD they never did, the connection went straight out and no rewrite ran.
func TestXimalayaSteeringMatchesIPOnlyConnections(t *testing.T) {
	b, err := os.ReadFile("mitm/testdata/ximalaya_weigiegie.js")
	if err != nil {
		t.Fatal(err)
	}
	rs := &mitm.Ruleset{}
	rs.ParseText(string(b), "喜马拉雅", nil)
	raw := map[string]any{"rules": []any{"MATCH,DIRECT"}}
	mitm.Inject(raw, 12345, rs, &mitm.Config{Enabled: true, MitM: true})
	payload := raw["rule-providers"].(map[string]any)["__mitm_hosts"].(map[string]any)["payload"].([]any)
	var parsed []C.Rule
	for _, l := range payload {
		tp, pl, target, params := RC.ParseRulePayload(l.(string), false)
		r, err := rules.ParseRule(tp, pl, target, params, nil)
		if err != nil {
			t.Fatalf("mihomo rejects payload line %q: %v", l, err)
		}
		parsed = append(parsed, r)
	}
	match := func(m *C.Metadata) bool {
		for _, r := range parsed {
			if ok, _ := r.Match(m, C.RuleMatchHelper{}); ok {
				return true
			}
		}
		return false
	}
	ipOnly := func(ip string) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr(ip), DstPort: 443}
	}
	for _, ip := range []string{"180.153.10.20", "114.80.139.25", "114.80.139.2", "114.80.139.237", "211.152.137.25", "112.99.146.108", "203.205.136.87", "120.229.25.1"} {
		if !match(ipOnly(ip)) {
			t.Errorf("IP-only connection to %s not steered into the engine", ip)
		}
	}
	for _, ip := range []string{"114.80.139.3", "8.8.8.8", "180.154.0.1"} {
		if match(ipOnly(ip)) {
			t.Errorf("IP-only connection to %s steered", ip)
		}
	}
	if !match(&C.Metadata{NetWork: C.TCP, Host: "mobile.ximalaya.com", DstPort: 443}) ||
		!match(&C.Metadata{NetWork: C.TCP, Host: "aod.cos.tx.xmcdn.com", DstPort: 443}) {
		t.Error("domain connections not steered")
	}
	// fake-ip: mihomo clears DstIP and keeps the host, so 198.18.1*.* in the list does not pull every
	// fake-ip connection into the engine.
	if match(&C.Metadata{NetWork: C.TCP, Host: "www.apple.com", DstPort: 443}) {
		t.Error("unrelated domain steered")
	}
}
