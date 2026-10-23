package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

// feat/tunnel-include-options: 阻止 WebRTC rejects every STUN / TURN UDP whatever the policy; Apple (FaceTime) is
// exempt from it and from 直连时丢弃 STUN.

func stunMD(t *testing.T, network C.NetWork, addr, host string) *C.Metadata {
	t.Helper()
	md := &C.Metadata{NetWork: network, Type: C.TUN}
	if err := md.SetRemoteAddress(addr); err != nil {
		t.Fatal(err)
	}
	md.Host = host // fake-ip: the name restored next to the (fake) address
	return md
}

func TestBlockWebRTCRule(t *testing.T) {
	r := stunDropRule{all: true}
	if r.Payload() != "WebRTC" || r.Adapter() != "REJECT" || r.RuleType() != C.Network {
		t.Fatal("WebRTC rule identity (controller shows Network(WebRTC) → REJECT)")
	}
	// Rejected whatever the rules would pick (no live rules needed: the look-ahead is skipped).
	for _, a := range []string{"203.0.113.9:3478", "203.0.113.9:3479", "203.0.113.9:5349", "203.0.113.9:5350",
		"74.125.250.129:19302", "74.125.250.129:19309", "[2001:db8::1]:3478"} {
		if ok, ada := r.Match(stunMD(t, C.UDP, a, ""), C.RuleMatchHelper{}); !ok || ada != "REJECT" {
			t.Errorf("%s: STUN/TURN should be rejected, got %v %q", a, ok, ada)
		}
	}
	if ok, _ := r.Match(stunMD(t, C.UDP, "203.0.113.9:3478", "stun.l.google.com"), C.RuleMatchHelper{}); !ok {
		t.Error("STUN by domain should be rejected")
	}
	// Not STUN / not UDP / the core's own traffic.
	inner := stunMD(t, C.UDP, "203.0.113.9:3478", "")
	inner.Type = C.INNER
	for _, md := range []*C.Metadata{
		stunMD(t, C.TCP, "203.0.113.9:3478", ""),
		stunMD(t, C.UDP, "203.0.113.9:443", ""),
		stunMD(t, C.UDP, "203.0.113.9:3480", ""),
		inner,
	} {
		if ok, _ := r.Match(md, C.RuleMatchHelper{}); ok {
			t.Errorf("must not match %v %v", md.NetWork, md.RemoteAddress())
		}
	}
	// FaceTime: Apple addresses and names pass, for both switches (直连时丢弃 STUN returns before its look-ahead).
	apple := []*C.Metadata{
		stunMD(t, C.UDP, "17.188.180.10:3478", ""),
		stunMD(t, C.UDP, "17.252.1.1:3479", ""),
		stunMD(t, C.UDP, "[2620:149:a44::1]:3478", ""),
		stunMD(t, C.UDP, "[2403:300:a0c::1]:3478", ""),
		stunMD(t, C.UDP, "[::ffff:17.1.2.3]:3478", ""),
		stunMD(t, C.UDP, "198.18.0.9:3478", "relay.facetime.apple.com"),
		stunMD(t, C.UDP, "198.18.0.9:3478", "ICLOUD.COM."),
	}
	for _, md := range apple {
		for _, rule := range []stunDropRule{{all: true}, {}} {
			if ok, _ := rule.Match(md, C.RuleMatchHelper{}); ok {
				t.Errorf("Apple destination %v %q must pass (all=%v)", md.RemoteAddress(), md.Host, rule.all)
			}
		}
	}
	if isAppleDest(stunMD(t, C.UDP, "18.0.0.1:3478", "notapple.com")) || isAppleDest(stunMD(t, C.UDP, "1.2.3.4:3478", "apple.com.evil.test")) {
		t.Error("non-Apple destination counted as Apple")
	}
}

func TestBlockWebRTCOption(t *testing.T) {
	parse := func() int {
		cfg, err := executor.ParseWithBytes([]byte(fmtProfile(stunProfile, "MATCH,PU")))
		if err != nil {
			t.Fatal(err)
		}
		n := len(cfg.Rules)
		return n
	}
	n := parse()
	for _, c := range []struct {
		direct, all bool
		payload     string
	}{{false, true, "WebRTC"}, {true, true, "WebRTC"}, {true, false, "STUN"}} {
		cfg, _ := executor.ParseWithBytes([]byte(fmtProfile(stunProfile, "MATCH,PU")))
		stunDropOption(c.direct, c.all)(cfg)
		stunDropOption(c.direct, c.all)(cfg)
		if len(cfg.Rules) != n+1 || !isSTUNDropRule(cfg.Rules[0]) || isSTUNDropRule(cfg.Rules[1]) {
			t.Fatalf("direct=%v all=%v: one STUN rule first, got %d rules", c.direct, c.all, len(cfg.Rules))
		}
		if p := cfg.Rules[0].Payload(); p != c.payload {
			t.Fatalf("direct=%v all=%v: payload %q, want %q (阻止 WebRTC supersedes)", c.direct, c.all, p, c.payload)
		}
	}
	cfg, _ := executor.ParseWithBytes([]byte(fmtProfile(stunProfile, "MATCH,PU")))
	stunDropOption(false, false)(cfg)
	if len(cfg.Rules) != n {
		t.Fatal("both off must not insert")
	}
}

// End to end through Start: 阻止 WebRTC + FaceTime 走代理. Proxied STUN is rejected, FaceTime's STUN to Apple passes
// the WebRTC rule and reaches the FaceTime rule (main proxy group).
func TestBlockWebRTCThroughCore(t *testing.T) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = freeTCPPort(t)
	ov.Secret = "s"
	ov.MixedPort = freeTCPPort(t)
	ov.BlockWebRTC = true
	ov.StunDropDirect = true
	ov.FaceTimeProxy = true
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte("mode: rule\nproxies:\n  - {name: T, type: ss, server: 127.0.0.1, port: "+strconv.Itoa(freeTCPPort(t))+
		", cipher: aes-128-gcm, password: x, udp: true}\nproxy-groups:\n  - {name: G, type: select, proxies: [T]}\nrules:\n  - MATCH,G\n"), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	rules := tunnel.Rules()
	if len(rules) < 2 || !isSTUNDropRule(rules[0]) || rules[0].Payload() != "WebRTC" {
		t.Fatalf("WebRTC rule not first in the live rules: %v", rules)
	}
	for _, r := range rules[1:] {
		if isSTUNDropRule(r) {
			t.Fatal("直连时丢弃 STUN inserted next to 阻止 WebRTC")
		}
	}
	// Through the proxy group (直连时丢弃 STUN alone would let it pass): rejected.
	if ok, ada := rules[0].Match(stunMD(t, C.UDP, "203.0.113.9:3478", ""), C.RuleMatchHelper{}); !ok || ada != "REJECT" {
		t.Fatalf("proxied STUN should be rejected: %v %s", ok, ada)
	}
	// FaceTime: not the WebRTC rule; the first rule that matches is FaceTime 走代理's, to G.
	ft := stunMD(t, C.UDP, "17.188.180.10:3478", "")
	if ok, _ := rules[0].Match(ft, C.RuleMatchHelper{}); ok {
		t.Fatal("FaceTime STUN must not be rejected")
	}
	got := ""
	for _, r := range rules[1:] {
		if ok, ada := r.Match(ft, C.RuleMatchHelper{}); ok {
			got = ada
			break
		}
	}
	if got != "G" {
		t.Fatalf("FaceTime STUN should go to the proxy group, got %q", got)
	}
}
