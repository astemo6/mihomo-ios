package libmihomo

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"go.yaml.in/yaml/v3"
)

func TestLoonUDPFallbackReject(t *testing.T) {
	def := asList(v07Build(t, "", map[string]string{})["rules"])
	for _, r := range def {
		if str(r) == UDPFallbackRejectRule {
			t.Fatalf("default (direct) must not add the reject rule: %v", def)
		}
	}
	rej := asList(v07Build(t, `{"udpFallback":"reject"}`, map[string]string{})["rules"])
	if str(rej[len(rej)-1]) != UDPFallbackRejectRule {
		t.Fatalf("reject: rule must end the list: %v", rej)
	}
	// Junk value = direct.
	junk := asList(v07Build(t, `{"udpFallback":"maybe"}`, map[string]string{})["rules"])
	if str(junk[len(junk)-1]) == UDPFallbackRejectRule {
		t.Fatalf("junk value must keep mihomo's fallback: %v", junk)
	}
}

func TestLoonDNSHijackList(t *testing.T) {
	if got := dnsHijackList(nil); len(got) != 1 || got[0] != "any:53" {
		t.Fatalf("missing key = any:53, got %v", got)
	}
	if got := dnsHijackList([]string{}); len(got) != 0 {
		t.Fatalf("empty list stays empty (core adds its own DNS address), got %v", got)
	}
	got := dnsHijackList([]string{" tcp://any:53 ", "8.8.8.8:53", "8.8.8.8:53", "bogus", "1.1.1.1", "[::]:53", "any:0"})
	want := []string{"tcp://any:53", "8.8.8.8:53", "[::]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	// Through buildRuntime with a tun fd: the list reaches tun.dns-hijack and the core accepts the config.
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"dnsHijack":["any:53","tcp://any:53"]}`), 0o644)
	rt, err := buildRuntime([]byte(v07Profile), readOverrides(home), 7)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	h := asList(asMap(raw["tun"])["dns-hijack"])
	if len(h) != 2 || str(h[1]) != "tcp://any:53" {
		t.Fatalf("tun dns-hijack: %v", h)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects runtime config: %v", err)
	}
}

const stunProfile = `
proxies:
  - {name: U, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x, udp: true}
  - {name: N, type: ss, server: 127.0.0.1, port: 2, cipher: aes-128-gcm, password: x, udp: false}
proxy-groups:
  - {name: PU, type: select, proxies: [U, DIRECT]}
  - {name: PD, type: select, proxies: [DIRECT, U]}
  - {name: PN, type: select, proxies: [N]}
rules:
%s
`

func stunCase(t *testing.T, rules string) bool {
	t.Helper()
	cfg, err := executor.ParseWithBytes([]byte(fmtProfile(stunProfile, rules)))
	if err != nil {
		t.Fatal(err)
	}
	stunDropOption(true)(cfg)
	if !isSTUNDropRule(cfg.Rules[0]) {
		t.Fatalf("STUN rule must be first: %v", cfg.Rules[0])
	}
	stunDropOption(true)(cfg) // inserted once
	if isSTUNDropRule(cfg.Rules[1]) {
		t.Fatal("STUN rule inserted twice")
	}
	md := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstPort: 3478}
	_ = md.SetRemoteAddress("203.0.113.9:3478")
	return resolvesDirect(md, C.RuleMatchHelper{}, cfg.Rules, cfg.Proxies)
}

func fmtProfile(p, rules string) string {
	out := ""
	for _, r := range strings.Split(strings.TrimSpace(rules), "\n") {
		out += "  - " + r + "\n"
	}
	return strings.Replace(p, "%s\n", out, 1)
}

func TestLoonSTUNDropOnlyWhenDirect(t *testing.T) {
	cases := []struct {
		name   string
		rules  string
		direct bool
	}{
		{"explicit DIRECT", "AND,((NETWORK,UDP),(DST-PORT,3478)),DIRECT\nMATCH,PU", true},
		{"proxy group with UDP node", "MATCH,PU", false},
		{"group currently on DIRECT", "MATCH,PD", true},
		{"FaceTime-style rule to the proxy first", "AND,((NETWORK,UDP),(DST-PORT,3478-3497)),PU\nMATCH,DIRECT", false},
		{"node without UDP falls through to DIRECT", "MATCH,PN", true},
		{"node without UDP, later rule proxies", "AND,((NETWORK,UDP),(DST-PORT,3478)),PN\nMATCH,PU", false},
		{"UDP 回落 reject catches the fall-through", "MATCH,PN\n" + UDPFallbackRejectRule, false},
		{"REJECT is not direct", "AND,((NETWORK,UDP),(DST-PORT,3478)),REJECT\nMATCH,DIRECT", false},
		{"PASS skips to the next rule", "AND,((NETWORK,UDP),(DST-PORT,3478)),PASS\nMATCH,DIRECT", true},
	}
	for _, c := range cases {
		if got := stunCase(t, c.rules); got != c.direct {
			t.Errorf("%s: resolvesDirect = %v, want %v", c.name, got, c.direct)
		}
	}
}

func TestLoonSTUNRuleScope(t *testing.T) {
	r := stunDropRule{}
	for _, md := range []*C.Metadata{
		{NetWork: C.TCP, DstPort: 3478},
		{NetWork: C.UDP, DstPort: 443},
		{NetWork: C.UDP, DstPort: 3478, Type: C.INNER}, // 网络诊断's NAT test
	} {
		if ok, _ := r.Match(md, C.RuleMatchHelper{}); ok {
			t.Fatalf("must not match %v/%d type %v", md.NetWork, md.DstPort, md.Type)
		}
	}
	for _, p := range []uint16{3478, 3479, 5349, 19302, 19309} {
		if !isSTUNPort(p) {
			t.Fatalf("%d should be STUN", p)
		}
	}
	if isSTUNPort(3480) || isSTUNPort(16384) {
		t.Fatal("FaceTime media ports outside STUN must not count")
	}
	if r.Adapter() != "REJECT" || r.Payload() != "STUN" || r.RuleType() != C.Network {
		t.Fatal("rule identity changed (app shows it as Network(STUN) → REJECT)")
	}
	cfg, err := executor.ParseWithBytes([]byte(fmtProfile(stunProfile, "MATCH,PU")))
	if err != nil {
		t.Fatal(err)
	}
	n := len(cfg.Rules)
	stunDropOption(false)(cfg)
	if len(cfg.Rules) != n {
		t.Fatal("switch off must not insert")
	}
}

func TestLoonTCPHandshakeDelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	js := `{"name":"T","type":"ss","server":"127.0.0.1","port":` + strconv.Itoa(port) + `,"cipher":"aes-128-gcm","password":"x"}`
	if d := TestTCPDelay(js, "http://127.0.0.1:1/", 2000); d < 1 {
		t.Fatalf("TCP handshake to a local listener: %d (%s)", d, LastError())
	}
	// Closed port: failure, not a fake number.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().(*net.TCPAddr).Port
	_ = ln2.Close()
	js2 := `{"name":"T","type":"vmess","server":"127.0.0.1","port":` + strconv.Itoa(closed) + `,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"cipher":"auto"}`
	if d := TestTCPDelay(js2, "http://127.0.0.1:1/", 1000); d != -1 {
		t.Fatalf("closed port should fail, got %d", d)
	}
	for _, ty := range []string{"hysteria2", "tuic", "wireguard", "direct", ""} {
		if tcpTransport(ty) {
			t.Fatalf("%q is not a TCP transport", ty)
		}
	}
	// Behind a 前置代理: URL test path (here: fails against a dead URL instead of measuring the server).
	js3 := `{"name":"T","type":"ss","server":"127.0.0.1","port":` + strconv.Itoa(port) + `,"cipher":"aes-128-gcm","password":"x","dialer-proxy":"X"}`
	if d := TestTCPDelay(js3, "http://127.0.0.1:1/", 1000); d != -1 {
		t.Fatalf("dialer-proxy node must not report a direct TCP handshake, got %d", d)
	}
}

// End-to-end through Start: the STUN rule is live at the top of the core's rules, the controller lists it, and
// /tern/node-tcp-delay measures a TCP node's handshake.
func TestLoonNetThroughCore(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = freeTCPPort(t)
	ov.Secret = "s"
	ov.MixedPort = freeTCPPort(t)
	ov.StunDropDirect = true
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte("mode: rule\nproxies:\n  - {name: T, type: ss, server: 127.0.0.1, port: "+strconv.Itoa(port)+
		", cipher: aes-128-gcm, password: x, udp: true}\nproxy-groups:\n  - {name: G, type: select, proxies: [T]}\nrules:\n  - DOMAIN,proxied.test,G\n  - MATCH,DIRECT\n"), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	rules := tunnel.Rules()
	if len(rules) == 0 || !isSTUNDropRule(rules[0]) {
		t.Fatalf("STUN rule not first in the live rules: %v", rules)
	}
	md := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstPort: 3478}
	_ = md.SetRemoteAddress("203.0.113.9:3478")
	if ok, ada := rules[0].Match(md, C.RuleMatchHelper{}); !ok || ada != "REJECT" {
		t.Fatalf("STUN to DIRECT should be rejected: %v %s", ok, ada)
	}
	md2 := &C.Metadata{NetWork: C.UDP, Type: C.TUN, DstPort: 3478, Host: "proxied.test"}
	_ = md2.SetRemoteAddress("proxied.test:3478")
	if ok, _ := rules[0].Match(md2, C.RuleMatchHelper{}); ok {
		t.Fatal("STUN through the proxy group must pass")
	}
	get := func(path string) string {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(ov.ControllerPort)+path, nil)
		req.Header.Set("Authorization", "Bearer s")
		var body []byte
		for i := 0; i < 30; i++ {
			r, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err == nil {
				body, _ = io.ReadAll(r.Body)
				r.Body.Close()
				return string(body)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("controller unreachable: %s", path)
		return ""
	}
	if b := get("/rules"); !strings.Contains(b, `"payload":"STUN"`) {
		t.Fatalf("/rules should list the STUN rule: %s", b)
	}
	var d struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal([]byte(get("/tern/node-tcp-delay?name=T&timeout=2000&url=http://127.0.0.1:1/")), &d); err != nil || d.Delay < 1 {
		t.Fatalf("tcp delay through the controller: %+v %v", d, err)
	}
	// A group falls back to the URL test (dead URL here → 0, not a fake number).
	if err := json.Unmarshal([]byte(get("/tern/node-tcp-delay?name=G&timeout=1000&url=http://127.0.0.1:1/")), &d); err != nil || d.Delay != 0 {
		t.Fatalf("group should use the URL test: %+v %v", d, err)
	}
}
