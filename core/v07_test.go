package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astemo6/mihomo-android/core/mitm"
	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

const v07Profile = "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: P, type: select, proxies: [A]}\nhosts:\n  keep.example: 9.9.9.9\nrules:\n  - DOMAIN-SUFFIX,cn,DIRECT\n  - MATCH,P\n"

func v07Build(t *testing.T, overrides string, files map[string]string) map[string]any {
	t.Helper()
	home := t.TempDir()
	if overrides != "" {
		files["overrides.json"] = overrides
	}
	for k, v := range files {
		if err := os.WriteFile(filepath.Join(home, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rt, err := buildRuntime([]byte(v07Profile), readOverrides(home), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects runtime config: %v\n%s", err, rt)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	return raw
}

func TestBlockQUICModes(t *testing.T) {
	def := asList(v07Build(t, "", map[string]string{})["rules"])
	if str(def[len(def)-1]) != UDPFallbackRule || str(def[0]) == mitm.QUICBlockAllRule {
		t.Fatalf("default should keep the v0.6.1 fallback: %v", def)
	}
	off := asList(v07Build(t, `{"blockQUIC":"off"}`, map[string]string{})["rules"])
	for _, r := range off {
		if str(r) == UDPFallbackRule || str(r) == mitm.QUICBlockAllRule {
			t.Fatalf("off must add nothing: %v", off)
		}
	}
	al := asList(v07Build(t, `{"blockQUIC":"always"}`, map[string]string{})["rules"])
	if str(al[0]) != mitm.QUICBlockAllRule || str(al[len(al)-1]) != UDPFallbackRule {
		t.Fatalf("always: %v", al)
	}
	// engine.json quic=all plus always: the block rule appears once.
	both := asList(v07Build(t, `{"blockQUIC":"always"}`, map[string]string{"engine.json": `{"quic":"all"}`})["rules"])
	n := 0
	for _, r := range both {
		if str(r) == mitm.QUICBlockAllRule {
			n++
		}
	}
	if n > 1 {
		t.Fatalf("duplicate block rule (%d)", n)
	}
}

func TestInboundModes(t *testing.T) {
	mix := v07Build(t, `{"tunnelMode":"mix"}`, map[string]string{})
	if mix["mixed-port"] != 7890 || mix["bind-address"] != "127.0.0.1" {
		t.Fatalf("mix inbound: %v %v", mix["mixed-port"], mix["bind-address"])
	}
	tun := v07Build(t, `{"tunnelMode":"tun"}`, map[string]string{})
	if _, ok := tun["mixed-port"]; ok {
		t.Fatal("tun mode must not open a local port")
	}
	lan := v07Build(t, `{"allowLan":true,"lanAuth":{"username":"u","password":"p w"},"lanLocalOnly":true}`, map[string]string{})
	if lan["bind-address"] != "*" || str(asList(lan["authentication"])[0]) != "u:p w" {
		t.Fatalf("lan auth: %v", lan["authentication"])
	}
	if len(asList(lan["lan-allowed-ips"])) == 0 || len(asList(lan["skip-auth-prefixes"])) != 2 {
		t.Fatalf("lan prefixes: %v %v", lan["lan-allowed-ips"], lan["skip-auth-prefixes"])
	}
	open := v07Build(t, `{"allowLan":true,"lanLocalOnly":false}`, map[string]string{})
	if _, ok := open["lan-allowed-ips"]; ok {
		t.Fatal("lanLocalOnly=false must not restrict sources")
	}
	if _, ok := open["authentication"]; ok {
		t.Fatal("no auth configured")
	}
}

func TestLocalDNSHostsAndRealIP(t *testing.T) {
	raw := v07Build(t, "", map[string]string{"localdns.json": `{"hosts":[{"domain":"Router.lan","value":"192.168.1.1"},{"domain":"+.multi.test","value":"1.1.1.1, 2.2.2.2"},{"domain":"alias.test","value":"example.com"},{"domain":"off.test","value":"1.2.3.4","disabled":true},{"domain":"bad.test","value":"a.com b.com"}],"realIP":["+.stun.example","*.lan"]}`})
	h := asMap(raw["hosts"])
	if h["router.lan"] != "192.168.1.1" || len(asList(h["+.multi.test"])) != 2 || h["alias.test"] != "example.com" || h["keep.example"] != "9.9.9.9" {
		t.Fatalf("hosts %v", h)
	}
	if _, ok := h["off.test"]; ok {
		t.Fatal("disabled entry applied")
	}
	if _, ok := h["bad.test"]; ok {
		t.Fatal("invalid entry applied")
	}
	f := asList(asMap(raw["dns"])["fake-ip-filter"])
	s := []string{}
	for _, x := range f {
		s = append(s, str(x))
	}
	joined := strings.Join(s, " ")
	if !strings.Contains(joined, "+.stun.example") || strings.Count(joined, "*.lan") != 1 {
		t.Fatalf("fake-ip-filter %v", s)
	}
	if ValidateHostEntry("x.com", "1.1.1.1,::1") != "" || ValidateHostEntry("x y", "1.1.1.1") == "" || ValidateHostEntry("x.com", "a.com,b.com") == "" {
		t.Fatal("ValidateHostEntry")
	}
}

func TestQXImportIcon(t *testing.T) {
	conf := "[server_local]\nshadowsocks=1.2.3.4:443, method=aes-128-gcm, password=x, tag=N1\n[policy]\nstatic=Proxy, N1, direct, img-url=https://example.com/a.png\nstatic=Plain, N1, img-url=Japan.png\n[filter_local]\nfinal, Proxy\n"
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(conf)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if !strings.Contains(res.YAML, "icon: https://example.com/a.png") || strings.Contains(res.YAML, "Japan.png") {
		t.Fatalf("icon mapping:\n%s", res.YAML)
	}
}
