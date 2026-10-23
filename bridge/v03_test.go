package libmihomo

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"

	"go.yaml.in/yaml/v3"
)

func TestDNSOverrideSplit(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	copyRepoGeo(t, home) // B12: geosite:cn / GeoIP fallback filter load the repo's Geo/ files, no download
	d := DNSOverride{Enabled: true, Split: true,
		Nameserver: []string{"https://223.5.5.5/dns-query", "tls://dot.pub"},
		Foreign:    []string{"https://1.1.1.1/dns-query", "quic://dns.adguard-dns.com"},
		Fallback:   []string{"tls://8.8.4.4"}, FallbackFilter: FallbackRule{GeoIP: true, IPCIDR: []string{"240.0.0.0/4"}},
		FakeIPRange: "198.18.0.1/16", FakeIPFilter: []string{"+.lan", "+.apple.com"}, FakeIPFilterMode: "blacklist",
		Policy: []DNSPolicy{{Match: "+.corp.example", Servers: []string{"10.0.0.1"}}}}
	b, _ := json.Marshal(d)
	_ = os.WriteFile(filepath.Join(home, "dns.json"), b, 0o644)
	o := readOverrides(home)
	if o.DNS == nil {
		t.Fatal("dns.json not loaded")
	}
	rt, err := buildRuntime([]byte(sample), o, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejected: %v\n%s", err, rt)
	}
	var m map[string]any
	_ = yaml.Unmarshal(rt, &m)
	dns := m["dns"].(map[string]any)
	if ns := dns["nameserver"].([]any); ns[0] != "https://1.1.1.1/dns-query" {
		t.Fatalf("split nameserver %v", ns)
	}
	pol := dns["nameserver-policy"].(map[string]any)
	if _, ok := pol["geosite:cn,private"]; !ok {
		t.Fatalf("policy %v", pol)
	}
	tun := m["tun"].(map[string]any)
	if tun["recvmsgx"] != false || tun["sendmsgx"] != false || tun["mtu"] != 4064 {
		t.Fatalf("tun %v", tun)
	}
}

func TestProxyOnlyMode(t *testing.T) {
	o := defaultOverrides()
	o.TunnelMode = "proxy"
	rt, _ := buildRuntime([]byte(sample), o, 0)
	var m map[string]any
	_ = yaml.Unmarshal(rt, &m)
	if m["mixed-port"] != 7890 || m["bind-address"] != "127.0.0.1" || m["tun"] != nil {
		t.Fatalf("proxy mode: %v %v %v", m["mixed-port"], m["bind-address"], m["tun"])
	}
}

func TestInspectAndManualMerge(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "mihomo")
	_ = os.MkdirAll(filepath.Join(root, "profiles"), 0o755)
	_ = os.MkdirAll(home, 0o755)
	if n := ManualAddText(filepath.Join(root, "profiles", "manual-nodes.yaml"), "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#mine"); n != 1 {
		t.Fatal(LastError())
	}
	ov := defaultOverrides()
	ov.MergeManual = true
	ov.Mode = "global"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	C.SetHomeDir(home)
	url := "https://example.com/sub.yaml"
	cache := C.Path.GetPathByHash("proxies", url)
	_ = os.MkdirAll(filepath.Dir(cache), 0o755)
	_ = os.WriteFile(cache, []byte("proxies:\n  - {name: p1, type: trojan, server: t.example.com, port: 443, password: x}\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(home, "ruleset"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "ruleset", "ads.txt"), []byte("+.ads.example\n+.track.example\n"), 0o644)
	prof := filepath.Join(root, "profiles", "p.yaml")
	_ = os.WriteFile(prof, []byte(sample+`proxy-providers:
  sub: {type: http, url: "`+url+`", interval: 3600}
  nope: {type: http, url: "https://example.com/none.yaml"}
rule-providers:
  ads: {type: file, behavior: domain, format: text, path: ./ruleset/ads.txt}
`), 0o644)
	if e := SaveSelection(prof, "PROXY", "DIRECT"); e != "" {
		t.Fatal(e)
	}
	var r inspectResult
	if err := json.Unmarshal([]byte(InspectProfile(home, prof)), &r); err != nil || r.Error != "" {
		t.Fatalf("%v %s", err, r.Error)
	}
	if r.Mode != "global" {
		t.Fatalf("mode %s", r.Mode)
	}
	var names []string
	for _, p := range r.Proxies {
		names = append(names, p.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "mine") {
		t.Fatalf("manual node not merged: %v", names)
	}
	var proxyGroup *inspectGroup
	for i := range r.Groups {
		if r.Groups[i].Name == "PROXY" {
			proxyGroup = &r.Groups[i]
		}
	}
	if proxyGroup == nil || proxyGroup.Proxies[0] != ManualGroupName || proxyGroup.Selected != "DIRECT" {
		t.Fatalf("group %+v", proxyGroup)
	}
	if len(r.ProxyProviders) != 2 || !r.ProxyProviders[1].Cached || r.ProxyProviders[1].Count != 1 || r.ProxyProviders[0].Cached {
		t.Fatalf("providers %+v", r.ProxyProviders)
	}
	if len(r.RuleProviders) != 1 || r.RuleProviders[0].Count != 2 {
		t.Fatalf("rule providers %+v", r.RuleProviders)
	}
	// + the UDP 443 fallback appended after MATCH (v0.6.1)
	if len(r.Rules) != 2 || r.Rules[0].Type != "MATCH" || r.Rules[0].Proxy != "PROXY" || r.Rules[1].Proxy != "REJECT" {
		t.Fatalf("rules %+v", r.Rules)
	}
	sr := splitRule("AND,((DOMAIN,a.com),(NETWORK,UDP)),REJECT")
	if sr.Type != "AND" || sr.Proxy != "REJECT" {
		t.Fatalf("%+v", sr)
	}
	sr = splitRule("IP-CIDR,1.1.1.1/32,DIRECT,no-resolve")
	if sr.Payload != "1.1.1.1/32" || sr.Proxy != "DIRECT" || sr.Options != "no-resolve" {
		t.Fatalf("%+v", sr)
	}
}

func TestGeoInfoAndURLs(t *testing.T) {
	home := t.TempDir()
	var l []geoFile
	_ = json.Unmarshal([]byte(GeoInfo(home)), &l)
	if len(l) != 4 || l[0].Exists {
		t.Fatalf("%+v", l)
	}
	if u := GeoDefaultURL("asn", "github"); u != "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb" {
		t.Fatal(u)
	}
	o := defaultOverrides()
	o.GeoURLs = map[string]string{"geosite": "cdn.example.com/geosite.dat"}
	g := geoxFor(o)
	if g["geosite"] != "https://cdn.example.com/geosite.dat" || !strings.Contains(g["mmdb"].(string), "jsdelivr") {
		t.Fatalf("%v", g)
	}
	if err := geoValidate("GeoSite.dat", []byte("<html>blocked</html>"+strings.Repeat(" ", 2000))); err == nil {
		t.Fatal("html accepted")
	}
	if src, err := os.ReadFile("../Geo/geoip.metadb"); err == nil {
		_ = os.WriteFile(filepath.Join(home, "geoip.metadb"), src, 0o644)
		_ = json.Unmarshal([]byte(GeoInfo(home)), &l)
		if !l[0].Exists || l[0].BuildDate == 0 {
			t.Fatalf("bundled mmdb: %+v", l[0])
		}
		t.Logf("bundled mmdb %s built %s", l[0].DBType, time.Unix(int64(l[0].BuildDate), 0).UTC())
	}
}

// /tools/tcp through the real core: DIRECT to a local listener succeeds and reports the chain.
func TestToolsTCPThroughCore(t *testing.T) {
	home := t.TempDir()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(time.Second); c.Close() }()
		}
	}()
	ov := defaultOverrides()
	ov.ControllerPort = 19292
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte("rules:\n  - MATCH,DIRECT\n"), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19292/tools/tcp?host=127.0.0.1&count=2&port="+port, nil)
	req.Header.Set("Authorization", "Bearer s")
	var resp *http.Response
	var err error
	for i := 0; i < 20; i++ {
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var res []probeResult
	_ = json.Unmarshal(b, &res)
	if len(res) != 2 || !res[0].OK || !strings.Contains(res[0].Chain, "DIRECT") {
		t.Fatalf("%s", b)
	}
	t.Logf("%s", b)
	if v := TrafficTotals(); !strings.Contains(v, ",") {
		t.Fatal(v)
	}
	if TestDelay(`{"name":"x","type":"ss"}`, "http://127.0.0.1/", 500) != -1 {
		t.Fatal("bad proxy should fail")
	}
}

func TestGeoInstallFileRejectsJunk(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, "x.download")
	_ = os.WriteFile(p, []byte("<html>blocked</html>"), 0o644)
	if _, err := GeoInstallFile(home, "geosite", p); err == nil {
		t.Fatal("expected error for junk file")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("temp file should be removed")
	}
	if _, err := GeoInstallFile(home, "nope", p); err == nil {
		t.Fatal("expected unknown kind error")
	}
}

// Loon gap: 「包含系统 DNS」 adds `system` to the domestic servers; 查询回落 writes fallback + a default filter.
func TestDNSOverrideIncludeSystemAndFallback(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	copyRepoGeo(t, home)
	parse := func(d DNSOverride) map[string]any {
		t.Helper()
		b, _ := json.Marshal(d)
		_ = os.WriteFile(filepath.Join(home, "dns.json"), b, 0o644)
		o := readOverrides(home)
		rt, err := buildRuntime([]byte(sample), o, 7)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executor.ParseWithBytes(rt); err != nil {
			t.Fatalf("core rejected: %v\n%s", err, rt)
		}
		var m map[string]any
		_ = yaml.Unmarshal(rt, &m)
		return m["dns"].(map[string]any)
	}
	has := func(l any, s string) bool {
		for _, e := range asList(l) {
			if e == s {
				return true
			}
		}
		return false
	}

	// not split: system joins the main nameserver list, once, after the user's servers
	dns := parse(DNSOverride{Enabled: true, Nameserver: []string{"https://223.5.5.5/dns-query", "system"}, IncludeSystem: true})
	ns := asList(dns["nameserver"])
	if len(ns) != 2 || ns[0] != "https://223.5.5.5/dns-query" || ns[1] != "system" {
		t.Fatalf("nameserver %v", ns)
	}
	dns = parse(DNSOverride{Enabled: true, Nameserver: []string{"https://223.5.5.5/dns-query"}, IncludeSystem: true})
	if ns := asList(dns["nameserver"]); len(ns) != 2 || ns[1] != "system" {
		t.Fatalf("nameserver %v", ns)
	}
	if dns["fallback"] != nil || dns["fallback-filter"] != nil {
		t.Fatalf("no fallback expected: %v", dns)
	}

	// split: only the domestic (geosite:cn) servers get system; foreign queries never go to the local resolver
	dns = parse(DNSOverride{Enabled: true, Split: true, Nameserver: []string{"223.5.5.5"}, Foreign: []string{"https://1.1.1.1/dns-query"},
		IncludeSystem: true, Fallback: []string{"tls://8.8.4.4"}, FallbackFilter: FallbackRule{GeoIP: true}})
	if has(dns["nameserver"], "system") {
		t.Fatalf("system leaked into foreign nameserver %v", dns["nameserver"])
	}
	pol := dns["nameserver-policy"].(map[string]any)
	if !has(pol["geosite:cn,private"], "system") || !has(pol["geosite:cn,private"], "223.5.5.5") {
		t.Fatalf("policy %v", pol)
	}
	if fb := asList(dns["fallback"]); len(fb) != 1 || fb[0] != "tls://8.8.4.4" {
		t.Fatalf("fallback %v", dns["fallback"])
	}
	ff := dns["fallback-filter"].(map[string]any)
	if ff["geoip"] != true || ff["geoip-code"] != "CN" {
		t.Fatalf("fallback-filter %v", ff)
	}

	// off: no system
	dns = parse(DNSOverride{Enabled: true, Nameserver: []string{"223.5.5.5"}})
	if has(dns["nameserver"], "system") {
		t.Fatalf("system without the toggle %v", dns["nameserver"])
	}
}
