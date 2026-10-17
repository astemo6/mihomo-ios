package libmihomo

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

// v0.11: the remaining QX profile keys.
const qxFull = "[general]\n" +
	"server_check_url=http://cp.cloudflare.com/generate_204\n" +
	"server_check_timeout=8000\n" +
	"dns_exclusion_list=*.cmpassport.com, *.jegotrip.com.cn, localhost.ptlogin2.qq.com\n" +
	"excluded_routes=239.255.255.250/32, 24.105.30.129/32, bad\n" +
	"ssid_suspended_list=Home-5G, Office\n" +
	"udp_drop_list=1900, 80, STUN, QUIC\n" +
	"fallback_udp_policy=direct\n" +
	"running_mode_trigger=filter, filter, Home:all_direct\n" +
	"[dns]\n" +
	"no-system\n" +
	"prefer-doh3\n" +
	"server=223.5.5.5\n" +
	"server=119.29.29.29, excluded_ssids=Home\n" +
	"server=/*.taobao.com/223.5.5.5\n" +
	"server=/example.cn/system\n" +
	"doh-server=https://dns.alidns.com/dns-query, https://doh.pub/dns-query\n" +
	"doq-server=quic://dns.adguard.com\n" +
	"address=/router.lan/192.168.1.1\n" +
	"alias=/www.example.org/example.net\n" +
	"[policy]\n" +
	"static=节点选择, 香港, 负载, 哈希, direct\n" +
	"url-latency-benchmark=香港, server-tag-regex=港, check-interval=600, alive-checking=false\n" +
	"round-robin=负载, server-tag-regex=日本\n" +
	"dest-hash=哈希, server-tag-regex=美国\n" +
	"[server_remote]\n" +
	"https://sub.example.com/a, tag=机场A, as-policy=available, enabled=true\n" +
	"[server_local]\n" +
	"shadowsocks=1.2.3.4:443, method=chacha20, password=pw, ssr-protocol=auth_chain_a, ssr-protocol-param=1:x, obfs=tls1.2_ticket_auth, obfs-host=a.com, tag=SSR\n" +
	"shadowsocks=1.2.3.5:443, method=2022-blake3-aes-128-gcm, password=AAAAAAAAAAAAAAAAAAAAAA==, udp-over-tcp=sp.v2, fast-open=true, tag=SS2022\n" +
	"trojan=t.example.com:443, password=pw, over-tls=true, tls-host=t.example.com, tls-cert-sha256=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99, tls-alpn=h2:http/1.1, tag=Trojan\n" +
	"vless=v.example.com:443, method=none, password=00000000-0000-0000-0000-000000000000, obfs=over-tls, tls-host=v.example.com, tls-alpn=02683208687474702f312e31, tag=VLESS\n" +
	"anytls=a.example.com:443, password=pw, tls-host=a.example.com, tag=AnyTLS\n" +
	"[filter_remote]\n" +
	"https://example.com/Netflix.list, tag=Netflix, force-policy=节点选择, enabled=true\n" +
	"https://example.com/Ads.list, tag=Ads, force-policy=reject, inserted-resource=true, enabled=true\n" +
	"FILTER_LAN, tag=LAN, force-policy=direct, enabled=true\n" +
	"FILTER_REGION, tag=CN, enabled=true\n" +
	"[filter_local]\n" +
	"host-suffix, google.com, 节点选择\n" +
	"final, 节点选择\n"

func TestImportQXRemainingKeys(t *testing.T) {
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(qxFull)), &res); err != nil || res.Error != "" {
		t.Fatalf("%v %s", err, res.Error)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal([]byte(res.YAML), &cfg); err != nil {
		t.Fatal(err)
	}
	// --- [dns]
	d := asMap(cfg["dns"])
	ns := asList(d["nameserver"])
	if len(ns) != 3 || str(ns[0]) != "https://dns.alidns.com/dns-query" || str(ns[2]) != "quic://dns.adguard.com" {
		t.Fatalf("nameserver (DoH/DoQ replace plain + system): %v", ns)
	}
	pol := asMap(d["nameserver-policy"])
	if str(asList(pol["+.taobao.com"])[0]) != "223.5.5.5" || str(asList(pol["+.example.cn"])[0]) != "system" {
		t.Fatalf("nameserver-policy: %v", pol)
	}
	if d["prefer-h3"] != true {
		t.Fatalf("prefer-doh3 not mapped")
	}
	ff := asList(d["fake-ip-filter"])
	if len(ff) != 3 || str(ff[0]) != "+.cmpassport.com" {
		t.Fatalf("dns_exclusion_list → fake-ip-filter: %v", ff)
	}
	hosts := asMap(cfg["hosts"])
	if str(hosts["router.lan"]) != "192.168.1.1" || str(hosts["www.example.org"]) != "example.net" {
		t.Fatalf("hosts: %v", hosts)
	}
	// --- settings for the app
	s := res.Settings
	if s == nil || len(s.ExcludedRoutes) != 2 || len(s.TrustedSSIDs) != 2 || s.TestURL != "http://cp.cloudflare.com/generate_204" || s.TestTimeoutMs != 5000 || !s.BlockQUIC {
		t.Fatalf("settings: %+v", s)
	}
	// --- groups
	groups := map[string]map[string]any{}
	for _, g := range asList(cfg["proxy-groups"]) {
		m := asMap(g)
		groups[str(m["name"])] = m
	}
	if groups["香港"]["lazy"] != true || str(groups["香港"]["url"]) != "http://cp.cloudflare.com/generate_204" || groups["香港"]["timeout"] != 5000 {
		t.Fatalf("url-latency-benchmark: %v", groups["香港"])
	}
	if groups["负载"]["strategy"] != "round-robin" || groups["哈希"]["strategy"] != "consistent-hashing" {
		t.Fatalf("load-balance strategies: %v / %v", groups["负载"], groups["哈希"])
	}
	if a := groups["机场A"]; a == nil || a["type"] != "fallback" || len(asList(a["use"])) != 1 {
		t.Fatalf("as-policy group: %v", a)
	}
	// --- nodes
	nodes := map[string]map[string]any{}
	for _, p := range asList(cfg["proxies"]) {
		m := asMap(p)
		nodes[str(m["name"])] = m
	}
	if n := nodes["SSR"]; n["type"] != "ssr" || n["protocol"] != "auth_chain_a" || n["obfs"] != "tls1.2_ticket_auth" || n["obfs-param"] != "a.com" {
		t.Fatalf("SSR: %v", n)
	}
	if n := nodes["SS2022"]; n["udp-over-tcp"] != true || n["udp-over-tcp-version"] != 2 || n["tfo"] != true {
		t.Fatalf("SS extras: %v", n)
	}
	if n := nodes["Trojan"]; n["fingerprint"] != strings.Repeat("aabbccddeeff00112233445566778899", 2) || len(asList(n["alpn"])) != 2 {
		t.Fatalf("trojan extras: %v", n)
	}
	if a := asList(nodes["VLESS"]["alpn"]); len(a) != 2 || str(a[0]) != "h2" || str(a[1]) != "http/1.1" {
		t.Fatalf("hex alpn: %v", a)
	}
	if n := nodes["AnyTLS"]; n["type"] != "anytls" || n["sni"] != "a.example.com" {
		t.Fatalf("anytls: %v", n)
	}
	// --- rules
	rules := asList(cfg["rules"])
	var rs []string
	for _, r := range rules {
		rs = append(rs, str(r))
	}
	joined := strings.Join(rs, "\n")
	if !strings.HasPrefix(rs[0], "AND,((NETWORK,UDP),(DST-PORT,1900/80/3478/5349/19302)),REJECT-DROP") {
		t.Fatalf("udp_drop_list first: %s", rs[0])
	}
	iAds, iLocal, iNetflix, iLAN := -1, -1, -1, -1
	for i, r := range rs {
		switch {
		case strings.HasPrefix(r, "RULE-SET,Ads,"):
			iAds = i
		case strings.HasPrefix(r, "DOMAIN-SUFFIX,google.com"):
			iLocal = i
		case strings.HasPrefix(r, "RULE-SET,Netflix,"):
			iNetflix = i
		case strings.HasPrefix(r, "IP-CIDR,192.168.0.0/16,DIRECT"):
			iLAN = i
		}
	}
	if !(iAds >= 0 && iAds < iLocal && iLocal < iNetflix && iNetflix < iLAN) {
		t.Fatalf("order (inserted Ads → local → Netflix → LAN): %v", rs)
	}
	if !strings.Contains(joined, "GEOIP,CN,DIRECT") {
		t.Fatalf("FILTER_REGION missing:\n%s", joined)
	}
	if rs[len(rs)-2] != "AND,((NETWORK,UDP)),DIRECT" || rs[len(rs)-1] != "MATCH,节点选择" {
		t.Fatalf("fallback_udp_policy before MATCH: %v", rs[len(rs)-3:])
	}
	// v0.12: running_mode_trigger is imported as a setting (v012_test.go).
	if res.Settings == nil || res.Settings.ModeTrigger == nil || res.Settings.ModeTrigger.SSIDs["Home"] != "direct" {
		t.Fatalf("running_mode_trigger not imported: %+v", res.Settings)
	}
	o := defaultOverrides()
	rt, err := buildRuntime([]byte(res.YAML), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The test environment has no MMDB; GEOIP is exercised by the device builds.
	rt = regexp.MustCompile(`(?m)^\s*- GEOIP,CN,DIRECT\n`).ReplaceAll(rt, nil)
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core rejects imported config: %v\n%s", err, rt)
	}
}

func TestLiveStatusShape(t *testing.T) {
	parts := strings.Split(LiveStatus(), "\t")
	if len(parts) != 5 {
		t.Fatalf("LiveStatus fields: %q", parts)
	}
}
