package libmihomo

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/dop251/goja"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

// v0.19.4 (review 5): end-to-end tests that feed realistic, synthetic inputs through import → override
// script → final runtime YAML → mihomo's own parser (executor.ParseWithBytes via ValidateConfigIn).
// Every server, password and uuid below is a placeholder.

func v0194Home(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, f := range []string{"geoip.metadb", "GeoSite.dat"} {
		g, err := os.ReadFile(filepath.Join("..", "Geo", f))
		if err != nil {
			t.Skipf("geo file %s missing: %v", f, err)
		}
		_ = os.WriteFile(filepath.Join(home, f), g, 0o644)
	}
	return home
}

func v0194Write(t *testing.T, home, name string, b []byte) string {
	t.Helper()
	dir := filepath.Join(home, "profiles")
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const v0194Surge = `[General]
loglevel = notify
dns-server = 223.5.5.5, 119.29.29.29
skip-proxy = 127.0.0.1, 192.168.0.0/16, localhost, *.local
ipv6 = false

[Proxy]
HK-SS = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=pw1, udp-relay=true
JP-VMess = vmess, jp.example.com, 443, username=0b5e6f2a-1111-4222-8333-444455556666, ws=true, ws-path=/ws, tls=true, sni=jp.example.com
US-Trojan = trojan, us.example.com, 443, password=pw2, sni=us.example.com, skip-cert-verify=true
SG-Hy2 = hysteria2, sg.example.com, 8443, password=pw3, sni=sg.example.com
TW-TUIC = tuic, tw.example.com, 443, token=tok, uuid=0b5e6f2a-1111-4222-8333-444455556666, password=pw4, alpn=h3
KR-Socks = socks5, kr.example.com, 1080, user, pass
DE-HTTP = https, de.example.com, 443, user, pass

[Proxy Group]
Proxy = select, Auto, HK-SS, JP-VMess, US-Trojan, SG-Hy2, TW-TUIC, KR-Socks, DE-HTTP, DIRECT
Auto = url-test, HK-SS, JP-VMess, US-Trojan, url=http://www.gstatic.com/generate_204, interval=600, tolerance=50
Fallback = fallback, SG-Hy2, TW-TUIC, url=http://www.gstatic.com/generate_204, interval=300
LB = load-balance, HK-SS, JP-VMess
Streaming = select, Proxy, HK-SS, policy-regex-filter=HK|JP

[Rule]
DOMAIN,ads.example.net,REJECT
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,youtube,Streaming
DOMAIN-WILDCARD,*.example.org,DIRECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR6,fd00::/8,DIRECT
GEOIP,CN,DIRECT
USER-AGENT,Instagram*,Proxy
URL-REGEX,^https?://ad\.example\.com,REJECT
PROCESS-NAME,Telegram,Proxy
DEST-PORT,25,REJECT
AND,((DOMAIN-SUFFIX,example.io),(DEST-PORT,443)),Fallback
OR,((DOMAIN,a.example.io),(DOMAIN,b.example.io)),LB
NOT,((DOMAIN-SUFFIX,cn)),Proxy
RULE-SET,https://rules.example.com/surge/apple.list,DIRECT
DOMAIN-SET,https://rules.example.com/surge/reject.txt,REJECT
FINAL,Proxy,dns-failed

[Host]
router.local = 192.168.1.1

[URL Rewrite]
^https?://(www.)?g.cn https://www.google.com 302

[MITM]
hostname = api.example.com
`

const v0194QX = `[general]
server_check_url = http://www.qualcomm.cn/generate_204
dns_exclusion_list = *.cmpassport.com

[dns]
server = 223.5.5.5
server = /*.example.cn/119.29.29.29

[policy]
static = 节点选择, 自动选择, 香港节点, direct, img-url=https://example.com/a.png
url-latency-benchmark = 自动选择, server-tag-regex=.*, check-interval=600, tolerance=50
available = 故障转移, HK-SS, JP-VMess
round-robin = 轮询, HK-SS, JP-VMess
static = 香港节点, server-tag-regex=HK, img-url=https://example.com/hk.png

[server_local]
shadowsocks = hk.example.com:8388, method=chacha20-ietf-poly1305, password=pw1, fast-open=false, udp-relay=true, tag=HK-SS
vmess = jp.example.com:443, method=chacha20-ietf-poly1305, password=0b5e6f2a-1111-4222-8333-444455556666, obfs=wss, obfs-host=jp.example.com, obfs-uri=/ws, tag=JP-VMess
trojan = us.example.com:443, password=pw2, over-tls=true, tls-host=us.example.com, tls-verification=false, tag=US-Trojan
http = de.example.com:443, username=u, password=p, over-tls=true, tag=DE-HTTP
vless = sg.example.com:443, method=none, password=0b5e6f2a-1111-4222-8333-444455556666, obfs=over-tls, obfs-host=sg.example.com, tag=SG-VLESS

[filter_local]
host, ads.example.net, reject
host-suffix, google.com, 节点选择
host-keyword, youtube, 香港节点
host-wildcard, *.example.org, direct
ip-cidr, 10.0.0.0/8, direct
ip6-cidr, fd00::/8, direct
user-agent, Instagram*, 节点选择
geoip, cn, direct
final, 节点选择

[filter_remote]
https://rules.example.com/qx/apple.list, tag=Apple, force-policy=direct, update-interval=86400, opt-parser=false, enabled=true

[rewrite_local]
^https?://ad\.example\.com url reject-200

[mitm]
hostname = api.example.com
`

const v0194Loon = `[General]
ip-mode = ipv4-only
dns-server = system,223.5.5.5

[Proxy]
HK-SS = Shadowsocks,hk.example.com,8388,aes-256-gcm,"pw1",fast-open=false,udp=true
JP-VMess = vmess,jp.example.com,443,auto,"0b5e6f2a-1111-4222-8333-444455556666",transport=ws,path=/ws,host=jp.example.com,over-tls=true,sni=jp.example.com
US-Trojan = trojan,us.example.com,443,"pw2",sni=us.example.com,skip-cert-verify=true
SG-Hy2 = Hysteria2,sg.example.com,8443,"pw3",sni=sg.example.com

[Proxy Group]
Proxy = select,Auto,HK-SS,JP-VMess,US-Trojan,SG-Hy2,DIRECT
Auto = url-test,HK-SS,JP-VMess,url=http://www.gstatic.com/generate_204,interval=600

[Rule]
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,ads,REJECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,Proxy
`

// Stash / Clash profile: imported as a YAML profile as is.
const v0194Stash = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5, https://doh.example.com/dns-query]
  nameserver-policy:
    "+.example.cn": 223.5.5.5
    "geosite:cn": 119.29.29.29
  fake-ip-filter: ["*.lan", "+.local"]
proxies:
  - {name: HK-SS, type: ss, server: hk.example.com, port: 8388, cipher: aes-256-gcm, password: pw1, udp: true}
  - {name: JP-VLESS, type: vless, server: jp.example.com, port: 443, uuid: 0b5e6f2a-1111-4222-8333-444455556666, network: tcp, tls: true, servername: jp.example.com, flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, short-id: "0123"}}
  - {name: US-AnyTLS, type: anytls, server: us.example.com, port: 443, password: pw5, sni: us.example.com}
  - name: SG-TUIC
    type: tuic
    server: sg.example.com
    port: 443
    uuid: 0b5e6f2a-1111-4222-8333-444455556666
    password: pw4
    alpn: [h3]
proxy-groups:
  - {name: Proxy, type: select, proxies: [Auto, HK-SS, JP-VLESS, US-AnyTLS, SG-TUIC, DIRECT]}
  - {name: Auto, type: url-test, proxies: [HK-SS, JP-VLESS], url: "https://www.gstatic.com/generate_204", interval: 300}
rule-providers:
  apple:
    type: http
    behavior: domain
    format: text
    url: https://rules.example.com/apple.txt
    path: ./rules/apple.txt
    interval: 86400
rules:
  - RULE-SET,apple,DIRECT
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
`

type v0194Import struct {
	YAML   string `json:"yaml"`
	Module string `json:"module"`
	Error  string `json:"error"`
	Report struct {
		Format  string   `json:"format"`
		Skipped []string `json:"skipped"`
	} `json:"report"`
}

// override-script stand-in: the same JSON in → JSON out contract the app's JavaScriptCore engine has
// (OverrideScripts.swift), run in goja so the Go round trip can be exercised without a device.
func v0194RunOverride(t *testing.T, src, input string, custom map[string]bool) string {
	t.Helper()
	rt := goja.New()
	cj, _ := json.Marshal(custom)
	if custom == nil {
		cj = []byte("null")
	}
	fn := "(function(__configText, __customText, __profileName) { var __config = JSON.parse(__configText); var __custom = JSON.parse(__customText); " + src +
		"\n;if (__custom && typeof ruleOptionsEnable !== 'undefined' && ruleOptionsEnable) { Object.assign(ruleOptionsEnable, __custom); }\nreturn JSON.stringify(main(__config, __profileName)); })"
	v, err := rt.RunString(fn)
	if err != nil {
		t.Fatalf("override compile: %v", err)
	}
	call, _ := goja.AssertFunction(v)
	out, err := call(goja.Undefined(), rt.ToValue(input), rt.ToValue(string(cj)), rt.ToValue("p"))
	if err != nil {
		t.Fatalf("override run: %v", err)
	}
	return out.String()
}

// A Bettbox-style script: switches, a new group, rules prepended, a DNS tweak.
const v0194Override = `const Compatible_With_Bettbox = { ruleOptionsEnable: true, policyGroupOptions: ['openai'] };
const ruleOptionsEnable = { openai: true, ads: false };
function main(config, profileName) {
  const names = (config.proxies || []).map(p => p.name);
  config['proxy-groups'] = config['proxy-groups'] || [];
  if (ruleOptionsEnable.openai) {
    config['proxy-groups'].unshift({ name: 'OpenAI', type: 'select', proxies: names.length ? names : ['DIRECT'] });
    config.rules = ['DOMAIN-SUFFIX,openai.com,OpenAI'].concat(config.rules || []);
  }
  if (ruleOptionsEnable.ads) {
    config.rules = ['DOMAIN-KEYWORD,adservice,REJECT'].concat(config.rules || []);
  }
  config.dns = config.dns || {};
  config.dns.enable = true;
  config.dns['fake-ip-range'] = '198.18.0.1/16';
  config['unified-delay'] = true;
  return config;
}`

func TestV0194ImportScriptRuntimeEndToEnd(t *testing.T) {
	home := v0194Home(t)
	cases := []struct {
		name, text, format    string
		minProxies, minGroups int
	}{
		{"surge", v0194Surge, "surge", 7, 5},
		{"qx", v0194QX, "qx", 5, 5},
		{"loon", v0194Loon, "surge", 4, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r v0194Import
			if err := json.Unmarshal([]byte(ImportConf(c.text)), &r); err != nil || r.Error != "" {
				t.Fatalf("import: %v %s", err, r.Error)
			}
			if r.Report.Format != c.format {
				t.Errorf("format %q, want %q", r.Report.Format, c.format)
			}
			v0194CheckProfile(t, home, c.name, []byte(r.YAML), c.minProxies, c.minGroups, r.Report.Skipped)
		})
	}
	t.Run("stash", func(t *testing.T) {
		if k := ClassifyText(v0194Stash); k == "conf" || strings.HasPrefix(k, "module") {
			t.Fatalf("stash profile classified as %q", k)
		}
		v0194CheckProfile(t, home, "stash", []byte(v0194Stash), 4, 2, nil)
	})
}

func v0194CheckProfile(t *testing.T, home, name string, y []byte, minProxies, minGroups int, skipped []string) {
	t.Helper()
	var raw map[string]any
	if err := yaml.Unmarshal(y, &raw); err != nil {
		t.Fatalf("generated YAML does not parse: %v\n%s", err, y)
	}
	if n := len(proxiesOf(raw)); n < minProxies {
		t.Errorf("%d proxies, want ≥ %d (skipped %v)\n%s", n, minProxies, skipped, y)
	}
	if g, _ := raw["proxy-groups"].([]any); len(g) < minGroups {
		t.Errorf("%d groups, want ≥ %d\n%s", len(g), minGroups, y)
	}
	p := v0194Write(t, home, name+".yaml", y)
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatalf("core refuses the imported profile: %s\n%s", e, y)
	}
	// override script round trip (YAML → JSON → script → JSON → YAML → core)
	snap, err := ScriptInputSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	sha, in, _ := strings.Cut(snap, "\n")
	out := v0194RunOverride(t, v0194Override, in, map[string]bool{"ads": true})
	if msg := ScriptOutputApplyFor(home, p, out, `["t"]`, sha); msg != "" {
		t.Fatalf("script output refused: %s", msg)
	}
	final, err := readRuntimeProfile(home, p, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(final), "OpenAI") || !strings.Contains(string(final), "DOMAIN-KEYWORD,adservice,REJECT") {
		t.Errorf("script output not used / switch not passed in:\n%s", final)
	}
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatalf("core refuses the scripted profile: %s", e)
	}
	// identity script keeps every proxy, group and rule
	out2 := v0194RunOverride(t, "function main(c){ return c }", in, nil)
	if msg := ScriptOutputApplyFor(home, p, out2, `["id"]`, sha); msg != "" {
		t.Fatalf("identity output refused: %s", msg)
	}
	f2, _ := readRuntimeProfile(home, p, false)
	var r2 map[string]any
	_ = yaml.Unmarshal(f2, &r2)
	if len(proxiesOf(r2)) != len(proxiesOf(raw)) {
		t.Errorf("identity script changed the proxy count %d → %d", len(proxiesOf(raw)), len(proxiesOf(r2)))
	}
	a, _ := raw["rules"].([]any)
	b, _ := r2["rules"].([]any)
	if len(a) != len(b) {
		t.Errorf("identity script changed the rule count %d → %d", len(a), len(b))
	}
	ScriptOutputClear(home, p)
}

// The bundled 示例配置 through the override-script round trip: every key survives YAML → JSON → YAML and
// the core still accepts it.
func TestV0194SampleProfileScriptRoundTrip(t *testing.T) {
	home := v0194Home(t)
	b, err := os.ReadFile(filepath.Join("..", "App", "Resources", "sample-profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := v0194Write(t, home, "sample.yaml", b)
	snap, err := ScriptInputSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	sha, in, _ := strings.Cut(snap, "\n")
	out := v0194RunOverride(t, "function main(c){ return c }", in, nil)
	if msg := ScriptOutputApplyFor(home, p, out, `["id"]`, sha); msg != "" {
		t.Fatalf("identity output of the sample refused: %s", msg)
	}
	var orig, got map[string]any
	_ = yaml.Unmarshal(b, &orig)
	f, _ := readRuntimeProfile(home, p, false)
	_ = yaml.Unmarshal(f, &got)
	for k := range orig {
		if _, ok := got[k]; !ok {
			t.Errorf("key %q lost in the script round trip", k)
		}
	}
	if len(proxiesOf(orig)) != len(proxiesOf(got)) {
		t.Errorf("proxies %d → %d", len(proxiesOf(orig)), len(proxiesOf(got)))
	}
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatalf("core refuses the scripted sample: %s", e)
	}
	out2 := v0194RunOverride(t, v0194Override, in, nil)
	if msg := ScriptOutputApplyFor(home, p, out2, `["t"]`, sha); msg != "" {
		t.Fatalf("sample + Bettbox script refused: %s", msg)
	}
}

// Subscription bodies as providers serve them: plain links, base64 (std / url-safe / no padding / wrapped
// lines / CRLF), with comments and junk lines, and a Clash YAML subscription.
func TestV0194SubscriptionBodies(t *testing.T) {
	home := v0194Home(t)
	uuid := "0b5e6f2a-1111-4222-8333-444455556666"
	links := []string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw1")) + "@hk.example.com:8388#HK%20SS",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw1@hk2.example.com:8389")) + "#HK2",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"JP VMess","add":"jp.example.com","port":"443","id":"`+uuid+`","aid":"0","net":"ws","type":"none","host":"jp.example.com","path":"/ws","tls":"tls","sni":"jp.example.com"}`)),
		"vless://" + uuid + "@sg.example.com:443?encryption=none&security=reality&sni=sg.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123&type=tcp&flow=xtls-rprx-vision#SG%20VLESS",
		"vless://" + uuid + "@sg2.example.com:443?encryption=none&security=tls&type=grpc&serviceName=g&sni=sg2.example.com#SG2%20gRPC",
		"trojan://pw2@us.example.com:443?sni=us.example.com&allowInsecure=1#US%20Trojan",
		"hysteria2://pw3@hy.example.com:8443?sni=hy.example.com&obfs=salamander&obfs-password=ob#HY2",
		"hy2://pw3@hy2.example.com:8443/?sni=hy2.example.com#HY2b",
		"tuic://" + uuid + ":pw4@tuic.example.com:443?alpn=h3&congestion_control=bbr&sni=tuic.example.com#TUIC",
		"anytls://pw5@at.example.com:443?sni=at.example.com#AnyTLS",
	}
	n := len(links)
	plain := strings.Join(links, "\n")
	std := base64.StdEncoding.EncodeToString([]byte(plain))
	var wrapped strings.Builder
	for i := 0; i < len(std); i += 76 {
		wrapped.WriteString(std[i:min(i+76, len(std))] + "\r\n")
	}
	bodies := map[string]string{
		"plain":       plain,
		"plain-crlf":  "# comment\r\n" + strings.Join(links, "\r\n") + "\r\n\r\n",
		"plain-junk":  "STATUS=剩余流量：100GB\n" + plain + "\nnot a link\n",
		"b64-std":     std,
		"b64-url-raw": base64.RawURLEncoding.EncodeToString([]byte(plain)),
		"b64-wrapped": wrapped.String(),
		"b64-bom":     "\ufeff" + std + "\n",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			// the app stores what ProfileStore.normalize makes of the body (ConvertShareLinks)
			conv := ConvertShareLinks(body)
			if conv == "" {
				t.Fatalf("ConvertShareLinks returned nothing: %s", LastError())
			}
			p := v0194Write(t, home, "sub-"+name+".yaml", []byte(conv))
			raw, err := profileAsMap([]byte(conv))
			if err != nil {
				t.Fatal(err)
			}
			if got := len(proxiesOf(raw)); got != n {
				var names []string
				for _, px := range proxiesOf(raw) {
					names = append(names, str(px["name"]))
				}
				t.Errorf("%d nodes, want %d: %v", got, n, names)
			}
			if e := ValidateConfigIn(home, p); e != "" {
				t.Fatalf("core refuses the subscription: %s", e)
			}
		})
	}
	// ParseNodes (manual add / node subscriptions) on the same bodies
	for name, body := range bodies {
		var ps []map[string]any
		if err := json.Unmarshal([]byte(ParseNodes(body)), &ps); err != nil || len(ps) != n {
			var names []string
			for _, px := range ps {
				names = append(names, str(px["name"]))
			}
			t.Errorf("ParseNodes(%s): %d nodes, err %v (%s) %v", name, len(ps), err, LastError(), names)
		}
	}
}

// Loon node lines (positional secret) — v0.19.4 fix: cipher / password / uuid were empty before.
func TestV0194LoonNodeLines(t *testing.T) {
	uuid := "0b5e6f2a-1111-4222-8333-444455556666"
	text := strings.Join([]string{
		`HK = Shadowsocks,hk.example.com,8388,aes-256-gcm,"p,w1",udp=true`,
		`JP = vmess,jp.example.com,443,auto,"` + uuid + `",transport=ws,path=/ws,host=jp.example.com,over-tls=true,sni=jp.example.com,alterId=0`,
		`US = trojan,us.example.com,443,"pw2",sni=us.example.com,skip-cert-verify=true,transport=ws,path=/t`,
		`SG = vless,sg.example.com,443,"` + uuid + `",transport=tcp,flow=xtls-rprx-vision,public-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,short-id=0123,sni=sg.example.com`,
		`SG2 = vless,sg2.example.com,443,"` + uuid + `",transport=grpc,service-name=g,over-tls=true,sni=sg2.example.com`,
		`HY = Hysteria2,hy.example.com,8443,"pw3",sni=hy.example.com`,
		`S5 = socks5,s5.example.com,1080,user,"pass"`,
		// Surge spelling still wins when present
		`SURGE = ss, s.example.com, 8388, encrypt-method=chacha20-ietf-poly1305, password=pw`,
	}, "\n")
	var ps []map[string]any
	if err := json.Unmarshal([]byte(ParseNodes(text)), &ps); err != nil || len(ps) != 8 {
		t.Fatalf("%d nodes, err %v (%s)", len(ps), err, LastError())
	}
	by := map[string]map[string]any{}
	for _, p := range ps {
		by[str(p["name"])] = p
	}
	want := map[string]map[string]string{
		"HK":    {"type": "ss", "cipher": "aes-256-gcm", "password": "p,w1"},
		"JP":    {"type": "vmess", "uuid": uuid, "network": "ws", "servername": "jp.example.com"},
		"US":    {"type": "trojan", "password": "pw2", "network": "ws"},
		"SG":    {"type": "vless", "uuid": uuid, "flow": "xtls-rprx-vision", "servername": "sg.example.com"},
		"SG2":   {"type": "vless", "network": "grpc"},
		"HY":    {"type": "hysteria2", "password": "pw3"},
		"S5":    {"type": "socks5", "username": "user", "password": "pass"},
		"SURGE": {"type": "ss", "cipher": "chacha20-ietf-poly1305", "password": "pw"},
	}
	for name, fields := range want {
		p := by[name]
		for k, v := range fields {
			if got := str(p[k]); got != v {
				t.Errorf("%s.%s = %q, want %q (%v)", name, k, got, v, p)
			}
		}
	}
	if _, ok := by["SG"]["reality-opts"]; !ok {
		t.Error("SG: reality-opts missing")
	}
	// every node is accepted by the core
	home := t.TempDir()
	conv := ConvertShareLinks(text)
	p := v0194Write(t, home, "loon.yaml", []byte(conv))
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatalf("core refuses Loon nodes: %s\n%s", e, conv)
	}
}

// Legacy whole-base64 ss:// links in every base64 flavour (v0.19.4: padded / URL-safe were dropped silently).
func TestV0194LegacySSLinks(t *testing.T) {
	plain := "aes-128-gcm:p@ss:w0rd@ss.example.com:8388"
	for name, enc := range map[string]*base64.Encoding{"std": base64.StdEncoding, "raw": base64.RawStdEncoding, "url": base64.URLEncoding, "rawurl": base64.RawURLEncoding} {
		link := "ss://" + enc.EncodeToString([]byte(plain)) + "#Legacy%20" + name
		var ps []map[string]any
		if err := json.Unmarshal([]byte(ParseNodes(link)), &ps); err != nil || len(ps) != 1 {
			t.Errorf("%s: %d nodes (%s)", name, len(ps), LastError())
			continue
		}
		p := ps[0]
		if str(p["cipher"]) != "aes-128-gcm" || str(p["password"]) != "p@ss:w0rd" || str(p["server"]) != "ss.example.com" || str(p["name"]) != "Legacy "+name {
			t.Errorf("%s: %v", name, p)
		}
	}
	// SIP002 and plugin links are left alone
	if got := normalizeLegacySS("ss://YWVzLTEyOC1nY206cHc@h.example.com:1?plugin=obfs-local#n"); got != "ss://YWVzLTEyOC1nY206cHc@h.example.com:1?plugin=obfs-local#n" {
		t.Errorf("SIP002 rewritten: %s", got)
	}
}

// Rewrite / MitM / rule modules in every supported format: parsed without errors, and the core rules they
// carry are accepted by mihomo when added to a profile (what addRemoteModuleRules does at connect).
func TestV0194ModulesCoreRulesParse(t *testing.T) {
	mods := map[string]string{
		"surge": `#!name=Surge Test
#!desc=desc
[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
DOMAIN-KEYWORD,tracker,REJECT-TINYGIF
IP-CIDR,203.0.113.0/24,REJECT,no-resolve
[URL Rewrite]
^https?://ad\.example\.com/ - reject
^https?://old\.example\.com/(.*) https://new.example.com/$1 302
[Header Rewrite]
^https?://api\.example\.com header-del Cookie
[Map Local]
^https?://api\.example\.com/ads data-type=text data="{}" status-code=200
[Script]
s1 = type=http-response,pattern=^https?://api\.example\.com/v1,requires-body=1,script-path=https://example.com/s.js
cron1 = type=cron,cronexp="0 8 * * *",script-path=https://example.com/c.js
[MITM]
hostname = %APPEND% api.example.com, *.example.org
`,
		"qx": `#!name=QX Test
hostname = api.example.com
^https?://ad\.example\.com url reject-200
^https?://api\.example\.com/v1 url script-response-body https://example.com/s.js
^https?://old\.example\.com url 302 https://new.example.com
`,
		"loon": `#!name=Loon Test
[Argument]
ad = switch,true,tag=去广告
[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
[Rewrite]
^https?://ad\.example\.com reject
[Script]
http-response ^https?://api\.example\.com/v1 script-path=https://example.com/s.js, requires-body=true, tag=s1, enable={ad}
[MitM]
hostname = api.example.com
`,
		"stash": `name: Stash Test
http:
  mitm:
    - api.example.com
  url-rewrite:
    - ^https?://ad\.example\.com - reject
  script:
    - match: ^https?://api\.example\.com/v1
      name: s1
      type: response
      require-body: true
script-providers:
  s1:
    url: https://example.com/s.js
    interval: 86400
rules:
  - DOMAIN-SUFFIX,ads.example.com,REJECT
`,
		"egern": `name: Egern Test
rules:
  - domain_suffix:
      match: ads.example.com
      policy: REJECT
url_rewrites:
  - match: ^https?://old\.example\.com/(.*)
    location: https://new.example.com/$1
    status_code: 302
mitm:
  hostnames:
    includes:
      - api.example.com
scriptings:
  - http_response:
      name: s1
      match: ^https?://api\.example\.com/v1
      script_url: https://example.com/s.js
      body_required: true
`,
	}
	home := v0194Home(t)
	base := []byte(v0194Stash)
	for name, text := range mods {
		var p parsedText
		if err := json.Unmarshal([]byte(EngineParseText(text, "")), &p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(p.Errors) > 0 {
			t.Errorf("%s: errors %v", name, p.Errors)
		}
		if len(p.Rules) == 0 || len(p.Hostnames) == 0 {
			t.Errorf("%s: %d rules, hostnames %v (unsupported %v)", name, len(p.Rules), p.Hostnames, p.Unsupported)
		}
		if name != "qx" && len(p.CoreRules) == 0 {
			t.Errorf("%s: no core rules", name)
		}
		// what mitm.Inject prepends for an enabled engine (policies mapped onto the profile)
		rt, err := buildRuntimeWith(base, readOverrides(home), 0, func(raw map[string]any) {
			var pre []any
			for _, r := range mitm.ResolveCoreRules(raw, p.CoreRules, nil) {
				pre = append(pre, r)
			}
			rules, _ := raw["rules"].([]any)
			raw["rules"] = append(pre, rules...)
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		C_SetHome(home)
		if _, err := executorParse(rt); err != nil {
			t.Errorf("%s: core refuses module rules %v: %v", name, p.CoreRules, err)
		}
	}
}

// Group order copy of the bundled sample + regenerate: the copy must stay valid for the core.
func TestV0194GroupOrderCopySample(t *testing.T) {
	home := v0194Home(t)
	b, err := os.ReadFile(filepath.Join("..", "App", "Resources", "sample-profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := v0194Write(t, home, "SUB-1.yaml", b)
	cp := filepath.Join(home, "profiles", "COPY-1.yaml")
	var raw map[string]any
	_ = yaml.Unmarshal(b, &raw)
	var names []string
	for _, g := range raw["proxy-groups"].([]any) {
		names = append(names, str(g.(map[string]any)["name"]))
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	order, _ := json.Marshal(names)
	var r reorderResult
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, string(order))), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("GroupOrderCopy: %+v", r)
	}
	if e := ValidateConfigIn(home, cp); e != "" {
		t.Fatalf("core refuses the reordered copy: %s", e)
	}
	cb, _ := os.ReadFile(cp)
	if got := groupNamesOf(t, cb); got[0] != names[0] {
		t.Errorf("copy order starts with %q, want %q", got[0], names[0])
	}
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Error != "" {
		t.Fatalf("regenerate: %+v", r)
	}
	if e := ValidateConfigIn(home, cp); e != "" {
		t.Fatalf("core refuses the regenerated copy: %s", e)
	}
}

func C_SetHome(home string) { C.SetHomeDir(home) }

func executorParse(b []byte) (any, error) { return executor.ParseWithBytes(b) }

// Rule lists in Surge / QX / Loon / Clash payload / Egern spelling → converted provider file → a profile
// that loads it as a file rule-provider → the core parses every converted line.
func TestV0194RuleListsThroughCore(t *testing.T) {
	lists := map[string]struct {
		text, kind string
		min        int
	}{
		"surge":   {"# c\nDOMAIN,a.example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,trk\nDOMAIN-WILDCARD,*.w.example.com\nIP-CIDR,203.0.113.0/24,no-resolve\nIP-CIDR6,2001:db8::/32\nUSER-AGENT,App*\nURL-REGEX,^https?://x\nPROCESS-NAME,App\nDEST-PORT,8443\nAND,((DOMAIN,b.example.com),(DEST-PORT,443))\n", "classical", 9},
		"qx":      {"HOST,a.example.com,proxy\nHOST-SUFFIX,example.net,proxy\nHOST-KEYWORD,trk,reject\nHOST-WILDCARD,*.w.example.com,direct\nIP-CIDR,203.0.113.0/24,direct\nIP6-CIDR,2001:db8::/32,direct\nUSER-AGENT,App*,proxy\n", "classical", 6},
		"clash":   {"payload:\n  - DOMAIN,a.example.com\n  - DOMAIN-SUFFIX,example.net\n  - IP-CIDR,203.0.113.0/24\n", "classical", 3},
		"plainip": {"203.0.113.0/24\n2001:db8::/32\n198.51.100.7\n", "classical", 3},
		"domset":  {"a.example.com\n.example.net\n# c\n+.example.org\n", "domainset", 3},
		"egern":   {"domain_set:\n  - a.example.com\ndomain_suffix_set:\n  - example.net\nip_cidr_set:\n  - 203.0.113.0/24\n", "classical", 3},
	}
	home := v0194Home(t)
	for name, l := range lists {
		out, n, _ := convertListText(strings.NewReader(l.text), l.kind)
		if n < l.min {
			t.Errorf("%s: %d rules converted, want ≥ %d:\n%s", name, n, l.min, out)
		}
		behavior := "classical"
		if l.kind == "domainset" {
			behavior = "domain"
		}
		rp := filepath.Join(home, "rules", name+".txt")
		_ = os.MkdirAll(filepath.Dir(rp), 0o755)
		_ = os.WriteFile(rp, []byte(out), 0o644)
		prof := strings.Replace(v0194Stash, "rule-providers:\n", "rule-providers:\n  conv:\n    type: file\n    behavior: "+behavior+"\n    format: text\n    path: ./rules/"+name+".txt\n", 1)
		prof = strings.Replace(prof, "rules:\n  - RULE-SET,apple,DIRECT\n", "rules:\n  - RULE-SET,conv,Proxy\n  - RULE-SET,apple,DIRECT\n", 1)
		p := v0194Write(t, home, "rl-"+name+".yaml", []byte(prof))
		if e := ValidateConfigIn(home, p); e != "" {
			t.Errorf("%s: core refuses the converted list: %s\n%s", name, e, out)
		}
	}
}

// nameserver-policy keeps its order in the runtime config (first match wins in mihomo): the profile's own
// order, and the DNS page's order (v0.19.4: both were rewritten alphabetically).
func TestV0194NameserverPolicyOrder(t *testing.T) {
	profile := []byte(`proxies:
  - {name: a, type: ss, server: a.example.com, port: 1, cipher: aes-128-gcm, password: x}
dns:
  enable: true
  nameserver: [223.5.5.5]
  nameserver-policy:
    "rule-set:corp": 10.0.0.1
    "+.z.example.com": 10.0.0.2
    "geosite:cn": 223.5.5.5
rules:
  - MATCH,DIRECT
`)
	rt, err := buildRuntime(profile, Overrides{Mode: "rule"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := string(rt)
	a, b, c := strings.Index(s, "rule-set:corp"), strings.Index(s, "+.z.example.com"), strings.Index(s, "geosite:cn")
	if !(a >= 0 && a < b && b < c) {
		t.Errorf("profile nameserver-policy order lost (%d %d %d):\n%s", a, b, c, s)
	}
	o := Overrides{Mode: "rule", DNS: &DNSOverride{Enabled: true, Nameserver: []string{"223.5.5.5"}, Foreign: []string{"8.8.8.8"}, Split: true,
		Policy: []DNSPolicy{{Match: "rule-set:zz", Servers: []string{"10.0.0.9"}}, {Match: "+.a.example.com", Servers: []string{"10.0.0.8"}}}}}
	rt, err = buildRuntime(profile, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	s = string(rt)
	a, b, c = strings.Index(s, "geosite:cn,private"), strings.Index(s, "rule-set:zz"), strings.Index(s, "+.a.example.com")
	if !(a >= 0 && a < b && b < c) {
		t.Errorf("DNS page policy order lost (%d %d %d):\n%s", a, b, c, s)
	}
}
