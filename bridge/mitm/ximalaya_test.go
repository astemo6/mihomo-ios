package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// v0.19.17 喜马拉雅 report: a QX rewrite subscription that is the script file itself
// (https://raw.githubusercontent.com/WeiGiegie/666/main/ximalaya.js, saved as testdata) did nothing in
// Tern while it works in Quantumult X.

const ximalayaURL = "https://raw.githubusercontent.com/WeiGiegie/666/main/ximalaya.js"

func ximalayaFile(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/ximalaya_weigiegie.js")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestXimalayaModuleParse(t *testing.T) {
	rs := parseModuleText(string(ximalayaFile(t)), "喜马拉雅")
	if rs.Format != "qx" || len(rs.Errors) != 0 {
		t.Fatalf("format %q errors %v", rs.Format, rs.Errors)
	}
	// The /* … */ prose around [rewrite_local] and the JavaScript after it are not rules.
	if len(rs.Unsupported) != 0 {
		t.Fatalf("unsupported lines: %q", rs.Unsupported)
	}
	var scripts, rejects, reject200 int
	for _, r := range rs.Rules {
		switch {
		case r.Kind == KindScript:
			scripts++
			if r.Script.Path != ximalayaURL || r.Phase != "response" || !r.Script.RequiresBody {
				t.Errorf("script rule %+v / %+v", r, r.Script)
			}
		case r.Kind == KindURL && r.Action == "reject":
			rejects++
		case r.Kind == KindURL && r.Action == "reject-200":
			reject200++
		default:
			t.Errorf("unexpected rule %s", r.Line)
		}
	}
	if scripts != 1 || rejects != 7 || reject200 != 2 {
		t.Fatalf("scripts %d rejects %d reject-200 %d", scripts, rejects, reject200)
	}
	for _, h := range []string{"mobile.ximalaya.com", "apisg.himalaya.com", "211.152.137.*", "106.41.204.126",
		"112.99.146.108", "114.80.139.2*", "180.153.*.*", "120.22*.2*.*", "101.91.13*", "*.xmcdn.com", "*.ximalaya.com",
		"74.226.216.*"} {
		if !hasHost(rs, h) {
			t.Errorf("hostname %q missing", h)
		}
	}
}

func TestXimalayaURLRegex(t *testing.T) {
	rs := parseModuleText(string(ximalayaFile(t)), "喜马拉雅")
	var script *Rule
	for _, r := range rs.Rules {
		if r.Kind == KindScript {
			script = r
		}
	}
	for _, u := range []string{
		"https://mobile.ximalaya.com/mobile-user/v2/homePage/1729580000000?device=iPhone",
		"https://mobwsa.ximalaya.com/mobile-playpage/track/v4/baseInfo/ts-1729580000000?trackId=1&device=iPhone",
		"https://mobile.ximalaya.com/product/detail/v1/basic/ts-1729580000000?albumId=1",
		"https://mobile.ximalaya.com/mobile/v1/album/track/ts-1729580000000?albumId=1",
		"https://mobile.ximalaya.com/mobile-playpage/playpage/tabs/v2/1/ts-1729580000000",
		"https://mobile.ximalaya.com/mobile-playpage/playpage/track/qualityAndEffect/1",
		"https://mobile.ximalaya.com/mobile/download/v2/track/1/ts-1729580000000",
		"http://mobile.ximalaya.com/mobile-user/v2/homePage/1",
	} {
		ok, _ := script.re.MatchString(u)
		if !ok || !script.match(u) {
			t.Errorf("script regex does not match %s (regexp2 %v)", u, ok)
		}
	}
	for _, u := range []string{"https://mobile.ximalaya.com/discovery-feed/v4/mix", "https://example.com/mobile-user/v2/homePage/1"} {
		if script.match(u) {
			t.Errorf("script regex matches %s", u)
		}
	}
}

func TestIPv4GlobPrefixes(t *testing.T) {
	cases := map[string][]string{
		"180.153.*.*":   {"180.153.0.0/16"},
		"203.205.13*.*": {"203.205.13.0/24", "203.205.130.0/23", "203.205.132.0/22", "203.205.136.0/22"},
		"114.80.139.2*": {"114.80.139.2/32", "114.80.139.20/30", "114.80.139.24/30", "114.80.139.28/31", "114.80.139.200/29", "114.80.139.208/28", "114.80.139.224/27"},
	}
	for pat, want := range cases {
		got, ok := ipv4GlobPrefixes(pat)
		var gs []string
		for _, p := range got {
			gs = append(gs, p.String())
		}
		if !ok || strings.Join(gs, " ") != strings.Join(want, " ") {
			t.Errorf("%s: %v %v, want %v", pat, ok, gs, want)
		}
	}
	// Not an IPv4 glob, matches no address, or needs more than ipGlobMaxPrefixes prefixes (`*.*.*.5`):
	// stays a DOMAIN-WILDCARD.
	for _, pat := range []string{"*.ximalaya.com", "*xima*", "51*.com", "*", "1.2.3.4", "999.*", "*.mysteel.*", "*.*.*.5", "1?.2.*.3"} {
		if p, ok := ipv4GlobPrefixes(pat); ok {
			t.Errorf("%s expanded to %v", pat, p)
		}
	}
	// The prefixes select exactly the addresses the engine's own matcher (globMatch on the dotted form)
	// accepts: brute force over every address of the /16s the patterns touch, plus random addresses.
	rng := rand.New(rand.NewSource(1))
	for _, pat := range []string{"114.80.139.2*", "120.22*.2*.*", "101.91.13*", "58.251.62*", "198.18.1*.*", "221.204.4*.*", "43.132.8*.*", "61.172.1*.*", "1?.2.3.*", "*.1.2.3"} {
		prefixes, ok := ipv4GlobPrefixes(pat)
		if !ok {
			t.Fatalf("%s not expanded", pat)
		}
		in := func(a netip.Addr) bool {
			for _, p := range prefixes {
				if p.Contains(a) {
					return true
				}
			}
			return false
		}
		check := func(a netip.Addr) {
			if in(a) != globMatch(pat, a.String()) {
				t.Fatalf("%s: %s prefixes=%v glob=%v", pat, a, in(a), globMatch(pat, a.String()))
			}
		}
		var heads [][2]byte
		for _, p := range prefixes {
			b := p.Addr().As4()
			heads = append(heads, [2]byte{b[0], b[1]})
		}
		for _, h := range heads[:min(len(heads), 3)] {
			for c := 0; c < 256; c++ {
				for d := 0; d < 256; d++ {
					check(netip.AddrFrom4([4]byte{h[0], h[1], byte(c), byte(d)}))
				}
			}
		}
		for i := 0; i < 50000; i++ {
			check(netip.AddrFrom4([4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}))
		}
	}
}

// TestXimalayaInjectIPWildcards: the steering rule-set selects the module's IP wildcards by destination
// IP (IP-CIDR), not as DOMAIN-WILDCARD (that matched the empty host of an HTTPDNS connection: never).
func TestXimalayaInjectIPWildcards(t *testing.T) {
	rs := parseModuleText(string(ximalayaFile(t)), "喜马拉雅")
	rs.Hostnames = dedupe(rs.Hostnames)
	raw := map[string]any{"rules": []any{"MATCH,DIRECT"}}
	Inject(raw, 12345, rs, &Config{Enabled: true, MitM: true})
	rp := raw["rule-providers"].(map[string]any)["__mitm_hosts"].(map[string]any)
	payload := rp["payload"].([]any)
	set := map[string]bool{}
	for _, l := range payload {
		s := l.(string)
		if set[s] {
			t.Errorf("duplicate payload line %s", s)
		}
		set[s] = true
		if strings.HasPrefix(s, "DOMAIN-WILDCARD,") && isIPv4Glob(strings.TrimPrefix(s, "DOMAIN-WILDCARD,")) {
			t.Errorf("IP wildcard left as domain wildcard: %s", s)
		}
	}
	for _, want := range []string{"IP-CIDR,180.153.0.0/16,no-resolve", "IP-CIDR,114.80.139.2/32,no-resolve",
		"IP-CIDR,211.152.137.0/24,no-resolve", "IP-CIDR,112.99.146.108/32,no-resolve", "DOMAIN-WILDCARD,*.ximalaya.com",
		"DOMAIN,mobile.ximalaya.com", "DOMAIN-WILDCARD,*xima*"} {
		if !set[want] {
			t.Errorf("payload lacks %s", want)
		}
	}
	if len(payload) > 2000 {
		t.Errorf("payload too large: %d lines", len(payload))
	}
	rules := fmt.Sprint(raw["rules"])
	if !strings.Contains(rules, "AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,__mitm_hosts)),REJECT") ||
		!strings.Contains(rules, "(RULE-SET,__mitm_hosts)),__MITM__") {
		t.Errorf("steering rules %s", rules)
	}
}

func TestHostMatcherCertNames(t *testing.T) {
	m := NewHostMatcher([]string{"mobile.ximalaya.com", "*.ximalaya.com", "*xima*", "51*.com", "180.153.*.*", "1.2.3.4",
		"*.mysteel.*", "*.com", "api.example.com:8443", "-skip.ximalaya.com", "*.xmcdn.com"})
	got := strings.Join(m.CertNames(), " ")
	if got != "mobile.ximalaya.com *.ximalaya.com *.xmcdn.com" {
		t.Fatalf("cert names %q", got)
	}
}

// TestXimalayaEndToEnd runs the real subscription through the engine the way 喜马拉雅 connects: HTTPDNS
// gives it an IP, the CONNECT carries that IP (mihomo has no host), TLS has the domain as SNI or no SNI
// at all, and the Host header names the API domain.
func TestXimalayaEndToEnd(t *testing.T) {
	src := ximalayaFile(t)
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ModulePath(home, "xmly")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModulePath(home, "xmly"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	seedScript(t, home, ximalayaURL, src)

	var upMu sync.Mutex
	var upHits []string
	hit := func(s string) { upMu.Lock(); upHits = append(upHits, s); upMu.Unlock() }
	mux := http.NewServeMux()
	mux.HandleFunc("/mobile-user/v2/homePage/", func(w http.ResponseWriter, r *http.Request) {
		hit(r.Host + r.URL.Path)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, _ = io.WriteString(w, `{"ret":0,"msg":"成功","data":{"uid":1,"nickname":"tester","isVip":false,"vipStatus":0,"vipInfo":{"isVip":false},"svipInfo":{"isVip":false}}}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hit(r.Host + r.URL.Path)
		_, _ = io.WriteString(w, `{"upstream":true}`)
	})
	up := httptest.NewUnstartedServer(mux)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	e := New(home, dial, func(level, msg string) { t.Logf("[%s] %s", level, msg) })
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{{ID: "xmly", Name: "喜马拉雅", URL: ximalayaURL, Enabled: true}}}
	e.Reload(cfg, Build(home, cfg))
	h := &harness{t: t, home: home, e: e, ca: ca, up: up}
	dumpScriptLogs(h)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	newClient := func(sni string) *http.Client {
		tc := &tls.Config{RootCAs: pool, ServerName: sni}
		if sni == "" {
			// No SNI on the wire (Go never sends an IP as SNI); the app checks the certificate against
			// its API domain itself.
			tc = &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
				if cs.ServerName != "" {
					return fmt.Errorf("SNI %q sent", cs.ServerName)
				}
				inter := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: "mobile.ximalaya.com", Roots: pool, Intermediates: inter})
				return err
			}}
		}
		tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tc, ForceAttemptHTTP2: true, DisableCompression: true}
		return &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	get := func(c *http.Client, ip, host, path string) (int, string) {
		req, _ := http.NewRequest("GET", "https://"+ip+path, nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s via %s: %v", path, ip, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	vip := func(body string) bool {
		var v struct {
			Data struct {
				IsVip     bool `json:"isVip"`
				VipStatus int  `json:"vipStatus"`
			} `json:"data"`
		}
		return json.Unmarshal([]byte(body), &v) == nil && v.Data.IsVip && v.Data.VipStatus != 0
	}

	for _, sni := range []string{"mobile.ximalaya.com", ""} {
		c := newClient(sni)
		// 180.153.*.* and 114.80.139.2* are IP wildcards of the module's [mitm] list.
		for _, ip := range []string{"180.153.10.20", "114.80.139.25"} {
			code, body := get(c, ip, "mobile.ximalaya.com", "/mobile-user/v2/homePage/1729580000000?device=iPhone")
			if code != 200 || !vip(body) {
				t.Fatalf("sni=%q ip=%s homePage not unlocked: %d %s", sni, ip, code, clip(body, 300))
			}
		}
		code, body := get(c, "180.153.10.20", "ad.ximalaya.com", "/ting/feed")
		if code != 404 || body != "" {
			t.Errorf("sni=%q reject: %d %q", sni, code, body)
		}
		code, body = get(c, "180.153.10.20", "mobile.ximalaya.com", "/product/promotion/v1/album/price/ts-1?albumId=1")
		if code != 200 || body != "" {
			t.Errorf("sni=%q reject-200: %d %q", sni, code, body)
		}
	}
	upMu.Lock()
	defer upMu.Unlock()
	for _, hit := range upHits {
		if strings.Contains(hit, "ad.ximalaya.com") || strings.Contains(hit, "/album/price") {
			t.Errorf("rejected request reached upstream: %s", hit)
		}
	}
}
