package libmihomo

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secrets that must never appear anywhere in a diagnostic bundle.
var diagSecrets = []string{
	"hk1.secret-airport.example", "203.0.113.77", "s3cr3t-pass", "b831381d-6324-4d53-ad4f-8cda48b30811",
	"Zk8eKxPrivKeyBase64AAAAAAAAAAAAAAAAAAAAAAA=", "QmFzZTY0UHViS2V5Rm9yUmVhbGl0eQ", "a1b2c3d4", "sub.airport.example",
	"tok3nABCDEF123456", "ctrl-secret-123456", "userpw:hunter22", "sni.secret.example", "/wspath-token-777",
	"wgpeer.example.net", "psk-0000-shared", "myid42abc", "bearerTOKEN12345678",
}

const diagProfile = `
mixed-port: 7890
secret: ctrl-secret-123456
authentication: ["userpw:hunter22"]
proxies:
  - {name: 香港 01, type: ss, server: hk1.secret-airport.example, port: 8388, cipher: aes-128-gcm, password: s3cr3t-pass}
  - name: 美国 VLESS
    type: vless
    server: 203.0.113.77
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    servername: sni.secret.example
    network: ws
    ws-opts: {path: /wspath-token-777, headers: {Host: sni.secret.example}}
    reality-opts: {public-key: QmFzZTY0UHViS2V5Rm9yUmVhbGl0eQ, short-id: a1b2c3d4}
  - name: WG
    type: wireguard
    server: wgpeer.example.net
    port: 51820
    ip: 172.16.0.2
    private-key: Zk8eKxPrivKeyBase64AAAAAAAAAAAAAAAAAAAAAAA=
    public-key: QmFzZTY0UHViS2V5Rm9yUmVhbGl0eQ
    pre-shared-key: psk-0000-shared
proxy-providers:
  airport:
    type: http
    url: https://sub.airport.example/api/v1/client/subscribe?token=tok3nABCDEF123456
    path: ./providers/airport.yaml
rule-providers:
  reject:
    type: http
    behavior: domain
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt
dns:
  nameserver: ["https://dns.nextdns.io/myid42abc", "223.5.5.5"]
proxy-groups:
  - {name: 节点选择, type: select, proxies: [香港 01, 美国 VLESS, WG]}
rules:
  - DOMAIN-SUFFIX,google.com,节点选择
  - MATCH,DIRECT
`

func writeDiagHome(t *testing.T) (home, profile string) {
	t.Helper()
	container := t.TempDir()
	home = filepath.Join(container, "mihomo")
	_ = os.MkdirAll(filepath.Join(home, "diag"), 0o755)
	_ = os.MkdirAll(filepath.Join(container, "profiles"), 0o755)
	profile = filepath.Join(container, "profiles", "p1.yaml")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(profile, []byte(diagProfile), 0o644))
	must(os.WriteFile(filepath.Join(home, "runtime.yaml"), []byte(diagProfile), 0o644))
	must(os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"secret":"ctrl-secret-123456","logLevel":"info"}`), 0o644))
	must(os.WriteFile(filepath.Join(container, "profiles.json"),
		[]byte(`[{"id":"p1","name":"机场","kind":"remote","url":"https://sub.airport.example/link/tok3nABCDEF123456?clash=1"}]`), 0o644))
	must(os.WriteFile(filepath.Join(container, "startup-log.txt"),
		[]byte("12:00:00.000 [ext] dial hk1.secret-airport.example:8388 (203.0.113.77) failed\n12:00:01 [core] fetch https://sub.airport.example/api?token=tok3nABCDEF123456\n"), 0o644))
	must(os.WriteFile(filepath.Join(home, "diag", "core-log.txt"),
		[]byte("INFO [TCP] 198.18.0.3:5000 --> www.apple.com:443 match DomainSuffix using 香港 01[hk1.secret-airport.example]\nWARN uuid=b831381d-6324-4d53-ad4f-8cda48b30811 password: s3cr3t-pass\nINFO Authorization: Bearer bearerTOKEN12345678\n"), 0o644))
	return home, profile
}

func TestDiagnosticBundleRedaction(t *testing.T) {
	home, profile := writeDiagHome(t)
	out := filepath.Join(t.TempDir(), "diag.zip")
	if err := WriteDiagnosticBundle(home, profile, "app=0.6.0 (20)\ngroup=group.test ok=true", out); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	seen := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		seen[strings.TrimPrefix(f.Name, "mihomo-diagnostics/")] = string(b)
		for _, s := range diagSecrets {
			if strings.Contains(string(b), s) {
				t.Errorf("%s leaks %q", f.Name, s)
			}
		}
	}
	for _, want := range []string{"info.txt", "startup-log.txt", "core-log.txt", "memory.txt", "modules.txt", "config-effective.yaml", "config-next-start.yaml", "settings/overrides.json", "settings/profiles.json", "README.txt"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("bundle misses %s", want)
		}
	}
	eff := seen["config-effective.yaml"]
	// still useful: node names, types, ports, groups, rules and public rule-set URLs survive
	for _, keep := range []string{"香港 01", "type: vless", "port: 8388", "节点选择", "DOMAIN-SUFFIX,google.com", "testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt", "223.5.5.5", "<redacted-url>"} {
		if !strings.Contains(eff, keep) {
			t.Errorf("effective config lost %q:\n%s", keep, eff)
		}
	}
	if !strings.Contains(seen["core-log.txt"], "www.apple.com") || !strings.Contains(seen["core-log.txt"], "198.18.0.3") {
		t.Errorf("core log over-redacted: %s", seen["core-log.txt"])
	}
	if !strings.Contains(seen["startup-log.txt"], "203.0.x.x") && !strings.Contains(seen["startup-log.txt"], "<redacted>") {
		t.Errorf("startup log: %s", seen["startup-log.txt"])
	}
	if !strings.Contains(seen["info.txt"], "app=0.6.0") || !strings.Contains(seen["info.txt"], "core=") {
		t.Errorf("info: %s", seen["info.txt"])
	}
	// the text summary uses the same redaction
	sum := DiagnosticSummary(home, profile, "app=0.6.0")
	for _, s := range diagSecrets {
		if strings.Contains(sum, s) {
			t.Errorf("summary leaks %q", s)
		}
	}
}

func TestRedactText(t *testing.T) {
	r := newRedactor()
	cases := map[string]string{
		"vmess uuid 0e5c2f3a-1111-4222-8333-944445555666 ok": "vmess uuid <uuid> ok",
		"GET https://a.example/sub?token=abc&x=1 200":        "GET https://a.example/sub?<redacted> 200",
		"socks5://user:pw@1.2.3.4:1080":                      "socks5://<redacted>@1.2.x.x:1080",
		"password=hunter2, next":                             "password=<redacted>, next",
		"dns 8.8.8.8 and 192.168.1.1 and 198.18.0.9":         "dns 8.8.8.8 and 192.168.1.1 and 198.18.0.9",
	}
	for in, want := range cases {
		if got := r.text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
	if got := r.sanitizeURL("https://dns.nextdns.io/abc123def"); strings.Contains(got, "abc123def") {
		t.Errorf("token path kept: %s", got)
	}
	if got := r.sanitizeURL("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"); got != "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb" {
		t.Errorf("public URL changed: %s", got)
	}
}

func TestLineRingCap(t *testing.T) {
	r := newLineRing(100, 50)
	for i := 0; i < 10000; i++ {
		r.add(strings.Repeat("z", 200))
	}
	lines, seq := r.snapshot()
	if len(lines) > 100 || seq != 10000 {
		t.Fatalf("ring len %d seq %d", len(lines), seq)
	}
	for _, l := range lines {
		if len(l) > 50+len("…") {
			t.Fatalf("line not clipped: %d", len(l))
		}
	}
}

func TestDumpDiagnosticsWritesRings(t *testing.T) {
	home := t.TempDir()
	dumpMu.Lock()
	dumpHome = home
	dumpedSeq = [2]uint64{}
	dumpMu.Unlock()
	coreLog.add("12:00:00 INFO hello")
	RecordMemorySample(30<<20, 12<<20)
	DumpDiagnostics()
	b, err := os.ReadFile(filepath.Join(home, "diag", "core-log.txt"))
	if err != nil || !strings.Contains(string(b), "hello") {
		t.Fatalf("core log dump: %v %q", err, b)
	}
	m, err := os.ReadFile(filepath.Join(home, "diag", "memory.txt"))
	if err != nil || !strings.Contains(string(m), "footprint 30.0 MB") {
		t.Fatalf("memory dump: %v %q", err, m)
	}
}

func TestFriendlyError(t *testing.T) {
	cases := map[string]string{
		"yaml: line 3: mapping values are not allowed in this context": "YAML",
		"proxy group[0]: 'proxies' missing":                            "策略组",
		"rule-provider reject: can't download":                         "规则集",
		"listen tcp 127.0.0.1:7890: bind: address already in use":      "端口",
		"something odd": "配置无效",
	}
	for in, want := range cases {
		if got := friendlyError(errors.New(in)).Error(); !strings.Contains(got, want) || !strings.Contains(got, in) {
			t.Errorf("friendlyError(%q) = %q, want it to mention %q", in, got, want)
		}
	}
	if got := FriendlyError("读取配置失败"); got != "读取配置失败" {
		t.Errorf("chinese message rewritten: %q", got)
	}
}

func TestSafeModeSkipsCustomRulesAndEngine(t *testing.T) {
	home, profile := writeDiagHome(t)
	_ = os.WriteFile(filepath.Join(home, "rules.json"), []byte(`{"rules":[{"id":"1","enabled":true,"line":"DOMAIN,custom-rule.example,DIRECT"}]}`), 0o644)
	prof, _ := os.ReadFile(profile)
	o := overridesFor(home, profile)
	rt, err := buildRuntime(prof, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), "custom-rule.example") {
		t.Fatal("custom rule not applied in normal mode")
	}
	o.SafeMode = true
	rt, err = buildRuntime(prof, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rt), "custom-rule.example") {
		t.Fatal("safe mode kept custom rules")
	}
}

func TestSafeApplyRecoversPanic(t *testing.T) {
	// a missing profile is an error, never a panic
	if err := safeApply(t.TempDir(), "/nonexistent/profile.yaml", 0); err == nil || !strings.Contains(err.Error(), "读取配置失败") {
		t.Fatalf("missing profile: %v", err)
	}
}
