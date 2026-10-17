package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

const surgeConf = `[General]
dns-server = 223.5.5.5, 119.29.29.29
ipv6 = false

[Proxy]
HK = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw
JP = trojan, t.example.com, 443, password=pw, sni=t.example.com
Block = reject

[Proxy Group]
Proxy = select, Auto, HK, JP, DIRECT
Auto = url-test, HK, JP, url=http://www.gstatic.com/generate_204, interval=600
Streaming = smart, HK, JP

[Rule]
DOMAIN-SUFFIX,netflix.com,Streaming
DOMAIN-KEYWORD,ads,REJECT-TINYGIF
RULE-SET,https://example.com/apple.list,DIRECT
DOMAIN-SET,https://example.com/reject.txt,REJECT
USER-AGENT,Instagram*,Proxy
AND,((DOMAIN-SUFFIX,a.com),(DEST-PORT,443)),Proxy
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed

[URL Rewrite]
^https?://ad\.example\.com - reject

[MITM]
hostname = ad.example.com
`

const qxConf = `[general]
server_check_url=http://www.gstatic.com/generate_204

[dns]
server=223.5.5.5
server=/example.com/1.1.1.1

[policy]
static=节点选择, 香港, direct, img-url=https://x/y.png
url-latency-benchmark=自动, 香港, 美国, check-interval=600, tolerance=50

[server_local]
shadowsocks=1.2.3.4:8388, method=aes-128-gcm, password=pw, tag=香港
trojan=t.example.com:443, password=pw, over-tls=true, tls-host=t.example.com, tag=美国

[server_remote]
https://example.com/sub, tag=订阅

[filter_remote]
https://example.com/ads.list, tag=广告, force-policy=reject, update-interval=86400, enabled=true
https://example.com/off.list, tag=停用, force-policy=direct, enabled=false

[filter_local]
host-suffix, apple.com, direct
host-keyword, google, 节点选择
ip-cidr, 10.0.0.0/8, direct
user-agent, Foo*, reject
geoip, cn, direct
final, 节点选择

[rewrite_local]
^https?://ad\.example\.com url reject

[mitm]
hostname = ad.example.com
`

func TestImportConf(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	for name, text := range map[string]string{"surge": surgeConf, "qx": qxConf} {
		var r confResult
		if err := json.Unmarshal([]byte(ImportConf(text)), &r); err != nil || r.Error != "" {
			t.Fatalf("%s: %v %s", name, err, r.Error)
		}
		if r.Report.Format != name || r.Report.Proxies != 2 || !r.Report.Module || r.Report.Providers == 0 || len(r.Report.Skipped) == 0 {
			t.Fatalf("%s report %+v", name, r.Report)
		}
		rt, err := buildRuntime([]byte(r.YAML), readOverrides(home), 0)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rt), "convert+") {
			t.Fatalf("%s: convert+ URL not rewritten", name)
		}
		if _, err := executor.ParseWithBytes(rt); err != nil {
			t.Fatalf("%s: core rejected: %v\n%s", name, err, r.YAML)
		}
		lines := strings.Split(strings.TrimSpace(r.YAML), "\n")
		_ = lines
		if !strings.Contains(r.YAML, "MATCH,") {
			t.Fatalf("%s: no MATCH", name)
		}
		_ = os.WriteFile(filepath.Join(home, name+".yaml"), []byte(r.YAML), 0o644)
		t.Logf("%s: %+v", name, r.Report)
	}
	var bad confResult
	_ = json.Unmarshal([]byte(ImportConf("hello: world")), &bad)
	if bad.Error == "" {
		t.Fatal("expected error for non-conf")
	}
}
