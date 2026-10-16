package libmihomo

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseAllProtocols(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	vmessJSON := `{"v":"2","ps":"vm","add":"v.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"ws","path":"/ws","host":"v.example.com","tls":"tls"}`
	cases := map[string]string{
		"ss":         "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#ss1",
		"ss2022":     "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@1.2.3.4:8388#ss2022",
		"ssr":        "ssr://" + b64("1.2.3.4:8388:origin:aes-256-cfb:plain:"+b64("pw")+"/?remarks="+b64("ssr1")),
		"vmess":      "vmess://" + b64(vmessJSON),
		"vless":      "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=7Pq1mu0nSG2Jm1TTaR8dhJOiwSIn0PFk5Jc7mzeK_zU&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision&type=tcp#vless1",
		"trojan":     "trojan://pw@t.example.com:443?sni=t.example.com#tj",
		"hysteria":   "hysteria://h.example.com:443?protocol=udp&auth=pw&peer=h.example.com&upmbps=50&downmbps=100#hy1",
		"hysteria2":  "hysteria2://pw@h2.example.com:443?sni=h2.example.com#hy2a",
		"hy2":        "hy2://pw@h2.example.com:443?sni=h2.example.com#hy2b",
		"tuic":       "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example.com:443?congestion_control=bbr&alpn=h3&sni=tu.example.com#tuic1",
		"wireguard":  "wireguard://" + "yAnz5TF%2BlXXJte14tji3zlMNq%2BhD2rYUIgJBgB3fBmk%3D" + "@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32,2606:4700::2%2F128&reserved=1,2,3&mtu=1280#wg1",
		"wg":         "wg://162.159.192.1:2408?pk=yAnz5TF%2BlXXJte14tji3zlMNq%2BhD2rYUIgJBgB3fBmk%3D&peer_pk=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&local_address=172.16.0.2/32#wg2",
		"socks5":     "socks5://user:pass@1.2.3.4:1080#s5",
		"socks-b64":  "socks://" + b64("user:pass") + "@1.2.3.4:1080#s5b",
		"http":       "http://user:pass@1.2.3.4:8080#h1",
		"https":      "https://user:pass@1.2.3.4:443#h2",
		"anytls":     "anytls://pw@a.example.com:443?sni=a.example.com#any1",
		"snell":      "snell://psk123@1.2.3.4:6333?version=4&obfs=http&obfs-host=bing.com#sn1",
		"mieru":      "mierus://user:pass@1.2.3.4?port=6666&protocol=TCP&profile=default#mi1",
		"surge-ss":   "SurgeSS = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw, obfs=http, obfs-host=bing.com, udp-relay=true",
		"surge-vm":   "SurgeVM = vmess, v.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, ws=true, ws-path=/ws, ws-headers=Host:v.example.com, tls=true, sni=v.example.com",
		"surge-tj":   "SurgeTJ = trojan, t.example.com, 443, password=pw, sni=t.example.com",
		"surge-sn":   "SurgeSN = snell, 1.2.3.4, 6333, psk=abc, version=4",
		"surge-hy2":  "SurgeHY2 = hysteria2, h.example.com, 443, password=pw, sni=h.example.com",
		"surge-tuic": "SurgeTUIC = tuic-v5, tu.example.com, 443, uuid=b831381d-6324-4d53-ad4f-8cda48b30811, password=pw, sni=tu.example.com",
		"surge-any":  "SurgeAny = anytls, a.example.com, 443, password=pw",
		"surge-ssh":  "SurgeSSH = ssh, 1.2.3.4, 22, username=root, password=pw",
		"surge-s5":   "SurgeS5 = socks5, 1.2.3.4, 1080, user, pass",
		"surge-http": "SurgeHTTP = https, 1.2.3.4, 443, user, pass",
		"qx-ss":      "shadowsocks=1.2.3.4:8388, method=aes-128-gcm, password=pw, obfs=http, obfs-host=bing.com, udp-relay=true, tag=QXSS",
		"qx-vmess":   "vmess=v.example.com:443, method=chacha20-ietf-poly1305, password=b831381d-6324-4d53-ad4f-8cda48b30811, obfs=wss, obfs-host=v.example.com, obfs-uri=/ws, tag=QXVM",
		"qx-vless":   "vless=1.2.3.4:443, method=none, password=b831381d-6324-4d53-ad4f-8cda48b30811, obfs=over-tls, obfs-host=www.apple.com, reality-base64-pubkey=7Pq1mu0nSG2Jm1TTaR8dhJOiwSIn0PFk5Jc7mzeK_zU, reality-hex-shortid=6ba85179e30d4fc2, vless-flow=xtls-rprx-vision, tag=QXVL",
		"qx-trojan":  "trojan=t.example.com:443, password=pw, over-tls=true, tls-host=t.example.com, tag=QXTJ",
		"qx-http":    "http=1.2.3.4:8080, username=u, password=p, tag=QXH",
		"qx-socks":   "socks5=1.2.3.4:1080, username=u, password=p, tag=QXS",
	}
	for k, line := range cases {
		js := ParseNodes(line)
		if js == "" {
			t.Errorf("%s: parse failed: %s", k, LastError())
			continue
		}
		var ps []map[string]any
		json.Unmarshal([]byte(js), &ps)
		if len(ps) != 1 {
			t.Errorf("%s: got %d nodes", k, len(ps))
			continue
		}
		b, _ := json.Marshal(ps[0])
		dir := t.TempDir()
		p := filepath.Join(dir, "m.yaml")
		if e := ManualUpsert(p, string(b), ""); e != "" {
			t.Errorf("%s: core rejected %s: %s", k, b, e)
		} else {
			t.Logf("%s OK type=%v", k, ps[0]["type"])
		}
	}
	// base64 subscription with several links
	sub := b64(cases["ss"] + "\n" + cases["trojan"] + "\n" + cases["vless"] + "\n" + cases["wireguard"])
	js := ParseNodes(sub)
	var ps []map[string]any
	json.Unmarshal([]byte(js), &ps)
	if len(ps) != 4 {
		t.Fatalf("base64 sub: got %d (%s)", len(ps), LastError())
	}
	// manual profile flow
	dir := t.TempDir()
	mp := filepath.Join(dir, "manual.yaml")
	if n := ManualAddText(mp, cases["ss"]+"\n"+cases["ss"]); n != 2 {
		t.Fatalf("ManualAddText=%d %s", n, LastError())
	}
	var l []map[string]any
	json.Unmarshal([]byte(ManualList(mp)), &l)
	if len(l) != 2 || l[0]["name"] == l[1]["name"] {
		t.Fatalf("manual list %v", l)
	}
	if e := ManualDelete(mp, l[0]["name"].(string)); e != "" {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(mp)
	if e := validateBytes(b); e != "" {
		t.Fatalf("manual profile invalid: %s\n%s", e, b)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
