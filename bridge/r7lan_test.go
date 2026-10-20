package libmihomo

// v0.19.12: review 6 go-core P2-1 — Quantumult X behaviour: only the app's own HTTP / SOCKS proxy is
// shared to the LAN; a profile's protocol inbounds and legacy inbound servers are loopback-only.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

const r7LanInbounds = `listeners:
  - {name: socks-in, type: socks, port: 10808}
  - {name: http-in, type: http, listen: 0.0.0.0, port: 10814}
  - {name: ss-in, type: shadowsocks, port: 10809, cipher: aes-128-gcm, password: SSSECRETPW}
  - {name: vmess-in, type: vmess, listen: "::", port: 10815, users: [{username: u, uuid: 2b1d4b8e-1e0f-4a3c-9a7e-9c1b2f3d4e5f, alterId: 0}]}
  - {name: trojan-in, type: trojan, listen: 192.168.1.5, port: 10816, users: [{username: u, password: TROJANSECRET}]}
  - {name: vless-local, type: vless, listen: 127.0.0.1, port: 10817, users: [{username: u, uuid: 2b1d4b8e-1e0f-4a3c-9a7e-9c1b2f3d4e5f}]}
  - {name: v6-local, type: anytls, listen: "::1", port: 10818, users: {u: ANYTLSSECRET}}
  - {name: redir-in, type: redir, port: 10819}
  - {name: tproxy-in, type: tproxy, port: 10820}
  - {name: tun-in, type: tun, stack: system}
tuic-server: {enable: true, listen: "0.0.0.0:10443,[::]:10444", users: {u: TUICSECRET}}
ss-config: ss://aes-128-gcm:SSLEGACYPW@:10811,0.0.0.0:10821
vmess-config: vmess://aes-128-gcm:uuid@[::]:10812?x=1
`

func r7Listeners(raw map[string]any) map[string]map[string]any {
	got := map[string]map[string]any{}
	for _, l := range asList(raw["listeners"]) {
		m := asMap(l)
		got[str(m["name"])] = m
	}
	return got
}

func r7CaptureWarn(t *testing.T, f func()) string {
	t.Helper()
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	f()
	// events reach subscribers asynchronously: drain until quiet
	var buf bytes.Buffer
	for {
		select {
		case ev := <-sub:
			if ev.LogLevel == log.WARNING {
				buf.WriteString(ev.Payload)
				buf.WriteString("\n")
			}
		case <-time.After(300 * time.Millisecond):
			return buf.String()
		}
	}
}

func r7CheckProtocolLoopback(t *testing.T, raw map[string]any) {
	t.Helper()
	got := r7Listeners(raw)
	want := map[string]string{
		"ss-in": "127.0.0.1", "vmess-in": "127.0.0.1", "trojan-in": "127.0.0.1",
		"vless-local": "127.0.0.1", "v6-local": "::1",
	}
	for n, l := range want {
		m, ok := got[n]
		if !ok {
			t.Errorf("protocol listener %s dropped (listeners %v)", n, listenerNames(raw))
			continue
		}
		if str(m["listen"]) != l {
			t.Errorf("listener %s listen = %q, want %q", n, str(m["listen"]), l)
		}
	}
	for _, n := range []string{"redir-in", "tproxy-in", "tun-in"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s listener kept", n)
		}
	}
	if l := str(asMap(raw["tuic-server"])["listen"]); l != "127.0.0.1:10443,127.0.0.1:10444" {
		t.Errorf("tuic-server listen = %q", l)
	}
	if s := str(raw["ss-config"]); s != "ss://aes-128-gcm:SSLEGACYPW@127.0.0.1:10811,127.0.0.1:10821" {
		t.Errorf("ss-config = %q", s)
	}
	if s := str(raw["vmess-config"]); s != "vmess://aes-128-gcm:uuid@127.0.0.1:10812?x=1" {
		t.Errorf("vmess-config = %q", s)
	}
}

func r7CheckWarnings(t *testing.T, logs string) {
	t.Helper()
	for _, n := range []string{"ss-in(shadowsocks)", "vmess-in(vmess)", "trojan-in(trojan)", "tuic-server", "ss-config", "vmess-config"} {
		if !strings.Contains(logs, n) || !strings.Contains(logs, "127.0.0.1") {
			t.Errorf("no loopback warning naming %s in:\n%s", n, logs)
		}
	}
	for _, n := range []string{"vless-local", "v6-local"} {
		if strings.Contains(logs, n+"(") {
			t.Errorf("warning for already-loopback listener %s:\n%s", n, logs)
		}
	}
	for _, leak := range []string{"SSSECRETPW", "TROJANSECRET", "TUICSECRET", "SSLEGACYPW", "ANYTLSSECRET"} {
		if strings.Contains(logs, leak) {
			t.Errorf("warning leaks %s:\n%s", leak, logs)
		}
	}
}

// 局域网共享 on: protocol inbounds go to 127.0.0.1, http / socks / mixed keep LAN behaviour with the LAN users.
func TestR7LanOnProtocolInboundsLoopback(t *testing.T) {
	o := defaultOverrides()
	o.AllowLan = true
	o.MixedPort = 7890
	o.LanAuth.Username, o.LanAuth.Password = "lanuser", "lanpass99"
	var raw map[string]any
	logs := r7CaptureWarn(t, func() { raw = v01910Runtime(t, v01910Profile+r7LanInbounds, o) })
	r7CheckProtocolLoopback(t, raw)
	r7CheckWarnings(t, logs)
	got := r7Listeners(raw)
	for _, n := range []string{"socks-in", "http-in"} {
		m, ok := got[n]
		if !ok {
			t.Fatalf("%s dropped with 局域网共享 on", n)
		}
		if n == "http-in" && str(m["listen"]) != "0.0.0.0" {
			t.Errorf("http listener moved off LAN: %v", m["listen"])
		}
		users := asList(m["users"])
		if len(users) != 1 || str(asMap(users[0])["username"]) != "lanuser" {
			t.Errorf("%s users = %v", n, m["users"])
		}
	}
	if raw["allow-lan"] != true {
		t.Errorf("allow-lan = %v", raw["allow-lan"])
	}
	rt, _ := yaml.Marshal(raw)
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("runtime does not parse: %v", err)
	}
}

// 局域网共享 off: same loopback rewrite; non-loopback http / socks / mixed are still dropped.
func TestR7LanOffProtocolInboundsLoopback(t *testing.T) {
	var raw map[string]any
	logs := r7CaptureWarn(t, func() { raw = v01910Runtime(t, v01910Profile+r7LanInbounds, defaultOverrides()) })
	r7CheckProtocolLoopback(t, raw)
	r7CheckWarnings(t, logs)
	got := r7Listeners(raw)
	for _, n := range []string{"socks-in", "http-in"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s kept with 局域网共享 off", n)
		}
	}
	rt, _ := yaml.Marshal(raw)
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("runtime does not parse: %v", err)
	}
}

func TestR7LoopbackHelpers(t *testing.T) {
	for _, c := range []struct {
		in, out string
		changed, ok bool
	}{
		{"0.0.0.0:443", "127.0.0.1:443", true, true},
		{":443", "127.0.0.1:443", true, true},
		{"[::]:443", "127.0.0.1:443", true, true},
		{"127.0.0.1:443", "127.0.0.1:443", false, true},
		{"[::1]:443,localhost:80", "[::1]:443,localhost:80", false, true},
		{"443", "443", false, false},
		{"0.0.0.0", "0.0.0.0", false, false},
	} {
		out, ch, ok := loopbackHostList(c.in)
		if out != c.out || ch != c.changed || ok != c.ok {
			t.Errorf("loopbackHostList(%q) = %q %v %v", c.in, out, ch, ok)
		}
	}
	for _, c := range []struct {
		in, out string
		ok      bool
	}{
		{"ss://aes-128-gcm:p@ss/w@:8388", "ss://aes-128-gcm:p@ss/w@127.0.0.1:8388", true},
		{"ss://aes-128-gcm:pw@0.0.0.0:8388/?plugin=x", "ss://aes-128-gcm:pw@127.0.0.1:8388/?plugin=x", true},
		{"vmess://u:id@127.0.0.1:1", "vmess://u:id@127.0.0.1:1", true},
		{"garbage", "garbage", false},
		{"ss://aes-128-gcm:pw@nohostport", "ss://aes-128-gcm:pw@nohostport", false},
	} {
		out, _, ok := loopbackInboundURL(c.in)
		if out != c.out || ok != c.ok {
			t.Errorf("loopbackInboundURL(%q) = %q %v", c.in, out, ok)
		}
	}
	// a legacy key that can't be rewritten is dropped, not left on 0.0.0.0
	raw := map[string]any{"ss-config": "ss://x:y@bad", "tuic-server": map[string]any{"listen": "10443"}}
	sanitizeProfileInbounds(raw, Overrides{AllowLan: true})
	if _, ok := raw["ss-config"]; ok {
		t.Error("unparseable ss-config kept")
	}
	if _, ok := raw["tuic-server"]; ok {
		t.Error("unparseable tuic-server kept")
	}
}
