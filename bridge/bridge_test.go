package libmihomo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

const sample = `mode: rule
proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [demo, DIRECT]}
rules:
  - MATCH,PROXY
`

func TestBuildRuntimeParses(t *testing.T) {
	dir := t.TempDir()
	C.SetHomeDir(dir)
	o := defaultOverrides()
	o.Secret = "s"
	for _, fd := range []int32{0, 5} {
		rt, err := buildRuntime([]byte(sample), o, fd)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := executor.ParseWithBytes(rt)
		if err != nil {
			t.Fatalf("fd=%d parse: %v\n%s", fd, err, rt)
		}
		if fd > 0 && (!cfg.General.Tun.Enable || cfg.General.Tun.FileDescriptor != 5) {
			t.Fatalf("tun not set: %+v", cfg.General.Tun)
		}
		if cfg.Controller.ExternalController != "127.0.0.1:9090" {
			t.Fatalf("controller %q", cfg.Controller.ExternalController)
		}
	}
}

func TestConvertLinksAndValidate(t *testing.T) {
	dir := t.TempDir()
	links := "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#node1\ntrojan://pw@example.com:443?sni=example.com#node2\n"
	y := ConvertShareLinks(links)
	if y == "" || !strings.Contains(y, "node1") || !strings.Contains(y, "node2") {
		t.Fatalf("convert failed: %q %s", y, LastError())
	}
	p := filepath.Join(dir, "p.yaml")
	// GEOIP rule would download mmdb; strip it for the offline test.
	y = strings.ReplaceAll(y, "- GEOIP,CN,DIRECT\n", "")
	os.WriteFile(p, []byte(y), 0o644)
	if e := ValidateConfigIn(dir, p); e != "" {
		t.Fatalf("validate: %s\n%s", e, y)
	}
	os.WriteFile(p, []byte("proxies: [[["), 0o644)
	if e := ValidateConfigIn(dir, p); e == "" {
		t.Fatal("expected error")
	}
}
