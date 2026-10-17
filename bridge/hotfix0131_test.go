package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// v0.13.1 hotfix: a Quantumult X config must classify as "conf" and convert (and the result must pass the
// same validation addLocal runs) whatever way it arrives: CRLF, UTF-8 BOM, no trailing newline, upper-case
// section names, a .txt / no-extension file (same text path) and a large file.
func TestHotfix0131QXImportVariants(t *testing.T) {
	b, err := os.ReadFile("testdata/qx_realworld.conf")
	if err != nil {
		t.Fatal(err)
	}
	base := string(b)
	var big strings.Builder
	big.WriteString(base)
	big.WriteString("\n[filter_local]\n")
	for i := 0; i < 60000; i++ { // ~2.5 MB of rules
		big.WriteString("host-suffix, example")
		big.WriteString(strings.Repeat("x", i%7))
		big.WriteString(".com, direct\n")
	}
	variants := map[string]string{
		"lf":      base,
		"crlf":    strings.ReplaceAll(base, "\n", "\r\n"),
		"bom":     "\ufeff" + base,
		"notrail": strings.TrimRight(base, "\n"),
		"upper":   strings.NewReplacer("[server_local]", "[SERVER_LOCAL]", "[policy]", "[Policy]", "[filter_local]", "[Filter_Local]").Replace(base),
		"big":     big.String(),
	}
	home := t.TempDir()
	for name, text := range variants {
		t.Run(name, func(t *testing.T) {
			if c := ClassifyText(text); c != "conf" {
				t.Fatalf("ClassifyText = %q, want conf", c)
			}
			start := time.Now()
			var r confResult
			if err := json.Unmarshal([]byte(ImportConf(text)), &r); err != nil {
				t.Fatal(err)
			}
			if r.Error != "" || r.YAML == "" {
				t.Fatalf("ImportConf error=%q yaml=%d", r.Error, len(r.YAML))
			}
			if r.Report.Format != "qx" {
				t.Fatalf("format %q", r.Report.Format)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("conversion took %s", d)
			}
			p := filepath.Join(home, name+".yaml")
			os.WriteFile(p, []byte(r.YAML), 0o644)
			if e := ValidateConfigIn(home, p); e != "" && !strings.Contains(strings.ToLower(e), "geo") && !strings.Contains(strings.ToLower(e), "mmdb") {
				t.Fatalf("validation: %s", e)
			}
		})
	}
}

// Synthetic copy of the traits of the real-world export that failed on device: "#!" header, a 4 KB
// comment line, "[server_local] " with a trailing space, an unbracketed IPv6 vmess server, QX
// "*testflight.apple.com" DNS / host wildcards, [http_backend]. The converted profile must pass the same
// validation addLocal runs (that validation failure was the "导入 does nothing" on device).
func TestHotfix0131SyntheticRealWorld(t *testing.T) {
	b, err := os.ReadFile("testdata/qx_hotfix0131.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if c := ClassifyText(text); c != "conf" {
		t.Fatalf("classify %q", c)
	}
	var r confResult
	if err := json.Unmarshal([]byte(ImportConf(text)), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error != "" || r.YAML == "" {
		t.Fatalf("error %q", r.Error)
	}
	if r.Report.Proxies != 2 {
		t.Fatalf("proxies = %d (IPv6 server dropped?) skipped=%v", r.Report.Proxies, r.Report.Skipped)
	}
	if !strings.Contains(r.YAML, "+.testflight.apple.com") || strings.Contains(r.YAML, "*testflight") {
		t.Fatalf("testflight wildcard not normalised:\n%s", r.YAML)
	}
	home := t.TempDir()
	p := filepath.Join(home, "x.yaml")
	os.WriteFile(p, []byte(r.YAML), 0o644)
	if e := ValidateConfigIn(home, p); e != "" && !strings.Contains(strings.ToLower(e), "geo") && !strings.Contains(strings.ToLower(e), "mmdb") {
		t.Fatalf("validation: %s", e)
	}
}

func TestSplitHostPortIPv6Bare(t *testing.T) {
	for in, want := range map[string]string{"2001:db8:57::8e:889f:443": "2001:db8:57::8e:889f", "[2001:db8::1]:443": "2001:db8::1", "example.com:443": "example.com"} {
		h, p, err := splitHostPort(in)
		if err != nil || h != want || p != 443 {
			t.Fatalf("%s → %q %d %v", in, h, p, err)
		}
	}
	if _, _, err := splitHostPort("example.com"); err == nil {
		t.Fatal("missing port must fail")
	}
}
