package libmihomo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkBuildRuntime measures the full runtime-config build for a large
// profile (500 proxies): YAML parse, override / subscription merges, group
// processing and serialization — the cold-start hot path.
func BenchmarkBuildRuntime(b *testing.B) {
	root, err := os.MkdirTemp("", "buildbench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(root)
	home := filepath.Join(root, "engine")
	profiles := filepath.Join(root, "profiles")
	if err := os.MkdirAll(home, 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		b.Fatal(err)
	}

	const nodes = 500
	var sb strings.Builder
	sb.WriteString("mixed-port: 7890\nmode: rule\nlog-level: info\nproxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&sb, "  - {name: node-%03d, type: ss, server: 10.0.%d.%d, port: 8388, cipher: aes-128-gcm, password: test}\n",
			i, i/256, i%256)
	}
	names := make([]string, nodes)
	for i := range names {
		names[i] = fmt.Sprintf("node-%03d", i)
	}
	joined := strings.Join(names, ", ")
	sb.WriteString("proxy-groups:\n")
	fmt.Fprintf(&sb, "  - {name: select-all, type: select, proxies: [%s]}\n", joined)
	fmt.Fprintf(&sb, "  - {name: auto, type: url-test, proxies: [%s], url: 'http://www.gstatic.com/generate_204', interval: 300}\n", joined)
	sb.WriteString(`rules:
  - DOMAIN-SUFFIX,google.com,select-all
  - DOMAIN-KEYWORD,cdn,auto
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - MATCH,select-all
`)
	profile := []byte(sb.String())
	profilePath := filepath.Join(profiles, "bench.yaml")
	if err := os.WriteFile(profilePath, profile, 0o644); err != nil {
		b.Fatal(err)
	}

	o := overridesFor(home, profilePath)
	if _, err := buildRuntime(profile, o, 0); err != nil {
		b.Fatalf("buildRuntime: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buildRuntime(profile, o, 0); err != nil {
			b.Fatal(err)
		}
	}
}
