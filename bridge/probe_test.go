package libmihomo

import (
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

func TestProbeGroupAndListener(t *testing.T) {
	prof := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: B, type: socks5, server: 127.0.0.1, port: 2}\nproxy-groups:\n  - {name: P, type: select, proxies: [A, B]}\n  - {name: H, type: url-test, proxies: [A], hidden: true}\nlisteners:\n  - {name: mine, type: socks, listen: 127.0.0.1, port: 7000}\nrules:\n  - MATCH,P\n"
	o := defaultOverrides()
	rt, err := buildRuntime([]byte(prof), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatalf("core rejects runtime config: %v\n%s", err, rt)
	}
	pg, ok := cfg.Proxies[ProbeGroup]
	if !ok {
		t.Fatalf("probe group missing")
	}
	b, _ := pg.MarshalJSON()
	var m map[string]any
	_ = yaml.Unmarshal(b, &m)
	all := asList(m["all"])
	want := map[string]bool{"A": false, "B": false, "P": false, "H": false, "DIRECT": false}
	for _, a := range all {
		if _, ok := want[str(a)]; ok {
			want[str(a)] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Fatalf("probe group lacks %s: %v", k, all)
		}
	}
	if m["hidden"] != true {
		t.Fatalf("probe group must be hidden")
	}
	found := 0
	for name, l := range cfg.Listeners {
		if name == probeListener {
			found++
			if l.RawAddress() != "127.0.0.1:7899" {
				t.Fatalf("probe listener address %s", l.RawAddress())
			}
		}
		if name == "mine" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("listeners: %v", cfg.Listeners)
	}
	// Built twice (a runtime config used as a profile) → still one group, one listener.
	rt2, err := buildRuntime(rt, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt2); err != nil {
		t.Fatalf("rebuild rejected: %v", err)
	}
}

func TestProbePortAvoidsOtherPorts(t *testing.T) {
	o := defaultOverrides()
	o.MixedPort = 7899
	o.ControllerPort = 7898
	if p := probePort(o); p != 7897 {
		t.Fatalf("probe port %d", p)
	}
}
