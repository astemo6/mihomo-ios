//go:build with_gvisor

package libmihomo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

// v0.18: the real Tailscale outbound (tsnet) behind the memory guard. Runs with -tags with_gvisor
// (ui-tests.yml go job, "go test (with_gvisor)").

type fakeProbe struct{ fp, avail atomic.Int64 }

func (f *fakeProbe) Footprint() int64 { return f.fp.Load() }
func (f *fakeProbe) Available() int64 { return f.avail.Load() }

func TestV018TailscaleGuard(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	profile := []byte(`
proxies:
  - {name: ts, type: tailscale, auth-key: tskey-auth-xxxx, control-url: "http://127.0.0.1:9", udp: true}
proxy-groups:
  - {name: G, type: select, proxies: [ts, DIRECT]}
rules:
  - MATCH,G
`)
	rt, err := buildRuntime(profile, Overrides{home: home, ControllerPort: 19099, Secret: "x", DNSMode: "fake-ip"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), "state-dir: tailscale/ts-") {
		t.Fatalf("state-dir not normalized:\n%s", rt)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatalf("tailscale node does not parse with with_gvisor: %v", err)
	}
	guardTailscale(cfg)
	p := cfg.Proxies["ts"].(*adapter.Proxy)
	g, ok := p.ProxyAdapter.(*tsGuard)
	if !ok {
		t.Fatalf("not guarded: %T", p.ProxyAdapter)
	}
	defer g.Close()
	if !strings.Contains(TailscaleStatus(), `"nodes":1`) {
		t.Fatalf("status %s", TailscaleStatus())
	}

	probe := &fakeProbe{}
	probe.fp.Store(38 << 20)
	probe.avail.Store(10 << 20)
	SetMemoryProbe(probe)
	defer SetMemoryProbe(nil)
	md := &C.Metadata{NetWork: C.TCP, Host: "100.64.0.1", DstPort: 80}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = p.DialContext(ctx, md)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "Tailscale 未启动") {
		t.Fatalf("low memory start not refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "tailscale")); err == nil {
		t.Fatalf("tsnet started although refused")
	}
	if !strings.Contains(TailscaleStatus(), `"state":"refused"`) {
		t.Fatalf("status %s", TailscaleStatus())
	}

	// Enough headroom: tsnet starts (the control server is unreachable, so the dial itself fails).
	probe.fp.Store(25 << 20)
	probe.avail.Store(25 << 20)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = p.DialContext(ctx, md)
	cancel()
	if err == nil {
		t.Fatalf("dial without control server succeeded")
	}
	st := TailscaleStatus()
	if !strings.Contains(st, `"footprintBefore":26214400`) || strings.Contains(st, `"state":"refused"`) {
		t.Fatalf("start not recorded: %s", st)
	}
	entries, _ := os.ReadDir(filepath.Join(home, "tailscale"))
	if len(entries) != 1 {
		t.Fatalf("state dir not created inside home: %v", entries)
	}

	// Headroom gone: the watchdog stops tsnet and later dials say so.
	probe.avail.Store(2 << 20)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(TailscaleStatus(), `"state":"stopped"`) {
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(TailscaleStatus(), `"state":"stopped"`) {
		t.Fatalf("not stopped: %s", TailscaleStatus())
	}
	probe.avail.Store(30 << 20)
	if _, err := p.DialContext(context.Background(), md); err == nil || !strings.Contains(err.Error(), "Tailscale 已停止") {
		t.Fatalf("dial after stop: %v", err)
	}
}
