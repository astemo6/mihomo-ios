package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

// YouTube report (v0.19.20): Maasea's YouTube (Music) Enhance module through the whole apply path
// (engine.json → planEngine → buildRuntimeWith → mihomo's own parser) — the first rule the core matches
// for youtubei.googleapis.com / *.googlevideo.com must send TCP 443 into the engine and reject UDP 443
// (QUIC; HTTP/3 can't be decrypted, the app falls back to TCP), even when the profile routes
// googleapis.com / googlevideo.com / YouTube to a proxy group and the user blocks no QUIC.
func TestYouTubeModuleSteeringThroughCore(t *testing.T) {
	home := v0194Home(t)
	mod, err := os.ReadFile("mitm/testdata/yt_enhance.sgmodule")
	if err != nil {
		t.Fatal(err)
	}
	mp := mitm.ModulePath(home, "yt")
	_ = os.MkdirAll(filepath.Dir(mp), 0o755)
	if err := os.WriteFile(mp, mod, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &mitm.Config{Enabled: true, MitM: true, Modules: []mitm.Module{{ID: "yt", Name: "YouTube", Enabled: true,
		URL: "https://raw.githubusercontent.com/Maasea/sgmodule/master/YouTube.Enhance.sgmodule"}}}
	b, _ := json.Marshal(cfg)
	_ = os.MkdirAll(mitm.EngineDir(home), 0o755)
	if err := os.WriteFile(filepath.Join(mitm.EngineDir(home), "engine.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	inject, plan, err := planEngine(home)
	if err != nil || inject == nil {
		t.Fatalf("planEngine: %v (inject %v)", err, inject != nil)
	}
	plan.commit()
	t.Cleanup(stopEngine)

	profile := strings.Replace(v0194Stash, "rules:\n", "rules:\n  - DOMAIN-SUFFIX,googlevideo.com,Proxy\n  - DOMAIN-SUFFIX,googleapis.com,Proxy\n  - DOMAIN-KEYWORD,youtube,Proxy\n", 1)
	for _, quic := range []string{"nondirect", "off", "always"} {
		o := readOverrides(home)
		o.BlockQUIC = quic
		rt, err := buildRuntimeWith([]byte(profile), o, 0, inject)
		if err != nil {
			t.Fatal(err)
		}
		C_SetHome(home)
		pc, err := executor.ParseWithBytes(rt)
		if err != nil {
			t.Fatalf("core refuses the runtime config: %v", err)
		}
		tunnel.UpdateRules(pc.Rules, pc.SubRules, pc.RuleProviders)
		first := func(m *C.Metadata) string {
			for _, r := range pc.Rules {
				if ok, _ := r.Match(m, C.RuleMatchHelper{}); ok {
					return r.Adapter()
				}
			}
			return "(none)"
		}
		for _, host := range []string{"youtubei.googleapis.com", "rr3---sn-a5mekn6r.googlevideo.com"} {
			if got := first(&C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: host, DstPort: 443}); got != mitm.ProxyName {
				t.Errorf("quic=%s: TCP %s:443 → %s, want %s", quic, host, got, mitm.ProxyName)
			}
			if got := first(&C.Metadata{NetWork: C.UDP, Type: C.TUN, Host: host, DstPort: 443}); got != "REJECT" {
				t.Errorf("quic=%s: UDP %s:443 → %s, want REJECT", quic, host, got)
			}
		}
		// Unrelated QUIC keeps the user's choice.
		if got := first(&C.Metadata{NetWork: C.UDP, Type: C.TUN, Host: "www.google.com", DstPort: 443}); quic != "always" && got == "REJECT" {
			t.Errorf("quic=%s: unrelated QUIC rejected", quic)
		}
	}
}
