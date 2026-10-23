//go:build with_gvisor && !no_tailscale

package libmihomo

import (
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/tailscale/tsnet"
)

// TestV018TailnetAddrsFieldsPresent (named TestV018… so the with_gvisor CI step runs it): tailnetAddrs reads mihomo's unexported Tailscale fields by name (the 更多 →
// 高级设置 → 网络 → Tailscale tailnet IP). A core upgrade that renames or retypes them must fail here instead
// of silently showing no address (checked on mihomo v1.19.33).
func TestV018TailnetAddrsFieldsPresent(t *testing.T) {
	typ := reflect.TypeOf(outbound.Tailscale{})
	sf, ok := typ.FieldByName("serverStarted")
	if !ok || sf.Type.Kind() != reflect.Bool {
		t.Fatalf("outbound.Tailscale.serverStarted missing or not bool: %v", sf.Type)
	}
	srv, ok := typ.FieldByName("server")
	if !ok || srv.Type != reflect.TypeOf((*tsnet.Server)(nil)) {
		t.Fatalf("outbound.Tailscale.server missing or not *tsnet.Server: %v", srv.Type)
	}
	// Not started: no address, no panic.
	if started, v4, v6 := tailnetAddrs(&outbound.Tailscale{}); started || v4 != "" || v6 != "" {
		t.Fatalf("zero Tailscale: started=%v %q %q", started, v4, v6)
	}
}
