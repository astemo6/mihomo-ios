//go:build with_gvisor && !no_tailscale

package libmihomo

import (
	"reflect"
	"unsafe"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tailscale/tsnet"
)

// tailnetAddrs reads the tailnet addresses of a started Tailscale outbound. mihomo keeps its tsnet server
// unexported, so this looks it up by field name; a renamed field (core upgrade) or a server that is not up yet
// gives no address instead of a guess.
func tailnetAddrs(pa C.ProxyAdapter) (started bool, v4, v6 string) {
	defer func() {
		if recover() != nil {
			started, v4, v6 = false, "", ""
		}
	}()
	ts, ok := pa.(*outbound.Tailscale)
	if !ok || ts == nil {
		return false, "", ""
	}
	v := reflect.ValueOf(ts).Elem()
	sf, srv := v.FieldByName("serverStarted"), v.FieldByName("server")
	if !sf.IsValid() || sf.Kind() != reflect.Bool || !srv.IsValid() || srv.Kind() != reflect.Pointer || srv.IsNil() {
		return false, "", ""
	}
	if srv.Type() != reflect.TypeOf((*tsnet.Server)(nil)) || !sf.Bool() {
		return false, "", ""
	}
	s := (*tsnet.Server)(unsafe.Pointer(srv.Pointer()))
	a4, a6 := s.TailscaleIPs()
	if a4.IsValid() {
		v4 = a4.String()
	}
	if a6.IsValid() {
		v6 = a6.String()
	}
	return true, v4, v6
}
