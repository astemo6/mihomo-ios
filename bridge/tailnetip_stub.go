//go:build !with_gvisor || no_tailscale

package libmihomo

import C "github.com/metacubex/mihomo/constant"

// tailnetAddrs: no Tailscale outbound in this build.
func tailnetAddrs(C.ProxyAdapter) (bool, string, string) { return false, "", "" }
