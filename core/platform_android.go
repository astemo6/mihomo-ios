//go:build android

package libmihomo

import (
	"errors"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
)

func init() {
	platformMemoryLimitHook = func(int) int { return androidMemLimitMB }
	platformTunHook = androidTun
}

// SocketProtector is implemented by the Android VpnService (VpnService.protect(fd)): every socket the
// core opens is excluded from the VPN so the core's own traffic never loops back into the tun.
// Same mechanism as ClashMetaForAndroid (dialer.DefaultSocketHook, GPL-3.0).
type SocketProtector interface {
	Protect(fd int32) bool
}

var errProtect = errors.New("VpnService.protect failed")

// SetSocketProtector installs (or with nil removes) the protect hook. Call before Start.
func SetSocketProtector(p SocketProtector) {
	if p == nil {
		dialer.DefaultSocketHook = nil
		return
	}
	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		ok := true
		if err := conn.Control(func(fd uintptr) { ok = p.Protect(int32(fd)) }); err != nil {
			return err
		}
		if !ok {
			return errProtect
		}
		return nil
	}
}
