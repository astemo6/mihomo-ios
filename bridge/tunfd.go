package libmihomo

// fix/vpn-stays-on: the tun descriptor must survive a Reload that changes the tun listener.
//
// mihomo re-creates its tun listener whenever the parsed tun settings differ from the last ones (MTU, the tun
// address derived from dns.fake-ip-range — another profile, the DNS page —, IPv6, …). Closing the old listener
// closes the descriptor it was given (sing-tun NativeTun.Close → tunFile.Close). Every apply used to hand the
// listener the one descriptor from Start, so after such a Reload the new listener opened an already closed
// descriptor: the tunnel stayed "connected" in iOS but no packet reached the core any more until the user
// reconnected. Since the core also had no way to tell a fresh Start in a reused extension process from a reload
// (same descriptor number → equal settings → no listener at all), a quick reconnect could end the same way.
//
// Now the core keeps the descriptor from Start (base) to itself and gives the listener a dup of it. A Reload
// whose tun settings are unchanged reuses that dup (mihomo sees equal settings and keeps the listener and its
// connections); a Reload that changes them gets a new dup, so the listener mihomo closes takes only its own copy.

import (
	"encoding/json"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
)

type tunFdKeeper struct {
	mu     sync.Mutex
	base   int32  // the descriptor Start got (the core owns it); never given to a listener
	handed int32  // the dup the live tun listener was given (0 = none yet)
	sig    string // tun settings the handed descriptor was given with
}

var tunFds tunFdKeeper

// dupFd is replaceable in tests.
var dupFd = func(fd int32) (int32, error) {
	n, err := syscall.Dup(int(fd))
	if err != nil {
		return 0, err
	}
	syscall.CloseOnExec(n)
	return int32(n), nil
}

// begin is called by Start with the descriptor from the extension. A previous connection's descriptors are
// gone by now (Stop / the stale teardown ran end); nothing is closed here.
func (k *tunFdKeeper) begin(fd int32) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.base, k.handed, k.sig = fd, 0, ""
}

// pick returns the descriptor to write into this apply's tun settings, and a commit func that must be called
// with whether the apply went live. A descriptor dup'ed for an apply that failed is closed again; the listener
// then keeps the one it has.
func (k *tunFdKeeper) pick(sig string) (int32, func(ok bool)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.base <= 0 {
		return k.base, func(bool) {}
	}
	if k.handed > 0 && sig == k.sig {
		return k.handed, func(bool) {}
	}
	fd, err := dupFd(k.base)
	if err != nil {
		// No spare descriptor: the base itself (the previous behaviour). A later change of tun settings then
		// cannot be applied without a reconnect, but this connection works.
		stage("tun fd: dup failed (%s), using the start descriptor", err.Error())
		return k.base, func(bool) {}
	}
	return fd, func(ok bool) {
		k.mu.Lock()
		defer k.mu.Unlock()
		if !ok {
			_ = syscall.Close(int(fd))
			return
		}
		// The previous dup is closed by mihomo together with the old listener.
		k.handed, k.sig = fd, sig
	}
}

// end closes the base descriptor (the listener's dup is closed by mihomo's listener cleanup) and forgets the
// last tun settings, so the next Start always creates a listener even when the extension process is reused and
// the new descriptor has the old number.
func (k *tunFdKeeper) end() {
	k.mu.Lock()
	base := k.base
	k.base, k.handed, k.sig = 0, 0, ""
	k.mu.Unlock()
	if base > 0 {
		_ = syscall.Close(int(base))
	}
	forgetTunListener()
}

// forgetTunListener closes a remaining tun listener and resets mihomo's LastTunConf through its own locked path
// (a disabled config never touches the tunnel argument).
var forgetTunListener = func() { listener.ReCreateTun(LC.Tun{}, nil) }

// tunSignature: what decides the listener's settings — the tun section without the descriptor, plus the
// fake-ip ranges mihomo derives the tun addresses from.
func tunSignature(raw map[string]any) string {
	tun := asMap(raw["tun"])
	cp := make(map[string]any, len(tun))
	for k, v := range tun {
		if k != "file-descriptor" {
			cp[k] = v
		}
	}
	dns := asMap(raw["dns"])
	sig := map[string]any{"tun": cp, "fake-ip-range": dns["fake-ip-range"], "fake-ip-range6": dns["fake-ip-range6"]}
	b, err := json.Marshal(sig) // map keys are sorted
	if err != nil {
		return ""
	}
	return string(b)
}

// setTunFd picks the descriptor for this apply and writes it into raw. Returns the commit func.
func setTunFd(raw map[string]any) func(ok bool) {
	tun, ok := raw["tun"].(map[string]any)
	if !ok {
		return func(bool) {}
	}
	fd, commit := tunFds.pick(tunSignature(raw))
	tun["file-descriptor"] = int(fd)
	return commit
}
