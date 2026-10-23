package libmihomo

import (
	"strings"
	"syscall"
	"testing"
)

// fdOpen reports whether fd is a valid open descriptor.
func fdOpen(fd int32) bool {
	var st syscall.Stat_t
	return syscall.Fstat(int(fd), &st) == nil
}

func newSocketpair(t *testing.T) (int32, int32) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return int32(fds[0]), int32(fds[1])
}

func withQuietForget(t *testing.T) {
	t.Helper()
	old := forgetTunListener
	forgetTunListener = func() {}
	t.Cleanup(func() { forgetTunListener = old })
}

// fix/vpn-stays-on: unchanged tun settings reuse the listener's descriptor (mihomo keeps the listener); changed
// settings get a fresh dup, and the listener closing its old copy leaves the start descriptor usable.
func TestTunFdKeeperReloadKeepsDescriptorAlive(t *testing.T) {
	withQuietForget(t)
	peer, core := newSocketpair(t)
	defer syscall.Close(int(peer))
	var k tunFdKeeper
	k.begin(core)

	fd1, commit := k.pick("A")
	if fd1 == core || !fdOpen(fd1) {
		t.Fatalf("first apply must get its own open dup, got %d (base %d)", fd1, core)
	}
	commit(true)

	fd2, commit := k.pick("A")
	commit(true)
	if fd2 != fd1 {
		t.Fatalf("same tun settings must reuse fd %d, got %d", fd1, fd2)
	}

	fd3, commit := k.pick("B")
	if fd3 == fd1 || fd3 == core || !fdOpen(fd3) {
		t.Fatalf("changed tun settings need a new open dup, got %d", fd3)
	}
	commit(true)
	// mihomo closes the old listener's descriptor when it re-creates the listener.
	_ = syscall.Close(int(fd1))
	if !fdOpen(fd3) || !fdOpen(core) {
		t.Fatal("closing the old listener's descriptor must not close the new one or the base")
	}
	// The new listener's descriptor still reaches the extension's end of the socketpair.
	if _, err := syscall.Write(int(fd3), []byte{0, 0, 0, 2, 0x45}); err != nil {
		t.Fatalf("write through the new descriptor: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := syscall.Read(int(peer), buf); err != nil || n != 5 {
		t.Fatalf("peer read: n=%d err=%v", n, err)
	}

	k.end()
	if fdOpen(core) {
		t.Fatal("end must close the start descriptor")
	}
	_ = syscall.Close(int(fd3))
}

func TestTunFdKeeperFailedApplyClosesItsDup(t *testing.T) {
	withQuietForget(t)
	peer, core := newSocketpair(t)
	defer syscall.Close(int(peer))
	var k tunFdKeeper
	k.begin(core)
	fd1, commit := k.pick("A")
	commit(true)
	fd2, commit := k.pick("B")
	commit(false)
	if fdOpen(fd2) && fd2 != fd1 {
		t.Fatalf("a failed apply's dup %d must be closed", fd2)
	}
	fd3, commit := k.pick("A")
	commit(true)
	if fd3 != fd1 {
		t.Fatalf("after a failed apply the live descriptor %d stays current, got %d", fd1, fd3)
	}
	k.end()
	_ = syscall.Close(int(fd1))
}

func TestTunFdKeeperNoTun(t *testing.T) {
	withQuietForget(t)
	var k tunFdKeeper
	k.begin(0)
	fd, commit := k.pick("A")
	commit(true)
	if fd != 0 {
		t.Fatalf("no tun: got fd %d", fd)
	}
	k.end()
}

func TestTunSignatureIgnoresDescriptor(t *testing.T) {
	a := map[string]any{"tun": map[string]any{"mtu": 4064, "file-descriptor": 7}, "dns": map[string]any{"fake-ip-range": "198.18.0.1/16"}}
	b := map[string]any{"tun": map[string]any{"mtu": 4064, "file-descriptor": 9}, "dns": map[string]any{"fake-ip-range": "198.18.0.1/16"}}
	if tunSignature(a) != tunSignature(b) {
		t.Fatal("descriptor must not change the signature")
	}
	c := map[string]any{"tun": map[string]any{"mtu": 1500, "file-descriptor": 7}, "dns": map[string]any{"fake-ip-range": "198.18.0.1/16"}}
	d := map[string]any{"tun": map[string]any{"mtu": 4064, "file-descriptor": 7}, "dns": map[string]any{"fake-ip-range": "28.0.0.1/8"}}
	if tunSignature(a) == tunSignature(c) || tunSignature(a) == tunSignature(d) {
		t.Fatal("MTU or fake-ip-range changes must change the signature")
	}
}

// The runtime built for a Reload that changes the MTU carries a different descriptor than the one built at Start;
// an unchanged Reload carries the same one.
func TestBuildRuntimeTunFdFollowsSettings(t *testing.T) {
	withQuietForget(t)
	peer, core := newSocketpair(t)
	defer syscall.Close(int(peer))
	tunFds.begin(core)
	defer tunFds.end()
	profile := []byte("proxies: []\nrules:\n  - MATCH,DIRECT\n")
	build := func(mtu int) (string, func(bool)) {
		o := defaultOverrides()
		o.TunMTU = mtu
		var commit func(bool)
		rt, err := buildRuntimeWith(profile, o, core, func(raw map[string]any) { commit = setTunFd(raw) })
		if err != nil {
			t.Fatalf("buildRuntime: %v", err)
		}
		for _, l := range strings.Split(string(rt), "\n") {
			if strings.Contains(l, "file-descriptor:") {
				return strings.TrimSpace(l), commit
			}
		}
		t.Fatal("no file-descriptor in runtime")
		return "", nil
	}
	l1, c := build(4064)
	c(true)
	l2, c := build(4064)
	c(true)
	l3, c := build(1500)
	c(true)
	if l1 != l2 {
		t.Fatalf("unchanged settings: %q vs %q", l1, l2)
	}
	if l3 == l1 {
		t.Fatalf("MTU change must hand a new descriptor, both %q", l1)
	}
	if strings.HasSuffix(l1, " "+itoa(int(core))) {
		t.Fatalf("the listener must never get the start descriptor itself: %q", l1)
	}
}
