package libmihomo

// feat/go-pagereturn — page accounting probe (memory bench only: UnitTests/NativeMitmMemoryTests
// testPageAccounting; never called by the app or the tunnel).
//
// Question it answers: does the kernel take pages out of phys_footprint as soon as Go releases them
// (madvise MADV_FREE_REUSABLE, what Go 1.26's sysUnusedOS does on darwin/ios), or only later — the reason
// Tailscale once patched its Go fork (tailscale/go 38ab03e: mprotect(PROT_NONE) + mprotect(RW) right after the
// madvise)? If REUSABLE is credited at once, that runtime patch cannot give anything on top of returning pages
// sooner (debug.FreeOSMemory / pagereturn.go). The probe works on a private anonymous mapping, step by step,
// so the Swift side can read phys_footprint between the steps:
//   PageAcctMap(mb)      mmap + write every page (resident, dirty)
//   PageAcctAdvise(adv)  madvise the whole mapping: 5 = MADV_FREE, 7 = MADV_FREE_REUSABLE, 8 = MADV_FREE_REUSE
//   PageAcctMprotect()   the Tailscale step: mprotect(PROT_NONE) then mprotect(PROT_READ|PROT_WRITE)
//   PageAcctUnmap()      munmap
// and for the Go heap itself:
//   PageAcctGoGarbage(mb) allocate mb of garbage, write every page, drop it, runtime.GC() (freed, not released)
//   PageAcctGoRelease()   debug.FreeOSMemory(); returns the bytes Go marked released (HeapReleased delta)

import (
	"runtime"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

var paMem []byte

// PageAcctMap maps mb MB and dirties every page; "" or the error.
func PageAcctMap(mb int) string {
	PageAcctUnmap()
	b, err := unix.Mmap(-1, 0, mb<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return "mmap: " + err.Error()
	}
	for i := 0; i < len(b); i += 4096 {
		b[i] = byte(i>>12) | 1
	}
	paMem = b
	return ""
}

// PageAcctAdvise madvises the whole mapping with adv (raw darwin value).
func PageAcctAdvise(adv int) string {
	if paMem == nil {
		return "not mapped"
	}
	if err := unix.Madvise(paMem, adv); err != nil {
		return "madvise: " + err.Error()
	}
	return ""
}

// PageAcctMprotect is tailscale/go 38ab03e's extra step after MADV_FREE_REUSABLE.
func PageAcctMprotect() string {
	if paMem == nil {
		return "not mapped"
	}
	if err := unix.Mprotect(paMem, unix.PROT_NONE); err != nil {
		return "mprotect none: " + err.Error()
	}
	if err := unix.Mprotect(paMem, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		return "mprotect rw: " + err.Error()
	}
	return ""
}

// PageAcctTouch writes every page again (reuse after a release).
func PageAcctTouch() {
	for i := 0; i < len(paMem); i += 4096 {
		paMem[i] = byte(i>>12) | 2
	}
}

// PageAcctUnmap releases the mapping.
func PageAcctUnmap() {
	if paMem != nil {
		_ = unix.Munmap(paMem)
		paMem = nil
	}
}

var paSink [][]byte

// PageAcctGoGarbage leaves mb MB of freed-but-unreleased Go heap behind (pages written, then a GC).
func PageAcctGoGarbage(mb int) {
	debug.FreeOSMemory()
	for i := 0; i < mb*8; i++ { // 128 KB objects (large spans)
		b := make([]byte, 128<<10)
		for j := 0; j < len(b); j += 4096 {
			b[j] = 1
		}
		paSink = append(paSink, b)
	}
	paSink = nil
	runtime.GC()
}

// PageAcctGoRelease runs debug.FreeOSMemory and returns how many bytes Go marked released.
func PageAcctGoRelease() int64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	debug.FreeOSMemory()
	runtime.ReadMemStats(&b)
	return int64(b.HeapReleased) - int64(a.HeapReleased)
}
