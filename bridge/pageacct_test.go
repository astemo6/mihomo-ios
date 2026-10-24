package libmihomo

import "testing"

// The probe's steps run without error (the accounting itself is measured on iOS: NativeMitmMemoryTests.testPageAccounting).
func TestPageAcctSteps(t *testing.T) {
	if e := PageAcctMap(4); e != "" {
		t.Fatal(e)
	}
	if e := PageAcctMprotect(); e != "" {
		t.Fatal(e)
	}
	PageAcctTouch()
	PageAcctUnmap()
	if e := PageAcctAdvise(4); e != "not mapped" {
		t.Fatalf("advise after unmap: %q", e)
	}
	PageAcctGoGarbage(4)
	if rel := PageAcctGoRelease(); rel < 2<<20 {
		t.Fatalf("FreeOSMemory released only %d bytes of 4 MB garbage", rel)
	}
}
