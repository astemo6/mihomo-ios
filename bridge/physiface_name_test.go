package libmihomo

import "testing"

func TestIsPhysicalName(t *testing.T) {
	for n, want := range map[string]bool{"en0": true, "pdp_ip0": true, "utun3": false, "ipsec0": false, "lo0": false, "awdl0": false} {
		if isPhysicalName(n) != want {
			t.Fatalf("%s: want %v", n, want)
		}
	}
}
