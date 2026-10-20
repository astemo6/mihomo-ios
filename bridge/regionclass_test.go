package libmihomo

import "testing"

// TestRegionClassification pins the fast-path classification: patterns that gain a
// new regex construct must fail here (extend classifyRegion) instead of silently
// changing detectRegion results. IN is open because of 印度(?!尼).
func TestRegionClassification(t *testing.T) {
	var open []string
	for _, r := range regions {
		if r.open {
			open = append(open, r.code)
		}
	}
	if len(open) != 1 || open[0] != "IN" {
		t.Fatalf("open regions = %v, want [IN]", open)
	}
	if len(litRegions) == 0 || len(codeRegions) == 0 || len(litByHead) == 0 {
		t.Fatal("fast-path indexes not built")
	}
}
