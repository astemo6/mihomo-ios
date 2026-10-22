package libmihomo

import "testing"

// feat/geo-mirror-edit: 国内镜像 → 自定义 base URL.
func TestGeoCustomMirror(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/gh/MetaCubeX/meta-rules-dat@release/": "https://example.com/gh/MetaCubeX/meta-rules-dat@release/",
		" https://cdn.example.com/meta ":                           "https://cdn.example.com/meta/",
		"http://example.com/":                                      "",
		"example.com/x/":                                           "",
		"https:///nohost/":                                         "",
		"https://example.com/a b/":                                 "",
		"https://example.com/?q=1":                                 "",
		"":                                                         "",
	} {
		if got := GeoCustomBase(in); got != want {
			t.Errorf("GeoCustomBase(%q) = %q, want %q", in, got, want)
		}
	}
	if u := GeoMirrorURL("mmdb", "custom", "https://example.com/gh/MetaCubeX/meta-rules-dat@release"); u != "https://example.com/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb" {
		t.Fatal(u)
	}
	if u := GeoMirrorURL("asn", "custom", "ftp://bad"); u != geoMirrorBase+"GeoLite2-ASN.mmdb" {
		t.Fatalf("invalid custom base falls back to jsDelivr: %s", u)
	}
	if u := GeoMirrorURL("geosite", "fastly", "https://ignored.example.com/"); u != "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat" {
		t.Fatalf("base only applies to custom: %s", u)
	}
	o := defaultOverrides()
	o.GeoMirror, o.GeoMirrorBase = "custom", "https://mirror.example.org/rules/"
	o.GeoURLs = map[string]string{"geosite": "https://own.example.net/geosite.dat"}
	g := geoxFor(o)
	if g["mmdb"] != "https://mirror.example.org/rules/geoip.metadb" || g["geosite"] != "https://own.example.net/geosite.dat" {
		t.Fatalf("custom mirror for defaults, per-file URL wins: %v", g)
	}
}
