package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareNativeRuntimeLowersGeositeAndInType(t *testing.T) {
	home := t.TempDir()
	geo, err := os.ReadFile(filepath.Join("..", "Geo", "GeoSite.dat"))
	if err != nil {
		t.Skip("no Geo/GeoSite.dat")
	}
	if err := os.WriteFile(filepath.Join(home, "GeoSite.dat"), geo, 0o644); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(home, "p.yaml")
	conf := "proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: x}\n" +
		"proxy-groups:\n  - {name: G, type: select, proxies: [a, DIRECT]}\n" +
		"rules:\n  - GEOSITE,cn,DIRECT\n  - AND,((NETWORK,TCP),(NOT,((IN-TYPE,INNER))),(DST-PORT,80)),G\n  - MATCH,G\n"
	if err := os.WriteFile(profile, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := PrepareNativeRuntime(home, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(sum)
	rt, err := os.ReadFile(filepath.Join(home, "runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(rt)
	if strings.Contains(s, "GEOSITE,") || strings.Contains(s, "IN-TYPE") {
		t.Fatalf("not lowered:\n%s", s)
	}
	if !strings.Contains(s, "RULE-SET,__geosite_cn,DIRECT") || strings.Contains(s, "tun:") {
		t.Fatalf("unexpected runtime:\n%s", s)
	}
	list, err := os.ReadFile(filepath.Join(home, "nativecore-geosite", "cn.list"))
	if err != nil || len(list) < 1000 {
		t.Fatalf("geosite list: %v (%d B)", err, len(list))
	}
	if js, err := os.ReadFile(filepath.Join(home, NativeRuntimeJSONFile)); err != nil || !strings.Contains(string(js), "__geosite_cn") {
		t.Fatalf("runtime json: %v", err)
	}
	var rep nativePrep
	if err := json.Unmarshal([]byte(NativePrepReport(home)), &rep); err != nil || rep.Rules != 3 {
		t.Fatalf("report %+v %v", rep, err)
	}
}
