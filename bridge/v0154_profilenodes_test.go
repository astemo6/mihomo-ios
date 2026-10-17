package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const v0154Profile = `# my profile (comment kept)
mixed-port: 7890
proxies:
  # hong kong
  - name: HK 01
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: "pw1" # inline comment
    udp: true
  - {name: JP 01, type: trojan, server: 2.2.2.2, port: 443, password: pw2, sni: jp.example.com}
  - name: Relay
    type: ss
    server: 3.3.3.3
    port: 8388
    cipher: aes-128-gcm
    password: pw3
    dialer-proxy: HK 01
proxy-groups:
  - name: Proxy
    type: select
    proxies: [HK 01, JP 01, Relay, DIRECT]
  - name: OnlyHK
    type: select
    proxies:
      - HK 01
  - name: Auto
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies: [HK 01, JP 01]
rules:
  - DOMAIN-SUFFIX,hk.example.com,HK 01
  - AND,((DOMAIN,a.example.com),(NETWORK,UDP)),HK 01
  - IP-CIDR,10.0.0.0/8,HK 01,no-resolve
  - DOMAIN,keep.example.com,Proxy
  - MATCH,Proxy
`

func v0154Setup(t *testing.T) (home, path string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	_ = os.MkdirAll(home, 0o755)
	path = filepath.Join(home, "profiles", "p1.yaml")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(v0154Profile), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestV0154ProfileNodeGet(t *testing.T) {
	_, path := v0154Setup(t)
	var m map[string]any
	if err := json.Unmarshal([]byte(ProfileNodeGet(path, "JP 01")), &m); err != nil {
		t.Fatal(LastError(), err)
	}
	if m["password"] != "pw2" || m["sni"] != "jp.example.com" || m["port"].(float64) != 443 {
		t.Fatalf("get %v", m)
	}
	if ProfileNodeGet(path, "nope") != "" || !ProfileHasNode(path, "HK 01") || ProfileHasNode(path, "Proxy") {
		t.Fatal("missing / group should not be a node")
	}
}

func TestV0154ProfileNodeEditInPlace(t *testing.T) {
	home, path := v0154Setup(t)
	var m map[string]any
	_ = json.Unmarshal([]byte(ProfileNodeGet(path, "HK 01")), &m)
	m["server"] = "9.9.9.9"
	m["port"] = 9999
	delete(m, "udp")
	m["tfo"] = true
	b, _ := json.Marshal(m)
	if e := ProfileNodeUpsert(home, path, string(b), "HK 01"); e != "" {
		t.Fatal(e)
	}
	out, _ := os.ReadFile(path)
	s := string(out)
	for _, want := range []string{"# my profile (comment kept)", "# hong kong", "# inline comment", "server: 9.9.9.9", "port: 9999", "tfo: true", "mixed-port: 7890"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "udp: true") {
		t.Fatalf("removed key still there\n%s", s)
	}
	// order kept: HK 01 still first, name/type before server
	if strings.Index(s, "HK 01") > strings.Index(s, "JP 01") || strings.Index(s, "type: ss") > strings.Index(s, "server: 9.9.9.9") {
		t.Fatalf("order changed\n%s", s)
	}
	if bak, _ := os.ReadFile(path + ".bak"); string(bak) != v0154Profile {
		t.Fatal("backup not written")
	}
	if e := ProfileNodeUndo(path); e != "" {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(path); string(b) != v0154Profile {
		t.Fatal("undo did not restore")
	}
}

func TestV0154ProfileNodeRenamePropagates(t *testing.T) {
	home, path := v0154Setup(t)
	var m map[string]any
	_ = json.Unmarshal([]byte(ProfileNodeGet(path, "HK 01")), &m)
	m["name"] = "香港 01"
	b, _ := json.Marshal(m)
	if e := ProfileNodeUpsert(home, path, string(b), "HK 01"); e != "" {
		t.Fatal(e)
	}
	s := func() string { b, _ := os.ReadFile(path); return string(b) }()
	if strings.Contains(s, "HK 01") {
		t.Fatalf("old name left\n%s", s)
	}
	for _, want := range []string{
		"DOMAIN-SUFFIX,hk.example.com,香港 01", "AND,((DOMAIN,a.example.com),(NETWORK,UDP)),香港 01",
		"IP-CIDR,10.0.0.0/8,香港 01,no-resolve", "dialer-proxy: 香港 01", "MATCH,Proxy",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q\n%s", want, s)
		}
	}
	if e := ValidateConfigIn(home, path); e != "" {
		t.Fatal("renamed profile invalid:", e)
	}
	// duplicate names are refused
	m["name"] = "JP 01"
	b, _ = json.Marshal(m)
	if e := ProfileNodeUpsert(home, path, string(b), "香港 01"); e == "" {
		t.Fatal("rename onto an existing node accepted")
	}
	m["name"] = "Proxy"
	b, _ = json.Marshal(m)
	if e := ProfileNodeUpsert(home, path, string(b), "香港 01"); e == "" {
		t.Fatal("rename onto a group accepted")
	}
}

func TestV0154ProfileNodeInvalidRejected(t *testing.T) {
	home, path := v0154Setup(t)
	if e := ProfileNodeUpsert(home, path, `{"name":"Bad","type":"ss","server":"1.2.3.4","port":8388,"cipher":"nope","password":"x"}`, "HK 01"); e == "" {
		t.Fatal("invalid cipher accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != v0154Profile {
		t.Fatal("file changed after a rejected edit")
	}
}

func TestV0154ProfileNodeDuplicateAndAdd(t *testing.T) {
	home, path := v0154Setup(t)
	nn := ProfileNodeDuplicate(home, path, "JP 01", "副本")
	if nn != "JP 01 副本" {
		t.Fatal(nn, LastError())
	}
	if nn2 := ProfileNodeDuplicate(home, path, "JP 01", "副本"); nn2 != "JP 01 副本 2" {
		t.Fatal(nn2, LastError())
	}
	s := func() string { b, _ := os.ReadFile(path); return string(b) }()
	if !(strings.Index(s, "name: JP 01,") < strings.Index(s, "JP 01 副本") && strings.Index(s, "JP 01 副本") < strings.Index(s, "name: Relay")) {
		t.Fatalf("copy not right after the original\n%s", s)
	}
	if e := ProfileNodeUpsert(home, path, `{"name":"New","type":"socks5","server":"5.5.5.5","port":1080}`, ""); e != "" {
		t.Fatal(e)
	}
	if !ProfileHasNode(path, "New") {
		t.Fatal("new node missing")
	}
	if e := ValidateConfigIn(home, path); e != "" {
		t.Fatal(e)
	}
}

func TestV0154ProfileNodeDelete(t *testing.T) {
	home, path := v0154Setup(t)
	var c deleteCheck
	_ = json.Unmarshal([]byte(ProfileNodeDeleteCheck(path, "HK 01")), &c)
	if c.Error != "" || len(c.EmptyGroups) != 1 || c.EmptyGroups[0] != "OnlyHK" || c.Rules != 3 || len(c.Groups) != 3 || len(c.Dialers) != 1 {
		t.Fatalf("check %+v", c)
	}
	if b, _ := os.ReadFile(path); string(b) != v0154Profile {
		t.Fatal("check modified the file")
	}
	if e := ProfileNodeDelete(home, path, "HK 01"); e != "" {
		t.Fatal(e)
	}
	s := func() string { b, _ := os.ReadFile(path); return string(b) }()
	if strings.Contains(s, "HK 01") {
		t.Fatalf("references left\n%s", s)
	}
	if !strings.Contains(s, "DOMAIN,keep.example.com,Proxy") || !strings.Contains(s, "- DIRECT") {
		t.Fatalf("unrelated rule dropped or empty group not filled\n%s", s)
	}
	if e := ValidateConfigIn(home, path); e != "" {
		t.Fatal(e)
	}
}

func TestV0154RenameRefs(t *testing.T) {
	home, path := v0154Setup(t)
	if e := ProfileRenameRefs(home, path, "Proxy", "Proxy2"); e == "" {
		// Proxy2 does not exist as a group: rules now point at nothing → validation must refuse.
		t.Fatal("dangling rename accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != v0154Profile {
		t.Fatal("refused rename changed the file")
	}
	if e := ProfileRenameRefs(home, path, "Nothing", "X"); e != "" {
		t.Fatal(e)
	}
}
