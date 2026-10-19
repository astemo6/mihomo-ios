package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.19.2: a UTF-8 BOM on a rule list must not cost the first rule (classical) or poison the first domain
// (domainset); a line longer than the old 1 MB scanner limit must not drop every rule after it.
func TestV0192ListBOMAndLongLine(t *testing.T) {
	out, ok, _ := convertListText(strings.NewReader("\ufeffDOMAIN-SUFFIX,a.com\r\nDOMAIN,b.com\r\n"), "classical")
	if ok != 2 || !strings.HasPrefix(out, "DOMAIN-SUFFIX,a.com\n") {
		t.Fatalf("classical with BOM: ok=%d out=%q", ok, out)
	}
	out, ok, _ = convertListText(strings.NewReader("\ufeffa.com\n.b.com\n"), "domainset")
	if ok != 2 || strings.Contains(out, "\ufeff") || !strings.HasPrefix(out, "a.com\n") {
		t.Fatalf("domainset with BOM: ok=%d out=%q", ok, out)
	}
	long := "DOMAIN,a.com\n" + strings.Repeat("x", 2<<20) + "\nDOMAIN,c.com\n"
	out, ok, _ = convertListText(strings.NewReader(long), "classical")
	if ok != 2 || !strings.Contains(out, "DOMAIN,c.com") {
		t.Fatalf("rules after a 2 MB line were dropped: ok=%d", ok)
	}
}

// v0.19.2: a Surge / QX .conf saved with a BOM keeps its first section ([General] here).
func TestV0192ImportConfBOM(t *testing.T) {
	body := "[General]\r\ndns-server = 1.1.1.1\r\n[Proxy]\r\nA = ss, 1.2.3.4, 443, encrypt-method=aes-128-gcm, password=p\r\n[Rule]\r\nFINAL,DIRECT\r\n"
	var plain, bom struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal([]byte(ImportConf(body)), &plain); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(ImportConf("\ufeff"+body)), &bom); err != nil {
		t.Fatal(err)
	}
	if plain.YAML == "" || plain.YAML != bom.YAML {
		t.Fatalf("BOM changed the import:\nplain=%s\nbom=%s", plain.YAML, bom.YAML)
	}
	if !strings.Contains(bom.YAML, "1.1.1.1") {
		t.Fatalf("[General] dns-server lost: %s", bom.YAML)
	}
}

// v0.19.2: profile / manual-node writes replace the file atomically (no temp files left, .bak kept).
func TestV0192AtomicNodeWrites(t *testing.T) {
	dir := t.TempDir()
	manual := filepath.Join(dir, "manual-nodes.yaml")
	if n := ManualAddText(manual, "A = ss, 1.2.3.4, 443, encrypt-method=aes-128-gcm, password=p"); n != 1 {
		t.Fatalf("ManualAddText = %d (%s)", n, LastError())
	}
	if err := ManualDelete(manual, "A"); err != "" {
		t.Fatalf("ManualDelete: %s", err)
	}
	p := filepath.Join(dir, "p.yaml")
	orig := "proxies:\n  - {name: A, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: p}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	d, b, err := loadDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	if e := commit(dir, p, b, d); e != "" && !strings.Contains(e, "geo") {
		t.Logf("commit: %s", e)
	}
	if e := ProfileNodeUndo(p); e != "" {
		t.Fatalf("undo: %s", e)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("profile mode: %v %v", fi, err)
	}
}
