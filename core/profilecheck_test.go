package libmihomo

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func check(t *testing.T, home, text string) profileCheck {
	t.Helper()
	var r profileCheck
	if err := json.Unmarshal([]byte(ProfileCheck(home, filepath.Join(home, "x.yaml"), text)), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProfileCheckLocations(t *testing.T) {
	home := t.TempDir()
	ok := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n"
	if r := check(t, home, ok); !r.OK || r.Nodes != 1 || r.Groups != 1 || r.Rules < 1 {
		t.Fatalf("ok %+v", r)
	}
	// YAML syntax error → line.
	if r := check(t, home, "proxies:\n  - name: A\n   type: x\n"); r.OK || r.Line != 3 || !strings.HasPrefix(r.Error, "YAML") {
		t.Fatalf("yaml %+v", r)
	}
	// Bad proxy (2nd) → its line.
	bad := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - name: B\n    type: nope\n    server: x\n    port: 1\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n"
	if r := check(t, home, bad); r.OK || r.Line != 3 || r.Column != 5 {
		t.Fatalf("proxy %+v", r)
	}
	// Group referencing a missing proxy → group line.
	bad = "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\n  - {name: H, type: select, proxies: [Z]}\nrules:\n  - MATCH,G\n"
	if r := check(t, home, bad); r.OK || r.Line != 5 {
		t.Fatalf("group %+v", r)
	}
	// Rule with unknown target → rule line.
	bad = "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\nproxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - DOMAIN,a.com,G\n  - DOMAIN,b.com,Missing\n  - MATCH,G\n"
	if r := check(t, home, bad); r.OK || r.Line != 7 || r.Column != 5 {
		t.Fatalf("rule %+v", r)
	}
	// Duplicate proxy name.
	bad = "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: A, type: socks5, server: 127.0.0.1, port: 2}\nrules:\n  - MATCH,DIRECT\n"
	if r := check(t, home, bad); r.OK || r.Line == 0 {
		t.Fatalf("dup %+v", r)
	}
}
