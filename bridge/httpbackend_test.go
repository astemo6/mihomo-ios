package libmihomo

import (
	"encoding/json"
	"testing"
)

func TestQXHTTPBackends(t *testing.T) {
	conf := "[general]\nnetwork_check_url=http://www.qualcomm.cn\n\n[http_backend]\n" +
		"https://raw.githubusercontent.com/chavyleung/scripts/master/chavy.box.js, tag=BoxJS, path=^/, enabled=false\n" +
		"# ignored.js, path=^/x\n" +
		"api.js, path=^/api/\n\n[mitm]\nhostname = a.com\n"
	var out []map[string]any
	if err := json.Unmarshal([]byte(QXHTTPBackends(conf)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0]["tag"] != "BoxJS" || out[0]["enabled"] != false || out[1]["tag"] != "api" || out[1]["path"] != "^/api/" {
		t.Fatalf("backends: %v", out)
	}
	if QXHTTPBackends("[general]\n") != "[]" {
		t.Fatal("empty conf should give []")
	}
}
