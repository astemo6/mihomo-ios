package libmihomo

import (
	"encoding/json"
	"strings"
	"testing"
)

// The self-test the Swift loopback tests drive, on the Go path only (no native front registered): h2 to the
// client, the built-in rules applied, h2 and h1-only origins reached.
func TestMitmH2SelfTestGoPath(t *testing.T) {
	var st map[string]any
	if err := json.Unmarshal([]byte(MitmH2SelfTestStart("")), &st); err != nil || st["error"] != nil {
		t.Fatalf("start: %v %v", st, err)
	}
	defer MitmH2SelfTestStop()
	spec := `{"concurrent":true,"requests":[
		{"path":"/json"},{"path":"/r200"},{"path":"/old/x"},{"path":"/echo","method":"POST","body":"abc","repeat":1000},
		{"path":"/json?rb"},{"path":"/json?jd"},{"path":"/big?n=300000"},{"path":"/trailers"},{"host":"h1.test","path":"/echo"},
		{"path":"/stream?n=50"},{"path":"/nocontent"},{"path":"/gzip"}]}`
	var out struct {
		Conns   int          `json:"conns"`
		Results []h2stResult `json:"results"`
		Error   string       `json:"error"`
	}
	if err := json.Unmarshal([]byte(MitmH2SelfTestFetch(spec)), &out); err != nil || out.Error != "" {
		t.Fatalf("fetch: %v %s", err, out.Error)
	}
	if out.Conns != 2 { // one per host (h2.test, h1.test)
		t.Errorf("conns %d", out.Conns)
	}
	r := out.Results
	for i, x := range r {
		if x.Error != "" || x.Proto != "HTTP/2.0" {
			t.Errorf("%d: %+v", i, x)
		}
	}
	if !strings.Contains(r[0].Body, `"keep":1`) || r[1].Status != 200 || r[2].Status != 302 {
		t.Errorf("json/r200/302: %+v %+v %+v", r[0], r[1], r[2])
	}
	if !strings.Contains(r[3].Body, `"bodyLen":3000`) || !strings.Contains(r[3].Body, "x-added: hello") {
		t.Errorf("echo: %s", r[3].Body)
	}
	if !strings.Contains(r[4].Body, `"ad":false`) || strings.Contains(r[5].Body, `"ads"`) {
		t.Errorf("body rules: %s | %s", r[4].Body, r[5].Body)
	}
	if r[6].BodyLen != 300000 || len(r[7].Trailers) != 2 || !strings.Contains(r[8].Body, `"origin":"h1"`) {
		t.Errorf("big/trailers/h1: %d %v %s", r[6].BodyLen, r[7].Trailers, r[8].Body)
	}
	if r[10].Status != 204 {
		t.Errorf("204: %+v", r[10])
	}
	t.Logf("%s", MitmH2SelfTestFetch(`{"requests":[{"path":"/trailers"},{"path":"/gzip"}]}`))
	// h2-only client (what gRPC offers): served over h2 by the Go path
	var only struct {
		Results []struct {
			Status int    `json:"status"`
			Proto  string `json:"proto"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(MitmH2SelfTestFetch(`{"protos":["h2"],"requests":[{"path":"/json"}]}`)), &only); err != nil ||
		len(only.Results) != 1 || only.Results[0].Status != 200 || only.Results[0].Proto != "HTTP/2.0" {
		t.Fatalf("h2-only client: %+v %v", only, err)
	}
	var h1 struct {
		Results []struct {
			Proto string `json:"proto"`
		} `json:"results"`
	}
	_ = json.Unmarshal([]byte(MitmH2SelfTestFetch(`{"protos":["http/1.1"],"requests":[{"path":"/json"}]}`)), &h1)
	if len(h1.Results) != 1 || h1.Results[0].Proto != "HTTP/1.1" {
		t.Fatalf("http/1.1-only client: %+v", h1)
	}
}
