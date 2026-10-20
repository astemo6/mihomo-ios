package libmihomo

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestV0199ClassifyOfficialModules: pasted / opened official BoxJS and Sub-Store files route to the
// module importer (QX .snippet without sections, QX task gallery JSON included). Skips offline.
func TestV0199ClassifyOfficialModules(t *testing.T) {
	if os.Getenv("MIHOMO_OFFLINE") != "" {
		t.Skip("offline")
	}
	urls := map[string]string{
		"https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.surge.sgmodule":   "module:surge",
		"https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.loon.plugin":      "module:loon",
		"https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf":       "module:qx",
		"https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.stash.stoverride": "module:stash",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Surge.sgmodule":                 "module:surge",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Loon.plugin":                    "module:loon",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/QX.snippet":                     "module:qx",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/QX-Task.json":                   "module:qx",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Stash.stoverride":               "module:stash",
		"https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/Egern.yaml":                     "module:egern",
	}
	c := &http.Client{Timeout: 30 * time.Second}
	for u, want := range urls {
		resp, err := c.Get(u)
		if err != nil {
			t.Skipf("offline: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Skipf("%s: HTTP %d", u, resp.StatusCode)
		}
		if got := ClassifyText(string(b)); got != want {
			t.Errorf("%s: %q, want %q", u, got, want)
		}
	}
}
