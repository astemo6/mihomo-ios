package libmihomo

import (
	"encoding/json"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// QXHTTPBackends returns the [http_backend] lines of a Quantumult X configuration as a JSON array of
// {tag, script, path, imgURL, enabled} (QX preview 5). The app adds them to its HTTP Backend page.
func QXHTTPBackends(conf string) string {
	out := []mitm.BackendItem{}
	in := false
	for _, raw := range strings.Split(strings.ReplaceAll(conf, "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(raw)
		if m := confSectionRe.FindStringSubmatch(l); m != nil {
			in = strings.EqualFold(strings.TrimSpace(m[1]), "http_backend")
			continue
		}
		if !in {
			continue
		}
		if it, ok := mitm.ParseBackendLine(l); ok {
			out = append(out, it)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// EngineCachePath is where the engine caches a remote script (home = the App Group home, not the engine
// dir). The app downloads HTTP Backend scripts there so the first request does not wait for a fetch.
func EngineCachePath(home, url string) string {
	if url == "" {
		return ""
	}
	return mitm.CachePath(home, url)
}
