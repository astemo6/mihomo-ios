package libmihomo

import (
	_ "time/tzdata" // IANA zones for SetTimeZone (no zoneinfo in the iOS sandbox)

	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// startTimeout bounds Start: NetworkExtension's startTunnel must never wait on the network forever.
var startTimeout = 20 * time.Second

var (
	stageMu   sync.Mutex
	stagePath string
	stageZone = time.UTC
)

// SetStageLog sets the startup stage log file (App Group container). Lines are appended by the Go
// side ("core start begin/end", memory, errors); the Swift side writes its own stages to the same file.
// utcOffsetSeconds is the device's time zone offset so both sides log the same local clock.
func SetStageLog(path string, utcOffsetSeconds int) {
	stageMu.Lock()
	stagePath = path
	stageZone = time.FixedZone("local", utcOffsetSeconds)
	stageMu.Unlock()
}

func stage(format string, args ...any) {
	stageMu.Lock()
	defer stageMu.Unlock()
	if stagePath == "" {
		return
	}
	f, err := os.OpenFile(stagePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s [core] %s\n", time.Now().In(stageZone).Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

func memText() string {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return fmt.Sprintf("go heap %.1f MB, go sys %.1f MB, goroutines %d", float64(ms.HeapAlloc)/(1<<20), float64(ms.Sys)/(1<<20), runtime.NumGoroutine())
}

// MemoryStats returns a one-line Go runtime memory summary (for logs / diagnostics).
func MemoryStats() string { return memText() }

// geoMirrorBase is a China-reachable CDN for MetaCubeX/meta-rules-dat release files.
const geoMirrorBase = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"

// GeoBaseURL returns the download base for meta-rules-dat files for a mirror name.
func GeoBaseURL(mirror string) string {
	switch mirror {
	case "fastly":
		return "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
	case "github":
		return "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
	default:
		return geoMirrorBase
	}
}

// GeoCustomBase normalises a user mirror base for GeoMirror "custom": https only, with a host, ending in "/".
// Returns "" when base is not usable (the jsDelivr default is used then).
func GeoCustomBase(base string) string {
	b := strings.TrimSpace(base)
	u, err := url.Parse(b)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(b, " \t") {
		return ""
	}
	if !strings.HasSuffix(b, "/") {
		b += "/"
	}
	return b
}

// geoBase is the download base for o: the custom base when GeoMirror is "custom" and the base is valid,
// else the named mirror.
func geoBase(o Overrides) string {
	if o.GeoMirror == "custom" {
		if b := GeoCustomBase(o.GeoMirrorBase); b != "" {
			return b
		}
		return geoMirrorBase
	}
	return GeoBaseURL(o.GeoMirror)
}

func geoxMirror(mirror string) map[string]any {
	return geoxFor(Overrides{GeoMirror: mirror})
}

// geoxFor is the geox-url the core gets: custom URLs from the 地理与规则库 page, else the mirror default.
func geoxFor(o Overrides) map[string]any {
	out := map[string]any{}
	for _, g := range geoKinds {
		out[g.Kind] = geoURL(o, g.Kind)
	}
	return out
}

// geoURL returns the download URL for one database kind (mmdb / geoip / geosite / asn).
func geoURL(o Overrides, kind string) string {
	if u := strings.TrimSpace(o.GeoURLs[kind]); u != "" {
		return normalizeURL(u)
	}
	for _, g := range geoKinds {
		if g.Kind == kind {
			return geoBase(o) + g.Remote
		}
	}
	return ""
}

// normalizeURL adds https:// to "host/path" input from the URL field.
func normalizeURL(u string) string {
	if !strings.Contains(u, "://") {
		return "https://" + strings.TrimLeft(u, "/")
	}
	return u
}

// GeoDefaultURL is the URL used for kind when no custom URL is set (mirror: "" / jsdelivr, fastly, github).
func GeoDefaultURL(kind, mirror string) string { return geoURL(Overrides{GeoMirror: mirror}, kind) }

// GeoMirrorURL is GeoDefaultURL with the custom base for mirror "custom" (the 地理数据库 page's 默认地址 and preview).
func GeoMirrorURL(kind, mirror, base string) string {
	return geoURL(Overrides{GeoMirror: mirror, GeoMirrorBase: base}, kind)
}

// githubToMirror maps raw GitHub URLs to jsDelivr (reachable from mainland China):
//
//	https://raw.githubusercontent.com/u/r/branch/path  -> https://testingcf.jsdelivr.net/gh/u/r@branch/path
//	https://github.com/u/r/raw/branch/path             -> same
//	https://github.com/u/r/blob/branch/path            -> same
//
// "refs/heads/<branch>" is normalised. Anything else (gist, releases, other hosts) is left alone.
func githubToMirror(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return raw, false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	var user, repo, branch string
	var rest []string
	switch strings.ToLower(u.Host) {
	case "raw.githubusercontent.com":
		if len(parts) < 4 {
			return raw, false
		}
		user, repo, branch, rest = parts[0], parts[1], parts[2], parts[3:]
		if branch == "refs" && len(parts) >= 6 && parts[3] == "heads" {
			branch, rest = parts[4], parts[5:]
		}
	case "github.com":
		if len(parts) < 5 || (parts[2] != "raw" && parts[2] != "blob") {
			return raw, false
		}
		user, repo, branch, rest = parts[0], parts[1], parts[3], parts[4:]
		if branch == "refs" && len(parts) >= 7 && parts[4] == "heads" {
			branch, rest = parts[5], parts[6:]
		}
	default:
		return raw, false
	}
	if len(rest) == 0 || user == "" || repo == "" || branch == "" {
		return raw, false
	}
	return "https://testingcf.jsdelivr.net/gh/" + user + "/" + repo + "@" + branch + "/" + strings.Join(rest, "/"), true
}

// rewriteProviderURLs points rule-providers / proxy-providers hosted on raw GitHub at the jsDelivr
// mirror. On iOS the extension's own sockets bypass the tunnel, so provider downloads go out directly
// and raw.githubusercontent.com often stalls in mainland China. Providers with their own `proxy:` keep
// their URL (they are fetched through that proxy).
func rewriteProviderURLs(raw map[string]any) {
	for _, key := range []string{"rule-providers", "proxy-providers"} {
		pv, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		for _, v := range pv {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if p, _ := m["proxy"].(string); p != "" && !strings.EqualFold(p, "DIRECT") {
				continue
			}
			if s, ok := m["url"].(string); ok {
				if n, ok := githubToMirror(s); ok {
					if str(m["x-source"]) == "" {
						m["x-source"] = s
					}
					m["url"] = n
				}
			}
		}
	}
}

// SetTimeZone makes Go's local time match the device (the iOS sandbox gives Go no /etc/localtime, so
// time.Local would be UTC). Cron scripts and core logs depend on it. name is an IANA id
// (TimeZone.current.identifier); the fixed offset is the fallback.
func SetTimeZone(name string, utcOffsetSeconds int) {
	if loc, err := time.LoadLocation(name); err == nil && name != "" {
		time.Local = loc
		return
	}
	time.Local = time.FixedZone(name, utcOffsetSeconds)
}
