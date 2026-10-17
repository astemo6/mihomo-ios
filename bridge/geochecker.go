package libmihomo

// v0.12 geo_location_checker: QX lets a profile choose the exit-IP lookup used for the Home header
// ("geo_location_checker = <api url>, <script url>"). The app fetches the API through the tunnel and
// downloads the script; this runs the script like QX does — $response.body = the API reply, and
// $done({title, subtitle, ip, description}) gives the header text — in a throw-away script engine.

import (
	"encoding/json"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

type geoResult struct {
	Title       string `json:"title,omitempty"`
	Subtitle    string `json:"subtitle,omitempty"`
	IP          string `json:"ip,omitempty"`
	Description string `json:"description,omitempty"`
	Error       string `json:"error,omitempty"`
}

// GeoLocationRun runs a QX geo_location_checker script on an API reply. Returns geoResult as JSON.
func GeoLocationRun(homeDir, code, apiURL, body string) string {
	res := geoResult{}
	out := func() string {
		b, _ := json.Marshal(res)
		return string(b)
	}
	if strings.TrimSpace(code) == "" {
		res.Error = "没有脚本内容"
		return out()
	}
	in := mitm.DebugInput{Code: code, Name: "geo_location_checker", Type: "http-response", Timeout: 5,
		Request:  &mitm.DebugHTTP{URL: firstNonEmpty(apiURL, "http://ip-api.com/json"), Method: "GET"},
		Response: &mitm.DebugHTTP{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: body}}
	d := mitm.DebugRun(homeDir, in, nil)
	if d.Error != "" {
		res.Error = d.Error
		return out()
	}
	if !d.Done || d.DoneJSON == "" {
		res.Error = "脚本没有调用 $done"
		return out()
	}
	m := map[string]any{}
	if json.Unmarshal([]byte(d.DoneJSON), &m) != nil {
		res.Error = "脚本结果无法解析"
		return out()
	}
	res.Title, res.Subtitle, res.IP, res.Description = str(m["title"]), str(m["subtitle"]), str(m["ip"]), str(m["description"])
	if res.Title == "" && res.Subtitle == "" {
		res.Error = "脚本结果没有 title / subtitle"
	}
	return out()
}
