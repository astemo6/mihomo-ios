package libmihomo

// Geo databases for the 资源 page: versions / dates and one-tap updates from a China-reachable mirror.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type geoFile struct {
	Kind      string  `json:"kind"`   // mmdb | geosite | asn | geoip
	File      string  `json:"file"`   // file name in the core home dir
	Remote    string  `json:"remote"` // file name in meta-rules-dat
	Exists    bool    `json:"exists"`
	Size      int64   `json:"size"`
	Modified  float64 `json:"modified,omitempty"`  // unix seconds
	BuildDate float64 `json:"buildDate,omitempty"` // mmdb metadata build epoch
	DBType    string  `json:"dbType,omitempty"`
	Error     string  `json:"error,omitempty"`
}

var geoKinds = []geoFile{
	{Kind: "mmdb", File: "geoip.metadb", Remote: "geoip.metadb"},
	{Kind: "geosite", File: "GeoSite.dat", Remote: "geosite.dat"},
	{Kind: "asn", File: "ASN.mmdb", Remote: "GeoLite2-ASN.mmdb"},
	{Kind: "geoip", File: "GeoIP.dat", Remote: "geoip.dat"},
}

// findCI finds name in dir case-insensitively (mihomo does the same).
func findCI(dir, name string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return filepath.Join(dir, name)
	}
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(e.Name(), name) {
			return filepath.Join(dir, e.Name())
		}
	}
	return filepath.Join(dir, name)
}

func geoDescribe(home string, g geoFile) geoFile {
	p := findCI(home, g.File)
	st, err := os.Stat(p)
	if err != nil {
		return g
	}
	g.Exists, g.Size, g.Modified = true, st.Size(), float64(st.ModTime().Unix())
	if strings.HasSuffix(g.File, "mmdb") || strings.HasSuffix(g.File, "metadb") {
		if db, err := maxminddb.Open(p); err == nil {
			g.BuildDate = float64(db.Metadata.BuildEpoch)
			g.DBType = db.Metadata.DatabaseType
			_ = db.Close()
		} else {
			g.Error = err.Error()
		}
	}
	return g
}

// GeoInfo returns JSON [{kind,file,exists,size,modified,buildDate,dbType}] for the geo databases.
func GeoInfo(homeDir string) string {
	out := []geoFile{}
	for _, g := range geoKinds {
		out = append(out, geoDescribe(homeDir, g))
	}
	b, _ := json.Marshal(out)
	return string(b)
}

var geoHTTP = &http.Client{Timeout: 90 * time.Second}

// GeoUpdate downloads one database (kind: mmdb / geosite / asn / geoip) into homeDir atomically,
// validating it first. url "" = the URL from overrides.json (custom URL or mirror default).
// Returns the updated entry as JSON.
func GeoUpdate(homeDir, kind, url string) (string, error) {
	var g *geoFile
	for i := range geoKinds {
		if geoKinds[i].Kind == kind {
			g = &geoKinds[i]
		}
	}
	if g == nil {
		return "", fmt.Errorf("未知的数据库 %s", kind)
	}
	if strings.TrimSpace(url) == "" {
		url = geoURL(readOverrides(homeDir), kind)
	} else {
		url = normalizeURL(strings.TrimSpace(url))
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "mihomo-ios")
	resp, err := geoHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("下载失败：HTTP %d（%s）", resp.StatusCode, url)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("下载中断：%w", err)
	}
	return geoInstall(homeDir, *g, data)
}

// GeoInstallFile validates a database the app downloaded itself (with a progress bar) at path and moves
// it into homeDir. kind: mmdb / geosite / asn / geoip. Returns the updated entry as JSON.
func GeoInstallFile(homeDir, kind, path string) (string, error) {
	var g *geoFile
	for i := range geoKinds {
		if geoKinds[i].Kind == kind {
			g = &geoKinds[i]
		}
	}
	if g == nil {
		return "", fmt.Errorf("未知的数据库 %s", kind)
	}
	data, err := os.ReadFile(path)
	_ = os.Remove(path)
	if err != nil {
		return "", err
	}
	return geoInstall(homeDir, *g, data)
}

func geoInstall(homeDir string, g geoFile, data []byte) (string, error) {
	if err := geoValidate(g.File, data); err != nil {
		return "", err
	}
	dst := findCI(homeDir, g.File)
	tmp := dst + ".download"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	// rename keeps an mmap of the old file in the extension valid until it reopens (ReloadGeo).
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	b, _ := json.Marshal(geoDescribe(homeDir, g))
	return string(b), nil
}

func geoValidate(name string, data []byte) error {
	if len(data) < 1024 {
		return fmt.Errorf("文件过小（%d 字节），可能被拦截", len(data))
	}
	if strings.HasSuffix(name, "mmdb") || strings.HasSuffix(name, "metadb") {
		db, err := maxminddb.FromBytes(data)
		if err != nil {
			return fmt.Errorf("不是有效的 MMDB：%w", err)
		}
		_ = db.Close()
		return nil
	}
	// .dat files are protobuf lists (field 1, length-delimited) — reject HTML error pages.
	if data[0] != 0x0a || bytes.HasPrefix(bytes.TrimSpace(data[:64]), []byte("<")) {
		return fmt.Errorf("不是有效的 %s", name)
	}
	return nil
}
