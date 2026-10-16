package libmihomo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"

	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// Notifier is implemented on the Swift side (PacketTunnel) to post local notifications
// requested by scripts ($notification.post / $notify). payload is JSON {title, subtitle, body, url}.
type Notifier interface {
	Notify(payload string)
}

var (
	engMu    sync.Mutex
	eng      *mitm.Engine
	notifier Notifier
)

func init() {
	route.Register(mitm.Routes(func() *mitm.Engine {
		engMu.Lock()
		defer engMu.Unlock()
		return eng
	}))
}

// SetNotifier installs the notification callback (call before Start).
func SetNotifier(n Notifier) {
	engMu.Lock()
	notifier = n
	if eng != nil {
		installNotifier(eng)
	}
	engMu.Unlock()
}

func installNotifier(e *mitm.Engine) {
	n := notifier
	if n == nil {
		e.SetNotifier(nil)
		return
	}
	e.SetNotifier(func(title, subtitle, body, url string) {
		b, _ := json.Marshal(map[string]string{"title": title, "subtitle": subtitle, "body": body, "url": url})
		n.Notify(string(b))
	})
}

func coreDial(ctx context.Context, network, addr, policy string) (net.Conn, error) {
	return inner.HandleTcp(tunnel.Tunnel, addr, policy)
}

func engineLog(level, msg string) {
	switch level {
	case "error":
		log.Errorln("%s", msg)
	case "warning", "warn":
		log.Warnln("%s", msg)
	case "debug":
		log.Debugln("%s", msg)
	default:
		log.Infoln("%s", msg)
	}
}

// prepareEngine loads engine.json; when anything is enabled it lazily starts the engine and returns
// the config injector. Nothing is allocated when MitM / rewrite / scripts are all off.
func prepareEngine(home string) (func(raw map[string]any), error) {
	cfg := mitm.LoadConfig(home)
	rs := mitm.Build(home, cfg)
	needListener := (cfg.MitM && len(rs.Hostnames) > 0) || (cfg.Enabled && len(rs.Rules) > 0)
	engMu.Lock()
	defer engMu.Unlock()
	if !needListener {
		if eng != nil {
			eng.Stop()
			eng = nil
		}
		if cfg.Enabled && len(rs.CoreRules) > 0 {
			return func(raw map[string]any) { mitm.Inject(raw, 0, rs, cfg) }, nil
		}
		return nil, nil
	}
	if eng == nil {
		eng = mitm.New(home, coreDial, engineLog)
		installNotifier(eng)
		eng.Logs.SetHook(func(l mitm.LogLine) {
			if l.Level != "debug" {
				log.Infoln("[Script] %s: %s", l.Script, l.Msg)
			}
		})
	}
	if err := eng.Start(); err != nil {
		eng = nil
		return nil, fmt.Errorf("引擎启动失败：%w", err)
	}
	eng.Reload(cfg, rs)
	port := eng.Port()
	return func(raw map[string]any) { mitm.Inject(raw, port, rs, cfg) }, nil
}

func stopEngine() {
	engMu.Lock()
	if eng != nil {
		eng.Stop()
		eng = nil
	}
	engMu.Unlock()
}

// ---------------- CA helpers for the app ----------------

// CAInfo returns JSON {exists, subject, fingerprint, sha1, notBefore, notAfter, algorithm}.
func CAInfo(homeDir string) string { return mitm.InfoJSON(homeDir) }

// CAGenerate creates (or replaces) the MitM root CA and returns CAInfo JSON.
func CAGenerate(homeDir string) (string, error) {
	if _, err := mitm.GenerateCA(homeDir); err != nil {
		return "", err
	}
	return mitm.InfoJSON(homeDir), nil
}

// CAMobileConfig returns the .mobileconfig profile carrying the root certificate.
func CAMobileConfig(homeDir string) ([]byte, error) {
	ca, err := mitm.LoadCA(homeDir)
	if err != nil {
		return nil, errors.New("请先生成 CA 证书")
	}
	return ca.MobileConfig(), nil
}

// CACertDER returns the root certificate (DER, .cer).
func CACertDER(homeDir string) ([]byte, error) {
	ca, err := mitm.LoadCA(homeDir)
	if err != nil {
		return nil, errors.New("请先生成 CA 证书")
	}
	return ca.DER, nil
}

// CAExportP12 exports cert + key as a password protected .p12.
func CAExportP12(homeDir, password string) ([]byte, error) {
	ca, err := mitm.LoadCA(homeDir)
	if err != nil {
		return nil, errors.New("请先生成 CA 证书")
	}
	return ca.ExportP12(password)
}

// CAImportP12 replaces the CA with the one inside a .p12.
func CAImportP12(homeDir string, data []byte, password string) error {
	return mitm.ImportP12(homeDir, data, password)
}

// CATrustChain returns "leafDERBase64,caDERBase64,hostname" for a SecTrust check in the app.
func CATrustChain(homeDir string) (string, error) {
	ca, err := mitm.LoadCA(homeDir)
	if err != nil {
		return "", errors.New("请先生成 CA 证书")
	}
	leaf, root, host, err := ca.TrustTestChain()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(leaf) + "," + base64.StdEncoding.EncodeToString(root) + "," + host, nil
}

var (
	profSrvMu sync.Mutex
	profSrv   *http.Server
)

// CAServeProfile serves the profile at http://127.0.0.1:<port>/ca.mobileconfig for ~3 minutes so
// Safari can download and install it. Returns the port.
func CAServeProfile(homeDir string) (int, error) {
	ca, err := mitm.LoadCA(homeDir)
	if err != nil {
		return 0, errors.New("请先生成 CA 证书")
	}
	profSrvMu.Lock()
	defer profSrvMu.Unlock()
	if profSrv != nil {
		_ = profSrv.Close()
		profSrv = nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	mc := ca.MobileConfig()
	der := ca.DER
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="Mihomo-CA.mobileconfig"`)
		_, _ = w.Write(mc)
	})
	mux.HandleFunc("/ca.cer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		_, _ = w.Write(der)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>安装 Mihomo CA</title>
<body style="font-family:-apple-system;padding:24px;background:#0a0b10;color:#eee">
<h2>安装 Mihomo MitM 证书</h2><p><a style="color:#4ac7f5;font-size:20px" href="/ca.mobileconfig">点此下载描述文件</a></p>
<ol><li>点「允许」下载描述文件</li><li>打开 设置 → 已下载描述文件 → 安装</li><li>设置 → 通用 → 关于本机 → 证书信任设置 → 打开该证书的完全信任</li></ol></body>`)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	profSrv = srv
	go func() { _ = srv.Serve(ln) }()
	go func() {
		time.Sleep(3 * time.Minute)
		profSrvMu.Lock()
		if profSrv == srv {
			_ = srv.Close()
			profSrv = nil
		}
		profSrvMu.Unlock()
	}()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// ---------------- rule / module parsing for the app ----------------

type parsedRule struct {
	Kind    string `json:"kind"`
	Phase   string `json:"phase"`
	Pattern string `json:"pattern"`
	Desc    string `json:"desc"`
	Line    string `json:"line"`
	Script  string `json:"script,omitempty"`
	Path    string `json:"path,omitempty"`
}

type parsedText struct {
	Name        string        `json:"name"`
	Desc        string        `json:"desc"`
	Format      string        `json:"format"`
	Rules       []parsedRule  `json:"rules"`
	Hostnames   []string      `json:"hostnames"`
	CoreRules   []string      `json:"coreRules"`
	Errors      []string      `json:"errors"`
	Unsupported []string      `json:"unsupported"`
	Arguments   []mitm.ModArg `json:"arguments"`
}

func toParsed(rs *mitm.Ruleset) string {
	p := parsedText{Name: rs.Name, Desc: rs.Desc, Format: rs.Format, Hostnames: rs.Hostnames, CoreRules: rs.CoreRules,
		Errors: rs.Errors, Unsupported: rs.Unsupported, Arguments: rs.Arguments, Rules: []parsedRule{}}
	for _, r := range rs.Rules {
		pr := parsedRule{Kind: r.Kind, Phase: r.Phase, Pattern: r.Pattern, Desc: r.Desc, Line: r.Line}
		if r.Script != nil {
			pr.Script, pr.Path = r.Script.Name, r.Script.Path
		}
		p.Rules = append(p.Rules, pr)
	}
	if p.Hostnames == nil {
		p.Hostnames = []string{}
	}
	if p.CoreRules == nil {
		p.CoreRules = []string{}
	}
	if p.Errors == nil {
		p.Errors = []string{}
	}
	if p.Unsupported == nil {
		p.Unsupported = []string{}
	}
	if p.Arguments == nil {
		p.Arguments = []mitm.ModArg{}
	}
	b, _ := json.Marshal(p)
	return string(b)
}

// EngineParseText parses a module / snippet / list (Surge, QX, Loon, Stash) and returns a JSON summary.
// argsJSON is an optional {"key":"value"} map for #!arguments.
func EngineParseText(text, argsJSON string) string {
	args := map[string]string{}
	_ = json.Unmarshal([]byte(argsJSON), &args)
	rs := &mitm.Ruleset{}
	rs.ParseText(text, "模块", args)
	return toParsed(rs)
}

// EngineParseLine validates one rewrite / script line. section: "" (auto) or "script".
func EngineParseLine(line, section string) string {
	rs := &mitm.Ruleset{}
	rs.ParseLine(line, section, "用户")
	return toParsed(rs)
}
