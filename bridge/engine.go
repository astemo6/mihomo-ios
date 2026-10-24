package libmihomo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"

	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
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

// mitmLoop: an INNER connection (the engine's own upstream) whose chain contains __MITM__ to the same
// target means a proxy group picked the engine outbound → reject instead of looping.
//
// NOTE (reverted optimization): we briefly gated this scan on "no proxy group currently selects
// __MITM__", but TestV0141LoopRejected proved the gate wrong — a plain rule like MATCH,__MITM__
// (no group involved) is a valid loop vector too. The scan stays unconditional: this is a safety
// mechanism against unbounded resource exhaustion, not worth a clever gate.
func mitmLoop(target string) bool {
	found := false
	statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
		info := t.Info()
		if info == nil || info.Metadata == nil || info.Metadata.Type != C.INNER {
			return true
		}
		for _, c := range info.Chain {
			if c == mitm.ProxyName {
				// The http outbound may CONNECT with the resolved IP (hosts / DNS mapping make the dial
				// metadata "pure"), so compare both forms.
				md := info.Metadata
				if md.RemoteAddress() == target || (md.DstIP.IsValid() && net.JoinHostPort(md.DstIP.String(), strconv.Itoa(int(md.DstPort))) == target) {
					found = true
					return false
				}
				break
			}
		}
		return true
	})
	return found
}

func coreDial(ctx context.Context, network, addr, policy string) (net.Conn, error) {
	return inner.HandleTcp(tunnel.Tunnel, addr, policy)
}

// coreHandoff gives a native-upstream relay socket straight to the core: the same INNER metadata as
// inner.HandleTcp (rules, policy pin, loop check see the same connection) without its in-memory pipe and
// the engine-side goroutine pumping it (feat/s2-pipe).
func coreHandoff(c net.Conn, addr, policy string) error {
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DNSMode: C.DNSNormal, Process: C.MihomoName, SpecialProxy: policy}
	if err := metadata.SetRemoteAddress(addr); err != nil {
		return err
	}
	go tunnel.Tunnel.HandleTCPConn(c, metadata)
	return nil
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
// the config injector. Nothing is allocated when MitM / rewrite / scripts are all off. The engine change
// takes effect at once (tests, callers without a core parse); apply() uses planEngine instead.
func prepareEngine(home string) (func(raw map[string]any), error) {
	inject, plan, err := planEngine(home)
	plan.commit()
	return inject, err
}

// enginePlan is the engine change a config apply needs, held back until the new core config is live
// (r7 P2-2): commit after hub.Parse succeeded, rollback when the runtime build or the parse failed.
// Before, the engine was stopped / reloaded first, so for the seconds a large parse takes — and for good
// when it failed — the running core still pointed __MITM__ (all port-80 TCP, MitM hosts) at a closed
// port, or the engine already ran the new rules / tasks beside the old routing.
type enginePlan struct {
	commit   func()
	rollback func()
}

func noPlan() *enginePlan { return &enginePlan{commit: func() {}, rollback: func() {}} }

// planEngine is prepareEngine with the engine change deferred to the returned plan.
func planEngine(home string) (func(raw map[string]any), *enginePlan, error) {
	cfg := mitm.LoadConfig(home)
	inject, plan, err := planEngineWith(home, cfg)
	if cfg.QUIC != "all" {
		return inject, plan, err
	}
	// Block QUIC for all traffic (user setting); works even when the engine is off.
	return func(raw map[string]any) {
		if inject != nil {
			inject(raw)
		}
		rules, _ := raw["rules"].([]any)
		raw["rules"] = append([]any{mitm.QUICBlockAllRule}, rules...)
	}, plan, err
}

// stopEnginePlan is stopEngine deferred to commit (safe mode).
func stopEnginePlan() *enginePlan {
	engMu.Lock()
	cur := eng
	engMu.Unlock()
	return &enginePlan{
		commit: func() {
			engMu.Lock()
			if eng != nil && eng == cur {
				eng.Stop()
				eng = nil
			}
			engMu.Unlock()
		},
		rollback: func() {},
	}
}

func prepareEngineWith(home string, cfg *mitm.Config) (func(raw map[string]any), error) {
	inject, plan, err := planEngineWith(home, cfg)
	plan.commit()
	return inject, err
}

func planEngineWith(home string, cfg *mitm.Config) (func(raw map[string]any), *enginePlan, error) {
	rs := mitm.Build(home, cfg)
	needListener := (cfg.MitM && len(rs.Hostnames) > 0) || (cfg.AnyOn() && len(rs.Rules) > 0)
	needTasks := cfg.AnyOn() && (len(rs.Tasks) > 0 || len(rs.Panels) > 0) // cron / event / generic scripts, panels
	coreOnly := func(raw map[string]any) { mitm.Inject(raw, 0, rs, cfg); addRemoteModuleRules(raw, rs.CoreRules) }
	engMu.Lock()
	defer engMu.Unlock()
	if !needListener && !needTasks {
		plan := noPlan()
		if cur := eng; cur != nil {
			// Stop only once the new config (without __MITM__) is live.
			plan.commit = func() {
				engMu.Lock()
				if eng == cur {
					eng.Stop()
					eng = nil
				}
				engMu.Unlock()
			}
		}
		if cfg.AnyOn() && len(rs.CoreRules) > 0 {
			return coreOnly, plan, nil
		}
		return nil, plan, nil
	}
	created := false
	if eng == nil {
		eng = mitm.New(home, coreDial, engineLog)
		installNotifier(eng)
		eng.SetGeoLookup(geoLookup)
		eng.SetAPI(httpAPI)
		eng.SetLoopCheck(mitmLoop)
		eng.SetRelayHandoff(coreHandoff)
		eng.Logs.SetHook(func(l mitm.LogLine) {
			if l.Level != "debug" {
				log.Infoln("[Script] %s: %s", l.Script, l.Msg)
			}
		})
		created = true
	}
	// Starting the listener early is harmless (nothing is steered to it until the new config is live)
	// and gives the injector its port.
	if err := eng.Start(); err != nil {
		if created {
			eng = nil
		}
		return nil, noPlan(), fmt.Errorf("引擎启动失败：%w", err)
	}
	cur := eng
	plan := &enginePlan{
		commit: func() {
			engMu.Lock()
			if eng == cur {
				eng.Reload(cfg, rs)
			}
			engMu.Unlock()
		},
		rollback: func() {
			if !created {
				return // the old engine keeps its old rules, matching the old core config
			}
			engMu.Lock()
			if eng == cur {
				eng.Stop()
				eng = nil
			}
			engMu.Unlock()
		},
	}
	if !needListener {
		// Only task scripts / panels: the engine runs, but no traffic is steered to it.
		if len(rs.CoreRules) > 0 {
			return coreOnly, plan, nil
		}
		return nil, plan, nil
	}
	port := eng.Port()
	return func(raw map[string]any) { mitm.Inject(raw, port, rs, cfg); addRemoteModuleRules(raw, rs.CoreRules) }, plan, nil
}

// geoLookup backs $utils.geoip / ipasn / ipaso with mihomo's MMDB readers. The readers log.Fatal when
// the database file is missing, so check the files first.
func geoLookup(ip string) (string, string, string) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return "", "", ""
	}
	country, asn, org := "", "", ""
	if fi, err := os.Stat(C.Path.MMDB()); err == nil && fi.Size() > 1024 {
		if codes := mmdb.IPInstance().LookupCode(addr); len(codes) > 0 {
			country = strings.ToUpper(codes[0])
		}
	}
	if fi, err := os.Stat(C.Path.ASN()); err == nil && fi.Size() > 1024 {
		asn, org = lookupASNSafe(addr)
	}
	return country, asn, org
}

// lookupASNSafe: mihomo's reader returns "0" for an address the GeoLite2 ASN database does not know
// (scripts then saw ASN 0 instead of null) and slices ASN[2:] unchecked for ipinfo databases (a panic on
// a miss, inside a script callback). v0.19.4: both mapped to "no result".
func lookupASNSafe(addr net.IP) (asn, org string) {
	defer func() {
		if recover() != nil {
			asn, org = "", ""
		}
	}()
	asn, org = mmdb.ASNInstance().LookupASN(addr)
	asn = strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "as")
	if asn == "0" {
		asn = ""
	}
	return asn, org
}

// NotifyNetworkChanged is called by the extension when the default path changes (Wi-Fi ⇄ cellular,
// new Wi-Fi). infoJSON becomes $network for event scripts. Returns how many event scripts were started.
func NotifyNetworkChanged(infoJSON string) int {
	info := map[string]any{}
	_ = json.Unmarshal([]byte(infoJSON), &info)
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return 0
	}
	return e.NetworkChanged(info)
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
	Author      string        `json:"author,omitempty"`
	Category    string        `json:"category,omitempty"`
	Format      string        `json:"format"`
	Rules       []parsedRule  `json:"rules"`
	Hostnames   []string      `json:"hostnames"`
	CoreRules   []string      `json:"coreRules"`
	Errors      []string      `json:"errors"`
	Unsupported []string      `json:"unsupported"`
	Arguments   []mitm.ModArg `json:"arguments"`
	Tasks       []parsedTask  `json:"tasks"`
	Panels      []parsedPanel `json:"panels"`
}

type parsedTask struct {
	Kind   string `json:"kind"` // cron / event / generic
	Name   string `json:"name"`
	Cron   string `json:"cron,omitempty"`
	Event  string `json:"event,omitempty"`
	Path   string `json:"path"`
	Format string `json:"format,omitempty"`
	Desc   string `json:"desc"`
	Line   string `json:"line"`
}

type parsedPanel struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Script string `json:"script,omitempty"`
	Format string `json:"format"`
}

func toParsed(rs *mitm.Ruleset) string {
	p := parsedText{Name: rs.Name, Desc: rs.Desc, Author: rs.Author, Category: rs.Category, Format: rs.Format, Hostnames: rs.Hostnames, CoreRules: rs.CoreRules,
		Errors: rs.Errors, Unsupported: rs.Unsupported, Arguments: rs.Arguments, Rules: []parsedRule{}}
	for _, r := range rs.Rules {
		pr := parsedRule{Kind: r.Kind, Phase: r.Phase, Pattern: r.Pattern, Desc: r.Desc, Line: r.Line}
		if r.Script != nil {
			pr.Script, pr.Path = r.Script.Name, r.Script.Path
		}
		p.Rules = append(p.Rules, pr)
	}
	p.Tasks, p.Panels = []parsedTask{}, []parsedPanel{}
	for _, t := range rs.Tasks {
		d := "通用脚本（手动运行 / 面板）"
		switch t.Kind {
		case mitm.TaskCron:
			d = "定时脚本：" + t.Cron
		case mitm.TaskEvent:
			d = "事件脚本：网络变化"
		}
		p.Tasks = append(p.Tasks, parsedTask{Kind: t.Kind, Name: t.Script.Name, Cron: t.Cron, Event: t.Event, Path: t.Script.Path, Format: t.Format, Desc: d, Line: t.Line})
	}
	for _, pn := range rs.Panels {
		p.Panels = append(p.Panels, parsedPanel{Name: pn.Name, Title: pn.Title, Script: pn.Script, Format: pn.Format})
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

// EngineTaskList returns JSON [task, …]: the cron / event / generic / interaction tasks of the user's
// scripts and enabled modules, parsed the same way the tunnel does (v0.11, for the app's task list
// while disconnected). Never starts the engine.
func EngineTaskList(home string) string {
	cfg := mitm.LoadConfig(home)
	rs := mitm.Build(home, cfg)
	list := mitm.OrderTasks(rs.Tasks, mitm.ReadTaskPrefs(home).Order) // the user's order (task-prefs.json)
	if list == nil {
		list = []*mitm.Task{}
	}
	b, _ := json.Marshal(list)
	return string(b)
}
