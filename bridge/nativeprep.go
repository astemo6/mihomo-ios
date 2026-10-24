package libmihomo

// feat/native-core-eval: the Go-free tunnel (NativeCore) cannot build its own runtime config yet — profile overrides,
// 覆写脚本, custom rules, group edits, proxy chains, module core rules and share-link conversion all live in this
// package. Until they are ported to Swift, the APP process calls PrepareNativeRuntime before it starts the tunnel and
// before every reload; the tunnel only reads the files written here:
//
//   runtime.yaml               the same runtime config Start would build (no tun section — the tunnel owns the
//                              packet flow — no __MITM__ proxy: native MitM is decided by SNI in the data plane),
//                              lowered for NativeCore (GEOSITE → file rule sets, IN-TYPE terms dropped)
//   nativecore-runtime.json    runtime.yaml as JSON (what the tunnel decodes)
//   runtime-groups.json        the app's group order (as Start writes it)
//   nativecore-rewrite.json    the MitM / rewrite / script snapshot (mitm.RewriteSnapshot) for the native rewrite
//                              engine and the data plane's MitM host matcher ("" file removed when nothing is on)
//   nativecore-geosite/*.list  one classical rule list per GEOSITE code the rules use
//   nativecore-prep.json       what was prepared and what NativeCore will not do with it (shown in 诊断)
//
// Nothing is started: no engine, no listener, no hub.Parse.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// NativePrepFile is the report PrepareNativeRuntime leaves next to runtime.yaml.
const NativePrepFile = "nativecore-prep.json"

// NativeRuntimeJSONFile is runtime.yaml re-encoded as JSON for the tunnel.
const NativeRuntimeJSONFile = "nativecore-runtime.json"

type nativePrep struct {
	At       int64    `json:"at"`
	Profile  string   `json:"profile"`
	Rules    int      `json:"rules"`
	Geosite  []string `json:"geosite,omitempty"`
	Rewrite  bool     `json:"rewrite"`
	Hosts    int      `json:"mitmHosts"`
	Lowered  []string `json:"lowered,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

var inTypeTerm = regexp.MustCompile(`,?\(NOT,\(\(IN-TYPE,[A-Za-z-]+\)\)\)`)
var geositeRef = regexp.MustCompile(`(?i)\bGEOSITE,([^,()\s]+)`)

// PrepareNativeRuntime builds the runtime config for configPath (home = the core home dir) and writes the files the
// native tunnel reads. Returns a one-line summary.
func PrepareNativeRuntime(home, configPath string) (string, error) {
	C.SetHomeDir(home)
	C.SetConfig(configPath)
	o := overridesFor(home, configPath)
	profile, err := readRuntimeProfile(home, configPath, o.SafeMode)
	if err != nil {
		return "", fmt.Errorf("读取配置失败: %w", err)
	}
	rep := nativePrep{At: time.Now().Unix(), Profile: filepath.Base(configPath)}
	var cfg *mitm.Config
	var rs *mitm.Ruleset
	if !o.SafeMode {
		cfg = mitm.LoadConfig(home)
		rs = mitm.Build(home, cfg)
	}
	var groupOrder []string
	rt, err := buildRuntimeWith(profile, o, 0, func(raw map[string]any) {
		if cfg != nil {
			if cfg.AnyOn() {
				pre := mitm.ResolveCoreRules(raw, rs.CoreRules, nil)
				if len(pre) > 0 {
					rules, _ := raw["rules"].([]any)
					out := make([]any, 0, len(pre)+len(rules))
					for _, r := range pre {
						out = append(out, r)
					}
					raw["rules"] = append(out, rules...)
				}
				addRemoteModuleRules(raw, rs.CoreRules)
			}
			if cfg.QUIC == "all" {
				rules, _ := raw["rules"].([]any)
				raw["rules"] = append([]any{"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"}, rules...)
			}
		}
		lowerForNative(home, raw, &rep)
		groupOrder = runtimeGroupNames(raw)
	})
	if err != nil {
		return "", err
	}
	if err := writeAtomicFile(filepath.Join(home, "runtime.yaml"), rt); err != nil {
		return "", err
	}
	writeRuntimeGroupOrder(home, groupOrder)
	// The tunnel decodes JSON (Foundation) first; its YAML subset parser is the fallback only.
	js, err := NativeConfigJSON(home)
	if err != nil {
		return "", fmt.Errorf("native runtime JSON: %w", err)
	}
	if err := writeAtomicFile(filepath.Join(home, NativeRuntimeJSONFile), []byte(js)); err != nil {
		return "", err
	}
	snapPath := filepath.Join(home, "nativecore-rewrite.json")
	if cfg != nil && (cfg.AnyOn() || (cfg.MitM && len(rs.Hostnames) > 0)) {
		snap, hosts := mitm.ExportRewriteSnapshot(home, cfg, rs)
		rep.Rewrite = true
		rep.Hosts = hosts
		if err := writeAtomicFile(snapPath, []byte(snap)); err != nil {
			return "", err
		}
	} else {
		_ = os.Remove(snapPath)
	}
	if b, err := json.Marshal(rep); err == nil {
		_ = writeAtomicFile(filepath.Join(home, NativePrepFile), b)
	}
	return fmt.Sprintf("runtime.yaml %d B, %d rules, geosite %d, rewrite %v, mitm hosts %d, warnings %d",
		len(rt), rep.Rules, len(rep.Geosite), rep.Rewrite, rep.Hosts, len(rep.Warnings)), nil
}

func writeAtomicFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// lowerForNative rewrites rule shapes NativeCore does not evaluate into ones it does.
func lowerForNative(home string, raw map[string]any, rep *nativePrep) {
	rules, _ := raw["rules"].([]any)
	rp, _ := raw["rule-providers"].(map[string]any)
	if rp == nil {
		rp = map[string]any{}
	}
	codes := map[string]bool{}
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		s, ok := r.(string)
		if !ok {
			out = append(out, r)
			continue
		}
		orig := s
		// mihomo's IN-TYPE (inbound type) has no meaning in the native tunnel: there is one inbound.
		s = inTypeTerm.ReplaceAllString(s, "")
		s = geositeRef.ReplaceAllStringFunc(s, func(m string) string {
			code := strings.ToLower(geositeRef.FindStringSubmatch(m)[1])
			codes[code] = true
			return "RULE-SET," + geositeProvider(code)
		})
		if s != orig && len(rep.Lowered) < 20 {
			rep.Lowered = append(rep.Lowered, orig+" → "+s)
		}
		out = append(out, s)
	}
	raw["rules"] = out
	rep.Rules = len(out)
	if len(codes) == 0 {
		return
	}
	dir := filepath.Join(home, "nativecore-geosite")
	_ = os.MkdirAll(dir, 0o755)
	loader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		rep.Warnings = append(rep.Warnings, "GEOSITE: "+err.Error())
		return
	}
	dat, err := os.ReadFile(filepath.Join(home, "GeoSite.dat"))
	if err != nil {
		rep.Warnings = append(rep.Warnings, "GEOSITE: "+err.Error())
	}
	for code := range codes {
		name := geositeProvider(code)
		file := filepath.Join(dir, code+".list")
		list := code
		if i := strings.IndexByte(list, '@'); i >= 0 {
			list = list[:i]
			rep.Warnings = append(rep.Warnings, "GEOSITE "+code+": attributes ignored")
		}
		domains, err := loader.LoadSiteByBytes(dat, list)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "GEOSITE "+code+": "+err.Error())
			domains = nil
		}
		var b strings.Builder
		for _, d := range domains {
			switch d.Type {
			case router.Domain_Plain:
				b.WriteString("DOMAIN-KEYWORD," + d.Value + "\n")
			case router.Domain_Regex:
				b.WriteString("DOMAIN-REGEX," + d.Value + "\n")
			case router.Domain_Domain:
				b.WriteString("DOMAIN-SUFFIX," + d.Value + "\n")
			case router.Domain_Full:
				b.WriteString("DOMAIN," + d.Value + "\n")
			}
		}
		_ = writeAtomicFile(file, []byte(b.String()))
		rp[name] = map[string]any{"type": "file", "behavior": "classical", "path": file}
		rep.Geosite = append(rep.Geosite, fmt.Sprintf("%s (%d)", code, len(domains)))
	}
	raw["rule-providers"] = rp
}

func geositeProvider(code string) string { return "__geosite_" + strings.NewReplacer("@", "_", "!", "not_").Replace(code) }

// NativePrepReport returns the last nativecore-prep.json (诊断), "" when none.
func NativePrepReport(home string) string {
	b, err := os.ReadFile(filepath.Join(home, NativePrepFile))
	if err != nil {
		return ""
	}
	return string(b)
}

var _ = yaml.Marshal
