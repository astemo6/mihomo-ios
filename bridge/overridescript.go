package libmihomo

// v0.19 覆写脚本 (override scripts, Clash Verge / FlClash / Bettbox convention).
//
// The scripts themselves run in the app (JavaScriptCore). The core only:
//   - hands the app the profile as JSON (ScriptInput), the same profile Start would read
//     (share-link / base64 subscriptions converted, `rule:` → `rules:`, proxy-providers ensured);
//   - takes the script chain's output back (ScriptOutputApply), converts it to YAML, validates it
//     with the app's own overrides exactly as Start would, and only then stores it as
//     <home>/scripted/<profile id>.yaml with a meta file holding the SHA-256 of the source profile;
//   - reads that output instead of the profile file in apply / validate / inspect / offline groups
//     (readRuntimeProfile) while the source is unchanged. A stale output (the profile changed and
//     the app did not run the scripts again, e.g. an on-demand connect after a background
//     subscription update) is ignored with a warning: the profile itself is used.
// Safe mode always uses the profile file itself (safe mode = the profile only).
// Our own overrides (group edits, node subscriptions, chains, DNS, …) are applied after the
// script output, in buildRuntimeWith, as before.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

type scriptedMeta struct {
	Source  string   `json:"source"`  // sha256 of the profile file the scripts ran on
	At      int64    `json:"at"`      // unix seconds
	Scripts []string `json:"scripts"` // script names in run order (diagnostics)
}

func scriptedDir(home string) string { return filepath.Join(home, "scripted") }

func scriptedPaths(home, profilePath string) (string, string) {
	id := profileIDFromPath(profilePath)
	d := scriptedDir(home)
	return filepath.Join(d, id+".yaml"), filepath.Join(d, id+".json")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// scriptedFor returns the stored script output for the profile when it exists and was produced
// from exactly these source bytes. stale reports an output that exists but no longer matches.
func scriptedFor(home, profilePath string, source []byte) (out []byte, meta scriptedMeta, stale bool) {
	if home == "" {
		return nil, meta, false
	}
	yp, mp := scriptedPaths(home, profilePath)
	mb, err := os.ReadFile(mp)
	if err != nil {
		return nil, meta, false
	}
	if json.Unmarshal(mb, &meta) != nil || meta.Source == "" {
		return nil, meta, false
	}
	if meta.Source != sha256Hex(source) {
		return nil, meta, true
	}
	b, err := os.ReadFile(yp)
	if err != nil || len(b) == 0 {
		return nil, meta, false
	}
	return b, meta, false
}

// readRuntimeProfile reads the profile at path, or the override-script output for it when that is
// current. safe = safe mode (scripts off).
func readRuntimeProfile(home, path string, safe bool) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if safe {
		return b, nil
	}
	out, meta, stale := scriptedFor(home, path, b)
	if stale {
		log.Warnln("[Script] 覆写脚本的结果已过期（配置已变更、脚本未重新运行），本次使用配置文件本身；打开 App 会重新运行脚本")
		stage("override scripts: output stale (profile changed), using the profile itself")
		return b, nil
	}
	if out != nil {
		stage("override scripts: using script output (%d bytes, %d script(s))", len(out), len(meta.Scripts))
		return out, nil
	}
	return b, nil
}

// profileAsMap parses a profile the way buildRuntimeWith does before any override.
func profileAsMap(profile []byte) (map[string]any, error) {
	raw := map[string]any{}
	if err := yaml.Unmarshal(profile, &raw); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if raw == nil {
		raw = map[string]any{}
	}
	if _, ok := raw["proxies"]; !ok {
		if _, ok2 := raw["proxy-providers"]; !ok2 {
			if conv, err := convertLinks(profile); err == nil {
				raw = map[string]any{}
				_ = yaml.Unmarshal(conv, &raw)
			}
		}
	}
	return raw, nil
}

// jsonSafe converts YAML-decoded values into values encoding/json accepts (map keys as strings).
func jsonSafe(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = jsonSafe(x)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = jsonSafe(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = jsonSafe(x)
		}
		return l
	case time.Time:
		return t.Format(time.RFC3339)
	default:
		return v
	}
}

// ScriptInput returns the profile at path as a JSON object for override scripts.
func ScriptInput(profilePath string) (string, error) {
	js, _, err := scriptInput(profilePath)
	return js, err
}

// ScriptInputSnapshot is ScriptInput plus the sha256 of the exact bytes it read: "<sha>\n<json>". The app
// passes the sha to ScriptOutputApplyFor, so output computed from content that changed during the chain
// (a subscription download, a copy regeneration) is never stored as fresh.
func ScriptInputSnapshot(profilePath string) (string, error) {
	js, sha, err := scriptInput(profilePath)
	if err != nil {
		return "", err
	}
	return sha + "\n" + js, nil
}

// errScriptSourceChanged: the profile changed while the scripts ran.
const errScriptSourceChanged = "配置在脚本运行期间已改变，请重新运行"

func scriptInput(profilePath string) (string, string, error) {
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return "", "", fmt.Errorf("读取配置失败: %w", err)
	}
	sha := sha256Hex(b)
	raw, err := profileAsMap(b)
	if err != nil {
		return "", "", err
	}
	// Bettbox normalisation: `rule:` is an alias of `rules:`; scripts expect proxy-providers to exist.
	if r, ok := raw["rule"]; ok {
		if _, has := raw["rules"]; !has {
			raw["rules"] = r
		}
		delete(raw, "rule")
	}
	if p, ok := raw["proxy-providers"]; !ok || p == nil {
		raw["proxy-providers"] = map[string]any{}
	}
	safe := jsonSafe(raw).(map[string]any)
	orderPolicyForScript(safe, b)
	out, err := json.Marshal(safe)
	if err != nil {
		return "", "", fmt.Errorf("配置无法转换为 JSON: %w", err)
	}
	return string(out), sha, nil
}

// scriptOutputYAML turns the script chain's JSON output into profile YAML.
func scriptOutputYAML(outputJSON string) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(outputJSON), &raw); err != nil {
		return nil, fmt.Errorf("脚本返回的不是配置对象: %w", err)
	}
	if raw == nil {
		return nil, errors.New("脚本返回了空配置")
	}
	if p, ok := raw["proxy-providers"].(map[string]any); ok && len(p) == 0 {
		delete(raw, "proxy-providers")
	}
	normalizeJSONNumbers(raw)
	// v0.19.5: dns.nameserver-policy keeps the order the script produced (JSON object key order; mihomo
	// uses the first matching entry). Decoding into a Go map alone wrote it sorted by key.
	if dns, ok := raw["dns"].(map[string]any); ok {
		keepProfilePolicyOrder(dns, []byte(outputJSON))
	}
	return yaml.Marshal(raw)
}

// orderedJSONObject marshals a map with its keys in a fixed order (JSON key order is what a script sees
// in for…in / Object.keys and what it writes back).
type orderedJSONObject struct {
	keys []string
	vals map[string]any
}

func (o orderedJSONObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// orderPolicyForScript hands dns.nameserver-policy to override scripts in the profile's own order
// (keys missing from the profile order, if any, follow sorted).
func orderPolicyForScript(raw map[string]any, profile []byte) {
	dns, ok := raw["dns"].(map[string]any)
	if !ok {
		return
	}
	m, ok := dns["nameserver-policy"].(map[string]any)
	if !ok || len(m) < 2 {
		return
	}
	order := profilePolicyOrder(profile)
	if len(order) == 0 {
		return
	}
	seen := map[string]bool{}
	var keys []string
	for _, k := range order {
		if _, ok := m[k]; ok && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	dns["nameserver-policy"] = orderedJSONObject{keys: append(keys, rest...), vals: m}
}

// normalizeJSONNumbers turns whole float64 values (every JSON number) back into ints so ports,
// intervals and the like are written as 443, not 443.0 / 4.43e+02.
func normalizeJSONNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeJSONNumbers(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeJSONNumbers(x)
		}
		return t
	case float64:
		if t == float64(int64(t)) && t < 1e15 && t > -1e15 {
			return int64(t)
		}
		return t
	default:
		return v
	}
}

// ScriptOutputApply validates the script chain's output for the profile at profilePath with the
// app's overrides (as Start would) and stores it. scriptsJSON = ["name", …] in run order.
// Returns "" or the error (nothing is stored on error, the previous output is removed so a broken
// script never leaves an old result running silently).
func ScriptOutputApply(home, profilePath, outputJSON, scriptsJSON string) string {
	return ScriptOutputApplyFor(home, profilePath, outputJSON, scriptsJSON, "")
}

// ScriptOutputApplyFor is ScriptOutputApply for output computed from the profile content with sha256
// sourceSHA (from ScriptInputSnapshot): refused when the file no longer has that content. "" = no check.
func ScriptOutputApplyFor(home, profilePath, outputJSON, scriptsJSON, sourceSHA string) string {
	src, err := os.ReadFile(profilePath)
	if err != nil {
		return "读取配置失败: " + err.Error()
	}
	yp, mp := scriptedPaths(home, profilePath)
	defer lockPath(yp)() // v0.19.6: two applies of one profile wrote output and meta interleaved
	fail := func(msg string) string {
		_ = os.Remove(yp)
		_ = os.Remove(mp)
		return msg
	}
	if sourceSHA != "" && sourceSHA != sha256Hex(src) {
		return fail(errScriptSourceChanged)
	}
	y, err := scriptOutputYAML(outputJSON)
	if err != nil {
		return fail(err.Error())
	}
	if msg := safeValidate(home, profilePath, y); msg != "" {
		return fail("脚本输出的配置校验失败: " + msg)
	}
	var names []string
	_ = json.Unmarshal([]byte(scriptsJSON), &names)
	if err := os.MkdirAll(scriptedDir(home), 0o755); err != nil {
		return fail(err.Error())
	}
	if err := writeFileAtomic(yp, y); err != nil {
		return fail(err.Error())
	}
	mb, _ := json.Marshal(scriptedMeta{Source: sha256Hex(src), At: time.Now().Unix(), Scripts: names})
	if err := writeFileAtomic(mp, mb); err != nil {
		return fail(err.Error())
	}
	return ""
}

// ScriptOutputClear removes the stored output (no enabled scripts left).
func ScriptOutputClear(home, profilePath string) {
	yp, mp := scriptedPaths(home, profilePath)
	defer lockPath(yp)()
	_ = os.Remove(yp)
	_ = os.Remove(mp)
}

// ScriptOutputStatus: {"exists":bool,"fresh":bool,"at":unix,"scripts":[…],"bytes":n}.
func ScriptOutputStatus(home, profilePath string) string {
	src, _ := os.ReadFile(profilePath)
	yp, mp := scriptedPaths(home, profilePath)
	st := map[string]any{"exists": false, "fresh": false}
	if mb, err := os.ReadFile(mp); err == nil {
		var m scriptedMeta
		if json.Unmarshal(mb, &m) == nil {
			if fi, err := os.Stat(yp); err == nil {
				st["exists"] = true
				st["fresh"] = m.Source == sha256Hex(src)
				st["at"] = m.At
				st["scripts"] = m.Scripts
				st["bytes"] = fi.Size()
			}
		}
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// ScriptOutputYAML returns the stored output (for the 「查看结果」 screen), "" when none.
func ScriptOutputYAML(home, profilePath string) string {
	yp, _ := scriptedPaths(home, profilePath)
	b, _ := os.ReadFile(yp)
	return string(b)
}

func safeValidate(home, profilePath string, b []byte) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	return validateProfileBytes(home, profilePath, b)
}
