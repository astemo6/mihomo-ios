package libmihomo

// v0.19.22 开关类设置热应用: a switch flipped in the app (a rule set, a custom rule, a rewrite / module / plugin /
// script, 内核设置 / 连接方式 options) used to rebuild runtime.yaml and run hub.Parse on the whole profile — every
// proxy, provider, the DNS resolver and the listeners built again next to the live ones (memory peak old + new,
// see the reload memory line in the startup log). ReloadHot builds the same runtime.yaml the full apply would, diffs
// it against the one that is live, and when only parts mihomo can swap in place changed it applies just those:
//
//   - rules (and sub-rules re-parsed against the live proxies), with rule-providers added (parsed + initialised) or
//     removed (closed) while every remaining rule-provider is unchanged; the STUN / WebRTC drop rule (a hub.Parse
//     option, not in runtime.yaml) is applied the same way the full parse applies it
//   - mode, log-level
//   - the MitM / rewrite / script engine (rule, script and hostname sets, tasks): the same engine plan the full apply
//     commits, without the core parse
//
// Anything else that differs (proxies, groups, providers' settings, dns, tun, sniffer, listeners, hosts, …), a
// change of profile, 安全模式, an apply still loading, or a runtime.yaml on disk that is not the one that went live
// falls back to the full Reload. The new runtime.yaml (and runtime-groups.json) are written either way, so the next
// real reload or start builds and parses exactly what is running now.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/astemo6/mihomo-ios/bridge/mitm"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules"
	RB "github.com/metacubex/mihomo/rules/bundle"
	RC "github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"

	"go.yaml.in/yaml/v3"
)

// liveApply is what the last successful apply (full or hot) put live. ok=false: unknown (no apply yet, Stop,
// a failed apply) → the next ReloadHot does a full reload.
type liveApplyState struct {
	ok         bool
	sum        [32]byte // sha256 of the runtime.yaml that went live
	configPath string
	engineSum  [32]byte // engine.json (label only)
	stun       bool     // StunDropDirect the parse option was applied with
	webrtc     bool     // BlockWebRTC
}

var (
	liveApplyMu sync.Mutex
	liveApply   liveApplyState
)

// applyInFlight counts applies in progress (a Start apply keeps loading providers after Start returned).
var applyInFlight atomic.Int32

func engineJSONSum(home string) [32]byte {
	b, _ := os.ReadFile(filepath.Join(mitm.EngineDir(home), "engine.json"))
	return sha256.Sum256(b)
}

func recordLiveApply(home, configPath string, rt []byte, o Overrides) {
	liveApplyMu.Lock()
	liveApply.ok = true
	liveApply.sum = sha256.Sum256(rt)
	liveApply.configPath = configPath
	liveApply.engineSum = engineJSONSum(home)
	liveApply.stun, liveApply.webrtc = o.StunDropDirect, o.BlockWebRTC
	liveApplyMu.Unlock()
}

func forgetLiveApply() {
	liveApplyMu.Lock()
	liveApply.ok = false
	liveApplyMu.Unlock()
}

// hotAllowed: the runtime keys a hot apply can take over in place.
var hotAllowed = map[string]bool{"rules": true, "rule-providers": true, "mode": true, "log-level": true}

// ReloadHot is Reload for a switch the user flipped: applied in place when possible (see the file comment),
// otherwise the full Reload. The startup log says which ("hot-apply <what>" or "reload (<why>)").
func ReloadHot(configPath string) (err error) {
	done := reloadBegin("hot")
	defer func() { done(err) }()
	mu.Lock()
	defer mu.Unlock()
	if !running.Load() {
		return errors.New("core not running")
	}
	home := curHomeStr()
	if home == "" {
		return errors.New("core not started")
	}
	what, why, err := hotApplyLocked(home, configPath, curFd.Load())
	if why == "" {
		if err != nil {
			setLastError(err.Error())
		}
		return err
	}
	_ = what
	stage("reload (%s)", why)
	return reloadLocked(configPath)
}

// hotApplyLocked tries the in-place apply. why != "" means it was not possible (nothing was changed; the caller
// does the full reload). Caller holds mu.
func hotApplyLocked(home, configPath string, fd int32) (what string, why string, err error) {
	defer func() {
		if p := recover(); p != nil {
			stage("PANIC in hot-apply: %v", p)
			what, why, err = "", fmt.Sprintf("hot-apply panic: %v", p), nil
		}
	}()
	if applyInFlight.Load() > 0 {
		return "", "an apply is still loading", nil
	}
	liveApplyMu.Lock()
	live := liveApply
	liveApplyMu.Unlock()
	if !live.ok {
		return "", "no live config recorded", nil
	}
	if live.configPath != configPath {
		return "", "another profile", nil
	}
	o := overridesFor(home, configPath)
	if o.SafeMode {
		return "", "safe mode", nil
	}
	rtPath := filepath.Join(home, "runtime.yaml")
	old, rerr := os.ReadFile(rtPath)
	if rerr != nil || sha256.Sum256(old) != live.sum {
		return "", "runtime.yaml on disk is not the live one", nil
	}
	profile, perr := readRuntimeProfile(home, configPath, false)
	if perr != nil {
		return "", "profile read failed", nil
	}
	inject, plan, eerr := planEngine(home)
	if eerr != nil {
		plan.rollback()
		return "", "engine: " + eerr.Error(), nil
	}
	committed := false
	defer func() {
		if !committed {
			plan.rollback()
		}
	}()
	var groupOrder []string
	tunChanged := false
	rt, berr := buildRuntimeWith(profile, o, fd, func(raw map[string]any) {
		if inject != nil {
			inject(raw)
		}
		groupOrder = runtimeGroupNames(raw)
		if fd > 0 {
			if tun, ok := raw["tun"].(map[string]any); ok {
				h, same := tunFds.peek(tunSignature(raw))
				tunChanged = !same
				tun["file-descriptor"] = int(h)
			}
		}
	})
	if berr != nil {
		return "", "runtime build failed", nil
	}
	if tunChanged {
		return "", "tun changed", nil
	}

	var oldRaw, newRaw map[string]any
	changed := map[string]bool{}
	if !bytes.Equal(rt, old) {
		if yaml.Unmarshal(old, &oldRaw) != nil || yaml.Unmarshal(rt, &newRaw) != nil {
			return "", "runtime.yaml not comparable", nil
		}
		for _, k := range unionKeys(oldRaw, newRaw) {
			if !reflect.DeepEqual(oldRaw[k], newRaw[k]) {
				if !hotAllowed[k] {
					return "", k + " changed", nil
				}
				changed[k] = true
			}
		}
	} else if newRaw == nil {
		if yaml.Unmarshal(rt, &newRaw) != nil {
			return "", "runtime.yaml not comparable", nil
		}
	}
	stunChanged := live.stun != o.StunDropDirect || live.webrtc != o.BlockWebRTC

	// Rule providers: unchanged ones are kept, removed ones closed after the swap, added ones parsed now.
	var labels []string
	liveRP := tunnel.RuleProviders()
	providers := map[string]P.RuleProvider{}
	var added map[string]P.RuleProvider
	var removed, replaced []P.RuleProvider
	rulesChanged := changed["rules"] || changed["rule-providers"] || stunChanged
	if rulesChanged {
		oldRP, newRP := asMap(oldRaw["rule-providers"]), asMap(newRaw["rule-providers"])
		if oldRaw == nil {
			oldRP = newRP
		}
		for name := range oldRP {
			if _, ok := liveRP[name]; !ok {
				return "", "rule-provider " + name + " not live", nil
			}
		}
		added = map[string]P.RuleProvider{}
		for name, v := range newRP {
			if ov, ok := oldRP[name]; ok {
				if reflect.DeepEqual(ov, v) {
					providers[name] = liveRP[name]
					continue
				}
				// Changed settings (an inline set such as the MitM host list, another URL): built again like a
				// full parse would, the live one closed after the swap.
				replaced = append(replaced, liveRP[name])
			}
			mapping, ok := v.(map[string]any)
			if !ok {
				closeProviders(added)
				return "", "rule-provider " + name + " invalid", nil
			}
			RP.SetTunnel(tunnel.Tunnel)
			rp, perr := RP.ParseRuleProvider(name, mapping, R.ParseRule, RB.MakeBundleFile)
			if perr != nil {
				closeProviders(added)
				return "", "rule-provider " + name + ": " + perr.Error(), nil
			}
			added[name] = rp
			providers[name] = rp
		}
		for name := range oldRP {
			if _, ok := newRP[name]; !ok {
				removed = append(removed, liveRP[name])
			}
		}
		nAdded := len(added) - len(replaced)
		proxies := tunnel.Proxies()
		subRules, serr := parseSubRuleLines(newRaw["sub-rules"], proxies, providers)
		if serr != nil {
			closeProviders(added)
			return "", "sub-rules: " + serr.Error(), nil
		}
		rules, rerr := parseRuleLines(stringsOf(newRaw["rules"]), proxies, providers, subRules, "rules")
		if rerr != nil {
			closeProviders(added)
			return "", "rules: " + rerr.Error(), nil
		}
		cfg := &config.Config{Rules: rules}
		stunDropOption(o.StunDropDirect, o.BlockWebRTC)(cfg)
		// Added rule sets load before the swap (mihomo's full apply swaps first and loads after; a set that is not
		// loaded yet matches nothing either way).
		initProviders(added)
		flushRuleHits(home) // the new rules start counting at 0 (as Reload)
		proxyTrafficStats.resetClasses()
		tunnel.UpdateRules(cfg.Rules, subRules, providers)
		for _, rp := range append(removed, replaced...) {
			if c, ok := rp.(io.Closer); ok {
				_ = c.Close()
			}
		}
		l := fmt.Sprintf("rules (%d)", len(cfg.Rules))
		if nAdded > 0 || len(removed) > 0 || len(replaced) > 0 {
			l += fmt.Sprintf(", rule-sets +%d −%d ~%d", nAdded, len(removed), len(replaced))
		}
		if stunChanged {
			l += ", stun/webrtc"
		}
		labels = append(labels, l)
	}
	if changed["mode"] {
		m := strings.ToLower(str(newRaw["mode"]))
		if m == "" {
			m = "rule"
		}
		if tm, ok := tunnel.ModeMapping[m]; ok {
			tunnel.SetMode(tm)
		}
		labels = append(labels, "mode "+m)
	}
	if changed["log-level"] {
		lv := strings.ToLower(str(newRaw["log-level"]))
		if l, ok := log.LogLevelMapping[lv]; ok {
			log.SetLevel(l)
		} else {
			log.SetLevel(log.INFO)
		}
		labels = append(labels, "log-level "+lv)
	}
	startGC(o.MemoryLimitMB)
	if lv, ok := log.LogLevelMapping[strings.ToLower(o.LogLevel)]; ok {
		diagLevel.Store(int32(lv))
	} else {
		diagLevel.Store(int32(log.INFO))
	}
	committed = true
	plan.commit()
	if engineJSONSum(home) != live.engineSum {
		labels = append(labels, "engine (rewrite / script / MitM sets)")
	} else {
		labels = append(labels, "engine")
	}
	_ = os.WriteFile(rtPath, rt, 0o644)
	writeRuntimeGroupOrder(home, groupOrder)
	liveGroupOrder.Store(groupOrder)
	recordLiveApply(home, configPath, rt, o)
	// The same post-apply steps as Reload (the groups are untouched, so the policy-watch baseline stays).
	setNetPolicyProfile(configPath)
	startSmart(home, configPath)
	applyNetPolicy(home, configPath, "reload")
	m := readMem()
	what = strings.Join(labels, ", ")
	stage("hot-apply %s (no core re-parse), footprint %s, available %s, go heap %s", what, mbs(m.fp), mbs(m.avail), mbu(m.heap))
	return what, "", nil
}

// unionKeys: both maps' keys, sorted (the log names the same first blocker every time).
func unionKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func stringsOf(v any) []string {
	var out []string
	for _, x := range asList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

// parseRuleLines is mihomo's config.parseRules (unexported there): the same checks, the same wrapper for the
// top level rules.
func parseRuleLines(lines []string, proxies map[string]C.Proxy, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule
	for idx, line := range lines {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		if target == "" {
			return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
		}
		if _, ok := proxies[target]; !ok {
			if tp != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}
		parsed, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, err.Error())
		}
		for _, name := range parsed.ProviderNames() {
			if _, ok := ruleProviders[name]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: rule set [%s] not found", format, idx, line, name)
			}
		}
		if format == "rules" {
			parsed = RW.NewRuleWrapper(parsed)
		}
		rules = append(rules, parsed)
	}
	return rules, nil
}

// parseSubRuleLines is mihomo's parseSubRules for an unchanged sub-rules section (it was verified when it went live).
func parseSubRuleLines(v any, proxies map[string]C.Proxy, ruleProviders map[string]P.RuleProvider) (map[string][]C.Rule, error) {
	src := asMap(v)
	sub := map[string][]C.Rule{}
	names := make([]string, 0, len(src))
	for name := range src {
		sub[name] = []C.Rule{}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rules, err := parseRuleLines(stringsOf(src[name]), proxies, ruleProviders, sub, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		sub[name] = rules
	}
	return sub, nil
}

func initProviders(m map[string]P.RuleProvider) {
	var wg sync.WaitGroup
	for _, rp := range m {
		wg.Add(1)
		go func(rp P.RuleProvider) {
			defer wg.Done()
			log.Infoln("Start initial provider %s", rp.Name())
			if err := rp.Initial(); err != nil {
				log.Errorln("initial rule provider %s error: %v", rp.Name(), err)
			}
		}(rp)
	}
	wg.Wait()
}

func closeProviders(m map[string]P.RuleProvider) {
	for _, rp := range m {
		if c, ok := rp.(io.Closer); ok {
			_ = c.Close()
		}
	}
}
