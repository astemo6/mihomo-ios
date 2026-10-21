package libmihomo

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// FinalConfig returns the YAML the core would run for the profile at path (feat/more-dedup, user 2026-10-21
// 「导出最终配置（含覆写）」): the 覆写脚本 output when current, node processing, node subscriptions, the user's
// node-set edits and the app's core overrides — the same buildRuntime Start / ValidateConfig use, without the
// tunnel fd. Node credentials stay exactly as in the profile. App-internal plumbing is removed: the
// controller address and its secret, the hidden probe group and its loopback listener. Module / MitM
// injection is not included (it points at the app's own engine listener).
func FinalConfig(homeDir, path string) (string, error) {
	profile, err := readRuntimeProfile(homeDir, path, false)
	if err != nil {
		return "", fmt.Errorf("读取配置失败: %w", err)
	}
	C.SetHomeDir(homeDir)
	rt, err := buildRuntime(profile, overridesFor(homeDir, path), 0)
	if err != nil {
		return "", err
	}
	return stripAppInternals(rt)
}

func stripAppInternals(rt []byte) (string, error) {
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		return "", err
	}
	delete(raw, "secret")
	delete(raw, "external-controller")
	if gs := asList(raw["proxy-groups"]); len(gs) > 0 {
		kept := make([]any, 0, len(gs))
		for _, g := range gs {
			if str(asMap(g)["name"]) != ProbeGroup {
				kept = append(kept, g)
			}
		}
		raw["proxy-groups"] = kept
	}
	if ls, ok := raw["listeners"]; ok {
		kept := []any{}
		for _, l := range asList(ls) {
			if str(asMap(l)["name"]) != probeListener {
				kept = append(kept, l)
			}
		}
		if len(kept) == 0 {
			delete(raw, "listeners")
		} else {
			raw["listeners"] = kept
		}
	}
	out, err := yaml.Marshal(raw)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
