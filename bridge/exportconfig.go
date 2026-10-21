package libmihomo

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	o := overridesFor(homeDir, path)
	rt, err := buildRuntime(profile, o, 0)
	if err != nil {
		return "", err
	}
	return stripAppInternalsFor(rt, homeDir, o.Secret)
}

func stripAppInternals(rt []byte) (string, error) { return stripAppInternalsFor(rt, "", "") }

// stripAppInternalsFor (review 7 P2-2) also makes providers portable: loopback /convert URLs (Surge / QX
// imports) go back to the subscription's own URL and lose the controller's Authorization header; device-local
// file providers (节点订阅 ./nodesubs/<id>.yaml, QX 自有策略 lists in the App Group container, the profile's own
// file providers) are inlined as `type: inline` payloads. What cannot be made portable is explained in a
// comment block at the top of the file. The controller secret never appears in the output.
func stripAppInternalsFor(rt []byte, home, secret string) (string, error) {
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		return "", err
	}
	delete(raw, "secret")
	delete(raw, "external-controller")
	notes := portableProviders(raw, home, secret)
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
	text := string(out)
	if secret != "" && strings.Contains(text, secret) {
		text = strings.ReplaceAll(text, secret, "<redacted>") // belt and braces: no copy of the secret survives
	}
	if len(notes) > 0 {
		var b strings.Builder
		b.WriteString("# 导出说明 / Export notes:\n")
		for _, n := range notes {
			b.WriteString("#   - " + n + "\n")
		}
		text = b.String() + text
	}
	return text, nil
}

// privateProviderKeys are the app's own keys on a provider (ignored by mihomo, meaningless elsewhere).
var privateProviderKeys = []string{"x-source", "x-convert", "x-own-policy"}

func isLoopbackConvert(u string) bool {
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := pu.Hostname()
	return (h == "127.0.0.1" || h == "localhost" || h == "::1") && strings.HasSuffix(pu.Path, "/convert")
}

func portableProviders(raw map[string]any, home, secret string) (notes []string) {
	for _, key := range []string{"proxy-providers", "rule-providers"} {
		pv, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(pv))
		for n := range pv {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			m, ok := pv[name].(map[string]any)
			if !ok {
				continue
			}
			label := "节点集"
			if key == "rule-providers" {
				label = "规则集"
			}
			if u := str(m["url"]); isLoopbackConvert(u) {
				src := providerSourceURL(m)
				kind := ""
				if pu, err := url.Parse(u); err == nil {
					kind = pu.Query().Get("kind")
				}
				if src != "" && !isLoopbackConvert(src) {
					m["url"] = src
					if kind == "" {
						kind = "nodes"
					}
					notes = append(notes, fmt.Sprintf("%s「%s」的原始链接是需要转换的格式（%s），本 App 在本机转换后加载；其他客户端可能无法直接读取", label, name, kind))
				} else {
					delete(pv, name)
					notes = append(notes, fmt.Sprintf("%s「%s」只有本机转换地址，已从导出中移除", label, name))
					continue
				}
			}
			stripAuthHeader(m, secret)
			for _, k := range privateProviderKeys {
				delete(m, k)
			}
			if strings.EqualFold(str(m["type"]), "file") {
				if n := inlineFileProvider(key, name, m, home); n != "" {
					notes = append(notes, n)
				}
			}
		}
	}
	return notes
}

// stripAuthHeader drops Authorization headers carrying the controller secret (our loopback converter's).
func stripAuthHeader(m map[string]any, secret string) {
	h, ok := m["header"].(map[string]any)
	if !ok {
		return
	}
	for k, v := range h {
		if !strings.EqualFold(k, "Authorization") {
			continue
		}
		s := fmt.Sprint(v)
		if secret == "" || strings.Contains(s, secret) {
			delete(h, k)
		}
	}
	if len(h) == 0 {
		delete(m, "header")
	}
}

// inlineFileProvider turns a device-local file provider into `type: inline` with the file's content. Returns a
// note when the provider stays a file (unreadable / binary format).
func inlineFileProvider(key, name string, m map[string]any, home string) string {
	p := str(m["path"])
	label := "节点集"
	if key == "rule-providers" {
		label = "规则集"
	}
	if p == "" {
		return fmt.Sprintf("%s「%s」是本机文件，导出中无法携带", label, name)
	}
	full := p
	if !filepath.IsAbs(full) && home != "" {
		full = filepath.Join(home, p)
	}
	keep := func(why string) string {
		if filepath.IsAbs(p) {
			m["path"] = "./" + filepath.Base(p) // never export the device's container path
		}
		return fmt.Sprintf("%s「%s」是本机文件（%s），请在目标客户端里提供 %s", label, name, why, str(m["path"]))
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return keep("未找到")
	}
	if key == "proxy-providers" {
		doc := map[string]any{}
		if yaml.Unmarshal(b, &doc) != nil || len(asList(doc["proxies"])) == 0 {
			return keep("内容无法内联")
		}
		m["payload"] = asList(doc["proxies"])
	} else {
		format := strings.ToLower(str(m["format"]))
		var payload []any
		switch format {
		case "mrs":
			return keep("二进制 mrs 格式")
		case "yaml", "":
			doc := map[string]any{}
			if yaml.Unmarshal(b, &doc) == nil && doc["payload"] != nil {
				payload = asList(doc["payload"])
				break
			}
			if format == "yaml" {
				return keep("内容无法内联")
			}
			fallthrough
		default:
			for _, l := range strings.Split(string(b), "\n") {
				l = strings.TrimSpace(l)
				if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
					continue
				}
				payload = append(payload, l)
			}
		}
		m["payload"] = payload
		delete(m, "format")
	}
	m["type"] = "inline"
	delete(m, "path")
	delete(m, "interval")
	return ""
}
