package libmihomo

// 节点管理 (v0.16): one node's summary without secrets, and an offline delay test that also finds nodes of
// node subscriptions (profileRaw builds the runtime without the app home, so TestDelayByName only sees the
// profile's own providers). Both build the runtime exactly like InspectProfile.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// runtimeRawWithHome is the runtime map InspectProfile reads (manual merge, node subscriptions, group edits).
func runtimeRawWithHome(homeDir, profilePath string) map[string]any {
	raw := map[string]any{}
	C.SetHomeDir(homeDir)
	// v0.19.10 (review 5 go-core P2-1): the 覆写脚本 output, like Start / InspectProfile.
	b, err := readRuntimeProfile(homeDir, profilePath, false)
	if err != nil {
		setLastError(err.Error())
		return raw
	}
	rt, err := buildRuntime(b, overridesFor(homeDir, profilePath), 0)
	if err != nil {
		setLastError(err.Error())
		return raw
	}
	_ = yaml.Unmarshal(rt, &raw)
	if raw == nil {
		raw = map[string]any{}
	}
	return raw
}

// providerNodes reads the nodes of one proxy provider (inline payload or its cached file).
func providerNodes(m map[string]any) []map[string]any {
	if strings.EqualFold(str(m["type"]), "inline") {
		return proxiesOf(map[string]any{"proxies": m["payload"]})
	}
	cp := providerCache("proxy", m)
	if cp == "" {
		return nil
	}
	b, err := os.ReadFile(cp)
	if err != nil {
		return nil
	}
	pr := map[string]any{}
	if yaml.Unmarshal(b, &pr) == nil && pr != nil {
		if n := proxiesOf(pr); len(n) > 0 {
			return n
		}
	}
	n, _ := parseNodeText(string(b))
	return n
}

// findRuntimeNode returns the node named name and its source ("" = the profile, else the provider name).
func findRuntimeNode(raw map[string]any, name string) (map[string]any, string, bool) {
	for _, p := range proxiesOf(raw) {
		if str(p["name"]) == name {
			return p, "", true
		}
	}
	pv, _ := raw["proxy-providers"].(map[string]any)
	names := make([]string, 0, len(pv))
	for k := range pv {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		m, ok := pv[k].(map[string]any)
		if !ok {
			continue
		}
		for _, p := range providerNodes(m) {
			if str(p["name"]) == name {
				return p, k, true
			}
		}
	}
	return nil, "", false
}

// findRuntimeNodeIn (review 7 R7A-4) looks a node up in one source only: provider "" = the profile's own
// proxies, otherwise that proxy-provider (node subscriptions included, by their runtime provider name — the
// `source` NodeSummary returns and /providers/proxies lists). Same-named nodes of two subscriptions are
// allowed in mihomo; the name-only lookup returned the alphabetically first provider's node, so the detail
// of subscription B showed / copied / tested subscription A's credentials and server.
func findRuntimeNodeIn(raw map[string]any, provider, name string) (map[string]any, bool) {
	if provider == "" {
		for _, p := range proxiesOf(raw) {
			if str(p["name"]) == name {
				return p, true
			}
		}
		return nil, false
	}
	pv, _ := raw["proxy-providers"].(map[string]any)
	m, ok := pv[provider].(map[string]any)
	if !ok {
		return nil, false
	}
	for _, p := range providerNodes(m) {
		if str(p["name"]) == name {
			return p, true
		}
	}
	return nil, false
}

// credentialKeys are the secrets a node may carry; the summary only says which ones are set.
var credentialKeys = []string{"password", "uuid", "username", "private-key", "pre-shared-key", "public-key", "psk",
	"auth", "auth-str", "auth_str", "token", "auth-key", "obfs-password", "private-key-passphrase", "short-id"}

// nestedCredentialKeys lists secrets inside option maps as dotted paths (reality-opts.public-key,
// plugin-opts.password, peers.0.pre-shared-key). Names only; NodeConfig has the values.
func nestedCredentialKeys(m map[string]any) []string {
	var out []string
	if ro, ok := m["reality-opts"].(map[string]any); ok {
		for _, k := range []string{"public-key", "short-id"} {
			if str(ro[k]) != "" {
				out = append(out, "reality-opts."+k)
			}
		}
	}
	if po, ok := m["plugin-opts"].(map[string]any); ok && str(po["password"]) != "" {
		out = append(out, "plugin-opts.password")
	}
	if peers, ok := m["peers"].([]any); ok {
		for i, p := range peers {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			for _, k := range []string{"public-key", "pre-shared-key"} {
				if str(pm[k]) != "" {
					out = append(out, fmt.Sprintf("peers.%d.%s", i, k))
				}
			}
		}
	}
	return out
}

// nodeSummary keeps what the 节点管理 detail shows: protocol, address, transport / TLS options and which
// credentials exist — never their values (and no paths / headers / reality keys).
func nodeSummary(m map[string]any, source string) map[string]any {
	typ := strings.ToLower(str(m["type"]))
	out := map[string]any{"name": str(m["name"]), "type": typ, "server": str(m["server"]), "port": intOf(m["port"]),
		"udp": boolOf(m["udp"]), "source": source}
	set := func(k string, v string) {
		if v != "" {
			out[k] = v
		}
	}
	network := strings.ToLower(str(m["network"]))
	set("network", network)
	tls := boolOf(m["tls"])
	switch typ {
	case "trojan", "hysteria", "hysteria2", "tuic", "anytls", "shadowquic", "masque", "trusttunnel":
		tls = true
	}
	security := ""
	if ro, ok := m["reality-opts"].(map[string]any); ok && len(ro) > 0 {
		security = "reality"
		tls = true
	} else if tls {
		security = "tls"
	}
	set("security", security)
	set("sni", firstNonEmpty(str(m["servername"]), str(m["sni"])))
	if a := strList(m["alpn"]); len(a) > 0 {
		out["alpn"] = strings.Join(a, ",")
	}
	set("fingerprint", str(m["client-fingerprint"]))
	if boolOf(m["skip-cert-verify"]) {
		out["skipCertVerify"] = true
	}
	set("cipher", str(m["cipher"]))
	set("flow", str(m["flow"]))
	set("plugin", str(m["plugin"]))
	if po, ok := m["plugin-opts"].(map[string]any); ok {
		set("pluginMode", str(po["mode"]))
		if v := intOf(po["version"]); v > 0 {
			out["pluginVersion"] = v
		}
	}
	set("obfs", str(m["obfs"]))
	set("protocolParam", str(m["protocol"]))
	set("congestion", firstNonEmpty(str(m["congestion-controller"]), str(m["congestion-control"])))
	set("dialerProxy", str(m["dialer-proxy"]))
	set("ipVersion", str(m["ip-version"]))
	if boolOf(m["tfo"]) {
		out["tfo"] = true
	}
	if boolOf(m["mptcp"]) {
		out["mptcp"] = true
	}
	if sm, ok := m["smux"].(map[string]any); ok && boolOf(sm["enabled"]) {
		out["smux"] = firstNonEmpty(str(sm["protocol"]), "smux")
	}
	if up := str(m["up"]); up != "" {
		out["up"] = up
	}
	if dn := str(m["down"]); dn != "" {
		out["down"] = dn
	}
	if _, ok := m["amnezia-wg-option"]; ok {
		out["amnezia"] = true
	}
	if typ == "tailscale" {
		ts := map[string]any{"ephemeral": boolOf(m["ephemeral"])}
		for _, k := range []string{"hostname", "control-url", "state-dir", "exit-node"} {
			if v := str(m[k]); v != "" {
				ts[k] = v
			}
		}
		for _, k := range []string{"accept-routes", "exit-node-allow-lan-access"} {
			if v, ok := m[k]; ok {
				ts[k] = boolOf(v)
			}
		}
		out["tailscale"] = ts
	}
	var creds []string
	for _, k := range credentialKeys {
		if v, ok := m[k]; ok && str(v) != "" {
			creds = append(creds, k)
		}
	}
	if typ == "wireguard" {
		if peers, ok := m["peers"].([]any); ok && len(peers) > 0 {
			out["peers"] = len(peers)
		}
	}
	creds = append(creds, nestedCredentialKeys(m)...)
	if creds == nil {
		creds = []string{}
	}
	out["credentials"] = creds
	_, err := ShareLinkFor(m)
	out["shareable"] = err == nil
	return out
}

// NodeSummary returns the summary JSON of a node of the profile (profile proxies first, then providers,
// node subscriptions included), or {"error": "…"}.
func NodeSummary(homeDir, profilePath, name string) string {
	defer func() { _ = recover() }()
	raw := runtimeRawWithHome(homeDir, profilePath)
	m, src, ok := findRuntimeNode(raw, name)
	if !ok {
		b, _ := json.Marshal(map[string]any{"error": "在当前配置里找不到这个节点"})
		return string(b)
	}
	b, _ := json.Marshal(nodeSummary(m, src))
	return string(b)
}

// NodeSummaryIn is NodeSummary for the node named name in one source (provider "" = the profile's own proxies,
// else that proxy-provider / node subscription). R7A-4; NodeSummary keeps the name-only lookup.
func NodeSummaryIn(homeDir, profilePath, provider, name string) string {
	defer func() { _ = recover() }()
	raw := runtimeRawWithHome(homeDir, profilePath)
	m, ok := findRuntimeNodeIn(raw, provider, name)
	if !ok {
		b, _ := json.Marshal(map[string]any{"error": "在当前配置里找不到这个节点"})
		return string(b)
	}
	b, _ := json.Marshal(nodeSummary(m, provider))
	return string(b)
}

// NodeConfigIn is NodeConfig for the node named name in one source (see NodeSummaryIn). "" when not found.
func NodeConfigIn(homeDir, profilePath, provider, name string) string {
	defer func() { _ = recover() }()
	raw := runtimeRawWithHome(homeDir, profilePath)
	m, ok := findRuntimeNodeIn(raw, provider, name)
	if !ok {
		return ""
	}
	b, err := json.Marshal(jsonSafe(m))
	if err != nil {
		return ""
	}
	return string(b)
}

// NodeTestDelayIn is NodeTestDelay for the node named name in one source (see NodeSummaryIn).
func NodeTestDelayIn(homeDir, profilePath, provider, name, url string, timeoutMs int) int {
	raw := cachedRuntimeRaw(homeDir, profilePath)
	m, ok := findRuntimeNodeIn(raw, provider, name)
	if !ok {
		setLastError("在当前配置里找不到这个节点")
		return -1
	}
	b, _ := json.Marshal(m)
	return TestDelay(string(b), url, timeoutMs)
}

// NodeConfig returns the full config of a node of the profile (any source, node subscriptions included) as a
// JSON object, secrets included, or "" when it is not found. For the node detail's 显示 / 复制 of a credential
// and 添加到本地节点; the result is never logged.
func NodeConfig(homeDir, profilePath, name string) string {
	defer func() { _ = recover() }()
	raw := runtimeRawWithHome(homeDir, profilePath)
	m, _, ok := findRuntimeNode(raw, name)
	if !ok {
		return ""
	}
	b, err := json.Marshal(jsonSafe(m))
	if err != nil {
		return ""
	}
	return string(b)
}

// NodeSummaryJSON is NodeSummary for a node given as JSON (manual nodes not merged into the profile).
func NodeSummaryJSON(nodeJSON string) string {
	m := map[string]any{}
	if err := json.Unmarshal([]byte(nodeJSON), &m); err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return string(b)
	}
	b, _ := json.Marshal(nodeSummary(m, ""))
	return string(b)
}

// NodeTestDelay tests one node of the profile by name without the tunnel (any source, node subscriptions
// included). Returns ms or -1 (LastError has why).
func NodeTestDelay(homeDir, profilePath, name, url string, timeoutMs int) int {
	raw := cachedRuntimeRaw(homeDir, profilePath)
	m, _, ok := findRuntimeNode(raw, name)
	if !ok {
		setLastError("在当前配置里找不到这个节点")
		return -1
	}
	b, _ := json.Marshal(m)
	return TestDelay(string(b), url, timeoutMs)
}

// rtCache (selftest fix): 全部测速 in 节点管理 calls NodeTestDelay once per node, 8 at a time, and every call
// built the whole runtime (profile parse, manual merge, node subscriptions, group edits, sub rules) again —
// N full config builds for N nodes in the memory-capped app process. One build is now shared for 30 s as
// long as the inputs (profile, overrides, manual nodes, node subscription list, subscription rules,
// group chains, group edits, DNS override, local DNS, custom rules) are unchanged; concurrent
// callers wait for the one build instead of each starting their own. The map is only read afterwards.
var rtCache struct {
	sync.Mutex
	key string
	at  time.Time
	raw map[string]any
}

const rtCacheTTL = 30 * time.Second

func runtimeCacheKey(homeDir, profilePath string) string {
	parts := []string{homeDir, profilePath}
	for _, p := range []string{
		profilePath,
		filepath.Join(homeDir, "overrides.json"),
		filepath.Join(filepath.Dir(homeDir), "profiles", "manual-nodes.yaml"),
		nodeSubsPath(homeDir),
		// overridesFor also merges these into the runtime (sub rules + group chains)
		filepath.Join(homeDir, "subscriptions.json"),
		filepath.Join(homeDir, "groups.json"),
		// buildRuntimeWith applies 策略组编辑 (group-edits.json) too
		groupEditsPath(homeDir),
		// readOverrides loads the DNS settings page files; applyCustomRules reads rules.json
		filepath.Join(homeDir, "dns.json"),
		filepath.Join(homeDir, "localdns.json"),
		filepath.Join(homeDir, "rules.json"),
	} {
		parts = append(parts, statSig(p))
	}
	// v0.19.10: the 覆写脚本 output readRuntimeProfile prefers.
	yp, mp := scriptedPaths(homeDir, profilePath)
	for _, p := range []string{yp, mp} {
		parts = append(parts, statSig(p))
	}
	return strings.Join(parts, "|")
}

func statSig(p string) string {
	if fi, err := os.Stat(p); err == nil {
		return fmt.Sprintf("%d.%d", fi.Size(), fi.ModTime().UnixNano())
	}
	return "-"
}

func cachedRuntimeRaw(homeDir, profilePath string) map[string]any {
	key := runtimeCacheKey(homeDir, profilePath)
	rtCache.Lock()
	defer rtCache.Unlock()
	if rtCache.raw != nil && rtCache.key == key && time.Since(rtCache.at) < rtCacheTTL {
		return rtCache.raw
	}
	raw := runtimeRawWithHome(homeDir, profilePath)
	rtCache.key, rtCache.at, rtCache.raw = key, time.Now(), raw
	return raw
}

// resetRuntimeCache drops the shared runtime (tests).
func resetRuntimeCache() {
	rtCache.Lock()
	rtCache.raw = nil
	rtCache.Unlock()
}
