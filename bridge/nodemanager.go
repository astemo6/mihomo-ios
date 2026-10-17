package libmihomo

// 节点管理 (v0.16): one node's summary without secrets, and an offline delay test that also finds nodes of
// node subscriptions (profileRaw builds the runtime without the app home, so TestDelayByName only sees the
// profile's own providers). Both build the runtime exactly like InspectProfile.

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// runtimeRawWithHome is the runtime map InspectProfile reads (manual merge, node subscriptions, group edits).
func runtimeRawWithHome(homeDir, profilePath string) map[string]any {
	raw := map[string]any{}
	C.SetHomeDir(homeDir)
	b, err := os.ReadFile(profilePath)
	if err != nil {
		lastError = err.Error()
		return raw
	}
	rt, err := buildRuntime(b, overridesFor(homeDir, profilePath), 0)
	if err != nil {
		lastError = err.Error()
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

// credentialKeys are the secrets a node may carry; the summary only says which ones are set.
var credentialKeys = []string{"password", "uuid", "username", "private-key", "pre-shared-key", "public-key", "psk",
	"auth", "auth-str", "auth_str", "token", "obfs-password", "private-key-passphrase", "short-id"}

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
	raw := runtimeRawWithHome(homeDir, profilePath)
	m, _, ok := findRuntimeNode(raw, name)
	if !ok {
		lastError = "在当前配置里找不到这个节点"
		return -1
	}
	b, _ := json.Marshal(m)
	return TestDelay(string(b), url, timeoutMs)
}
