package libmihomo

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// FinalConfigReadable is FinalConfig rendered for people (feat/export-readable, 「导出最终配置（含覆写）」): the same
// runtime config (buildRuntime, then the portable-export clean-up of stripAppInternalsFor), written as block YAML
// in mihomo's conventional order — general keys, cache / GEO data, sniffer, tun, dns, hosts, proxies,
// proxy-providers, proxy-groups, rule-providers, rules, then everything else alphabetically — with a short file
// header and one Chinese comment per section. Keys inside known objects (nodes, groups, providers, dns, tun,
// sniffer) follow mihomo's documented order; everything else keeps the runtime order (nameserver-policy order
// is significant and survives, unlike the map round trip of FinalConfig).
//
// Export only: the runtime.yaml the tunnel loads is still written by buildRuntime / marshalConfig, lean and
// without comments. Memory: the runtime config is decoded once into a yaml.Node tree (yaml.v3 builds that tree
// for any Unmarshal anyway) and written section by section; long lists are encoded in chunks with one item per
// line, so no second full copy of the config is ever built besides the output text.
func FinalConfigReadable(homeDir, path, profileName, appVersion string) (string, error) {
	profile, err := readRuntimeProfile(homeDir, path, false)
	if err != nil {
		return "", fmt.Errorf("读取配置失败: %w", err)
	}
	C.SetHomeDir(homeDir)
	o := overridesFor(homeDir, path)
	rt, err := buildRuntime(profile, o, 0)
	profile = nil
	if err != nil {
		return "", err
	}
	return renderReadable(rt, homeDir, o.Secret, exportMeta{Profile: profileName, Version: appVersion, Time: time.Now()})
}

type exportMeta struct {
	Profile, Version string
	Time             time.Time
}

// readableFlowThreshold: from this many nodes on, each node is written on one line in flow style.
const readableFlowThreshold = 50

// readableGroupFlowMembers: a group's member list longer than this is written on one line.
const readableGroupFlowMembers = 20

// readableChunk: list items encoded per yaml.Encoder call (bounds the encoder's working buffer).
const readableChunk = 256

// Top-level order. Keys not listed go last, alphabetically.
var readableGeneralKeys = []string{
	"port", "socks-port", "redir-port", "tproxy-port", "mixed-port", "allow-lan", "bind-address", "lan-allowed-ips",
	"lan-disallowed-ips", "authentication", "skip-auth-prefixes", "mode", "log-level", "ipv6", "unified-delay",
	"tcp-concurrent", "find-process-mode", "global-client-fingerprint", "keep-alive-interval", "keep-alive-idle",
	"disable-keep-alive", "interface-name", "routing-mark", "external-controller", "external-controller-tls",
	"external-controller-unix", "external-controller-cors", "external-ui", "external-ui-name", "external-ui-url",
	"secret", "global-ua", "etag-support",
}

var readableGeoKeys = []string{"profile", "geodata-mode", "geodata-loader", "geosite-matcher", "geo-auto-update",
	"geo-update-interval", "geox-url"}

type readableSection struct {
	keys    []string
	comment func(n *yaml.Node) string // n: the value of the section's (first) key
}

func countOf(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	switch n.Kind {
	case yaml.SequenceNode:
		return len(n.Content)
	case yaml.MappingNode:
		return len(n.Content) / 2
	}
	return 0
}

var readableSections = []readableSection{
	{readableGeneralKeys, func(*yaml.Node) string { return "通用设置" }},
	{readableGeoKeys, func(*yaml.Node) string { return "缓存与 GEO 数据库" }},
	{[]string{"sniffer"}, func(*yaml.Node) string { return "域名嗅探" }},
	{[]string{"tun"}, func(*yaml.Node) string { return "TUN" }},
	{[]string{"dns"}, func(*yaml.Node) string { return "DNS 设置" }},
	{[]string{"hosts"}, func(*yaml.Node) string { return "Hosts" }},
	{[]string{"proxies"}, func(n *yaml.Node) string { return fmt.Sprintf("节点（共 %d 个）", countOf(n)) }},
	{[]string{"proxy-providers"}, func(n *yaml.Node) string { return fmt.Sprintf("节点集（共 %d 个）", countOf(n)) }},
	{[]string{"proxy-groups"}, func(n *yaml.Node) string { return fmt.Sprintf("策略组（共 %d 个）", countOf(n)) }},
	{[]string{"rule-providers"}, func(n *yaml.Node) string { return fmt.Sprintf("规则集（共 %d 个）", countOf(n)) }},
	{[]string{"rules"}, func(n *yaml.Node) string {
		return fmt.Sprintf("规则（共 %d 条，按顺序匹配，越靠前优先级越高）", countOf(n))
	}},
}

// Key order inside known objects (mihomo docs / config.yaml example). Keys not listed keep their order after these.
var (
	orderProxy = []string{"name", "type", "server", "port", "ports", "cipher", "password", "username", "uuid", "alterId",
		"auth-str", "auth", "obfs", "obfs-password", "obfs-param", "protocol", "protocol-param", "plugin", "plugin-opts",
		"flow", "network", "tls", "udp", "udp-over-tcp", "sni", "servername", "skip-cert-verify", "fingerprint",
		"client-fingerprint", "alpn", "up", "down", "reality-opts", "ws-opts", "h2-opts", "http-opts", "grpc-opts",
		"smux", "dialer-proxy", "interface-name", "routing-mark", "ip-version", "tfo", "mptcp"}
	orderGroup = []string{"name", "type", "proxies", "use", "url", "interval", "tolerance", "lazy", "timeout",
		"max-failed-times", "strategy", "disable-udp", "interface-name", "routing-mark", "include-all",
		"include-all-proxies", "include-all-providers", "filter", "exclude-filter", "exclude-type", "expected-status",
		"hidden", "icon"}
	orderProxyProvider = []string{"type", "url", "path", "interval", "proxy", "size-limit", "header", "health-check",
		"override", "filter", "exclude-filter", "exclude-type", "payload"}
	orderHealthCheck  = []string{"enable", "url", "interval", "timeout", "lazy", "expected-status"}
	orderRuleProvider = []string{"type", "behavior", "format", "url", "path", "interval", "proxy", "size-limit", "payload"}
	orderDNS          = []string{"enable", "cache-algorithm", "prefer-h3", "listen", "ipv6", "ipv6-timeout", "use-hosts",
		"use-system-hosts", "respect-rules", "enhanced-mode", "fake-ip-range", "fake-ip-range6", "fake-ip-filter-mode",
		"fake-ip-filter", "fake-ip-ttl", "default-nameserver", "nameserver-policy", "nameserver",
		"proxy-server-nameserver", "proxy-server-nameserver-policy", "direct-nameserver",
		"direct-nameserver-follow-policy", "fallback", "fallback-filter"}
	orderFallbackFilter = []string{"geoip", "geoip-code", "geosite", "ipcidr", "domain"}
	orderTun            = []string{"enable", "stack", "device", "dns-mode", "dns-hijack", "auto-route", "auto-redirect",
		"auto-detect-interface", "strict-route", "mtu", "gso", "gso-max-size", "udp-timeout", "file-descriptor",
		"inet4-address", "inet6-address", "route-address", "route-exclude-address", "route-address-set",
		"route-exclude-address-set", "include-interface", "exclude-interface", "endpoint-independent-nat"}
	orderSniffer = []string{"enable", "force-dns-mapping", "parse-pure-ip", "override-destination", "sniff",
		"force-domain", "skip-domain", "skip-src-address", "skip-dst-address"}
	orderProfile = []string{"store-selected", "store-fake-ip"}
	orderGeoxURL = []string{"geoip", "geosite", "mmdb", "asn"}
)

// renderReadable turns the runtime config rt into the human-readable export.
func renderReadable(rt []byte, home, secret string, meta exportMeta) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(rt, &doc); err != nil {
		return "", err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("配置内容为空")
	}
	root := doc.Content[0]
	notes, err := stripAppInternalsNode(root, home, secret)
	if err != nil {
		return "", err
	}
	plainStyles(root)
	orderKnown(root)

	var out bytes.Buffer
	out.Grow(len(rt) + len(rt)/4)
	writeReadableHeader(&out, meta, notes)

	// Index the top-level pairs; each is written exactly once.
	idx := make(map[string]int, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		idx[root.Content[i].Value] = i
	}
	done := make(map[string]bool, len(idx))
	for _, sec := range readableSections {
		var pairs []int
		for _, k := range sec.keys {
			if i, ok := idx[k]; ok && !done[k] {
				pairs = append(pairs, i)
				done[k] = true
			}
		}
		if len(pairs) == 0 {
			continue
		}
		writeSectionComment(&out, sec.comment(root.Content[pairs[0]+1]))
		for _, i := range pairs {
			if err := writePair(&out, root.Content[i], root.Content[i+1]); err != nil {
				return "", err
			}
		}
	}
	var rest []string
	for k := range idx {
		if !done[k] {
			rest = append(rest, k)
		}
	}
	if len(rest) > 0 {
		sort.Strings(rest)
		writeSectionComment(&out, "其他设置")
		for _, k := range rest {
			i := idx[k]
			if err := writePair(&out, root.Content[i], root.Content[i+1]); err != nil {
				return "", err
			}
		}
	}
	text := out.String()
	if secret != "" && strings.Contains(text, secret) {
		text = strings.ReplaceAll(text, secret, "<redacted>")
	}
	return text, nil
}

func writeSectionComment(out *bytes.Buffer, title string) {
	sep := " "
	if strings.HasSuffix(title, "）") {
		sep = ""
	}
	out.WriteString("\n# ===== " + title + sep + "=====\n")
}

// yaml11Bools are plain words YAML 1.1 parsers (other Clash clients) read as booleans; strings spelled like
// this stay quoted so the export means the same everywhere.
var yaml11Bools = map[string]bool{"y": true, "n": true, "yes": true, "no": true, "on": true, "off": true}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), " ")
}

func writeReadableHeader(out *bytes.Buffer, meta exportMeta, notes []string) {
	out.WriteString("# Tern 导出的最终配置（mihomo 格式）\n")
	if v := oneLine(meta.Version); v != "" {
		out.WriteString("# Tern 版本：" + v + "\n")
	}
	if p := oneLine(meta.Profile); p != "" {
		out.WriteString("# 配置：" + p + "\n")
	}
	if !meta.Time.IsZero() {
		out.WriteString("# 导出时间：" + meta.Time.Format("2006-01-02 15:04:05 -07:00") + "\n")
	}
	out.WriteString("# 内容即内核运行的配置：已包含覆写脚本、节点处理、节点订阅、对节点的修改和 App 内的内核设置；\n")
	out.WriteString("# 不含模块 / MitM，App 内部使用的控制器地址、密钥和探测用策略组已移除。节点凭据与原配置相同，请勿随意分享。\n")
	out.WriteString("# 以 # 开头的注释只为方便阅读，内核不读取。\n")
	if len(notes) > 0 {
		out.WriteString("#\n# 导出说明 / Export notes:\n")
		for _, n := range notes {
			out.WriteString("#   - " + oneLine(n) + "\n")
		}
	}
}

// writePair writes one top-level `key: value`. Sequences are written item by item in chunks; node lists from
// readableFlowThreshold on put each node on one line.
func writePair(out *bytes.Buffer, k, v *yaml.Node) error {
	if v.Kind == yaml.SequenceNode && len(v.Content) > 0 {
		var kb bytes.Buffer
		if err := encodeTo(&kb, k, ""); err != nil {
			return err
		}
		out.Write(bytes.TrimRight(kb.Bytes(), "\n"))
		out.WriteString(":\n")
		flow := k.Value == "proxies" && len(v.Content) >= readableFlowThreshold
		for start := 0; start < len(v.Content); start += readableChunk {
			end := start + readableChunk
			if end > len(v.Content) {
				end = len(v.Content)
			}
			items := v.Content[start:end]
			if flow {
				for _, it := range items {
					if it.Kind == yaml.MappingNode || it.Kind == yaml.SequenceNode {
						setFlow(it)
					}
				}
			}
			if err := encodeTo(out, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items}, "  "); err != nil {
				return err
			}
			for _, it := range items {
				it.Content = nil // done with it; let the GC take the subtree while later chunks are written
			}
		}
		return nil
	}
	err := encodeTo(out, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{k, v}}, "")
	v.Content = nil
	return err
}

// encodeTo encodes n with a 2-space indent and appends it to out, every non-empty line prefixed with indent.
func encodeTo(out *bytes.Buffer, n *yaml.Node, indent string) error {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if indent == "" {
		out.Write(b.Bytes())
		return nil
	}
	data := b.Bytes()
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		line := data
		if i >= 0 {
			line = data[:i+1]
		}
		if len(bytes.TrimRight(line, "\n")) > 0 {
			out.WriteString(indent)
		}
		out.Write(line)
		data = data[len(line):]
	}
	return nil
}

func setFlow(n *yaml.Node) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		n.Style = yaml.FlowStyle
	}
}

// plainStyles drops presentation styles from the decoded tree (the runtime config may be JSON: flow mappings and
// double-quoted strings everywhere). The encoder re-quotes any string that would otherwise read as another type
// and picks a literal block for multi-line strings.
func plainStyles(n *yaml.Node) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		n.Style &^= yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle | yaml.FlowStyle
		if (n.Tag == "!!str" || n.Tag == "") && yaml11Bools[strings.ToLower(n.Value)] {
			n.Style = yaml.DoubleQuotedStyle
		}
	case yaml.MappingNode, yaml.SequenceNode:
		n.Style &^= yaml.FlowStyle
		for _, c := range n.Content {
			plainStyles(c)
		}
	case yaml.DocumentNode:
		for _, c := range n.Content {
			plainStyles(c)
		}
	}
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
}

func child(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func deleteKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// orderKeys reorders a mapping's pairs: keys in pref first (in pref order), then the rest in their current order.
func orderKeys(m *yaml.Node, pref []string) {
	if m == nil || m.Kind != yaml.MappingNode || len(m.Content) < 4 {
		return
	}
	rank := func(k string) int {
		for i, p := range pref {
			if p == k {
				return i
			}
		}
		return len(pref)
	}
	n := len(m.Content) / 2
	pairs := make([][2]*yaml.Node, n)
	for i := 0; i < n; i++ {
		pairs[i] = [2]*yaml.Node{m.Content[2*i], m.Content[2*i+1]}
	}
	sort.SliceStable(pairs, func(a, b int) bool { return rank(pairs[a][0].Value) < rank(pairs[b][0].Value) })
	for i, p := range pairs {
		m.Content[2*i], m.Content[2*i+1] = p[0], p[1]
	}
}

func eachItem(seq *yaml.Node, f func(*yaml.Node)) {
	if seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			f(it)
		}
	}
}

func eachValue(m *yaml.Node, f func(*yaml.Node)) {
	if m != nil && m.Kind == yaml.MappingNode {
		for i := 1; i < len(m.Content); i += 2 {
			f(m.Content[i])
		}
	}
}

func orderProxyNode(p *yaml.Node) {
	orderKeys(p, orderProxy)
	orderKeys(child(p, "ws-opts"), []string{"path", "headers", "max-early-data", "early-data-header-name"})
	orderKeys(child(p, "reality-opts"), []string{"public-key", "short-id"})
}

// orderKnown applies the documented key order to the objects mihomo documents.
func orderKnown(root *yaml.Node) {
	eachItem(child(root, "proxies"), orderProxyNode)
	eachItem(child(root, "proxy-groups"), func(g *yaml.Node) {
		orderKeys(g, orderGroup)
		if ps := child(g, "proxies"); ps != nil && ps.Kind == yaml.SequenceNode && len(ps.Content) > readableGroupFlowMembers {
			ps.Style = yaml.FlowStyle
		}
		if us := child(g, "use"); us != nil && us.Kind == yaml.SequenceNode && len(us.Content) > readableGroupFlowMembers {
			us.Style = yaml.FlowStyle
		}
	})
	eachValue(child(root, "proxy-providers"), func(p *yaml.Node) {
		orderKeys(p, orderProxyProvider)
		orderKeys(child(p, "health-check"), orderHealthCheck)
		eachItem(child(p, "payload"), func(n *yaml.Node) { orderProxyNode(n); setFlow(n) })
	})
	eachValue(child(root, "rule-providers"), func(p *yaml.Node) { orderKeys(p, orderRuleProvider) })
	dns := child(root, "dns")
	orderKeys(dns, orderDNS)
	orderKeys(child(dns, "fallback-filter"), orderFallbackFilter)
	orderKeys(child(root, "tun"), orderTun)
	orderKeys(child(root, "sniffer"), orderSniffer)
	orderKeys(child(root, "profile"), orderProfile)
	orderKeys(child(root, "geox-url"), orderGeoxURL)
}

// stripAppInternalsNode is stripAppInternalsFor on the node tree (same removals, same provider clean-up, same
// notes), so mapping order survives.
func stripAppInternalsNode(root *yaml.Node, home, secret string) ([]string, error) {
	deleteKey(root, "secret")
	deleteKey(root, "external-controller")
	filterByName := func(key, drop string) {
		seq := child(root, key)
		if seq == nil || seq.Kind != yaml.SequenceNode {
			return
		}
		kept := seq.Content[:0]
		for _, it := range seq.Content {
			if n := child(it, "name"); n != nil && n.Value == drop {
				continue
			}
			kept = append(kept, it)
		}
		seq.Content = kept
	}
	filterByName("proxy-groups", ProbeGroup)
	if ls := child(root, "listeners"); ls != nil {
		filterByName("listeners", probeListener)
		if ls.Kind == yaml.SequenceNode && len(ls.Content) == 0 {
			deleteKey(root, "listeners")
		}
	}
	// Providers: run the shared map-based clean-up on just these two (small) sections, then put them back in
	// their original order.
	var notes []string
	for _, key := range []string{"proxy-providers", "rule-providers"} {
		pn := child(root, key)
		if pn == nil || pn.Kind != yaml.MappingNode {
			continue
		}
		var order []string
		for i := 0; i < len(pn.Content); i += 2 {
			order = append(order, pn.Content[i].Value)
		}
		var m map[string]any
		if err := pn.Decode(&m); err != nil {
			return nil, err
		}
		notes = append(notes, portableProviders(map[string]any{key: m}, home, secret)...)
		pn.Content = pn.Content[:0]
		for _, name := range order {
			v, ok := m[name]
			if !ok {
				continue
			}
			var vn yaml.Node
			if err := vn.Encode(v); err != nil {
				return nil, err
			}
			pn.Content = append(pn.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, &vn)
		}
	}
	return notes, nil
}
