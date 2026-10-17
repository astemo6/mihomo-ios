package libmihomo

// SIP008: Shadowsocks online configuration (https://shadowsocks.org/doc/sip008.html).
//
//	{"version":1,"servers":[{"id":"…","remarks":"…","server":"…","server_port":8388,
//	  "password":"…","method":"…","plugin":"…","plugin_opts":"…"}], …}
//
// Each server becomes a mihomo `ss` proxy. SIP003 plugins obfs-local / simple-obfs map to
// mihomo's `obfs` plugin and v2ray-plugin to `v2ray-plugin` (websocket mode only, as in mihomo).

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type sip008Server struct {
	ID         string          `json:"id"`
	Remarks    string          `json:"remarks"`
	Server     string          `json:"server"`
	ServerPort json.RawMessage `json:"server_port"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	Plugin     string          `json:"plugin"`
	PluginOpts string          `json:"plugin_opts"`
}

type sip008Doc struct {
	Version *json.Number    `json:"version"`
	Servers *[]sip008Server `json:"servers"`
}

// parseSIP008 reports ok=false when text is not a SIP008 document (so other parsers can try it).
// Accepts the standard object form and, leniently, a bare array of server objects.
func parseSIP008(text string) (out []map[string]any, errs []string, ok bool) {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return nil, nil, false
	}
	var servers []sip008Server
	if t[0] == '{' {
		var doc sip008Doc
		if json.Unmarshal([]byte(t), &doc) != nil || doc.Servers == nil {
			return nil, nil, false
		}
		servers = *doc.Servers
	} else {
		if json.Unmarshal([]byte(t), &servers) != nil || len(servers) == 0 {
			return nil, nil, false
		}
		for _, s := range servers {
			if s.Server == "" || s.Method == "" {
				return nil, nil, false
			}
		}
	}
	for i, s := range servers {
		p, err := sip008Proxy(s)
		if err != nil {
			errs = append(errs, fmt.Sprintf("SIP008 #%d: %v", i+1, err))
			continue
		}
		out = append(out, p)
	}
	return out, errs, true
}

// looksSIP008 is the cheap check ClassifyText uses before the YAML / module heuristics.
func looksSIP008(text string) bool {
	ps, _, ok := parseSIP008(text)
	return ok && len(ps) > 0
}

func sip008Port(raw json.RawMessage) (int, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || s == "null" {
		return 0, fmt.Errorf("缺少 server_port")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("server_port 无效: %s", s)
	}
	return n, nil
}

func sip008Proxy(s sip008Server) (map[string]any, error) {
	if s.Server == "" {
		return nil, fmt.Errorf("缺少 server")
	}
	port, err := sip008Port(s.ServerPort)
	if err != nil {
		return nil, err
	}
	if s.Method == "" {
		return nil, fmt.Errorf("缺少 method")
	}
	name := firstNonEmpty(strings.TrimSpace(s.Remarks), strings.TrimSpace(s.ID), fmt.Sprintf("ss %s:%d", s.Server, port))
	p := map[string]any{
		"name":     name,
		"type":     "ss",
		"server":   s.Server,
		"port":     port,
		"cipher":   strings.ToLower(s.Method),
		"password": s.Password,
		"udp":      true,
	}
	if s.Plugin == "" {
		return p, nil
	}
	plugin, opts, err := sip003Plugin(s.Plugin, s.PluginOpts)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	p["plugin"] = plugin
	p["plugin-opts"] = opts
	return p, nil
}

// sip003Opts splits a SIP003 plugin_opts string ("k=v;flag;k2=v2"); "\;" "\=" "\\" are escapes.
func sip003Opts(s string) map[string]string {
	out := map[string]string{}
	var key, cur strings.Builder
	inVal := false
	flush := func() {
		k := strings.TrimSpace(key.String())
		v := cur.String()
		if !inVal {
			k, v = strings.TrimSpace(cur.String()), ""
		}
		if k != "" {
			out[k] = strings.TrimSpace(v)
		}
		key.Reset()
		cur.Reset()
		inVal = false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == '=' && !inVal:
			key.WriteString(cur.String())
			cur.Reset()
			inVal = true
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func sip003Plugin(name, optStr string) (string, map[string]any, error) {
	kv := sip003Opts(optStr)
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "obfs-local", "simple-obfs", "obfs":
		mode := strings.ToLower(firstNonEmpty(kv["obfs"], kv["mode"], "http"))
		if mode != "http" && mode != "tls" {
			return "", nil, fmt.Errorf("不支持的 obfs 模式 %q", mode)
		}
		opts := map[string]any{"mode": mode}
		if h := kv["obfs-host"]; h != "" {
			opts["host"] = h
		}
		return "obfs", opts, nil
	case "v2ray-plugin", "v2ray":
		mode := strings.ToLower(firstNonEmpty(kv["mode"], "websocket"))
		if mode != "websocket" {
			return "", nil, fmt.Errorf("v2ray-plugin 模式 %q 不受 mihomo 支持（仅 websocket）", mode)
		}
		opts := map[string]any{"mode": "websocket"}
		if _, ok := kv["tls"]; ok && kv["tls"] != "false" && kv["tls"] != "0" {
			opts["tls"] = true
		}
		if h := kv["host"]; h != "" {
			opts["host"] = h
		}
		opts["path"] = firstNonEmpty(kv["path"], "/")
		if v, ok := kv["mux"]; ok {
			opts["mux"] = v != "0" && v != "false"
		}
		if v, ok := kv["skip-cert-verify"]; ok && truthy(firstNonEmpty(v, "true")) {
			opts["skip-cert-verify"] = true
		}
		return "v2ray-plugin", opts, nil
	}
	return "", nil, fmt.Errorf("不支持的插件 %q", name)
}
