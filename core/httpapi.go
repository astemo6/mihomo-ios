package libmihomo

// Minimal Surge $httpAPI for scripts: policy query / switch, outbound mode, profile reload.
// Anything else answers {"error": "…"} and is logged, so scripts fail visibly instead of hanging.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// HTTPAPISupported lists the $httpAPI endpoints scripts can use (shown in the README / app).
var HTTPAPISupported = []string{
	"GET /v1/policies",
	"GET /v1/policy_groups",
	"GET /v1/policy_groups/select?group_name=…",
	"POST /v1/policy_groups/select {group_name, policy}",
	"GET /v1/outbound",
	"POST /v1/outbound {mode: direct|proxy|rule}",
	"GET /v1/profiles/current",
	"POST /v1/profiles/reload",
}

func bodyField(body any, key string) string {
	if m, ok := body.(map[string]any); ok {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func isGroup(p C.Proxy) bool {
	_, ok := p.Adapter().(outboundgroup.ProxyGroup)
	return ok
}

func surgeMode(m tunnel.TunnelMode) string {
	switch m {
	case tunnel.Global:
		return "proxy"
	case tunnel.Direct:
		return "direct"
	}
	return "rule"
}

// httpAPI implements mitm.APIFunc.
func httpAPI(method, rawPath string, body any) (any, error) {
	u, err := url.Parse(rawPath)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSuffix(u.Path, "/")
	proxies := tunnel.Proxies()
	switch {
	case method == "GET" && path == "/v1/policies":
		var nodes, groups []string
		for name, p := range proxies {
			if strings.HasPrefix(name, "__") {
				continue
			}
			if isGroup(p) {
				groups = append(groups, name)
			} else {
				nodes = append(nodes, name)
			}
		}
		return map[string]any{"proxies": nodes, "policy-groups": groups}, nil

	case method == "GET" && path == "/v1/policy_groups":
		out := map[string]any{}
		for name, p := range proxies {
			g, ok := p.Adapter().(outboundgroup.ProxyGroup)
			if !ok || strings.HasPrefix(name, "__") {
				continue
			}
			var members []any
			for _, m := range g.Proxies() {
				members = append(members, map[string]any{"name": m.Name(), "typeDescription": m.Type().String(),
					"isGroup": isGroup(m), "enabled": true})
			}
			out[name] = members
		}
		return out, nil

	case method == "GET" && path == "/v1/policy_groups/select":
		name := u.Query().Get("group_name")
		p, ok := proxies[name]
		if !ok {
			return nil, fmt.Errorf("策略组 %s 不存在", name)
		}
		g, ok := p.Adapter().(outboundgroup.ProxyGroup)
		if !ok {
			return nil, fmt.Errorf("%s 不是策略组", name)
		}
		return map[string]any{"policy": g.Now()}, nil

	case method == "POST" && path == "/v1/policy_groups/select":
		name, pol := bodyField(body, "group_name"), bodyField(body, "policy")
		p, ok := proxies[name]
		if !ok {
			return nil, fmt.Errorf("策略组 %s 不存在", name)
		}
		s, ok := p.Adapter().(outboundgroup.SelectAble)
		if !ok {
			return nil, fmt.Errorf("策略组 %s 不能手动选择", name)
		}
		if err := s.Set(pol); err != nil {
			return nil, err
		}
		log.Infoln("[Script] $httpAPI: %s → %s", name, pol)
		return map[string]any{}, nil

	case method == "GET" && path == "/v1/outbound":
		return map[string]any{"mode": surgeMode(tunnel.Mode())}, nil

	case method == "POST" && path == "/v1/outbound":
		switch strings.ToLower(bodyField(body, "mode")) {
		case "direct":
			tunnel.SetMode(tunnel.Direct)
		case "proxy", "global":
			tunnel.SetMode(tunnel.Global)
		case "rule":
			tunnel.SetMode(tunnel.Rule)
		default:
			return nil, errors.New("mode 只能是 direct / proxy / rule")
		}
		return map[string]any{}, nil

	case method == "GET" && path == "/v1/profiles/current":
		return map[string]any{"name": profileIDFromPath(C.Path.Config())}, nil

	case method == "POST" && path == "/v1/profiles/reload":
		cfg := C.Path.Config()
		go func() {
			if err := Reload(cfg); err != nil {
				log.Warnln("[Script] $httpAPI reload: %v", err)
			}
		}()
		return map[string]any{}, nil
	}
	return nil, fmt.Errorf("不支持的 $httpAPI：%s %s（支持：%s）", method, path, strings.Join(HTTPAPISupported, "；"))
}
