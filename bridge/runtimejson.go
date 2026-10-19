package libmihomo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"go.yaml.in/yaml/v3"
)

// v0.19.6 (review 7): yaml.v3's encoder is the most memory-hungry step of a start. Measured under a 36 MB
// GOMEMLIMIT (the extension runs with ~3/4 of its ~50 MB budget): yaml.Marshal of the runtime config of a
// 5k-node / 20k-rule profile peaked at +58 MB live heap (buildRuntime +63 MB), the same map as JSON at
// +8 MB; a 5k-node share-link 节点订阅 converted by /nodes/convert peaked at +60 MB. Either was enough to
// get the extension killed by jetsam with a big profile / subscription. JSON is YAML (flow style), so the
// core parses it unchanged (TestV0196LargeRuntimeIsJSONAndEquivalent). Small configs stay block YAML
// (readable runtime.yaml, unchanged behaviour); large ones are written as JSON.
const runtimeJSONThreshold = 256 << 10

// runtimeJSONItems: proxies + groups + rules from which the config is written as JSON whatever the profile's
// size (node subscriptions and manual nodes are merged into a small profile).
const runtimeJSONItems = 3000

func configItems(raw map[string]any) int {
	return len(asList(raw["proxies"])) + len(asList(raw["proxy-groups"])) + len(asList(raw["rules"]))
}

var errNotJSONable = errors.New("value not representable as JSON")

// marshalConfig writes v as JSON when big is true and every value is representable, else as YAML.
func marshalConfig(v any, big bool) ([]byte, error) {
	if big {
		if j, err := toJSONable(v, 0); err == nil {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(j); err == nil {
				return buf.Bytes(), nil
			}
		}
	}
	return yaml.Marshal(v)
}

// toJSONable converts the decoded-YAML tree into values encoding/json writes the way yaml.Marshal would:
// maps with string keys (sorted, like yaml.v3), ordered mappings (*yaml.Node, the nameserver-policy order)
// kept in order. Anything else (non-string map keys, NaN / Inf, unknown types) is refused, and the caller
// falls back to yaml.Marshal.
func toJSONable(v any, depth int) (any, error) {
	if depth > 200 {
		return nil, errNotJSONable
	}
	switch t := v.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return t, nil
	case float32:
		if math.IsNaN(float64(t)) || math.IsInf(float64(t), 0) {
			return nil, errNotJSONable
		}
		return t, nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil, errNotJSONable
		}
		return t, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			c, err := toJSONable(x, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, errNotJSONable
			}
			c, err := toJSONable(x, depth+1)
			if err != nil {
				return nil, err
			}
			out[ks] = c
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			c, err := toJSONable(x, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(t))
		for i, x := range t {
			c, err := toJSONable(x, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case []string:
		return t, nil
	case orderedJSONObject:
		vals := make(map[string]any, len(t.vals))
		for _, k := range t.keys {
			c, err := toJSONable(t.vals[k], depth+1)
			if err != nil {
				return nil, err
			}
			vals[k] = c
		}
		return orderedJSONObject{keys: t.keys, vals: vals}, nil
	case *yaml.Node:
		return yamlNodeJSONable(t, depth)
	case yaml.Node:
		return yamlNodeJSONable(&t, depth)
	}
	return nil, fmt.Errorf("%w: %T", errNotJSONable, v)
}

// yamlNodeJSONable: a mapping node keeps its key order (orderedJSONObject); anything else is decoded.
func yamlNodeJSONable(n *yaml.Node, depth int) (any, error) {
	if n == nil {
		return nil, nil
	}
	if n.Kind != yaml.MappingNode {
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return toJSONable(v, depth+1)
	}
	o := orderedJSONObject{vals: map[string]any{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Kind != yaml.ScalarNode {
			return nil, errNotJSONable
		}
		var v any
		if err := n.Content[i+1].Decode(&v); err != nil {
			return nil, err
		}
		c, err := toJSONable(v, depth+1)
		if err != nil {
			return nil, err
		}
		if _, dup := o.vals[k.Value]; !dup {
			o.keys = append(o.keys, k.Value)
		}
		o.vals[k.Value] = c
	}
	return o, nil
}

// marshalProxiesYAML writes {"proxies": list} for a proxy provider: one JSON flow mapping per line (valid
// YAML, a few KB of heap however many nodes), falling back to yaml.Marshal for values JSON cannot carry.
func marshalProxiesYAML(list []map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("proxies:\n")
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, p := range list {
		j, err := toJSONable(p, 0)
		if err != nil {
			return yaml.Marshal(map[string]any{"proxies": list})
		}
		buf.WriteString("  - ")
		if err := enc.Encode(j); err != nil { // Encode ends the line
			return yaml.Marshal(map[string]any{"proxies": list})
		}
	}
	if len(list) == 0 {
		return []byte("proxies: []\n"), nil
	}
	return buf.Bytes(), nil
}
