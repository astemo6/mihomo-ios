package libmihomo

// Native-core transition export (2026-10-24, docs/native-core-design.md): the native
// Swift core consumes the same runtime config the Go core runs, but as JSON — Swift
// has no YAML parser and JSON is a YAML subset, so this is a pure re-encode of the
// runtime.yaml buildRuntime already wrote for the current profile. Read-only: it
// never builds or applies a config, and it is only meaningful after a Start/Reload
// has produced runtime.yaml.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// NativeConfigJSON returns the current runtime config (home/runtime.yaml) as JSON.
func NativeConfigJSON(homeDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(homeDir, "runtime.yaml"))
	if err != nil {
		return "", err
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return "", err
	}
	v, err := toJSONable(raw, 0)
	if err != nil {
		return "", errors.New("runtime config is not JSON-representable: " + err.Error())
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
