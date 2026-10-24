package mitm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExportRewriteSnapshot builds the RewriteSnapshot for cfg / rs without an engine running (feat/native-core-eval:
// the app writes it for the Go-free native tunnel, PrepareNativeRuntime). Hostnames only count while MitM is on.
// Returns the JSON and the number of MitM hostname patterns.
func ExportRewriteSnapshot(home string, cfg *Config, rs *Ruleset) (string, int) {
	if cfg == nil || rs == nil {
		return "", 0
	}
	e := &Engine{home: home}
	e.res = NewResources(home, e)
	hostnames := rs.Hostnames
	if !cfg.MitM {
		hostnames = nil
	}
	st := &state{cfg: cfg, rs: rs, hosts: NewHostMatcher(hostnames)}
	s := buildRewriteSnapshot(st, e)
	s.Gen = 1
	js, _ := json.Marshal(s)
	return string(js), len(hostnames)
}

// ---- feat/native-core-eval: script manifest for the Go-free tunnel ----

// ScriptManifestFile lists every script rule of the exported snapshot for the native script host
// (PacketTunnel/NativeMitM/Script/NativeScriptGo.swift NativeScriptHost.prepare). The code of each script (BOM
// stripped, Egern scripts adapted: scriptCode) is written to ScriptManifestDir/<key>.js so the tunnel never parses
// a module or downloads a script itself.
const (
	ScriptManifestFile = "nativecore-scripts.json"
	ScriptManifestDir  = "nativecore-scripts"
)

// ScriptManifestEntry is one script rule (I = the rule index, RWSnapRule.i).
type ScriptManifestEntry struct {
	I         int             `json:"i"`
	Key       string          `json:"key,omitempty"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	File      string          `json:"file,omitempty"`
	TimeoutMs int64           `json:"timeoutMs"`
	Setup     json.RawMessage `json:"setup,omitempty"` // runCtx.setupJSON(nil, nil): __tern_begin's base
	Err       string          `json:"err,omitempty"`   // load / adapt error, reported as the script's run error
}

type scriptManifest struct {
	Version int                   `json:"version"`
	Scripts []ScriptManifestEntry `json:"scripts"`
}

// ExportScriptManifest writes ScriptManifestFile + the code files for rs (removing code files no rule uses any
// more). Returns the number of scripts and of scripts that could not be loaded.
func ExportScriptManifest(home string, cfg *Config, rs *Ruleset) (int, int, error) {
	dir := filepath.Join(home, ScriptManifestDir)
	man := scriptManifest{Version: 1, Scripts: []ScriptManifestEntry{}}
	keep := map[string]bool{}
	bad := 0
	if cfg != nil && rs != nil {
		e := &Engine{home: home}
		e.res = NewResources(home, e)
		e.st.Store(&state{cfg: cfg, rs: rs})
		for i, r := range rs.Rules {
			if r.Kind != KindScript || r.Script == nil {
				continue
			}
			sc := r.Script
			ent := ScriptManifestEntry{I: i, Name: sc.Name, Type: sc.Type,
				TimeoutMs: scriptTimeout(sc, 120*time.Second, 10*time.Second).Milliseconds()}
			rc := &runCtx{script: sc, name: sc.Name, e: e}
			if setup, err := rc.setupJSON(nil, nil); err == nil {
				ent.Setup = json.RawMessage(setup)
			} else {
				ent.Err = err.Error()
			}
			src := sc.Source
			if src == nil && ent.Err == "" {
				b, err := e.res.Get(sc.Path, sc.UpdateInterval)
				if err != nil {
					ent.Err = fmt.Errorf("加载脚本失败：%w", err).Error()
				}
				src = b
			}
			if ent.Err == "" {
				code, err := scriptCode(src)
				if err != nil {
					ent.Err = err.Error()
				} else {
					sum := sha256.Sum256([]byte(code))
					ent.Key = "nc-" + hex.EncodeToString(sum[:12])
					ent.File = filepath.Join(ScriptManifestDir, ent.Key+".js")
					if !keep[ent.Key] {
						if err := os.MkdirAll(dir, 0o755); err != nil {
							return 0, 0, err
						}
						p := filepath.Join(home, ent.File)
						if _, err := os.Stat(p); err != nil {
							if err := os.WriteFile(p+".tmp", []byte(code), 0o644); err != nil {
								return 0, 0, err
							}
							if err := os.Rename(p+".tmp", p); err != nil {
								return 0, 0, err
							}
						}
						keep[ent.Key] = true
					}
				}
			}
			if ent.Err != "" {
				bad++
			}
			man.Scripts = append(man.Scripts, ent)
		}
	}
	if des, err := os.ReadDir(dir); err == nil {
		for _, de := range des {
			n := de.Name()
			if strings.HasSuffix(n, ".js") && !keep[strings.TrimSuffix(n, ".js")] {
				_ = os.Remove(filepath.Join(dir, n))
			}
		}
	}
	b, err := json.Marshal(man)
	if err != nil {
		return 0, 0, err
	}
	p := filepath.Join(home, ScriptManifestFile)
	if err := os.WriteFile(p+".tmp", b, 0o644); err != nil {
		return 0, 0, err
	}
	return len(man.Scripts), bad, os.Rename(p+".tmp", p)
}
