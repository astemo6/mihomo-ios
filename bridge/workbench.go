package libmihomo

import (
	"encoding/json"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// ScriptDebugRun runs one script for the 脚本调试 workbench (app process, no tunnel needed).
// inputJSON is mitm.DebugInput; returns mitm.DebugOutput as JSON.
func ScriptDebugRun(homeDir, inputJSON string) string {
	var in mitm.DebugInput
	if err := json.Unmarshal([]byte(inputJSON), &in); err != nil {
		b, _ := json.Marshal(mitm.DebugOutput{Error: "参数无效：" + err.Error(), Logs: []mitm.DebugLog{}, Summary: []string{}, Notifications: []map[string]string{}})
		return string(b)
	}
	out := mitm.DebugRun(homeDir, in, nil)
	b, _ := json.Marshal(out)
	return string(b)
}

// RewriteLineFromForm builds and validates a rewrite line from the visual editor's form (JSON in/out).
func RewriteLineFromForm(formJSON string) string {
	var f mitm.RewriteForm
	if err := json.Unmarshal([]byte(formJSON), &f); err != nil {
		f.Error = err.Error()
	} else {
		f = mitm.LineFromForm(f)
	}
	b, _ := json.Marshal(f)
	return string(b)
}

// RewriteFormFromLine maps a stored rewrite line onto the form (type "raw" when it does not fit one).
func RewriteFormFromLine(line string) string {
	b, _ := json.Marshal(mitm.FormFromLine(line))
	return string(b)
}

// ScriptSource returns the code of a local script or the cached copy of a remote one ("" + LastError on failure).
func ScriptSource(homeDir, path string) string {
	b, err := mitm.ScriptSource(homeDir, path)
	if err != nil {
		lastError = err.Error()
		return ""
	}
	return string(b)
}
