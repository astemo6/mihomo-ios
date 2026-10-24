package mitm

import "encoding/json"

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
