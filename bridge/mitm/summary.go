package mitm

import (
	"fmt"
	"sort"
	"strings"
)

// Summary describes what the engine currently runs (rule lines, hostnames, tasks, switches): v0.19.22 hot-apply
// tests compare it after a hot apply and after a full reload.
func (e *Engine) Summary() string {
	if e == nil {
		return "<nil>"
	}
	st := e.state()
	if st == nil || st.rs == nil || st.cfg == nil {
		return "<empty>"
	}
	rules := make([]string, 0, len(st.rs.Rules))
	for _, r := range st.rs.Rules {
		rules = append(rules, fmt.Sprintf("%s|%s|%s", r.Kind, r.Phase, r.Pattern))
	}
	hosts := append([]string(nil), st.rs.Hostnames...)
	sort.Strings(hosts)
	return fmt.Sprintf("rewrite=%v scripts=%v mitm=%v rules=[%s] hosts=[%s] tasks=%d", st.cfg.RewriteOn(), st.cfg.ScriptsOn(), st.cfg.MitM,
		strings.Join(rules, "; "), strings.Join(hosts, ","), len(st.rs.Tasks))
}
