package mitm

// Response header rules for the native rewrite engine when Swift cannot apply them itself (native MitM stage 3,
// lane s3-full): an upstream header value that is not ASCII (the ICU translation is exact for ASCII only), or a
// QX raw header-block rewrite whose result would depend on Go's header map order. The Swift engine committed to
// the request natively before the response existed, so it cannot hand the flow back; instead it asks Go to run
// exactly modifyResponse's applyHeaderOps for the matched rules. No flow, no goroutine, no request log entry.

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RewriteHeaderOps applies the header operations of rules (Ruleset indices of snapshot generation gen) to the
// response header pairs as modifyResponse would for status. ok false: generation unknown or a rule that is not
// a header rule.
func (e *Engine) RewriteHeaderOps(gen int64, rules []int, status int, pairs [][2]string) ([][2]string, bool) {
	st := e.snapState(gen)
	if st == nil || st.rs == nil {
		return nil, false
	}
	h := http.Header{}
	for _, kv := range pairs {
		h[kv[0]] = append(h[kv[0]], kv[1])
	}
	line := "HTTP/1.1 " + fmt.Sprintf("%d %s", status, http.StatusText(status))
	for _, i := range rules {
		if i < 0 || i >= len(st.rs.Rules) || st.rs.Rules[i].Kind != KindHeader {
			return nil, false
		}
		applyHeaderOps(h, st.rs.Rules[i].Headers, func() string { return line })
	}
	return flowHeaderPairs(h), true
}

// RewriteHeaderOpsJSON is RewriteHeaderOps over JSON (gomobile): rules a JSON int array, headers JSON pairs;
// "" when it cannot.
func (e *Engine) RewriteHeaderOpsJSON(gen int64, rulesJSON string, status int, headersJSON string) string {
	var rules []int
	var pairs [][2]string
	if json.Unmarshal([]byte(rulesJSON), &rules) != nil || json.Unmarshal([]byte(headersJSON), &pairs) != nil {
		return ""
	}
	out, ok := e.RewriteHeaderOps(gen, rules, status, pairs)
	if !ok {
		return ""
	}
	b, _ := json.Marshal(out)
	return string(b)
}
