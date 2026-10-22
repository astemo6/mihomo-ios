package libmihomo

import (
	"strings"
	"testing"

	R "github.com/metacubex/mihomo/rules"
)

func TestFaceTimeRulesParse(t *testing.T) {
	for _, m := range faceTimeMatchers {
		line := m + ",Proxy"
		i := strings.Index(line, ",")
		tp, rest := line[:i], line[i+1:]
		j := strings.LastIndex(rest, ",")
		if _, err := R.ParseRule(tp, rest[:j], rest[j+1:], nil, nil); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
}
