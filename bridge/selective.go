package libmihomo

// Selective native MitM (feat/selective-native; bridge/mitm/selective.go). Swift sets the mode when it installs the
// native front (switch nativeMitmSelective): 0 off (every eligible connection may go native — stage 2 behaviour),
// 1 hosts with a body / jq / json rewrite or a script rule, 2 hosts with a script rule only.

import (
	"encoding/json"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// MitmSetNativeSelective sets the selective mode (see above).
func MitmSetNativeSelective(mode int) { mitm.SetNativeSelective(mode) }

// MitmNativeSelective reports the selective mode.
func MitmNativeSelective() int { return mitm.NativeSelective() }

// MitmNativeSelectiveStats: JSON {mode, handed, skipped, learned} since process start.
func MitmNativeSelectiveStats() string {
	h, s, l := mitm.SelectiveStats()
	b, _ := json.Marshal(map[string]any{"mode": mitm.NativeSelective(), "handed": h, "skipped": s, "learned": l})
	return string(b)
}
