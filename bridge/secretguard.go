package libmihomo

// B04 (review 3 「empty secret」): the app fills the controller secret on every CoreOverrides.load(), but the
// Go side used to write overrides.json's value into the runtime as is, so an empty one (a hand-edited or
// truncated file, a restore of an old backup) started mihomo's controller WITHOUT authentication on
// 127.0.0.1 — any app on the device could drive it. Now an empty secret is replaced by a random one, written
// back into overrides.json (only the "secret" key; the app's next load keeps it) so the app and the core
// agree. When the file cannot be written (missing / unreadable) the random value is kept for this process
// and a warning is logged: the core still never runs open.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

var (
	fallbackSecretOnce sync.Once
	fallbackSecret     string
)

func randomSecret() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("tern-%x-%x", time.Now().UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(b)
}

func processSecret() string {
	fallbackSecretOnce.Do(func() { fallbackSecret = randomSecret() })
	return fallbackSecret
}

// ensureControllerSecret returns the secret overrides.json holds now, or stores a new random one there.
func ensureControllerSecret(home string) string {
	if home == "" {
		return processSecret()
	}
	p := overridesPath(home)
	defer lockPath(p)()
	b, err := os.ReadFile(overridesPath(home))
	if err != nil {
		log.Warnln("[Bridge] 控制器密钥为空且无法写回 overrides.json，本次使用随机密钥")
		return processSecret()
	}
	raw := map[string]any{}
	if json.Unmarshal(b, &raw) != nil {
		log.Warnln("[Bridge] 控制器密钥为空且 overrides.json 无法解析，本次使用随机密钥")
		return processSecret()
	}
	if s, _ := raw["secret"].(string); strings.TrimSpace(s) != "" {
		return s // another writer filled it meanwhile
	}
	s := randomSecret()
	raw["secret"] = s
	nb, err := json.Marshal(raw)
	if err == nil {
		err = writeFileAtomic(p, nb)
	}
	if err != nil {
		log.Warnln("[Bridge] 控制器密钥为空，写回 overrides.json 失败（%v），本次使用随机密钥", err)
		return processSecret()
	}
	log.Warnln("[Bridge] 控制器密钥为空，已生成随机密钥并写回 overrides.json")
	return s
}
