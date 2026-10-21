package libmihomo

// B04 (review 3 「empty secret」): the app fills the controller secret on every CoreOverrides.load(), but the
// Go side used to write overrides.json's value into the runtime as is, so an empty one (a hand-edited or
// truncated file, a restore of an old backup) started mihomo's controller WITHOUT authentication on
// 127.0.0.1 — any app on the device could drive it. Now an empty secret is replaced by a random one, written
// back (r7 B01: into secrets.json, only the "secret" key; the app's next load keeps it) so the app and the core
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

// ensureControllerSecret returns the secret secrets.json holds now, or stores a new random one there.
// r7 B01 (merged with B04): secrets live in <home>/secrets.json, not overrides.json — the write-back goes there
// (only the "secret" key, other keys kept, 0600), so overrides.json, which goes into plain backups / the sync
// folder / diagnostics, never carries it. The app reads secrets.json when overrides.json has no secret.
// Without an overrides.json (no app data yet) nothing is created and a per-process secret is used.
func ensureControllerSecret(home string) string {
	if home == "" {
		return processSecret()
	}
	if _, err := os.Stat(overridesPath(home)); err != nil {
		log.Warnln("[Bridge] 控制器密钥为空且 overrides.json 不存在，本次使用随机密钥")
		return processSecret()
	}
	sp := secretsPath(home)
	defer lockPath(sp)()
	raw := map[string]any{}
	if b, err := os.ReadFile(sp); err == nil {
		if json.Unmarshal(b, &raw) != nil {
			log.Warnln("[Bridge] 控制器密钥为空且 secrets.json 无法解析，本次使用随机密钥")
			return processSecret()
		}
	} else if !os.IsNotExist(err) {
		log.Warnln("[Bridge] 控制器密钥为空且无法读取 secrets.json，本次使用随机密钥")
		return processSecret()
	}
	if s, _ := raw["secret"].(string); strings.TrimSpace(s) != "" {
		return s // another writer filled it meanwhile
	}
	s := randomSecret()
	raw["secret"] = s
	nb, err := json.Marshal(raw)
	if err == nil {
		err = writeAtomic(sp, nb)
	}
	if err != nil {
		log.Warnln("[Bridge] 控制器密钥为空，写回 secrets.json 失败（%v），本次使用随机密钥", err)
		return processSecret()
	}
	_ = os.Chmod(sp, 0o600)
	log.Warnln("[Bridge] 控制器密钥为空，已生成随机密钥并写回 secrets.json")
	return s
}
