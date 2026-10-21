package libmihomo

// r7 (backlog B01): the controller secret, the LAN-share password and the 其他用户 passwords live in
// <home>/secrets.json, written by the app (Shared/AppShared.swift CoreSecrets) — overrides.json, which goes into
// backups, the sync folder and diagnostics, carries the usernames only. readOverrides overlays this file. A value
// still present in overrides.json (written by an older build, or a restored older backup the app has not migrated
// yet) wins, which is the same precedence the app uses.

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type coreSecrets struct {
	Secret      string            `json:"secret"`
	LanPassword string            `json:"lanPassword"`
	LanUsers    map[string]string `json:"lanUsers"` // username → password
}

func secretsPath(home string) string { return filepath.Join(home, "secrets.json") }

// readSecrets returns the stored secrets, nil when the file is missing or unreadable.
func readSecrets(home string) *coreSecrets {
	if home == "" {
		return nil
	}
	b, err := os.ReadFile(secretsPath(home))
	if err != nil {
		return nil
	}
	var s coreSecrets
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

func applySecrets(o *Overrides, s *coreSecrets) {
	if s == nil {
		return
	}
	if o.Secret == "" {
		o.Secret = s.Secret
	}
	if o.LanAuth.Password == "" {
		o.LanAuth.Password = s.LanPassword
	}
	for i := range o.LanUsers {
		if o.LanUsers[i].Password == "" {
			o.LanUsers[i].Password = s.LanUsers[o.LanUsers[i].Username]
		}
	}
}
