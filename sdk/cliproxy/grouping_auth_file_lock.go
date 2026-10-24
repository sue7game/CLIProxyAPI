package cliproxy

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func withGroupingCredentialFileLock(change groupingFileChange, write func() error) error {
	for _, raw := range [][]byte{change.before, change.after} {
		var metadata struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &metadata) == nil && strings.EqualFold(strings.TrimSpace(metadata.Type), "codex") {
			return codex.WithFileLock(change.path, write)
		}
	}
	return write()
}
