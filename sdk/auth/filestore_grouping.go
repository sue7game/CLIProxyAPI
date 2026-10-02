package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// ApplyFileGroupingIDs propagates existing file identities without allocating any.
// Multi-record plugins must supply distinct, persisted child UUIDs; a file-level
// UUID is never inherited by their virtual credentials. require rejects missing IDs.
func ApplyFileGroupingIDs(auths []*coreauth.Auth, source map[string]any, require bool) error {
	sourceID, err := mergeFileGroupingID("", source["grouping_id"])
	if err != nil {
		return err
	}
	ids := make([]string, len(auths))
	seen := make(map[string]bool)
	runtimeIDs := make(map[string]bool)
	for i, auth := range auths {
		if auth == nil {
			continue
		}
		if require && len(auths) > 1 && (auth.ID == "" || runtimeIDs[auth.ID]) {
			return fmt.Errorf("grouping: plugin credentials require distinct nonempty runtime IDs")
		}
		runtimeIDs[auth.ID] = true
		id, err := fileAuthGroupingID(auth)
		if err == nil && len(auths) == 1 {
			id, err = mergeFileGroupingID(id, source["grouping_id"])
		}
		if err != nil {
			return err
		}
		if len(auths) > 1 && id != "" && id == sourceID {
			return fmt.Errorf("grouping: plugin child must not reuse its source file identity")
		}
		if id == "" && require {
			return fmt.Errorf("grouping: credential requires a persisted UUID; multi-record plugins need independent child identities")
		}
		if id != "" && seen[id] {
			return fmt.Errorf("grouping: plugin credentials have duplicate child identities")
		}
		seen[id], ids[i] = true, id
	}
	for i, auth := range auths {
		if auth != nil && ids[i] != "" {
			setFileGroupingID(auth, ids[i])
		}
	}
	return nil
}

func mergeFileGroupingID(id string, raw any) (string, error) {
	if raw == nil {
		return id, nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("grouping: file credential identity must be a UUID string")
	}
	if value == "" {
		return id, nil
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || !strings.EqualFold(value, parsed.String()) {
		return "", fmt.Errorf("grouping: file credential identity must be a nonzero canonical UUID")
	}
	value = parsed.String()
	if id != "" && id != value {
		return "", fmt.Errorf("grouping: conflicting file credential identities")
	}
	return value, nil
}

func fileAuthGroupingID(auth *coreauth.Auth) (string, error) {
	id, err := mergeFileGroupingID("", auth.Attributes["grouping_id"])
	if err != nil {
		return "", err
	}
	return mergeFileGroupingID(id, auth.Metadata["grouping_id"])
}

func setFileGroupingID(auth *coreauth.Auth, id string) {
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Attributes["grouping_id"] = id
	auth.Metadata["grouping_id"] = id
}

func preserveFileGroupingID(path string, auth *coreauth.Auth) error {
	id, err := fileAuthGroupingID(auth)
	if err != nil {
		return err
	}
	raw, errRead := os.ReadFile(path)
	if errRead == nil {
		var stored map[string]any
		if err = json.Unmarshal(raw, &stored); err != nil {
			return fmt.Errorf("grouping: cannot verify existing file identity: %w", err)
		}
		id, err = mergeFileGroupingID(id, stored["grouping_id"])
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(errRead) {
		return fmt.Errorf("grouping: read existing file identity: %w", errRead)
	}
	if id == "" {
		return nil
	}
	if auth.Storage != nil {
		if _, ok := auth.Storage.(interface{ SetMetadata(map[string]any) }); !ok {
			return fmt.Errorf("grouping: token storage cannot preserve credential metadata")
		}
	}
	setFileGroupingID(auth, id)
	return nil
}
