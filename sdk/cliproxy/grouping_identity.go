package cliproxy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type groupingHasher func(string, string) (string, error)

func groupingCredentialIdentity(auth *coreauth.Auth, hash groupingHasher) (grouping.Identity, error) {
	if auth == nil || hash == nil || auth.Provider == "" {
		return grouping.Identity{}, grouping.ErrInvalid
	}
	id := auth.Attributes["grouping_id"]
	if metadataID, ok := auth.Metadata["grouping_id"].(string); ok {
		if id != "" && id != metadataID {
			return grouping.Identity{}, grouping.ErrConflict
		}
		id = metadataID
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return grouping.Identity{}, grouping.ErrInvalid
	}
	material, err := groupingCredentialMaterial(auth)
	if err != nil {
		return grouping.Identity{}, err
	}
	fingerprint, err := hash("credential:"+auth.Provider, material)
	if err != nil {
		return grouping.Identity{}, err
	}
	return grouping.Identity{Binding: grouping.Binding{ID: id, Kind: grouping.Credential, GroupID: grouping.AllGroups, State: grouping.Active}, Provider: auth.Provider, Fingerprint: fingerprint}, nil
}

func groupingCredentialMaterial(auth *coreauth.Auth) (string, error) {
	material := make(map[string]string)
	if coreauth.IsConfigAPIKeyAuth(auth) {
		material["api_key"] = auth.Attributes["api_key"]
		material["base_url"] = auth.Attributes["base_url"]
		for key, value := range auth.Attributes {
			if !strings.HasPrefix(key, "header:") {
				continue
			}
			name := strings.ToLower(strings.TrimPrefix(key, "header:"))
			if material["api_key"] == "" || groupingAuthenticationHeader(name) {
				material["header:"+name] = value
			}
		}
	} else {
		// Mutable access/refresh tokens are deliberately excluded from OAuth identity.
		for _, key := range []string{"account_id", "user_id", "email", "project_id", "organization_id"} {
			if value, ok := auth.Metadata[key].(string); ok && value != "" {
				material[key] = value
			}
		}
		if len(material) == 0 {
			return "", fmt.Errorf("grouping: credential has no stable account identity")
		}
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", grouping.ErrInvalid
	}
	return string(encoded), nil
}

func groupingAuthenticationHeader(name string) bool {
	switch name {
	case "user-agent", "accept", "accept-encoding", "content-type", "anthropic-version", "anthropic-beta":
		return false
	default:
		return true
	}
}
