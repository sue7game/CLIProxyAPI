package handlers

import (
	"context"
	"net/http"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// AuthorizeRetainedCredential checks both the original and current credential.
// Runtime IDs can be reused after config reordering; retained resources must not
// silently move to another permanent identity, even when both are accessible.
func AuthorizeRetainedCredential(ctx context.Context, manager *coreauth.Manager, original *coreauth.Auth) (*coreauth.Auth, error) {
	if manager == nil || original == nil {
		return nil, retainedCredentialUnavailable()
	}
	current, exists := manager.GetByID(original.ID)
	if !exists || current == nil || current.EffectiveDisabled() {
		return nil, retainedCredentialUnavailable()
	}
	if manager.CredentialAccessPolicyEnabled() {
		id := retainedGroupingID(original)
		if id == "" || id != retainedGroupingID(current) || original.Provider != current.Provider {
			return nil, retainedCredentialUnavailable()
		}
		if err := manager.AuthorizeCredentialUse(ctx, original); err != nil {
			return nil, err
		}
	}
	if err := manager.AuthorizeCredentialUse(ctx, current); err != nil {
		return nil, err
	}
	return current, nil
}

func retainedGroupingID(credential *coreauth.Auth) string {
	id := credential.Attributes["grouping_id"]
	if value, exists := credential.Metadata["grouping_id"]; exists {
		metadataID, ok := value.(string)
		if !ok || metadataID == "" || (id != "" && id != metadataID) {
			return ""
		}
		id = metadataID
	}
	return id
}

func retainedCredentialUnavailable() error {
	return &coreauth.Error{Code: "credential_access_denied", Message: "retained credential identity is unavailable", HTTPStatus: http.StatusForbidden}
}
