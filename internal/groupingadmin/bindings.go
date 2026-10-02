package groupingadmin

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

type bindingChange struct {
	ids     []string
	changed map[string]struct{}
}

func prepareBinding(snapshot grouping.Snapshot, request groupingapi.BindingRequest) (bindingChange, error) {
	count := len(request.TokenIDs) + len(request.CredentialIDs)
	if count == 0 || count > 500 {
		return bindingChange{}, groupingapi.ErrConflict
	}
	if _, exists := snapshot.Groups[request.GroupID]; !exists && request.GroupID != grouping.AllGroups {
		return bindingChange{}, groupingapi.ErrConflict
	}
	change := bindingChange{ids: make([]string, 0, count), changed: make(map[string]struct{}, count)}
	seen := make(map[string]bool, count)
	for kind, ids := range map[grouping.ObjectKind][]string{
		grouping.Token: request.TokenIDs, grouping.Credential: request.CredentialIDs,
	} {
		for _, id := range ids {
			identity, exists := snapshot.Identities[id]
			if !exists || seen[id] || identity.Kind != kind || identity.State != grouping.Active {
				return bindingChange{}, groupingapi.ErrConflict
			}
			seen[id] = true
			change.ids = append(change.ids, id)
			if identity.GroupID != request.GroupID {
				change.changed[id] = struct{}{}
			}
		}
	}
	return change, nil
}

func applyBinding(snapshot *grouping.Snapshot, request groupingapi.BindingRequest) error {
	change, err := prepareBinding(*snapshot, request)
	if err != nil {
		return err
	}
	if !request.ConfirmPermissionExpansion && expandsAccess(*snapshot, request.GroupID, change.changed) {
		return groupingapi.ErrConflict
	}
	return snapshot.Bind(change.ids, request.GroupID)
}

// expandsAccess compares the full batch without materializing the token/credential
// cross product. All changed identities share one target group. New edges can only
// join a changed concrete identity to an unchanged target-group identity, or join
// two changed identities that previously belonged to different concrete groups.
func expandsAccess(snapshot grouping.Snapshot, target string, changed map[string]struct{}) bool {
	if len(changed) == 0 {
		return false
	}
	if target == grouping.AllGroups {
		return true
	}
	tokenGroups, credentialGroups := make(map[string]bool), make(map[string]bool)
	unchangedToken, unchangedCredential := false, false
	for id, identity := range snapshot.Identities {
		if identity.State != grouping.Active {
			continue
		}
		if _, moving := changed[id]; moving {
			if identity.GroupID != grouping.AllGroups {
				if identity.Kind == grouping.Token {
					tokenGroups[identity.GroupID] = true
				} else {
					credentialGroups[identity.GroupID] = true
				}
			}
		} else if identity.GroupID == target {
			unchangedToken = unchangedToken || identity.Kind == grouping.Token
			unchangedCredential = unchangedCredential || identity.Kind == grouping.Credential
		}
	}
	if len(tokenGroups) > 0 && unchangedCredential || len(credentialGroups) > 0 && unchangedToken {
		return true
	}
	return differentGroups(tokenGroups, credentialGroups)
}

func differentGroups(tokens, credentials map[string]bool) bool {
	if len(tokens) == 0 || len(credentials) == 0 {
		return false
	}
	if len(tokens) > 1 || len(credentials) > 1 {
		return true
	}
	for group := range tokens {
		return !credentials[group]
	}
	return false
}
