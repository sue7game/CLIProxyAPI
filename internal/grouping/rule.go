package grouping

import (
	"errors"
	"strings"
)

// Rules is an immutable group catalog supporting concurrent authorization reads.
// Its zero value denies all access; create a usable catalog with NewRules.
type Rules struct {
	groups map[string]struct{}
}

// NewRules copies the concrete group IDs and adds the built-in wildcard scope.
// Empty, padded, reserved, or duplicate IDs invalidate the entire catalog.
// UUID and display-name validation belong to the group administration layer.
func NewRules(groupIDs []string) (*Rules, error) {
	groups := make(map[string]struct{}, len(groupIDs)+1)
	groups[AllGroups] = struct{}{}
	for _, id := range groupIDs {
		if id == "" || strings.TrimSpace(id) != id {
			return nil, errors.New("grouping: invalid group identifier")
		}
		if _, exists := groups[id]; exists {
			return nil, errors.New("grouping: duplicate or reserved group identifier")
		}
		groups[id] = struct{}{}
	}
	return &Rules{groups: groups}, nil
}

// Allows checks group eligibility for two trusted, registered bindings.
// This does not replace authentication, disabled-state, model, or quota checks.
// Missing or invalid bindings never acquire the wildcard scope implicitly.
func (r *Rules) Allows(token, credential Binding) bool {
	if !r.validBinding(token, Token) || !r.validBinding(credential, Credential) {
		return false
	}
	return token.GroupID == AllGroups || credential.GroupID == AllGroups || token.GroupID == credential.GroupID
}

func (r *Rules) validBinding(binding Binding, kind ObjectKind) bool {
	if r == nil || binding.Kind != kind || binding.State != Active {
		return false
	}
	if binding.ID == "" || strings.TrimSpace(binding.ID) != binding.ID {
		return false
	}
	_, exists := r.groups[binding.GroupID]
	return exists
}
