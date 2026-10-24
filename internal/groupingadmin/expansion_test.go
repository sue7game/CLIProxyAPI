package groupingadmin

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestRealStoreCrossGroupExpansionMatrix(t *testing.T) {
	groups := []string{"all", "A", "B", "C"}
	for _, tokenGroup := range groups {
		for _, credentialGroup := range groups {
			for _, target := range groups {
				for mode := 1; mode <= 3; mode++ {
					name := fmt.Sprintf("token=%s/credential=%s/target=%s/mode=%d", tokenGroup, credentialGroup, target, mode)
					t.Run(name, func(t *testing.T) { checkRealExpansion(t, tokenGroup, credentialGroup, target, mode) })
				}
			}
		}
	}
}

func checkRealExpansion(t *testing.T, tokenGroup, credentialGroup, target string, mode int) {
	t.Helper()
	f := newFixture(t, sourceRecord{"token", grouping.Token, tokenGroup, grouping.Active},
		sourceRecord{"credential", grouping.Credential, credentialGroup, grouping.Active})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	request := groupingapi.BindingRequest{GroupID: f.groups[target]}
	if mode&1 != 0 {
		request.TokenIDs = []string{f.ids["token"]}
	}
	if mode&2 != 0 {
		request.CredentialIDs = []string{f.ids["credential"]}
	}
	change, err := prepareBinding(before, request)
	if err != nil {
		t.Fatal(err)
	}
	requiresConfirmation := bruteExpansion(t, before, request.GroupID, change.changed)
	preview, err := f.backend.Preview(testContext(), request)
	if err != nil || preview.PermissionExpansion != requiresConfirmation || preview.AffectedCount != len(change.changed) {
		t.Fatalf("preview diverged from the binding consent predicate: %+v %v", preview, err)
	}
	result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	if requiresConfirmation {
		if !errors.Is(err, groupingapi.ErrConflict) || result.AppliedRevision != 0 {
			t.Fatalf("expansion was not rejected: %+v %v", result, err)
		}
		assertUnchanged(t, f, before, data)
		request.ConfirmPermissionExpansion = true
		result, err = f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	}
	if err != nil || result.AppliedRevision != 2 || f.notifications.Load() != 1 {
		t.Fatalf("authorized binding failed: %+v %v", result, err)
	}
	after := snapshotOf(t, f)
	for _, id := range change.ids {
		if after.Identities[id].GroupID != request.GroupID {
			t.Fatal("batch was not applied atomically")
		}
	}
}

func TestExpansionAlgorithmMatchesFullAccessMatrix(t *testing.T) {
	base := grouping.NewSnapshot()
	groups := []string{grouping.AllGroups}
	for _, name := range []string{"A", "B", "C"} {
		group, err := base.CreateGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, group.ID)
	}
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for layout := range 256 {
		snapshot := base.Clone()
		value := layout
		for index, id := range ids {
			kind := grouping.Token
			if index >= 2 {
				kind = grouping.Credential
			}
			snapshot.Identities[id] = grouping.Identity{Binding: grouping.Binding{
				ID: id, Kind: kind, GroupID: groups[value%4], State: grouping.Active}}
			value /= 4
		}
		for _, target := range groups {
			for mask := range 16 {
				changed := make(map[string]struct{})
				for index, id := range ids {
					if mask&(1<<index) != 0 && snapshot.Identities[id].GroupID != target {
						changed[id] = struct{}{}
					}
				}
				want := bruteExpansion(t, snapshot, target, changed)
				if got := expandsAccess(snapshot, target, changed); got != want {
					t.Fatalf("matrix mismatch: layout=%d target=%s mask=%d got=%t want=%t", layout, target, mask, got, want)
				}
			}
		}
	}
}

func bruteExpansion(t *testing.T, before grouping.Snapshot, target string, changed map[string]struct{}) bool {
	t.Helper()
	if target == grouping.AllGroups && len(changed) > 0 {
		return true
	}
	after := before.Clone()
	for id := range changed {
		identity := after.Identities[id]
		identity.GroupID = target
		after.Identities[id] = identity
	}
	groups := make([]string, 0, len(before.Groups))
	for id := range before.Groups {
		groups = append(groups, id)
	}
	rules, err := grouping.NewRules(groups)
	if err != nil {
		t.Fatal(err)
	}
	for tokenID, token := range before.Identities {
		if token.Kind != grouping.Token {
			continue
		}
		for credentialID, credential := range before.Identities {
			if credential.Kind == grouping.Credential &&
				rules.Allows(after.Identities[tokenID].Binding, after.Identities[credentialID].Binding) &&
				!rules.Allows(token.Binding, credential.Binding) {
				return true
			}
		}
	}
	return false
}

func TestPendingAndRetiredOpponentsDoNotInventExpansion(t *testing.T) {
	for _, state := range []grouping.RegistrationState{grouping.PendingRebind, grouping.Tombstone} {
		f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active},
			sourceRecord{"credential", grouping.Credential, "B", state})
		_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind,
			Binding: groupingapi.BindingRequest{TokenIDs: []string{f.ids["token"]}, GroupID: f.groups["B"]}})
		if err != nil {
			t.Fatalf("inactive opponent created a nonexistent access relation: %v", err)
		}
	}
}
