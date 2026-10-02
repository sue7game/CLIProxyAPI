package groupingadmin

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestCredentialPreviewMatchesAuthorizationMatrix(t *testing.T) {
	base := grouping.NewSnapshot()
	groups := []string{grouping.AllGroups}
	for _, name := range []string{"A", "B", "C"} {
		group, err := base.CreateGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, group.ID)
	}
	rules, err := grouping.NewRules(groups[1:])
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for layout := range 256 {
		snapshot := previewLayout(base, groups, ids, layout)
		for _, target := range groups {
			for mask := range 16 {
				changed := previewSelection(snapshot, ids, target, mask)
				want := bruteCredentialChanges(snapshot, rules, target, changed)
				got := credentialAccessChanges(snapshot, target, changed)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("layout=%d target=%s mask=%d got=%+v want=%+v", layout, target, mask, got, want)
				}
			}
		}
	}
}

func previewLayout(base grouping.Snapshot, groups, ids []string, layout int) grouping.Snapshot {
	snapshot := base.Clone()
	for index, id := range ids {
		kind := grouping.Token
		if index >= 2 {
			kind = grouping.Credential
		}
		snapshot.Identities[id] = grouping.Identity{Binding: grouping.Binding{
			ID: id, Kind: kind, GroupID: groups[layout%4], State: grouping.Active}}
		layout /= 4
	}
	return snapshot
}

func previewSelection(snapshot grouping.Snapshot, ids []string, target string, mask int) map[string]struct{} {
	changed := make(map[string]struct{})
	for index, id := range ids {
		if mask&(1<<index) != 0 && snapshot.Identities[id].GroupID != target {
			changed[id] = struct{}{}
		}
	}
	return changed
}

func bruteCredentialChanges(before grouping.Snapshot, rules *grouping.Rules, target string, changed map[string]struct{}) []groupingapi.CredentialAccessChange {
	after := before.Clone()
	for id := range changed {
		identity := after.Identities[id]
		identity.GroupID = target
		after.Identities[id] = identity
	}
	result := make([]groupingapi.CredentialAccessChange, 0)
	for id, token := range before.Identities {
		if token.Kind != grouping.Token || token.State != grouping.Active {
			continue
		}
		change := groupingapi.CredentialAccessChange{TokenID: id}
		for cid, credential := range before.Identities {
			was := rules.Allows(token.Binding, credential.Binding)
			now := rules.Allows(after.Identities[id].Binding, after.Identities[cid].Binding)
			if was {
				change.BeforeCount++
			}
			if now {
				change.AfterCount++
			}
			if now && !was {
				change.AddedCount++
			}
			if was && !now {
				change.RemovedCount++
			}
		}
		if change.AddedCount != 0 || change.RemovedCount != 0 {
			result = append(result, change)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TokenID < result[j].TokenID })
	return result
}

func TestPreviewIncludesUnselectedTokensAndExcludesInactiveIdentities(t *testing.T) {
	f := newFixture(t, sourceRecord{"tA", grouping.Token, "A", grouping.Active},
		sourceRecord{"tB", grouping.Token, "B", grouping.Active},
		sourceRecord{"tAll", grouping.Token, "all", grouping.Active},
		sourceRecord{"pendingToken", grouping.Token, "A", grouping.PendingRebind},
		sourceRecord{"cB", grouping.Credential, "B", grouping.Active},
		sourceRecord{"cAll", grouping.Credential, "all", grouping.Active},
		sourceRecord{"retiredCredential", grouping.Credential, "A", grouping.Tombstone})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
		CredentialIDs: []string{f.ids["cB"]}, GroupID: f.groups["A"],
	})
	if err != nil || !result.PermissionExpansion || result.AffectedCount != 1 || result.Revision != 1 {
		t.Fatalf("incorrect preview: %+v %v", result, err)
	}
	want := []groupingapi.CredentialAccessChange{
		{TokenID: f.ids["tA"], BeforeCount: 1, AfterCount: 2, AddedCount: 1},
		{TokenID: f.ids["tB"], BeforeCount: 2, AfterCount: 1, RemovedCount: 1},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].TokenID < want[j].TokenID })
	if !reflect.DeepEqual(result.CredentialAccessChanges, want) {
		t.Fatalf("incorrect access changes: %+v", result.CredentialAccessChanges)
	}
	assertUnchanged(t, f, before, data)
}

func TestWildcardPreviewRequiresConsentEvenWithoutNewCurrentEdges(t *testing.T) {
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
		TokenIDs: []string{f.ids["token"]}, GroupID: "all",
	})
	if err != nil || !result.PermissionExpansion || len(result.CredentialAccessChanges) != 0 {
		t.Fatalf("wildcard permission semantics diverged from Apply: %+v %v", result, err)
	}
	result, err = f.backend.Preview(testContext(), groupingapi.BindingRequest{
		TokenIDs: []string{f.ids["token"]}, GroupID: f.groups["A"],
	})
	if err != nil || result.PermissionExpansion || result.AffectedCount != 0 || len(result.CredentialAccessChanges) != 0 {
		t.Fatalf("no-op preview invented access changes: %+v %v", result, err)
	}
	assertUnchanged(t, f, before, data)
}
