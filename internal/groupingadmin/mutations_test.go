package groupingadmin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestGroupCRUDUsesDurableRevisions(t *testing.T) {
	f := newFixture(t)
	created, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "Team D"})
	if err != nil || created.AppliedRevision != 2 || created.Group == nil || created.Group.Name != "Team D" {
		t.Fatalf("create failed: %+v %v", created, err)
	}
	id := created.Group.ID
	renamed, err := f.backend.Apply(testContext(), 2, groupingapi.Mutation{Operation: groupingapi.RenameGroup, ID: id, Name: "Team E"})
	if err != nil || renamed.AppliedRevision != 3 || renamed.Group == nil || renamed.Group.ID != id || renamed.Group.Name != "Team E" {
		t.Fatalf("rename failed: %+v %v", renamed, err)
	}
	deleted, err := f.backend.Apply(testContext(), 3, groupingapi.Mutation{Operation: groupingapi.DeleteGroup, ID: id})
	if err != nil || deleted.AppliedRevision != 4 || f.notifications.Load() != 3 {
		t.Fatalf("delete failed: %+v %v", deleted, err)
	}
	if _, exists := snapshotOf(t, f).Groups[id]; exists {
		t.Fatal("deleted group is still published")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = grouping.OpenStore(f.dir)
	if err != nil || snapshotOf(t, f).Revision != 4 {
		t.Fatalf("durable policy could not be reopened: %v", err)
	}
}

func TestRejectedGroupMutationsLeaveStoreUnchanged(t *testing.T) {
	f := newFixture(t, sourceRecord{"credential", grouping.Credential, "A", grouping.Active})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	mutations := []groupingapi.Mutation{
		{Operation: groupingapi.CreateGroup, Name: "a"},
		{Operation: groupingapi.CreateGroup, Name: "all"},
		{Operation: groupingapi.CreateGroup, Name: ""},
		{Operation: groupingapi.RenameGroup, ID: "all", Name: "new"},
		{Operation: groupingapi.RenameGroup, ID: f.groups["B"], Name: "C"},
		{Operation: groupingapi.DeleteGroup, ID: f.groups["A"]},
		{Operation: groupingapi.DeleteGroup, ID: "all"},
		{Operation: groupingapi.DeleteGroup, ID: uuid.NewString()},
		{Operation: "unknown"},
	}
	for _, mutation := range mutations {
		result, err := f.backend.Apply(testContext(), 1, mutation)
		if !errors.Is(err, groupingapi.ErrConflict) || result.AppliedRevision != 0 {
			t.Fatalf("unexpected outcome for %+v: %+v %v", mutation, result, err)
		}
		assertUnchanged(t, f, before, data)
	}
}

func TestBindingValidatesWholeBatchAndIdentityKind(t *testing.T) {
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active},
		sourceRecord{"credential", grouping.Credential, "A", grouping.Active},
		sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind},
		sourceRecord{"retired", grouping.Credential, "A", grouping.Tombstone})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	requests := []groupingapi.BindingRequest{
		{}, {TokenIDs: []string{f.ids["token"]}, GroupID: "missing"},
		{TokenIDs: []string{f.ids["credential"]}},
		{CredentialIDs: []string{f.ids["token"]}},
		{TokenIDs: []string{f.ids["token"], f.ids["token"]}},
		{TokenIDs: []string{f.ids["token"]}, CredentialIDs: []string{f.ids["token"]}},
		{TokenIDs: []string{f.ids["token"]}, CredentialIDs: []string{f.ids["pending"]}},
		{TokenIDs: []string{f.ids["token"]}, CredentialIDs: []string{f.ids["retired"]}},
		{TokenIDs: []string{f.ids["token"]}, CredentialIDs: []string{uuid.NewString()}},
		{TokenIDs: make([]string, 501)},
	}
	for _, request := range requests {
		if request.GroupID == "" {
			request.GroupID = f.groups["B"]
		}
		request.ConfirmPermissionExpansion = true
		_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
		if !errors.Is(err, groupingapi.ErrConflict) {
			t.Fatalf("invalid binding accepted: %+v %v", request, err)
		}
		if _, err := f.backend.Preview(testContext(), request); !errors.Is(err, groupingapi.ErrConflict) {
			t.Fatalf("invalid preview accepted: %+v %v", request, err)
		}
		assertUnchanged(t, f, before, data)
	}
}

func TestDuplicateFingerprintsRemainIndependentlyBound(t *testing.T) {
	f := newFixture(t, sourceRecord{"c1", grouping.Credential, "A", grouping.Active},
		sourceRecord{"c2", grouping.Credential, "A", grouping.Active})
	before := snapshotOf(t, f)
	request := groupingapi.BindingRequest{CredentialIDs: []string{f.ids["c1"]}, GroupID: f.groups["B"]}
	result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	if err != nil || result.AppliedRevision != 2 {
		t.Fatalf("independent binding failed: %+v %v", result, err)
	}
	after := snapshotOf(t, f)
	first := before.Identities[f.ids["c1"]]
	first.GroupID = f.groups["B"]
	if !reflect.DeepEqual(first, after.Identities[f.ids["c1"]]) ||
		!reflect.DeepEqual(before.Identities[f.ids["c2"]], after.Identities[f.ids["c2"]]) {
		t.Fatal("binding altered another record or source identity")
	}
}

func TestRealStoreConcurrentCAS(t *testing.T) {
	f := newFixture(t)
	const count = 24
	results := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: fmt.Sprintf("Team %d", index)})
			results <- err
		}(index)
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, groupingapi.ErrPrecondition) {
			t.Fatalf("unexpected CAS error: %v", err)
		}
	}
	after := snapshotOf(t, f)
	if successes != 1 || after.Revision != 2 || len(after.Groups) != 4 || f.notifications.Load() != 1 {
		t.Fatalf("CAS failed: successes=%d revision=%d notifications=%d", successes, after.Revision, f.notifications.Load())
	}
}

func TestStorageFailureCannotReportWriteSuccess(t *testing.T) {
	f := newFixture(t)
	data := policyBytes(t, f)
	if err := os.Remove(filepath.Join(f.dir, "identity.key")); err != nil {
		t.Fatal(err)
	}
	result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "new"})
	if !errors.Is(err, groupingapi.ErrUnavailable) || result.AppliedRevision != 0 || f.notifications.Load() != 0 {
		t.Fatalf("broken store reported success: %+v %v", result, err)
	}
	if !reflect.DeepEqual(data, policyBytes(t, f)) {
		t.Fatal("failed preflight changed the persisted policy")
	}
	if _, err := f.store.Snapshot(); !errors.Is(err, grouping.ErrUnavailable) {
		t.Fatal("broken store remained available for authorization")
	}
}
