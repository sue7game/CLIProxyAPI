package cliproxy

import (
	"errors"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGroupingOAuthPendingExcludesPolicyMutations(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	backend, err := f.g.backend()
	if err != nil {
		t.Fatal(err)
	}
	group, err := backend.Apply(f.ctx, f.snapshot(t).Revision, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "Before OAuth"})
	if err != nil {
		t.Fatal(err)
	}
	record := oauthTestRecord("isolated.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	staged := f.snapshot(t)
	mutations := []groupingapi.Mutation{
		{Operation: groupingapi.CreateGroup, Name: "During OAuth"},
		{Operation: groupingapi.RenameGroup, ID: group.Group.ID, Name: "Renamed"},
		{Operation: groupingapi.DeleteGroup, ID: group.Group.ID},
		{Operation: groupingapi.Bind, Binding: groupingapi.BindingRequest{CredentialIDs: []string{record.Attributes["grouping_id"]}, GroupID: group.Group.ID}},
		{Operation: groupingapi.Rebind, ID: record.Attributes["grouping_id"], Confirm: true},
		{Operation: groupingapi.Activate, Enabled: false, ConfirmPermissionExpansion: true},
	}
	for _, mutation := range mutations {
		if _, err := backend.Apply(f.ctx, staged.Revision, mutation); !errors.Is(err, groupingapi.ErrConflict) {
			t.Fatalf("%s interleaved with OAuth: %v", mutation.Operation, err)
		}
		if !reflect.DeepEqual(staged, f.snapshot(t)) {
			t.Fatal("rejected mutation changed signed staged policy")
		}
	}
	completeIsolatedOAuth(t, f, record)
	if _, err := backend.Apply(f.ctx, f.snapshot(t).Revision, mutations[0]); err != nil {
		t.Fatal("completed transaction still blocks policy mutation", err)
	}
}

func TestGroupingOAuthPendingWatcherDoesNotTombstoneUnwrittenSource(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("pending-watcher.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	staged := f.snapshot(t)
	if err := f.g.reconcileRuntimeSources(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(staged, f.snapshot(t)) || !f.g.healthy() {
		t.Fatal("watcher changed staged OAuth policy or readiness")
	}
	if f.g.owner.applyConfigUpdateWithAuthSynthesis(f.ctx, f.g.current.Load().CloneForRuntime(), true) {
		t.Fatal("configuration reload interleaved with staged OAuth")
	}
	if !reflect.DeepEqual(staged, f.snapshot(t)) || !f.g.healthy() {
		t.Fatal("deferred config reload corrupted staged policy")
	}
	completeIsolatedOAuth(t, f, record)
	if err := f.g.reconcileRuntimeSources(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.snapshot(t).Identities[record.Attributes["grouping_id"]].State != grouping.Active {
		t.Fatal("deferred reconciliation lost the saved source")
	}
}

func TestGroupingOAuthDeferredWatcherPreservesCrashRecovery(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("abandoned.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := f.g.reconcileRuntimeSources(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.g.mu.Lock()
	err := f.g.recoverSourceTransaction()
	f.g.mu.Unlock()
	if err != nil {
		t.Fatal("abandoned OAuth could not recover its unchanged source", err)
	}
	if _, exists := f.snapshot(t).Identities[record.Attributes["grouping_id"]]; exists {
		t.Fatal("recovery retained an unwritten new credential")
	}
	if f.g.sourcePending {
		t.Fatal("successful recovery did not release transaction reservation")
	}
}

func completeIsolatedOAuth(t *testing.T, f *groupingAuthFixture, record *coreauth.Auth) {
	t.Helper()
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if f.g.sourcePending || !f.g.healthy() {
		t.Fatal("successful OAuth did not release transaction reservation")
	}
}
