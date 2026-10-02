package groupingadmin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestSuccessfulLifecycleAuditKeepsCallbackLockOwnership(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t, sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind})
	f.backend.options.Initialize = func(context.Context) (groupingapi.Status, error) {
		if !f.mutex.TryLock() {
			t.Fatal("initialize audit retained the shared lock")
		}
		defer f.mutex.Unlock()
		snapshot := snapshotOf(t, f)
		return groupingapi.Status{Namespace: snapshot.Namespace, Revision: snapshot.Revision, Initialized: true}, nil
	}
	if _, err := f.backend.Initialize(testContext()); err != nil {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), "initialize", 1, true)
	if hook.LastEntry().Data["namespace"] != snapshotOf(t, f).Namespace {
		t.Fatal("initialization audit lost namespace")
	}
	f.backend.options.Activation = activationCallback(t, f)
	if _, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Activate, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Activate, 2, true)
	if _, err := f.backend.Apply(testContext(), 2, groupingapi.Mutation{Operation: groupingapi.Activate, ConfirmPermissionExpansion: true}); err != nil {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Activate, 3, true)
	if hook.LastEntry().Data["confirmation_reason"] != "disable_grouping" {
		t.Fatal("disable audit lost the explicit expansion reason")
	}
	f.backend.options.Rebind = auditedRebindCallback(t, f)
	if _, err := f.backend.Apply(testContext(), 3, groupingapi.Mutation{Operation: groupingapi.Rebind, ID: f.ids["pending"], Confirm: true}); err != nil {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Rebind, 4, true)
	want := []groupingapi.AuditGroupChange{{ID: f.ids["pending"], OldGroup: f.groups["A"], NewGroup: f.groups["A"]}}
	if !reflect.DeepEqual(hook.LastEntry().Data["group_changes"], want) || hook.LastEntry().Data["confirmation_reason"] != "identity_rebind" {
		t.Fatal("rebind audit lost the preserved logical relationship")
	}
}

func auditedRebindCallback(t *testing.T, f *fixture) func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	t.Helper()
	return func(_ context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		if !f.mutex.TryLock() {
			t.Fatal("rebind audit retained the shared lock")
		}
		defer f.mutex.Unlock()
		snapshot, err := f.store.Update(expected, func(next *grouping.Snapshot) error {
			identity := next.Identities[mutation.ID]
			if !mutation.Confirm || identity.State != grouping.PendingRebind {
				return grouping.ErrConflict
			}
			return next.ReplaceIdentity(mutation.ID, identity.Fingerprint, "private-secret-replacement")
		})
		return groupingapi.ApplyResult{AppliedRevision: snapshot.Revision}, err
	}
}

func TestLifecycleAuditCannotAuthorizeAStaleCallback(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t)
	callback := activationCallback(t, f)
	f.backend.options.Activation = func(ctx context.Context, revision uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		f.mutex.Lock()
		_, err := f.store.Update(revision, func(*grouping.Snapshot) error { return nil })
		f.mutex.Unlock()
		if err != nil {
			return groupingapi.ApplyResult{}, err
		}
		return callback(ctx, revision, mutation)
	}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Activate, Enabled: true})
	if !errors.Is(err, groupingapi.ErrPrecondition) || f.enabled || f.notifications.Load() != 0 {
		t.Fatal("audit observation replaced callback CAS")
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Activate, 1, false)
}

func TestUnavailableStoreAuditCannotInventMetadata(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "private-secret"})
	if !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.CreateGroup, 1, false)
	if hook.LastEntry().Data["namespace"] != nil || hook.LastEntry().Data["group_changes"] != nil {
		t.Fatal("unavailable policy invented audit relationships")
	}
}
