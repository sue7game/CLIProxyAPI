package groupingadmin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestInitializeCallbackOwnsTransactionLock(t *testing.T) {
	var mutex sync.Mutex
	var store *grouping.Store
	dir := filepath.Join(t.TempDir(), "policy")
	notified := false
	backend, err := New(Options{Mutex: &mutex, Store: func() *grouping.Store { return store }, Enabled: func() bool { return false },
		Initialize: func(context.Context) (groupingapi.Status, error) {
			if !mutex.TryLock() {
				t.Error("initializer was called with the management lock held")
				return groupingapi.Status{}, groupingapi.ErrUnavailable
			}
			defer mutex.Unlock()
			var err error
			store, err = grouping.InitializeStore(dir, grouping.NewSnapshot())
			if err != nil {
				return groupingapi.Status{}, err
			}
			snapshot, err := store.Snapshot()
			return groupingapi.Status{Initialized: true, Healthy: true, Revision: snapshot.Revision, Namespace: snapshot.Namespace}, err
		}, OnPolicyChanged: func() {
			if !mutex.TryLock() {
				t.Error("notification was called with the management lock held")
				return
			}
			mutex.Unlock()
			notified = true
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	status, err := backend.Initialize(testContext())
	if err != nil || !status.Initialized || status.Enabled || status.Revision != 1 || !notified {
		t.Fatalf("initialization failed: %+v %v", status, err)
	}
}

func TestActivationCallbackOwnsCASAndExpansionCheck(t *testing.T) {
	f := newFixture(t)
	f.backend.options.Activation = activationCallback(t, f)
	result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Activate, Enabled: true})
	if err != nil || result.AppliedRevision != 2 || !f.enabled || f.notifications.Load() != 1 {
		t.Fatalf("activation failed: %+v %v", result, err)
	}
	f.notifications.Store(0)
	before, data := snapshotOf(t, f), policyBytes(t, f)
	_, err = f.backend.Apply(testContext(), 2, groupingapi.Mutation{Operation: groupingapi.Activate})
	if !errors.Is(err, groupingapi.ErrConflict) || !f.enabled {
		t.Fatalf("unconfirmed disable was accepted: %v", err)
	}
	assertUnchanged(t, f, before, data)
	_, err = f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Activate, Enabled: true})
	if !errors.Is(err, groupingapi.ErrPrecondition) {
		t.Fatalf("stale lifecycle revision accepted: %v", err)
	}
	assertUnchanged(t, f, before, data)
	result, err = f.backend.Apply(testContext(), 2, groupingapi.Mutation{Operation: groupingapi.Activate, ConfirmPermissionExpansion: true})
	if err != nil || result.AppliedRevision != 3 || f.enabled {
		t.Fatalf("confirmed disable failed: %+v %v", result, err)
	}
}

func activationCallback(t *testing.T, f *fixture) func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	t.Helper()
	return func(_ context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		if !f.mutex.TryLock() {
			t.Error("activation callback cannot acquire its transaction lock")
			return groupingapi.ApplyResult{}, groupingapi.ErrUnavailable
		}
		defer f.mutex.Unlock()
		if f.enabled && !mutation.Enabled && !mutation.ConfirmPermissionExpansion {
			return groupingapi.ApplyResult{}, groupingapi.ErrConflict
		}
		snapshot, err := f.store.Update(expected, func(*grouping.Snapshot) error { return nil })
		if err != nil {
			return groupingapi.ApplyResult{}, err
		}
		f.enabled = mutation.Enabled
		return groupingapi.ApplyResult{AppliedRevision: snapshot.Revision, Enabled: &mutation.Enabled}, nil
	}
}

func TestMissingLifecycleCallbacksDoNotInventSuccess(t *testing.T) {
	f := newFixture(t, sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	if _, err := f.backend.Initialize(testContext()); !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatalf("missing initialization callback succeeded: %v", err)
	}
	for _, operation := range []groupingapi.Operation{groupingapi.Activate, groupingapi.Rebind} {
		result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: operation, ID: f.ids["pending"], Confirm: true})
		if !errors.Is(err, groupingapi.ErrUnavailable) || result.AppliedRevision != 0 {
			t.Fatalf("missing lifecycle callback succeeded: %+v %v", result, err)
		}
	}
	assertUnchanged(t, f, before, data)
}

func TestRebindRequiresSuccessfulSourceRevalidation(t *testing.T) {
	f := newFixture(t, sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	verifiedSource := false
	f.backend.options.Rebind = func(_ context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		if !f.mutex.TryLock() {
			t.Error("rebind callback cannot acquire its transaction lock")
			return groupingapi.ApplyResult{}, groupingapi.ErrUnavailable
		}
		defer f.mutex.Unlock()
		if !verifiedSource {
			return groupingapi.ApplyResult{}, errors.New("private source verification details")
		}
		snapshot, err := f.store.Update(expected, func(next *grouping.Snapshot) error {
			identity := next.Identities[mutation.ID]
			if !mutation.Confirm || identity.State != grouping.PendingRebind {
				return grouping.ErrConflict
			}
			return next.ReplaceIdentity(mutation.ID, identity.Fingerprint, "verified-new-fingerprint")
		})
		return groupingapi.ApplyResult{AppliedRevision: snapshot.Revision}, err
	}
	mutation := groupingapi.Mutation{Operation: groupingapi.Rebind, ID: f.ids["pending"], Confirm: true}
	_, err := f.backend.Apply(testContext(), 1, mutation)
	if err != groupingapi.ErrUnavailable {
		t.Fatalf("source verification failure was not safely mapped: %v", err)
	}
	assertUnchanged(t, f, before, data)
	verifiedSource = true
	result, err := f.backend.Apply(testContext(), 1, mutation)
	if err != nil || result.AppliedRevision != 2 || f.notifications.Load() != 1 {
		t.Fatalf("verified rebind failed: %+v %v", result, err)
	}
	identity := snapshotOf(t, f).Identities[mutation.ID]
	if identity.State != grouping.Active || identity.GroupID != f.groups["A"] || identity.Fingerprint != "verified-new-fingerprint" {
		t.Fatal("verified rebind lost identity or grouping state")
	}
}

func TestPolicyChangedRunsAfterUnlockAndCanReadBackend(t *testing.T) {
	f := newFixture(t)
	notified := false
	f.backend.options.OnPolicyChanged = func() {
		if !f.mutex.TryLock() {
			t.Error("ordinary mutation notification held the transaction lock")
			return
		}
		f.mutex.Unlock()
		status, err := f.backend.Status(testContext())
		if err != nil || status.Revision != 2 {
			t.Errorf("notification cannot see committed state: %+v %v", status, err)
		}
		notified = true
	}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "New"})
	if err != nil || !notified {
		t.Fatalf("write returned before notifying observers: %v", err)
	}
}

func TestErrorMappingRemovesInternalDetails(t *testing.T) {
	for internal, public := range map[error]error{
		grouping.ErrUnavailable:        groupingapi.ErrUnavailable,
		grouping.ErrRevision:           groupingapi.ErrPrecondition,
		grouping.ErrConflict:           groupingapi.ErrConflict,
		grouping.ErrNotFound:           groupingapi.ErrConflict,
		grouping.ErrInvalid:            groupingapi.ErrConflict,
		groupingapi.ErrConflict:        groupingapi.ErrConflict,
		groupingapi.ErrPrecondition:    groupingapi.ErrPrecondition,
		groupingapi.ErrUnavailable:     groupingapi.ErrUnavailable,
		errors.New("internal failure"): groupingapi.ErrUnavailable,
	} {
		if got := publicError(fmt.Errorf("secret source details: %w", internal)); got != public {
			t.Fatalf("unsafe error mapping: %v", got)
		}
	}
}
