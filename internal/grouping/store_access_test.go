package grouping

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestStoreAccessMatchesIsolatedSnapshotRules(t *testing.T) {
	for _, state := range []RegistrationState{Active, PendingRebind, Tombstone} {
		for _, duplicate := range []bool{false, true} {
			t.Run(string(state)+map[bool]string{false: "", true: "_duplicate"}[duplicate], func(t *testing.T) {
				snapshot, token, credential := accessFixture(t)
				token.State = state
				snapshot.Identities[token.ID] = token
				if duplicate {
					other := token
					other.ID, other.State = uuid.NewString(), Active
					snapshot.Identities[other.ID] = other
				}
				store := newAccessTestStore(t, snapshot)
				want, wantErr := BeginAccess(snapshot, token.Provider, token.Fingerprint)
				got, gotErr := store.BeginAccess(token.Provider, token.Fingerprint)
				if !errors.Is(gotErr, wantErr) {
					t.Fatalf("cached lookup: %v; isolated lookup: %v", gotErr, wantErr)
				}
				if wantErr == nil && got.Allows(credential.ID, credential.Provider, credential.Fingerprint) != want.Allows(credential.ID, credential.Provider, credential.Fingerprint) {
					t.Fatal("cached and isolated rules differ")
				}
			})
		}
	}
}

func TestStoreAccessPublicationIsIsolatedAndRevocable(t *testing.T) {
	snapshot, token, credential := accessFixture(t)
	store := newAccessTestStore(t, snapshot)
	scope, err := store.BeginAccess(token.Provider, token.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	management, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	delete(snapshot.Identities, credential.ID)
	delete(management.Identities, credential.ID)
	if err := store.AuthorizeUse(scope, credential.ID, credential.Provider, credential.Fingerprint); err != nil {
		t.Fatal("caller mutated the read-only publication", err)
	}
	next, err := store.Update(management.Revision, func(next *Snapshot) error {
		return next.SetIdentityState(credential.ID, Tombstone)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeUse(scope, credential.ID, credential.Provider, credential.Fingerprint); !errors.Is(err, ErrPolicyChanged) {
		t.Fatal("old scope survived policy replacement", err)
	}
	delete(next.Identities, token.ID)
	fresh, err := store.BeginAccess(token.Provider, token.Fingerprint)
	if err != nil {
		t.Fatal("update result aliases publication", err)
	}
	if err := store.AuthorizeUse(fresh, credential.ID, credential.Provider, credential.Fingerprint); !errors.Is(err, ErrDenied) {
		t.Fatal("fresh scope authorized a tombstone", err)
	}
}

func TestStoreAccessRejectsUnavailableAndUnknownPrincipal(t *testing.T) {
	for _, cause := range []string{"close", "write_failure"} {
		t.Run(cause, func(t *testing.T) {
			snapshot, token, credential := accessFixture(t)
			store := newAccessTestStore(t, snapshot)
			scope, err := store.BeginAccess(token.Provider, token.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			for _, ref := range [][2]string{{"", token.Fingerprint}, {token.Provider, ""}, {"missing", token.Fingerprint}, {token.Provider, "missing"}} {
				if _, err := store.BeginAccess(ref[0], ref[1]); !errors.Is(err, ErrUnauthenticated) {
					t.Fatal("unknown principal accepted", err)
				}
			}
			if cause == "close" {
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				store.writeSnapshot = func(Snapshot) error { return errors.New("injected write failure") }
				if _, err := store.Update(snapshot.Revision, func(*Snapshot) error { return nil }); err == nil {
					t.Fatal("write failure was ignored")
				}
			}
			if _, err := store.BeginAccess(token.Provider, token.Fingerprint); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unavailable store issued a scope", err)
			}
			if err := store.AuthorizeUse(scope, credential.ID, credential.Provider, credential.Fingerprint); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unavailable store accepted a retained scope", err)
			}
		})
	}
}

func newAccessTestStore(t *testing.T, snapshot Snapshot) *Store {
	t.Helper()
	store, err := InitializeStore(privateTestDir(t), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}
