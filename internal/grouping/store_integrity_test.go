package grouping

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreDiskLossDisablesUpdates(t *testing.T) {
	for _, name := range []string{"identity.key", "policy.json", ".writer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			snapshot, _ := store.Snapshot()
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			_, err := store.Update(snapshot.Revision, func(*Snapshot) error {
				t.Error("change ran after backing data disappeared")
				return nil
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("missing data did not reject write: %v", err)
			}
			assertStoreDisabled(t, store)
		})
	}
}

func TestStoreDiskCorruptionDisablesUpdates(t *testing.T) {
	for _, name := range []string{"identity.key", "policy.json"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			before, _ := store.Snapshot()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Update(before.Revision, func(*Snapshot) error { return nil }); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("corrupt backing data accepted: %v", err)
			}
			assertStoreDisabled(t, store)
		})
	}
}

func TestStoreWriterLockReplacementDisablesUpdates(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	lock := filepath.Join(dir, ".writer.lock")
	if err := os.Rename(lock, lock+".retired"); err != nil {
		t.Skipf("platform prevents replacement of an open writer lock: %v", err)
	}
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(1, func(*Snapshot) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replacement writer lock accepted: %v", err)
	}
	assertStoreDisabled(t, store)
}

func TestStoreUncertainCommitDisablesReadsUntilReopen(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	before, _ := store.Snapshot()
	persist := store.writeSnapshot
	store.writeSnapshot = func(snapshot Snapshot) error {
		if err := persist(snapshot); err != nil {
			return err
		}
		return errors.New("injected error after successful replacement")
	}
	if _, err := store.Update(before.Revision, func(*Snapshot) error { return nil }); err == nil {
		t.Fatal("uncertain commit reported success")
	}
	assertStoreDisabled(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, reopened)
	after, err := reopened.Snapshot()
	if err != nil || after.Revision != before.Revision+1 {
		t.Fatalf("failed to recover durable revision: %v", err)
	}
}

func TestStorePublishedSnapshotsHaveNoCallerAliases(t *testing.T) {
	initial := NewSnapshot()
	identity := testIdentity(Credential, "same-secret-fingerprint")
	if err := initial.Register(identity); err != nil {
		t.Fatal(err)
	}
	store, err := InitializeStore(privateTestDir(t), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, store)
	delete(initial.Identities, identity.ID)
	var retained *Snapshot
	updated, err := store.Update(initial.Revision, func(s *Snapshot) error { retained = s; return nil })
	if err != nil {
		t.Fatal(err)
	}
	delete(retained.Identities, identity.ID)
	delete(updated.Identities, identity.ID)
	copy, _ := store.Snapshot()
	delete(copy.Identities, identity.ID)
	got, err := store.Snapshot()
	if err != nil || len(got.Identities) != 1 || got.Identities[identity.ID] != identity {
		t.Fatalf("caller alias changed published snapshot: %v", err)
	}
}

func assertStoreDisabled(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed store still exposes a policy snapshot")
	}
	if _, err := store.Fingerprint("test", "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed store still derives identities")
	}
}

func closeTestStore(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Error(err)
	}
}
