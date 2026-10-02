package grouping

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckIntegrityHealthyReadsAndWrites(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	before, _ := store.Snapshot()
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); err != nil {
		t.Fatal(err)
	}
	after, err := store.Snapshot()
	if err != nil || after.Revision != before.Revision || after.Digest != before.Digest {
		t.Fatalf("healthy check changed published policy: %v", err)
	}
	if _, err := hasher("provider", "secret"); err != nil {
		t.Fatalf("healthy check invalidated a request calculator: %v", err)
	}
	if _, err := store.Update(after.Revision, func(next *Snapshot) error {
		_, err := next.CreateGroup("Checked")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); err != nil {
		t.Fatalf("committed update rejected: %v", err)
	}
}

func TestCheckIntegrityRejectsMissingAndCorruptFiles(t *testing.T) {
	for _, name := range []string{"identity.key", "policy.json", ".writer.lock"} {
		for _, operation := range []string{"remove", "corrupt"} {
			if name == ".writer.lock" && operation == "corrupt" {
				continue // Lock content has no policy meaning; its inode is checked separately.
			}
			t.Run(name+"/"+operation, func(t *testing.T) {
				dir := privateTestDir(t)
				store := initializeTestStore(t, dir)
				hasher, err := store.IdentityHasher()
				if err != nil {
					t.Fatal(err)
				}
				alterIntegrityFile(t, filepath.Join(dir, name), operation)
				assertIntegrityFailure(t, store, hasher)
			})
		}
	}
}

func TestCheckIntegrityRejectsReplacedWriterLock(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".writer.lock")
	if err := os.Rename(path, path+".retired"); err != nil {
		t.Skipf("platform prevents open lock replacement: %v", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	assertIntegrityFailure(t, store, hasher)
}

func TestCheckIntegrityRejectsExternalSignedPolicyChange(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	changed, _ := store.Snapshot()
	changed.Revision++
	if err := sealSnapshot(&changed); err != nil {
		t.Fatal(err)
	}
	if err := store.persist(changed); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("external policy was silently adopted: %v", err)
	}
	assertStoreDisabled(t, store)
}

func TestCheckIntegrityRejectsRekeyedSignedPolicy(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	snapshot, _ := store.Snapshot()
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	replacement := &Store{dir: dir, key: bytes.Repeat([]byte{0x42}, 32)}
	if err := os.WriteFile(filepath.Join(dir, "identity.key"), replacement.key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := replacement.persist(snapshot); err != nil {
		t.Fatal(err)
	}
	assertIntegrityFailure(t, store, hasher)
}

func TestCheckIntegrityCannotRecoverFailedStore(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	path := filepath.Join(dir, "identity.key")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing key accepted: %v", err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("restoring disk files silently re-enabled authorization: %v", err)
	}
	assertStoreDisabled(t, store)
}

func TestCheckIntegrityClosedOrAbsentStoreHasNoSideEffects(t *testing.T) {
	var absent *Store
	for _, store := range []*Store{absent, {}} {
		if err := store.CheckIntegrity(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("absent store returned %v", err)
		}
	}
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckIntegrity(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store returned %v", err)
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("check on closed store reacquired the writer lock: %v", err)
	}
	closeTestStore(t, reopened)
}

func alterIntegrityFile(t *testing.T, path, operation string) {
	t.Helper()
	if operation == "remove" {
		if err := os.Remove(path); err != nil {
			if filepath.Base(path) == ".writer.lock" {
				t.Skipf("platform prevents open lock deletion: %v", err)
			}
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("read fixture: %v", err)
	}
	corrupted := bytes.Clone(data)
	corrupted[0] ^= 1
	if err := os.WriteFile(path, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertIntegrityFailure(t *testing.T, store *Store, hasher func(string, string) (string, error)) {
	t.Helper()
	if err := store.CheckIntegrity(); err != ErrUnavailable {
		t.Fatalf("integrity check must return the safe sentinel: %v", err)
	}
	assertStoreDisabled(t, store)
	if _, err := hasher("provider", "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cached calculator survived integrity failure")
	}
	if _, err := store.Update(1, func(*Snapshot) error {
		t.Error("change callback ran after integrity failure")
		return nil
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed store accepted a write: %v", err)
	}
}
