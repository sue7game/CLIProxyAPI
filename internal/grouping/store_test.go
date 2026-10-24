package grouping

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreExplicitInitializeAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	if store, err := OpenStore(dir); err == nil || store != nil {
		t.Fatal("missing policy was automatically initialized")
	}
	store, err := InitializeStore(dir, NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Snapshot()
	fingerprint, err := store.Fingerprint("provider", "example-secret")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(before.Revision, func(s *Snapshot) error { _, e := s.CreateGroup("A"); return e })
	if err != nil || updated.Revision != before.Revision+1 || updated.Digest == before.Digest {
		t.Fatalf("update: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	got, _ := store.Snapshot()
	afterFingerprint, _ := store.Fingerprint("provider", "example-secret")
	if got.Revision != updated.Revision || got.Digest != updated.Digest || fingerprint != afterFingerprint {
		t.Fatal("restart lost persisted policy or identity key")
	}
	if _, err := InitializeStore(dir, NewSnapshot()); err == nil {
		t.Fatal("initialization overwrote existing policy")
	}
}

func TestStoreRejectsConcurrentWriters(t *testing.T) {
	dir := privateTestDir(t)
	first, err := InitializeStore(dir, NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := OpenStore(dir)
	if err == nil || second != nil {
		t.Fatal("second writer acquired the same policy directory")
	}
}

func TestStoreOptimisticConcurrencyAndFailedWrite(t *testing.T) {
	store, err := InitializeStore(privateTestDir(t), NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	before, _ := store.Snapshot()
	if _, err := store.Update(before.Revision+1, func(*Snapshot) error { t.Fatal("stale operation executed"); return nil }); !errors.Is(err, ErrRevision) {
		t.Fatalf("revision conflict: %v", err)
	}
	store.writeSnapshot = func(Snapshot) error { return errors.New("injected disk failure") }
	if _, err := store.Update(before.Revision, func(s *Snapshot) error { _, e := s.CreateGroup("B"); return e }); err == nil {
		t.Fatal("disk failure returned success")
	}
	if _, err := store.Snapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uncertain write left an authorizing snapshot")
	}
}

func TestStoreMissingKeyAndCorruptionFailClosed(t *testing.T) {
	for _, file := range []string{"identity.key", "policy.json"} {
		t.Run(file, func(t *testing.T) {
			dir := privateTestDir(t)
			store, err := InitializeStore(dir, NewSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if next, err := OpenStore(dir); err == nil || next != nil {
				t.Fatal("corrupt policy was accepted")
			}
		})
	}
}
