package grouping

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStoreRejectsUnsafePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes do not represent Windows ACLs")
	}
	for _, name := range []string{".", "identity.key", "policy.json", ".writer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0644)
			if name == "." {
				mode = 0755
			}
			if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
				t.Fatal(err)
			}
			assertStoreCannotOpen(t, dir)
		})
	}
}

func TestStoreRejectsSymlinks(t *testing.T) {
	for _, name := range []string{"identity.key", "policy.json", ".writer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			target := path + ".original"
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			assertStoreCannotOpen(t, dir)
		})
	}
}

func TestStoreRejectsSymlinkDirectory(t *testing.T) {
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	assertStoreCannotOpen(t, alias)
}

func TestStoreRejectsHardLinkedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link-count validation")
	}
	dir := privateTestDir(t)
	store := initializeTestStore(t, dir)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "identity.key"), filepath.Join(dir, "linked-key")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	assertStoreCannotOpen(t, dir)
}

func TestStoreErrorsDoNotExposePaths(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "sensitive-account-identifier", "missing")
	_, err := OpenStore(secretPath)
	if err == nil || strings.Contains(err.Error(), "sensitive-account-identifier") {
		t.Fatalf("filesystem error disclosed path: %v", err)
	}
	store := initializeTestStore(t, privateTestDir(t))
	snapshot, _ := store.Snapshot()
	store.writeSnapshot = func(Snapshot) error { return errors.New("secret-provider-key") }
	_, err = store.Update(snapshot.Revision, func(*Snapshot) error { return nil })
	if err == nil || strings.Contains(err.Error(), "secret-provider-key") {
		t.Fatalf("write error disclosed sensitive detail: %v", err)
	}
}

func initializeTestStore(t *testing.T, dir string) *Store {
	t.Helper()
	store, err := InitializeStore(dir, NewSnapshot())
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

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertStoreCannotOpen(t *testing.T, dir string) {
	t.Helper()
	store, err := OpenStore(dir)
	if store != nil {
		if errClose := store.Close(); errClose != nil {
			t.Error(errClose)
		}
	}
	if err == nil || store != nil {
		t.Fatal("unsafe policy store was accepted")
	}
}
