package grouping

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckIntegrityRejectsUnsafeFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes do not represent Windows ACLs")
	}
	for _, name := range []string{"identity.key", "policy.json", ".writer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			hasher, err := store.IdentityHasher()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, name), 0644); err != nil {
				t.Fatal(err)
			}
			assertIntegrityFailure(t, store, hasher)
		})
	}
}

func TestCheckIntegrityRejectsSymlinkSubstitution(t *testing.T) {
	for _, name := range []string{"identity.key", "policy.json", ".writer.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			store := initializeTestStore(t, dir)
			hasher, err := store.IdentityHasher()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.Rename(path, path+".retired"); err != nil {
				t.Skipf("platform prevents file replacement: %v", err)
			}
			if err := os.Symlink(path+".retired", path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			assertIntegrityFailure(t, store, hasher)
		})
	}
}
