//go:build !windows

package cliproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func protectGroupingFSTestDir(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestGroupingFSTemporaryAndPublishedSourceArePrivate(t *testing.T) {
	dir := groupingFSTestDir(t)
	target := filepath.Join(dir, "source.json")
	name, err := prepareGroupingSourceTemp(target, []byte("private-test-source"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{name, target} {
		if path == target {
			if err := publishNewGroupingFile(name, target); err != nil {
				t.Fatal(err)
			}
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("source permissions are not private: %v", err)
		}
	}
}

func TestGroupingFSDirectorySyncFailsForNonDirectory(t *testing.T) {
	dir := groupingFSTestDir(t)
	path := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, filepath.Join(dir, "missing")} {
		if err := syncGroupingDirectory(path); err == nil {
			t.Fatal("invalid directory sync was silently accepted")
		}
	}
}

func TestGroupingFSRejectsSymlinkPublicationAndRemoval(t *testing.T) {
	dir := groupingFSTestDir(t)
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "source.json")
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, before := range [][]byte{nil, []byte("existing")} {
		if err := writeGroupingSource(groupingFileChange{path: link, before: before, after: []byte("replacement")}); err == nil {
			t.Fatal("source publication accepted a symlink")
		}
	}
	if err := removeGroupingFile(link); err == nil {
		t.Fatal("journal removal accepted a symlink")
	}
	assertGroupingFSContent(t, target, []byte("existing"))
	assertGroupingFSOnlyEntries(t, dir, "source.json", "target")
}
