package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/storage/filesystem/dotgit"
)

func TestIsRepositoryCorruptionError(t *testing.T) {
	packName := "pack-" + strings.Repeat("a", 40)
	packPath := filepath.Join("objects", "pack", packName+".pack")
	missing := func(path string) error {
		return fmt.Errorf("packhandle: pack size: %w", &os.PathError{Op: "statat", Path: path, Err: os.ErrNotExist})
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil"},
		{name: "missing pack sentinel", err: dotgit.ErrPackfileNotFound, want: true},
		{name: "wrapped object sentinel", err: fmt.Errorf("commit: %w", plumbing.ErrObjectNotFound), want: true},
		{name: "missing pack stat", err: missing(packPath), want: true},
		{name: "absolute pack path", err: missing(filepath.Join(t.TempDir(), ".git", packPath)), want: true},
		{name: "wrapped missing index", err: fmt.Errorf("read index: %w", missing(filepath.Join("objects", "pack", packName+".idx"))), want: true},
		{name: "sha256 pack", err: missing(filepath.Join("objects", "pack", "pack-"+strings.Repeat("b", 64)+".pack")), want: true},
		{name: "bare missing error", err: os.ErrNotExist},
		{name: "text without cause", err: errors.New("packhandle: pack size: statat " + packPath + ": no such file or directory")},
		{name: "permission denied", err: &os.PathError{Op: "statat", Path: packPath, Err: os.ErrPermission}},
		{name: "unrelated stat failure", err: &os.PathError{Op: "statat", Path: packPath, Err: errors.New("I/O error")}},
		{name: "missing worktree config", err: missing(filepath.Join("config", "config.yaml"))},
		{name: "missing git config", err: missing(filepath.Join(".git", "config"))},
		{name: "missing worktree index", err: missing(filepath.Join(".git", "index"))},
		{name: "missing loose object", err: missing(filepath.Join("objects", "aa", strings.Repeat("a", 38)))},
		{name: "missing reverse index", err: missing(filepath.Join("objects", "pack", packName+".rev"))},
		{name: "incorrect directory", err: missing(filepath.Join("config", "pack", packName+".pack"))},
		{name: "incorrect filename prefix", err: missing(filepath.Join("objects", "pack", "data-"+strings.Repeat("a", 40)+".pack"))},
		{name: "short hash", err: missing(filepath.Join("objects", "pack", "pack-"+strings.Repeat("a", 39)+".pack"))},
		{name: "long hash", err: missing(filepath.Join("objects", "pack", "pack-"+strings.Repeat("a", 65)+".pack"))},
		{name: "nonhex hash", err: missing(filepath.Join("objects", "pack", "pack-"+strings.Repeat("z", 40)+".pack"))},
		{name: "unclean path", err: missing(filepath.Join("objects", "pack") + string(filepath.Separator) + ".." + string(filepath.Separator) + "pack" + string(filepath.Separator) + packName + ".pack")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRepositoryCorruptionError(tt.err); got != tt.want {
				t.Fatalf("isRepositoryCorruptionError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func corruptGitRepository(t *testing.T, repoDir string) {
	t.Helper()

	repackGitRepository(t, repoDir)
	removeGitObjectFiles(t, repoDir)
	// Reopening avoids reusing cached objects or handles for the removed pack.
	repo, errOpen := git.PlainOpen(repoDir)
	if errOpen != nil {
		t.Fatalf("reopen corrupted repository: %v", errOpen)
	}
	defer func() {
		if errClose := repo.Close(); errClose != nil {
			t.Errorf("close corrupted repository: %v", errClose)
		}
	}()
	if errVerify := verifyRepositoryHead(repo); !isRepositoryCorruptionError(errVerify) {
		t.Fatalf("verifyRepositoryHead error = %v, want repository corruption", errVerify)
	}
}

func repackGitRepository(t *testing.T, repoDir string) {
	t.Helper()

	repo, errOpen := git.PlainOpen(repoDir)
	if errOpen != nil {
		t.Fatalf("open repository before repack: %v", errOpen)
	}
	defer func() {
		if errClose := repo.Close(); errClose != nil {
			t.Errorf("close repacked repository: %v", errClose)
		}
	}()
	if errRepack := repo.RepackObjects(&git.RepackConfig{}); errRepack != nil {
		t.Fatalf("repack repository objects: %v", errRepack)
	}
}

func removeGitObjectFiles(t *testing.T, repoDir string) {
	t.Helper()

	objectsDir := filepath.Join(repoDir, ".git", "objects")
	objectEntries, errReadDir := os.ReadDir(objectsDir)
	if errReadDir != nil {
		t.Fatalf("read object directory: %v", errReadDir)
	}
	for _, entry := range objectEntries {
		if entry.IsDir() && len(entry.Name()) == 2 {
			if errRemove := os.RemoveAll(filepath.Join(objectsDir, entry.Name())); errRemove != nil {
				t.Fatalf("remove loose object directory %s: %v", entry.Name(), errRemove)
			}
		}
	}
	packfiles, errGlob := filepath.Glob(filepath.Join(objectsDir, "pack", "*.pack"))
	if errGlob != nil {
		t.Fatalf("glob packfiles: %v", errGlob)
	}
	if len(packfiles) == 0 {
		t.Fatal("no packfiles found to corrupt")
	}
	for _, packfile := range packfiles {
		if errRemove := os.Remove(packfile); errRemove != nil {
			t.Fatalf("remove packfile %s: %v", filepath.Base(packfile), errRemove)
		}
	}
}
