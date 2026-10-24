package store

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/storage/filesystem/dotgit"
)

func isRepositoryCorruptionError(err error) bool {
	if errors.Is(err, dotgit.ErrPackfileNotFound) || errors.Is(err, plumbing.ErrObjectNotFound) {
		return true
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || !errors.Is(pathErr.Err, fs.ErrNotExist) {
		return false
	}
	// go-git v6 may return a wrapped stat error instead of ErrPackfileNotFound.
	// Restrict recovery to missing Git pack artifacts, not arbitrary missing files.
	return isGitPackArtifactPath(pathErr.Path)
}

func isGitPackArtifactPath(path string) bool {
	if filepath.Clean(path) != path {
		return false
	}
	directory := filepath.Dir(path)
	if filepath.Base(directory) != "pack" || filepath.Base(filepath.Dir(directory)) != "objects" {
		return false
	}
	name := filepath.Base(path)
	extension := filepath.Ext(name)
	if !strings.HasPrefix(name, "pack-") || (extension != ".pack" && extension != ".idx") {
		return false
	}
	hash := strings.TrimSuffix(strings.TrimPrefix(name, "pack-"), extension)
	if len(hash) != 40 && len(hash) != 64 {
		return false
	}
	for _, char := range hash {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
