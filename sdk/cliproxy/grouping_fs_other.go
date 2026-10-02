//go:build !windows && !darwin && !linux

package cliproxy

import (
	"errors"
	"os"
	"path/filepath"
)

func publishGroupingDirectory(source, target string) error {
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return os.ErrExist
	}
	// Complete policy directories are nonempty, so rename cannot replace another
	// completed installation on platforms without an exclusive directory rename.
	if err := os.Rename(source, target); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(target))
}
