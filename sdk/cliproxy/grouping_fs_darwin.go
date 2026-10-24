package cliproxy

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishGroupingDirectory(source, target string) error {
	if err := unix.RenameatxNp(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_EXCL); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(target))
}
