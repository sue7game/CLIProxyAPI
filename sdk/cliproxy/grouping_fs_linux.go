package cliproxy

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishGroupingDirectory(source, target string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(target))
}
