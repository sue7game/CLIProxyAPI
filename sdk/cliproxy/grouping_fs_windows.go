package cliproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func replaceGroupingFile(source, target string) error {
	return moveGroupingWindows(source, target, windows.MOVEFILE_REPLACE_EXISTING)
}

func publishNewGroupingFile(source, target string) error {
	return moveGroupingWindows(source, target, 0)
}

func publishGroupingDirectory(source, target string) error {
	return moveGroupingWindows(source, target, 0)
}

func moveGroupingWindows(source, target string, flags uint32) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	// Match internal/grouping: file data is synced before a write-through move.
	// Never use COPY_ALLOWED: cross-volume copy/delete is not an atomic publish.
	return windows.MoveFileEx(from, to, flags|windows.MOVEFILE_WRITE_THROUGH)
}

func removeGroupingFileDurably(path string) error {
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	retired := filepath.Join(filepath.Dir(path), ".grouping-retired-"+id.String())
	// Windows has no equivalent of POSIX directory fsync. First durably retire
	// the active journal name; an orphaned retired file cannot be replayed.
	if err := moveGroupingWindows(path, retired, 0); err != nil {
		return err
	}
	return os.Remove(retired)
}

func syncGroupingDirectory(string) error {
	// Callers must use durable publish/remove helpers, never pretend that a
	// failed FlushFileBuffers on a Windows directory established durability.
	return fmt.Errorf("grouping: Windows directory sync requires a write-through publication: %w", errors.ErrUnsupported)
}
