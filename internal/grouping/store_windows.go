package grouping

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func privatePolicyOwnership(os.FileInfo, bool) bool { return true }

func openPolicyHandle(path string, flags int) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	access, creation := uint32(windows.GENERIC_READ), uint32(windows.OPEN_EXISTING)
	sharing := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if flags&os.O_CREATE != 0 {
		access |= windows.GENERIC_WRITE
		creation, sharing = windows.OPEN_ALWAYS, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE
	}
	handle, err := windows.CreateFile(name, access, sharing, nil, creation, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(handle), path), nil
}

func acquirePolicyLock(path string) (*os.File, error) {
	file, err := openPolicyLock(path)
	if err != nil {
		return nil, err
	}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func replacePolicyFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
