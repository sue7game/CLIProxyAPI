//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package grouping

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func privatePolicyOwnership(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid()) && (directory || stat.Nlink == 1)
}

func privatePolicyDirectory(string) bool { return true }

func privatePolicyHandleAccess(*os.File) bool { return true }

func openPolicyHandle(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), path), nil
}

func acquirePolicyLock(path string) (*os.File, error) {
	file, err := openPolicyLock(path)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func replacePolicyFile(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
