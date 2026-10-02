//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package grouping

import (
	"errors"
	"os"
)

func privatePolicyOwnership(os.FileInfo, bool) bool { return false }

func privatePolicyDirectory(string) bool { return false }

func privatePolicyHandleAccess(*os.File) bool { return false }

func openPolicyHandle(string, int) (*os.File, error) { return nil, ErrUnavailable }

func acquirePolicyLock(string) (*os.File, error) {
	return nil, errors.New("grouping: local policy locking is unsupported on this platform")
}

func replacePolicyFile(string, string) error {
	return errors.New("grouping: atomic local policy writes are unsupported on this platform")
}
