package grouping

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"runtime"
)

func privatePolicyInfo(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return false
	}
	if !directory && !info.Mode().IsRegular() {
		return false
	}
	// Windows access is controlled by ACLs, not the synthetic POSIX mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return false
	}
	return privatePolicyOwnership(info, directory)
}

func checkedPolicyDirectory(dir string) (string, os.FileInfo, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	info, err := os.Lstat(absolute)
	if err != nil || !privatePolicyInfo(info, true) {
		return "", nil, ErrUnavailable
	}
	if !privatePolicyDirectory(absolute) {
		return "", nil, ErrUnavailable
	}
	return absolute, info, nil
}

func checkPolicyHandle(file *os.File, path string) error {
	info, err := file.Stat()
	if err != nil || !privatePolicyInfo(info, false) {
		return ErrUnavailable
	}
	entry, err := os.Lstat(path)
	if err != nil || !privatePolicyInfo(entry, false) || !os.SameFile(info, entry) {
		return ErrUnavailable
	}
	if !privatePolicyHandleAccess(file) {
		return ErrUnavailable
	}
	return nil
}

func openPolicyLock(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && !privatePolicyInfo(info, false) {
		return nil, ErrUnavailable
	} else if err != nil && !os.IsNotExist(err) {
		return nil, ErrUnavailable
	}
	file, err := openPolicyHandle(path, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := checkPolicyHandle(file, path); err != nil {
		return nil, closeFailedPolicy(file, err)
	}
	return file, nil
}

func closeFailedPolicy(file *os.File, err error) error {
	if errClose := file.Close(); errClose != nil {
		return ErrUnavailable
	}
	return err
}

func (s *Store) checkStorage(current *Snapshot) error {
	_, info, err := checkedPolicyDirectory(s.dir)
	if err != nil || !os.SameFile(info, s.dirInfo) || s.lock == nil {
		return ErrUnavailable
	}
	if err := checkPolicyHandle(s.lock, filepath.Join(s.dir, ".writer.lock")); err != nil {
		return err
	}
	disk := &Store{dir: s.dir}
	if err := disk.load(); err != nil {
		return ErrUnavailable
	}
	defer clear(disk.key)
	loaded := disk.current.Load()
	if !hmac.Equal(s.key, disk.key) || current.Namespace != loaded.Namespace ||
		current.Revision != loaded.Revision || current.Digest != loaded.Digest {
		return ErrUnavailable
	}
	return nil
}
