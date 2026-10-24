package grouping

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func atomicPolicyWrite(dir, name string, data []byte) (err error) {
	file, err := os.CreateTemp(dir, ".policy-write-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if errRemove := os.Remove(temp); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("grouping: remove temporary snapshot: %w", errRemove))
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	err = file.Close()
	closed = true
	if err != nil {
		return err
	}
	return replacePolicyFile(temp, filepath.Join(dir, name))
}
