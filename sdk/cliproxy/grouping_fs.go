package cliproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareGroupingSourceTemp(path string, data []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".grouping-source-*")
	if err != nil {
		return "", fmt.Errorf("grouping: cannot prepare source update")
	}
	name := file.Name()
	if err := writeGroupingTemp(file, data); err != nil {
		return "", errors.Join(err, removeGroupingTemporary(name))
	}
	return name, nil
}

func removeGroupingTemporary(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("grouping: cannot remove source temporary file")
	}
	return nil
}

func removeGroupingFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("grouping: journal must be a regular file")
	}
	return removeGroupingFileDurably(path)
}
