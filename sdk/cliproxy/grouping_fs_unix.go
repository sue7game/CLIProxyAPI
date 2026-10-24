//go:build !windows

package cliproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func secureGroupingTemp(file *os.File) error {
	return file.Chmod(0600)
}

func replaceGroupingFile(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(target))
}

func publishNewGroupingFile(source, target string) error {
	// A link is an exclusive create even if the target appeared after preflight.
	if err := os.Link(source, target); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(target))
}

func removeGroupingFileDurably(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncGroupingDirectory(filepath.Dir(path))
}

func syncGroupingDirectory(path string) (err error) {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("grouping: cannot open source directory for sync")
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		return fmt.Errorf("grouping: source sync path is not a directory")
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("grouping: cannot sync source directory")
	}
	return nil
}
