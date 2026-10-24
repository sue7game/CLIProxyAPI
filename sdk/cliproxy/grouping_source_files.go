package cliproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

type groupingFileChange struct {
	path   string
	before []byte
	after  []byte
}

// prepareGroupingFileIDs plans source-record identities without changing files.
// Partial initialization is safe to retry because persisted IDs are never replaced.
func prepareGroupingFileIDs(dir string) ([]groupingFileChange, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("grouping: cannot read credential directory")
	}
	changes := make([]groupingFileChange, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		change, id, errPrepare := prepareGroupingFile(filepath.Join(dir, entry.Name()))
		if errPrepare != nil {
			return nil, errPrepare
		}
		if id == "" {
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("grouping: duplicate source identity in credential files")
		}
		seen[id] = true
		if change != nil {
			changes = append(changes, *change)
		}
	}
	return changes, nil
}

func prepareGroupingFile(path string) (*groupingFileChange, string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("grouping: credential source must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("grouping: cannot read credential source")
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, "", fmt.Errorf("grouping: invalid credential JSON")
	}
	if _, ok := metadata["type"]; !ok {
		return nil, "", nil
	}
	var id string
	if raw, ok := metadata["grouping_id"]; ok {
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, "", fmt.Errorf("grouping: invalid source identity")
		}
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, "", fmt.Errorf("grouping: invalid source identity")
		}
		return nil, id, nil
	}
	generated, err := uuid.NewRandom()
	if err != nil {
		return nil, "", fmt.Errorf("grouping: cannot generate source identity")
	}
	id = generated.String()
	encodedID, err := json.Marshal(id)
	if err != nil {
		return nil, "", err
	}
	metadata["grouping_id"] = encodedID
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("grouping: cannot encode credential source")
	}
	return &groupingFileChange{path, data, append(updated, '\n')}, id, nil
}

// writeGroupingSource replaces a known source only if it has not changed since read.
func writeGroupingSource(change groupingFileChange) (err error) {
	return withGroupingCredentialFileLock(change, func() error {
		return writeGroupingSourceLocked(change)
	})
}

func writeGroupingSourceLocked(change groupingFileChange) (err error) {
	if change.before == nil {
		return createGroupingSource(change)
	}
	info, err := os.Lstat(change.path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("grouping: source is unavailable or not a regular file")
	}
	current, err := os.ReadFile(change.path)
	if err != nil || !bytes.Equal(current, change.before) {
		return fmt.Errorf("grouping: source changed; retry after reload")
	}
	name, err := prepareGroupingSourceTemp(change.path, change.after)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, removeGroupingTemporary(name)) }()
	currentInfo, err := os.Lstat(change.path)
	if err != nil || !os.SameFile(info, currentInfo) {
		return fmt.Errorf("grouping: source changed during update")
	}
	current, err = os.ReadFile(change.path)
	if err != nil || !bytes.Equal(current, change.before) {
		return fmt.Errorf("grouping: source changed during update")
	}
	if err := replaceGroupingFile(name, change.path); err != nil {
		return fmt.Errorf("grouping: cannot publish source update")
	}
	return nil
}

func createGroupingSource(change groupingFileChange) (err error) {
	if _, err := os.Lstat(change.path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("grouping: new source path already exists or is unavailable")
	}
	name, err := prepareGroupingSourceTemp(change.path, change.after)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, removeGroupingTemporary(name)) }()
	if err := publishNewGroupingFile(name, change.path); err != nil {
		return fmt.Errorf("grouping: cannot exclusively publish new source")
	}
	return nil
}

func writeGroupingTemp(file *os.File, data []byte) (err error) {
	defer func() { err = errors.Join(err, file.Close()) }()
	if err := secureGroupingTemp(file); err != nil {
		return fmt.Errorf("grouping: cannot secure source update")
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("grouping: cannot write source update")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("grouping: cannot sync source update")
	}
	return nil
}
