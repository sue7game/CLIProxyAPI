package cliproxy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func (g *groupingService) canonicalSourcePath(path string) (string, string, error) {
	if g == nil || g.owner == nil || strings.TrimSpace(path) == "" {
		return "", "", grouping.ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", grouping.ErrInvalid
	}
	abs = filepath.Clean(abs)
	configPath, err := canonicalGroupingFilePath(g.owner.configPath)
	if err != nil {
		return "", "", err
	}
	canonical, err := canonicalGroupingFilePath(abs)
	if err != nil {
		return "", "", err
	}
	if canonical == configPath {
		return canonical, "config", nil
	}
	cfg := g.current.Load()
	if cfg == nil || !strings.EqualFold(filepath.Ext(abs), ".json") {
		return "", "", grouping.ErrInvalid
	}
	authDir, err := canonicalGroupingDirectory(cfg.AuthDir)
	if err != nil || filepath.Dir(canonical) != authDir {
		return "", "", grouping.ErrInvalid
	}
	return canonical, "auth", nil
}

func canonicalGroupingFilePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", grouping.ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", grouping.ErrInvalid
	}
	parent, err := canonicalGroupingDirectory(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// canonicalGroupingDirectory rejects a symlink at the configured boundary.
// Physical parent paths are pinned into the signed intent, including OS aliases.
func canonicalGroupingDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", grouping.ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", grouping.ErrInvalid
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", grouping.ErrUnavailable
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", grouping.ErrUnavailable
	}
	physical, err := os.Lstat(resolved)
	if err != nil || !os.SameFile(info, physical) {
		return "", grouping.ErrUnavailable
	}
	return filepath.Clean(resolved), nil
}

func (g *groupingService) validateIntentSource(intent groupingSourceIntent) error {
	path, kind, err := g.canonicalSourcePath(intent.SourcePath)
	if err != nil || path != intent.SourcePath || kind != intent.SourceKind {
		return grouping.ErrUnavailable
	}
	return nil
}

func sourceStateHash(data []byte) string {
	if data == nil {
		return ""
	}
	return groupingSourceDigest(data)
}

func readOptionalSourceFile(path string) ([]byte, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, grouping.ErrUnavailable
	}
	data, err := readSourceTransactionFile(path, 64<<20)
	return data, true, err
}

func (g *groupingService) writeIntentSource(intent groupingSourceIntent, change groupingFileChange) error {
	if err := g.validateIntentSource(intent); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(intent.SourcePath))
	if err != nil || !parent.IsDir() {
		return grouping.ErrUnavailable
	}
	if change.path != intent.SourcePath || sourceStateHash(change.before) != intent.BeforeHash ||
		sourceStateHash(change.after) != intent.AfterHash || (change.before != nil) != intent.BeforeExists {
		return grouping.ErrInvalid
	}
	if err := writeGroupingSource(change); err != nil {
		return grouping.ErrUnavailable
	}
	if err := g.validateIntentSource(intent); err != nil {
		return err
	}
	current, err := os.Lstat(filepath.Dir(intent.SourcePath))
	if err != nil || !os.SameFile(parent, current) {
		return grouping.ErrUnavailable
	}
	data, err := readSourceTransactionFile(intent.SourcePath, 64<<20)
	if err != nil || !bytes.Equal(data, change.after) {
		return grouping.ErrUnavailable
	}
	return nil
}

func readSourceTransactionFile(path string, limit int64) (data []byte, err error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, grouping.ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, grouping.ErrUnavailable
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			data, err = nil, grouping.ErrUnavailable
		}
	}()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, grouping.ErrUnavailable
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, grouping.ErrUnavailable
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) || !current.Mode().IsRegular() {
		return nil, grouping.ErrUnavailable
	}
	return data, nil
}
