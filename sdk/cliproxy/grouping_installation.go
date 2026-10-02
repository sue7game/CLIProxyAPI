package cliproxy

import (
	"bytes"
	"errors"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

// The receipt lives beside the policy directory so losing that directory cannot
// turn an existing installation into a fresh all-groups initialization.
func (g *groupingService) installationReceiptPath() string { return g.path + ".initialized" }

func (g *groupingService) hasInstallationReceipt() bool {
	_, err := os.Lstat(g.installationReceiptPath())
	return !errors.Is(err, os.ErrNotExist)
}

func (g *groupingService) ensureInstallationReceipt(store *grouping.Store) error {
	snapshot, err := store.Snapshot()
	if err != nil {
		return err
	}
	path := g.installationReceiptPath()
	want := []byte(snapshot.Namespace + "\n")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > 128 {
			return grouping.ErrUnavailable
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, want) {
			return grouping.ErrUnavailable
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return grouping.ErrUnavailable
	}
	return createGroupingSource(groupingFileChange{path: path, after: want})
}
