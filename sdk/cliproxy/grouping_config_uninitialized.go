package cliproxy

import (
	"bytes"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

// writeUninitializedGroupingConfig preserves upstream bind-mounted configuration
// support before a grouping policy exists. Initialized policies must use journals.
func writeUninitializedGroupingConfig(change groupingFileChange) error {
	info, err := os.Lstat(change.path)
	if err != nil || !info.Mode().IsRegular() {
		return grouping.ErrUnavailable
	}
	current, err := os.ReadFile(change.path)
	if err != nil {
		return grouping.ErrUnavailable
	}
	if !bytes.Equal(current, change.before) {
		return grouping.ErrConflict
	}
	if err = management.WriteConfig(change.path, change.after); err != nil {
		return grouping.ErrUnavailable
	}
	return nil
}
