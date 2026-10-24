package cliproxy

import (
	"bytes"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func prepareManagedGroupingConfig(path string, request management.ConfigApplyRequest, proposed *config.Config, initialized bool) (*groupingFileChange, error) {
	before, err := os.ReadFile(path)
	if err != nil {
		return nil, grouping.ErrUnavailable
	}
	if initialized {
		if err := validateManagedGroupingSourceDocument(before, request.Current); err != nil {
			return nil, err
		}
	}
	if request.CanonicalYAML == nil && request.SourceYAML == nil {
		return prepareGroupingConfigWrite(path, before, proposed)
	}
	if request.CanonicalYAML == nil || request.SourceYAML == nil || !bytes.Equal(before, request.SourceYAML) {
		return nil, grouping.ErrConflict
	}
	after := bytes.Clone(request.CanonicalYAML)
	if initialized {
		after, err = config.PrepareGroupingConfigDocument(after, proposed)
		if err != nil {
			return nil, grouping.ErrConflict
		}
	}
	return &groupingFileChange{path: path, before: before, after: after}, nil
}
