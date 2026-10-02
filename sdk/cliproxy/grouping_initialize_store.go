package cliproxy

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// initializeSourcePolicy publishes a complete policy, never an empty live store.
// Interrupted source UUID writes are idempotent; an unpublished temporary policy
// cannot contain administrator bindings and is never reused automatically.
func (g *groupingService) initializeSourcePolicy(cfg *config.Config, auths []*coreauth.Auth, changes []groupingFileChange) (_ *grouping.Store, err error) {
	parent := filepath.Dir(g.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return nil, grouping.ErrUnavailable
	}
	stage, err := os.MkdirTemp(parent, ".grouping-initialize-*")
	if err != nil {
		return nil, grouping.ErrUnavailable
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	if err := stageGroupingPolicy(stage, cfg, auths); err != nil {
		return nil, err
	}
	for _, change := range changes {
		if err := writeGroupingSource(change); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(g.path); !errors.Is(err, os.ErrNotExist) {
		return nil, grouping.ErrConflict
	}
	if err := publishGroupingDirectory(stage, g.path); err != nil {
		return nil, grouping.ErrUnavailable
	}
	store, err := grouping.OpenStore(g.path)
	if err != nil {
		return nil, err
	}
	if err := g.ensureInstallationReceipt(store); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return store, nil
}

func stageGroupingPolicy(path string, cfg *config.Config, auths []*coreauth.Auth) (err error) {
	store, err := grouping.InitializeStore(path, grouping.NewSnapshot())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	identities, err := groupingSourceIdentities(store, cfg, auths)
	if err != nil {
		return err
	}
	_, err = store.Update(1, func(snapshot *grouping.Snapshot) error {
		for _, identity := range identities {
			if err := snapshot.Register(identity); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
