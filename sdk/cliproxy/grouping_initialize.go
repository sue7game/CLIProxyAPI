package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func (g *groupingService) initialize(ctx context.Context) (groupingapi.Status, error) {
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	cfg, auths, result, err := g.initializeLocked(ctx)
	g.mu.Unlock()
	if err != nil {
		return groupingapi.Status{}, err
	}
	if err := g.publishSources(ctx, cfg, auths); err != nil {
		return groupingapi.Status{}, err
	}
	if !g.owner.applyConfigUpdateTransaction(ctx, cfg, true) {
		return groupingapi.Status{}, grouping.ErrUnavailable
	}
	g.notify()
	return result, nil
}

func (g *groupingService) initializeLocked(ctx context.Context) (*config.Config, []*coreauth.Auth, groupingapi.Status, error) {
	empty := groupingapi.Status{}
	if ctx.Err() != nil {
		return nil, nil, empty, ctx.Err()
	}
	if g.closed || g.enabled.Load() || g.store != nil || g.hasInstallationReceipt() {
		return nil, nil, empty, grouping.ErrConflict
	}
	if _, err := os.Lstat(g.path); !errors.Is(err, os.ErrNotExist) {
		return nil, nil, empty, grouping.ErrConflict
	}
	cfg := g.current.Load()
	if cfg == nil {
		return nil, nil, empty, grouping.ErrUnavailable
	}
	if err := g.validateLocalConfig(cfg); err != nil {
		return nil, nil, empty, err
	}
	working, configChange, err := prepareGroupingConfig(g.owner.configPath, cfg)
	if err != nil {
		return nil, nil, empty, err
	}
	changes, err := prepareGroupingFileIDs(working.AuthDir)
	if err != nil {
		return nil, nil, empty, err
	}
	auths, err := g.collectSources(working, changes)
	if err != nil {
		return nil, nil, empty, err
	}
	store, err := g.initializeSourcePolicy(working, auths, append([]groupingFileChange{*configChange}, changes...))
	if err != nil {
		return nil, nil, empty, err
	}
	g.store = store
	g.installed = true
	snapshot, err := store.Snapshot()
	if err != nil {
		return nil, nil, empty, err
	}
	g.current.Store(working.CloneForRuntime())
	g.startMonitor(g.owner.groupingContext())
	return working, auths, groupingapi.Status{Initialized: true, Healthy: true, Revision: snapshot.Revision, Namespace: snapshot.Namespace}, nil
}

func (s *Service) groupingContext() context.Context {
	if s.grouping != nil && s.grouping.context != nil {
		return s.grouping.context
	}
	return context.Background()
}

func (g *groupingService) validateActivationSources(cfg *config.Config) ([]*coreauth.Auth, error) {
	if err := g.validateLocalConfig(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidateGroupingCredentialIDs(cfg); err != nil {
		return nil, err
	}
	changes, err := prepareGroupingFileIDs(cfg.AuthDir)
	if err != nil || len(changes) != 0 {
		return nil, fmt.Errorf("grouping: source identity initialization is incomplete")
	}
	auths, err := g.collectSources(cfg, nil)
	if err != nil {
		return nil, err
	}
	identities, err := g.initialIdentities(cfg, auths)
	if err != nil {
		return nil, err
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return nil, err
	}
	for _, source := range identities {
		if !registeredGroupingSource(snapshot, source) {
			return nil, fmt.Errorf("grouping: source requires explicit identity reconciliation")
		}
	}
	return auths, nil
}

func registeredGroupingSource(snapshot grouping.Snapshot, source grouping.Identity) bool {
	if source.Kind == grouping.Credential {
		identity, ok := snapshot.Identities[source.ID]
		return ok && identity.Kind == source.Kind && identity.Provider == source.Provider && identity.Fingerprint == source.Fingerprint && identity.State == grouping.Active
	}
	count := 0
	for _, identity := range snapshot.Identities {
		if identity.Kind == source.Kind && identity.Provider == source.Provider && identity.Fingerprint == source.Fingerprint && identity.State == grouping.Active {
			count++
		}
	}
	return count == 1
}
