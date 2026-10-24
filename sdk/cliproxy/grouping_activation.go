package cliproxy

import (
	"context"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func (g *groupingService) activate(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	release := g.owner.beginManagementConfigMutation()
	defer release()
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	cfg, result, err := g.activateLocked(ctx, expected, mutation)
	g.mu.Unlock()
	g.notify()
	if err != nil {
		return groupingapi.ApplyResult{}, err
	}
	if !g.owner.applyConfigUpdateTransaction(ctx, cfg, true) {
		return groupingapi.ApplyResult{}, grouping.ErrUnavailable
	}
	return result, nil
}

func (g *groupingService) activateLocked(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (*config.Config, groupingapi.ApplyResult, error) {
	empty := groupingapi.ApplyResult{}
	if !g.healthy() || g.closed {
		return nil, empty, grouping.ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil, empty, ctx.Err()
	}
	if err := g.sourceTransactionIdle(); err != nil {
		return nil, empty, err
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return nil, empty, err
	}
	if snapshot.Revision != expected {
		return nil, empty, grouping.ErrRevision
	}
	if !mutation.Enabled && g.enabled.Load() && !mutation.ConfirmPermissionExpansion {
		return nil, empty, grouping.ErrConflict
	}
	cfg := g.current.Load().CloneForRuntime()
	if cfg == nil {
		return nil, empty, grouping.ErrUnavailable
	}
	cfg.Grouping.Enabled = mutation.Enabled
	if mutation.Enabled {
		if g.owner.server != nil {
			release, err := g.owner.server.BeginCredentialAccessActivation()
			if err != nil {
				return nil, empty, err
			}
			defer release()
		}
		if _, err := g.validateActivationSources(cfg); err != nil {
			return nil, empty, err
		}
	}
	if mutation.Enabled == g.enabled.Load() {
		return cfg, groupingapi.ApplyResult{AppliedRevision: expected, Enabled: &mutation.Enabled}, nil
	}
	result, err := g.commitActivation(cfg, expected, mutation.Enabled)
	return cfg, result, err
}

func (g *groupingService) commitActivation(cfg *config.Config, expected uint64, enabled bool) (groupingapi.ApplyResult, error) {
	empty := groupingapi.ApplyResult{}
	before, err := os.ReadFile(g.owner.configPath)
	if err != nil {
		return empty, grouping.ErrUnavailable
	}
	change, err := prepareGroupingActivationConfig(g.owner.configPath, before, cfg)
	if err != nil {
		return empty, err
	}
	if err := g.prepareActivationIntent(expected, enabled, *change); err != nil {
		return empty, err
	}
	// Once a durable intent exists, uncertain activation must not leave an
	// unprotected process running. Recovery is explicit on the next startup.
	if enabled {
		g.installPolicy()
	}
	next, err := g.store.Update(expected, func(*grouping.Snapshot) error { return nil })
	if err != nil {
		return empty, g.failActivation()
	}
	if err := writeGroupingSource(*change); err != nil {
		return empty, g.failActivation()
	}
	if err := g.finishActivationIntent(); err != nil {
		return empty, g.failActivation()
	}
	cfg.SourceHash = internalconfig.ComputeSourceHash(change.after)
	g.current.Store(cfg.CloneForRuntime())
	g.enabled.Store(enabled)
	if enabled {
		g.installPolicy()
	} else if g.owner.coreManager != nil {
		g.owner.coreManager.SetCredentialAccessPolicy(nil)
	}
	return groupingapi.ApplyResult{AppliedRevision: next.Revision, Enabled: &enabled}, nil
}

func (g *groupingService) failActivation() error {
	g.unavailable.Store(true)
	if err := g.store.Close(); err != nil {
		return err
	}
	return grouping.ErrUnavailable
}

func (g *groupingService) rebind(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.healthy() || g.closed {
		return groupingapi.ApplyResult{}, grouping.ErrUnavailable
	}
	if !mutation.Confirm || ctx.Err() != nil {
		return groupingapi.ApplyResult{}, grouping.ErrInvalid
	}
	if err := g.sourceTransactionIdle(); err != nil {
		return groupingapi.ApplyResult{}, err
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return groupingapi.ApplyResult{}, err
	}
	if snapshot.Revision != expected {
		return groupingapi.ApplyResult{}, grouping.ErrRevision
	}
	old, ok := snapshot.Identities[mutation.ID]
	if !ok || old.State != grouping.PendingRebind {
		return groupingapi.ApplyResult{}, grouping.ErrConflict
	}
	fingerprint, err := g.currentSourceFingerprint(old)
	if err != nil {
		return groupingapi.ApplyResult{}, err
	}
	next, err := g.store.Update(expected, func(snapshot *grouping.Snapshot) error {
		return snapshot.ReplaceIdentity(old.ID, old.Fingerprint, fingerprint)
	})
	if err != nil {
		return groupingapi.ApplyResult{}, err
	}
	return groupingapi.ApplyResult{AppliedRevision: next.Revision}, nil
}

func (g *groupingService) currentSourceFingerprint(identity grouping.Identity) (string, error) {
	cfg := g.current.Load()
	auths, err := g.collectSources(cfg, nil)
	if err != nil {
		return "", err
	}
	sources, err := g.initialIdentities(cfg, auths)
	if err != nil {
		return "", err
	}
	for _, source := range sources {
		if source.Kind != identity.Kind || source.Provider != identity.Provider {
			continue
		}
		if source.Kind == grouping.Credential && source.ID == identity.ID {
			return source.Fingerprint, nil
		}
		if source.Kind == grouping.Token && source.Fingerprint == identity.Fingerprint {
			return source.Fingerprint, nil
		}
	}
	return "", grouping.ErrNotFound
}
