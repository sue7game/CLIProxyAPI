package cliproxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

var errGroupingSourcePending = errors.New("grouping: source transaction is pending")

func (g *groupingService) validateReload(cfg *config.Config) error {
	if cfg.Grouping.Enabled != g.enabled.Load() {
		return fmt.Errorf("grouping: activation changes require the revision-checked management endpoint")
	}
	if groupingStorePath(g.owner.configPath, cfg) != g.path {
		return fmt.Errorf("grouping: changing the policy directory requires a restart")
	}
	if cfg.Grouping.Enabled {
		return g.validateLocalConfig(cfg)
	}
	return nil
}

func (g *groupingService) reconcileSources(ctx context.Context, cfg *config.Config) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reconcileSourcesLocked(ctx, cfg)
}

func (g *groupingService) reconcileSourcesLocked(ctx context.Context, cfg *config.Config) error {
	if g.closed {
		return grouping.ErrUnavailable
	}
	if g.sourcePending {
		return errGroupingSourcePending
	}
	if g.store == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	auths, err := g.collectSources(cfg, nil)
	if err != nil {
		return err
	}
	sources, err := g.initialIdentities(cfg, auths)
	if err != nil {
		return err
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return err
	}
	changes := reconcileGroupingIdentities(snapshot, sources, grouping.PendingRebind)
	if !changes {
		g.refreshCatalog(cfg, auths)
		return nil
	}
	_, err = g.store.Update(snapshot.Revision, func(current *grouping.Snapshot) error {
		reconcileGroupingIdentities(*current, sources, grouping.PendingRebind)
		return nil
	})
	if err == nil {
		g.refreshCatalog(cfg, auths)
	}
	return err
}

func (g *groupingService) reconcileRuntimeSources(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.sourcePending {
		// A staged OAuth identity may not have a physical file yet. Keep its
		// signed policy unchanged; runtime updates remain subject to that policy.
		g.mu.Unlock()
		return nil
	}
	err := g.reconcileSourcesLocked(ctx, g.current.Load())
	g.mu.Unlock()
	g.sourcesUnavailable.Store(err != nil)
	g.notify()
	return err
}

func reconcileGroupingIdentities(snapshot grouping.Snapshot, sources []grouping.Identity, newState grouping.RegistrationState) bool {
	seen := make(map[string]bool, len(sources))
	changed := false
	for _, source := range sources {
		if source.Kind == grouping.Token {
			source.ID = existingGroupingTokenID(snapshot, source)
		}
		seen[source.ID] = true
		old, ok := snapshot.Identities[source.ID]
		if !ok {
			source.State = newState
			snapshot.Identities[source.ID] = source
			changed = true
			continue
		}
		if old.State == grouping.Tombstone || (old.State == grouping.Active && (old.Fingerprint != source.Fingerprint || old.Provider != source.Provider || old.Kind != source.Kind)) {
			old.State = grouping.PendingRebind
			snapshot.Identities[old.ID] = old
			changed = true
		}
	}
	for id, identity := range snapshot.Identities {
		if seen[id] || identity.State == grouping.Tombstone {
			continue
		}
		identity.State = grouping.Tombstone
		snapshot.Identities[id] = identity
		changed = true
	}
	return changed
}

func existingGroupingTokenID(snapshot grouping.Snapshot, source grouping.Identity) string {
	for _, identity := range snapshot.Identities {
		if identity.Kind == grouping.Token && identity.Provider == source.Provider && identity.Fingerprint == source.Fingerprint {
			return identity.ID
		}
	}
	return source.ID
}
