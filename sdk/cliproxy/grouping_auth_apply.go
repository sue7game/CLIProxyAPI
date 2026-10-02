package cliproxy

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// applyAuthFile owns the complete upload transaction, including synchronous runtime publication.
func (g *groupingService) applyAuthFile(ctx context.Context, path string, raw []byte) error {
	if g == nil || g.owner == nil || ctx == nil {
		return grouping.ErrUnavailable
	}
	defer g.notify()
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	plan, err := g.commitAuthFile(ctx, path, raw)
	g.mu.Unlock()
	if err != nil {
		return err
	}
	return g.publishAuthSource(ctx, plan.auths)
}

func (g *groupingService) commitAuthFile(ctx context.Context, path string, raw []byte) (*groupingAuthSourcePlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.owner.coreManager == nil || g.unavailable.Load() {
		return nil, grouping.ErrUnavailable
	}
	if g.store == nil {
		if err := g.validateAuthLegacyMode(); err != nil {
			return nil, err
		}
		return g.commitLegacyAuthFile(path, raw)
	}
	if err := g.sourceTransactionIdle(); err != nil {
		return nil, err
	}
	if err := g.checkAuthSourceBaseline(); err != nil {
		return nil, err
	}
	canonical, kind, err := g.canonicalSourcePath(path)
	if err != nil || kind != "auth" {
		return nil, grouping.ErrInvalid
	}
	before, _, err := readOptionalSourceFile(canonical)
	if err != nil {
		return nil, g.failAuthSourceValidation()
	}
	after, err := assignGroupingAuthFileID(before, raw)
	if err != nil {
		return nil, err
	}
	plan, err := g.planAuthSource(canonical, before, after)
	if err != nil {
		return nil, err
	}
	if _, err := g.commitSourceTransaction(plan.change, plan.before, plan.after); err != nil {
		return nil, err
	}
	return plan, nil
}

// publishAuthSource runs outside g.mu but inside transactionMu; persisted writes
// must finish publication even when the originating HTTP request is cancelled.
func (g *groupingService) publishAuthSource(ctx context.Context, auths []*coreauth.Auth) error {
	ctx = coreauth.WithSkipPersist(sdkaccess.WithInternalOperation(context.WithoutCancel(ctx), sdkaccess.InternalManagement))
	for _, auth := range auths {
		g.owner.ensureExecutorsForAuthWithContext(ctx, auth, false)
	}
	// The physical directory used for synthesis must not rewrite the configured spelling.
	current := g.current.Load()
	if current == nil {
		return g.failAuthPublication()
	}
	if err := g.publishSources(ctx, current, auths); err != nil {
		return g.failAuthPublication()
	}
	for _, auth := range auths {
		// Persisted watcher revisions prevent a queued older event from reverting this update.
		if err := g.owner.runtimeAuthSyncHook()(ctx, auth); err != nil {
			return g.failAuthPublication()
		}
		current, ok := g.owner.coreManager.GetByID(auth.ID)
		if !ok || current.Provider != auth.Provider || current.Attributes["grouping_id"] != auth.Attributes["grouping_id"] || g.sourcesUnavailable.Load() {
			return g.failAuthPublication()
		}
		if g.store != nil && !g.registeredAuthRuntime(current) {
			return g.failAuthPublication()
		}
	}
	return nil
}

func (g *groupingService) registeredAuthRuntime(auth *coreauth.Auth) bool {
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return false
	}
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return false
	}
	identity, err := groupingCredentialIdentity(auth, hash)
	return err == nil && registeredGroupingSource(snapshot, identity)
}

func (g *groupingService) failAuthPublication() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.unavailable.Store(true)
	if g.store != nil {
		return g.failSourceTransaction()
	}
	return grouping.ErrUnavailable
}

func (g *groupingService) validateAuthLegacyMode() error {
	cfg := g.current.Load()
	if cfg == nil || cfg.Grouping.Enabled || g.enabled.Load() || g.unavailable.Load() || g.closed {
		return grouping.ErrUnavailable
	}
	return nil
}
