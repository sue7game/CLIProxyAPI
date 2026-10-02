package cliproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// prepareOAuthRecord stages a signed, pending source before the caller persists it.
// It does not hold either service lock across the caller's asynchronous save.
func (g *groupingService) prepareOAuthRecord(ctx context.Context, record *coreauth.Auth) error {
	if g == nil || g.owner == nil || ctx == nil || record == nil {
		return grouping.ErrInvalid
	}
	defer g.notify()
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.store == nil {
		return g.validateAuthLegacyMode()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.unavailable.Load() || g.owner.coreManager == nil {
		return grouping.ErrUnavailable
	}
	if err := g.sourceTransactionIdle(); err != nil {
		return err
	}
	if err := g.checkAuthSourceBaseline(); err != nil {
		return err
	}
	plan, prepared, err := g.planOAuthRecord(record)
	if err != nil {
		return err
	}
	intent, staged, err := g.prepareSourceIntent(plan.change, plan.before, plan.after)
	if err != nil {
		return err
	}
	if _, err := g.publishSourcePolicy(plan.before.Revision, staged); err != nil {
		return g.failSourceTransaction()
	}
	storage, err := newGroupingOAuthStorage(g, plan.change, intent, prepared.Metadata)
	if err != nil {
		return g.failSourceTransaction()
	}
	prepared.Storage = storage
	*record = *prepared
	return nil
}

func (g *groupingService) oauthRecordPath(record *coreauth.Auth) (string, error) {
	if record == nil || g.current.Load() == nil {
		return "", grouping.ErrInvalid
	}
	path := strings.TrimSpace(record.Attributes[coreauth.AttributePath])
	if path == "" {
		path = strings.TrimSpace(record.FileName)
		if path == "" {
			path = strings.TrimSpace(record.ID)
		}
		if path == "" {
			return "", grouping.ErrInvalid
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(g.current.Load().AuthDir, path)
		}
	}
	path, kind, err := g.canonicalSourcePath(path)
	if err != nil || kind != "auth" {
		return "", grouping.ErrInvalid
	}
	return path, nil
}

// finalizeOAuthRecord verifies persisted bytes before activating and publishing a source.
// Calling it without prepare may only publish an already registered unchanged identity.
func (g *groupingService) finalizeOAuthRecord(ctx context.Context, record *coreauth.Auth) error {
	if g == nil || g.owner == nil || ctx == nil || record == nil {
		return grouping.ErrInvalid
	}
	defer g.notify()
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	plan, err := g.finalizeOAuthRecordLocked(record)
	g.mu.Unlock()
	if err != nil || plan == nil {
		return err
	}
	if err := g.publishAuthSource(ctx, plan.auths); err != nil {
		return err
	}
	return g.flushDeferredConfig(ctx)
}

func (g *groupingService) finalizeOAuthRecordLocked(record *coreauth.Auth) (*groupingAuthSourcePlan, error) {
	if g.store == nil {
		return nil, g.validateAuthLegacyMode()
	}
	if g.unavailable.Load() {
		return nil, grouping.ErrUnavailable
	}
	path, err := g.oauthRecordPath(record)
	if err != nil {
		return nil, g.failAuthSourceValidation()
	}
	journal := filepath.Join(g.path, "config.pending")
	if _, err := os.Lstat(journal); errors.Is(err, os.ErrNotExist) {
		return g.validatePersistedOAuthRecord(path, record, nil)
	}
	intent, err := g.readSourceIntent(journal)
	if err != nil {
		return nil, g.failSourceTransaction()
	}
	if intent.SourceKind != "auth" || intent.SourcePath != path {
		return nil, grouping.ErrConflict
	}
	plan, err := g.validatePersistedOAuthRecord(path, record, &intent)
	if err != nil {
		return nil, err
	}
	current, err := g.store.Snapshot()
	if err != nil {
		return nil, g.failSourceTransaction()
	}
	staged, err := stageSourceIntent(intent)
	if err != nil || !reflect.DeepEqual(current, staged) {
		return nil, g.failSourceTransaction()
	}
	if _, err := g.publishSourcePolicy(current.Revision, intent.After); err != nil {
		return nil, g.failSourceTransaction()
	}
	if err := g.finishSourceIntent(); err != nil {
		return nil, g.failSourceTransaction()
	}
	return plan, nil
}
