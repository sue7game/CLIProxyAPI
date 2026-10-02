package cliproxy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"reflect"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func (s *Service) applyGroupingConfigMutation(ctx context.Context, request management.ConfigApplyRequest) error {
	if s == nil || s.grouping == nil || request.Current == nil || request.Proposed == nil {
		return groupingConfigError(grouping.ErrUnavailable)
	}
	g := s.grouping
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	protected, wasUnavailable := g.enabled.Load(), g.unavailable.Load()
	if protected {
		g.unavailable.Store(true)
	}
	cfg, err := g.commitManagedConfig(ctx, request)
	if err != nil && protected && !wasUnavailable {
		// Rejected validation must not poison a healthy policy. An uncertain write
		// closes the store, in which case the runtime remains unavailable.
		if _, snapshotErr := g.store.Snapshot(); snapshotErr == nil {
			g.unavailable.Store(false)
		}
	}
	g.mu.Unlock()
	g.notify()
	if err != nil {
		return groupingConfigError(err)
	}
	if !s.applyConfigUpdateTransaction(ctx, cfg, true) {
		return groupingConfigError(grouping.ErrUnavailable)
	}
	return nil
}

func (g *groupingService) commitManagedConfig(ctx context.Context, request management.ConfigApplyRequest) (*config.Config, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current := g.current.Load()
	if !reflect.DeepEqual(current, request.Current) {
		return nil, grouping.ErrConflict
	}
	proposed := request.Proposed.CloneForRuntime()
	if g.store != nil {
		if _, err := config.EnsureGroupingCredentialIDs(proposed); err != nil {
			return nil, err
		}
	}
	if err := config.ValidateGroupingMode(proposed); err != nil {
		return nil, err
	}
	if err := g.validateReload(proposed); err != nil {
		return nil, err
	}
	if g.store == nil {
		if err := persistGroupingConfig(g.owner.configPath, proposed); err != nil {
			return nil, err
		}
		g.current.Store(proposed.CloneForRuntime())
		return proposed, nil
	}
	if err := config.ValidateGroupingCredentialIDs(proposed); err != nil {
		return nil, err
	}
	before, err := g.store.Snapshot()
	if err != nil {
		return nil, err
	}
	after, err := g.managedPolicyTransition(before, proposed, request.TokenRotation)
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(g.owner.configPath)
	if err != nil {
		return nil, grouping.ErrUnavailable
	}
	change, err := prepareGroupingConfigWrite(g.owner.configPath, bytes, proposed)
	if err != nil {
		return nil, err
	}
	if _, err := g.commitSourceTransaction(*change, before, after); err != nil {
		return nil, err
	}
	g.current.Store(proposed.CloneForRuntime())
	return proposed, nil
}

func groupingConfigError(err error) error {
	var existing *management.ConfigApplyError
	if errors.As(err, &existing) {
		return existing
	}
	if errors.Is(err, grouping.ErrConflict) || errors.Is(err, grouping.ErrInvalid) || errors.Is(err, grouping.ErrNotFound) || errors.Is(err, grouping.ErrRevision) {
		return &management.ConfigApplyError{StatusCode: http.StatusConflict, Code: "grouping_conflict", Message: "configuration or grouping identities changed; refresh before retrying"}
	}
	return &management.ConfigApplyError{StatusCode: http.StatusServiceUnavailable, Code: "grouping_unavailable", Message: "grouping configuration transaction could not complete; inspect local policy health before retrying"}
}
