package cliproxy

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
)

type groupingDeferredConfig struct {
	config     *config.Config
	synthesize bool
}

func (g *groupingService) deferConfigReload(ctx context.Context, cfg *config.Config, synthesize bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.sourcePending {
		return grouping.ErrConflict
	}
	g.deferredConfig = &groupingDeferredConfig{cfg.CloneForRuntime(), synthesize}
	return nil
}

func (g *groupingService) clearDeferredConfig() {
	g.mu.Lock()
	g.deferredConfig = nil
	g.mu.Unlock()
}

// flushDeferredConfig runs with transactionMu held and never reacquires it.
// A failed replay remains queued and closed until a successful config update.
func (g *groupingService) flushDeferredConfig(ctx context.Context) error {
	g.mu.Lock()
	deferred := g.deferredConfig
	if deferred == nil {
		g.mu.Unlock()
		return nil
	}
	if g.sourcePending {
		g.mu.Unlock()
		return g.failDeferredConfig(fmt.Errorf("grouping: cannot replay configuration before source transaction recovery completes: %w", grouping.ErrConflict))
	}
	g.unavailable.Store(true)
	g.mu.Unlock()
	g.notify()
	if err := ctx.Err(); err != nil {
		return g.failDeferredConfig(fmt.Errorf("grouping: deferred configuration replay canceled: %w", err))
	}
	if !g.owner.applyConfigUpdateTransaction(ctx, deferred.config, deferred.synthesize) {
		if err := ctx.Err(); err != nil {
			return g.failDeferredConfig(fmt.Errorf("grouping: deferred configuration replay canceled: %w", err))
		}
		return g.failDeferredConfig(fmt.Errorf("grouping: deferred configuration replay failed; apply a valid configuration or restart to recover"))
	}
	return nil
}

func (g *groupingService) failDeferredConfig(err error) error {
	g.unavailable.Store(true)
	g.notify()
	log.WithError(err).Error("grouping retained a failed deferred configuration; new proxy attempts remain disabled")
	return err
}
