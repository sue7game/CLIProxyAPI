package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type guard struct {
	host               hostClient
	store              *stateStore
	config             func() guardConfig
	quota              *quotaService
	now                func() time.Time
	operations         sync.Mutex
	rateLimitDecisions sync.Map
	proxyCleanupRetry  map[string]time.Time
	lifecycle          sync.Mutex
	cancel             context.CancelFunc
	startOnce          sync.Once
	stopOnce           sync.Once
	wait               sync.WaitGroup
	stopped            bool
}

func newGuard(host hostClient, store *stateStore, config func() guardConfig, quotaServices ...*quotaService) *guard {
	quota := (*quotaService)(nil)
	if len(quotaServices) > 0 {
		quota = quotaServices[0]
	}
	if quota == nil {
		quota = newQuotaService(host, store, config)
	}
	return &guard{
		host:              host,
		store:             store,
		config:            config,
		quota:             quota,
		now:               time.Now,
		proxyCleanupRetry: make(map[string]time.Time),
	}
}

func (g *guard) start() {
	g.startOnce.Do(func() {
		g.lifecycle.Lock()
		defer g.lifecycle.Unlock()
		if g.stopped || g.cancel != nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		g.cancel = cancel
		g.wait.Add(1)
		go g.restoreLoop(ctx)
	})
}

func (g *guard) applyCooldown(authIndex, action string, priority int, trigger, retrySource string, until time.Time) {
	g.operations.Lock()
	defer g.operations.Unlock()
	cfg := g.config()
	if !cfg.Enabled || !cfg.Auto429Enabled {
		return
	}
	g.applyCooldownLocked(authIndex, action, priority, trigger, retrySource, until)
}

func (g *guard) applyCooldownLocked(authIndex, action string, priority int, trigger, retrySource string, until time.Time) {
	generation, shouldApply := g.store.beginCooldown(authIndex, action, priority, trigger, retrySource, until)
	if !shouldApply {
		return
	}
	entry, errList := g.authEntry(authIndex)
	if errList != nil {
		g.store.completeCooldownStart(authIndex, generation, runtimeOverrideRevisions{}, errList)
		return
	}
	g.store.setCooldownOriginal(authIndex, generation, entry.RuntimeOverride)
	field := "disabled"
	if action == actionPriority {
		field = "priority"
	}
	revision := entry.RuntimeOverrideRevisions.forField(field)
	request := runtimeOverrideRequest{
		AuthIndex:       authIndex,
		IfRevision:      &revision,
		IfRevisionField: field,
	}
	if action == actionPriority {
		request.Priority = &priority
	} else {
		disabled := true
		request.Disabled = &disabled
	}
	response, errSet := g.host.SetRuntimeOverride(request)
	if errSet == nil && !response.Applied {
		errSet = fmt.Errorf("runtime override changed while applying cooldown")
	}
	g.store.completeCooldownStart(authIndex, generation, response.Revisions, errSet)
}

func (g *guard) applyWeeklyQuarantineLocked(authIndex string, priority int, until time.Time, retrySource string) {
	generation, shouldApply := g.store.beginWeeklyQuarantine(authIndex, priority, until, retrySource)
	if !shouldApply {
		return
	}
	entry, errList := g.authEntry(authIndex)
	if errList != nil {
		g.store.completeCooldownStart(authIndex, generation, runtimeOverrideRevisions{}, errList)
		return
	}
	g.store.setCooldownOriginal(authIndex, generation, entry.RuntimeOverride)
	disabled := true
	expectedRevisions := entry.RuntimeOverrideRevisions
	response, errSet := g.host.SetRuntimeOverride(runtimeOverrideRequest{
		AuthIndex:   authIndex,
		Disabled:    &disabled,
		Priority:    &priority,
		IfRevisions: &expectedRevisions,
	})
	if errSet == nil && !response.Applied {
		errSet = fmt.Errorf("runtime override changed while applying weekly quarantine")
	}
	g.store.completeCooldownStart(authIndex, generation, response.Revisions, errSet)
}

func (g *guard) setProxy(authIndex string, proxyURL *string) error {
	g.operations.Lock()
	defer g.operations.Unlock()
	if !g.config().Enabled {
		return fmt.Errorf("plugin is disabled")
	}
	request := runtimeOverrideRequest{AuthIndex: authIndex}
	if proxyURL == nil {
		request.Clear = []string{"proxy_url"}
	} else {
		request.ProxyURL = proxyURL
	}
	response, errSet := g.host.SetRuntimeOverride(request)
	if errSet != nil {
		return errSet
	}
	if !response.Applied {
		return fmt.Errorf("runtime override changed while setting proxy")
	}
	delete(g.proxyCleanupRetry, authIndex)
	g.store.setManagedProxy(authIndex, proxyURL, response.Revisions.ProxyURL)
	return nil
}

func (g *guard) restoreLoop(ctx context.Context) {
	defer g.wait.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			g.store.expireQuotas(now)
			g.reconcileConfiguredDisables(now)
			g.restoreDue(now)
			g.retryManagedProxyCleanup(now)
		}
	}
}

func (g *guard) shutdown() {
	g.stopOnce.Do(func() {
		g.lifecycle.Lock()
		g.stopped = true
		cancel := g.cancel
		g.lifecycle.Unlock()
		if cancel != nil {
			cancel()
		}
		g.wait.Wait()
		_ = g.clearAutomaticOverrides()
		g.clearManagedProxies()
	})
}

func (g *guard) clearManagedProxies() {
	g.operations.Lock()
	defer g.operations.Unlock()
	g.clearManagedProxiesLocked()
}

func (g *guard) clearManagedProxiesLocked() {
	now := g.now()
	for authIndex, state := range g.store.allSnapshots(now) {
		if state.ManagedProxy == nil {
			continue
		}
		g.clearManagedProxyLocked(authIndex, state, now)
	}
}

func (g *guard) retryManagedProxyCleanup(now time.Time) {
	g.operations.Lock()
	defer g.operations.Unlock()
	for authIndex, retryAt := range g.proxyCleanupRetry {
		if now.Before(retryAt) {
			continue
		}
		state := g.store.snapshot(authIndex, now)
		if state.ManagedProxy == nil {
			delete(g.proxyCleanupRetry, authIndex)
			continue
		}
		g.clearManagedProxyLocked(authIndex, state, now)
	}
}

func (g *guard) clearManagedProxyLocked(authIndex string, state credentialState, now time.Time) {
	revision := state.ManagedProxyRevision
	_, errClear := g.host.SetRuntimeOverride(runtimeOverrideRequest{
		AuthIndex:       authIndex,
		Clear:           []string{"proxy_url"},
		IfRevision:      &revision,
		IfRevisionField: "proxy_url",
	})
	if errClear != nil {
		g.proxyCleanupRetry[authIndex] = now.Add(g.config().RestoreRetry)
		return
	}
	delete(g.proxyCleanupRetry, authIndex)
	g.store.setManagedProxy(authIndex, nil, 0)
}

func validateAuthIndex(authIndex string) (string, error) {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return "", fmt.Errorf("auth_index is required")
	}
	return authIndex, nil
}
