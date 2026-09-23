package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	triggerWeeklyQuotaEmpty     = "weekly_quota_empty"
	triggerFiveHourQuotaEmpty   = "five_hour_quota_empty"
	retrySourceWeeklyQuotaReset = "weekly_quota_reset"
	retrySourceFiveHourReset    = "five_hour_quota_reset"
	codexTriggerUsageLimit      = "codex_usage_limit"
	codexTriggerUnauthorized    = "codex_401"
)

func (g *guard) handleUsage(record pluginapi.UsageRecord) {
	if !record.Generate {
		return
	}
	provider := strings.ToLower(strings.TrimSpace(record.Provider))
	if provider == "codex" {
		g.handleCodexUsage(record)
		return
	}
	if provider != "antigravity" {
		return
	}
	cfg := g.config()
	if !cfg.Enabled {
		return
	}
	authIndex := strings.TrimSpace(record.AuthIndex)
	stateKey := authIndex
	if stateKey == "" {
		stateKey = strings.TrimSpace(record.AuthID)
	}
	if stateKey == "" {
		return
	}
	now := g.now()
	statusCode := 0
	if record.Failed {
		statusCode = record.Failure.StatusCode
	}
	consecutive := g.store.observeUsage(stateKey, record.Model, record.Failed, statusCode, now)
	if !cfg.Auto429Enabled {
		g.store.resetConsecutive429(stateKey)
		return
	}
	if authIndex == "" || statusCode != 429 {
		return
	}
	g.handleRateLimit(authIndex, record, consecutive, cfg, now)
}

func (g *guard) handleCodexUsage(record pluginapi.UsageRecord) {
	cfg := g.config()
	if !cfg.Enabled {
		return
	}
	authIndex := strings.TrimSpace(record.AuthIndex)
	if authIndex == "" {
		authIndex = strings.TrimSpace(record.AuthID)
	}
	if authIndex == "" {
		return
	}
	now := g.now()
	errorType := parseCodexErrorType(record.Failure.Body)
	consecutive, quota := g.store.observeCodex(authIndex, errorType, record.Failure.StatusCode, record.ResponseHeaders, record.Failure.Body, now)
	if !record.Failed {
		return
	}
	if record.Failure.StatusCode == http.StatusUnauthorized {
		g.applyCodexDisable(authIndex, codexTriggerUnauthorized, now.Add(100*365*24*time.Hour), "codex_401", true)
		return
	}
	if !cfg.Auto429Enabled {
		return
	}
	if !strings.Contains(strings.ToLower(errorType), "usage_limit") || consecutive < 2 {
		return
	}
	until, source, ok := codexQuotaDeadline(quota, now)
	if !ok {
		retry := detectRetryTime(record.ResponseHeaders, record.Failure.Body, now)
		until, source = rateLimitDeadline(retry, cfg, now)
	}
	g.applyCodexDisable(authIndex, codexTriggerUsageLimit, until, source, false)
}

func (g *guard) applyCodexDisable(authIndex, trigger string, until time.Time, retrySource string, manual bool) {
	g.operations.Lock()
	defer g.operations.Unlock()
	if manual {
		generation, shouldApply := g.store.beginManualDisable(authIndex, trigger, retrySource, until)
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
		response, errSet := g.host.SetRuntimeOverride(runtimeOverrideRequest{AuthIndex: authIndex, Disabled: &disabled, IfRevisionField: "disabled", IfRevision: ptr(entry.RuntimeOverrideRevisions.Disabled)})
		if errSet == nil && !response.Applied {
			errSet = fmt.Errorf("runtime override changed while applying Codex 401 disable")
		}
		g.store.completeCooldownStart(authIndex, generation, response.Revisions, errSet)
		return
	}
	g.applyCooldownLocked(authIndex, actionDisable, 0, trigger, retrySource, until)
}

func ptr(value uint64) *uint64 { return &value }

func (g *guard) handleRateLimit(authIndex string, record pluginapi.UsageRecord, consecutive int, cfg guardConfig, now time.Time) {
	if consecutive < cfg.Consecutive429Limit {
		return
	}
	retry := detectRetryTime(record.ResponseHeaders, record.Failure.Body, now)
	quotaExhausted := isQuota429(record.Failure.Body) || isLongRateLimit(record.Failure.Body, retry, now)
	trigger := "generic_429"
	if quotaExhausted {
		trigger = "quota_429"
	}
	if g.handleExistingCooldown(authIndex, retry, now) {
		return
	}
	g.evaluateRateLimit(authIndex, trigger, retry, cfg.GenericRequireRetry, now)
}

func (g *guard) evaluateRateLimit(authIndex, trigger string, retry retryTime, genericRequireRetry bool, now time.Time) {
	if !g.reserveRateLimitDecision(authIndex, now) {
		return
	}
	defer g.rateLimitDecisions.Delete(authIndex)

	var quotaResult weeklyQuotaResult
	weeklyEmpty := false
	fiveHourEmpty := false
	entry, errEntry := g.authEntry(authIndex)
	if errEntry != nil {
		g.store.recordQuotaError(authIndex, errEntry, now)
	} else {
		var errRefresh error
		quotaResult, errRefresh = g.quota.refresh(authIndex, entry.ProjectID, "")
		weeklyEmpty = errRefresh == nil && quotaResult.Found && quotaResult.Empty
		fiveHourEmpty = errRefresh == nil && quotaResult.FiveHourFound && quotaResult.FiveHourEmpty
	}

	decisionNow := g.now()
	quotaResetUntil := time.Time{}
	if weeklyEmpty {
		trigger = triggerWeeklyQuotaEmpty
		if resetUntil, found := localQuotaResetTime(quotaResult, decisionNow); found {
			quotaResetUntil = resetUntil
		}
	} else if fiveHourEmpty {
		trigger = triggerFiveHourQuotaEmpty
		if resetUntil, found := localFiveHourResetTime(quotaResult, decisionNow); found {
			quotaResetUntil = resetUntil
		}
	}
	if !weeklyEmpty && !fiveHourEmpty && trigger == "generic_429" && genericRequireRetry && !retry.Found {
		return
	}
	g.applyRateLimitCooldown(authIndex, trigger, retry, quotaResetUntil)
}

func (g *guard) applyRateLimitCooldown(authIndex, trigger string, retry retryTime, quotaResetUntil time.Time) {
	g.operations.Lock()
	defer g.operations.Unlock()
	cfg := g.config()
	if !cfg.Enabled || !cfg.Auto429Enabled {
		return
	}
	if trigger == triggerWeeklyQuotaEmpty {
		retrySource := ""
		if !quotaResetUntil.IsZero() {
			retrySource = retrySourceWeeklyQuotaReset
		}
		g.applyWeeklyQuarantineLocked(authIndex, cfg.TemporaryPriority, quotaResetUntil, retrySource)
		return
	}
	if trigger == triggerFiveHourQuotaEmpty && quotaResetUntil.After(g.now()) {
		g.applyCooldownLocked(authIndex, cfg.Action, cfg.TemporaryPriority, trigger, retrySourceFiveHourReset, quotaResetUntil)
		return
	}
	until, retrySource := rateLimitDeadline(retry, cfg, g.now())
	g.applyCooldownLocked(authIndex, cfg.Action, cfg.TemporaryPriority, trigger, retrySource, until)
}

func (g *guard) handleExistingCooldown(authIndex string, retry retryTime, now time.Time) bool {
	g.operations.Lock()
	defer g.operations.Unlock()
	state := g.store.snapshot(authIndex, now)
	if !state.Cooldown.Active && !state.Cooldown.Pending {
		return false
	}
	if state.Cooldown.ManualReleaseRequired {
		return true
	}
	if !retry.Found || !retry.Until.After(state.Cooldown.Until) {
		return true
	}
	priority := 0
	if state.Cooldown.Priority != nil {
		priority = *state.Cooldown.Priority
	}
	g.store.beginCooldown(
		authIndex,
		state.Cooldown.Action,
		priority,
		state.Cooldown.Trigger,
		retry.Source,
		retry.Until,
	)
	return true
}

func (g *guard) reserveRateLimitDecision(authIndex string, now time.Time) bool {
	state := g.store.snapshot(authIndex, now)
	if state.Cooldown.Active || state.Cooldown.Pending {
		return false
	}
	if _, loaded := g.rateLimitDecisions.LoadOrStore(authIndex, struct{}{}); loaded {
		return false
	}
	state = g.store.snapshot(authIndex, now)
	if state.Cooldown.Active || state.Cooldown.Pending {
		g.rateLimitDecisions.Delete(authIndex)
		return false
	}
	return true
}

func localQuotaResetTime(result weeklyQuotaResult, now time.Time) (time.Time, bool) {
	return localQuotaDeadline(result, result.ResetTime, now)
}

func localFiveHourResetTime(result weeklyQuotaResult, now time.Time) (time.Time, bool) {
	return localQuotaDeadline(result, result.FiveHourResetTime, now)
}

func localQuotaDeadline(result weeklyQuotaResult, resetTime, now time.Time) (time.Time, bool) {
	if resetTime.IsZero() {
		return time.Time{}, false
	}
	serverNow := result.ObservedServer
	if serverNow.IsZero() {
		serverNow = result.CheckedAt
	}
	if serverNow.IsZero() {
		serverNow = now
	} else if !result.CheckedAt.IsZero() && now.After(result.CheckedAt) {
		serverNow = serverNow.Add(now.Sub(result.CheckedAt))
	}
	remaining := resetTime.Sub(serverNow)
	if remaining <= 0 {
		return time.Time{}, false
	}
	return now.Add(remaining), true
}

func rateLimitDeadline(retry retryTime, cfg guardConfig, now time.Time) (time.Time, string) {
	if retry.Found && retry.Until.After(now) {
		return retry.Until, retry.Source
	}
	return now.Add(cfg.FallbackCooldown), "fallback_cooldown"
}
