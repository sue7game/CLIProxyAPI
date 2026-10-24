package main

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestGuardEmptyFiveHourQuotaUsesQuotaResetCooldown(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	serverNow := now.Add(2 * time.Minute)
	fiveHourReset := serverNow.Add(4*time.Hour + 30*time.Minute)
	weeklyReset := serverNow.Add(4 * 24 * time.Hour)
	host := quotaWindowGuardHost("five-hour-empty", serverNow, fiveHourReset, weeklyReset, 0, 0.8)
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	config.TemporaryPriority = 12
	config.Consecutive429Limit = 2
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }
	record := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "five-hour-empty",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"error":{"code":429,"message":"Resource has been exhausted."}}`,
		},
	}

	repeatUsage(guard, record, config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Priority == nil || *requests[0].Priority != 12 || requests[0].Disabled != nil {
		t.Fatalf("five-hour cooldown requests = %#v", requests)
	}
	state := store.snapshot("five-hour-empty", now)
	if !state.Cooldown.Active || state.Cooldown.Trigger != triggerFiveHourQuotaEmpty || state.Cooldown.RetrySource != retrySourceFiveHourReset {
		t.Fatalf("five-hour cooldown state = %#v", state.Cooldown)
	}
	if wantUntil := now.Add(4*time.Hour + 30*time.Minute); !state.Cooldown.Until.Equal(wantUntil) {
		t.Fatalf("five-hour cooldown until = %s, want %s", state.Cooldown.Until, wantUntil)
	}
	if state.Cooldown.ManualReleaseRequired {
		t.Fatal("five-hour cooldown must restore automatically")
	}
}

func TestLocalQuotaResetTimeAdvancesObservedServerClock(t *testing.T) {
	checkedAt := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	serverNow := checkedAt.Add(2 * time.Minute)
	decisionNow := checkedAt.Add(3 * time.Minute)
	result := weeklyQuotaResult{
		ResetTime:      serverNow.Add(5 * time.Hour),
		ObservedServer: serverNow,
		CheckedAt:      checkedAt,
	}

	until, found := localQuotaResetTime(result, decisionNow)
	if !found {
		t.Fatal("expected a corrected weekly reset time")
	}
	if want := checkedAt.Add(5 * time.Hour); !until.Equal(want) {
		t.Fatalf("corrected reset = %s, want %s", until, want)
	}
}

func TestGuardAvailableWeeklyQuotaUsesConfiguredPriorityStrategy(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("weekly-available", now, now.Add(5*time.Hour), 0.25)
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	config.TemporaryPriority = 11
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-available"), config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Priority == nil || *requests[0].Priority != 11 || requests[0].Disabled != nil {
		t.Fatalf("available-quota override requests = %#v", requests)
	}
	state := store.snapshot("weekly-available", now)
	if state.Cooldown.Trigger != "quota_429" || !state.Quota.Found || state.Quota.Empty {
		t.Fatalf("available-quota state = %#v", state)
	}
}

func TestGuardQuotaFailureRecordsErrorAndFallsBackToConfiguredStrategy(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{
		auths:        []hostAuthEntry{quotaGuardAuth("quota-error")},
		requestError: errors.New("quota endpoint unavailable"),
	}
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	config.TemporaryPriority = 12
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("quota-error"), config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Priority == nil || *requests[0].Priority != 12 {
		t.Fatalf("quota-error override requests = %#v", requests)
	}
	state := store.snapshot("quota-error", now)
	if state.Quota.LastError == "" || state.Cooldown.Trigger != "quota_429" {
		t.Fatalf("quota-error state = %#v", state)
	}
}

func TestGuardActiveWeeklyCooldownKeepsQuotaResetWithoutRefreshingAgain(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("already-cooling", now, now.Add(5*time.Hour), 0)
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }
	record := quota429Record("already-cooling")

	repeatUsage(guard, record, config.Consecutive429Limit)
	guard.handleUsage(pluginapi.UsageRecord{
		Provider:        "antigravity",
		AuthIndex:       "already-cooling",
		Generate:        true,
		Failed:          true,
		ResponseHeaders: http.Header{"Retry-After": []string{"21600"}},
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"reason":"RATE_LIMIT_EXCEEDED"}`,
		},
	})

	if got := len(host.authRequests); got != 2 {
		t.Fatalf("auth request count = %d, want one quota/subscription pair while cooldown is active", got)
	}
	if got := len(host.overrides()); got != 1 {
		t.Fatalf("override request count = %d, want 1 while cooldown is active", got)
	}
	state := store.snapshot("already-cooling", now)
	if state.Cooldown.Trigger != triggerWeeklyQuotaEmpty || !state.Cooldown.Until.Equal(now.Add(5*time.Hour)) || !state.Cooldown.ManualReleaseRequired {
		t.Fatalf("weekly reset cooldown = %#v", state.Cooldown)
	}
}

func TestGuardConcurrent429DecisionOnlyRefreshesQuotaOnce(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	baseHost := quotaGuardHost("concurrent", now, now.Add(5*time.Hour), 0.5)
	host := &blockingQuotaHost{
		fakeHost: baseHost,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	store := newStateStore()
	config := testConfig()
	config.Consecutive429Limit = 1
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }
	record := quota429Record("concurrent")

	done := make(chan struct{})
	go func() {
		guard.handleUsage(record)
		close(done)
	}()
	<-host.entered
	guard.handleUsage(record)
	close(host.release)
	<-done

	if got := len(baseHost.authRequests); got != 2 {
		t.Fatalf("auth request count = %d, want one quota/subscription pair for concurrent decisions", got)
	}
	if got := len(baseHost.overrides()); got != 1 {
		t.Fatalf("override request count = %d, want 1 for concurrent decisions", got)
	}
}

func TestGuardUsesLatestStrategyAfterQuotaRefresh(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	baseHost := quotaGuardHost("strategy-change", now, now.Add(5*time.Hour), 0.5)
	host := &blockingQuotaHost{
		fakeHost: baseHost,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	config := testConfig()
	config.Consecutive429Limit = 1
	config.Action = actionDisable
	holder := &guardConfigHolder{value: config}
	store := newStateStore()
	quota := newQuotaService(host, store, holder.load)
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, holder.load, quota)
	guard.now = func() time.Time { return now }

	done := make(chan struct{})
	go func() {
		guard.handleUsage(quota429Record("strategy-change"))
		close(done)
	}()
	<-host.entered
	holder.updateStrategy(actionPriority, 9)
	close(host.release)
	<-done

	requests := baseHost.overrides()
	if len(requests) != 1 || requests[0].Priority == nil || *requests[0].Priority != 9 || requests[0].Disabled != nil {
		t.Fatalf("strategy-change override requests = %#v", requests)
	}
}
