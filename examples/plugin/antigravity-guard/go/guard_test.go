package main

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestGuardAppliesAndRestoresQuotaCooldown(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("auth-1", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	record := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "auth-1",
		Model:     "claude-sonnet",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"QUOTA_EXHAUSTED","retryDelay":"5h"}`,
		},
	}
	repeatUsage(guard, record, config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Disabled == nil || !*requests[0].Disabled {
		t.Fatalf("override requests = %#v", requests)
	}
	if requests[0].IfRevision == nil || *requests[0].IfRevision != 0 || requests[0].IfRevisionField != "disabled" {
		t.Fatalf("cooldown CAS request = %#v", requests[0])
	}
	state := store.snapshot("auth-1", now)
	if !state.Cooldown.Active || state.Cooldown.AppliedDisabledRevision != 1 || !state.Cooldown.Until.Equal(now.Add(5*time.Hour)) {
		t.Fatalf("cooldown state = %#v", state.Cooldown)
	}

	now = now.Add(5 * time.Hour)
	guard.restoreDue(now)
	requests = host.overrides()
	if len(requests) != 2 || len(requests[1].Clear) != 1 || requests[1].Clear[0] != "disabled" {
		t.Fatalf("restore requests = %#v", requests)
	}
	if requests[1].IfRevision == nil || *requests[1].IfRevision != 1 || requests[1].IfRevisionField != "disabled" {
		t.Fatalf("restore CAS request = %#v", requests[1])
	}
	if store.snapshot("auth-1", now).Cooldown.Active {
		t.Fatal("cooldown should be cleared after restore")
	}
}

func TestGuardUsesOneConsecutiveThresholdForEvery429(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	shortHost := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-short", 14)}}
	shortStore := newStateStore()
	config := testConfig()
	shortGuard := newGuard(shortHost, shortStore, func() guardConfig { return config })
	shortGuard.now = func() time.Time { return now }
	shortRecord := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "ag-short",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: 429,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"RATE_LIMIT_EXCEEDED","retryDelay":"30s"}`,
		},
	}
	repeatUsage(shortGuard, shortRecord, config.Consecutive429Limit-1)
	if len(shortHost.overrides()) != 0 {
		t.Fatal("short rate limit triggered before the shared threshold")
	}
	shortGuard.handleUsage(shortRecord)
	if len(shortHost.overrides()) != 1 {
		t.Fatal("short rate limit did not trigger at the shared threshold")
	}

	longHost := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-long", 14)}}
	longStore := newStateStore()
	longGuard := newGuard(longHost, longStore, func() guardConfig { return config })
	longGuard.now = func() time.Time { return now }
	longRecord := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "ag-long",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: 429,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"RATE_LIMIT_EXCEEDED","quotaResetDelay":"5h"}`,
		},
	}
	repeatUsage(longGuard, longRecord, config.Consecutive429Limit-1)
	if len(longHost.overrides()) != 0 {
		t.Fatal("long rate limit triggered before the shared threshold")
	}
	longGuard.handleUsage(longRecord)
	if len(longHost.overrides()) != 1 {
		t.Fatal("long rate limit did not trigger at the shared threshold")
	}
}

func TestGuardNon429ResetsConsecutiveThreshold(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("reset-streak", now, now.Add(5*time.Hour), 0.5)
	store := newStateStore()
	config := testConfig()
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }
	rateLimited := quota429Record("reset-streak")

	repeatUsage(guard, rateLimited, 2)
	guard.handleUsage(pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "reset-streak",
		Generate:  true,
	})
	repeatUsage(guard, rateLimited, 2)
	if len(host.overrides()) != 0 {
		t.Fatal("two 429 responses after a non-429 reset must not trigger")
	}
	guard.handleUsage(rateLimited)
	if len(host.overrides()) != 1 {
		t.Fatal("third consecutive 429 after reset must trigger")
	}
}

func TestGuardIgnoresCountTokensUsage(t *testing.T) {
	host := &fakeHost{}
	store := newStateStore()
	config := testConfig()
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.handleUsage(pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "auth-1",
		Generate:  false,
		Failed:    true,
		Failure:   pluginapi.UsageFailure{StatusCode: 429, Body: `{"reason":"QUOTA_EXHAUSTED"}`},
	})
	if len(host.overrides()) != 0 {
		t.Fatal("count_tokens usage must not change routing")
	}
	if state := store.snapshot("auth-1", time.Now()); state.Usage.RateLimited != 0 {
		t.Fatalf("count_tokens usage changed state: %#v", state.Usage)
	}
}

func TestGuardGeneric429RequiresRetryAfterSharedThreshold(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("auth-2", 14)}}
	store := newStateStore()
	config := testConfig()
	guard := newGuard(host, store, func() guardConfig { return config })
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard.now = func() time.Time { return now }

	record := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "auth-2",
		Generate:  true,
		Failed:    true,
		Failure:   pluginapi.UsageFailure{StatusCode: 429, Body: `{"message":"requests are too frequent"}`},
	}
	repeatUsage(guard, record, config.Consecutive429Limit-1)
	if len(host.overrides()) != 0 {
		t.Fatal("generic 429 triggered before the shared threshold")
	}
	guard.handleUsage(record)
	if len(host.overrides()) != 0 {
		t.Fatal("generic 429 without Retry time must not trigger")
	}
	record.ResponseHeaders = http.Header{"Retry-After": []string{"120"}}
	guard.handleUsage(record)
	if len(host.overrides()) != 1 {
		t.Fatalf("expected one override after Retry time, got %d", len(host.overrides()))
	}
	state := store.snapshot("auth-2", now)
	if state.Cooldown.RetrySource != "Retry-After" || !state.Cooldown.Until.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("Retry cooldown = %#v", state.Cooldown)
	}
}

func TestGuardWeeklyEmptyQuarantinesWithPriorityAndCorrectedResetTime(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	serverNow := now.Add(2 * time.Minute)
	serverReset := serverNow.Add(5 * time.Hour)
	host := quotaGuardHost("weekly-empty", serverNow, serverReset, 0)
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-empty"), config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Disabled == nil || !*requests[0].Disabled || requests[0].Priority == nil || *requests[0].Priority != config.TemporaryPriority {
		t.Fatalf("weekly-empty override requests = %#v", requests)
	}
	if requests[0].IfRevisions == nil || *requests[0].IfRevisions != (runtimeOverrideRevisions{}) {
		t.Fatalf("weekly-empty multi-field CAS = %#v", requests[0])
	}
	state := store.snapshot("weekly-empty", now)
	if state.Cooldown.Trigger != triggerWeeklyQuotaEmpty || state.Cooldown.RetrySource != retrySourceWeeklyQuotaReset || !state.Cooldown.ManualReleaseRequired {
		t.Fatalf("weekly-empty cooldown = %#v", state.Cooldown)
	}
	if wantUntil := now.Add(5 * time.Hour); !state.Cooldown.Until.Equal(wantUntil) {
		t.Fatalf("cooldown until = %s, want corrected local time %s", state.Cooldown.Until, wantUntil)
	}
}

func TestGuardGeneric429AlsoForcesDisableWhenWeeklyQuotaIsEmpty(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("weekly-empty-generic", now, now.Add(5*time.Hour), 0)
	store := newStateStore()
	config := testConfig()
	config.Action = actionPriority
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }
	record := pluginapi.UsageRecord{
		Provider:        "antigravity",
		AuthIndex:       "weekly-empty-generic",
		Generate:        true,
		Failed:          true,
		ResponseHeaders: http.Header{"Retry-After": []string{"120"}},
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"message":"requests are too frequent"}`,
		},
	}

	repeatUsage(guard, record, config.Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Disabled == nil || !*requests[0].Disabled || requests[0].Priority == nil || *requests[0].Priority != config.TemporaryPriority {
		t.Fatalf("generic weekly-empty override requests = %#v", requests)
	}
	state := store.snapshot("weekly-empty-generic", now)
	if state.Cooldown.Trigger != triggerWeeklyQuotaEmpty || !state.Cooldown.Until.Equal(now.Add(5*time.Hour)) || !state.Cooldown.ManualReleaseRequired {
		t.Fatalf("generic weekly-empty cooldown = %#v", state.Cooldown)
	}
}

func TestGuardWeeklyQuarantineRequiresManualReleaseAfterReset(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	resetTime := now.Add(5 * time.Hour)
	host := quotaGuardHost("weekly-manual", now, resetTime, 0)
	store := newStateStore()
	config := testConfig()
	config.TemporaryPriority = 11
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-manual"), config.Consecutive429Limit)
	now = resetTime.Add(time.Minute)
	guard.restoreDue(now)

	if requests := host.overrides(); len(requests) != 1 {
		t.Fatalf("weekly quarantine restored automatically: %#v", requests)
	}
	state := store.snapshot("weekly-manual", now)
	if !state.Cooldown.Active || !state.Cooldown.ManualReleaseRequired || !state.Quota.Found || !state.Quota.Empty {
		t.Fatalf("weekly quarantine after reset = %#v", state)
	}
	weekly := weeklyViewFromState(state.Quota, now)
	if weekly == nil || weekly.RemainingSeconds != 0 {
		t.Fatalf("weekly view after reset = %#v", weekly)
	}

	if errClear := guard.clearCooldown("weekly-manual"); errClear != nil {
		t.Fatal(errClear)
	}
	requests := host.overrides()
	if len(requests) != 3 {
		t.Fatalf("manual release requests = %#v", requests)
	}
	assertRuntimeFieldClear(t, requests[1], "priority", 1)
	assertRuntimeFieldClear(t, requests[2], "disabled", 1)
	if store.snapshot("weekly-manual", now).Cooldown.Active {
		t.Fatal("weekly quarantine remained active after manual release")
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride != nil {
		t.Fatalf("manual release left runtime override: %#v", entries[0].RuntimeOverride)
	}
}

func TestGuardConfiguredDisableAutomaticallyClearsWeeklyQuarantine(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("weekly-config-disabled", now, now.Add(5*time.Hour), 0)
	store := newStateStore()
	config := testConfig()
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-config-disabled"), config.Consecutive429Limit)
	host.setConfiguredDisabled("weekly-config-disabled", true)
	guard.reconcileConfiguredDisables(now)

	state := store.snapshot("weekly-config-disabled", now)
	if state.Cooldown.Active || state.Cooldown.RestoreOutcome != restoreOutcomeRestored {
		t.Fatalf("configured disable reconciliation state = %#v", state.Cooldown)
	}
	requests := host.overrides()
	if len(requests) != 3 {
		t.Fatalf("configured disable reconciliation requests = %#v", requests)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if !entries[0].ConfiguredDisabled || entries[0].RuntimeOverride != nil {
		t.Fatalf("configured disabled credential = %#v", entries[0])
	}
}

func TestGuardConfiguredDisableAfterManagementTakeoverClearsWeeklyQuarantine(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("weekly-management-disabled", now, now.Add(5*time.Hour), 0)
	store := newStateStore()
	config := testConfig()
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-management-disabled"), config.Consecutive429Limit)
	host.setRuntimeOverride("weekly-management-disabled", nil)
	host.setConfiguredDisabled("weekly-management-disabled", true)
	guard.reconcileConfiguredDisables(now)

	state := store.snapshot("weekly-management-disabled", now)
	if state.Cooldown.Active || state.Cooldown.RestoreOutcome != restoreOutcomeManualTakeover || !state.Cooldown.Superseded {
		t.Fatalf("management takeover reconciliation state = %#v", state.Cooldown)
	}
	if got := len(host.overrides()); got != 1 {
		t.Fatalf("management takeover must not write runtime fields: %#v", host.overrides())
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if !entries[0].ConfiguredDisabled || entries[0].RuntimeOverride != nil {
		t.Fatalf("management-disabled credential = %#v", entries[0])
	}
}

func TestGuardReentersWeeklyQuarantineAfterManualRelease(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("weekly-reenter", now, now.Add(5*time.Hour), 0)
	store := newStateStore()
	config := testConfig()
	config.Consecutive429Limit = 2
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("weekly-reenter"), config.Consecutive429Limit)
	host.setRuntimeOverride("weekly-reenter", nil)
	if errClear := guard.clearCooldown("weekly-reenter"); errClear != nil {
		t.Fatal(errClear)
	}

	record := pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "weekly-reenter",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"error":{"code":429,"message":"Resource has been exhausted."}}`,
		},
	}
	repeatUsage(guard, record, config.Consecutive429Limit)

	state := store.snapshot("weekly-reenter", now)
	if !state.Cooldown.Active || state.Cooldown.Trigger != triggerWeeklyQuotaEmpty || !state.Cooldown.ManualReleaseRequired {
		t.Fatalf("reentered weekly quarantine state = %#v", state)
	}
	if got := len(host.authRequests); got != 2 {
		t.Fatalf("quota request count = %d, want 2", got)
	}
	if got := len(host.overrides()); got != 4 {
		t.Fatalf("override request count = %d, want 4", got)
	}
}

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

func TestGuardWeeklyEmptyTakesPrecedenceOverFiveHourEmpty(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	host := quotaWindowGuardHost("both-empty", now, now.Add(4*time.Hour), now.Add(4*24*time.Hour), 0, 0)
	store := newStateStore()
	config := testConfig()
	quota := newQuotaService(host, store, func() guardConfig { return config })
	quota.now = func() time.Time { return now }
	guard := newGuard(host, store, func() guardConfig { return config }, quota)
	guard.now = func() time.Time { return now }

	repeatUsage(guard, quota429Record("both-empty"), config.Consecutive429Limit)

	state := store.snapshot("both-empty", now)
	if state.Cooldown.Trigger != triggerWeeklyQuotaEmpty || !state.Cooldown.ManualReleaseRequired {
		t.Fatalf("both-empty cooldown = %#v", state.Cooldown)
	}
}

func TestGuardWeeklyQuarantineRestoresOriginalRuntimeFields(t *testing.T) {
	originalDisabled := true
	originalPriority := 12
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("weekly-original", 14)}}
	host.auths[0].RuntimeOverride = &runtimeOverride{
		Disabled: &originalDisabled,
		Priority: &originalPriority,
	}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.operations.Lock()
	guard.applyWeeklyQuarantineLocked("weekly-original", 11, now.Add(5*time.Hour), retrySourceWeeklyQuotaReset)
	guard.operations.Unlock()
	if errClear := guard.clearCooldown("weekly-original"); errClear != nil {
		t.Fatal(errClear)
	}

	requests := host.overrides()
	if len(requests) != 3 || requests[1].Priority == nil || *requests[1].Priority != originalPriority || requests[2].Disabled == nil || !*requests[2].Disabled {
		t.Fatalf("original runtime restore requests = %#v", requests)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.Priority == nil || *entries[0].RuntimeOverride.Priority != originalPriority || entries[0].RuntimeOverride.Disabled == nil || !*entries[0].RuntimeOverride.Disabled {
		t.Fatalf("restored runtime override = %#v", entries[0].RuntimeOverride)
	}
	state := store.snapshot("weekly-original", now)
	if state.Cooldown.RestoreTargetSnapshot != "runtime priority 12; runtime disabled" {
		t.Fatalf("restore target snapshot = %q", state.Cooldown.RestoreTargetSnapshot)
	}
}

func TestGuardWeeklyQuarantineRespectsPriorityTakeoverAndRestoresDisabled(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("weekly-takeover", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.operations.Lock()
	guard.applyWeeklyQuarantineLocked("weekly-takeover", 11, now.Add(5*time.Hour), retrySourceWeeklyQuotaReset)
	guard.operations.Unlock()
	manualPriority := 10
	if response, errSet := host.SetRuntimeOverride(runtimeOverrideRequest{
		AuthIndex: "weekly-takeover",
		Priority:  &manualPriority,
	}); errSet != nil || !response.Applied {
		t.Fatalf("manual priority takeover error=%v response=%#v", errSet, response)
	}
	if errClear := guard.clearCooldown("weekly-takeover"); errClear != nil {
		t.Fatal(errClear)
	}

	state := store.snapshot("weekly-takeover", now)
	if state.Cooldown.RestoreOutcome != restoreOutcomeManualTakeover || !state.Cooldown.Superseded {
		t.Fatalf("takeover outcome = %#v", state.Cooldown)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.Priority == nil || *entries[0].RuntimeOverride.Priority != manualPriority || entries[0].RuntimeOverride.Disabled != nil {
		t.Fatalf("manual priority takeover was not preserved: %#v", entries[0].RuntimeOverride)
	}
}

func TestGuardWeeklyQuarantineRetriesOnlyUnrestoredDisabledField(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("weekly-restore-retry", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.operations.Lock()
	guard.applyWeeklyQuarantineLocked("weekly-restore-retry", 11, now.Add(5*time.Hour), retrySourceWeeklyQuotaReset)
	guard.operations.Unlock()
	host.overrideErrors = []error{nil, errors.New("temporary disabled restore failure")}
	if errClear := guard.clearCooldown("weekly-restore-retry"); errClear == nil {
		t.Fatal("manual release error = nil, want disabled restore failure")
	}

	state := store.snapshot("weekly-restore-retry", now)
	if !state.Cooldown.Active || !state.Cooldown.PriorityRestored || state.Cooldown.DisabledRestored || state.Cooldown.LastError == "" {
		t.Fatalf("partial restore state = %#v", state.Cooldown)
	}
	retryAt := state.Cooldown.NextRestoreAttempt
	guard.restoreDue(retryAt)

	requests := host.overrides()
	if len(requests) != 4 {
		t.Fatalf("restore retry requests = %#v", requests)
	}
	assertRuntimeFieldClear(t, requests[1], "priority", 1)
	assertRuntimeFieldClear(t, requests[2], "disabled", 1)
	assertRuntimeFieldClear(t, requests[3], "disabled", 1)
	state = store.snapshot("weekly-restore-retry", retryAt)
	if state.Cooldown.Active || state.Cooldown.RestoreOutcome != restoreOutcomeRestored {
		t.Fatalf("retry completion state = %#v", state.Cooldown)
	}
}

func TestGuardWeeklyQuarantineDoesNotOverwriteConcurrentPriorityChange(t *testing.T) {
	baseHost := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("weekly-cas", 14)}}
	host := &staleWeeklyCASHost{fakeHost: baseHost, priority: 12}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.operations.Lock()
	guard.applyWeeklyQuarantineLocked("weekly-cas", 11, now.Add(5*time.Hour), retrySourceWeeklyQuotaReset)
	guard.operations.Unlock()

	state := store.snapshot("weekly-cas", now)
	if state.Cooldown.Active || state.Cooldown.LastError == "" {
		t.Fatalf("stale multi-field CAS state = %#v", state.Cooldown)
	}
	entries, errList := baseHost.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.Priority == nil || *entries[0].RuntimeOverride.Priority != 12 || entries[0].RuntimeOverride.Disabled != nil {
		t.Fatalf("concurrent priority change was overwritten: %#v", entries[0].RuntimeOverride)
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

	if got := len(host.authRequests); got != 1 {
		t.Fatalf("quota request count = %d, want 1 while cooldown is active", got)
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

	if got := len(baseHost.authRequests); got != 1 {
		t.Fatalf("quota request count = %d, want 1 for concurrent decisions", got)
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

func TestGuardRestoresOriginalRuntimePriority(t *testing.T) {
	originalPriority := 12
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-priority", 14)}}
	host.auths[0].RuntimeOverride = &runtimeOverride{Priority: &originalPriority}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-priority", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	state := store.snapshot("ag-priority", now)
	if state.Cooldown.OriginalPriority == nil || *state.Cooldown.OriginalPriority != originalPriority {
		t.Fatalf("original runtime priority = %#v", state.Cooldown.OriginalPriority)
	}
	if target := state.Cooldown.restoreTarget(false, 14); target != "runtime priority 12" {
		t.Fatalf("restore target = %q", target)
	}

	now = now.Add(time.Hour)
	guard.restoreDue(now)
	requests := host.overrides()
	if len(requests) != 2 || requests[1].Priority == nil || *requests[1].Priority != originalPriority {
		t.Fatalf("restore requests = %#v", requests)
	}
	state = store.snapshot("ag-priority", now)
	if state.Cooldown.RestoreOutcome != restoreOutcomeRestored || state.Cooldown.Superseded {
		t.Fatalf("restored state = %#v", state.Cooldown)
	}
}

func TestGuardRestoresCurrentConfiguredPriorityAfterConfigurationChange(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-config", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-config", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	host.setConfiguredPriority("ag-config", 15)
	now = now.Add(time.Hour)
	guard.restoreDue(now)

	requests := host.overrides()
	if len(requests) != 2 || len(requests[1].Clear) != 1 || requests[1].Clear[0] != "priority" {
		t.Fatalf("restore requests = %#v", requests)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].ConfiguredPriority != 15 || entries[0].RuntimeOverride != nil {
		t.Fatalf("restored credential = %#v", entries[0])
	}
}

func TestGuardDoesNotOverwriteManualPriorityTakeover(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-manual", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-manual", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	manualPriority := 11
	host.setRuntimeOverride("ag-manual", &runtimeOverride{Priority: &manualPriority})
	now = now.Add(time.Hour)
	guard.restoreDue(now)

	if requests := host.overrides(); len(requests) != 2 || requests[1].IfRevision == nil || requests[1].IfRevisionField != "priority" {
		t.Fatalf("manual takeover CAS request = %#v", requests)
	}
	state := store.snapshot("ag-manual", now)
	if state.Cooldown.Active || !state.Cooldown.Superseded || state.Cooldown.RestoreOutcome != restoreOutcomeManualTakeover {
		t.Fatalf("manual takeover state = %#v", state.Cooldown)
	}
	if phase := state.Cooldown.phase(now); phase != restoreOutcomeManualTakeover {
		t.Fatalf("manual takeover phase = %q", phase)
	}
}

func TestGuardSameValueManualWriteFencesRestore(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-same-value", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-same-value", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	samePriority := 13
	host.setRuntimeOverride("ag-same-value", &runtimeOverride{Priority: &samePriority})
	now = now.Add(time.Hour)
	guard.restoreDue(now)

	state := store.snapshot("ag-same-value", now)
	if state.Cooldown.RestoreOutcome != restoreOutcomeManualTakeover || !state.Cooldown.Superseded {
		t.Fatalf("same-value takeover state = %#v", state.Cooldown)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.Priority == nil || *entries[0].RuntimeOverride.Priority != samePriority {
		t.Fatalf("same-value takeover was cleared: %#v", entries[0])
	}
}

func TestGuardUnrelatedProxyWriteDoesNotBlockPriorityRestore(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-unrelated", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-unrelated", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	proxyURL := "direct"
	if response, errSet := host.SetRuntimeOverride(runtimeOverrideRequest{AuthIndex: "ag-unrelated", ProxyURL: &proxyURL}); errSet != nil || !response.Applied {
		t.Fatalf("unrelated proxy write error=%v response=%#v", errSet, response)
	}
	now = now.Add(time.Hour)
	guard.restoreDue(now)

	state := store.snapshot("ag-unrelated", now)
	if state.Cooldown.RestoreOutcome != restoreOutcomeRestored || state.Cooldown.Active {
		t.Fatalf("priority restore state = %#v", state.Cooldown)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.Priority != nil || entries[0].RuntimeOverride.ProxyURL == nil {
		t.Fatalf("unrelated proxy was not preserved: %#v", entries[0].RuntimeOverride)
	}
}

func TestGuardRetriesFailedRestore(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-retry", 14)}}
	store := newStateStore()
	config := testConfig()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	guard := newGuard(host, store, func() guardConfig { return config })
	guard.now = func() time.Time { return now }

	guard.applyCooldown("ag-retry", actionDisable, 0, "quota_429", "Retry-After", now.Add(time.Hour))
	now = now.Add(time.Hour)
	host.setOverrideError(errors.New("temporary host failure"))
	guard.restoreDue(now)

	state := store.snapshot("ag-retry", now)
	wantRetry := now.Add(config.RestoreRetry)
	if !state.Cooldown.Active || state.Cooldown.LastError == "" || !state.Cooldown.NextRestoreAttempt.Equal(wantRetry) {
		t.Fatalf("retry state = %#v", state.Cooldown)
	}
	if phase := state.Cooldown.phase(now); phase != "retry_wait" {
		t.Fatalf("retry phase = %q", phase)
	}
	guard.restoreDue(wantRetry.Add(-time.Second))
	if requests := host.overrides(); len(requests) != 2 {
		t.Fatalf("restore retried too early: %#v", requests)
	}

	host.setOverrideError(nil)
	guard.restoreDue(wantRetry)
	requests := host.overrides()
	if len(requests) != 3 || len(requests[2].Clear) != 1 || requests[2].Clear[0] != "disabled" {
		t.Fatalf("retry requests = %#v", requests)
	}
	state = store.snapshot("ag-retry", wantRetry)
	if state.Cooldown.RestoreOutcome != restoreOutcomeRestored || state.Cooldown.Active {
		t.Fatalf("retry completion state = %#v", state.Cooldown)
	}
}

type blockingQuotaHost struct {
	*fakeHost
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type staleWeeklyCASHost struct {
	*fakeHost
	priority int
	once     sync.Once
}

type guardConfigHolder struct {
	mu    sync.RWMutex
	value guardConfig
}

func (h *guardConfigHolder) load() guardConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.value
}

func (h *guardConfigHolder) updateStrategy(action string, priority int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.value.Action = action
	h.value.TemporaryPriority = priority
}

func (h *blockingQuotaHost) Request(request hostAuthRequest) (hostAuthResponse, error) {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.fakeHost.Request(request)
}

func (h *staleWeeklyCASHost) SetRuntimeOverride(request runtimeOverrideRequest) (runtimeOverrideResponse, error) {
	if request.IfRevisions != nil {
		h.once.Do(func() {
			_, _ = h.fakeHost.SetRuntimeOverride(runtimeOverrideRequest{
				AuthIndex: request.AuthIndex,
				Priority:  &h.priority,
			})
		})
	}
	return h.fakeHost.SetRuntimeOverride(request)
}

func quotaGuardHost(authIndex string, serverNow, reset time.Time, remaining float64) *fakeHost {
	body := fmt.Sprintf(
		`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":%g,"resetTime":"%s"}]}]}`,
		remaining,
		reset.Format(time.RFC3339Nano),
	)
	return &fakeHost{
		auths: []hostAuthEntry{quotaGuardAuth(authIndex)},
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Date": []string{serverNow.Format(http.TimeFormat)}},
			Body:       []byte(body),
		},
	}
}

func quotaWindowGuardHost(
	authIndex string,
	serverNow, fiveHourReset, weeklyReset time.Time,
	fiveHourRemaining, weeklyRemaining float64,
) *fakeHost {
	body := fmt.Sprintf(
		`{"groups":[{"displayName":"Gemini models","buckets":[`+
			`{"window":"five_hour","remainingFraction":%g,"resetTime":"%s"},`+
			`{"window":"weekly","remainingFraction":%g,"resetTime":"%s"}`+
			`]}]}`,
		fiveHourRemaining,
		fiveHourReset.Format(time.RFC3339Nano),
		weeklyRemaining,
		weeklyReset.Format(time.RFC3339Nano),
	)
	return &fakeHost{
		auths: []hostAuthEntry{quotaGuardAuth(authIndex)},
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Date": []string{serverNow.Format(http.TimeFormat)}},
			Body:       []byte(body),
		},
	}
}

func quotaGuardAuth(authIndex string) hostAuthEntry {
	entry := testAntigravityAuth(authIndex, 14)
	entry.ProjectID = "project-123"
	return entry
}

func quota429Record(authIndex string) pluginapi.UsageRecord {
	return pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: authIndex,
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"QUOTA_EXHAUSTED","retryDelay":"5h"}`,
		},
	}
}

func repeatUsage(guard *guard, record pluginapi.UsageRecord, count int) {
	for range count {
		guard.handleUsage(record)
	}
}

func assertRuntimeFieldClear(t *testing.T, request runtimeOverrideRequest, field string, revision uint64) {
	t.Helper()
	if len(request.Clear) != 1 || request.Clear[0] != field {
		t.Fatalf("%s clear request = %#v", field, request)
	}
	if request.IfRevision == nil || *request.IfRevision != revision || request.IfRevisionField != field {
		t.Fatalf("%s clear CAS request = %#v", field, request)
	}
}
