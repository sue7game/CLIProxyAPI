package main

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

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
	if got := len(host.authRequests); got != 4 {
		t.Fatalf("auth request count = %d, want two quota/subscription pairs", got)
	}
	if got := len(host.overrides()); got != 4 {
		t.Fatalf("override request count = %d, want 4", got)
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
