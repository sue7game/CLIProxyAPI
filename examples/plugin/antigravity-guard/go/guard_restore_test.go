package main

import (
	"errors"
	"testing"
	"time"
)

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
