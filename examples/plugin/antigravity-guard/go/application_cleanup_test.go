package main

import (
	"errors"
	"testing"
	"time"
)

func TestDisabledReconfigureReportsAndRetriesAllRuntimeCleanup(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("cleanup-retry", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	proxy := "direct"
	if errSet := app.guard.setProxy("cleanup-retry", &proxy); errSet != nil {
		t.Fatal(errSet)
	}
	app.guard.applyCooldown("cleanup-retry", actionDisable, 0, "quota_429", "Retry-After", now.Add(time.Hour))
	host.setOverrideError(errors.New("temporary host failure"))
	if errDisable := configurePluginEnabledResult(app, false); errDisable == nil {
		t.Fatal("failed runtime cleanup was reported as successful deactivation")
	}
	if app.loadedConfig().Enabled {
		t.Fatal("failed cleanup must not leave protection enabled")
	}
	state := app.store.snapshot("cleanup-retry", now)
	if !state.Cooldown.Active || state.ManagedProxy == nil {
		t.Fatal("failed cleanup discarded retry state")
	}
	host.setOverrideError(nil)
	if errRetry := configurePluginEnabledResult(app, false); errRetry != nil {
		t.Fatalf("equivalent disabled reconfigure did not retry cleanup: %v", errRetry)
	}
	state = app.store.snapshot("cleanup-retry", now)
	if state.Cooldown.Active || state.ManagedProxy != nil {
		t.Fatal("successful retry retained owned runtime overrides")
	}
}
