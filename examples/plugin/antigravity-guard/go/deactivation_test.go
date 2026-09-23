package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestPluginDeactivationClearsCooldownAndManagedProxy(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-cleanup", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }

	proxyURL := "direct"
	if errSet := app.guard.setProxy("ag-cleanup", &proxyURL); errSet != nil {
		t.Fatal(errSet)
	}
	app.guard.applyCooldown("ag-cleanup", actionDisable, 0, "quota_429", "Retry-After", now.Add(time.Hour))
	configurePluginEnabled(t, app, false)

	state := app.store.snapshot("ag-cleanup", now)
	if state.Cooldown.Active || state.ManagedProxy != nil {
		t.Fatalf("deactivated state = %#v", state)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride != nil {
		t.Fatalf("runtime override was not cleared: %#v", entries[0].RuntimeOverride)
	}
	assertDeactivationCASRequests(t, host.overrides())
}

func TestPluginDeactivationClearsWeeklyQuarantineFields(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-weekly-cleanup", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }

	app.guard.operations.Lock()
	app.guard.applyWeeklyQuarantineLocked("ag-weekly-cleanup", 13, now.Add(5*time.Hour), retrySourceWeeklyQuotaReset)
	app.guard.operations.Unlock()
	configurePluginEnabled(t, app, false)

	requests := host.overrides()
	if len(requests) != 3 {
		t.Fatalf("weekly cleanup requests = %#v", requests)
	}
	assertRuntimeFieldClear(t, requests[1], "priority", 1)
	assertRuntimeFieldClear(t, requests[2], "disabled", 1)
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride != nil {
		t.Fatalf("weekly cleanup left runtime override: %#v", entries[0].RuntimeOverride)
	}
}

func TestPluginDeactivationIgnores429Usage(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-disabled", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	configurePluginEnabled(t, app, false)

	app.guard.handleUsage(quota429Usage("ag-disabled"))
	proxyURL := "direct"
	if errSet := app.guard.setProxy("ag-disabled", &proxyURL); errSet == nil {
		t.Fatal("disabled plugin accepted a new managed proxy")
	}
	if requests := host.overrides(); len(requests) != 0 {
		t.Fatalf("disabled plugin wrote a runtime override: %#v", requests)
	}
	if usage := app.store.snapshot("ag-disabled", time.Now()).Usage; usage.RateLimited != 0 {
		t.Fatalf("disabled plugin observed usage: %#v", usage)
	}
}

func TestPluginReactivationCanApplyCooldownAgain(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-reactivate", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	configurePluginEnabled(t, app, false)
	app.guard.handleUsage(quota429Usage("ag-reactivate"))

	configurePluginEnabled(t, app, true)
	repeatUsage(app.guard, quota429Usage("ag-reactivate"), app.loadedConfig().Consecutive429Limit)

	requests := host.overrides()
	if len(requests) != 1 || requests[0].Disabled == nil || !*requests[0].Disabled {
		t.Fatalf("reactivated plugin requests = %#v", requests)
	}
	if !app.store.snapshot("ag-reactivate", time.Now()).Cooldown.Active {
		t.Fatal("reactivated plugin did not create a cooldown")
	}
}

func TestPluginDeactivationUsesCASForManagedProxyCleanup(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-proxy-cas", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	proxyURL := "direct"
	if errSet := app.guard.setProxy("ag-proxy-cas", &proxyURL); errSet != nil {
		t.Fatal(errSet)
	}
	host.setRuntimeOverride("ag-proxy-cas", &runtimeOverride{ProxyURL: &proxyURL})

	configurePluginEnabled(t, app, false)

	requests := host.overrides()
	if len(requests) != 2 || requests[1].IfRevision == nil || *requests[1].IfRevision != 1 || requests[1].IfRevisionField != "proxy_url" {
		t.Fatalf("proxy cleanup request = %#v", requests)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride == nil || entries[0].RuntimeOverride.ProxyURL == nil || *entries[0].RuntimeOverride.ProxyURL != proxyURL {
		t.Fatalf("manual proxy takeover was cleared: %#v", entries[0].RuntimeOverride)
	}
	if managed := app.store.snapshot("ag-proxy-cas", time.Now()).ManagedProxy; managed != nil {
		t.Fatalf("stale managed proxy tracking was retained: %#v", managed)
	}
}

func TestPluginDeactivationRetriesManagedProxyCleanupAfterHostError(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-proxy-retry", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.July, 27, 14, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	proxyURL := "direct"
	if errSet := app.guard.setProxy("ag-proxy-retry", &proxyURL); errSet != nil {
		t.Fatal(errSet)
	}
	host.setOverrideError(errors.New("temporary override failure"))

	configurePluginEnabled(t, app, false)
	if managed := app.store.snapshot("ag-proxy-retry", now).ManagedProxy; managed == nil {
		t.Fatal("failed proxy cleanup discarded retry tracking")
	}

	host.setOverrideError(nil)
	app.guard.retryManagedProxyCleanup(now.Add(testConfig().RestoreRetry))

	if managed := app.store.snapshot("ag-proxy-retry", now).ManagedProxy; managed != nil {
		t.Fatalf("retried proxy cleanup retained managed state: %#v", managed)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride != nil {
		t.Fatalf("retried proxy cleanup left runtime override: %#v", entries[0].RuntimeOverride)
	}
	if requests := host.overrides(); len(requests) != 3 {
		t.Fatalf("runtime override request count = %d, want 3: %#v", len(requests), requests)
	}
}

func configurePluginEnabled(t *testing.T, app *application, enabled bool) {
	t.Helper()
	configYAML := []byte("enabled: false\n")
	if enabled {
		configYAML = []byte("enabled: true\n")
	}
	raw, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: configYAML})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errConfigure := app.configure(raw); errConfigure != nil {
		t.Fatal(errConfigure)
	}
}

func quota429Usage(authIndex string) pluginapi.UsageRecord {
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

func assertDeactivationCASRequests(t *testing.T, requests []runtimeOverrideRequest) {
	t.Helper()
	if len(requests) != 4 {
		t.Fatalf("runtime override request count = %d, want 4: %#v", len(requests), requests)
	}
	disabledRestore := requests[2]
	if len(disabledRestore.Clear) != 1 || disabledRestore.Clear[0] != "disabled" || disabledRestore.IfRevision == nil || *disabledRestore.IfRevision != 1 {
		t.Fatalf("cooldown restore request = %#v", disabledRestore)
	}
	proxyCleanup := requests[3]
	if len(proxyCleanup.Clear) != 1 || proxyCleanup.Clear[0] != "proxy_url" || proxyCleanup.IfRevision == nil || *proxyCleanup.IfRevision != 1 {
		t.Fatalf("proxy cleanup request = %#v", proxyCleanup)
	}
}
