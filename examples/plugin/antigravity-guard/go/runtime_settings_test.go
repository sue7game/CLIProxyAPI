package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRuntimeSettingsDoNotMigrateActiveCooldowns(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-existing", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }

	app.guard.applyCooldown("ag-existing", actionDisable, 0, "quota_429", "Retry-After", now.Add(time.Hour))
	response := app.dispatchManagement(managementRequest{
		Method: http.MethodPost,
		Path:   managementAPIPath + "/settings",
		Body:   []byte(`{"auto_429_enabled":true,"action":"priority","temporary_priority":7,"consecutive_429_threshold":5}`),
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}
	var view configView
	if errDecode := json.Unmarshal(response.Body, &view); errDecode != nil {
		t.Fatalf("decode settings response: %v", errDecode)
	}
	if !view.Auto429Enabled || view.Action != actionPriority || view.TemporaryPriority != 7 || view.Consecutive429Threshold != 5 {
		t.Fatalf("settings response = %#v", view)
	}
	if view.Quota429Threshold != 5 || view.Generic429Threshold != 5 {
		t.Fatalf("legacy threshold views = %d/%d, want 5/5", view.Quota429Threshold, view.Generic429Threshold)
	}

	requests := host.overrides()
	if len(requests) != 1 {
		t.Fatalf("active cooldown was migrated: %#v", requests)
	}
	existing := app.store.snapshot("ag-existing", now)
	if existing.Cooldown.Action != actionDisable || existing.Cooldown.Priority != nil {
		t.Fatalf("existing cooldown changed after settings update: %#v", existing.Cooldown)
	}
	viewCooldown := cooldownViewFromState(existing.Cooldown, false, 14, now)
	if viewCooldown == nil || viewCooldown.Action != actionDisable || viewCooldown.Priority != nil {
		t.Fatalf("existing cooldown view changed after settings update: %#v", viewCooldown)
	}
}

func TestRuntimeSettingsPriorityAppliesToFutureCooldowns(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-new", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	response := app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"priority","temporary_priority":7,"consecutive_429_threshold":1}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}

	app.guard.handleUsage(pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "ag-new",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"QUOTA_EXHAUSTED","retryDelay":"1h"}`,
		},
	})
	requests := host.overrides()
	if len(requests) != 1 || requests[0].Priority == nil || *requests[0].Priority != 7 || requests[0].Disabled != nil {
		t.Fatalf("new cooldown request = %#v, want priority 7", requests)
	}
	created := app.store.snapshot("ag-new", now)
	if created.Cooldown.Action != actionPriority || created.Cooldown.Priority == nil || *created.Cooldown.Priority != 7 {
		t.Fatalf("new cooldown state = %#v", created.Cooldown)
	}
	viewCooldown := cooldownViewFromState(created.Cooldown, false, 14, now)
	if viewCooldown == nil || viewCooldown.Priority == nil || *viewCooldown.Priority != 7 {
		t.Fatalf("new cooldown view = %#v", viewCooldown)
	}
}

func TestRuntimeSettingsMissingThresholdPreservesCurrentValue(t *testing.T) {
	app := newApplication(&fakeHost{})
	defer app.shutdown()

	response := app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"priority","temporary_priority":7,"consecutive_429_threshold":6}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initial settings status = %d, body=%s", response.StatusCode, response.Body)
	}
	response = app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"disable","temporary_priority":9}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("legacy settings status = %d, body=%s", response.StatusCode, response.Body)
	}

	var view configView
	if errDecode := json.Unmarshal(response.Body, &view); errDecode != nil {
		t.Fatalf("decode settings response: %v", errDecode)
	}
	if view.Consecutive429Threshold != 6 || view.Quota429Threshold != 6 || view.Generic429Threshold != 6 {
		t.Fatalf("threshold changed after legacy payload: %#v", view)
	}
}

func TestRuntimeSettingsDisablingGuardClearsActiveCooldownAndBlocksNewOnes(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{
		testAntigravityAuth("ag-existing", 14),
		testAntigravityAuth("ag-new", 14),
	}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	app.guard.applyCooldown("ag-existing", actionPriority, 9, "quota_429", "Retry-After", now.Add(time.Hour))

	response := app.settingsResponse([]byte(`{"auto_429_enabled":false,"action":"disable","temporary_priority":3}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}
	requests := host.overrides()
	if len(requests) != 2 || len(requests[1].Clear) != 1 || requests[1].Clear[0] != "priority" {
		t.Fatalf("disable settings requests = %#v", requests)
	}
	if state := app.store.snapshot("ag-existing", now); state.Cooldown.Active || state.Cooldown.Pending {
		t.Fatalf("active cooldown was not cleared: %#v", state.Cooldown)
	}

	app.guard.handleUsage(pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "ag-new",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"reason":"QUOTA_EXHAUSTED","retryDelay":"1h"}`,
		},
	})
	if requests = host.overrides(); len(requests) != 2 {
		t.Fatalf("disabled guard wrote a new cooldown: %#v", requests)
	}
}

func TestRuntimeSettingsDisabledGuardDoesNotCarry429StreakIntoReenable(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-streak", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }

	disableResponse := app.settingsResponse([]byte(`{"auto_429_enabled":false,"action":"disable","temporary_priority":13}`))
	if disableResponse.StatusCode != http.StatusOK {
		t.Fatalf("disable settings status = %d, body=%s", disableResponse.StatusCode, disableResponse.Body)
	}
	repeatUsage(app.guard, quota429Record("ag-streak"), 5)
	if state := app.store.snapshot("ag-streak", now); state.Usage.Consecutive429 != 0 {
		t.Fatalf("disabled guard retained 429 streak: %#v", state.Usage)
	}

	enableResponse := app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"disable","temporary_priority":13}`))
	if enableResponse.StatusCode != http.StatusOK {
		t.Fatalf("enable settings status = %d, body=%s", enableResponse.StatusCode, enableResponse.Body)
	}
	repeatUsage(app.guard, quota429Record("ag-streak"), app.loadedConfig().Consecutive429Limit-1)
	if requests := host.overrides(); len(requests) != 0 {
		t.Fatalf("reenabled guard triggered before a fresh streak: %#v", requests)
	}
	app.guard.handleUsage(quota429Record("ag-streak"))
	if requests := host.overrides(); len(requests) != 1 || requests[0].Disabled == nil || !*requests[0].Disabled {
		t.Fatalf("reenabled guard did not trigger after a fresh streak: %#v", requests)
	}
}

func TestRuntimeSettingsDisablingGuardReportsCleanupSummary(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{
		testAntigravityAuth("ag-manual", 14),
		testAntigravityAuth("ag-restored", 14),
	}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	app.guard.applyCooldown("ag-manual", actionPriority, 13, "quota_429", "Retry-After", now.Add(5*time.Hour))
	app.guard.applyCooldown("ag-restored", actionPriority, 13, "quota_429", "Retry-After", now.Add(5*time.Hour))

	manualPriority := 11
	host.setRuntimeOverride("ag-manual", &runtimeOverride{Priority: &manualPriority})
	response := app.settingsResponse([]byte(`{"auto_429_enabled":false,"action":"priority","temporary_priority":13}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}

	var result runtime429SettingsResult
	if errDecode := json.Unmarshal(response.Body, &result); errDecode != nil {
		t.Fatalf("decode settings response: %v", errDecode)
	}
	if result.Auto429Enabled {
		t.Fatalf("settings response did not disable guard: %#v", result)
	}
	if result.Cleanup == nil {
		t.Fatalf("settings response omitted cleanup summary: %s", response.Body)
	}
	if result.Cleanup.Attempted != 2 || result.Cleanup.Restored != 1 || result.Cleanup.ManualTakeover != 1 || len(result.Cleanup.Failed) != 0 {
		t.Fatalf("cleanup summary = %#v", result.Cleanup)
	}

	manualState := app.store.snapshot("ag-manual", now)
	if manualState.Cooldown.Active || manualState.Cooldown.RestoreOutcome != restoreOutcomeManualTakeover {
		t.Fatalf("manual takeover state = %#v", manualState.Cooldown)
	}
	restoredState := app.store.snapshot("ag-restored", now)
	if restoredState.Cooldown.Active || restoredState.Cooldown.RestoreOutcome != restoreOutcomeRestored {
		t.Fatalf("restored state = %#v", restoredState.Cooldown)
	}
}

func TestRuntimeSettingsDisablingGuardRetriesFailedImmediateRestore(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-existing", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	app.guard.applyCooldown("ag-existing", actionPriority, 13, "quota_429", "Retry-After", now.Add(5*time.Hour))
	host.setOverrideError(errors.New("temporary host failure"))

	response := app.settingsResponse([]byte(`{"auto_429_enabled":false,"action":"priority","temporary_priority":13}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}
	var result runtime429SettingsResult
	if errDecode := json.Unmarshal(response.Body, &result); errDecode != nil {
		t.Fatalf("decode settings response: %v", errDecode)
	}
	if result.Auto429Enabled || result.Cleanup == nil {
		t.Fatalf("failed cleanup response = %#v", result)
	}
	if result.Cleanup.Attempted != 1 || result.Cleanup.Restored != 0 || result.Cleanup.ManualTakeover != 0 {
		t.Fatalf("failed cleanup summary = %#v", result.Cleanup)
	}
	if got := result.Cleanup.Failed["ag-existing"]; got != "temporary host failure" {
		t.Fatalf("failed cleanup detail = %q, response=%s", got, response.Body)
	}
	state := app.store.snapshot("ag-existing", now)
	wantRetry := now.Add(app.loadedConfig().RestoreRetry)
	if !state.Cooldown.Active || !state.Cooldown.Until.Equal(now) || !state.Cooldown.NextRestoreAttempt.Equal(wantRetry) {
		t.Fatalf("immediate restore retry state = %#v", state.Cooldown)
	}
	if state.Cooldown.phase(now) != "retry_wait" {
		t.Fatalf("immediate restore phase = %q", state.Cooldown.phase(now))
	}

	host.setOverrideError(nil)
	app.guard.restoreDue(wantRetry)
	state = app.store.snapshot("ag-existing", wantRetry)
	if state.Cooldown.Active || state.Cooldown.RestoreOutcome != restoreOutcomeRestored {
		t.Fatalf("immediate restore retry completion = %#v", state.Cooldown)
	}
}

func TestRuntimeSettingsRejectInvalidRequestsWithoutChangingConfiguration(t *testing.T) {
	tests := map[string]string{
		"empty body":           "",
		"empty object":         `{}`,
		"missing enabled":      `{"action":"disable","temporary_priority":13}`,
		"missing action":       `{"auto_429_enabled":true,"temporary_priority":13}`,
		"missing priority":     `{"auto_429_enabled":true,"action":"disable"}`,
		"null enabled":         `{"auto_429_enabled":null,"action":"disable","temporary_priority":13}`,
		"string enabled":       `{"auto_429_enabled":"true","action":"disable","temporary_priority":13}`,
		"invalid action":       `{"auto_429_enabled":true,"action":"pause","temporary_priority":13}`,
		"non-canonical action": `{"auto_429_enabled":true,"action":" Disable ","temporary_priority":13}`,
		"fractional priority":  `{"auto_429_enabled":true,"action":"priority","temporary_priority":1.5}`,
		"string priority":      `{"auto_429_enabled":true,"action":"priority","temporary_priority":"13"}`,
		"zero threshold":       `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"consecutive_429_threshold":0}`,
		"negative threshold":   `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"consecutive_429_threshold":-1}`,
		"null threshold":       `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"consecutive_429_threshold":null}`,
		"fractional threshold": `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"consecutive_429_threshold":1.5}`,
		"string threshold":     `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"consecutive_429_threshold":"3"}`,
		"unknown field":        `{"auto_429_enabled":true,"action":"disable","temporary_priority":13,"persist":true}`,
		"trailing object":      `{"auto_429_enabled":true,"action":"disable","temporary_priority":13}{}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			host := &fakeHost{}
			app := newApplication(host)
			defer app.shutdown()
			before := app.loadedConfig()

			response := app.settingsResponse([]byte(body))
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, body=%s", response.StatusCode, response.Body)
			}
			after := app.loadedConfig()
			if before.Auto429Enabled != after.Auto429Enabled || before.Action != after.Action || before.TemporaryPriority != after.TemporaryPriority || before.Consecutive429Limit != after.Consecutive429Limit {
				t.Fatalf("invalid request changed config from %#v to %#v", before, after)
			}
			if len(host.overrides()) != 0 {
				t.Fatalf("invalid request wrote runtime override: %#v", host.overrides())
			}
		})
	}
}

func TestRuntimeSettingsSurviveEquivalentLifecycleConfiguration(t *testing.T) {
	host := &fakeHost{}
	app := newApplication(host)
	defer app.shutdown()
	configYAML := []byte("auto_429_enabled: true\naction: disable\ntemporary_priority: 14\n")
	rawLifecycle, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: configYAML})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errConfigure := app.configure(rawLifecycle); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	if response := app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"priority","temporary_priority":2,"consecutive_429_threshold":8}`)); response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}
	if config := app.loadedConfig(); config.Action != actionPriority || config.TemporaryPriority != 2 || config.Consecutive429Limit != 8 {
		t.Fatalf("runtime config = %#v", config)
	}

	if errConfigure := app.configure(rawLifecycle); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	config := app.loadedConfig()
	if !config.Auto429Enabled || config.Action != actionPriority || config.TemporaryPriority != 2 || config.Consecutive429Limit != 8 {
		t.Fatalf("equivalent lifecycle config replaced runtime settings: %#v", config)
	}
}

func TestRuntimeSettingsAreReplacedWhenLifecycleConfigurationChanges(t *testing.T) {
	app := newApplication(&fakeHost{})
	defer app.shutdown()
	initialYAML := []byte("auto_429_enabled: true\naction: disable\ntemporary_priority: 14\n")
	initialLifecycle, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: initialYAML})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errConfigure := app.configure(initialLifecycle); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	if response := app.settingsResponse([]byte(`{"auto_429_enabled":true,"action":"priority","temporary_priority":2,"consecutive_429_threshold":8}`)); response.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d, body=%s", response.StatusCode, response.Body)
	}

	changedYAML := []byte("auto_429_enabled: true\naction: disable\ntemporary_priority: 15\nconsecutive_429_threshold: 4\n")
	changedLifecycle, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: changedYAML})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errConfigure := app.configure(changedLifecycle); errConfigure != nil {
		t.Fatal(errConfigure)
	}
	config := app.loadedConfig()
	if !config.Auto429Enabled || config.Action != actionDisable || config.TemporaryPriority != 15 || config.Consecutive429Limit != 4 {
		t.Fatalf("changed lifecycle config did not replace runtime settings: %#v", config)
	}
}

func TestRuntimeSettingsConcurrentReadsAndWrites(t *testing.T) {
	app := newApplication(&fakeHost{})
	defer app.shutdown()
	allowed := func(config guardConfig) bool {
		return (config.Auto429Enabled && config.Action == actionPriority && config.TemporaryPriority == 111 && config.Consecutive429Limit == 11) ||
			(!config.Auto429Enabled && config.Action == actionDisable && config.TemporaryPriority == 222 && config.Consecutive429Limit == 22) ||
			(config.Auto429Enabled && config.Action == actionDisable && config.TemporaryPriority == 13 && config.Consecutive429Limit == 3)
	}

	var wait sync.WaitGroup
	errors := make(chan guardConfig, 1)
	for index := 0; index < 64; index++ {
		wait.Add(2)
		go func(usePriority bool) {
			defer wait.Done()
			threshold := 22
			settings := runtime429Settings{Auto429Enabled: usePriority, Action: actionDisable, TemporaryPriority: 222, Consecutive429Threshold: &threshold}
			if usePriority {
				settings.Action = actionPriority
				settings.TemporaryPriority = 111
				threshold = 11
			}
			app.applyRuntime429Settings(settings)
		}(index%2 == 0)
		go func() {
			defer wait.Done()
			if config := app.loadedConfig(); !allowed(config) {
				select {
				case errors <- config:
				default:
				}
			}
		}()
	}
	wait.Wait()
	close(errors)
	if config, found := <-errors; found {
		t.Fatalf("observed partially updated config: %#v", config)
	}
}
