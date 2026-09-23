package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCodexUsageLimitDisablesAfterTwoFailuresUsingQuotaReset(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-1", Provider: "codex", Priority: 10}}}
	store := newStateStore()
	cfg := testConfig()
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	record := pluginapi.UsageRecord{Provider: "codex", AuthIndex: "codex-1", Generate: true, Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: `{"error":{"type":"usage_limit_reached"}}`}, ResponseHeaders: http.Header{
		"X-Codex-Primary-Used-Percent": {"100"}, "X-Codex-Primary-Window-Minutes": {"10080"}, "X-Codex-Primary-Reset-After-Seconds": {"3600"},
		"X-Codex-Secondary-Used-Percent": {"20"}, "X-Codex-Secondary-Window-Minutes": {"300"}, "X-Codex-Secondary-Reset-After-Seconds": {"60"},
	}}
	guard.handleUsage(record)
	if len(host.overrides()) != 0 {
		t.Fatal("first usage_limit must not disable")
	}
	guard.handleUsage(record)
	if len(host.overrides()) != 1 || host.overrides()[0].Disabled == nil || !*host.overrides()[0].Disabled {
		t.Fatalf("overrides = %#v", host.overrides())
	}
	state := store.snapshot("codex-1", now)
	if state.Cooldown.Trigger != codexTriggerUsageLimit || !state.Cooldown.Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("cooldown = %#v", state.Cooldown)
	}
}

func TestCodexUsageLimitUsesBodyResetWithoutQuotaHeaders(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-body-reset", Provider: "codex"}}}
	store := newStateStore()
	cfg := testConfig()
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	record := pluginapi.UsageRecord{
		Provider:  "codex",
		AuthIndex: "codex-body-reset",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"error":{"type":"usage_limit_reached","resets_in_seconds":900}}`,
		},
	}

	guard.handleUsage(record)
	guard.handleUsage(record)

	state := store.snapshot("codex-body-reset", now)
	if !state.Cooldown.Active || !state.Cooldown.Until.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("cooldown = %#v", state.Cooldown)
	}
	if state.Cooldown.RetrySource != "body.resets_in_seconds" {
		t.Fatalf("retry source = %q", state.Cooldown.RetrySource)
	}
}

func TestCodexUsageLimitFallsBackWhenQuotaDeadlineMissing(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-fallback", Provider: "codex"}}}
	store := newStateStore()
	cfg := testConfig()
	cfg.FallbackCooldown = 45 * time.Minute
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	record := pluginapi.UsageRecord{
		Provider:  "codex",
		AuthIndex: "codex-fallback",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"error":{"type":"usage_limit_reached"}}`,
		},
	}

	guard.handleUsage(record)
	guard.handleUsage(record)

	state := store.snapshot("codex-fallback", now)
	if !state.Cooldown.Active || !state.Cooldown.Until.Equal(now.Add(45*time.Minute)) {
		t.Fatalf("cooldown = %#v", state.Cooldown)
	}
	if state.Cooldown.RetrySource != "fallback_cooldown" {
		t.Fatalf("retry source = %q", state.Cooldown.RetrySource)
	}
}

func TestCodexUnauthorizedRequiresManualRecovery(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-401", Provider: "codex"}}}
	store := newStateStore()
	cfg := testConfig()
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	guard.handleUsage(pluginapi.UsageRecord{Provider: "codex", AuthIndex: "codex-401", Generate: true, Failed: true, Failure: pluginapi.UsageFailure{StatusCode: http.StatusUnauthorized, Body: `{"error":{"type":"invalid_token"}}`}})
	state := store.snapshot("codex-401", now)
	if !state.Cooldown.Active || !state.Cooldown.ManualReleaseRequired || state.Cooldown.Trigger != codexTriggerUnauthorized {
		t.Fatalf("state = %#v", state.Cooldown)
	}
	if len(host.overrides()) != 1 || host.overrides()[0].Disabled == nil || !*host.overrides()[0].Disabled {
		t.Fatalf("overrides = %#v", host.overrides())
	}
}

func TestConfiguredDisableClearsEveryCodexGuardState(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		trigger string
		manual  bool
	}{
		{name: "usage limit", trigger: codexTriggerUsageLimit},
		{name: "unauthorized", trigger: codexTriggerUnauthorized, manual: true},
		{name: "other plugin disable", trigger: "codex_other_disable", manual: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
			host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-manual", Provider: "codex"}}}
			store := newStateStore()
			cfg := testConfig()
			guard := newGuard(host, store, func() guardConfig { return cfg })
			guard.now = func() time.Time { return now }
			store.observeCodex("codex-manual", "usage_limit_reached", http.StatusTooManyRequests, nil, "usage limit", now)
			guard.applyCodexDisable("codex-manual", testCase.trigger, now.Add(time.Hour), testCase.trigger, testCase.manual)
			host.setConfiguredDisabled("codex-manual", true)

			guard.reconcileConfiguredDisables(now)

			state := store.snapshot("codex-manual", now)
			if state.Cooldown.Active {
				t.Fatalf("cooldown should be cleared: %#v", state.Cooldown)
			}
			if state.Codex.ConsecutiveUsageLimit != 0 || state.Codex.LastErrorType != "" || state.Codex.LastStatusCode != 0 {
				t.Fatalf("Codex error state should be cleared: %#v", state.Codex)
			}
			entries, errList := host.ListAuths()
			if errList != nil {
				t.Fatal(errList)
			}
			if !entries[0].ConfiguredDisabled || entries[0].RuntimeOverride != nil {
				t.Fatalf("configured disable should remain while runtime override is cleared: %#v", entries[0])
			}
		})
	}
}

func TestManualRecoverCodexClearsPluginStateAndRuntimeDisable(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-recover", Provider: "codex"}}}
	store := newStateStore()
	cfg := testConfig()
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	guard.handleUsage(pluginapi.UsageRecord{Provider: "codex", AuthIndex: "codex-recover", Generate: true, Failed: true, Failure: pluginapi.UsageFailure{StatusCode: http.StatusUnauthorized, Body: `{"error":{"type":"invalid_token"}}`}})
	store.observeCodex("codex-recover", "usage_limit_reached", http.StatusTooManyRequests, http.Header{
		"X-Codex-Primary-Used-Percent":   {"100"},
		"X-Codex-Primary-Window-Minutes": {"10080"},
	}, "stale", now)

	if errRecover := guard.manualRecover("codex-recover"); errRecover != nil {
		t.Fatal(errRecover)
	}
	state := store.snapshot("codex-recover", now)
	if state.Cooldown.Active || state.Codex.ConsecutiveUsageLimit != 0 || state.Codex.LastErrorType != "" || state.Codex.LastStatusCode != 0 || state.Codex.Weekly.Found {
		t.Fatalf("state after recovery = %#v", state)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if entries[0].RuntimeOverride != nil {
		t.Fatalf("runtime disable remains after recovery: %#v", entries[0].RuntimeOverride)
	}
}

func TestManualRecoverKeepsConfiguredCodexDisable(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-config-disabled", Provider: "codex", ConfiguredDisabled: true, Disabled: true}}}
	store := newStateStore()
	cfg := testConfig()
	guard := newGuard(host, store, func() guardConfig { return cfg })
	guard.now = func() time.Time { return now }
	guard.applyCodexDisable("codex-config-disabled", codexTriggerUnauthorized, now.Add(time.Hour), codexTriggerUnauthorized, true)
	if errRecover := guard.manualRecover("codex-config-disabled"); errRecover != nil {
		t.Fatal(errRecover)
	}
	entries, errList := host.ListAuths()
	if errList != nil {
		t.Fatal(errList)
	}
	if !entries[0].ConfiguredDisabled {
		t.Fatal("manual recovery cleared CPA configured disable")
	}
}
