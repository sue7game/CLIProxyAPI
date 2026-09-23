package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestDecodeConfigSeparatesHostEnabledFromAutomatic429Protection(t *testing.T) {
	config, errDecode := decodeConfig([]byte("enabled: true\npriority: 10\nauto_429_enabled: false\n"))
	if errDecode != nil {
		t.Fatalf("decodeConfig() error = %v", errDecode)
	}
	if config.Auto429Enabled {
		t.Fatal("host enabled flag must not enable automatic 429 protection")
	}
	if !config.Enabled {
		t.Fatal("host enabled flag was not decoded")
	}
}

func TestDecodeConfigDefaultsAutomatic429ProtectionAndCurrentUserAgent(t *testing.T) {
	config, errDecode := decodeConfig([]byte("enabled: true\npriority: 10\n"))
	if errDecode != nil {
		t.Fatalf("decodeConfig() error = %v", errDecode)
	}
	if !config.Auto429Enabled {
		t.Fatal("automatic 429 protection should default to enabled")
	}
	if !config.Enabled {
		t.Fatal("plugin should default to enabled when the host flag is absent")
	}
	wantUserAgent := "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)"
	if config.QuotaUserAgent != wantUserAgent {
		t.Fatalf("QuotaUserAgent = %q, want %q", config.QuotaUserAgent, wantUserAgent)
	}
	if config.Consecutive429Limit != 3 {
		t.Fatalf("Consecutive429Limit = %d, want 3", config.Consecutive429Limit)
	}
	if config.WeeklyGroup != "gemini-models" {
		t.Fatalf("WeeklyGroup = %q, want gemini-models", config.WeeklyGroup)
	}
}

func TestDecodeConfigUsesUnifiedConsecutive429Threshold(t *testing.T) {
	config, errDecode := decodeConfig([]byte("consecutive_429_threshold: 5\n"))
	if errDecode != nil {
		t.Fatalf("decodeConfig() error = %v", errDecode)
	}
	if config.Consecutive429Limit != 5 {
		t.Fatalf("Consecutive429Limit = %d, want 5", config.Consecutive429Limit)
	}
}

func TestDecodeConfigAllowsCheckingEveryWeeklyGroupExplicitly(t *testing.T) {
	config, errDecode := decodeConfig([]byte("weekly_group: \"\"\n"))
	if errDecode != nil {
		t.Fatalf("decodeConfig() error = %v", errDecode)
	}
	if config.WeeklyGroup != "" {
		t.Fatalf("WeeklyGroup = %q, want explicit empty value", config.WeeklyGroup)
	}
}

func TestDecodeConfigMigratesLegacy429Thresholds(t *testing.T) {
	config, errDecode := decodeConfig([]byte("quota_429_threshold: 1\ngeneric_429_threshold: 4\n"))
	if errDecode != nil {
		t.Fatalf("decodeConfig() error = %v", errDecode)
	}
	if config.Consecutive429Limit != 4 {
		t.Fatalf("Consecutive429Limit = %d, want 4", config.Consecutive429Limit)
	}
}

func TestDecodeConfigRejectsInvalidUnified429Threshold(t *testing.T) {
	if _, errDecode := decodeConfig([]byte("consecutive_429_threshold: 0\n")); errDecode == nil {
		t.Fatal("decodeConfig() accepted a zero consecutive_429_threshold")
	}
}

func TestConfigFieldsExposeUnified429Threshold(t *testing.T) {
	fields := configFields()
	foundUnified := false
	for _, field := range fields {
		switch field.Name {
		case "consecutive_429_threshold":
			foundUnified = true
		case "quota_429_threshold", "generic_429_threshold":
			t.Fatalf("configFields() still exposes legacy field %q", field.Name)
		}
	}
	if !foundUnified {
		t.Fatal("configFields() omitted consecutive_429_threshold")
	}
}

func TestSameNormalizedReconfigurePreservesRuntimeSettings(t *testing.T) {
	app := newApplication(&fakeHost{})
	defer app.shutdown()

	legacyLifecycle := lifecycleConfigRequest(t, []byte("quota_429_threshold: 1\ngeneric_429_threshold: 3\n"))
	if _, errRegister := app.handleMethod(pluginabi.MethodPluginRegister, legacyLifecycle); errRegister != nil {
		t.Fatalf("plugin.register error = %v", errRegister)
	}

	threshold := 6
	app.applyRuntime429Settings(runtime429Settings{
		Auto429Enabled:          false,
		Action:                  actionPriority,
		TemporaryPriority:       7,
		Consecutive429Threshold: &threshold,
	})

	unifiedLifecycle := lifecycleConfigRequest(t, []byte("consecutive_429_threshold: 3\n"))
	if _, errReconfigure := app.handleMethod(pluginabi.MethodPluginReconfigure, unifiedLifecycle); errReconfigure != nil {
		t.Fatalf("plugin.reconfigure error = %v", errReconfigure)
	}

	config := app.loadedConfig()
	if config.Auto429Enabled || config.Action != actionPriority || config.TemporaryPriority != 7 || config.Consecutive429Limit != 6 {
		t.Fatalf("same normalized reconfigure replaced runtime settings: %#v", config)
	}
}

func TestChangedLifecycleConfigurationResetsRuntimeSettings(t *testing.T) {
	app := newApplication(&fakeHost{})
	defer app.shutdown()

	initialLifecycle := lifecycleConfigRequest(t, []byte("consecutive_429_threshold: 3\nfallback_cooldown: 5h\n"))
	if errConfigure := app.configure(initialLifecycle); errConfigure != nil {
		t.Fatalf("configure() initial error = %v", errConfigure)
	}

	threshold := 6
	app.applyRuntime429Settings(runtime429Settings{
		Auto429Enabled:          false,
		Action:                  actionPriority,
		TemporaryPriority:       7,
		Consecutive429Threshold: &threshold,
	})

	changedLifecycle := lifecycleConfigRequest(t, []byte("consecutive_429_threshold: 3\nfallback_cooldown: 6h\n"))
	if errConfigure := app.configure(changedLifecycle); errConfigure != nil {
		t.Fatalf("configure() changed error = %v", errConfigure)
	}

	config := app.loadedConfig()
	if !config.Auto429Enabled || config.Action != actionDisable || config.TemporaryPriority != 13 || config.Consecutive429Limit != 3 {
		t.Fatalf("changed lifecycle config did not reset runtime settings: %#v", config)
	}
	if config.FallbackCooldown != 6*time.Hour {
		t.Fatalf("FallbackCooldown = %s, want 6h", config.FallbackCooldown)
	}
}

func lifecycleConfigRequest(t *testing.T, configYAML []byte) []byte {
	t.Helper()
	rawRequest, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: configYAML})
	if errMarshal != nil {
		t.Fatalf("json.Marshal() error = %v", errMarshal)
	}
	return rawRequest
}

func TestReconfigureDisablingAutomatic429ClearsAutomaticOverride(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-1", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	app.guard.applyCooldown("ag-1", actionDisable, 0, "quota_429", "Retry-After", time.Now().Add(time.Hour))

	rawRequest, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: []byte("enabled: true\npriority: 10\nauto_429_enabled: false\n")})
	if errMarshal != nil {
		t.Fatalf("json.Marshal() error = %v", errMarshal)
	}
	if errConfigure := app.configure(rawRequest); errConfigure != nil {
		t.Fatalf("configure() error = %v", errConfigure)
	}

	requests := host.overrides()
	if len(requests) != 2 {
		t.Fatalf("runtime override request count = %d, want 2", len(requests))
	}
	if len(requests[1].Clear) != 1 || requests[1].Clear[0] != "disabled" {
		t.Fatalf("automatic override clear request = %#v", requests[1])
	}
}

func TestReconfigureDisablingAutomatic429RejectsStaleUsageDecision(t *testing.T) {
	host := &fakeHost{}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }

	staleConfig := app.loadedConfig()
	rawRequest, errMarshal := json.Marshal(lifecycleRequest{ConfigYAML: []byte("enabled: true\nauto_429_enabled: false\n")})
	if errMarshal != nil {
		t.Fatalf("json.Marshal() error = %v", errMarshal)
	}
	if errConfigure := app.configure(rawRequest); errConfigure != nil {
		t.Fatalf("configure() error = %v", errConfigure)
	}

	app.guard.handleRateLimit("ag-1", pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: "ag-1",
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"QUOTA_EXHAUSTED","retryDelay":"5h"}`,
		},
	}, staleConfig.Consecutive429Limit, staleConfig, now)

	if requests := host.overrides(); len(requests) != 0 {
		t.Fatalf("stale usage decision wrote runtime override after disable: %#v", requests)
	}
	state := app.store.snapshot("ag-1", now)
	if state.Cooldown.Active || state.Cooldown.Pending {
		t.Fatalf("stale usage decision created cooldown state after disable: %#v", state.Cooldown)
	}
}
