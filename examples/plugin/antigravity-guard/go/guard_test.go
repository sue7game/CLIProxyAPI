package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
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
