package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestQuotaRefreshQueriesSubscriptionWithCredentialScope(t *testing.T) {
	host, service, store := subscriptionTestService()
	if _, errRefresh := service.refresh("ag-1", "project-1", "callback-1"); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	if len(host.authRequests) != 2 {
		t.Fatalf("request count = %d, want one quota and one subscription", len(host.authRequests))
	}
	request := host.authRequests[1]
	if request.URL != antigravitySubscriptionURL || request.Method != http.MethodPost || request.AuthIndex != "ag-1" || request.HostCallbackID != "callback-1" {
		t.Fatalf("subscription request scope = %#v", request)
	}
	if request.Headers.Get("Authorization") != "Bearer $TOKEN$" || request.Headers.Get("Content-Type") != "application/json" || request.Headers.Get("User-Agent") != testConfig().QuotaUserAgent {
		t.Fatalf("subscription headers = %#v", request.Headers)
	}
	var body map[string]map[string]string
	if errDecode := json.Unmarshal(request.Body, &body); errDecode != nil || len(body) != 1 || len(body["metadata"]) != 1 || body["metadata"]["ideType"] != "ANTIGRAVITY" {
		t.Fatalf("subscription body = %s, error = %v", request.Body, errDecode)
	}
	state := store.snapshot("ag-1", service.now())
	if !state.Quota.Found || !state.Subscription.Found || state.Subscription.Summary.Plan != "pro" || len(host.overrides()) != 0 {
		t.Fatalf("refreshed state = %#v", state)
	}
}

func TestQuotaFailureStillQueriesSubscription(t *testing.T) {
	for _, test := range []struct {
		name    string
		project string
		result  fakeAuthResult
	}{
		{"missing project", "", fakeAuthResult{}},
		{"http failure", "project-1", fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusForbidden}}},
		{"parse failure", "project-1", fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}}},
		{"network failure", "project-1", fakeAuthResult{err: errors.New("quota unavailable")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, service, store := subscriptionTestService()
			host.requestResponse, host.requestError = test.result.response, test.result.err
			if _, errRefresh := service.refresh("ag-1", test.project, "callback-1"); errRefresh == nil {
				t.Fatal("expected quota error")
			}
			state := store.snapshot("ag-1", service.now())
			if state.Quota.LastError == "" || !state.Subscription.Found || state.Subscription.Summary.Plan != "pro" {
				t.Fatalf("independent subscription state = %#v", state)
			}
			assertSubscriptionRequestCount(t, host, 1)
			expectedRequests := len(testConfig().QuotaURLs) + 1
			if test.project == "" {
				expectedRequests = 1
			}
			if len(host.authRequests) != expectedRequests {
				t.Fatalf("auth requests = %d, want %d", len(host.authRequests), expectedRequests)
			}
		})
	}
}

func TestSubscriptionFailureDoesNotFailQuota(t *testing.T) {
	for _, test := range []struct {
		name   string
		result fakeAuthResult
	}{
		{"http error", fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusForbidden, Body: []byte(`private upstream data`)}}},
		{"network error", fakeAuthResult{err: errors.New("subscription unavailable")}},
		{"malformed json", fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusOK, Body: []byte(`{`)}}},
		{"missing tier", fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, service, store := subscriptionTestService()
			host.requestResults[antigravitySubscriptionURL] = test.result
			result, errRefresh := service.refresh("ag-1", "project-1", "callback-1")
			state := store.snapshot("ag-1", service.now())
			if errRefresh != nil || !result.Found || !state.Quota.Found || state.Quota.LastError != "" || state.Subscription.Found || state.Subscription.LastError == "" {
				t.Fatalf("quota = %#v, error = %v, state = %#v", result, errRefresh, state)
			}
			if containsText(state.Subscription.LastError, "private upstream data") {
				t.Fatal("subscription error leaked upstream response body")
			}
			assertSubscriptionRequestCount(t, host, 1)
		})
	}
}

func TestSubscriptionRefreshRetainsSuccessAndClearsErrorOnRecovery(t *testing.T) {
	host, service, store := subscriptionTestService()
	now := service.now()
	service.refreshSubscription("ag-1", "callback-1")
	first := store.snapshot("ag-1", now).Subscription
	host.requestResults[antigravitySubscriptionURL] = fakeAuthResult{err: errors.New("temporary failure")}
	service.now = func() time.Time { return now.Add(time.Minute) }
	service.refreshSubscription("ag-1", "callback-1")
	failed := store.snapshot("ag-1", service.now()).Subscription
	if !failed.Found || failed.Summary != first.Summary || failed.UpdatedAt != first.UpdatedAt || failed.CheckedAt != service.now() || failed.LastError == "" {
		t.Fatalf("cached subscription after failure = %#v", failed)
	}
	host.requestResults[antigravitySubscriptionURL] = subscriptionTestResult("g1-ultra-tier")
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	service.refreshSubscription("ag-1", "callback-1")
	updated := store.snapshot("ag-1", service.now()).Subscription
	if updated.Summary.Plan != "ultra" || updated.LastError != "" || updated.UpdatedAt != service.now() {
		t.Fatalf("recovered subscription = %#v", updated)
	}
	assertSubscriptionRequestCount(t, host, 3)
}

func TestSubscriptionStateIsPerCredentialAndSurvivesGuardRecovery(t *testing.T) {
	host, service, store := subscriptionTestService()
	service.refreshSubscription("ag-1", "callback-1")
	host.requestResults[antigravitySubscriptionURL] = subscriptionTestResult("free-tier")
	service.refreshSubscription("ag-2", "callback-2")
	store.clearGuardState("ag-1")
	first := store.snapshot("ag-1", service.now()).Subscription
	second := store.snapshot("ag-2", service.now()).Subscription
	if first.Summary.Plan != "pro" || second.Summary.Plan != "free" {
		t.Fatalf("credential subscriptions = %#v, %#v", first, second)
	}
	first.Summary.Plan = "changed copy"
	if store.snapshot("ag-1", service.now()).Subscription.Summary.Plan != "pro" {
		t.Fatal("snapshot mutated stored subscription")
	}
}

func TestInvalidQuotaTargetDoesNotQuerySubscription(t *testing.T) {
	host, service, _ := subscriptionTestService()
	if _, errRefresh := service.refresh("", "project-1", "callback-1"); errRefresh == nil {
		t.Fatal("expected invalid target error")
	}
	if len(host.authRequests) != 0 {
		t.Fatal("invalid target caused an upstream request")
	}
}

func subscriptionTestService() (*fakeHost, *quotaService, *stateStore) {
	now := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	host := quotaGuardHost("ag-1", now, now.Add(5*time.Hour), 1)
	host.requestResults = map[string]fakeAuthResult{antigravitySubscriptionURL: subscriptionTestResult("g1-pro-tier")}
	store := newStateStore()
	service := newQuotaService(host, store, testConfig)
	service.now = func() time.Time { return now }
	return host, service, store
}

func subscriptionTestResult(tierID string) fakeAuthResult {
	return fakeAuthResult{response: hostAuthResponse{StatusCode: http.StatusOK, Body: []byte(`{"currentTier":{"id":"` + tierID + `"}}`)}}
}

func assertSubscriptionRequestCount(t *testing.T, host *fakeHost, expected int) {
	t.Helper()
	count := 0
	for _, request := range host.authRequests {
		if request.URL == antigravitySubscriptionURL {
			count++
		}
	}
	if count != expected {
		t.Fatalf("subscription request count = %d, want %d", count, expected)
	}
}
