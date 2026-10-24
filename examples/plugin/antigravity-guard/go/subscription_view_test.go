package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestSubscriptionDashboardUsesCachedAntigravityStateOnly(t *testing.T) {
	host, _, _ := subscriptionTestService()
	host.auths = append(host.auths, hostAuthEntry{AuthIndex: "codex-1", Provider: "codex"})
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	app.auth.now = func() time.Time { return now }
	for _, authIndex := range []string{"ag-1", "codex-1"} {
		app.store.recordSubscriptionResult(authIndex, subscriptionSummary{Plan: "pro", TierID: "g1-pro-tier"}, nil, now)
	}
	for range 3 {
		response := app.stateResponse("dashboard-callback")
		var state dashboardState
		if errDecode := json.Unmarshal(response.Body, &state); errDecode != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("dashboard status = %d, decode = %v", response.StatusCode, errDecode)
		}
		if len(state.Credentials) != 1 || state.Credentials[0].Subscription == nil || state.Credentials[0].Subscription.Plan != "pro" {
			t.Fatalf("Antigravity subscription view = %#v", state.Credentials)
		}
		if len(state.CodexCredentials) != 1 || state.CodexCredentials[0].Subscription != nil {
			t.Fatalf("Codex subscription view = %#v", state.CodexCredentials)
		}
	}
	if len(host.authRequests) != 0 || len(host.overrides()) != 0 {
		t.Fatal("cached dashboard polling caused upstream requests or routing changes")
	}
}

func TestQuotaManagementResponseIncludesSubscription(t *testing.T) {
	host, _, _ := subscriptionTestService()
	app := newApplication(host)
	defer app.shutdown()
	response := app.quotaResponse([]byte(`{"auth_index":"ag-1"}`), "quota-callback")
	var result struct {
		Subscription *subscriptionView `json:"subscription"`
	}
	if errDecode := json.Unmarshal(response.Body, &result); errDecode != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("quota response = %d, error = %v", response.StatusCode, errDecode)
	}
	if result.Subscription == nil || !result.Subscription.Found || result.Subscription.Plan != "pro" || result.Subscription.CheckedAt == nil || result.Subscription.UpdatedAt == nil {
		t.Fatalf("quota subscription = %#v", result.Subscription)
	}
	assertSubscriptionRequestCount(t, host, 1)
}

func TestSubscriptionViewDistinguishesUnqueriedAndFailed(t *testing.T) {
	view := subscriptionViewFromState(subscriptionState{})
	if view.Found || view.Plan != "" || view.CheckedAt != nil || view.UpdatedAt != nil || view.LastError != "" {
		t.Fatalf("unqueried view = %#v", view)
	}
	now := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	view = subscriptionViewFromState(subscriptionState{CheckedAt: now, LastError: "failed"})
	if view.Found || view.Plan != "" || view.CheckedAt == nil || view.LastError != "failed" {
		t.Fatalf("failed view = %#v", view)
	}
}

func TestQuotaManagementFailureKeepsSuccessfulSubscription(t *testing.T) {
	host, _, _ := subscriptionTestService()
	host.requestResponse = hostAuthResponse{StatusCode: http.StatusServiceUnavailable}
	app := newApplication(host)
	defer app.shutdown()
	response := app.quotaResponse([]byte(`{"auth_index":"ag-1"}`), "quota-callback")
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("quota status = %d, want 502", response.StatusCode)
	}
	state, errState := app.auth.dashboard()
	if errState != nil || len(state.Credentials) != 1 {
		t.Fatalf("dashboard = %#v, error = %v", state, errState)
	}
	credential := state.Credentials[0]
	if credential.QuotaError == "" || credential.Subscription == nil || credential.Subscription.Plan != "pro" {
		t.Fatalf("quota failure subscription view = %#v", credential)
	}
	assertSubscriptionRequestCount(t, host, 1)
}
