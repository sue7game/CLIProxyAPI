package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestParseWeeklyQuotaMarksOnlyWhenAllWeeklyBucketsAreEmpty(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(72 * time.Hour)
	body := []byte(`{"groups":[
		{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + reset.Format(time.RFC3339) + `"}]},
		{"displayName":"Claude and GPT models","buckets":[{"window":"weekly","remainingFraction":0.2,"resetTime":"` + reset.Format(time.RFC3339) + `"}]}
	]}`)
	config := testConfig()
	config.WeeklyGroup = ""

	result, errParse := parseWeeklyQuota(body, config, nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if result.Empty {
		t.Fatal("credential must not be marked empty while one weekly bucket has quota")
	}
	if !result.ResetTime.Equal(reset) {
		t.Fatalf("reset time = %s, want %s", result.ResetTime, reset)
	}
}

func TestParseWeeklyQuotaKeepsResetTimeWhenQuotaIsAvailable(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(5 * 24 * time.Hour)
	body := []byte(`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0.6,"resetTime":"` + reset.Format(time.RFC3339) + `"}]}]}`)
	config := testConfig()
	config.WeeklyGroup = "gemini-models"

	result, errParse := parseWeeklyQuota(body, config, nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !result.Found || result.Empty {
		t.Fatalf("weekly result = %#v, want available quota", result)
	}
	if len(result.Groups) != 1 || result.Groups[0] != "Gemini models" {
		t.Fatalf("groups = %#v, want Gemini models", result.Groups)
	}
	if !result.ResetTime.Equal(reset) {
		t.Fatalf("reset time = %s, want %s", result.ResetTime, reset)
	}
}

func TestParseWeeklyQuotaUsesEarliestResetWhenAllWeeklyBucketsAreEmpty(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	earlierReset := now.Add(48 * time.Hour)
	laterReset := now.Add(96 * time.Hour)
	body := []byte(`{"groups":[
		{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + laterReset.Format(time.RFC3339) + `"}]},
		{"displayName":"Claude and GPT models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + earlierReset.Format(time.RFC3339) + `"}]}
	]}`)

	config := testConfig()
	config.WeeklyGroup = ""
	result, errParse := parseWeeklyQuota(body, config, nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !result.Empty {
		t.Fatal("credential should be marked empty when every weekly bucket is empty")
	}
	if !result.ResetTime.Equal(earlierReset) {
		t.Fatalf("reset time = %s, want earliest reset %s", result.ResetTime, earlierReset)
	}
}

func TestParseWeeklyQuotaSupportsGroupFilterAndServerDate(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	serverNow := now.Add(90 * time.Second)
	reset := serverNow.Add(5 * 24 * time.Hour)
	body := []byte(`{"groups":[
		{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0.7}]},
		{"displayName":"Claude and GPT models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + reset.Format(time.RFC3339) + `"}]}
	]}`)
	config := testConfig()
	config.WeeklyGroup = "claude-and-gpt-models"
	headers := http.Header{"Date": []string{serverNow.Format(http.TimeFormat)}}

	result, errParse := parseWeeklyQuota(body, config, headers, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !result.Empty || len(result.Groups) != 1 || result.Groups[0] != "Claude and GPT models" {
		t.Fatalf("weekly result = %#v", result)
	}
	if !result.ObservedServer.Equal(serverNow) {
		t.Fatalf("server time = %s, want %s", result.ObservedServer, serverNow)
	}
}

func TestParseWeeklyQuotaAcceptsStringFraction(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":"0%"}]}]}`)
	result, errParse := parseWeeklyQuota(body, testConfig(), nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !result.Empty {
		t.Fatal("0% string fraction must be treated as empty")
	}
}

func TestParseQuotaDetectsEmptyFiveHourWindowAndResetTime(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	fiveHourReset := now.Add(4*time.Hour + 32*time.Minute)
	weeklyReset := now.Add(4 * 24 * time.Hour)
	body := []byte(`{"groups":[{"displayName":"Gemini models","buckets":[
		{"window":"five_hour","remainingFraction":0,"resetTime":"` + fiveHourReset.Format(time.RFC3339) + `"},
		{"window":"weekly","remainingFraction":0.7,"resetTime":"` + weeklyReset.Format(time.RFC3339) + `"}
	]}]}`)

	result, errParse := parseWeeklyQuota(body, testConfig(), nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if !result.Found || result.Empty {
		t.Fatalf("weekly quota = %#v, want available", result)
	}
	if !result.FiveHourFound || !result.FiveHourEmpty {
		t.Fatalf("five-hour quota = %#v, want empty", result)
	}
	if !result.FiveHourResetTime.Equal(fiveHourReset) {
		t.Fatalf("five-hour reset = %s, want %s", result.FiveHourResetTime, fiveHourReset)
	}
}

func TestParseQuotaAcceptsFiveHourWindowWithoutWeeklyWindow(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(5 * time.Hour)
	body := []byte(`{"groups":[{"displayName":"Gemini models","buckets":[
		{"displayName":"5 hour limit","remainingFraction":0,"resetTime":"` + reset.Format(time.RFC3339) + `"}
	]}]}`)

	result, errParse := parseWeeklyQuota(body, testConfig(), nil, now)
	if errParse != nil {
		t.Fatal(errParse)
	}
	if result.Found || !result.FiveHourFound || !result.FiveHourEmpty {
		t.Fatalf("quota result = %#v", result)
	}
}

func TestQuotaStateBecomesAvailableAtResetTime(t *testing.T) {
	store := newStateStore()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Empty:          true,
		Found:          true,
		Groups:         []string{"Claude and GPT models"},
		ResetTime:      now.Add(time.Hour),
		ObservedServer: now,
		CheckedAt:      now,
	})
	store.expireQuotas(now.Add(time.Hour))
	if state := store.snapshot("auth-1", now.Add(time.Hour)); !state.Quota.Found || state.Quota.Empty || !state.Quota.ResetElapsed {
		t.Fatalf("empty weekly state = %#v, want available after reset", state.Quota)
	}
}

func TestAvailableQuotaStateRemainsAvailableAtResetTime(t *testing.T) {
	store := newStateStore()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Found:          true,
		Groups:         []string{"Gemini models"},
		ResetTime:      now.Add(time.Hour),
		ObservedServer: now,
		CheckedAt:      now,
	})
	store.expireQuotas(now.Add(time.Hour))
	if state := store.snapshot("auth-1", now.Add(time.Hour)); !state.Quota.Found || state.Quota.Empty || !state.Quota.ResetElapsed {
		t.Fatalf("available weekly state = %#v, want available after reset", state.Quota)
	}
}

func TestApplyQuotaResultReplacesPreviousResetTime(t *testing.T) {
	store := newStateStore()
	firstCheckedAt := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	secondCheckedAt := firstCheckedAt.Add(15 * time.Minute)
	secondReset := secondCheckedAt.Add(5 * 24 * time.Hour)
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Empty:          true,
		Found:          true,
		Groups:         []string{"Gemini Models"},
		ResetTime:      firstCheckedAt.Add(3 * 24 * time.Hour),
		ObservedServer: firstCheckedAt,
		CheckedAt:      firstCheckedAt,
	})
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Empty:          true,
		Found:          true,
		Groups:         []string{"Gemini Models"},
		ResetTime:      secondReset,
		ObservedServer: secondCheckedAt.Add(time.Minute),
		CheckedAt:      secondCheckedAt,
	})

	state := store.snapshot("auth-1", secondCheckedAt)
	if !state.Quota.ResetTime.Equal(secondReset) {
		t.Fatalf("reset time = %s, want %s", state.Quota.ResetTime, secondReset)
	}
	if !state.Quota.CheckedAt.Equal(secondCheckedAt) {
		t.Fatalf("checked at = %s, want %s", state.Quota.CheckedAt, secondCheckedAt)
	}
	if !state.Quota.ObservedServer.Equal(secondCheckedAt.Add(time.Minute)) {
		t.Fatalf("observed server = %s, want refreshed server time", state.Quota.ObservedServer)
	}
}

func TestApplyQuotaResultStoresAvailableQuotaRefreshTime(t *testing.T) {
	store := newStateStore()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(5 * 24 * time.Hour)
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Found:          true,
		Groups:         []string{"Gemini models"},
		ResetTime:      reset,
		ObservedServer: now.Add(time.Minute),
		CheckedAt:      now,
	})

	state := store.snapshot("auth-1", now)
	if !state.Quota.Found || state.Quota.Empty {
		t.Fatalf("quota state = %#v, want available quota", state.Quota)
	}
	if !state.Quota.ResetTime.Equal(reset) {
		t.Fatalf("reset time = %s, want %s", state.Quota.ResetTime, reset)
	}
}

func TestQuotaErrorPreservesLastSuccessfulRefreshTime(t *testing.T) {
	store := newStateStore()
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(5 * 24 * time.Hour)
	store.applyQuotaResult("auth-1", weeklyQuotaResult{
		Found:          true,
		Groups:         []string{"Gemini models"},
		ResetTime:      reset,
		ObservedServer: now,
		CheckedAt:      now,
	})
	store.recordQuotaError("auth-1", errors.New("temporary quota failure"), now.Add(time.Minute))

	state := store.snapshot("auth-1", now.Add(time.Minute))
	if !state.Quota.Found || !state.Quota.ResetTime.Equal(reset) {
		t.Fatalf("quota state = %#v, want previous successful result", state.Quota)
	}
	if state.Quota.LastError != "temporary quota failure" {
		t.Fatalf("quota error = %q", state.Quota.LastError)
	}
}

func TestWeeklyViewJSONIncludesRemainingSeconds(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	view := weeklyViewFromState(quotaState{
		Found:          true,
		Empty:          true,
		ResetTime:      now.Add(2 * time.Hour),
		ObservedAt:     now,
		ObservedServer: now,
		CheckedAt:      now,
	}, now)
	raw, errMarshal := json.Marshal(view)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if !json.Valid(raw) || !containsJSONField(raw, `"remaining_seconds":7200`) {
		t.Fatalf("weekly view JSON = %s", raw)
	}
}

func TestWeeklyViewIncludesAvailableQuotaRefreshTime(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	view := weeklyViewFromState(quotaState{
		Found:          true,
		Groups:         []string{"Gemini models"},
		ResetTime:      now.Add(90 * time.Minute),
		ObservedAt:     now,
		ObservedServer: now,
		CheckedAt:      now,
	}, now)
	if view == nil || view.Empty || !view.RefreshKnown {
		t.Fatalf("weekly view = %#v, want available quota with refresh time", view)
	}
	if view.RemainingSeconds != 90*60 {
		t.Fatalf("remaining seconds = %d, want %d", view.RemainingSeconds, 90*60)
	}
}

func TestQuotaRefreshUsesCredentialProjectAndTokenPlaceholder(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(7 * 24 * time.Hour)
	host := &fakeHost{
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Date": []string{now.Format(http.TimeFormat)}},
			Body:       []byte(`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":0,"resetTime":"` + reset.Format(time.RFC3339) + `"}]}]}`),
		},
	}
	store := newStateStore()
	config := testConfig()
	service := newQuotaService(host, store, func() guardConfig { return config })
	service.now = func() time.Time { return now }

	if _, errRefresh := service.refresh("ag-1", "project-123", "callback-123"); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	if len(host.authRequests) != 1 {
		t.Fatalf("request count = %d", len(host.authRequests))
	}
	request := host.authRequests[0]
	if request.HostCallbackID != "callback-123" {
		t.Fatalf("host callback ID = %q, want callback-123", request.HostCallbackID)
	}
	if request.Headers.Get("Authorization") != "Bearer $TOKEN$" {
		t.Fatalf("authorization header = %q", request.Headers.Get("Authorization"))
	}
	if !containsJSONField(request.Body, `"project":"project-123"`) {
		t.Fatalf("quota request body = %s", request.Body)
	}
}

func containsJSONField(raw []byte, field string) bool {
	return string(raw) != "" && len(field) > 0 && jsonContains(string(raw), field)
}

func jsonContains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
