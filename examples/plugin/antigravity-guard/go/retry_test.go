package main

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestDetectRetryTimeUsesLatestCandidate(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	headers := http.Header{"Retry-After": []string{"60"}}
	body := `{"error":{"details":[{"retryDelay":"5h"}]}}`

	retry := detectRetryTime(headers, body, now)
	if !retry.Found {
		t.Fatal("expected retry time")
	}
	want := now.Add(5 * time.Hour)
	if !retry.Until.Equal(want) {
		t.Fatalf("retry until = %s, want %s", retry.Until, want)
	}
	if retry.Source != "body.retryDelay" {
		t.Fatalf("retry source = %q", retry.Source)
	}
}

func TestDetectRetryTimeParsesAbsoluteReset(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(4*time.Hour + 30*time.Minute)
	body := `{"error":{"details":[{"metadata":{"quotaResetTimeStamp":"` + reset.Format(time.RFC3339) + `"}}]}}`

	retry := detectRetryTime(nil, body, now)
	if !retry.Found || !retry.Until.Equal(reset) {
		t.Fatalf("retry = %#v, want %s", retry, reset)
	}
}

func TestDetectRetryTimeParsesCodexResetFields(t *testing.T) {
	now := time.Date(2026, time.July, 25, 12, 0, 0, 0, time.UTC)
	reset := now.Add(30 * time.Minute)
	tests := []struct {
		name   string
		body   string
		source string
	}{
		{name: "relative", body: `{"error":{"resets_in_seconds":1800}}`, source: "body.resets_in_seconds"},
		{name: "absolute", body: `{"error":{"resets_at":` + strconv.FormatInt(reset.Unix(), 10) + `}}`, source: "body.resets_at"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			retry := detectRetryTime(nil, test.body, now)
			if !retry.Found || !retry.Until.Equal(reset) || retry.Source != test.source {
				t.Fatalf("retry = %#v, want %s from %s", retry, reset, test.source)
			}
		})
	}
}

func TestQuota429Classification(t *testing.T) {
	for _, body := range []string{
		`{"reason":"QUOTA_EXHAUSTED"}`,
		`You have 0 weighted tokens left`,
	} {
		if !isQuota429(body) {
			t.Fatalf("expected quota classification for %q", body)
		}
	}
	if isQuota429(`{"message":"requests are too frequent"}`) {
		t.Fatal("generic rate limit must not be classified as quota exhaustion")
	}
	if isQuota429(`{"status":"RESOURCE_EXHAUSTED"}`) {
		t.Fatal("bare RESOURCE_EXHAUSTED must remain a generic 429")
	}
}
