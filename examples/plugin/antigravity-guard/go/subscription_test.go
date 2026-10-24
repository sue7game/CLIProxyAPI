package main

import (
	"testing"
)

func TestParseAntigravitySubscription(t *testing.T) {
	tests := []struct {
		name string
		body string
		want subscriptionSummary
	}{
		{"free", `{"currentTier":{"id":"free-tier","name":"Free tier"}}`, subscriptionSummary{"free", "free-tier", "Free tier"}},
		{"pro", `{"currentTier":{"id":" g1-pro-tier ","name":" Pro "}}`, subscriptionSummary{"pro", "g1-pro-tier", "Pro"}},
		{"ultra paid precedence", `{"currentTier":{"id":"free-tier"},"paidTier":{"id":"g1-ultra-tier","name":"Ultra"}}`, subscriptionSummary{"ultra", "g1-ultra-tier", "Ultra"}},
		{"snake ultra lite", `{"current_tier":{"id":"free-tier"},"paid_tier":{"id":"g1-ultra-lite-tier"}}`, subscriptionSummary{"ultra-lite", "g1-ultra-lite-tier", ""}},
		{"null alias fallback", `{"currentTier":null,"current_tier":{"id":"g1-pro-tier"}}`, subscriptionSummary{"pro", "g1-pro-tier", ""}},
		{"paid without id", `{"currentTier":{"id":"g1-pro-tier"},"paidTier":{"name":"Unnamed paid"}}`, subscriptionSummary{"pro", "g1-pro-tier", ""}},
		{"unknown paid wins", `{"currentTier":{"id":"free-tier"},"paidTier":{"id":"future-tier","name":"Future"}}`, subscriptionSummary{"unknown", "future-tier", "Future"}},
		{"name only", `{"currentTier":{"name":"Enterprise"}}`, subscriptionSummary{"unknown", "", "Enterprise"}},
		{"nonstring id ignored", `{"currentTier":{"id":12,"name":"Custom"}}`, subscriptionSummary{"unknown", "", "Custom"}},
		{"nonstring name ignored", `{"currentTier":{"id":"free-tier","name":{}}}`, subscriptionSummary{"free", "free-tier", ""}},
		{"invalid current valid paid", `{"currentTier":[],"paidTier":{"id":"g1-ultra-tier"}}`, subscriptionSummary{"ultra", "g1-ultra-tier", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, errParse := parseAntigravitySubscription([]byte(test.body))
			if errParse != nil || got != test.want {
				t.Fatalf("subscription = %#v, error = %v, want %#v", got, errParse, test.want)
			}
		})
	}
}

func TestParseAntigravitySubscriptionRejectsMissingOrInvalidData(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`, `"text"`, `{`,
		`{"currentTier":{"id":" ","name":""}}`,
		`{"currentTier":{"id":123,"name":true}}`,
		`{"currentTier":[],"paidTier":{"name":"Paid without ID"}}`,
	} {
		t.Run(body, func(t *testing.T) {
			result, errParse := parseAntigravitySubscription([]byte(body))
			if errParse == nil || result.Plan != "" {
				t.Fatalf("invalid subscription = %#v, error = %v", result, errParse)
			}
		})
	}
}
