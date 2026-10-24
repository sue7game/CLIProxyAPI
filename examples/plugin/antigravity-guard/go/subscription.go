package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const antigravitySubscriptionURL = "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"

type subscriptionSummary struct {
	Plan     string
	TierID   string
	TierName string
}

type subscriptionTier struct {
	ID   string
	Name string
}

func (s *quotaService) refreshSubscription(authIndex, hostCallbackID string) {
	result, errFetch := s.fetchSubscription(authIndex, hostCallbackID)
	s.store.recordSubscriptionResult(authIndex, result, errFetch, s.now())
}

func (s *quotaService) fetchSubscription(authIndex, hostCallbackID string) (subscriptionSummary, error) {
	response, errRequest := s.host.Request(hostAuthRequest{
		AuthIndex:      authIndex,
		HostCallbackID: hostCallbackID,
		Method:         http.MethodPost,
		URL:            antigravitySubscriptionURL,
		Headers: http.Header{
			"Authorization": []string{"Bearer $TOKEN$"},
			"Content-Type":  []string{"application/json"},
			"User-Agent":    []string{s.config().QuotaUserAgent},
		},
		Body: []byte(`{"metadata":{"ideType":"ANTIGRAVITY"}}`),
	})
	if errRequest != nil {
		return subscriptionSummary{}, fmt.Errorf("request Antigravity subscription: %w", errRequest)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return subscriptionSummary{}, fmt.Errorf("subscription endpoint returned HTTP %d", response.StatusCode)
	}
	return parseAntigravitySubscription(response.Body)
}

func parseAntigravitySubscription(body []byte) (subscriptionSummary, error) {
	var payload map[string]json.RawMessage
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return subscriptionSummary{}, fmt.Errorf("decode Antigravity subscription response: %w", errDecode)
	}
	current := parseSubscriptionTier(subscriptionTierField(payload, "currentTier", "current_tier"))
	paid := parseSubscriptionTier(subscriptionTierField(payload, "paidTier", "paid_tier"))
	effective := current
	if paid.ID != "" {
		effective = paid
	}
	if effective.ID == "" && effective.Name == "" {
		return subscriptionSummary{}, fmt.Errorf("subscription tier not found in Antigravity response")
	}
	return subscriptionSummary{
		Plan:     subscriptionPlan(effective.ID),
		TierID:   effective.ID,
		TierName: effective.Name,
	}, nil
}

func subscriptionTierField(payload map[string]json.RawMessage, camel, snake string) json.RawMessage {
	if value := payload[camel]; len(value) > 0 && strings.TrimSpace(string(value)) != "null" {
		return value
	}
	return payload[snake]
}

func parseSubscriptionTier(raw json.RawMessage) subscriptionTier {
	var tier map[string]json.RawMessage
	if errDecode := json.Unmarshal(raw, &tier); errDecode != nil {
		return subscriptionTier{}
	}
	return subscriptionTier{ID: subscriptionString(tier["id"]), Name: subscriptionString(tier["name"])}
}

func subscriptionString(raw json.RawMessage) string {
	var value string
	if errDecode := json.Unmarshal(raw, &value); errDecode != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func subscriptionPlan(tierID string) string {
	switch tierID {
	case "free-tier":
		return "free"
	case "g1-pro-tier":
		return "pro"
	case "g1-ultra-tier":
		return "ultra"
	case "g1-ultra-lite-tier":
		return "ultra-lite"
	default:
		return "unknown"
	}
}
