package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

type quotaService struct {
	host   hostClient
	store  *stateStore
	config func() guardConfig
	now    func() time.Time
}

type quotaGroupPayload struct {
	DisplayName      string               `json:"displayName"`
	DisplayNameSnake string               `json:"display_name"`
	Description      string               `json:"description"`
	Buckets          []quotaBucketPayload `json:"buckets"`
}

type quotaBucketPayload struct {
	DisplayName      string        `json:"displayName"`
	DisplayNameSnake string        `json:"display_name"`
	Window           string        `json:"window"`
	Remaining        quotaFraction `json:"remainingFraction"`
	RemainingSnake   quotaFraction `json:"remaining_fraction"`
	ResetTime        string        `json:"resetTime"`
	ResetTimeSnake   string        `json:"reset_time"`
}

type quotaModelPayload struct {
	QuotaInfo      quotaBucketPayload `json:"quotaInfo"`
	QuotaInfoSnake quotaBucketPayload `json:"quota_info"`
}

type quotaSummaryPayload struct {
	Groups []quotaGroupPayload          `json:"groups"`
	Models map[string]quotaModelPayload `json:"models"`
}

type weeklyQuotaResult struct {
	Empty             bool
	Found             bool
	Groups            []string
	ResetTime         time.Time
	FiveHourEmpty     bool
	FiveHourFound     bool
	FiveHourResetTime time.Time
	ObservedServer    time.Time
	CheckedAt         time.Time
}

func newQuotaService(host hostClient, store *stateStore, config func() guardConfig) *quotaService {
	return &quotaService{host: host, store: store, config: config, now: time.Now}
}

func (s *quotaService) refresh(authIndex, projectID, hostCallbackID string) (weeklyQuotaResult, error) {
	authIndex, errValidate := validateAuthIndex(authIndex)
	if errValidate != nil {
		return weeklyQuotaResult{}, errValidate
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		errProject := fmt.Errorf("Antigravity credential does not contain project_id")
		s.store.recordQuotaError(authIndex, errProject, s.now())
		return weeklyQuotaResult{}, errProject
	}
	result, errFetch := s.fetch(authIndex, projectID, hostCallbackID)
	if errFetch != nil {
		s.store.recordQuotaError(authIndex, errFetch, s.now())
		return weeklyQuotaResult{}, errFetch
	}
	s.store.applyQuotaResult(authIndex, result)
	return result, nil
}

func (s *quotaService) fetch(authIndex, projectID, hostCallbackID string) (weeklyQuotaResult, error) {
	cfg := s.config()
	body, _ := json.Marshal(map[string]string{"project": projectID})
	var lastError error
	for _, endpoint := range cfg.QuotaURLs {
		response, errRequest := s.host.Request(hostAuthRequest{
			AuthIndex:      authIndex,
			HostCallbackID: hostCallbackID,
			Method:         http.MethodPost,
			URL:            endpoint,
			Headers: http.Header{
				"Authorization": []string{"Bearer $TOKEN$"},
				"Content-Type":  []string{"application/json"},
				"User-Agent":    []string{cfg.QuotaUserAgent},
			},
			Body: body,
		})
		if errRequest != nil {
			lastError = errRequest
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			lastError = fmt.Errorf("quota endpoint returned HTTP %d: %s", response.StatusCode, compactErrorBody(response.Body))
			continue
		}
		result, errParse := parseWeeklyQuota(response.Body, cfg, response.Headers, s.now())
		if errParse != nil {
			lastError = errParse
			continue
		}
		return result, nil
	}
	if lastError == nil {
		lastError = fmt.Errorf("no Antigravity quota endpoint is configured")
	}
	return weeklyQuotaResult{}, lastError
}

func parseWeeklyQuota(body []byte, cfg guardConfig, headers http.Header, now time.Time) (weeklyQuotaResult, error) {
	var payload quotaSummaryPayload
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return weeklyQuotaResult{}, fmt.Errorf("decode Antigravity quota response: %w", errDecode)
	}
	groups := payload.Groups
	if len(groups) == 0 && len(payload.Models) > 0 {
		groups = quotaGroupsFromModels(payload.Models)
	}
	result := weeklyResultFromGroups(groups, cfg, now)
	if serverDate := parseServerDate(headers); !serverDate.IsZero() {
		result.ObservedServer = serverDate
	} else {
		result.ObservedServer = now
	}
	result.CheckedAt = now
	if !result.Found && !result.FiveHourFound {
		return weeklyQuotaResult{}, fmt.Errorf("weekly or five-hour quota bucket not found in Antigravity response")
	}
	return result, nil
}

func weeklyResultFromGroups(groups []quotaGroupPayload, cfg guardConfig, now time.Time) weeklyQuotaResult {
	result := weeklyQuotaResult{Empty: true, FiveHourEmpty: true}
	matchedGroups := make(map[string]struct{})
	for index, group := range groups {
		label := firstNonEmpty(group.DisplayName, group.DisplayNameSnake, fmt.Sprintf("quota-group-%d", index+1))
		if cfg.WeeklyGroup != "" && slug(label) != cfg.WeeklyGroup {
			continue
		}
		for _, bucket := range group.Buckets {
			remaining, ok := bucketRemaining(bucket)
			if !ok {
				continue
			}
			switch {
			case isWeeklyBucket(bucket):
				result.Found = true
				matchedGroups[label] = struct{}{}
				if remaining > cfg.WeeklyEmptyThreshold {
					result.Empty = false
				}
				result.ResetTime = earlierResetTime(result.ResetTime, bucketResetTime(bucket))
			case isFiveHourBucket(bucket):
				result.FiveHourFound = true
				if remaining > cfg.WeeklyEmptyThreshold {
					result.FiveHourEmpty = false
				}
				result.FiveHourResetTime = earlierResetTime(result.FiveHourResetTime, bucketResetTime(bucket))
			}
		}
	}
	result.Groups = sortedKeys(matchedGroups)
	_ = now
	return result
}

func quotaGroupsFromModels(models map[string]quotaModelPayload) []quotaGroupPayload {
	groups := make([]quotaGroupPayload, 0, len(models))
	for name, model := range models {
		quotaInfo := model.QuotaInfo
		if !quotaInfo.Remaining.Valid && model.QuotaInfoSnake.Remaining.Valid {
			quotaInfo = model.QuotaInfoSnake
		}
		groups = append(groups, quotaGroupPayload{DisplayName: name, Buckets: []quotaBucketPayload{quotaInfo}})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].DisplayName < groups[j].DisplayName })
	return groups
}

func isWeeklyBucket(bucket quotaBucketPayload) bool {
	window := slug(bucket.Window)
	if window == "weekly" || window == "week" || window == "seven-day" || window == "7-day" {
		return true
	}
	label := slug(firstNonEmpty(bucket.DisplayName, bucket.DisplayNameSnake))
	return strings.Contains(label, "weekly") || strings.Contains(label, "week")
}

func isFiveHourBucket(bucket quotaBucketPayload) bool {
	window := slug(bucket.Window)
	label := slug(firstNonEmpty(bucket.DisplayName, bucket.DisplayNameSnake))
	for _, value := range []string{window, label} {
		switch value {
		case "5h", "5-hour", "5-hours", "five-hour", "five-hours", "300m", "300-minute", "300-minutes", "18000s", "18000-second", "18000-seconds":
			return true
		}
		if strings.Contains(value, "5-hour") || strings.Contains(value, "five-hour") {
			return true
		}
	}
	return false
}

func earlierResetTime(current, candidate time.Time) time.Time {
	if candidate.IsZero() || (!current.IsZero() && !candidate.Before(current)) {
		return current
	}
	return candidate
}

func bucketRemaining(bucket quotaBucketPayload) (float64, bool) {
	if bucket.Remaining.Valid {
		return bucket.Remaining.Value, true
	}
	if bucket.RemainingSnake.Valid {
		return bucket.RemainingSnake.Value, true
	}
	return 0, false
}

func bucketResetTime(bucket quotaBucketPayload) time.Time {
	raw := firstNonEmpty(bucket.ResetTime, bucket.ResetTimeSnake)
	parsed, _ := time.Parse(time.RFC3339Nano, raw)
	return parsed
}

func parseServerDate(headers http.Header) time.Time {
	if headers == nil {
		return time.Time{}
	}
	parsed, _ := http.ParseTime(headers.Get("Date"))
	return parsed
}

func compactErrorBody(body []byte) string {
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > 240 {
		text = text[:240] + "…"
	}
	if text == "" {
		return "empty response"
	}
	return text
}
