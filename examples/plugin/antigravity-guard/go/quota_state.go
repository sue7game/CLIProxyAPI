package main

import (
	"fmt"
	"strings"
	"time"
)

func (s *stateStore) applyQuotaResult(authIndex string, result weeklyQuotaResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	state.Quota = quotaState{
		Found:          result.Found,
		Empty:          result.Empty,
		Groups:         append([]string(nil), result.Groups...),
		ResetTime:      result.ResetTime,
		ObservedAt:     result.CheckedAt,
		ObservedServer: result.ObservedServer,
		CheckedAt:      result.CheckedAt,
	}
}

func (s *stateStore) recordQuotaError(authIndex string, err error, checkedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	state.Quota.CheckedAt = checkedAt
	if err != nil {
		state.Quota.LastError = err.Error()
	}
}

func quotaServerNow(state quotaState, now time.Time) time.Time {
	if state.ObservedAt.IsZero() || state.ObservedServer.IsZero() {
		return now
	}
	return state.ObservedServer.Add(now.Sub(state.ObservedAt))
}

func quotaRemaining(state quotaState, now time.Time) time.Duration {
	if state.ResetTime.IsZero() {
		return 0
	}
	remaining := state.ResetTime.Sub(quotaServerNow(state, now))
	if remaining < 0 {
		return 0
	}
	return remaining
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sortStrings(result)
	return result
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, runeValue := range value {
		isAlphaNumeric := runeValue >= 'a' && runeValue <= 'z' || runeValue >= '0' && runeValue <= '9'
		if isAlphaNumeric {
			builder.WriteRune(runeValue)
			lastDash = false
			continue
		}
		if builder.Len() > 0 && !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

func formatDuration(duration time.Duration) string {
	if duration <= 0 {
		return ""
	}
	totalMinutes := int64(duration.Round(time.Minute) / time.Minute)
	if totalMinutes < 1 {
		totalMinutes = 1
	}
	days := totalMinutes / (24 * 60)
	hours := totalMinutes % (24 * 60) / 60
	minutes := totalMinutes % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
