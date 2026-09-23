package main

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var quota429Markers = []string{
	"quota_exhausted",
	"quota exhausted",
	"quota exceeded",
	"weighted tokens left",
}

const longRateLimitRetry = 5 * time.Minute

type retryTime struct {
	Until  time.Time
	Source string
	Found  bool
}

func isQuota429(body string) bool {
	normalized := strings.ToLower(body)
	for _, marker := range quota429Markers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func isRateLimitExceeded(body string) bool {
	normalized := strings.ToLower(body)
	return strings.Contains(normalized, "rate_limit_exceeded") || strings.Contains(normalized, "rate limit exceeded")
}

func isLongRateLimit(body string, retry retryTime, now time.Time) bool {
	return isRateLimitExceeded(body) && retry.Found && retry.Until.Sub(now) >= longRateLimitRetry
}

func detectRetryTime(headers http.Header, body string, now time.Time) retryTime {
	candidates := make([]retryTime, 0, 8)
	appendRetryHeaderCandidates(&candidates, headers, now)
	appendRetryBodyCandidates(&candidates, body, now)
	return latestRetryTime(candidates)
}

func appendRetryHeaderCandidates(dst *[]retryTime, headers http.Header, now time.Time) {
	if headers == nil {
		return
	}
	if value := strings.TrimSpace(headers.Get("Retry-After")); value != "" {
		if parsed, ok := parseRetryAfter(value, now); ok {
			*dst = append(*dst, retryTime{Until: parsed, Source: "Retry-After", Found: true})
		}
	}
	for _, name := range []string{"X-RateLimit-Reset", "X-RateLimit-Reset-Requests", "X-Quota-Reset"} {
		if parsed, ok := parseNumericTime(headers.Get(name), now, true); ok {
			*dst = append(*dst, retryTime{Until: parsed, Source: name, Found: true})
		}
	}
	for _, name := range []string{"X-RateLimit-Reset-After", "X-Retry-In"} {
		if parsed, ok := parseNumericTime(headers.Get(name), now, false); ok {
			*dst = append(*dst, retryTime{Until: parsed, Source: name, Found: true})
		}
	}
}

func parseRetryAfter(value string, now time.Time) (time.Time, bool) {
	if seconds, errParse := strconv.ParseFloat(strings.TrimSpace(value), 64); errParse == nil && seconds >= 0 {
		return now.Add(floatSeconds(seconds)), true
	}
	parsed, errTime := http.ParseTime(value)
	if errTime != nil || parsed.Before(now) {
		return time.Time{}, false
	}
	return parsed, true
}

func parseNumericTime(value string, now time.Time, allowEpoch bool) (time.Time, bool) {
	number, errParse := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if errParse != nil || number < 0 {
		return time.Time{}, false
	}
	if allowEpoch && number > 1_000_000_000_000 {
		parsed := time.UnixMilli(int64(number))
		return parsed, parsed.After(now)
	}
	if allowEpoch && number > 1_000_000_000 {
		parsed := time.Unix(int64(number), 0)
		return parsed, parsed.After(now)
	}
	return now.Add(floatSeconds(number)), true
}

func appendRetryBodyCandidates(dst *[]retryTime, body string, now time.Time) {
	if strings.TrimSpace(body) == "" {
		return
	}
	var value any
	if errDecode := json.Unmarshal([]byte(body), &value); errDecode != nil {
		return
	}
	walkRetryValue(dst, "", value, now)
}

func walkRetryValue(dst *[]retryTime, key string, value any, now time.Time) {
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			walkRetryValue(dst, childKey, child, now)
		}
	case []any:
		for _, child := range typed {
			walkRetryValue(dst, key, child, now)
		}
	default:
		if parsed, ok := retryValueTime(key, typed, now); ok {
			*dst = append(*dst, retryTime{Until: parsed, Source: "body." + key, Found: true})
		}
	}
}

func retryValueTime(key string, value any, now time.Time) (time.Time, bool) {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
	if isDurationRetryKey(normalized) {
		return parseDurationValue(value, now)
	}
	if isAbsoluteRetryKey(normalized) {
		return parseAbsoluteValue(value, now)
	}
	return time.Time{}, false
}

func isDurationRetryKey(key string) bool {
	switch key {
	case "retrydelay", "retryafter", "retryafterseconds", "resetafterseconds", "resetsinseconds", "quotaresetdelay", "ttl":
		return true
	default:
		return false
	}
}

func isAbsoluteRetryKey(key string) bool {
	switch key {
	case "resettime", "resetsat", "retryat", "quotaresettimestamp", "resettimestamp":
		return true
	default:
		return false
	}
}

func parseDurationValue(value any, now time.Time) (time.Time, bool) {
	switch typed := value.(type) {
	case float64:
		return now.Add(floatSeconds(typed)), typed >= 0
	case string:
		raw := strings.TrimSpace(typed)
		if duration, errParse := time.ParseDuration(raw); errParse == nil && duration >= 0 {
			return now.Add(duration), true
		}
		return parseNumericTime(raw, now, false)
	default:
		return time.Time{}, false
	}
}

func parseAbsoluteValue(value any, now time.Time) (time.Time, bool) {
	if number, ok := value.(float64); ok {
		return parseNumericTime(strconv.FormatFloat(number, 'f', -1, 64), now, true)
	}
	raw, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	raw = strings.TrimSpace(raw)
	if parsed, errParse := time.Parse(time.RFC3339Nano, raw); errParse == nil && parsed.After(now) {
		return parsed, true
	}
	return parseNumericTime(raw, now, true)
}

func latestRetryTime(values []retryTime) retryTime {
	var result retryTime
	for _, value := range values {
		if value.Found && (!result.Found || value.Until.After(result.Until)) {
			result = value
		}
	}
	return result
}

func floatSeconds(value float64) time.Duration {
	if value > float64(math.MaxInt64)/float64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(value * float64(time.Second))
}
