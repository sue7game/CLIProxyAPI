package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type codexQuotaWindow struct {
	Found         bool
	UsedPercent   float64
	WindowMinutes int
	ResetAt       time.Time
}

type codexQuotaState struct {
	ConsecutiveUsageLimit int
	LastErrorType         string
	LastError             string
	LastStatusCode        int
	Weekly                codexQuotaWindow
	FiveHour              codexQuotaWindow
	CheckedAt             time.Time
}

func isCodexUsageLimitError(errorType string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(errorType)), "usage_limit")
}

func parseCodexErrorType(body string) string {
	var payload map[string]any
	if json.Unmarshal([]byte(body), &payload) != nil {
		if strings.Contains(strings.ToLower(body), "usage_limit_reached") {
			return "usage_limit_reached"
		}
		return ""
	}
	var walkUsage func(any) string
	walkUsage = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			if value, ok := x["type"].(string); ok && strings.EqualFold(strings.TrimSpace(value), "usage_limit_reached") {
				return "usage_limit_reached"
			}
			for _, child := range x {
				if found := walkUsage(child); found != "" {
					return found
				}
			}
		case []any:
			for _, child := range x {
				if found := walkUsage(child); found != "" {
					return found
				}
			}
		}
		return ""
	}
	if found := walkUsage(payload); found != "" {
		return found
	}
	var walk func(any) string
	walk = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			if value, ok := x["type"].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
			for _, child := range x {
				if found := walk(child); found != "" {
					return found
				}
			}
		case []any:
			for _, child := range x {
				if found := walk(child); found != "" {
					return found
				}
			}
		}
		return ""
	}
	return walk(payload)
}

func parseCodexQuotaState(headers http.Header, now time.Time) (codexQuotaState, bool) {
	state := codexQuotaState{CheckedAt: now}
	for name := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if !strings.HasPrefix(strings.ToLower(canonical), "x-codex-") || !strings.HasSuffix(strings.ToLower(canonical), "-window-minutes") {
			continue
		}
		base := strings.TrimSuffix(canonical, "-Window-Minutes")
		window := parseCodexWindow(headers, base, now)
		if !window.Found {
			continue
		}
		switch {
		case window.WindowMinutes >= 10000:
			if !state.Weekly.Found || window.UsedPercent > state.Weekly.UsedPercent {
				state.Weekly = window
			}
		case window.WindowMinutes >= 240 && window.WindowMinutes <= 360:
			if !state.FiveHour.Found || window.UsedPercent > state.FiveHour.UsedPercent {
				state.FiveHour = window
			}
		}
	}
	return state, state.Weekly.Found || state.FiveHour.Found
}

func parseCodexWindow(headers http.Header, base string, now time.Time) codexQuotaWindow {
	if headers == nil {
		return codexQuotaWindow{}
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(headers.Get(base + "-Window-Minutes")))
	if err != nil || minutes <= 0 {
		return codexQuotaWindow{}
	}
	used, err := strconv.ParseFloat(strings.TrimSpace(headers.Get(base+"-Used-Percent")), 64)
	if err != nil {
		used = 0
		if !strings.EqualFold(strings.TrimSpace(headers.Get(base+"-Limit-Reached")), "true") {
			return codexQuotaWindow{}
		}
		used = 100
	}
	reset := time.Time{}
	if raw := strings.TrimSpace(headers.Get(base + "-Reset-At")); raw != "" {
		if value, e := strconv.ParseInt(raw, 10, 64); e == nil {
			reset = time.Unix(value, 0)
		}
	}
	if reset.IsZero() {
		if raw := strings.TrimSpace(headers.Get(base + "-Reset-After-Seconds")); raw != "" {
			if value, e := strconv.ParseInt(raw, 10, 64); e == nil && value >= 0 {
				reset = now.Add(time.Duration(value) * time.Second)
			}
		}
	}
	return codexQuotaWindow{Found: true, UsedPercent: used, WindowMinutes: minutes, ResetAt: reset}
}

func codexWindowExhausted(window codexQuotaWindow) bool {
	return window.Found && window.UsedPercent >= 100
}

func codexQuotaDeadline(state codexQuotaState, now time.Time) (time.Time, string, bool) {
	var deadline time.Time
	source := ""
	if codexWindowExhausted(state.Weekly) && state.Weekly.ResetAt.After(now) {
		deadline, source = state.Weekly.ResetAt, "codex_weekly_reset"
	}
	if codexWindowExhausted(state.FiveHour) && state.FiveHour.ResetAt.After(now) && state.FiveHour.ResetAt.After(deadline) {
		deadline, source = state.FiveHour.ResetAt, "codex_five_hour_reset"
	}
	return deadline, source, !deadline.IsZero()
}
