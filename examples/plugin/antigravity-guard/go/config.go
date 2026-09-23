package main

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	actionDisable  = "disable"
	actionPriority = "priority"
)

var defaultQuotaURLs = []string{
	"https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
	"https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary",
	"https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
}

type pluginConfig struct {
	Enabled              bool     `yaml:"enabled"`
	Auto429Enabled       bool     `yaml:"auto_429_enabled"`
	Action               string   `yaml:"action"`
	TemporaryPriority    int      `yaml:"temporary_priority"`
	Consecutive429Limit  *int     `yaml:"consecutive_429_threshold"`
	Quota429Threshold    int      `yaml:"quota_429_threshold"`
	Generic429Threshold  int      `yaml:"generic_429_threshold"`
	GenericRequireRetry  bool     `yaml:"generic_require_retry"`
	FallbackCooldown     string   `yaml:"fallback_cooldown"`
	RecentWindow         string   `yaml:"recent_window"`
	RestoreRetry         string   `yaml:"restore_retry"`
	WeeklyGroup          string   `yaml:"weekly_group"`
	WeeklyEmptyThreshold float64  `yaml:"weekly_empty_threshold"`
	QuotaURLs            []string `yaml:"quota_urls"`
	QuotaUserAgent       string   `yaml:"quota_user_agent"`
}

type guardConfig struct {
	Enabled              bool
	Auto429Enabled       bool
	Action               string
	TemporaryPriority    int
	Consecutive429Limit  int
	GenericRequireRetry  bool
	FallbackCooldown     time.Duration
	RecentWindow         time.Duration
	RestoreRetry         time.Duration
	WeeklyGroup          string
	WeeklyEmptyThreshold float64
	QuotaURLs            []string
	QuotaUserAgent       string
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		Enabled:              true,
		Auto429Enabled:       true,
		Action:               actionDisable,
		TemporaryPriority:    13,
		GenericRequireRetry:  true,
		FallbackCooldown:     "5h",
		RecentWindow:         "10m",
		RestoreRetry:         "15s",
		WeeklyGroup:          "gemini-models",
		WeeklyEmptyThreshold: 0,
		QuotaURLs:            append([]string(nil), defaultQuotaURLs...),
		QuotaUserAgent:       "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)",
	}
}

func decodeConfig(raw []byte) (guardConfig, error) {
	cfg := defaultPluginConfig()
	if len(raw) > 0 {
		if errUnmarshal := yaml.Unmarshal(raw, &cfg); errUnmarshal != nil {
			return guardConfig{}, fmt.Errorf("decode plugin config: %w", errUnmarshal)
		}
	}
	return normalizeConfig(cfg)
}

func normalizeConfig(cfg pluginConfig) (guardConfig, error) {
	action := strings.ToLower(strings.TrimSpace(cfg.Action))
	if action != actionDisable && action != actionPriority {
		return guardConfig{}, fmt.Errorf("action must be %q or %q", actionDisable, actionPriority)
	}
	consecutive429Limit, errThreshold := normalizedConsecutive429Limit(cfg)
	if errThreshold != nil {
		return guardConfig{}, errThreshold
	}
	fallback, errFallback := positiveDuration(cfg.FallbackCooldown, "fallback_cooldown")
	if errFallback != nil {
		return guardConfig{}, errFallback
	}
	recent, errRecent := positiveDuration(cfg.RecentWindow, "recent_window")
	if errRecent != nil {
		return guardConfig{}, errRecent
	}
	restoreRetry, errRestore := positiveDuration(cfg.RestoreRetry, "restore_retry")
	if errRestore != nil {
		return guardConfig{}, errRestore
	}
	if cfg.WeeklyEmptyThreshold < 0 || cfg.WeeklyEmptyThreshold > 1 {
		return guardConfig{}, fmt.Errorf("weekly_empty_threshold must be between 0 and 1")
	}
	quotaURLs, errURLs := normalizeQuotaURLs(cfg.QuotaURLs)
	if errURLs != nil {
		return guardConfig{}, errURLs
	}
	return guardConfig{
		Enabled:              cfg.Enabled,
		Auto429Enabled:       cfg.Auto429Enabled,
		Action:               action,
		TemporaryPriority:    cfg.TemporaryPriority,
		Consecutive429Limit:  consecutive429Limit,
		GenericRequireRetry:  cfg.GenericRequireRetry,
		FallbackCooldown:     fallback,
		RecentWindow:         recent,
		RestoreRetry:         restoreRetry,
		WeeklyGroup:          slug(cfg.WeeklyGroup),
		WeeklyEmptyThreshold: cfg.WeeklyEmptyThreshold,
		QuotaURLs:            quotaURLs,
		QuotaUserAgent:       strings.TrimSpace(cfg.QuotaUserAgent),
	}, nil
}

func normalizedConsecutive429Limit(cfg pluginConfig) (int, error) {
	if cfg.Consecutive429Limit != nil {
		if *cfg.Consecutive429Limit < 1 {
			return 0, fmt.Errorf("consecutive_429_threshold must be at least 1")
		}
		return *cfg.Consecutive429Limit, nil
	}
	if cfg.Quota429Threshold < 0 || cfg.Generic429Threshold < 0 {
		return 0, fmt.Errorf("legacy 429 thresholds must not be negative")
	}
	if cfg.Quota429Threshold > cfg.Generic429Threshold {
		return cfg.Quota429Threshold, nil
	}
	if cfg.Generic429Threshold > 0 {
		return cfg.Generic429Threshold, nil
	}
	return 3, nil
}

func guardConfigsEqual(left, right guardConfig) bool {
	return left.Enabled == right.Enabled &&
		left.Auto429Enabled == right.Auto429Enabled &&
		left.Action == right.Action &&
		left.TemporaryPriority == right.TemporaryPriority &&
		left.Consecutive429Limit == right.Consecutive429Limit &&
		left.GenericRequireRetry == right.GenericRequireRetry &&
		left.FallbackCooldown == right.FallbackCooldown &&
		left.RecentWindow == right.RecentWindow &&
		left.RestoreRetry == right.RestoreRetry &&
		left.WeeklyGroup == right.WeeklyGroup &&
		left.WeeklyEmptyThreshold == right.WeeklyEmptyThreshold &&
		left.QuotaUserAgent == right.QuotaUserAgent &&
		slices.Equal(left.QuotaURLs, right.QuotaURLs)
}

func positiveDuration(raw, name string) (time.Duration, error) {
	duration, errParse := time.ParseDuration(strings.TrimSpace(raw))
	if errParse != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return duration, nil
}

func normalizeQuotaURLs(values []string) ([]string, error) {
	if len(values) == 0 {
		values = defaultQuotaURLs
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		parsed, errParse := url.Parse(strings.TrimSpace(raw))
		if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, fmt.Errorf("quota_urls must contain absolute HTTPS URLs")
		}
		result = append(result, parsed.String())
	}
	return result, nil
}
