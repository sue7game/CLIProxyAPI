package main

import "time"

type dashboardState struct {
	GeneratedAt      time.Time        `json:"generated_at"`
	Configuration    configView       `json:"configuration"`
	Credentials      []credentialView `json:"credentials"`
	CodexCredentials []credentialView `json:"codex_credentials"`
	ProxyGroups      []proxyGroupView `json:"proxy_groups"`
}

type configView struct {
	Auto429Enabled          bool    `json:"auto_429_enabled"`
	Action                  string  `json:"action"`
	TemporaryPriority       int     `json:"temporary_priority"`
	Consecutive429Threshold int     `json:"consecutive_429_threshold"`
	Quota429Threshold       int     `json:"quota_429_threshold"`
	Generic429Threshold     int     `json:"generic_429_threshold"`
	FallbackCooldown        string  `json:"fallback_cooldown"`
	RecentWindow            string  `json:"recent_window"`
	WeeklyGroup             string  `json:"weekly_group,omitempty"`
	WeeklyEmptyThreshold    float64 `json:"weekly_empty_threshold"`
}

type credentialView struct {
	Provider           string            `json:"provider"`
	AuthIndex          string            `json:"auth_index"`
	Name               string            `json:"name"`
	Label              string            `json:"label,omitempty"`
	Email              string            `json:"email,omitempty"`
	Status             string            `json:"status,omitempty"`
	StatusMessage      string            `json:"status_message,omitempty"`
	ConfiguredDisabled bool              `json:"configured_disabled"`
	EffectiveDisabled  bool              `json:"effective_disabled"`
	ConfiguredPriority int               `json:"configured_priority"`
	EffectivePriority  int               `json:"effective_priority"`
	ConfiguredProxy    string            `json:"configured_proxy"`
	EffectiveProxy     string            `json:"effective_proxy"`
	ProxySource        string            `json:"proxy_source"`
	ProxyReusable      bool              `json:"proxy_reusable"`
	ProxyID            string            `json:"proxy_id"`
	ProxyAlias         string            `json:"proxy_alias"`
	Recent             bool              `json:"recent"`
	LastRequest        *time.Time        `json:"last_request,omitempty"`
	LastModel          string            `json:"last_model,omitempty"`
	Usage              usageView         `json:"usage"`
	Cooldown           *cooldownView     `json:"cooldown,omitempty"`
	GuardOutcome       *guardOutcomeView `json:"guard_outcome,omitempty"`
	GuardError         string            `json:"guard_error,omitempty"`
	WeeklyQuota        *weeklyView       `json:"weekly_quota,omitempty"`
	QuotaError         string            `json:"quota_error,omitempty"`
	DetailError        string            `json:"detail_error,omitempty"`
	Codex              *codexView        `json:"codex,omitempty"`
}

type codexView struct {
	ConsecutiveUsageLimit int              `json:"consecutive_usage_limit"`
	Status                string           `json:"status"`
	ErrorType             string           `json:"error_type,omitempty"`
	LastStatusCode        int              `json:"last_status_code,omitempty"`
	Weekly                *codexWindowView `json:"weekly,omitempty"`
	FiveHour              *codexWindowView `json:"five_hour,omitempty"`
}

type codexWindowView struct {
	UsedPercent      float64    `json:"used_percent"`
	WindowMinutes    int        `json:"window_minutes"`
	ResetTime        *time.Time `json:"reset_time,omitempty"`
	RemainingSeconds int64      `json:"remaining_seconds,omitempty"`
	Exhausted        bool       `json:"exhausted"`
}

type usageView struct {
	Success        int64 `json:"success"`
	Failed         int64 `json:"failed"`
	RateLimited    int64 `json:"rate_limited"`
	Consecutive429 int   `json:"consecutive_429"`
}

type cooldownView struct {
	Action                string     `json:"action"`
	Priority              *int       `json:"priority,omitempty"`
	Trigger               string     `json:"trigger"`
	Until                 time.Time  `json:"until"`
	Remaining             string     `json:"remaining"`
	RemainingSeconds      int64      `json:"remaining_seconds"`
	RetrySource           string     `json:"retry_source"`
	Pending               bool       `json:"pending"`
	Phase                 string     `json:"phase"`
	ManualReleaseRequired bool       `json:"manual_release_required"`
	RestoreTarget         string     `json:"restore_target"`
	NextRestoreAttempt    *time.Time `json:"next_restore_attempt,omitempty"`
	Superseded            bool       `json:"superseded,omitempty"`
	LastError             string     `json:"last_error,omitempty"`
}

type guardOutcomeView struct {
	Outcome       string    `json:"outcome"`
	At            time.Time `json:"at"`
	RestoreTarget string    `json:"restore_target"`
}

type weeklyView struct {
	Empty            bool       `json:"empty"`
	ResetElapsed     bool       `json:"reset_elapsed,omitempty"`
	Groups           []string   `json:"groups,omitempty"`
	ResetTime        *time.Time `json:"reset_time,omitempty"`
	Remaining        string     `json:"remaining,omitempty"`
	RemainingSeconds int64      `json:"remaining_seconds,omitempty"`
	RefreshKnown     bool       `json:"refresh_known"`
	CheckedAt        time.Time  `json:"checked_at"`
}

type proxyGroupView struct {
	ProxyID     string `json:"proxy_id"`
	ProxyAlias  string `json:"proxy_alias"`
	Proxy       string `json:"proxy"`
	Source      string `json:"source"`
	Credentials int    `json:"credentials"`
	Recent      int    `json:"recent"`
	Success     int64  `json:"success"`
	Failed      int64  `json:"failed"`
	RateLimited int64  `json:"rate_limited"`
	Cooling     int    `json:"cooling"`
}
