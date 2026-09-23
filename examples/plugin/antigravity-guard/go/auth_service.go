package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type authService struct {
	host    hostClient
	store   *stateStore
	config  func() guardConfig
	proxies *proxyCatalog
	now     func() time.Time
}

func newAuthService(host hostClient, store *stateStore, config func() guardConfig, proxies *proxyCatalog) *authService {
	return &authService{host: host, store: store, config: config, proxies: proxies, now: time.Now}
}

func (s *authService) dashboard() (dashboardState, error) {
	entries, errList := s.host.ListAuths()
	if errList != nil {
		return dashboardState{}, fmt.Errorf("list credentials: %w", errList)
	}
	s.proxies.reconcile(s.proxies.currentIDs(entries))
	now := s.now()
	views := make([]credentialView, 0, len(entries))
	codexViews := make([]credentialView, 0)
	for _, entry := range entries {
		if strings.TrimSpace(entry.AuthIndex) == "" {
			continue
		}
		view := s.credentialView(entry, now)
		if isAntigravityEntry(entry) {
			views = append(views, view)
		} else if isCodexEntry(entry) {
			codexViews = append(codexViews, view)
		}
	}
	sortCredentialViews(views)
	sortCredentialViews(codexViews)
	return dashboardState{
		GeneratedAt:      now,
		Configuration:    configurationView(s.config()),
		Credentials:      views,
		CodexCredentials: codexViews,
		ProxyGroups:      buildProxyGroups(views),
	}, nil
}

func (s *authService) credentialView(entry hostAuthEntry, now time.Time) credentialView {
	state := s.store.snapshot(entry.AuthIndex, now)
	configuredProxy := entry.ConfiguredProxyURL
	effectiveProxyURL, proxySource := effectiveProxy(entry, configuredProxy)
	proxyDescriptor, proxyReusable := s.proxies.describe(effectiveProxyURL)
	effectiveProxy := maskProxyURL(effectiveProxyURL)
	if proxyReusable {
		effectiveProxy = proxyDescriptor.Display
	}
	configuredPriority := entry.ConfiguredPriority
	if configuredPriority == 0 {
		configuredPriority = entry.Priority
	}
	effectivePriority := entry.EffectivePriority
	if entry.RuntimeOverride != nil && entry.RuntimeOverride.Priority != nil {
		effectivePriority = *entry.RuntimeOverride.Priority
	} else if effectivePriority == 0 {
		effectivePriority = configuredPriority
	}
	configuredDisabled := entry.ConfiguredDisabled
	if entry.RuntimeOverride == nil && entry.Disabled {
		configuredDisabled = true
	}
	effectiveDisabled := entry.EffectiveDisabled || entry.Disabled
	if entry.RuntimeOverride != nil && entry.RuntimeOverride.Disabled != nil {
		effectiveDisabled = configuredDisabled || *entry.RuntimeOverride.Disabled
	}
	view := credentialView{
		Provider:           firstNonEmpty(entry.Provider, entry.Type),
		AuthIndex:          entry.AuthIndex,
		Name:               entry.Name,
		Label:              entry.Label,
		Email:              entry.Email,
		Status:             entry.Status,
		StatusMessage:      entry.StatusMessage,
		ConfiguredDisabled: configuredDisabled,
		EffectiveDisabled:  effectiveDisabled,
		ConfiguredPriority: configuredPriority,
		EffectivePriority:  effectivePriority,
		ConfiguredProxy:    maskProxyURL(configuredProxy),
		EffectiveProxy:     effectiveProxy,
		ProxySource:        proxySource,
		ProxyReusable:      proxyReusable,
		ProxyID:            proxyDescriptor.ID,
		ProxyAlias:         proxyDescriptor.Alias,
		LastModel:          state.Usage.LastModel,
		Usage: usageView{
			Success:        state.Usage.Success,
			Failed:         state.Usage.Failed,
			RateLimited:    state.Usage.RateLimited,
			Consecutive429: state.Usage.Consecutive429,
		},
		QuotaError: state.Quota.LastError,
		GuardError: state.Cooldown.LastError,
	}
	if strings.EqualFold(strings.TrimSpace(view.Provider), "codex") {
		view.Codex = codexViewFromState(state.Codex, state.Cooldown, now)
	}
	if !state.Usage.LastRequest.IsZero() {
		lastRequest := state.Usage.LastRequest
		view.LastRequest = &lastRequest
		view.Recent = now.Sub(lastRequest) <= s.config().RecentWindow
	}
	view.Cooldown = cooldownViewFromState(state.Cooldown, configuredDisabled, configuredPriority, now)
	view.GuardOutcome = guardOutcomeViewFromState(state.Cooldown)
	view.WeeklyQuota = weeklyViewFromState(state.Quota, now)
	return view
}

func codexViewFromState(state codexQuotaState, cooldown cooldownState, now time.Time) *codexView {
	view := &codexView{ConsecutiveUsageLimit: state.ConsecutiveUsageLimit, ErrorType: state.LastErrorType, LastStatusCode: state.LastStatusCode}
	switch {
	case cooldown.Active && cooldown.Trigger == codexTriggerUnauthorized:
		view.Status = "401 已禁用"
	case cooldown.Active && cooldown.Trigger == codexTriggerUsageLimit:
		view.Status = "额度冷却中"
	case state.ConsecutiveUsageLimit > 0:
		view.Status = "检测到 usage_limit"
	default:
		view.Status = "正常"
	}
	view.Weekly = codexWindowViewFromState(state.Weekly, now)
	view.FiveHour = codexWindowViewFromState(state.FiveHour, now)
	return view
}

func codexWindowViewFromState(window codexQuotaWindow, now time.Time) *codexWindowView {
	if !window.Found {
		return nil
	}
	view := &codexWindowView{UsedPercent: window.UsedPercent, WindowMinutes: window.WindowMinutes, Exhausted: window.UsedPercent >= 100}
	if !window.ResetAt.IsZero() {
		reset := window.ResetAt
		view.ResetTime = &reset
		if reset.After(now) {
			view.RemainingSeconds = int64(reset.Sub(now) / time.Second)
		}
	}
	return view
}

func cooldownViewFromState(state cooldownState, configuredDisabled bool, configuredPriority int, now time.Time) *cooldownView {
	if !state.Active && !state.Pending {
		return nil
	}
	remaining := state.Until.Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	view := &cooldownView{
		Action:                state.Action,
		Priority:              state.Priority,
		Trigger:               state.Trigger,
		Until:                 state.Until,
		Remaining:             formatDuration(remaining),
		RemainingSeconds:      int64(remaining / time.Second),
		RetrySource:           state.RetrySource,
		Pending:               state.Pending,
		Phase:                 state.phase(now),
		ManualReleaseRequired: state.ManualReleaseRequired,
		RestoreTarget:         state.restoreTarget(configuredDisabled, configuredPriority),
		Superseded:            state.Superseded,
		LastError:             state.LastError,
	}
	if !state.NextRestoreAttempt.IsZero() {
		nextAttempt := state.NextRestoreAttempt
		view.NextRestoreAttempt = &nextAttempt
	}
	return view
}

func guardOutcomeViewFromState(state cooldownState) *guardOutcomeView {
	if state.Active || state.Pending || state.Restoring || state.RestoreOutcome == "" || state.RestoredAt.IsZero() {
		return nil
	}
	return &guardOutcomeView{
		Outcome:       state.RestoreOutcome,
		At:            state.RestoredAt,
		RestoreTarget: state.RestoreTargetSnapshot,
	}
}

func weeklyViewFromState(state quotaState, now time.Time) *weeklyView {
	if !state.Found {
		return nil
	}
	view := &weeklyView{
		Empty:        state.Empty,
		ResetElapsed: state.ResetElapsed,
		Groups:       append([]string(nil), state.Groups...),
		CheckedAt:    state.CheckedAt,
	}
	if !state.ResetTime.IsZero() {
		resetTime := state.ResetTime
		view.ResetTime = &resetTime
		view.RefreshKnown = true
		remaining := quotaRemaining(state, now)
		view.Remaining = formatDuration(remaining)
		view.RemainingSeconds = int64(remaining / time.Second)
	}
	return view
}

func buildProxyGroups(credentials []credentialView) []proxyGroupView {
	groups := make(map[proxyGroupKey]*proxyGroupView)
	for _, credential := range credentials {
		groupKey := proxyGroupKeyFor(credential)
		group := groups[groupKey]
		if group == nil {
			group = newProxyGroup(credential)
			groups[groupKey] = group
		}
		group.addCredential(credential)
	}
	result := make([]proxyGroupView, 0, len(groups))
	for _, group := range groups {
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Credentials != result[j].Credentials {
			return result[i].Credentials > result[j].Credentials
		}
		return result[i].Proxy < result[j].Proxy
	})
	return result
}

type proxyGroupKey struct {
	Identity string
	Source   string
}

func proxyGroupKeyFor(credential credentialView) proxyGroupKey {
	if credential.ProxyID != "" {
		return proxyGroupKey{Identity: credential.ProxyID}
	}
	return proxyGroupKey{Identity: credential.EffectiveProxy, Source: credential.ProxySource}
}

func newProxyGroup(credential credentialView) *proxyGroupView {
	return &proxyGroupView{
		ProxyID:    credential.ProxyID,
		ProxyAlias: credential.ProxyAlias,
		Proxy:      credential.EffectiveProxy,
		Source:     credential.ProxySource,
	}
}

func (g *proxyGroupView) addCredential(credential credentialView) {
	if g.Source != credential.ProxySource {
		g.Source = "mixed"
	}
	g.Credentials++
	if credential.Recent {
		g.Recent++
	}
	g.Success += credential.Usage.Success
	g.Failed += credential.Usage.Failed
	g.RateLimited += credential.Usage.RateLimited
	if credential.Cooldown != nil {
		g.Cooling++
	}
}

func sortCredentialViews(views []credentialView) {
	sort.SliceStable(views, func(i, j int) bool {
		return credentialViewLess(views[i], views[j])
	})
}

func credentialViewLess(left, right credentialView) bool {
	leftEmpty := left.WeeklyQuota != nil && left.WeeklyQuota.Empty
	rightEmpty := right.WeeklyQuota != nil && right.WeeklyQuota.Empty
	if leftEmpty != rightEmpty {
		return !leftEmpty
	}
	if leftEmpty {
		leftKnown := left.WeeklyQuota.RefreshKnown
		rightKnown := right.WeeklyQuota.RefreshKnown
		if leftKnown != rightKnown {
			return leftKnown
		}
		if leftKnown {
			leftReset := left.WeeklyQuota.ResetTime
			rightReset := right.WeeklyQuota.ResetTime
			if leftReset != nil && rightReset != nil && !leftReset.Equal(*rightReset) {
				return leftReset.Before(*rightReset)
			}
			if left.WeeklyQuota.RemainingSeconds != right.WeeklyQuota.RemainingSeconds {
				return left.WeeklyQuota.RemainingSeconds < right.WeeklyQuota.RemainingSeconds
			}
		}
	}
	if left.EffectivePriority != right.EffectivePriority {
		return left.EffectivePriority > right.EffectivePriority
	}
	leftName := strings.ToLower(left.Name)
	rightName := strings.ToLower(right.Name)
	if leftName != rightName {
		return leftName < rightName
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.AuthIndex < right.AuthIndex
}

func isAntigravityEntry(entry hostAuthEntry) bool {
	provider := firstNonEmpty(entry.Provider, entry.Type)
	return strings.EqualFold(strings.TrimSpace(provider), "antigravity")
}

func isCodexEntry(entry hostAuthEntry) bool {
	provider := firstNonEmpty(entry.Provider, entry.Type)
	return strings.EqualFold(strings.TrimSpace(provider), "codex")
}

func configurationView(cfg guardConfig) configView {
	return configView{
		Auto429Enabled:          cfg.Auto429Enabled,
		Action:                  cfg.Action,
		TemporaryPriority:       cfg.TemporaryPriority,
		Consecutive429Threshold: cfg.Consecutive429Limit,
		Quota429Threshold:       cfg.Consecutive429Limit,
		Generic429Threshold:     cfg.Consecutive429Limit,
		FallbackCooldown:        cfg.FallbackCooldown.String(),
		RecentWindow:            cfg.RecentWindow.String(),
		WeeklyGroup:             cfg.WeeklyGroup,
		WeeklyEmptyThreshold:    cfg.WeeklyEmptyThreshold,
	}
}
