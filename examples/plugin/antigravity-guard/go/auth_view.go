package main

import "time"

func (s *authService) credentialView(entry hostAuthEntry, now time.Time) credentialView {
	state := s.store.snapshot(entry.AuthIndex, now)
	view := s.baseCredentialView(entry)
	view.LastModel = state.Usage.LastModel
	view.Usage = usageView{
		Success:        state.Usage.Success,
		Failed:         state.Usage.Failed,
		RateLimited:    state.Usage.RateLimited,
		Consecutive429: state.Usage.Consecutive429,
	}
	view.QuotaError = state.Quota.LastError
	view.GuardError = state.Cooldown.LastError
	if isCodexEntry(entry) {
		view.Codex = codexViewFromState(state.Codex, state.Cooldown, now)
	} else if isAntigravityEntry(entry) {
		view.Subscription = subscriptionViewFromState(state.Subscription)
	}
	if !state.Usage.LastRequest.IsZero() {
		lastRequest := state.Usage.LastRequest
		view.LastRequest = &lastRequest
		view.Recent = now.Sub(lastRequest) <= s.config().RecentWindow
	}
	view.Cooldown = cooldownViewFromState(state.Cooldown, view.ConfiguredDisabled, view.ConfiguredPriority, now)
	view.GuardOutcome = guardOutcomeViewFromState(state.Cooldown)
	view.WeeklyQuota = weeklyViewFromState(state.Quota, now)
	return view
}

func (s *authService) baseCredentialView(entry hostAuthEntry) credentialView {
	effectiveProxyURL, proxySource := effectiveProxy(entry, entry.ConfiguredProxyURL)
	proxyDescriptor, proxyReusable := s.proxies.describe(effectiveProxyURL)
	effectiveProxy := maskProxyURL(effectiveProxyURL)
	if proxyReusable {
		effectiveProxy = proxyDescriptor.Display
	}
	configuredPriority, effectivePriority := credentialPriorities(entry)
	configuredDisabled, effectiveDisabled := credentialDisabledStates(entry)
	return credentialView{
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
		ConfiguredProxy:    maskProxyURL(entry.ConfiguredProxyURL),
		EffectiveProxy:     effectiveProxy,
		ProxySource:        proxySource,
		ProxyReusable:      proxyReusable,
		ProxyID:            proxyDescriptor.ID,
		ProxyAlias:         proxyDescriptor.Alias,
	}
}

func credentialPriorities(entry hostAuthEntry) (int, int) {
	configured := entry.ConfiguredPriority
	if configured == 0 {
		configured = entry.Priority
	}
	effective := entry.EffectivePriority
	if entry.RuntimeOverride != nil && entry.RuntimeOverride.Priority != nil {
		effective = *entry.RuntimeOverride.Priority
	} else if effective == 0 {
		effective = configured
	}
	return configured, effective
}

func credentialDisabledStates(entry hostAuthEntry) (bool, bool) {
	configured := entry.ConfiguredDisabled
	if entry.RuntimeOverride == nil && entry.Disabled {
		configured = true
	}
	effective := entry.EffectiveDisabled || entry.Disabled
	if entry.RuntimeOverride != nil && entry.RuntimeOverride.Disabled != nil {
		effective = configured || *entry.RuntimeOverride.Disabled
	}
	return configured, effective
}
