package main

import (
	"net/http"
	"sync"
	"time"
)

const (
	restoreOutcomeRestored       = "restored"
	restoreOutcomeManualTakeover = "manual_takeover"
)

type usageState struct {
	Success        int64
	Failed         int64
	RateLimited    int64
	Consecutive429 int
	LastRequest    time.Time
	LastModel      string
}

type cooldownState struct {
	Active                  bool
	Pending                 bool
	Restoring               bool
	ManualReleaseRequired   bool
	RestoreRequested        bool
	Generation              uint64
	Action                  string
	Priority                *int
	Trigger                 string
	Until                   time.Time
	RetrySource             string
	LastError               string
	NextRestoreAttempt      time.Time
	OriginalDisabled        *bool
	OriginalPriority        *int
	AppliedDisabled         *bool
	AppliedPriority         *int
	AppliedDisabledRevision uint64
	AppliedPriorityRevision uint64
	DisabledRestored        bool
	PriorityRestored        bool
	RestoreManualTakeover   bool
	RestoreTargetSnapshot   string
	RestoreOutcome          string
	RestoredAt              time.Time
	Superseded              bool
}

type quotaState struct {
	Found          bool
	Empty          bool
	ResetElapsed   bool
	Groups         []string
	ResetTime      time.Time
	ObservedAt     time.Time
	ObservedServer time.Time
	CheckedAt      time.Time
	LastError      string
}

type credentialState struct {
	Usage                usageState
	Codex                codexQuotaState
	Cooldown             cooldownState
	Quota                quotaState
	ManagedProxy         *string
	ManagedProxyRevision uint64
}

type stateStore struct {
	mu          sync.Mutex
	credentials map[string]*credentialState
}

func newStateStore() *stateStore {
	return &stateStore{credentials: make(map[string]*credentialState)}
}

func (s *stateStore) observeUsage(authIndex, model string, failed bool, statusCode int, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	state.Usage.LastRequest = now
	state.Usage.LastModel = model
	if failed {
		state.Usage.Failed++
	} else {
		state.Usage.Success++
	}
	if statusCode == 429 {
		state.Usage.RateLimited++
		state.Usage.Consecutive429++
	} else {
		state.Usage.Consecutive429 = 0
	}
	return state.Usage.Consecutive429
}

func (s *stateStore) setManagedProxy(authIndex string, proxyURL *string, revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	if proxyURL == nil {
		state.ManagedProxy = nil
		state.ManagedProxyRevision = 0
		return
	}
	value := *proxyURL
	state.ManagedProxy = &value
	state.ManagedProxyRevision = revision
}

func (s *stateStore) snapshot(authIndex string, now time.Time) credentialState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	expireQuotaLocked(state, now)
	return cloneCredentialState(*state)
}

func (s *stateStore) allSnapshots(now time.Time) map[string]credentialState {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]credentialState, len(s.credentials))
	for authIndex, state := range s.credentials {
		expireQuotaLocked(state, now)
		result[authIndex] = cloneCredentialState(*state)
	}
	return result
}

func (s *stateStore) expireQuotas(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.credentials {
		expireQuotaLocked(state, now)
	}
}

func (s *stateStore) getLocked(authIndex string) *credentialState {
	state := s.credentials[authIndex]
	if state == nil {
		state = &credentialState{}
		s.credentials[authIndex] = state
	}
	return state
}

func cloneCredentialState(state credentialState) credentialState {
	state.Quota.Groups = append([]string(nil), state.Quota.Groups...)
	state.Cooldown.Priority = cloneInt(state.Cooldown.Priority)
	state.Cooldown.OriginalDisabled = cloneBool(state.Cooldown.OriginalDisabled)
	state.Cooldown.OriginalPriority = cloneInt(state.Cooldown.OriginalPriority)
	state.Cooldown.AppliedDisabled = cloneBool(state.Cooldown.AppliedDisabled)
	state.Cooldown.AppliedPriority = cloneInt(state.Cooldown.AppliedPriority)
	if state.ManagedProxy != nil {
		value := *state.ManagedProxy
		state.ManagedProxy = &value
	}
	return state
}

func (s *stateStore) observeCodex(authIndex, errorType string, statusCode int, headers http.Header, body string, now time.Time) (int, codexQuotaState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	codex := &state.Codex
	if parsed, ok := parseCodexQuotaState(headers, now); ok {
		codex.Weekly = parsed.Weekly
		codex.FiveHour = parsed.FiveHour
		codex.CheckedAt = now
	}
	codex.LastStatusCode = statusCode
	codex.LastErrorType = errorType
	codex.LastError = body
	if isCodexUsageLimitError(errorType) {
		codex.ConsecutiveUsageLimit++
	} else {
		codex.ConsecutiveUsageLimit = 0
	}
	return codex.ConsecutiveUsageLimit, *codex
}

func (s *stateStore) clearCodexErrorState(authIndex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	codex := &s.getLocked(authIndex).Codex
	codex.ConsecutiveUsageLimit = 0
	codex.LastErrorType = ""
	codex.LastError = ""
	codex.LastStatusCode = 0
}

func (s *stateStore) clearGuardState(authIndex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	state.Cooldown = cooldownState{Generation: state.Cooldown.Generation + 1}
	state.Codex = codexQuotaState{}
	state.Quota = quotaState{}
	state.Usage.Consecutive429 = 0
}

func expireQuotaLocked(state *credentialState, now time.Time) {
	if state == nil || !state.Quota.Found || state.Quota.ResetTime.IsZero() {
		return
	}
	if quotaServerNow(state.Quota, now).Before(state.Quota.ResetTime) {
		return
	}
	if state.Quota.Empty && state.Cooldown.Active && state.Cooldown.ManualReleaseRequired {
		return
	}
	state.Quota.Empty = false
	state.Quota.ResetElapsed = true
	state.Quota.ResetTime = time.Time{}
	state.Quota.ObservedAt = now
	state.Quota.ObservedServer = now
	state.Quota.LastError = ""
}
