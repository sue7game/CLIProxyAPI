package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
)

const auto429DisabledStatusMessage = "auto disabled after consecutive 429"
const auto429MaxEventsPerAuth = 50

const (
	auto429EventCleared  = "cleared"
	auto429EventDisabled = "disabled"
	auto429EventRestored = "restored"
)

type auto429ProbeContextKey struct{}

type auto429State struct {
	consecutive429      int
	autoDisabled        bool
	disabledAt          time.Time
	last429At           time.Time
	last429Model        string
	nextRecheckAt       time.Time
	lastCountedRequest  string
	lastProbeModel      string
	lastProbeStatusCode int
	lastProbeError      string
	probing             bool
	probeStartedAt      time.Time
}

// Auto429Snapshot exposes runtime-only auto-disable state for management output.
type Auto429Snapshot struct {
	Count               int
	AutoDisabled        bool
	DisabledAt          time.Time
	Last429At           time.Time
	Last429Model        string
	NextRecheckAt       time.Time
	LastProbeModel      string
	LastProbeStatusCode int
	LastProbeError      string
}

// Auto429Event is a compact runtime-only history entry for auto-429 state changes.
type Auto429Event struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Model  string    `json:"model"`
	Result string    `json:"result"`
}

// Auto429DisabledStatusMessage returns the runtime status shown for auto-429 disabled auths.
func Auto429DisabledStatusMessage() string {
	return auto429DisabledStatusMessage
}

func contextWithAuto429Probe(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auto429ProbeContextKey{}, true)
}

func isAuto429Probe(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(auto429ProbeContextKey{}).(bool)
	return v
}

// Auto429Events returns compact runtime-only auto-429 history for an auth.
func (m *Manager) Auto429Events(authID string) []Auto429Event {
	if m == nil || strings.TrimSpace(authID) == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneAuto429Events(m.auto429Events[strings.TrimSpace(authID)])
}

// Auto429EventCount returns the number of runtime-only auto-429 history entries for an auth.
func (m *Manager) Auto429EventCount(authID string) int {
	if m == nil || strings.TrimSpace(authID) == "" {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.auto429Events[strings.TrimSpace(authID)])
}

func cloneAuto429Events(events []Auto429Event) []Auto429Event {
	if len(events) == 0 {
		return nil
	}
	out := make([]Auto429Event, len(events))
	copy(out, events)
	return out
}

func (m *Manager) appendAuto429EventLocked(authID string, event Auto429Event) {
	if m == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	event.Type = strings.TrimSpace(event.Type)
	event.Model = strings.TrimSpace(event.Model)
	event.Result = strings.TrimSpace(event.Result)
	if event.Type == "" || event.Result == "" {
		return
	}
	if m.auto429Events == nil {
		m.auto429Events = make(map[string][]Auto429Event)
	}
	events := append(m.auto429Events[authID], event)
	events = compactAuto429Events(events)
	if len(events) > auto429MaxEventsPerAuth {
		events = events[len(events)-auto429MaxEventsPerAuth:]
	}
	m.auto429Events[authID] = append([]Auto429Event(nil), events...)
}

func compactAuto429Events(events []Auto429Event) []Auto429Event {
	if len(events) <= 2 {
		return events
	}
	out := make([]Auto429Event, 0, len(events))
	for i := 0; i < len(events); {
		if !isAuto429RepeatedProbeEvent(events[i]) {
			out = append(out, events[i])
			i++
			continue
		}
		j := i + 1
		for j < len(events) && isAuto429RepeatedProbeEvent(events[j]) {
			j++
		}
		if j-i <= 2 {
			out = append(out, events[i:j]...)
		} else {
			out = append(out, events[i], events[j-1])
		}
		i = j
	}
	return out
}

func isAuto429RepeatedProbeEvent(event Auto429Event) bool {
	eventType := strings.TrimSpace(event.Type)
	if eventType != auto429EventManualProbe && eventType != auto429EventAutoProbe {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(event.Result), "429")
}

// Auto429Snapshot returns runtime-only auto-disable state for an auth.
func (m *Manager) Auto429Snapshot(authID string) (Auto429Snapshot, bool) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return Auto429Snapshot{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := m.auto429[strings.TrimSpace(authID)]
	if st == nil {
		return Auto429Snapshot{}, false
	}
	return Auto429Snapshot{
		Count:               st.consecutive429,
		AutoDisabled:        st.autoDisabled,
		DisabledAt:          st.disabledAt,
		Last429At:           st.last429At,
		Last429Model:        st.last429Model,
		NextRecheckAt:       st.nextRecheckAt,
		LastProbeModel:      st.lastProbeModel,
		LastProbeStatusCode: st.lastProbeStatusCode,
		LastProbeError:      st.lastProbeError,
	}, true
}

// ClearAuto429State removes runtime-only auto-disable state and restores the auth if needed.
func (m *Manager) ClearAuto429State(authID string) bool {
	if m == nil {
		return false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}

	var snapshot *Auth
	var clearedModels []string
	now := time.Now()

	m.mu.Lock()
	auth := m.auths[authID]
	if m.clearAuto429StateWithEventLocked(authID, now, "cleared") && auth != nil {
		if !shouldPreserveManualDisableOnAuto429Clear(auth) {
			auth.Disabled = false
			clearAuthStateOnSuccess(auth, now)
			clearedModels = resetAllModelStates(auth, now)
			snapshot = auth.Clone()
		}
	}
	m.mu.Unlock()

	if snapshot != nil && m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	for _, model := range clearedModels {
		registry.GetGlobalRegistry().ClearModelQuotaExceeded(authID, model)
		registry.GetGlobalRegistry().ResumeClientModel(authID, model)
	}
	return snapshot != nil
}

func (m *Manager) deleteAuto429EventsLocked(authID string) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return
	}
	delete(m.auto429Events, strings.TrimSpace(authID))
}

// ForgetAuto429State drops runtime-only auto-429 state without changing the auth.
func (m *Manager) ForgetAuto429State(authID string) {
	if m == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	m.mu.Lock()
	m.clearAuto429StateWithEventLocked(authID, time.Now(), "manual disabled, auto-429 cleared")
	m.mu.Unlock()
}

func (m *Manager) clearAuto429StateWithEventLocked(authID string, now time.Time, result string) bool {
	if m == nil || strings.TrimSpace(authID) == "" {
		return false
	}
	authID = strings.TrimSpace(authID)
	st := m.auto429[authID]
	if st == nil {
		return false
	}
	delete(m.auto429, authID)
	if st.autoDisabled {
		if now.IsZero() {
			now = time.Now()
		}
		result = strings.TrimSpace(result)
		if result == "" {
			result = "cleared"
		}
		m.appendAuto429EventLocked(authID, Auto429Event{
			Time:   now,
			Type:   auto429EventCleared,
			Result: result,
		})
	}
	return st.autoDisabled
}

func (m *Manager) isAuto429DisabledLocked(authID string) bool {
	if m == nil || strings.TrimSpace(authID) == "" {
		return false
	}
	st := m.auto429[authID]
	return st != nil && st.autoDisabled
}

func (m *Manager) forgetAuto429ForManualDisableLocked(auth *Auth) {
	if m == nil || auth == nil || auth.ID == "" {
		return
	}
	if isExplicitManualDisableUpdate(auth) {
		m.clearAuto429StateWithEventLocked(auth.ID, time.Now(), "manual disabled, auto-429 cleared")
		if isRemovedManualDisableUpdate(auth) {
			m.deleteAuto429EventsLocked(auth.ID)
		}
	}
}

func isExplicitManualDisableUpdate(auth *Auth) bool {
	if auth == nil || !auth.Disabled || auth.StatusMessage == auto429DisabledStatusMessage {
		return false
	}
	if auth.Metadata != nil {
		if disabled, ok := parseBoolAny(auth.Metadata["disabled"]); ok && disabled {
			return true
		}
	}
	msg := strings.ToLower(strings.TrimSpace(auth.StatusMessage))
	return strings.HasPrefix(msg, "disabled") || strings.HasPrefix(msg, "removed")
}

func isRemovedManualDisableUpdate(auth *Auth) bool {
	if auth == nil || !auth.Disabled {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(auth.StatusMessage))
	return strings.HasPrefix(msg, "removed")
}

func shouldPreserveManualDisableOnAuto429Clear(auth *Auth) bool {
	if auth == nil || !auth.Disabled || auth.StatusMessage == auto429DisabledStatusMessage {
		return false
	}
	if isExplicitManualDisableUpdate(auth) {
		return true
	}
	if auth.Status != StatusDisabled {
		return false
	}
	return !looksLikeAuto429RuntimeFailure(auth)
}

func looksLikeAuto429RuntimeFailure(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if auth.LastError != nil && auth.LastError.HTTPStatus == http.StatusTooManyRequests {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(auth.StatusMessage))
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "resource exhausted") ||
		strings.Contains(msg, "resource has been exhausted") ||
		strings.Contains(msg, "quota")
}

func (m *Manager) authForAuto429SafePersistLocked(auth *Auth) *Auth {
	if auth == nil {
		return nil
	}
	if m.isAuto429DisabledLocked(auth.ID) {
		return authWithoutAuto429RuntimeDisable(auth)
	}
	if auth.Disabled && auth.StatusMessage != auto429DisabledStatusMessage {
		return auth
	}
	if auth.StatusMessage == auto429DisabledStatusMessage {
		return authWithoutAuto429RuntimeDisable(auth)
	}
	return auth
}

func authWithoutAuto429RuntimeDisable(auth *Auth) *Auth {
	if auth == nil {
		return nil
	}
	persistAuth := auth.Clone()
	clearAuto429RuntimeDisable(persistAuth, time.Time{})
	return persistAuth
}

func clearAuto429RuntimeDisable(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	auth.Disabled = false
	auth.Status = StatusActive
	auth.StatusMessage = ""
	auth.LastError = nil
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	if auth.Metadata != nil {
		auth.Metadata["disabled"] = false
	}
	if !now.IsZero() {
		auth.UpdatedAt = now
	}
}

func (m *Manager) reapplyAuto429StateLocked(auth *Auth, now time.Time) {
	if m == nil || auth == nil || auth.ID == "" {
		return
	}
	st := m.auto429[auth.ID]
	if st == nil {
		if auth.StatusMessage == auto429DisabledStatusMessage {
			clearAuto429RuntimeDisable(auth, now)
		}
		return
	}
	if auth.AutoDisable429Threshold() <= 0 {
		cleared := m.clearAuto429StateWithEventLocked(auth.ID, now, "threshold disabled, auto-429 cleared")
		if cleared || auth.StatusMessage == auto429DisabledStatusMessage {
			clearAuto429RuntimeDisable(auth, now)
		}
		return
	}
	if !st.autoDisabled {
		return
	}
	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = auto429DisabledStatusMessage
	auth.LastError = nil
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.UpdatedAt = now
}

func (m *Manager) recordAuto429ResultLocked(ctx context.Context, auth *Auth, result Result, now time.Time) {
	if m == nil || auth == nil || auth.ID == "" || isAuto429Probe(ctx) {
		return
	}
	threshold := auth.AutoDisable429Threshold()
	if threshold <= 0 {
		if m.clearAuto429StateWithEventLocked(auth.ID, now, "threshold disabled, auto-429 cleared") {
			clearAuto429RuntimeDisable(auth, now)
		}
		return
	}
	if m.auto429 == nil {
		m.auto429 = make(map[string]*auto429State)
	}

	status := statusCodeFromResult(result.Error)
	if result.Success || status != http.StatusTooManyRequests {
		if st := m.auto429[auth.ID]; st != nil && !st.autoDisabled {
			st.consecutive429 = 0
			st.lastCountedRequest = ""
		}
		return
	}

	requestID := logging.GetRequestID(ctx)
	st := m.auto429[auth.ID]
	if st == nil {
		st = &auto429State{}
		m.auto429[auth.ID] = st
	}
	if requestID != "" && st.lastCountedRequest == requestID {
		return
	}

	st.consecutive429++
	st.lastCountedRequest = requestID
	st.last429At = now
	if model := strings.TrimSpace(result.Model); model != "" {
		st.last429Model = model
	}

	if st.consecutive429 < threshold || st.autoDisabled {
		return
	}

	st.autoDisabled = true
	st.disabledAt = now
	st.nextRecheckAt = now.Add(time.Duration(auth.Auto429RecheckIntervalSeconds()) * time.Second)
	m.appendAuto429EventLocked(auth.ID, Auto429Event{
		Time:   now,
		Type:   auto429EventDisabled,
		Model:  st.last429Model,
		Result: "auto disabled after consecutive 429",
	})
	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = auto429DisabledStatusMessage
	auth.LastError = nil
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.UpdatedAt = now
}

func resetAllModelStates(auth *Auth, now time.Time) []string {
	if auth == nil || len(auth.ModelStates) == 0 {
		return nil
	}
	models := make([]string, 0, len(auth.ModelStates))
	for model, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		resetModelState(state, now)
		models = append(models, model)
	}
	updateAggregatedAvailability(auth, now)
	return models
}
