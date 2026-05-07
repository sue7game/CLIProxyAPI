package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
)

const (
	auto429RecheckLoopInterval = 30 * time.Second
	auto429ProbeTimeout        = 30 * time.Second
	auto429ProbeMaxConcurrency = 4
	auto429EventAutoProbe      = "auto_probe"
	auto429EventManualProbe    = "manual_probe"
)

var (
	ErrAuto429AuthNotFound          = errors.New("auto-429 auth not found")
	ErrAuto429NotDisabled           = errors.New("auth is not auto-429 disabled")
	ErrAuto429ExecutorNotRegistered = errors.New("auto-429 executor not registered")
	ErrAuto429ProbeModelUnavailable = errors.New("auto-429 probe model unavailable")
	ErrAuto429ProbeInProgress       = errors.New("auto-429 probe already in progress")
)

type auto429ProbeJob struct {
	auth          *Auth
	executor      ProviderExecutor
	routeModel    string
	upstreamModel string
}

// Auto429ProbeOutcome reports the result of a manual or scheduled auto-429 recovery probe.
type Auto429ProbeOutcome struct {
	AuthID         string    `json:"auth_id"`
	Model          string    `json:"model"`
	UpstreamModel  string    `json:"upstream_model"`
	Restored       bool      `json:"restored"`
	StatusCode     int       `json:"probe_status"`
	Error          string    `json:"probe_error,omitempty"`
	NextRecheckAt  time.Time `json:"next_auto_429_recheck_at,omitempty"`
	AutoDisabled   bool      `json:"auto_disabled_by_429"`
	Auto429Cleared bool      `json:"auto_429_cleared"`
}

// StartAuto429Recheck launches the runtime-only auto-429 recovery loop.
func (m *Manager) StartAuto429Recheck(parent context.Context, interval time.Duration) {
	if m == nil {
		return
	}
	if interval <= 0 {
		interval = auto429RecheckLoopInterval
	}

	m.mu.Lock()
	cancelPrev := m.auto429RecheckCancel
	m.auto429RecheckCancel = nil
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}

	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.auto429RecheckCancel = cancel
	m.mu.Unlock()

	go m.runAuto429RecheckLoop(ctx, interval)
}

// StopAuto429Recheck cancels the runtime-only auto-429 recovery loop.
func (m *Manager) StopAuto429Recheck() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.auto429RecheckCancel
	m.auto429RecheckCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) runAuto429RecheckLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		m.runDueAuto429Probes(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) runDueAuto429Probes(ctx context.Context, now time.Time) {
	jobs := m.auto429DueProbeJobs(now)
	if len(jobs) == 0 {
		return
	}

	sem := make(chan struct{}, auto429ProbeMaxConcurrency)
	var wg sync.WaitGroup
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(job auto429ProbeJob) {
			defer wg.Done()
			defer func() { <-sem }()
			startedAt := time.Now()
			if errBegin := m.beginAuto429Probe(job.auth.ID, startedAt); errBegin != nil {
				return
			}
			m.runAuto429Probe(ctx, job, startedAt, auto429EventAutoProbe)
		}(job)
	}
	wg.Wait()
}

func (m *Manager) auto429DueProbeJobs(now time.Time) []auto429ProbeJob {
	if m == nil {
		return nil
	}
	authIDs := make([]string, 0)

	m.mu.Lock()
	for authID, state := range m.auto429 {
		if state == nil || !state.autoDisabled {
			continue
		}
		auth := m.auths[authID]
		if auth == nil || auth.AutoDisable429Threshold() <= 0 {
			delete(m.auto429, authID)
			continue
		}
		if state.probing {
			continue
		}
		if !state.nextRecheckAt.IsZero() && state.nextRecheckAt.After(now) {
			continue
		}
		authIDs = append(authIDs, authID)
	}
	m.mu.Unlock()

	jobs := make([]auto429ProbeJob, 0, len(authIDs))
	for _, authID := range authIDs {
		job, err := m.auto429ProbeJob(authID, now, auto429EventAutoProbe)
		if err == nil {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func firstRegisteredModel(authID string) string {
	for _, model := range registry.GetGlobalRegistry().GetModelsForClient(authID) {
		if model == nil {
			continue
		}
		if id := strings.TrimSpace(model.ID); id != "" {
			return id
		}
	}
	return ""
}

// ProbeAuto429State runs an immediate recovery probe for one auto-429 disabled auth.
func (m *Manager) ProbeAuto429State(ctx context.Context, authID string) (Auto429ProbeOutcome, error) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return Auto429ProbeOutcome{}, ErrAuto429AuthNotFound
	}
	startedAt := time.Now()
	job, err := m.auto429ProbeJob(authID, startedAt, auto429EventManualProbe)
	if err != nil {
		return Auto429ProbeOutcome{AuthID: authID}, err
	}
	if errBegin := m.beginAuto429Probe(authID, startedAt); errBegin != nil {
		return Auto429ProbeOutcome{AuthID: authID}, errBegin
	}
	return m.runAuto429Probe(ctx, job, startedAt, auto429EventManualProbe), nil
}

func (m *Manager) auto429ProbeJob(authID string, now time.Time, eventType string) (auto429ProbeJob, error) {
	authID = strings.TrimSpace(authID)
	if m == nil || authID == "" {
		return auto429ProbeJob{}, ErrAuto429AuthNotFound
	}

	var auth *Auth
	var exec ProviderExecutor
	var routeModel string

	m.mu.Lock()
	state := m.auto429[authID]
	if state == nil || !state.autoDisabled {
		m.mu.Unlock()
		return auto429ProbeJob{}, ErrAuto429NotDisabled
	}
	if state.probing {
		m.mu.Unlock()
		return auto429ProbeJob{}, ErrAuto429ProbeInProgress
	}
	currentAuth := m.auths[authID]
	if currentAuth == nil {
		delete(m.auto429, authID)
		m.mu.Unlock()
		return auto429ProbeJob{}, ErrAuto429AuthNotFound
	}
	if currentAuth.AutoDisable429Threshold() <= 0 {
		delete(m.auto429, authID)
		m.mu.Unlock()
		return auto429ProbeJob{}, ErrAuto429NotDisabled
	}
	provider := strings.TrimSpace(currentAuth.Provider)
	exec = m.executors[provider]
	if exec == nil {
		lowerProvider := strings.ToLower(provider)
		if lowerProvider != provider {
			exec = m.executors[lowerProvider]
		}
	}
	auth = currentAuth.Clone()
	routeModel = strings.TrimSpace(state.last429Model)
	m.mu.Unlock()

	if exec == nil {
		m.recordAuto429ProbeSetupError(authID, "executor not registered", "", now, eventType)
		return auto429ProbeJob{}, ErrAuto429ExecutorNotRegistered
	}
	if routeModel == "" {
		routeModel = firstRegisteredModel(authID)
	}
	if routeModel == "" {
		m.recordAuto429ProbeSetupError(authID, "no model available for probe", "", now, eventType)
		return auto429ProbeJob{}, ErrAuto429ProbeModelUnavailable
	}

	upstreamModel := m.resolveAuto429ProbeUpstreamModel(auth, routeModel, now)
	if upstreamModel == "" {
		m.recordAuto429ProbeSetupError(authID, "no upstream model available for probe", routeModel, now, eventType)
		return auto429ProbeJob{}, ErrAuto429ProbeModelUnavailable
	}

	return auto429ProbeJob{
		auth:          auth,
		executor:      exec,
		routeModel:    routeModel,
		upstreamModel: upstreamModel,
	}, nil
}

func (m *Manager) beginAuto429Probe(authID string, startedAt time.Time) error {
	if m == nil || strings.TrimSpace(authID) == "" {
		return ErrAuto429AuthNotFound
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	authID = strings.TrimSpace(authID)
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.auto429[authID]
	if state == nil || !state.autoDisabled {
		return ErrAuto429NotDisabled
	}
	auth := m.auths[authID]
	if auth == nil {
		delete(m.auto429, authID)
		return ErrAuto429AuthNotFound
	}
	if auth.AutoDisable429Threshold() <= 0 {
		delete(m.auto429, authID)
		return ErrAuto429NotDisabled
	}
	if state.probing {
		return ErrAuto429ProbeInProgress
	}
	state.probing = true
	state.probeStartedAt = startedAt
	return nil
}

func (m *Manager) resolveAuto429ProbeUpstreamModel(auth *Auth, routeModel string, now time.Time) string {
	if auth == nil {
		return ""
	}
	probeAuth := auth.Clone()
	clearAuto429RuntimeDisable(probeAuth, now)
	candidates := m.executionModelCandidates(probeAuth, routeModel)
	for _, candidate := range candidates {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed
		}
	}
	return strings.TrimSpace(routeModel)
}

func (m *Manager) recordAuto429ProbeSetupError(authID, message, probeModel string, baseTime time.Time, eventType string) {
	if m == nil || strings.TrimSpace(authID) == "" {
		return
	}
	authID = strings.TrimSpace(authID)
	if baseTime.IsZero() {
		baseTime = time.Now()
	}
	m.mu.Lock()
	state := m.auto429[authID]
	auth := m.auths[authID]
	if state == nil || auth == nil {
		m.mu.Unlock()
		return
	}
	state.lastProbeStatusCode = 0
	state.lastProbeError = message
	state.lastProbeModel = strings.TrimSpace(probeModel)
	state.nextRecheckAt = baseTime.Add(time.Duration(auth.Auto429RecheckIntervalSeconds()) * time.Second)
	m.appendAuto429EventLocked(authID, Auto429Event{
		Time:   baseTime,
		Type:   normalizeAuto429ProbeEventType(eventType),
		Model:  probeModel,
		Result: message,
	})
	m.mu.Unlock()
}

func (m *Manager) runAuto429Probe(ctx context.Context, job auto429ProbeJob, startedAt time.Time, eventType string) Auto429ProbeOutcome {
	outcome := Auto429ProbeOutcome{
		AuthID:        "",
		Model:         strings.TrimSpace(job.routeModel),
		UpstreamModel: strings.TrimSpace(job.upstreamModel),
		AutoDisabled:  true,
	}
	if job.auth != nil {
		outcome.AuthID = job.auth.ID
	}
	if job.auth == nil || job.auth.ID == "" || job.executor == nil || outcome.UpstreamModel == "" {
		return outcome
	}
	if outcome.Model == "" {
		outcome.Model = outcome.UpstreamModel
	}
	if startedAt.IsZero() {
		startedAt = time.Now()
	}

	// Bound only the background recovery probe. User-facing upstream requests still
	// rely on their existing connection lifecycle.
	probeCtx, cancel := context.WithTimeout(contextWithAuto429Probe(ctx), auto429ProbeTimeout)
	defer cancel()
	req := buildAuto429ProbeRequest(outcome.Model, outcome.UpstreamModel)
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Metadata: map[string]any{
			"auto_429_probe": true,
		},
	}
	opts = ensureRequestedModelMetadata(opts, outcome.Model)
	probeCtx = contextWithRequestedModelAlias(probeCtx, opts, outcome.Model)
	if rt := m.roundTripperFor(job.auth); rt != nil {
		probeCtx = context.WithValue(probeCtx, roundTripperContextKey{}, rt)
		probeCtx = context.WithValue(probeCtx, "cliproxy.roundtripper", rt)
	}

	probeAuth := job.auth.Clone()
	probeAuth.Disabled = false
	probeAuth.Status = StatusActive
	_, err := job.executor.Execute(probeCtx, probeAuth, req, opts)
	return m.recordAuto429ProbeResult(job.auth.ID, err, startedAt, outcome.Model, outcome.UpstreamModel, eventType)
}

func buildAuto429ProbeRequest(routeModel, upstreamModel string) cliproxyexecutor.Request {
	routeModel = strings.TrimSpace(routeModel)
	upstreamModel = strings.TrimSpace(upstreamModel)
	if routeModel == "" {
		routeModel = upstreamModel
	}
	if upstreamModel == "" {
		upstreamModel = routeModel
	}
	escapedModel := strings.ReplaceAll(upstreamModel, `"`, `\"`)
	payload := []byte(fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"ping"}],"max_tokens":1,"stream":false}`, escapedModel))
	return cliproxyexecutor.Request{
		Model:    upstreamModel,
		Payload:  payload,
		Format:   sdktranslator.FormatOpenAI,
		Metadata: map[string]any{"auto_429_probe": true},
	}
}

func (m *Manager) recordAuto429ProbeResult(authID string, err error, baseTime time.Time, routeModel, upstreamModel, eventType string) Auto429ProbeOutcome {
	outcome := Auto429ProbeOutcome{
		AuthID:        strings.TrimSpace(authID),
		Model:         strings.TrimSpace(routeModel),
		UpstreamModel: strings.TrimSpace(upstreamModel),
		AutoDisabled:  true,
	}
	if m == nil || strings.TrimSpace(authID) == "" {
		return outcome
	}
	authID = strings.TrimSpace(authID)
	now := time.Now()
	if baseTime.IsZero() {
		baseTime = now
	}

	var snapshot *Auth
	var clearedModels []string
	var clearModelsForAuthID string

	m.mu.Lock()
	state := m.auto429[authID]
	auth := m.auths[authID]
	if state == nil || auth == nil {
		m.mu.Unlock()
		return outcome
	}
	state.probing = false
	state.probeStartedAt = time.Time{}

	if err == nil {
		if !state.autoDisabled {
			m.mu.Unlock()
			outcome.AutoDisabled = false
			return outcome
		}
		if auth.Disabled && auth.StatusMessage != auto429DisabledStatusMessage {
			delete(m.auto429, authID)
			m.mu.Unlock()
			outcome.AutoDisabled = false
			outcome.Auto429Cleared = true
			return outcome
		}
		delete(m.auto429, authID)
		auth.Disabled = false
		clearAuthStateOnSuccess(auth, now)
		clearedModels = resetAllModelStates(auth, now)
		clearModelsForAuthID = authID
		m.appendAuto429EventLocked(authID, Auto429Event{
			Time:   now,
			Type:   "restored",
			Model:  routeModel,
			Result: "success, restored",
		})
		snapshot = auth.Clone()
		m.mu.Unlock()
		if snapshot != nil && m.scheduler != nil {
			m.scheduler.upsertAuth(snapshot)
		}
		for _, model := range clearedModels {
			registry.GetGlobalRegistry().ClearModelQuotaExceeded(clearModelsForAuthID, model)
			registry.GetGlobalRegistry().ResumeClientModel(clearModelsForAuthID, model)
		}
		outcome.Restored = true
		outcome.AutoDisabled = false
		outcome.Auto429Cleared = true
		return outcome
	}

	status := statusCodeFromError(err)
	state.lastProbeStatusCode = status
	state.lastProbeError = err.Error()
	state.lastProbeModel = strings.TrimSpace(upstreamModel)
	state.nextRecheckAt = baseTime.Add(time.Duration(auth.Auto429RecheckIntervalSeconds()) * time.Second)
	outcome.StatusCode = status
	outcome.Error = state.lastProbeError
	outcome.NextRecheckAt = state.nextRecheckAt
	m.appendAuto429EventLocked(authID, Auto429Event{
		Time:   baseTime,
		Type:   normalizeAuto429ProbeEventType(eventType),
		Model:  routeModel,
		Result: auto429ProbeFailureResult(status),
	})
	m.mu.Unlock()

	if status != http.StatusTooManyRequests {
		log.WithField("auth_id", authID).Debugf("auto-429 probe failed with status %d: %v", status, err)
	}
	return outcome
}

func normalizeAuto429ProbeEventType(eventType string) string {
	switch strings.TrimSpace(eventType) {
	case auto429EventManualProbe:
		return auto429EventManualProbe
	default:
		return auto429EventAutoProbe
	}
}

func auto429ProbeFailureResult(status int) string {
	if status == http.StatusTooManyRequests {
		return "429, still disabled"
	}
	if status > 0 {
		return fmt.Sprintf("status %d, still disabled", status)
	}
	return "error, still disabled"
}
