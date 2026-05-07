package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type captureStore struct {
	mu    sync.Mutex
	saves []*Auth
}

func (s *captureStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *captureStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, auth.Clone())
	return "", nil
}

func (s *captureStore) Delete(context.Context, string) error { return nil }

func (s *captureStore) LastSave() *Auth {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saves) == 0 {
		return nil
	}
	return s.saves[len(s.saves)-1].Clone()
}

type auto429ProbeExecutor struct {
	id  string
	err error

	mu      sync.Mutex
	calls   int
	models  []string
	payload [][]byte
}

func (e *auto429ProbeExecutor) Identifier() string {
	if e.id != "" {
		return e.id
	}
	return "test-provider"
}

func (e *auto429ProbeExecutor) Execute(_ context.Context, _ *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.calls++
	e.models = append(e.models, req.Model)
	e.payload = append(e.payload, append([]byte(nil), req.Payload...))
	e.mu.Unlock()
	if e.err != nil {
		return cliproxyexecutor.Response{}, e.err
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
}

func (e *auto429ProbeExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, e.err
}

func (e *auto429ProbeExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *auto429ProbeExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *auto429ProbeExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *auto429ProbeExecutor) Calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func (e *auto429ProbeExecutor) Models() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.models))
	copy(out, e.models)
	return out
}

func (e *auto429ProbeExecutor) Payloads() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([][]byte, len(e.payload))
	for i := range e.payload {
		out[i] = append([]byte(nil), e.payload[i]...)
	}
	return out
}

func TestAuto429DisablesAfterThresholdAndClears(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 2,
			"auto_429_recheck_interval":  60,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	if snapshot, ok := mgr.Auto429Snapshot("auth-1"); !ok || snapshot.Count != 1 || snapshot.AutoDisabled {
		t.Fatalf("expected count=1 and not disabled, got %#v ok=%v", snapshot, ok)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	got, ok := mgr.GetByID("auth-1")
	if !ok {
		t.Fatalf("auth missing")
	}
	if !got.Disabled || got.Status != StatusDisabled {
		t.Fatalf("expected auth disabled by auto-429, got disabled=%v status=%s", got.Disabled, got.Status)
	}
	snapshot, ok := mgr.Auto429Snapshot("auth-1")
	if !ok || !snapshot.AutoDisabled || snapshot.Count != 2 || snapshot.Last429Model != "model-a" {
		t.Fatalf("unexpected auto-429 snapshot: %#v ok=%v", snapshot, ok)
	}

	if !mgr.ClearAuto429State("auth-1") {
		t.Fatalf("expected ClearAuto429State to report restored auth")
	}
	got, ok = mgr.GetByID("auth-1")
	if !ok {
		t.Fatalf("auth missing after clear")
	}
	if got.Disabled || got.Status != StatusActive {
		t.Fatalf("expected auth active after clear, got disabled=%v status=%s", got.Disabled, got.Status)
	}
	if _, okSnapshot := mgr.Auto429Snapshot("auth-1"); okSnapshot {
		t.Fatalf("expected auto-429 snapshot to be removed")
	}
}

func TestAuto429SuccessResetsPendingCount(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "test-provider",
		Metadata: map[string]any{"auto_disable_429_threshold": 2},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	mgr.MarkResult(context.Background(), Result{AuthID: "auth-1", Model: "model-a", Success: true})

	snapshot, ok := mgr.Auto429Snapshot("auth-1")
	if !ok {
		t.Fatalf("expected snapshot to remain for pending runtime state")
	}
	if snapshot.Count != 0 || snapshot.AutoDisabled {
		t.Fatalf("expected success to reset pending count, got %#v", snapshot)
	}
}

func TestAuto429DisableIsNotPersisted(t *testing.T) {
	store := &captureStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "test-provider",
		Metadata: map[string]any{
			"type":                       "test-provider",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	got, ok := mgr.GetByID("auth-1")
	if !ok || !got.Disabled {
		t.Fatalf("expected runtime auth to be disabled, got %#v ok=%v", got, ok)
	}
	saved := store.LastSave()
	if saved == nil {
		t.Fatalf("expected auth save")
	}
	if saved.Disabled {
		t.Fatalf("expected persisted auth to remain enabled")
	}
	if disabled, _ := saved.Metadata["disabled"].(bool); disabled {
		t.Fatalf("expected persisted metadata disabled=false, got true")
	}
}

func TestAuto429DisableIsNotPersistedByLaterResult(t *testing.T) {
	store := &captureStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "test-provider",
		Metadata: map[string]any{
			"type":                       "test-provider",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	got, ok := mgr.GetByID("auth-1")
	if !ok || !got.Disabled {
		t.Fatalf("expected runtime auth to remain disabled, got %#v ok=%v", got, ok)
	}
	saved := store.LastSave()
	if saved == nil {
		t.Fatalf("expected auth save")
	}
	if saved.Disabled || saved.StatusMessage == auto429DisabledStatusMessage {
		t.Fatalf("expected persisted auth to exclude runtime disable, got disabled=%v message=%q", saved.Disabled, saved.StatusMessage)
	}
}

func TestAuto429DisableIsNotPersistedByRegistryReconcile(t *testing.T) {
	store := &captureStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-reconcile",
		Provider: "test-provider",
		Metadata: map[string]any{
			"type":                       "test-provider",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-reconcile",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	mgr.ReconcileRegistryModelStates(context.Background(), "auth-reconcile")

	got, ok := mgr.GetByID("auth-reconcile")
	if !ok || !got.Disabled {
		t.Fatalf("expected runtime auth to remain disabled, got %#v ok=%v", got, ok)
	}
	saved := store.LastSave()
	if saved == nil {
		t.Fatalf("expected auth save")
	}
	if saved.Disabled || saved.StatusMessage == auto429DisabledStatusMessage {
		t.Fatalf("expected reconcile persist to exclude runtime disable, got disabled=%v message=%q", saved.Disabled, saved.StatusMessage)
	}
}

func TestManualDisableWinsOverAuto429RuntimeState(t *testing.T) {
	store := &captureStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-manual",
		Provider: "test-provider",
		Metadata: map[string]any{
			"type":                       "test-provider",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-manual",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	manual, ok := mgr.GetByID("auth-manual")
	if !ok || !manual.Disabled {
		t.Fatalf("expected auth to be auto-disabled before manual update, got %#v ok=%v", manual, ok)
	}
	manual.Disabled = true
	manual.Status = StatusDisabled
	manual.StatusMessage = "disabled via file"
	if _, errUpdate := mgr.Update(context.Background(), manual); errUpdate != nil {
		t.Fatalf("manual update: %v", errUpdate)
	}

	got, ok := mgr.GetByID("auth-manual")
	if !ok {
		t.Fatalf("auth missing")
	}
	if !got.Disabled || got.StatusMessage != "disabled via file" {
		t.Fatalf("expected manual disable to win, got disabled=%v message=%q", got.Disabled, got.StatusMessage)
	}
	if _, okSnapshot := mgr.Auto429Snapshot("auth-manual"); okSnapshot {
		t.Fatalf("expected stale auto-429 state to be forgotten")
	}
	saved := store.LastSave()
	if saved == nil {
		t.Fatalf("expected auth save")
	}
	if !saved.Disabled || saved.StatusMessage != "disabled via file" {
		t.Fatalf("expected manual disable to be persisted, got disabled=%v message=%q", saved.Disabled, saved.StatusMessage)
	}
}

func TestAuto429ProbeRestoresOrReschedules(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-1",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	failing := &auto429ProbeExecutor{err: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "still quota"}}
	mgr.RegisterExecutor(failing)
	mgr.runDueAuto429Probes(context.Background(), time.Now().Add(2*time.Second))
	if failing.Calls() != 1 {
		t.Fatalf("expected one failing probe call, got %d", failing.Calls())
	}
	snapshot, ok := mgr.Auto429Snapshot("auth-1")
	if !ok || !snapshot.AutoDisabled || snapshot.LastProbeStatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected failed probe to keep auth disabled, got %#v ok=%v", snapshot, ok)
	}

	successful := &auto429ProbeExecutor{}
	mgr.RegisterExecutor(successful)
	mgr.runDueAuto429Probes(context.Background(), time.Now().Add(2*time.Second))
	if successful.Calls() != 1 {
		t.Fatalf("expected one successful probe call, got %d", successful.Calls())
	}
	got, ok := mgr.GetByID("auth-1")
	if !ok {
		t.Fatalf("auth missing after successful probe")
	}
	if got.Disabled || got.Status != StatusActive {
		t.Fatalf("expected successful probe to restore auth, got disabled=%v status=%s", got.Disabled, got.Status)
	}
	if _, okSnapshot := mgr.Auto429Snapshot("auth-1"); okSnapshot {
		t.Fatalf("expected successful probe to remove auto-429 state")
	}
}

func TestAuto429ProbeFindsExecutorWithRawProviderKey(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-raw-provider",
		Provider: "Test-Provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-raw-provider",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	executor := &auto429ProbeExecutor{id: "pool"}
	mgr.mu.Lock()
	mgr.executors["Test-Provider"] = executor
	mgr.mu.Unlock()

	mgr.runDueAuto429Probes(context.Background(), time.Now().Add(2*time.Second))
	if executor.Calls() != 1 {
		t.Fatalf("expected raw provider executor to be used, got %d calls", executor.Calls())
	}
}

func TestAuto429ProbeUsesMappedUpstreamModel(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	mgr.SetConfig(&internalconfig.Config{
		OpenAICompatibility: []internalconfig.OpenAICompatibility{{
			Name: "pool",
			Models: []internalconfig.OpenAICompatibilityModel{{
				Name:  "actual-upstream-model",
				Alias: "public-alias-model",
			}},
		}},
	})
	auth := &Auth{
		ID:       "auth-mapped-model",
		Provider: "pool",
		Attributes: map[string]string{
			"api_key":      "test-key",
			"compat_name":  "pool",
			"provider_key": "pool",
		},
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-mapped-model",
		Model:  "public-alias-model",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	executor := &auto429ProbeExecutor{id: "pool"}
	mgr.RegisterExecutor(executor)
	mgr.runDueAuto429Probes(context.Background(), time.Now().Add(2*time.Second))

	models := executor.Models()
	if len(models) != 1 {
		t.Fatalf("expected one probe call, got models=%v", models)
	}
	if models[0] != "actual-upstream-model" {
		t.Fatalf("probe model = %q, want mapped upstream model", models[0])
	}
	payloads := executor.Payloads()
	if len(payloads) != 1 || !strings.Contains(string(payloads[0]), `"model":"actual-upstream-model"`) {
		t.Fatalf("probe payload = %q, want mapped upstream model", payloads)
	}
	events := mgr.Auto429Events("auth-mapped-model")
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2: %#v", len(events), events)
	}
	if events[0].Model != "public-alias-model" || events[1].Model != "public-alias-model" {
		t.Fatalf("expected event model to consistently use route model, got %#v", events)
	}
}

func TestManualAuto429ProbeReschedulesFromProbeStart(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-manual-probe",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  60,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-manual-probe",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	executor := &auto429ProbeExecutor{err: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "still quota"}}
	mgr.RegisterExecutor(executor)

	startedAt := time.Now()
	outcome, errProbe := mgr.ProbeAuto429State(context.Background(), "auth-manual-probe")
	if errProbe != nil {
		t.Fatalf("manual probe: %v", errProbe)
	}
	if outcome.Restored || outcome.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected failed 429 probe outcome, got %#v", outcome)
	}
	if outcome.NextRecheckAt.Before(startedAt.Add(60*time.Second)) || outcome.NextRecheckAt.After(time.Now().Add(65*time.Second)) {
		t.Fatalf("next recheck = %s, want about manual probe start + interval", outcome.NextRecheckAt)
	}
}

func TestAuto429EventsRecordDisableProbeAndRestore(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-events",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  60,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-events",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	events := mgr.Auto429Events("auth-events")
	if len(events) != 1 || events[0].Type != "disabled" || events[0].Model != "model-a" {
		t.Fatalf("expected disabled event for model-a, got %#v", events)
	}

	executor := &auto429ProbeExecutor{err: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "still quota"}}
	mgr.RegisterExecutor(executor)
	if _, errProbe := mgr.ProbeAuto429State(context.Background(), "auth-events"); errProbe != nil {
		t.Fatalf("manual probe: %v", errProbe)
	}
	events = mgr.Auto429Events("auth-events")
	if len(events) != 2 || events[1].Type != "manual_probe" || events[1].Result != "429, still disabled" {
		t.Fatalf("expected manual probe 429 event, got %#v", events)
	}

	executor.err = nil
	if _, errProbe := mgr.ProbeAuto429State(context.Background(), "auth-events"); errProbe != nil {
		t.Fatalf("manual restore probe: %v", errProbe)
	}
	events = mgr.Auto429Events("auth-events")
	if len(events) != 3 || events[2].Type != "restored" || events[2].Result != "success, restored" {
		t.Fatalf("expected restored event to remain after state clear, got %#v", events)
	}
	if count := mgr.Auto429EventCount("auth-events"); count != 3 {
		t.Fatalf("event count = %d, want 3", count)
	}
}

func TestAuto429EventsCompactMiddleRepeated429Probes(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-events-compact",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  60,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-events-compact",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	executor := &auto429ProbeExecutor{err: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "still quota"}}
	mgr.RegisterExecutor(executor)
	for i := 0; i < 5; i++ {
		if _, errProbe := mgr.ProbeAuto429State(context.Background(), "auth-events-compact"); errProbe != nil {
			t.Fatalf("manual probe %d: %v", i, errProbe)
		}
	}

	events := mgr.Auto429Events("auth-events-compact")
	if len(events) != 3 {
		t.Fatalf("events len = %d, want disabled + first/latest repeated 429: %#v", len(events), events)
	}
	if events[0].Type != "disabled" || events[1].Type != "manual_probe" || events[2].Type != "manual_probe" {
		t.Fatalf("unexpected compacted events: %#v", events)
	}
}

func TestAuto429ProbeInProgressSkipsManualAndAutoProbe(t *testing.T) {
	mgr := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-probing",
		Provider: "test-provider",
		Metadata: map[string]any{
			"auto_disable_429_threshold": 1,
			"auto_429_recheck_interval":  1,
		},
	}
	if _, errRegister := mgr.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	mgr.MarkResult(context.Background(), Result{
		AuthID: "auth-probing",
		Model:  "model-a",
		Error:  &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	executor := &auto429ProbeExecutor{}
	mgr.RegisterExecutor(executor)

	mgr.mu.Lock()
	mgr.auto429["auth-probing"].probing = true
	mgr.mu.Unlock()

	if _, errProbe := mgr.ProbeAuto429State(context.Background(), "auth-probing"); !errors.Is(errProbe, ErrAuto429ProbeInProgress) {
		t.Fatalf("manual probe error = %v, want ErrAuto429ProbeInProgress", errProbe)
	}
	mgr.runDueAuto429Probes(context.Background(), time.Now().Add(2*time.Second))
	if executor.Calls() != 0 {
		t.Fatalf("expected in-progress auth to skip probes, got %d calls", executor.Calls())
	}
}
