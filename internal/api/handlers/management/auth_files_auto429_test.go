package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPatchAuthFileFieldsUpdatesAuto429Config(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:         "auto429.json",
		FileName:   "auto429.json",
		Provider:   "claude",
		Attributes: map[string]string{"path": "/tmp/auto429.json"},
		Metadata:   map[string]any{"type": "claude"},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	recorder := patchAuthFileFields(t, h, `{"name":"auto429.json","auto_disable_429_threshold":20,"auto_429_recheck_interval":600}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	updated, ok := manager.GetByID("auto429.json")
	if !ok || updated == nil {
		t.Fatal("expected auth record to exist after patch")
	}
	if got := updated.AutoDisable429Threshold(); got != 20 {
		t.Fatalf("auto_disable_429_threshold = %d, want 20", got)
	}
	if got := updated.Auto429RecheckIntervalSeconds(); got != 600 {
		t.Fatalf("auto_429_recheck_interval = %d, want 600", got)
	}
}

func TestPatchAuthFileFieldsUpdatesDisableCooling(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:         "disable-cooling.json",
		FileName:   "disable-cooling.json",
		Provider:   "claude",
		Attributes: map[string]string{"path": "/tmp/disable-cooling.json"},
		Metadata: map[string]any{
			"type":            "claude",
			"disable-cooling": true,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	recorder := patchAuthFileFields(t, h, `{"name":"disable-cooling.json","disable_cooling":false}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	updated, ok := manager.GetByID("disable-cooling.json")
	if !ok || updated == nil {
		t.Fatal("expected auth record to exist after patch")
	}
	disableCooling, hasOverride := updated.DisableCoolingOverride()
	if hasOverride || disableCooling {
		t.Fatalf("disable_cooling override = %v ok=%v, want false ok=false", disableCooling, hasOverride)
	}
	if got := updated.Metadata["disable_cooling"]; got != false {
		t.Fatalf("metadata.disable_cooling = %#v, want false", got)
	}
	if _, okLegacy := updated.Metadata["disable-cooling"]; okLegacy {
		t.Fatal("expected legacy metadata.disable-cooling to be removed")
	}
	if got := updated.Attributes["disable_cooling"]; got != "false" {
		t.Fatalf("attrs.disable_cooling = %q, want false", got)
	}
}

func TestPatchAuthFileFieldsDisablingAuto429RestoresAuth(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := newAuto429TestAuth("auto429-disabled.json")
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}
	markAuto429Failure(manager, record.ID)
	disabled, ok := manager.GetByID(record.ID)
	if !ok || !disabled.Disabled {
		t.Fatalf("expected auth to be auto-disabled before patch, got %#v ok=%v", disabled, ok)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	recorder := patchAuthFileFields(t, h, `{"name":"auto429-disabled.json","auto_disable_429_threshold":0}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	assertAuto429AuthRestored(t, manager, record.ID)
	updated, _ := manager.GetByID(record.ID)
	if got := updated.AutoDisable429Threshold(); got != 0 {
		t.Fatalf("auto_disable_429_threshold = %d, want 0", got)
	}
}

func TestPatchAuthFileStatusEnableClearsAuto429State(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := newAuto429TestAuth("auto429-status.json")
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}
	markAuto429Failure(manager, record.ID)

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(`{"name":"auto429-status.json","disabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileStatus(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	assertAuto429AuthRestored(t, manager, record.ID)
}

func patchAuthFileFields(t *testing.T, handler *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	handler.PatchAuthFileFields(ctx)
	return recorder
}

func newAuto429TestAuth(id string) *coreauth.Auth {
	return &coreauth.Auth{
		ID:         id,
		FileName:   id,
		Provider:   "claude",
		Attributes: map[string]string{"path": "/tmp/" + id},
		Metadata: map[string]any{
			"type":                       "claude",
			"auto_disable_429_threshold": 1,
		},
	}
}

func markAuto429Failure(manager *coreauth.Manager, authID string) {
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: authID,
		Model:  "claude-test",
		Error:  &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
}

func assertAuto429AuthRestored(t *testing.T, manager *coreauth.Manager, authID string) {
	t.Helper()
	updated, ok := manager.GetByID(authID)
	if !ok || updated == nil {
		t.Fatal("expected auth record to exist after update")
	}
	if updated.Disabled || updated.Status != coreauth.StatusActive {
		t.Fatalf("expected auth restored, got disabled=%v status=%s", updated.Disabled, updated.Status)
	}
	if updated.LastError != nil || updated.Quota.Exceeded {
		t.Fatalf("expected aggregate runtime errors cleared, got last_error=%#v quota=%#v", updated.LastError, updated.Quota)
	}
	if state := updated.ModelStates["claude-test"]; state != nil {
		if state.Unavailable || state.Status != coreauth.StatusActive || state.LastError != nil || state.Quota.Exceeded {
			t.Fatalf("expected cleared model state, got %#v", state)
		}
	}
	if _, okSnapshot := manager.Auto429Snapshot(authID); okSnapshot {
		t.Fatal("expected auto-429 runtime state to be cleared")
	}
}
