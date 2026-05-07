package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestPatchAuthFileFields_MergeHeadersAndDeleteEmptyValues(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	record := &coreauth.Auth{
		ID:       "test.json",
		FileName: "test.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path":            "/tmp/test.json",
			"header:X-Old":    "old",
			"header:X-Remove": "gone",
		},
		Metadata: map[string]any{
			"type": "claude",
			"headers": map[string]any{
				"X-Old":    "old",
				"X-Remove": "gone",
			},
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	body := `{"name":"test.json","prefix":"p1","proxy_url":"http://proxy.local","headers":{"X-Old":"new","X-New":"v","X-Remove":"  ","X-Nope":""}}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	updated, ok := manager.GetByID("test.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}

	if updated.Prefix != "p1" {
		t.Fatalf("prefix = %q, want %q", updated.Prefix, "p1")
	}
	if updated.ProxyURL != "http://proxy.local" {
		t.Fatalf("proxy_url = %q, want %q", updated.ProxyURL, "http://proxy.local")
	}

	if updated.Metadata == nil {
		t.Fatalf("expected metadata to be non-nil")
	}
	if got, _ := updated.Metadata["prefix"].(string); got != "p1" {
		t.Fatalf("metadata.prefix = %q, want %q", got, "p1")
	}
	if got, _ := updated.Metadata["proxy_url"].(string); got != "http://proxy.local" {
		t.Fatalf("metadata.proxy_url = %q, want %q", got, "http://proxy.local")
	}

	headersMeta, ok := updated.Metadata["headers"].(map[string]any)
	if !ok {
		raw, _ := json.Marshal(updated.Metadata["headers"])
		t.Fatalf("metadata.headers = %T (%s), want map[string]any", updated.Metadata["headers"], string(raw))
	}
	if got := headersMeta["X-Old"]; got != "new" {
		t.Fatalf("metadata.headers.X-Old = %#v, want %q", got, "new")
	}
	if got := headersMeta["X-New"]; got != "v" {
		t.Fatalf("metadata.headers.X-New = %#v, want %q", got, "v")
	}
	if _, ok := headersMeta["X-Remove"]; ok {
		t.Fatalf("expected metadata.headers.X-Remove to be deleted")
	}
	if _, ok := headersMeta["X-Nope"]; ok {
		t.Fatalf("expected metadata.headers.X-Nope to be absent")
	}

	if got := updated.Attributes["header:X-Old"]; got != "new" {
		t.Fatalf("attrs header:X-Old = %q, want %q", got, "new")
	}
	if got := updated.Attributes["header:X-New"]; got != "v" {
		t.Fatalf("attrs header:X-New = %q, want %q", got, "v")
	}
	if _, ok := updated.Attributes["header:X-Remove"]; ok {
		t.Fatalf("expected attrs header:X-Remove to be deleted")
	}
	if _, ok := updated.Attributes["header:X-Nope"]; ok {
		t.Fatalf("expected attrs header:X-Nope to be absent")
	}
}

func TestPatchAuthFileFields_HeadersEmptyMapIsNoop(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	record := &coreauth.Auth{
		ID:       "noop.json",
		FileName: "noop.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path":         "/tmp/noop.json",
			"header:X-Kee": "1",
		},
		Metadata: map[string]any{
			"type": "claude",
			"headers": map[string]any{
				"X-Kee": "1",
			},
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	body := `{"name":"noop.json","note":"hello","headers":{}}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	updated, ok := manager.GetByID("noop.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	if got := updated.Attributes["header:X-Kee"]; got != "1" {
		t.Fatalf("attrs header:X-Kee = %q, want %q", got, "1")
	}
	headersMeta, ok := updated.Metadata["headers"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata.headers to remain a map, got %T", updated.Metadata["headers"])
	}
	if got := headersMeta["X-Kee"]; got != "1" {
		t.Fatalf("metadata.headers.X-Kee = %#v, want %q", got, "1")
	}
}

func TestPatchAuthFileFields_UpdatesAuto429Config(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "auto429.json",
		FileName: "auto429.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path": "/tmp/auto429.json",
		},
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	body := `{"name":"auto429.json","auto_disable_429_threshold":20,"auto_429_recheck_interval":600}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	updated, ok := manager.GetByID("auto429.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	if got := updated.AutoDisable429Threshold(); got != 20 {
		t.Fatalf("auto_disable_429_threshold = %d, want 20", got)
	}
	if got := updated.Auto429RecheckIntervalSeconds(); got != 600 {
		t.Fatalf("auto_429_recheck_interval = %d, want 600", got)
	}
}

func TestPatchAuthFileFields_UpdatesDisableCooling(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "disable-cooling.json",
		FileName: "disable-cooling.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path": "/tmp/disable-cooling.json",
		},
		Metadata: map[string]any{
			"type":            "claude",
			"disable-cooling": true,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	body := `{"name":"disable-cooling.json","disable_cooling":false}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	updated, ok := manager.GetByID("disable-cooling.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	got, ok := updated.DisableCoolingOverride()
	if !ok || got {
		t.Fatalf("disable_cooling override = %v ok=%v, want false ok=true", got, ok)
	}
	if got := updated.Metadata["disable_cooling"]; got != false {
		t.Fatalf("metadata.disable_cooling = %#v, want false", got)
	}
	if _, ok := updated.Metadata["disable-cooling"]; ok {
		t.Fatalf("expected legacy metadata.disable-cooling to be removed")
	}
	if got := updated.Attributes["disable_cooling"]; got != "false" {
		t.Fatalf("attrs.disable_cooling = %q, want false", got)
	}
	if _, ok := updated.Attributes["disable-cooling"]; ok {
		t.Fatalf("expected legacy attrs.disable-cooling to be removed")
	}
}

func TestPatchAuthFileFields_DisablingAuto429RestoresRuntimeDisable(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "auto429-disabled.json",
		FileName: "auto429-disabled.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path": "/tmp/auto429-disabled.json",
		},
		Metadata: map[string]any{
			"type":                       "claude",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: "auto429-disabled.json",
		Model:  "claude-test",
		Error:  &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})
	disabled, ok := manager.GetByID("auto429-disabled.json")
	if !ok || !disabled.Disabled {
		t.Fatalf("expected auth to be auto-disabled before patch, got %#v ok=%v", disabled, ok)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	body := `{"name":"auto429-disabled.json","auto_disable_429_threshold":0}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileFields(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	updated, ok := manager.GetByID("auto429-disabled.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	if updated.Disabled || updated.Status != coreauth.StatusActive {
		t.Fatalf("expected threshold=0 to restore auth, got disabled=%v status=%s", updated.Disabled, updated.Status)
	}
	if updated.LastError != nil || updated.Quota.Exceeded {
		t.Fatalf("expected threshold=0 to clear aggregate runtime errors, got last_error=%#v quota=%#v", updated.LastError, updated.Quota)
	}
	if state := updated.ModelStates["claude-test"]; state != nil {
		if state.Unavailable || state.Status != coreauth.StatusActive || state.LastError != nil || state.Quota.Exceeded {
			t.Fatalf("expected threshold=0 to keep cleared model state, got %#v", state)
		}
	}
	if got := updated.AutoDisable429Threshold(); got != 0 {
		t.Fatalf("auto_disable_429_threshold = %d, want 0", got)
	}
	if _, okSnapshot := manager.Auto429Snapshot("auto429-disabled.json"); okSnapshot {
		t.Fatalf("expected auto-429 runtime state to be cleared")
	}
}

func TestPatchAuthFileStatus_EnableClearsAuto429RuntimeState(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "auto429-status.json",
		FileName: "auto429-status.json",
		Provider: "claude",
		Attributes: map[string]string{
			"path": "/tmp/auto429-status.json",
		},
		Metadata: map[string]any{
			"type":                       "claude",
			"auto_disable_429_threshold": 1,
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}
	manager.MarkResult(context.Background(), coreauth.Result{
		AuthID: "auto429-status.json",
		Model:  "claude-test",
		Error:  &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
	})

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	body := `{"name":"auto429-status.json","disabled":false}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	updated, ok := manager.GetByID("auto429-status.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	if updated.Disabled || updated.Status != coreauth.StatusActive {
		t.Fatalf("expected status patch to restore auth, got disabled=%v status=%s", updated.Disabled, updated.Status)
	}
	if state := updated.ModelStates["claude-test"]; state != nil {
		if state.Unavailable || state.Status != coreauth.StatusActive || state.LastError != nil || state.Quota.Exceeded {
			t.Fatalf("expected status patch to keep cleared model state, got %#v", state)
		}
	}
	if _, okSnapshot := manager.Auto429Snapshot("auto429-status.json"); okSnapshot {
		t.Fatalf("expected auto-429 runtime state to be cleared")
	}
}
